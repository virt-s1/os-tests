from .resources import VMResource, StorageResource, NetworkResource, UnSupportedAction, UnSupportedStatus
from os_tests.libs import utils_lib
import logging
import time
import sys
try:
    import oci
    from oci.core import ComputeClient, BlockstorageClient, VirtualNetworkClient
    from oci.core.models import (
        LaunchInstanceDetails,
        CreateVnicDetails,
        InstanceSourceViaImageDetails,
        LaunchInstanceShapeConfigDetails,
        CreateVolumeDetails,
        AttachIScsiVolumeDetails,
        AttachParavirtualizedVolumeDetails,
        CreateVcnDetails,
    )
except ImportError:
    print("Please install oci module if run OCI test")
    sys.exit(1)

LOG = logging.getLogger('os_tests.os_tests_run')
logging.basicConfig(level=logging.INFO)


class OCIVM(VMResource):
    _instance = None

    def __init__(self, params, vendor="redhat"):
        LOG.info('Init OCIVM resource')
        super().__init__(params)
        self.id = None
        self.ipv4 = None
        self.ipv6 = None

        # OCI authentication
        config_file = params.get('config_file') or '~/.oci/config'
        profile_name = params.get('profile_name') or 'DEFAULT'
        try:
            self.oci_config = oci.config.from_file(file_location=config_file, profile_name=profile_name)
        except Exception as err:
            LOG.error("Failed to load OCI config: {}".format(err))
            raise

        self.compute_client = ComputeClient(self.oci_config)
        self.network_client = VirtualNetworkClient(self.oci_config)
        self.blockstorage_client = BlockstorageClient(self.oci_config)

        # VM parameters
        self.compartment_id = params.get('compartment_id')
        self.availability_domain = params.get('availability_domain')
        self.image_id = params.get('image_id')
        self.shape = params.get('shape')
        self.subnet_id = params.get('subnet_id')
        self.vm_username = params.get('username')
        self.ssh_key_path = params.get('ssh_key_path')
        self.ssh_pubkey_path = params.get('ssh_pubkey_path')
        self.tag = params.get('tagname') or 'os_tests_vm_oci'
        self.run_uuid = params.get('run_uuid')
        self.user_data = None
        self.ssh_conn = None
        self.is_created = False

        # Shape config for flexible shapes
        self.ocpus = params.get('ocpus')
        self.memory_in_gbs = params.get('memory_in_gbs')
        self.boot_volume_size_in_gbs = params.get('boot_volume_size_in_gbs') or 50

        LOG.info("OCI picked vendor:{} image:{} shape:{}".format(vendor, self.image_id, self.shape))

    def show(self):
        if self.is_exist():
            LOG.info("Instance ID: {}".format(self.id))

    def create(self, wait=True, userdata=None, sshkey=None):
        self.is_created = False
        if self.id and not self.params.get("is_allow_delete"):
            LOG.info("Use exists {} which is_allow_delete is {}".format(
                self.id, self.params.get("is_allow_delete")))
            self._instance = self.compute_client.get_instance(self.id).data
            self.is_created = True
            self.shape = self._instance.shape
            return True

        # Read SSH public key for metadata
        ssh_authorized_keys = None
        pubkey_path = sshkey or self.ssh_pubkey_path
        if pubkey_path:
            try:
                with open(pubkey_path, 'r') as f:
                    ssh_authorized_keys = f.read().strip()
            except Exception as err:
                LOG.warning("Failed to read SSH public key {}: {}".format(pubkey_path, err))

        # Build VNIC details
        create_vnic_details = CreateVnicDetails(
            subnet_id=self.subnet_id,
            assign_public_ip=True
        )

        # Build source details
        source_details = InstanceSourceViaImageDetails(
            image_id=self.image_id,
            boot_volume_size_in_gbs=self.boot_volume_size_in_gbs
        )

        # Build launch details
        launch_kwargs = {
            'compartment_id': self.compartment_id,
            'availability_domain': self.availability_domain,
            'shape': self.shape,
            'display_name': self.tag,
            'create_vnic_details': create_vnic_details,
            'source_details': source_details,
            'freeform_tags': {'Name': self.tag},
        }

        # Set metadata (SSH key and user_data)
        metadata = {}
        if ssh_authorized_keys:
            metadata['ssh_authorized_keys'] = ssh_authorized_keys
        userdata = userdata or self.user_data
        if userdata:
            import base64
            metadata['user_data'] = base64.b64encode(userdata.encode()).decode('ascii')
        if metadata:
            launch_kwargs['metadata'] = metadata

        # Shape config for flexible shapes (e.g., VM.Standard.E4.Flex)
        if self.ocpus or self.memory_in_gbs:
            shape_config = LaunchInstanceShapeConfigDetails(
                ocpus=float(self.ocpus) if self.ocpus else None,
                memory_in_gbs=float(self.memory_in_gbs) if self.memory_in_gbs else None
            )
            launch_kwargs['shape_config'] = shape_config

        launch_instance_details = LaunchInstanceDetails(**launch_kwargs)

        LOG.info("Create instance {}".format(launch_kwargs))
        try:
            response = self.compute_client.launch_instance(launch_instance_details)
            self._instance = response.data
            self.id = self._instance.id
            self.is_created = True
        except Exception as err:
            LOG.error("Failed to create instance with error: {}".format(err))
            self.msgs = str(err)
            return False

        if wait:
            try:
                get_response = oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_instance(self.id),
                    'lifecycle_state',
                    'RUNNING',
                    max_wait_seconds=600
                )
                self._instance = get_response.data
            except Exception as err:
                LOG.error("Failed to wait instance running: {}".format(err))

        self.show()
        self.floating_ip
        return True

    @property
    @utils_lib.wait_for(not_ret='', ck_not_ret=True, timeout=120)
    def floating_ip(self):
        try:
            vnic_attachments = self.compute_client.list_vnic_attachments(
                compartment_id=self.compartment_id,
                instance_id=self.id
            ).data
            for vnic_attachment in vnic_attachments:
                if vnic_attachment.lifecycle_state != 'ATTACHED':
                    continue
                vnic = self.network_client.get_vnic(vnic_attachment.vnic_id).data
                if vnic.is_primary:
                    self.ipv4 = vnic.public_ip or ''
                    if self.ipv4:
                        LOG.info("instance: {} public ip is: {}".format(self.id, self.ipv4))
                        return self.ipv4
            LOG.info("No public ip available yet!")
            return ''
        except Exception as err:
            LOG.info("Failed to get floating ip: {}".format(err))
            return ''

    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def private_ip(self):
        try:
            vnic_attachments = self.compute_client.list_vnic_attachments(
                compartment_id=self.compartment_id,
                instance_id=self.id
            ).data
            for vnic_attachment in vnic_attachments:
                if vnic_attachment.lifecycle_state != 'ATTACHED':
                    continue
                vnic = self.network_client.get_vnic(vnic_attachment.vnic_id).data
                if vnic.is_primary:
                    LOG.info("instance: {} private_ip is: {}".format(self.id, vnic.private_ip))
                    return vnic.private_ip
        except Exception as err:
            LOG.info("Failed to get private ip: {}".format(err))
        return None

    @property
    def vm_name(self):
        try:
            self._instance = self.compute_client.get_instance(self.id).data
            LOG.info("display_name is: {}".format(self._instance.display_name))
            return self._instance.display_name
        except Exception as err:
            LOG.info("display_name is not available now, return None")
            return None

    @property
    def ipv6_address(self):
        LOG.info("ipv6 not implemented for OCI yet")
        return None

    @property
    def disk_count(self):
        if self.disks_cfg:
            LOG.info("Setting in cfg {}".format(self.disks_cfg))
            return self.disks_cfg
        default_disks = 1
        try:
            volume_attachments = self.compute_client.list_volume_attachments(
                compartment_id=self.compartment_id,
                instance_id=self.id
            ).data
            default_disks += len([v for v in volume_attachments if v.lifecycle_state == 'ATTACHED'])
        except Exception as err:
            LOG.info("Cannot get disk count: {}".format(err))
        LOG.info("{} has {} disks".format(self.id, default_disks))
        return default_disks

    @property
    def is_secure_boot(self):
        LOG.info("return false for now, need to update is_secure_boot() on OCI")
        return False

    @property
    def is_uefi_boot(self):
        try:
            self._instance = self.compute_client.get_instance(self.id).data
            launch_options = self._instance.launch_options
            if launch_options and launch_options.firmware == 'UEFI_64':
                return True
        except Exception as err:
            LOG.info("Cannot determine boot mode: {}".format(err))
        return False

    @property
    def is_metal(self):
        return 'BM.' in self.shape if self.shape else False

    def start(self, wait=True):
        try:
            LOG.info("Starting instance: {}".format(self.id))
            self.compute_client.instance_action(self.id, 'START')
        except Exception as err:
            LOG.error("Failed to start instance: {}".format(err))
            return False

        if wait:
            try:
                oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_instance(self.id),
                    'lifecycle_state',
                    'RUNNING',
                    max_wait_seconds=300
                )
            except Exception as err:
                LOG.error("Failed to wait instance running: {}".format(err))
                return False
            self._instance = self.compute_client.get_instance(self.id).data
            if self._instance.lifecycle_state != 'RUNNING':
                LOG.error("Instance is not in running state! It is in {} state!".format(
                    self._instance.lifecycle_state))
                return False
            LOG.info("Instance is in running state!")
            self.floating_ip
        return True

    def stop(self, wait=True, loops=4):
        try:
            LOG.info("Stopping instance: {}".format(self.id))
            self.compute_client.instance_action(self.id, 'SOFTSTOP')
        except Exception as err:
            LOG.error("Failed to stop instance: {}".format(err))
            return False

        if wait:
            try:
                oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_instance(self.id),
                    'lifecycle_state',
                    'STOPPED',
                    max_wait_seconds=300 * loops
                )
                return 'STOPPED' == self.get_state()
            except Exception as err:
                LOG.error("Failed to wait instance stopped: {}".format(err))
                return 'STOPPED' == self.get_state()
        return True

    def reboot(self, wait=False):
        LOG.info("Rebooting instance: {}".format(self.id))
        try:
            self.compute_client.instance_action(self.id, 'SOFTRESET')
            if 'BM.' in self.shape:
                time.sleep(120)
            else:
                time.sleep(5)
            return True
        except Exception as err:
            LOG.error("Failed to reboot instance: {}".format(err))
            return False

    def delete(self, wait=True, loops=4):
        if self.id and not self.params.get("is_allow_delete"):
            LOG.info("Use exists {} which is_allow_delete is {}".format(
                self.id, self.params.get("is_allow_delete")))
            return True
        try:
            LOG.info("Deleting instance: {}".format(self.id))
            self.compute_client.terminate_instance(self.id, preserve_boot_volume=False)
        except Exception as err:
            LOG.info("Failed to delete instance: {}".format(err))
            return False
        if wait:
            try:
                oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_instance(self.id),
                    'lifecycle_state',
                    'TERMINATED',
                    max_wait_seconds=300 * loops,
                    succeed_on_not_found=True
                )
                return 'TERMINATED' == self.get_state()
            except Exception as err:
                LOG.error("Failed to wait instance terminated: {}".format(err))
                return 'TERMINATED' == self.get_state()
        return True

    def send_nmi(self):
        try:
            LOG.info("Send diagnostic interrupt to {}".format(self.id))
            self.compute_client.instance_action(self.id, 'SENDDIAGNOSTICINTERRUPT')
            return True
        except Exception as err:
            LOG.error("Failed to send diagnostic interrupt: {}".format(err))
        raise UnSupportedAction('This instance does not support send nmi')

    def send_hibernation(self):
        LOG.info("Hibernation is not supported on OCI")
        return False

    def get_console_log(self, silent=False):
        ret = None
        try:
            LOG.info("try to retrieve console log of {}".format(self.id))
            response = self.compute_client.get_console_history_content(
                self._get_or_create_console_history()
            )
            ret = response.data
            if not silent:
                LOG.info(ret)
            return ret
        except Exception as err:
            LOG.error("Failed to get console log: {}".format(err))
            return str(err)

    def _get_or_create_console_history(self):
        try:
            histories = self.compute_client.list_console_histories(
                compartment_id=self.compartment_id,
                instance_id=self.id
            ).data
            for h in histories:
                if h.lifecycle_state == 'SUCCEEDED':
                    return h.id
            # Create a new console history capture
            from oci.core.models import CaptureConsoleHistoryDetails
            response = self.compute_client.capture_console_history(
                CaptureConsoleHistoryDetails(instance_id=self.id)
            )
            console_history_id = response.data.id
            oci.wait_until(
                self.compute_client,
                self.compute_client.get_console_history(console_history_id),
                'lifecycle_state',
                'SUCCEEDED',
                max_wait_seconds=120
            )
            return console_history_id
        except Exception as err:
            LOG.error("Failed to get/create console history: {}".format(err))
            raise

    def get_state(self):
        try:
            state = 'unknown'
            self._instance = self.compute_client.get_instance(self.id).data
            state = self._instance.lifecycle_state
        except Exception as err:
            LOG.info("Exception found: {}".format(err))
        LOG.info("instance:{} state: {}".format(self.id, state))
        return state

    def is_exist(self):
        try:
            LOG.info("check if instance exists")
            state = self.get_state()
            if state in ['TERMINATED', 'unknown']:
                return False
            return True
        except Exception as err:
            LOG.info("{}".format(err))
            return False

    def exists(self):
        return self.is_exist()

    def is_stopped(self):
        return self.get_state() == 'STOPPED'

    def is_started(self):
        return self.get_state() == 'RUNNING'

    def attach_block(self, disk, target, wait=True, timeout=120):
        try:
            LOG.info("try to attach {} to {}".format(disk.id, self.id))
            attach_details = AttachParavirtualizedVolumeDetails(
                display_name=target,
                instance_id=self.id,
                volume_id=disk.id
            )
            response = self.compute_client.attach_volume(attach_details)
            if wait:
                oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_volume_attachment(response.data.id),
                    'lifecycle_state',
                    'ATTACHED',
                    max_wait_seconds=timeout
                )
            return True
        except Exception as err:
            LOG.error("Failed to attach volume: {}".format(err))
            return False

    def detach_block(self, disk, wait=True, force=False):
        try:
            LOG.info("try to detach {} from {}".format(disk.id, self.id))
            volume_attachments = self.compute_client.list_volume_attachments(
                compartment_id=self.compartment_id,
                instance_id=self.id,
                volume_id=disk.id
            ).data
            for va in volume_attachments:
                if va.lifecycle_state == 'ATTACHED':
                    self.compute_client.detach_volume(va.id)
                    if wait:
                        oci.wait_until(
                            self.compute_client,
                            self.compute_client.get_volume_attachment(va.id),
                            'lifecycle_state',
                            'DETACHED',
                            max_wait_seconds=120,
                            succeed_on_not_found=True
                        )
                    return True
            LOG.info("No attached volume found")
            return False
        except Exception as err:
            LOG.error("Failed to detach volume: {}".format(err))
            return False

    def attach_nic(self, nic, wait=True, timeout=120, **kwargs):
        try:
            LOG.info("try to attach nic to {}".format(self.id))
            from oci.core.models import AttachVnicDetails, CreateVnicDetails
            attach_vnic_details = AttachVnicDetails(
                instance_id=self.id,
                create_vnic_details=CreateVnicDetails(
                    subnet_id=nic.subnet_id,
                    assign_public_ip=False,
                    display_name=nic.tag,
                    freeform_tags={'Name': nic.tag}
                )
            )
            response = self.compute_client.attach_vnic(attach_vnic_details)
            nic.vnic_attachment_id = response.data.id
            if wait:
                get_response = oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_vnic_attachment(nic.vnic_attachment_id),
                    'lifecycle_state',
                    'ATTACHED',
                    max_wait_seconds=timeout
                )
                vnic_attachment = get_response.data
                nic.id = vnic_attachment.vnic_id
                LOG.info("nic attached, vnic_id: {}, attachment_id: {}".format(nic.id, nic.vnic_attachment_id))
            return True
        except Exception as err:
            LOG.error("Failed to attach nic: {}".format(err))
            return False

    def detach_nic(self, nic, wait=True, force=False):
        try:
            if not nic.vnic_attachment_id:
                LOG.info("No vnic_attachment_id found, searching...")
                vnic_attachments = self.compute_client.list_vnic_attachments(
                    compartment_id=self.compartment_id,
                    instance_id=self.id
                ).data
                for va in vnic_attachments:
                    if va.vnic_id == nic.id and va.lifecycle_state == 'ATTACHED':
                        nic.vnic_attachment_id = va.id
                        break
            if not nic.vnic_attachment_id:
                LOG.info("No attached vnic found to detach")
                return False
            LOG.info("try to detach nic {} from {}".format(nic.vnic_attachment_id, self.id))
            self.compute_client.detach_vnic(nic.vnic_attachment_id)
            if wait:
                oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_vnic_attachment(nic.vnic_attachment_id),
                    'lifecycle_state',
                    'DETACHED',
                    max_wait_seconds=120,
                    succeed_on_not_found=True
                )
            nic.vnic_attachment_id = None
            nic.id = None
            LOG.info("nic detached successfully")
            return True
        except Exception as err:
            LOG.error("Failed to detach nic: {}".format(err))
            return False
    
    def is_paused(self):
        raise NotImplementedError

    def pause(self):
        raise NotImplementedError

    def unpause(self):
        raise NotImplementedError


class OCIVolume(StorageResource):
    '''
    OCI Volume class
    '''
    volume = None

    def __init__(self, params):
        super(OCIVolume, self).__init__(params)
        LOG.info('Init OCIVolume resource')
        config_file = params.get('config_file') or '~/.oci/config'
        profile_name = params.get('profile_name') or 'DEFAULT'
        self.oci_config = oci.config.from_file(file_location=config_file, profile_name=profile_name)
        self.blockstorage_client = BlockstorageClient(self.oci_config)
        self.compute_client = ComputeClient(self.oci_config)

        self.compartment_id = params.get('compartment_id')
        self.availability_domain = params.get('availability_domain')
        self.tag = params.get('tagname') or 'os_tests_storage_oci'
        self.id = None
        self.size = 100
        self.type = None

    def is_free(self):
        try:
            volume_attachments = self.compute_client.list_volume_attachments(
                compartment_id=self.compartment_id,
                volume_id=self.id
            ).data
            for va in volume_attachments:
                if va.lifecycle_state in ['ATTACHING', 'ATTACHED']:
                    LOG.info("{} volume is attached (state: {})".format(self.id, va.lifecycle_state))
                    return False
            LOG.info("{} volume is free".format(self.id))
            return True
        except Exception as err:
            LOG.info("Failed to check volume attachment: {}".format(err))
            return True

    def create(self, wait=True):
        try:
            volume_details = CreateVolumeDetails(
                compartment_id=self.compartment_id,
                availability_domain=self.availability_domain,
                display_name=self.tag,
                size_in_gbs=self.size,
                freeform_tags={'Name': self.tag}
            )
            LOG.info("Create volume {}".format(volume_details))
            response = self.blockstorage_client.create_volume(volume_details)
            self.volume = response.data
            self.id = self.volume.id

            if wait:
                oci.wait_until(
                    self.blockstorage_client,
                    self.blockstorage_client.get_volume(self.id),
                    'lifecycle_state',
                    'AVAILABLE',
                    max_wait_seconds=120
                )
            LOG.info("Volume created {} state {}".format(self.id, self.get_state()))
            return True
        except Exception as err:
            LOG.error("Failed to create volume: {}".format(err))
            return False

    def delete(self, wait=True):
        if self.volume is not None:
            LOG.info("Delete {}".format(self.id))
            try:
                self.blockstorage_client.delete_volume(self.id)
                if wait:
                    oci.wait_until(
                        self.blockstorage_client,
                        self.blockstorage_client.get_volume(self.id),
                        'lifecycle_state',
                        'TERMINATED',
                        max_wait_seconds=120,
                        succeed_on_not_found=True
                    )
                return True
            except Exception as err:
                LOG.error("Failed to delete volume: {}".format(err))
                return False
        else:
            LOG.info("No specify volume delete.")

    def get_state(self):
        try:
            state = 'unknown'
            self.volume = self.blockstorage_client.get_volume(self.id).data
            state = self.volume.lifecycle_state
            self.size = self.volume.size_in_gbs
            LOG.info("disk state: {}, size: {}".format(state, self.size))
        except Exception as err:
            return state
        return state

    def show(self):
        if self.is_exist():
            LOG.info("Volume ID: {}".format(self.id))

    def is_exist(self):
        try:
            self.volume = self.blockstorage_client.get_volume(self.id).data
            if self.volume.lifecycle_state in ['TERMINATING', 'TERMINATED']:
                LOG.info("Volume is deleted {}".format(self.id))
                return False
            LOG.info("Volume exists {}".format(self.id))
            return True
        except Exception as err:
            LOG.info("Volume does not exist {}".format(self.id))
            return False

    def modify_disk_size(self, os_disk_size=10, expand_num=10):
        try:
            os_disk_size = self.size
            from oci.core.models import UpdateVolumeDetails
            update_details = UpdateVolumeDetails(
                size_in_gbs=os_disk_size + expand_num
            )
            self.blockstorage_client.update_volume(self.id, update_details)
            time.sleep(20)
            self.get_state()
            return True
        except Exception as err:
            LOG.info("Failed to modify disk size: {}".format(err))
            return False


class OCINIC(NetworkResource):
    '''
    OCI Network class
    On OCI, secondary VNICs are created and attached in one API call
    (attach_vnic) and detached and deleted in one call (detach_vnic).
    So create() just marks the NIC as ready, and delete() is a no-op
    since detach_vnic already removes the VNIC.
    '''

    def __init__(self, params):
        super(OCINIC, self).__init__(params)
        LOG.info('Init OCINIC resource')
        config_file = params.get('config_file') or '~/.oci/config'
        profile_name = params.get('profile_name') or 'DEFAULT'
        self.oci_config = oci.config.from_file(file_location=config_file, profile_name=profile_name)
        self.compute_client = ComputeClient(self.oci_config)
        self.network_client = VirtualNetworkClient(self.oci_config)

        self.compartment_id = params.get('compartment_id')
        self.subnet_id = params.get('subnet_id') or params.get('subnet_id_ipv4')
        self.tag = params.get('tagname') or 'os_tests_nic_oci'
        self.id = None
        self.vnic_attachment_id = None

    def show(self):
        if self.is_exist():
            LOG.info("VNIC ID: {}".format(self.id))

    def create(self):
        LOG.info("OCINIC created (will be provisioned on attach_nic)")
        return True

    def delete(self, wait=True):
        LOG.info("OCINIC delete (already handled by detach_vnic)")
        self.id = None
        self.vnic_attachment_id = None
        return True

    def get_state(self):
        if not self.id:
            return 'unknown'
        try:
            vnic = self.network_client.get_vnic(self.id).data
            state = vnic.lifecycle_state
            LOG.info("vnic state: {}".format(state))
            return state
        except Exception as err:
            LOG.info("Failed to get vnic state: {}".format(err))
            return 'unknown'

    def is_exist(self):
        if not self.id:
            return False
        try:
            vnic = self.network_client.get_vnic(self.id).data
            if vnic.lifecycle_state in ['TERMINATING', 'TERMINATED']:
                LOG.info("VNIC is deleted {}".format(self.id))
                return False
            LOG.info("VNIC exists {}".format(self.id))
            return True
        except Exception as err:
            LOG.info("VNIC does not exist {}".format(self.id))
            return False

    def is_free(self):
        if not self.id:
            return True
        if not self.vnic_attachment_id:
            return True
        try:
            va = self.compute_client.get_vnic_attachment(self.vnic_attachment_id).data
            if va.lifecycle_state in ['ATTACHED', 'ATTACHING']:
                LOG.info("{} nic is in use (state: {})".format(self.id, va.lifecycle_state))
                return False
        except Exception:
            pass
        return True
