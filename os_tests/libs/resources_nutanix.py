#from ..base import VM
#from .nutanix import PrismApi
#from ..utils import utils_misc
from os_tests.libs import utils_lib
#from ..utils import ssh_key
import logging

import json
import base64
from requests.compat import urljoin
import requests
import subprocess
import time

from .resources import VMResource,StorageResource,UnSupportedAction,UnSupportedStatus

# Disable HTTPS verification warnings.
try:
    from requests.packages import urllib3
except ImportError:
    import urllib3
else:
    urllib3.disable_warnings()

logger = logging.getLogger('urllib3')
logger.setLevel(logging.DEBUG)

class PrismSession(object):
    def __init__(self, cvmIP, username, password):
        self.s = requests.Session()
        logging.info('self.s is' + str(self.s))
        # Base Url v2 API
        self.base_url = "https://" + cvmIP + ":9440/PrismGateway/services/rest/v2.0/"
        credential = base64.b64encode(
            ('%s:%s' % (username, password)).encode()).decode()
        self.headers = {"Authorization": "Basic %s" % credential}
        self.s.headers.update(self.headers)
        self.r = None

    def get(self, url):
        logging.info("Making api get call to %s" % url)
        try:
            self.r = self.s.get(url, headers=self.headers, verify=False)
        except requests.exceptions.RequestException as e:
            logging.error("Failed to connect to Prism")
        # convert response to json
        return self.__json()

    def post(self, url, data):
        logging.info("Making api post call to %s" % url)
        try:
            self.r = self.s.post(url, json=data, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("Failed to connect to Prism")
        # convert response to json
        return self.__json()

    def put(self, url, data):
        logging.info("Making api put call to %s" % url)
        try:
            self.r = self.s.put(url, json=data, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("Failed to connect to Prism")
        # convert response to json
        return self.__json()

    def delete(self, url):
        logging.info("Making api delete call to %s" % url)
        try:
            self.r = self.s.delete(url, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("Failed to connect to Prism")
        # convert response to json
        return self.__json()

    def __json(self):
        try:
            json_obj = json.loads(self.r.text)
            return json_obj
        except ValueError:
            if self.r.text:
                logging.error("Unable to convert string to json\n %s" %
                          self.r.text)
            else:
                logging.debug("Response has no content.")

class PrismApi(PrismSession):
    def __init__(self, params):

        # Nutanix connection credentials
        #self.cvmIP = params.get('cvm_ip', '*/Cloud/*')
        self.cvmIP = params['Cloud']['cvm_ip']
        logging.info('sefl.cvmIP is ' + self.cvmIP + ', type is '+ str(type(self.cvmIP)))
        #username = params.get('username', '*/Credential/*')
        username = params['Credential']['username']
        logging.info('username is ' + str(username) + ', type is '+ str(type(username)))
        #password = params.get('password', '*/Credential/*')
        password = params['Credential']['password']

        # VM creation parameters
        #self.vm_name = params.get('vm_name', '*/VM/*')
        self.vm_name = params['VM']['vm_name']
        #self.vm_username = params.get('username', '*/VM/*')
        self.vm_username = params['VM']['username']
        #self.vm_password = params.get('password', '*/VM/*')
        self.vm_password = params['VM']['password']
        #self.image_name = params.get('image_name', '*/VM/*')
        self.image_name = params['VM']['image_name']
        #self.image_name_iso = params.get('image_name_iso','*/VM/*')
        self.image_name_iso = params['VM']['image_name_iso']
        #self.image_name_kickstart_iso = params.get('image_name_kickstart_iso','*/VM/*')
        self.image_name_kickstart_iso = params['VM']['image_name_kickstart_iso']
        #self.storage_container_uuid = params.get('storage_container_uuid', '*/VM/*')
        self.storage_container_uuid = params['VM']['storage_container_uuid']
        #self.disk = params.get('size', '*/Flavor/*')
        self.disk_size = params['Flavor']['size']
        #self.network_uuid = params.get('network_uuid', '*/VM/*')
        self.network_uuid = params['VM']['network_uuid']
        #self.cpu = params.get('cpu', '*/Flavor/*')
        self.cpu = params['Flavor']['cpu']
        #self.memory = params.get('memory', '*/Flavor/*')
        self.memory = params['Flavor']['memory']
        #self.vm_user_data = params.get('custom_data', '*/VM/*')
        self.vm_user_data = params['VM']['custom_data']
        self.vm_custom_file = None

        self.base_cmd = ["ssh", username+"@"+self.cvmIP]

        super(PrismApi, self).__init__(self.cvmIP, username, password)

    def make_request(self, endpoint, action, data=None):
        functions = {
            'get': self.get,
            'post': self.post,
            'put': self.put,
            'delete': self.delete
        }
        func = functions[action]
        if data:
            json_obj = func(endpoint, data=data)
        else:
            json_obj = func(endpoint)
        if self.r.status_code not in (200, 201) and not \
          (self.r.status_code == 204 and action == "delete"):
            logging.error("%s %s." % (self.r.status_code, self.r.text))
            exit(self.r.status_code)
        return json_obj

    def create_vm(self, ssh_pubkey=None):
        logging.debug("Create VM")
        endpoint = urljoin(self.base_url, "vms")
	# Attach image.
        images = self.list_images()
        vmdisk_uuid = ""
        for image in images['entities']:
            if self.image_name == image['name']:
                vmdisk_uuid = image['vm_disk_id']
        if vmdisk_uuid == "":
            logging.error("Image %s not found." % self.image_name)
            exit(1)
        # Attach ssh keys.
        ssh_key = ''
        ssh_pwauth = '\nchpasswd:\n  list: |\n    %s:%s\n  expire: false\nssh_pwauth: yes' % (
            self.vm_username, self.vm_password)
        if (ssh_pubkey):
            ssh_key = '\nssh_authorized_keys:\n- %s' % ssh_pubkey
            ssh_pwauth = ''
        # Attach user_data.
        user_data = '#cloud-config\ndisable_root: false\nlock_passwd: false%s%s\n' % (
            ssh_pwauth, ssh_key)
        if self.vm_user_data:
            user_data += self.vm_user_data
        # Attach user script.
        user_script=[]
        if self.vm_custom_file:
            user_script = [{'source_path': 'adsf:///{}/{}'.format(self.get_container()['name'], self.vm_custom_file),
                      'destination_path': '/tmp/{}'.format(self.vm_custom_file)}]
        print(user_script)
        # Attach NICs (all).
        network_uuids = []
        for network in self.list_networks_detail()["entities"]:
            network_uuids.append({"network_uuid": network["uuid"]})
        data = {'boot': {
                'disk_address': {
                'device_bus': 'scsi',
                'device_index': 0
                },
                'boot_device_type': 'disk',
                'uefi_boot': False
	        },
            'memory_mb':
            self.memory * 1024,
            'name':
            self.vm_name,
            'num_cores_per_vcpu':
            1,
            'num_vcpus':
            self.cpu,
            'timezone':
            'UTC',
            'vm_customization_config': {
                'datasource_type': 'CONFIG_DRIVE_V2',
                'userdata': user_data,
                'files_to_inject_list': user_script
            },
            'vm_disks': [{
                'is_cdrom': False,
                'is_empty': False,
                'is_scsi_pass_through': True,
                'is_thin_provisioned': False,
                'vm_disk_clone': {
                    'disk_address': {
                        'device_bus': 'scsi',
                        'device_index': 0,
                        'vmdisk_uuid': vmdisk_uuid
                    },
                    'minimum_size': self.disk_size*1024*1024*1024,
                    'storage_container_uuid': self.storage_container_uuid
                }
            },
            {
                "disk_address": {
                    "device_bus": "scsi",
                    "device_index": 1
                },
                "is_cdrom": False,
                "is_empty": True,
                "vm_disk_create": {
                "size": 1*1024*1024*1024,
                "storage_container_uuid": "41797d39-e961-4ab5-adcc-e5c9ab817729"
                }
            }
        ],
            'vm_nics': network_uuids
        }
        return self.make_request(endpoint, 'post', data=data)
       
    def create_vm_ISO_kickstart(self):
        logging.debug("Create VM by ISO kickstart")
        endpoint = urljoin(self.base_url, "vms")
	# Attach image.
        images = self.list_images()
        vmdisk_uuid = []
        for image in images['entities']:
            if self.image_name_iso == image['name']:
                vmdisk_uuid.append(image['vm_disk_id'])
            if self.image_name_kickstart_iso == image['name']:
                vmdisk_uuid.append(image['vm_disk_id'])
        if len(vmdisk_uuid) != 2:
            logging.error("Image not found, image list be got is %s" % str(vmdisk_uuid))
            exit(1)
        # Attach NICs (all).
        network_uuids = []
        for network in self.list_networks_detail()["entities"]:
            network_uuids.append({"network_uuid": network["uuid"]})
        data = {
            'boot': {
                'uefi_boot': False
            },
            'boot_device_type': 'CDROM',
            'memory_mb':
            self.memory * 1024,
            'name':
            self.vm_name,
            'num_cores_per_vcpu':
            1,
            'num_vcpus':
            self.cpu,
            'timezone':
            'UTC',
            'vm_disks': [{
                'is_cdrom': True,
                'is_empty': False,
                'is_scsi_pass_through': True,
                'is_thin_provisioned': False,
                'vm_disk_clone': {
                    'disk_address': {
                        'device_bus': 'ide',
                        'device_index': 0,
                        'vmdisk_uuid': vmdisk_uuid[0]
                    }
                }
            },
            {
                'is_cdrom': True,
                'is_empty': False,
                'is_scsi_pass_through': True,
                'is_thin_provisioned': False,
                'vm_disk_clone': {
                    'disk_address': {
                        'device_bus': 'ide',
                        'device_index': 1,
                        'vmdisk_uuid': vmdisk_uuid[1]
                    },
                }
            },
            {
                'is_cdrom': False,
                'is_empty': True,
                'is_scsi_pass_through': True,
                'is_thin_provisioned': False,
                'vm_disk_create': {
                    'size': self.disk_size*1024*1024*1024,
                    'storage_container_uuid': self.storage_container_uuid
                }
            }],
            'vm_nics': network_uuids
        }
        logging.debug("data is " + str(data))
        return self.make_request(endpoint, 'post', data=data)
        
    def delete_vm(self, vm_uuid):
        logging.debug("Delete VM")
        endpoint = urljoin(self.base_url, "vms/%s" % vm_uuid)
        return self.make_request(endpoint, 'delete')

    def restart_vm(self, vm_uuid):
        logging.debug("Restart VM")
        endpoint = urljoin(self.base_url, "vms/%s/set_power_state" % vm_uuid)
        data = {"transition": "ACPI_REBOOT"}
        return self.make_request(endpoint, 'post', data=data)

    def stop_vm(self, vm_uuid):
        logging.debug("Stop VM")
        endpoint = urljoin(self.base_url, "vms/%s/set_power_state" % vm_uuid)
        data = {"transition": "ACPI_SHUTDOWN"}
        return self.make_request(endpoint, 'post', data=data)

    def start_vm(self, vm_uuid):
        endpoint = urljoin(self.base_url, "vms/%s/set_power_state" % vm_uuid)
        data = {"transition": "ON"}
        return self.make_request(endpoint, 'post', data=data)
        
    def list_vm_detail(self):
        logging.debug("Query details about VM")
        endpoint = urljoin(
            self.base_url,
            "vms/?include_vm_nic_config=True&include_vm_disk_config=True&filter=vm_name==%s"
            % self.vm_name)
        return self.make_request(endpoint, 'get')

    def list_tasks(self, task_uuid):
        logging.debug("Query the execution status of task %s" % task_uuid)
        endpoint = urljoin(self.base_url, "tasks/%s" % task_uuid)
        return self.make_request(endpoint, 'get')

    def list_images(self):
        logging.debug("Getting list of images")
        endpoint = urljoin(self.base_url, "images")
        return self.make_request(endpoint, 'get')

    def list_snapshots(self, vm_uuid):
        logging.debug("Getting list of snapshots")
        endpoint = urljoin(self.base_url, "snapshots/?vm_uuid=%s" % vm_uuid)
        return self.make_request(endpoint, 'get')

    def cvm_cmd(self, command):
        cmd = self.base_cmd
        cmd.append(command)
        return subprocess.check_output(cmd)

    def list_networks_detail(self):
        logging.debug("Query details about netowrks")
        endpoint = urljoin(
            self.base_url,
            "networks/")
        return self.make_request(endpoint, 'get')

    def create_network(self):
        logging.debug("Creating virtual network")
        networks = self.list_networks_detail()
        exst_IPs = []
        for network in networks["entities"]:
            exst_IPs.append(network["ip_config"]["network_address"])
        for dig in range(2, 254):
            if "192.168."+str(dig)+".0" not in exst_IPs:
                new_prefix = "192.168."+str(dig)
                break
        endpoint = urljoin(self.base_url, "networks/")
        data = {
                "vlan_id": dig,
                "name": "nic%s" % str(dig),
                "ip_config": {
                  "default_gateway": "%s.1" % new_prefix,
                  "network_address": "%s.0" % new_prefix,
                  "pool": [{
                  "range": "%s.2 %s.253" % (new_prefix, new_prefix)
                }],
                "prefix_length": 24
               }}
        return self.make_request(endpoint, 'post', data=data)

    def delete_networks(self):
        # We delete all NICs leaving the one in .yaml.
        networks = self.list_networks_detail()
        for network in networks["entities"]:
            if not network["uuid"] == self.network_uuid:
                endpoint = urljoin(self.base_url, "networks/%s" % network["uuid"])
                self.make_request(endpoint, 'delete')

    def attach_disk(self, vm_uuid, device_bus, disk_size, is_cdrom, *is_empty):
        '''
        Attach disk/cdrom, need to indicate clone_from_img_service or clone_from_adsf_file when is_empty equals False
        '''
        logging.info("Prism creating and attaching disk, device_bus:{}, disk_size: {}, is_cdrom: {}, is_empty: {}".format(device_bus, disk_size, is_cdrom, is_empty))
        endpoint = urljoin(self.base_url, "vms/%s/disks/attach" % vm_uuid)
        if is_cdrom:
            is_cdrom = "true"
        else:
            is_cdrom = "false"
        if is_empty[0]:
            data = {"vm_disks": [{"disk_address":{"device_bus":device_bus},
                    "is_cdrom": is_cdrom,
                    "is_empty": "true",
                    "vm_disk_create": {
                         "storage_container_uuid": self.storage_container_uuid,
                         "size": disk_size*1024*1024*1024}
                    }]}
        else:
            if is_empty[1] == 'clone_from_img_service':
                if is_cdrom:
                    images = self.list_images()
                    for image in images['entities']:
                        if self.image_name_kickstart_iso == image['name']:
                            vmdisk_uuid = image['vm_disk_id']
                else:
                    logging.info('OPPS.Clone disk form img_service has not yet support.')
                data = {"vm_disks": [{"disk_address":{"device_bus":device_bus},
                    "is_cdrom": "true",
                    "is_empty": "false",
                    'vm_disk_clone': {
                    'disk_address': {
                        'vmdisk_uuid': vmdisk_uuid
                    },
                    'storage_container_uuid': self.storage_container_uuid
                    }}]}
            else:
                logging.info('OPPS.Clone disk form adsf file path has not yet support.')
        return self.make_request(endpoint, 'post', data=data)

    def detach_disk(self, vm_uuid, device_bus, vmdisk_uuid):
        logging.info("detach disk, vmdisk uuid: {}".format(str(vmdisk_uuid)))
        endpoint = urljoin(self.base_url, "vms/%s/disks/detach" % vm_uuid)
        data = {"uuid": vmdisk_uuid,
                "vm_disks":[{"disk_address":{"device_bus":device_bus,"device_index":2}}]
               }
        return self.make_request(endpoint, 'post', data=data)

    def get_container(self):
        endpoint = urljoin(self.base_url, "storage_containers/%s" % self.storage_container_uuid)
        return self.make_request(endpoint, 'get')
        
    def get_disk(self, disk_uuid):
        endpoint = urljoin(self.base_url, "virtual_disks/%s" % disk_uuid)
        return self.make_request(endpoint, 'get')
        
    def expand_disk(self, disk_uuid, disk_size, device_index):
        # Shrinking disk is not available in Nutanix.
        logging.info("Expanding designated disk. disk_uuid is {}, disk_size is {} and device_index is {}".format(disk_uuid, disk_size, device_index))
        disk = self.get_disk(disk_uuid)
        logging.debug(disk)
        endpoint = urljoin(self.base_url, "vms/%s/disks/update" % disk['attached_vm_uuid'])
        data = {"vm_disks": [{
                    "disk_address": {
                         "vmdisk_uuid": disk_uuid,
                         "device_uuid": disk['uuid'],
                         "device_index": device_index,
                         "device_bus": "scsi"},
                    "flash_mode_enabled": False,
                    "is_cdrom": False,
                    "is_empty": False,
                    "vm_disk_create": {
                         "storage_container_uuid": disk['storage_container_uuid'],
                         "size": disk_size*1024*1024*1024}
                    }]}
        return self.make_request(endpoint, 'put', data=data)

    def take_snapshot(self, vm_uuid, snpst_name):
        endpoint = urljoin(self.base_url, "snapshots/?vm_uuid=%s" % vm_uuid)
        data = {"snapshot_specs": [
                {
                    "snapshot_name": snpst_name,
                    "vm_uuid": vm_uuid
                }
                ]}
        return self.make_request(endpoint, 'post', data=data)

    def restore_vm(self, vm_uuid, snpst_uuid):
        endpoint = urljoin(self.base_url, "vms/%s/restore" % vm_uuid)
        data = { "restore_network_configuration": True,
                 "snapshot_uuid": snpst_uuid
                }
        return self.make_request(endpoint, 'post', data=data)

class NutanixVM(VMResource):
    def __init__(self, params):
        super(NutanixVM, self).__init__(params)
        self._data = None

        # VM parameters
        #self.vm_name = params.get('vm_name', '*/VM/*')
        self.vm_name = params['VM']['vm_name']

        # VM access parameters
        #self.vm_username = params.get('username', '*/VM/*')
        self.vm_username = params['VM']['username']
        #self.vm_password = params.get('password', '*/VM/*')
        self.vm_password = params['VM']['password']
        #self.vm_user_data = params.get('custom_data', '*/VM/*')
        self.vm_user_data = params['VM']['custom_data']
        #self.network_uuid = params.get('network_uuid', '*/VM/*')
        self.network_uuid = params['VM']['network_uuid']
        self.ssh_pubkey = utils_lib.get_public_key()
        self.arch = 'x86_64'
        self.vm_custom_file = None
        self.provider = params['Cloud']['provider']

        self.prism = PrismApi(params)

    @property
    def data(self):
        if not self._data:
            self._data = {}
            for vm in self.prism.list_vm_detail()['entities']:
                if vm["name"] == self.vm_name:
                    self._data = vm
                    break
        return self._data

    @property
    def floating_ip(self):
        f_ip = None
        for nic in self.data.get('vm_nics'):
            if nic['network_uuid'] == self.network_uuid:
                f_ip = nic['ip_address']
        return f_ip

    def wait_for_status(self, task_uuid, timeout, error_message):
        for count in utils_lib.iterate_timeout(timeout, error_message):
            res = self.prism.list_tasks(task_uuid)
            if res['progress_status'] == 'Succeeded':
                break
            if res['progress_status'] == 'Failed':
                logging.error("progress status of task is Failed")
                break

    def create(self, wait=False):
        logging.info("Create VM")
        self.prism.vm_user_data = self.vm_user_data
        self.prism.vm_custom_file = self.vm_custom_file
        res = self.prism.create_vm(self.ssh_pubkey)
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for server to get created.")
        self._data = None
        
    def create_by_ISO_kickstart(self, wait=False):
        logging.info("Create VM by ISO kickstart")
        res = self.prism.create_vm_ISO_kickstart()
        logging.debug("res is " + str(res))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for server to get created.")
        self._data = None

    def delete(self, wait=False):
        logging.info("Delete VM")
        res = self.prism.delete_vm(self.data.get('uuid'))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 30,
                "Timed out waiting for server to get deleted.")

    def start(self, wait=False):
        logging.info("start vm")
        res = self.prism.start_vm(self.data.get('uuid'))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 120,
                "Timed out waiting for server to get started.")
            
            for count in utils_lib.iterate_timeout(
                    120, "Timed out waiting for getting IP address."):
                if self.exists() and self.floating_ip:
                    break

    def stop(self, wait=False):
        logging.info("Stop VM")
        res = self.prism.stop_vm(self.data.get('uuid'))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for server to get stopped.")
            for count in utils_lib.iterate_timeout(
                    30, "Timed out waiting for server to get stopped."):
                if self.is_stopped():
                    break

    def reboot(self, wait=False):
        logging.info("Restart VM")
        res = self.prism.restart_vm(self.data.get('uuid'))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for server to get rebooted.")
            for count in utils_lib.iterate_timeout(
                    120, "Timed out waiting for getting IP address."):
                if self.exists() and self.floating_ip:
                    break

    def exists(self):
        self._data = None
        count = sum(1 for i in self.data)
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self._data = None
        return self.data.get('power_state')

    def is_started(self):
        return self._get_status() == 'on'

    def is_stopped(self):
        return self._get_status() == 'off'

    def show(self):
        return self.data

    def cvm_cmd(self, command):
        return self.prism.cvm_cmd(command)

    def attach_disk(self, device_bus, disk_size, is_cdrom, *is_empty, wait=False):
        '''
        Attach disk/cdrom, device_info args including disksize, is cdrom or not, and is empty or not
        '''
        res = self.prism.attach_disk(self.data.get('uuid'), device_bus, disk_size, is_cdrom, *is_empty)
        time.sleep(30)

        if wait:
            self.wait_for_status(
                res['task_uuid'], 30,
                "Timed out attaching disk.")

    def detach_disk(self, device_bus, vmdisk_uuid, wait=False):
        '''
        Attach disk according to vmdisk_uuid
        '''
        res = self.prism.detach_disk(self.data.get('uuid'), device_bus, vmdisk_uuid)
        if wait:
            self.wait_for_status(
                res['task_uuid'], 30,
                "Timed out attaching disk.")
    
    def attach_block(self, disk, target, wait=True, timeout=120):
        raise NotImplementedError

    def detach_block(self, disk, wait=True, force=False):
        raise NotImplementedError
    
    def detach_nic(self, nic, wait=True, force=False):
        raise NotImplementedError

    def attach_nic(self, nic, wait=True, timeout=120):
        raise NotImplementedError

    def get_console_log(self):
        raise UnSupportedAction('No such operation in nutanix')
    
    def get_state(self):
        raise NotImplementedError

    def is_exist(self):
        raise NotImplementedError

    def is_paused(self):
        raise NotImplementedError
    
    def pause(self, wait=False):
        raise NotImplementedError

    def send_hibernation(self):
        raise UnSupportedAction('No such operation in nutanix')

    def send_nmi(self):
        raise UnSupportedAction('No such operation in nutanix')

    def unpause(self, wait=False):
        raise NotImplementedError

    def disk_count(self):
        raise NotImplementedError

    def get_disk_uuid(self, disk_number=0):
        disk_uuid = self.show()['vm_disk_info'][disk_number]['disk_address']['vmdisk_uuid']
        return disk_uuid

    def take_snapshot(self, snpst_name, wait=False):
        logging.info("take snapshot for VM")
        res = self.prism.take_snapshot(self.data.get('uuid'), snpst_name)
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for taking snapshot.")

    def list_snapshots(self):
        logging.info("list snapshot for VM")
        res = self.prism.list_snapshots(self.data.get('uuid'))
        logging.info("snapshot list for VM is: \n {}".format(res))
        return res

    def restore_vm(self, snpst_uuid, wait=False):
        logging.info("restore vm by specific snapshot: {}".format(snpst_uuid))
        res = self.prism.restore_vm(self.data.get('uuid'), snpst_uuid)
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for restoring VM.")

class NutanixVolume(StorageResource):
    '''
    Volume class
    '''
    def __init__(self, params):
        super(NutanixVolume, self).__init__(params)
        self._data = None
        self.vm = NutanixVM(params)
        self.prism = PrismApi(params)

    def is_free(self):
        raise NotImplementedError
    def create(self):
        raise NotImplementedError

    def delete(self):
        raise NotImplementedError

    def get_state(self):
        raise NotImplementedError
    def is_exist(self):
        if self.vm.show():
            logging.info("Instance disk: {}".format(self.vm.show()['vm_disk_info']))

    def show(self):
        raise NotImplementedError

    def modify_disk_size(self, origin_disk_size, disk_index:('int >= 0'), expand_size:('int > 0'), wait=True):
        disk_uuid = self.vm.get_disk_uuid(disk_index)
        res = self.prism.expand_disk(disk_uuid=disk_uuid, disk_size=origin_disk_size+expand_size, device_index=disk_index)
        self.vm.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for restoring VM.")