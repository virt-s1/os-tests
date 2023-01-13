from .resources import VMResource,StorageResource,NetworkResource,UnSupportedAction,UnSupportedStatus
from os_tests.libs import utils_lib
import logging
import time
import sys
import re
try:
    import boto3
    from botocore.exceptions import ClientError
    from botocore.config import Config
    import botocore.exceptions as boto_err
except ImportError:
    print("Please install boto3 module if run aws test")
    sys.exit(1)

LOG = logging.getLogger('os_tests.os_tests_run')
logging.basicConfig(level=logging.INFO)

class EC2VM(VMResource):
    ec2_instance = None

    def __init__(self, params, vendor="redhat"):
        config = Config(retries=dict(max_attempts=10, ))
        self.profile_name = params.get('profile_name')
        if self.profile_name is None:
            self.profile_name = 'default'
        LOG.info('Load profile_name: {}'.format(self.profile_name))
        self.session = boto3.session.Session(profile_name=self.profile_name, region_name=params.get('region'))
        self.resource = self.session.resource('ec2', config=config)
        self.client = self.session.client('ec2', config=config, region_name=params.get('region'))
        super().__init__(params)
        self.id = None
        self.ipv4 = None
        self.ssh_user = params.get('remote_user')
        if vendor == "amzn2_x86":
            self.ami_id = params.get('amzn2_ami_id_x86')
            self.ssh_user = params.get('amzn2_ssh_user')
        elif vendor == "amzn2_arm":
            self.ami_id = params.get('amzn2_ami_id_arm')
            self.ssh_user = params.get('amzn2_ssh_user')
        elif vendor == "ubuntu_x86":
            self.ami_id = params.get('ubuntu_ami_id_x86')
            self.ssh_user = params.get('ubuntu_ssh_user')
        elif vendor == "ubuntu_arm":
            self.ami_id = params.get('ubuntu_ami_id_arm')
            self.ssh_user = params.get('ubuntu_ssh_user')
        else:
            self.ami_id = params.get('ami_id')
        self.instance_type = params.get('instance_type')
        if params.get('ipv6'):
            self.subnet_id = params.get('subnet_id_ipv6')
            LOG.info('Instance support ipv6, use subnet %s', self.subnet_id)
        else:
            self.subnet_id = params.get('subnet_id_ipv4')
            LOG.info('Instance only support ipv4, use subnet %s',
                     self.subnet_id)
        self.security_group_ids = params.get('security_group_ids')
        self.region = params.get('region')
        self.subnet = self.resource.Subnet(self.subnet_id)
        self.additionalinfo = params.get('additionalinfo')
        if params.get('tagname'):
            self.tag = params.get('tagname')
        else:
            self.tag = 'os_tests_vm_ec2'
        self.ssh_key_name = params.get('ssh_key_name')
        self.ssh_key_path = params.get('ssh_key_path')
        LOG.info("AMI picked vendor:{} ami:{} key:{}".format(vendor, self.ami_id, self.ssh_key_name))
        self.vm_username = self.ssh_user
        self.vm_password = None
        self.ssh_conn = None
        self.volume_id = None
        # load instance spec while cannot retrive it automatically
        self.cpus_cfg = params.get('cpus')
        self.memory_cfg = params.get('memory')
        self.disks_cfg = params.get('disks')
        self.net_bandwidth_cfg = params.get('net_bandwidth')
        self.is_created = False
        self.another_ip = None
        self.run_uuid = params.get('run_uuid')
        self.user_data = '#!/bin/bash\nmkdir -p /tmp/userdata_{}'.format(self.run_uuid)
        self.hibernation_support = False
        # efa_support default set to False, will query instance property next
        self.efa_support = False

    def show(self):
        if self.is_exist():
            LOG.info("Instance ID: {}".format(self.ec2_instance.id))

    def create(self, wait=True, enable_efa=True):
        # enable_efa is option to enable or disable efa when create vms
        # if vm does not support efa, it will be disabled
        self.is_created = False

        try:
            self.efa_support = self.client.describe_instance_types(
                InstanceTypes=[self.instance_type],
            )['InstanceTypes'][0]['NetworkInfo']['EfaSupported']
            LOG.info('efa supported status: {}'.format(self.efa_support))
        except Exception as error:
            LOG.info('Cannot determin efa status, disable in launch')
        try:
            self.hibernation_support = self.client.describe_instance_types(
                InstanceTypes=[self.instance_type],
            )['InstanceTypes'][0]['HibernationSupported']
            LOG.info('Hibernation supported status: {}'.format(self.hibernation_support))
        except Exception as error:
            LOG.info('Cannot determin Hibernation status, disable in launch')
        self.root_device_name = '/dev/sda1'
        try:
            self.root_device_name = self.client.describe_images(ImageIds=[self.ami_id])['Images'][0]['RootDeviceName']
            LOG.info('root device name: {}'.format(self.root_device_name))
        except Exception as error:
            LOG.info('Cannot determin root device name, use default {}'.format(self.root_device_name))

        volume_size = 10
        vm_kwargs = {
            'BlockDeviceMappings':[
                {
                    'DeviceName': self.root_device_name,
                    'Ebs': {
                        'DeleteOnTermination': True,
                        'VolumeSize': volume_size,
                        # root disk must be encrypted when hibernation enabled
                        'Encrypted': self.hibernation_support
                    },
                },
            ],
            "ImageId":self.ami_id,
            "InstanceType":self.instance_type,
            "KeyName":self.ssh_key_name,
            "MaxCount":1,
            "MinCount":1,
            "NetworkInterfaces":[
                {
                    'AssociatePublicIpAddress': True,
                    'DeleteOnTermination': True,
                    'DeviceIndex': 0,
                    'SubnetId': self.subnet_id,
                    'Groups': [
                         self.security_group_ids,
                     ],
                },
            ],
            "TagSpecifications":[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': self.tag
                        },
                    ]
                },
            ],
            'HibernationOptions':{
                'Configured': self.hibernation_support
            },
            'MetadataOptions':{
                'InstanceMetadataTags': 'enabled'
            },
            "UserData":self.user_data
        }
        if self.efa_support:
            if enable_efa:
                vm_kwargs["NetworkInterfaces"][0]["InterfaceType"] = 'efa'
            else:
                LOG.info("efa is supported, but disable it as request")
        #vm_kwargs["EnclaveOptions"]["Enabled"] = True       
        if not self.additionalinfo:
            for volume_size in [10,20,40,50]:
                LOG.info("Create instance {}".format(vm_kwargs))
                try:
                    self.ec2_instance = self.resource.create_instances(**vm_kwargs)[0]
                    self.is_created = True
                    break
                except Exception as err:
                    LOG.error("Failed to create instance with error:{}".format(err))
                    if 'UnsupportedHibernationConfiguration' in str(err):
                        vm_kwargs["BlockDeviceMappings"][0]['Ebs']['VolumeSize'] = volume_size
                        LOG.info("Increase disk size {}".format(volume_size))
                        if volume_size == 40:
                            LOG.info("try to launch with hibernation disabled")
                            self.hibernation_support = False
                            vm_kwargs["HibernationOptions"]['Configured'] = self.hibernation_support
                        continue
        if self.additionalinfo:
            for additionalinfo in self.additionalinfo.split(';'):
                LOG.info("try addtionalinfo:{}".format(additionalinfo))
                vm_kwargs['AdditionalInfo'] = additionalinfo
                for volume_size in [10,20,40,50]:
                    LOG.info("Create instance {}".format(vm_kwargs))
                    try:
                        self.ec2_instance = self.resource.create_instances(**vm_kwargs)[0]
                        self.is_created = True
                        break
                    except Exception as err:
                        LOG.error("Failed to create instance with error:{}".format(err))
                        if 'UnsupportedHibernationConfiguration' in str(err):
                            vm_kwargs["BlockDeviceMappings"][0]['Ebs']['VolumeSize'] = volume_size
                            LOG.info("Increase disk size {}".format(volume_size))
                            if volume_size == 40:
                                LOG.info("try to launch with hibernation disabled")
                                self.hibernation_support = False
                                vm_kwargs["HibernationOptions"]['Configured'] = self.hibernation_support
                            continue
                if self.is_created:
                    break
        if not self.is_created:
            raise Exception("Cannot create instance")
        if wait:
            try:
                self.ec2_instance.wait_until_running()
                self.ec2_instance.reload()
            except Exception as err:
                LOG.error("Failed to wait instance running! %s" % err)

        self.id = self.ec2_instance.id
        self.show()
        # self.ipv4 = self.ec2_instance.public_ip_address
        self.floating_ip
        #self.boot_volume_id

    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def floating_ip(self):
        self.ec2_instance.reload()
        self.ipv4 = self.ec2_instance.public_dns_name
        if self.ipv4 is None or self.ipv4 == '':
            LOG.info("No public ip available! Try to reload it!")
            return None
        LOG.info("Public ip is: %s" % self.ipv4)
        return self.ipv4

    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def private_ip(self):
        self.ec2_instance.reload()
        LOG.info("private_ip_address is: {}".format(self.ec2_instance.private_ip_address))
        return self.ec2_instance.private_ip_address

    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def vm_name(self):
        self.ec2_instance.reload()
        LOG.info("private_dns_name is: {}".format(self.ec2_instance.private_dns_name))
        return self.ec2_instance.private_dns_name


    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def ipv6_address(self):
        self.ec2_instance.reload()
        ipv6_address = self.ec2_instance.ipv6_address
        LOG.info("ipv6_address is: %s" % ipv6_address)
        return ipv6_address

    @property
    def disk_count(self):
        if self.disks_cfg:
            LOG.info("Setting in cfg {}".format(self.disks_cfg))
            return self.disks_cfg
        default_disks = 1
        instance_types_dict = self.client.describe_instance_types(InstanceTypes=[self.instance_type])
        instance_types = instance_types_dict.get('InstanceTypes')
        if not instance_types:
            LOG.info("Cannot get instance type info, return {}".format(default_disks))
            return default_disks
        for instance_type in instance_types:
            if instance_type['InstanceStorageSupported']:
                default_disks = instance_type["InstanceStorageInfo"]["Disks"][0]["Count"] + 1
        LOG.info("{} has {} disks".format(self.instance_type, default_disks))
        return default_disks

    @property
    def net_bandwidth(self):
        if self.net_bandwidth_cfg:
            LOG.info("Setting in cfg {}".format(self.net_bandwidth_cfg))
            return self.net_bandwidth_cfg
        default_bandwidth = 5
        instance_types_dict = self.client.describe_instance_types(InstanceTypes=[self.instance_type])
        instance_types = instance_types_dict.get('InstanceTypes')
        if not instance_types:
            LOG.info("Cannot get instance type info, return default bandwidth {}".format(default_bandwidth))
            return default_bandwidth
        for instance_type in instance_types:
            if instance_type.get('NetworkInfo'):
                net_bandwidth = instance_type["NetworkInfo"]["NetworkPerformance"]
        if 'Gigabit' in net_bandwidth:
            net_bandwidth = re.findall('[\d]+', net_bandwidth)[0]
        else:
            LOG.info("{} net setting spec {}, ret {}".format(self.instance_type, net_bandwidth, default_bandwidth))
            return default_bandwidth
        LOG.info("{} net setting spec {}".format(self.instance_type, net_bandwidth))
        return int(net_bandwidth)

    @property
    def is_secure_boot(self):
        return False

    @property
    def is_uefi_boot(self):
        self.ec2_instance.reload()
        try:
            bootmode = self.client.describe_instances(
                InstanceIds=[
                    self.ec2_instance.id,
                ])['Reservations'][0]['Instances'][0].get("BootMode")
            LOG.info('boot mode: {}'.format(bootmode))
            if bootmode and 'uefi' in bootmode:
                return True
            else:
                return False
        except Exception as error:
            LOG.info('Cannot determin boot mode, return False')
        return False

    @property
    def is_metal(self):
        """
        return if vm is metal or not
        """
        return 'metal' in self.instance_type

    def start(self, wait=True):
        start_ok = False
        if self.additionalinfo != None and self.additionalinfo != '':
            for additionalinfo in self.additionalinfo.split(';'):
                try:
                    LOG.info("Start instance using AdditionalInfo: {}".format(additionalinfo))
                    self.ec2_instance.start(AdditionalInfo=additionalinfo)
                    start_ok = True
                    break
                except Exception as err:
                    LOG.error("Failed to start instance, try another AdditionalInfo: {}".format(err))
        if not start_ok:
            try:
                self.ec2_instance.start()
            except Exception as err:
                LOG.error(err)
                return False

        if wait:
            self.ec2_instance.wait_until_running()
            if self.ec2_instance.state['Name'] == 'running':
                LOG.info("Instance is in running state!")
            else:
                LOG.error(
                    "Instance is not in running state! It is in %s state!" %
                    self.ec2_instance.state['Name'])
                return False
            self.ec2_instance.reload()
            self.floating_ip
        return True

    def stop(self, wait=True, loops=4, hibernate=False):
        try:
            LOG.info("Stopping instance {} with hibernation {}".format(self.id, hibernate))
            self.ec2_instance.stop(Hibernate=hibernate)
        except Exception as err:
            LOG.error("%s" % err)
            return False

        if wait:
            for i in range(0, loops):
                LOG.info("Wait loop %s, max loop %s" % (i, loops))
                try:
                    self.ec2_instance.wait_until_stopped()
                    return 'stopped' in self.get_state()
                except boto_err.WaiterError as err:
                    LOG.error("%s" % err)
            return 'stopped' in self.get_state()
        return True

    def reboot(self, wait=False):
        '''
        Reboot from outside
        '''
        LOG.info("Rebooting instance: %s" % self.id)
        try:
            self.ec2_instance.reboot()
            if 'metal' in self.instance_type:
                time.sleep(120)
            else:
                time.sleep(5)
            return True
        except Exception as err:
            LOG.error(err)
            return False

    def delete(self, wait=True, loops=4):
        try:
            LOG.info("Deleting instance: %s" % self.ec2_instance.id)
            self.ec2_instance.terminate()
        except Exception as err:
            LOG.info(err)
            return False
        if wait:
            for i in range(0, loops):
                LOG.info("Wait loop %s, max loop %s" % (i, loops))
                try:
                    self.ec2_instance.wait_until_terminated()
                    return 'terminated' in self.get_state()
                except boto_err.WaiterError as err:
                    LOG.error(err)
            return 'terminated' in self.get_state()
        return True

    def pause(self, wait=False):
        raise UnSupportedAction('No such operation in ec2')

    def unpause(self, wait=False):
        raise UnSupportedAction('No such operation in ec2')

    def send_nmi(self):
        try:
            LOG.info("Send diagnostic interrupt to %s" %
                     (self.ec2_instance.id))
            self.client.send_diagnostic_interrupt(
                InstanceId=self.ec2_instance.id, DryRun=False)
            return True
        except ClientError as err:
            LOG.error("Failed to send_diagnostic_interrupt to {}:{}".format(self.ec2_instance.id, err))
            if 'UnsupportedOperation' not in str(err):
                return False
        raise UnSupportedAction('This instance does not support send nmi')

    def send_hibernation(self):
        if not self.hibernation_support:
            LOG.info("this instance not support hibernation")
            return False
        return self.stop(hibernate=True)

    def get_console_log(self, silient=False):
        ret = None
        try:
            LOG.info("try to retrive console log......")
            ret = self.ec2_instance.console_output(Latest=True).get('Output')
            if not silient: LOG.info(ret)
            return ret
        except Exception as err:
            LOG.error("Failed to get console log, try without latest option! {}".format(err))
        try:
            ret = self.ec2_instance.console_output().get('Output')
            if not silient: LOG.info(ret)
            return ret
        except Exception as err:
            LOG.error("Failed to get console log! %s" % err)
            if not silient: LOG.info(err)
            return err

    def get_state(self):
        try:
            state = 'unknown'
            self.ec2_instance.reload()
            state = self.ec2_instance.state['Name']
            LOG.info("instance is in {}".format(state))
        except Exception as err:
            return state
        return state

    def is_exist(self):
        try:
            self.ec2_instance.reload()
            return True
        except Exception as exc:
            return False

    def exists(self):
        return self.is_exist()

    def is_stopped(self):
        if self.get_state() == 'stopped':
            return True
        else:
            return False

    def is_started(self):
        if self.get_state() == 'running':
            return True
        else:
            return False

    def is_paused(self):
        raise UnSupportedStatus("No such state in ec2")

    def attach_block(self, disk, target, wait=True, timeout=120):
        try:
            LOG.info("try to attach {} to {}".format(disk.id, self.id))
            self.ec2_instance.attach_volume(
            Device=target,
            VolumeId=disk.id,
            DryRun=False
            )
        except Exception as err:
            LOG.error(err)
            return False
        return True

    def detach_block(self, disk, wait=True, force=False):
        try:
            LOG.info("try to detach {} from {}".format(disk.id, self.id))
            self.ec2_instance.detach_volume(
                #Device='string',
                Force=force,
                VolumeId=disk.id,
                DryRun=False
            )
        except Exception as err:
            LOG.error(err)
            return False
        return True

    def attach_nic(self,nic,device_index=1, wait=True):
        return nic.attach_to_instance(self.id, device_index, wait=wait)

    def detach_nic(self,nic,force=False):
        return nic.detach_from_instance(self.id, wait=True, force=force)

    @property
    def primary_nic_id(self):
        for nic in self.ec2_instance.network_interfaces_attribute:
            if nic['Attachment']['DeviceIndex'] == 0:
                return nic['NetworkInterfaceId']
        LOG.info("primary nic id not found")
        return None

    def assign_new_ip(self):
        nic = self.resource.NetworkInterface(self.primary_nic_id)
        ret = nic.assign_private_ip_addresses(
                AllowReassignment=True,
                SecondaryPrivateIpAddressCount=1
            )
        self.another_ip = ret['AssignedPrivateIpAddresses'][0]['PrivateIpAddress']
        LOG.info("second nic ip{}".format(self.another_ip))
        return self.another_ip
    
    def remove_added_ip(self):
        nic = self.resource.NetworkInterface(self.primary_nic_id)
        if self.another_ip is None:
            LOG.info("second nic ip is {}".format(self.another_ip))
            return False
        try:
            ret = nic.unassign_private_ip_addresses(
                    PrivateIpAddresses=[
                        self.another_ip,
                    ]
                )
            LOG.info("removed second nic ip{}".format(self.another_ip))
            return True
        except Exception as err:
            LOG.info(err)
        return False

class EC2Volume(StorageResource):
    '''
    Volume class
    '''
    volume = None

    def __init__(self, params):
        super(EC2Volume, self).__init__(params)
        config = Config(retries=dict(max_attempts=10, ))
        self.profile_name = params.get('profile_name')
        if self.profile_name is None:
            self.profile_name = 'default'
        LOG.info('Load profile_name: {}'.format(self.profile_name))
        self.session = boto3.session.Session(profile_name=self.profile_name, region_name=params.get('region'))
        self.resource = self.session.resource('ec2', config=config, region_name=params.get('region'))
        self.disksize = 100
        if params.get('ipv6'):
            self.subnet_id = params.get('subnet_id_ipv6')
            LOG.info('Instance support ipv6, use subnet %s', self.subnet_id)
        else:
            self.subnet_id = params.get('subnet_id_ipv4')
            LOG.info('Instance only support ipv4, use subnet %s',
                     self.subnet_id)
        self.subnet = self.resource.Subnet(self.subnet_id)
        self.zone = self.subnet.availability_zone
        LOG.info('Get zone from subnet {}'.format(self.zone))
        if params.get('tagname'):
            self.tag = params.get('tagname')
        else:
            self.tag = 'os_tests_storage_ec2'
        self.outpostarn = params.get('outpostarn')
        self.type = 'standard'
        self.iops = None
        self.id = None
        self.iops = 3000
        self.size = 100

    def is_free(self):
        self.volume.reload()
        if self.volume.state == 'in-use':
            LOG.info("%s disk is in use.", self.volume.id)
            return False
        return True

    def create(self, wait=True):
        """
        Create volume
        :param wait: Wait for instance created
        :param size: disk size required, byt default it is 100GiBs
        :param type: options 'standard'|'io1'|'gp2'|'sc1'|'st1'
        :param iops: must for io1 type volume, range 100~20000
        :return: True|False
        """
        try:
            # sc1 type disk size minimal 500 GiB
            if self.type == 'sc1' and self.size < 500:
                self.size = 500
                LOG.info("{} minimal size is 500G, create 500G disk instead.".format(self.type))
            disk_kwargs = {
                "AvailabilityZone":self.zone,
                "Size":self.size,
                "VolumeType":self.type,
                "Iops":self.iops,
                "TagSpecifications":[
                    {
                        'ResourceType': 'volume',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': self.tag
                            },
                        ]
                    },
                ]
            }
            if self.type != 'io1':
                disk_kwargs.pop('Iops')
            if self.outpostarn:
                disk_kwargs['OutpostArn'] = self.outpostarn
            LOG.info(disk_kwargs)
            self.volume = self.snapshot = self.resource.create_volume(**disk_kwargs)
            self.volume.reload()
            self.id = self.volume.id
            timeout = 120
            interval = 5
            time_start = int(time.time())
            while True:
                try:
                    self.volume.reload()
                    if self.volume.state == 'available':
                        break
                    time.sleep(10)
                except ClientError as err:
                    LOG.error("%s" % err)
                time_end = int(time.time())
                if time_end - time_start > timeout:
                   LOG.info('timeout ended: {}'.format(timeout))
                   break
                LOG.info('retry after {}s'.format(interval))
                time.sleep(interval)
            LOG.info("Volume created %s, state %s" % (self.id, self.volume.state))
            return True

        except Exception as err:
            LOG.error(err)
            return False

    def delete(self, wait=True):
        """
        Delete volume
        :param wait: Wait for volume deleted
        :return: True|False  and raise Exception if volume delete failed
        """
        if self.volume is not None:
            LOG.info("Delete %s" % self.id)
            try:
                self.volume.delete()
                return True
            except Exception as err:
                LOG.error(err)
                return False
        else:
            LOG.info("No specify volume delete.")

    def get_state(self):
        try:
            state = 'unknown'
            self.volume.reload()
            state = self.volume.state
            LOG.info("disk state: {}".format(state))
        except Exception as err:
            return state
        return state

    def show(self):
        if self.is_exist():
            LOG.info("Disk ID: {}".format(self.volume.id))

    def is_exist(self):
        """
        Judge if volume exists
        :return: True if exists.
        Example:
        return True if self._get_status() != -1 else False
        """
        try:
            self.volume.reload()
            if self.volume.state in "deleting | deleted":
                LOG.info("Volume is deleted %s" % self.id)
                return False
            else:
                LOG.info("Volume exists %s" % self.id)
                return True
        except Exception as err:
            LOG.info("Volume does not exists %s" % self.id)
            return False

    def modify_disk_size(self, os_disk_size, expand_num):
        raise NotImplementedError

class EC2NIC(NetworkResource):
    '''
    AWS Network class
    '''
    __network_interface = None
    EC2_CLIENT = boto3.client('ec2')

    def __init__(self, params):
        super(EC2NIC, self).__init__(params)
        self.profile_name = params.get('profile_name')
        if self.profile_name is None:
            self.profile_name = 'default'
        self.session = boto3.session.Session(profile_name=self.profile_name, region_name=params.get('region'))
        self.__ec2 = self.session.resource('ec2', region_name=params.get('region'))
        self._resource = self.session.resource('ec2', region_name=params.get('region'))
        if params.get('ipv6'):
            self.subnet_id = params.get('subnet_id_ipv6')
            LOG.info('Instance support ipv6, use subnet %s', self.subnet_id)
        else:
            self.subnet_id = params.get('subnet_id_ipv4')
            LOG.info('Instance only support ipv4, use subnet %s',
                     self.subnet_id)
        self.subnet = self.__ec2.Subnet(self.subnet_id)

        self.zone = self.subnet.availability_zone
        LOG.info("Get zone from current instance's subnet {}".format(self.zone))
        if params.get('tagname'):
            self.tag = params.get('tagname')
        else:
            self.tag = 'os_tests_network_ec2'
        self.outpostarn = params.get('outpostarn')
        self.id = None
        self.security_group_ids = params.get('security_group_ids')

    def show(self):
        """
        Show instance properties
        Must show after VM properties are changed
        """
        if self.is_exist():
            LOG.info("NIC ID: {}".format(self.__network_interface.id))

    def reuse_init(self, network_interface_id):
        '''
        To reuse an exist network interface than create a new one
        :params network-intserface_id: id of existing network_interface
        '''
        if network_interface_id is None:
            return False
        try:
            self.__network_interface = self.__ec2.NetworkInterface(
                network_interface_id)
            if self.is_attached():
                return False
            LOG.info(
                "Existing %s state is %s" %
                (self.__network_interface.id, self.__network_interface.status))
            return True
        except ClientError as err:
            LOG.error(err)
            return False

    def is_free(self):
        self.__network_interface.reload()
        if self.__network_interface.status == 'in-use':
            LOG.info("%s network interface is in use.",
                     self.__network_interface.id)
            return True
        return False

    def get_state(self):
        try:
            state = 'unknown'
            self.__network_interface.reload()
            state = self.__network_interface.status
            LOG.info("nic state: {}".format(state))
        except Exception as err:
            return state
        return state

    def is_exist(self):
        """
        Judge if nic exists
        :return: True if exists.
        Example:
        return True if self._get_status() != -1 else False
        """
        try:
            self.__network_interface.reload()
            if self.__network_interface.status in "deleting | deleted":
                LOG.info("nic is deleted %s" % self.id)
                return False
            else:
                LOG.info("nic exists %s" % self.id)
                return True
        except Exception as err:
            LOG.info("nic does not exists %s" % self.id)
            return False

    def add_tag(self):
        try:
            self.__network_interface.reload()
            self.__network_interface.create_tags(Tags=[
                {
                    'Key': 'Name',
                    'Value': self.tag
                },
            ])
        except Exception as err:
            LOG.info("Failed to add tag to %s", self.__network_interface.id)
            LOG.error(err)

    def create(self,interfaceType='interface'):
        '''Create a new network interface
        '''
        try:
            if interfaceType == 'efa':
                self.__network_interface = self.subnet.create_network_interface(
                    Description=self.tag,
                    InterfaceType='efa',
                    SubnetId=self.subnet_id,
                    Groups=[self.security_group_ids, ])
                LOG.info("%s efa network interface created!" %
                         self.__network_interface.id)
                self.add_tag()
                self.id = self.__network_interface.id
                return self.__network_interface
            else:
                self.__network_interface = self.subnet.create_network_interface(
                    Description=self.tag, Groups=[
                        self.security_group_ids,
                    ])
                LOG.info("%s network interface created!" %
                         self.__network_interface.id)
                self.add_tag()
                self.id = self.__network_interface.id
                return True
        except Exception as err:
            LOG.info("Failed to create interface")
            LOG.error(err)
            return False

    def delete(self, wait=True):
        '''
        Delete network interface
        :param wait: Wait for interface deleted
        :return: True|False  and raise Exception if interface delete failed
        '''

        if self.__network_interface is not None:
            LOG.info("Delete {}".format(self.id))
            try:
                self.__network_interface.delete()
                return True
            except Exception as err:
                LOG.error(err)
                return False
        else:
            LOG.info("No specify network interface delete.")

    def attach_to_instance(self, instance_id, device_index, wait=True):
        """
        Attach nic to instance as $device_index
        :param instance_id: id of instance
        :param device_index: [0..9]
        :return: True if success, False as failed
        """
        try:
            LOG.info("Try to attach %s to %s" %
                     (self.__network_interface.id, instance_id))
            self.__network_interface.attach(
                DeviceIndex=device_index,
                InstanceId=instance_id,
            )

            if wait:
                start_time = time.time()
                while True:
                    self.__network_interface.reload()
                    if self.__network_interface.status == 'in-use':
                        LOG.info('NIC attached!')
                        return True
                    else:
                        end_time = time.time()
                        if int(end_time) - int(start_time) > 80:
                            LOG.error(
                                "Failed to attach to instance after 80s! %s" %
                                self.__network_interface.status)
                            return False
                    time.sleep(10)

            return True
        except Exception as err:
            LOG.error("NIC cannot attach to %s error %s" % (instance_id, err))
            return False

    def detach_from_instance(self, instance_id, wait=True, force=False):
        """Detach nic from instance as $device_name

        Arguments:
            instance_id {string} -- instance id
            device_name {string} -- target device name from instance,
                                    like 'sdX','xvdx'

        Keyword Arguments:
            wait {bool} -- wait or not wait detach operation complete
                           (default: {True})
            force {bool} -- force or not force detach from instance
                            (default: {False})

        Returns:
            bool -- True if success, False as failed
        """
        try:
            LOG.info("Try to detach %s from %s" %
                     (self.__network_interface.id, instance_id))
            self.__network_interface.reload()
            self.__network_interface.detach(Force=force)
            if wait:
                start_time = time.time()
                while True:
                    self.__network_interface.reload()
                    if self.__network_interface.status == 'available':
                        LOG.info('NIC detached!')
                        return True
                    else:
                        end_time = time.time()
                        if int(end_time) - int(start_time) > 80:
                            LOG.error(
                                "Failed to detach from instance after 80s! %s" %
                                self.__network_interface.status)
                            return False
                    time.sleep(10)
            return True
        except Exception as err:
            LOG.error("NIC cannot detach from %s error %s" %
                      (instance_id, err))
            return False

    def allocate_eip(self):
        try:
            return self.EC2_CLIENT.allocate_address(Domain='vpc', TagSpecifications=[
                {'ResourceType': 'elastic-ip', 'Tags': [{'Key': 'Name', 'Value': 'efa-elastic-ip'}, ]}, ])
        except Exception as err:
            LOG.info("Failed to allocate elastic ip")
            LOG.error(err)

    def associate_eip(self,instance_id):
        try:
            response = self.EC2_CLIENT.describe_addresses(Filters=[{'Name': 'tag:Name', 'Values': ['efa-elastic-ip']}])
            public_ip = response['Addresses'][0]['PublicIp']
            allocation_id = response['Addresses'][0]['AllocationId']
            self.EC2_CLIENT.associate_address(InstanceId=instance_id, AllocationId=allocation_id)
            LOG.info(f'EIP {public_ip} associated with the instance {instance_id}')
            return True
        except Exception as err:
            LOG.info("Failed to associate elastic ip to the instance")
            LOG.error(err)
            return False

    def release_eip(self):
        try:
            response = self.EC2_CLIENT.describe_addresses(
                Filters=[{'Name': 'tag:Name', 'Values': ['efa-elastic-ip']}])
            public_ip = response['Addresses'][0]['PublicIp']
            allocation_id = response['Addresses'][0]['AllocationId']
            self.EC2_CLIENT.release_address(AllocationId=allocation_id)
            LOG.info(f'EIP {public_ip} has been released')
        except Exception as err:
            LOG.info("Failed to release Elastic IP")
            LOG.error(err)
