from .resources import VMResource,StorageResource
from os_tests.libs import utils_lib
import logging
import time
import sys
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
        super(EC2VM, self).__init__(params)
        self.instance_id = None
        self.ipv4 = None
        self.ssh_user = params.get('ssh_user')
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
        self.is_created = False
        self.another_ip = None

    def show(self):
        if self.is_exist():
            LOG.info("Instance ID: {}".format(self.ec2_instance.id))

    def create(self, wait=True):
        self.is_created = False
        if self.additionalinfo == None or self.additionalinfo == '':
            try:
                self.ec2_instance = self.resource.create_instances(
                    ImageId=self.ami_id,
                    InstanceType=self.instance_type,
                    KeyName=self.ssh_key_name,
                    MaxCount=1,
                    MinCount=1,
                    NetworkInterfaces=[
                        {
                            'AssociatePublicIpAddress': True,
                            'DeviceIndex': 0,
                            'SubnetId': self.subnet_id,
                            'Groups': [
                                 self.security_group_ids,
                             ],
                        },
                    ],
                    TagSpecifications=[
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
                    UserData='#!/bin/bash\nmkdir /home/%s/instance_create_%s' %
                    (self.ssh_user, self.instance_type))[0]
                self.is_created = True
            except ClientError as err:
                LOG.error("Failed to create instance!")
                self.is_createable = False
                raise err
            except Exception as err:
                raise err
        if self.additionalinfo != None and self.additionalinfo != '':
            for additionalinfo in self.additionalinfo.split(';'):
                try:
                    LOG.error("Create instance using addtionalinfo: {}".format(additionalinfo))
                    self.ec2_instance = self.resource.create_instances(
                        ImageId=self.ami_id,
                        InstanceType=self.instance_type,
                        KeyName=self.ssh_key_name,
                        MaxCount=1,
                        MinCount=1,
                        AdditionalInfo=additionalinfo,
                        NetworkInterfaces=[
                            {
                                'AssociatePublicIpAddress': True,
                                'DeviceIndex': 0,
                                'SubnetId': self.subnet_id,
                                'Groups': [
                                     self.security_group_ids,
                                 ],
                            },
                        ],
                        TagSpecifications=[
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
                        UserData='#!/bin/bash\nmkdir /home/%s/instance_create_%s' %
                        (self.ssh_user, self.instance_type))[0]
                    self.is_created = True
                except ClientError as err:
                    LOG.error("Failed to create instance, try another addtionalinfo {}".format(err))
                except Exception as err:
                    LOG.error("Failed to create instance, try another addtionalinfo {}".format(err))
                if self.is_created:
                    break
            if not self.is_created:
                raise 'Cannot create'
        if wait:
            try:
                self.ec2_instance.wait_until_running()
                self.ec2_instance.reload()
            except Exception as err:
                LOG.error("Failed to wait instance running! %s" % err)

        self.instance_id = self.ec2_instance.id
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

    def start(self, wait=True):
        start_ok = False
        if self.additionalinfo != None and self.additionalinfo != '':
            for additionalinfo in self.additionalinfo.split(';'):
                try:
                    LOG.info("Start instance using addtionalinfo: {}".format(additionalinfo))
                    self.ec2_instance.start(AdditionalInfo=additionalinfo)
                    start_ok = True
                    break
                except Exception as err:
                    LOG.error("Failed to start instance, try another addtionalinfo {}".format(err))
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

    def stop(self, wait=True, loops=4):
        try:
            LOG.info("Stopping instance %s " % self.instance_id)
            self.ec2_instance.stop()
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
        LOG.info("Rebooting instance: %s" % self.instance_id)
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

    def send_nmi(self):
        try:
            LOG.info("Send diagnostic interrupt to %s" %
                     (self.ec2_instance.id))
            self.client.send_diagnostic_interrupt(
                InstanceId=self.ec2_instance.id, DryRun=False)
            return True
        except ClientError as err:
            LOG.error("Failed to send_diagnostic_interrupt to %s" %
                      self.ec2_instance.id)
            return False

    def send_hibernation(self):
        LOG.info("Wow, will add support later!")
        return False

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
            state = 'unknow'
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

class EC2Volume(StorageResource):
    '''
    Volume classs
    '''
    __volume = None

    def __init__(self, params):
        config = Config(retries=dict(max_attempts=10, ))
        super(EC2Volume, self).__init__(params)
        self.profile_name = params.get('profile_name')
        if self.profile_name is None:
            self.profile_name = 'default'
        self.session = boto3.session.Session(profile_name=self.profile_name, region_name=params.get('region'))
        self._resource = self.session.resource('ec2', config=config, region_name=params.get('region'))
        self.disksize = 100
        if params.get('ipv6'):
            self.subnet_id = params.get('subnet_id_ipv6')
            LOG.info('Instance support ipv6, use subnet %s', self.subnet_id)
        else:
            self.subnet_id = params.get('subnet_id_ipv4')
            LOG.info('Instance only support ipv4, use subnet %s',
                     self.subnet_id)
        self.subnet = self._resource.Subnet(self.subnet_id)

        #self.zone = params.get('availability_zone', '*/Cloud/*')
        self.zone = self.subnet.availability_zone
        LOG.info('Get zone from subnet {}'.format(self.zone))
        #self.zone = params.get('availability_zone', '*/Cloud/*')
        self.tagname = params.get('ec2_tagname')
        self.outpostarn = params.get('outpostarn')
        self.disktype = 'standard'
        self.id = None
        self.iops = 3000

    def reuse_init(self, volume_id):
        '''
        To reuse an exist volume than create a new one
        :params volume_id: id of existing volume
        '''
        if volume_id is None:
            return False
        try:
            self.__volume = self._resource.Volume(volume_id)
            if self.is_attached():
                return False
            LOG.info("Existing %s state is %s" %
                     (self.__volume.id, self.__volume.state))
            return True
        except ClientError as err:
            LOG.error(err)
            return False

    def is_attached(self):
        self.__volume.reload()
        if self.__volume.state == 'in-use':
            LOG.info("%s disk is in use.", self.__volume.id)
            return True
        return False

    def create(self, wait=True, disksize=100, disktype='standard', iops=3000, loops=5):
        """
        Create volume
        :param wait: Wait for instance created
        :param disksize: disk size required, byt default it is 100GiBs
        :param disktype: options 'standard'|'io1'|'gp2'|'sc1'|'st1'
        :param iops: must for io1 type volume, range 100~20000
        :return: True|False
        """
        try:
            self.disksize = disksize
            self.disktype = disktype
            # sc1 type disk size minimal 500 GiB
            if self.disktype == 'sc1' and self.disksize < 500:
                self.disksize = 500
                LOG.info("sc1 type disk size minimal 500G, so will create \
500G disk!")
            self.iops = iops
            if self.outpostarn is None:
                if self.disktype == 'io1':
                    self.__volume = self.__snapshot = self._resource.create_volume(
                        AvailabilityZone=self.zone,
                        Size=self.disksize,
                        VolumeType=self.disktype,
                        Iops=self.iops,
                        TagSpecifications=[
                            {
                                'ResourceType': 'volume',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ])
                else:
                    self.__volume = self.__snapshot = self._resource.create_volume(
                        AvailabilityZone=self.zone,
                        Size=self.disksize,
                        VolumeType=self.disktype,
                        TagSpecifications=[
                            {
                                'ResourceType': 'volume',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ])
            else:
                if self.disktype == 'io1':
                    self.__volume = self.__snapshot = self._resource.create_volume(
                        AvailabilityZone=self.zone,
                        Size=self.disksize,
                        VolumeType=self.disktype,
                        Iops=self.iops,
                        OutpostArn=self.outpostarn,
                        TagSpecifications=[
                            {
                                'ResourceType': 'volume',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ])
                else:
                    self.__volume = self.__snapshot = self._resource.create_volume(
                        AvailabilityZone=self.zone,
                        Size=self.disksize,
                        VolumeType=self.disktype,
                        OutpostArn=self.outpostarn,
                        TagSpecifications=[
                            {
                                'ResourceType': 'volume',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ])
            self.id = self.__volume.id
            if wait:
                for i in xrange(0, loops):
                    LOG.info("Wait loop %s, max loop %s" % (i, loops))
                    try:
                        self.__volume.reload()
                        if self.__volume.state == 'available':
                            break
                        time.sleep(10)
                    except ClientError as err:
                        LOG.error("%s" % err)
            LOG.info("Volume created %s, state %s" % (self.id, self.__volume.state))
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
        if self.__volume is not None:
            LOG.info("Delete %s" % self.res_id)
            try:
                self.__volume.delete()
                return True
            except Exception as err:
                LOG.error(err)
                return False
        else:
            LOG.info("No specify volume delete.")

    def exists(self):
        """
        Judge if volume exists
        :return: True if exists.
        Example:
        return True if self._get_status() != -1 else False
        """
        try:
            self.__volume.reload()
            if self.__volume.state in "deleting | deleted":
                LOG.info("Volume is deleted %s" % self.id)
                return False
            else:
                LOG.info("Volume exists %s" % self.id)
                return True
        except Exception as err:
            LOG.info("Volume does not exists %s" % self.id)
            return False

    def attach_to_instance(self, instance_id, device_name, wait=True, timeout=120):
        """
        Attach disk to instance as $device_name
        :param instance_id: id of instance
        :param device_name: like sdX or xvdX
        :return: True if success, False as failed
        """
        try:
            LOG.info("Try to attach %s to %s" %
                     (self.__volume.id, instance_id))
            self.__volume.attach_to_instance(
                Device=device_name,
                InstanceId=instance_id,
            )

            if wait:
                start_time = time.time()
                while True:
                    self.__volume.reload()
                    if self.__volume.state == 'in-use':
                        LOG.info('Volume attached!')
                        return True
                    else:
                        end_time = time.time()
                        if int(end_time) - int(start_time) > timeout:
                            LOG.error(
                                "Failed to attach to instance after %ss! Current state:%s" %
                                (timeout, self.__volume.state))
                            return False
                    time.sleep(10)
                    LOG.info("Waiting volume %s attached, current state %s, timeout %s" % (self.__volume.id, self.__volume.state, timeout))

            return True
        except Exception as err:
            LOG.error("Volume cannot attach to %s error %s" %
                      (instance_id, err))
            return False

    def detach_from_instance(self, wait=True, force=False):
        """Detach disk from instance as $device_name

        Arguments:
            instance_id {string} -- instance id
            device_name {string} -- target device name from instance, like
                                    'sdX','xvdx'

        Keyword Arguments:
            wait {bool} -- wait or not wait detach operation complete
                           (default: {True})
            force {bool} -- force or not force detach from instance
                            (default: {False})

        Returns:
            bool -- True if success, False as failed
        """
        try:
            instance_id = self.__volume.attachments[0]['InstanceId']
            device_name = self.__volume.attachments[0]['Device']
        except Exception as err:
            LOG.error("Cannot get attached instance id %s", self.__volume.id)
            LOG.error("error %s", err)
            LOG.info(self.__volume)
        try:
            self.__volume.load()
            instance_id = self.__volume.attachments[0]['InstanceId']
            device_name = self.__volume.attachments[0]['Device']
        except Exception as err:
            LOG.error("Cannot get attached instance id %s", self.__volume.id)
            LOG.error("error %s", err)
            LOG.info(self.__volume)
            return False
        try:
            instance_id = self.__volume.attachments[0]['InstanceId']
            device_name = self.__volume.attachments[0]['Device']
            LOG.info("Try to dettach %s from %s" %
                     (self.__volume.id, instance_id))

            self.__volume.detach_from_instance(
                Device=device_name,
                Force=force,
                InstanceId=instance_id,
            )
            if wait:
                start_time = time.time()
                while True:
                    self.__volume.reload()
                    if self.__volume.state == 'available':
                        LOG.info('Volume dettached!')
                        return True
                    else:
                        end_time = time.time()
                        LOG.info("Wait volume available, current state:{}".format(self.__volume.state))
                        if int(end_time) - int(start_time) > 180:
                            LOG.error(
                                "Failed to dettach to instance after 180s! %s"
                                % self.__volume.state)
                            return False
                    time.sleep(10)
        except Exception as err:
            LOG.error("Volume cannot detach from %s error %s" %
                      (instance_id, err))
            return False
