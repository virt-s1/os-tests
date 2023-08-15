import base64
from .resources import VMResource,StorageResource,NetworkResource,UnSupportedAction,UnSupportedStatus
from os_tests.libs import utils_lib
import logging
import time
import json
import os
import sys
try:
    from aliyunsdkcore.client import AcsClient
    from aliyunsdkecs.request.v20140526 import DescribeInstancesRequest
    from aliyunsdkecs.request.v20140526 import CreateInstanceRequest
    from aliyunsdkecs.request.v20140526 import StartInstanceRequest
    from aliyunsdkecs.request.v20140526 import StopInstanceRequest
    from aliyunsdkecs.request.v20140526 import RebootInstanceRequest
    from aliyunsdkecs.request.v20140526 import DeleteInstanceRequest
    from aliyunsdkecs.request.v20140526 import DescribeInstanceAttributeRequest
    from aliyunsdkecs.request.v20140526 import ModifyInstanceAttributeRequest
    from aliyunsdkecs.request.v20140526 import ModifyInstanceSpecRequest
    from aliyunsdkecs.request.v20140526 import AllocatePublicIpAddressRequest
    from aliyunsdkecs.request.v20140526 import DescribeKeyPairsRequest
    from aliyunsdkecs.request.v20140526 import CreateKeyPairRequest
    from aliyunsdkecs.request.v20140526 import ImportKeyPairRequest
    from aliyunsdkecs.request.v20140526 import DeleteKeyPairsRequest
    from aliyunsdkecs.request.v20140526 import DescribeImagesRequest
    from aliyunsdkecs.request.v20140526 import CreateImageRequest
    from aliyunsdkecs.request.v20140526 import DescribeDisksRequest
    from aliyunsdkecs.request.v20140526 import CreateDiskRequest
    from aliyunsdkecs.request.v20140526 import DeleteDiskRequest
    from aliyunsdkecs.request.v20140526 import AttachDiskRequest
    from aliyunsdkecs.request.v20140526 import DetachDiskRequest
    from aliyunsdkecs.request.v20140526 import CreateNetworkInterfaceRequest
    from aliyunsdkecs.request.v20140526 import AttachNetworkInterfaceRequest
    from aliyunsdkecs.request.v20140526 import DescribeNetworkInterfacesRequest
    from aliyunsdkecs.request.v20140526 import DetachNetworkInterfaceRequest
    from aliyunsdkecs.request.v20140526 import DeleteNetworkInterfaceRequest
    from aliyunsdkecs.request.v20140526 import GetInstanceConsoleOutputRequest
    from aliyunsdkecs.request.v20140526 import DescribeAvailableResourceRequest
    from aliyunsdkecs.request.v20140526 import AssignPrivateIpAddressesRequest
    from aliyunsdkecs.request.v20140526 import UnassignPrivateIpAddressesRequest
except ImportError:
    print("Please install aliyun-python-sdk-core,aliyun-python-sdk-ecs modules if run alicloud test")
    sys.exit(1)

class AliyunConfig(object):

    aliyuncli = os.path.join(os.path.expanduser('~'), ".aliyuncli")
    configure = {"path": os.path.join(aliyuncli, "configure")}
    credentials = {"path": os.path.join(aliyuncli, "credentials")}
    ossutilconfig = {"path": os.path.join(aliyuncli, ".ossutilconfig")}

    configure["content"] = """\
[default]
output = json
region = %(region)s
"""

    credentials["content"] = """\
[default]
aliyun_access_key_secret = %(access_key_secret)s
aliyun_access_key_id = %(access_key_id)s
"""

    ossutilconfig["content"] = """\
[Credentials]
language=CH
endpoint=oss-%(region)s.aliyuncs.com
accessKeyID=%(access_key_id)s
accessKeySecret=%(access_key_secret)s
"""

    def __init__(self,
                 access_key_id=None,
                 access_key_secret=None,
                 region=None):
        self.config = dict()
        self.config["access_key_id"] = access_key_id
        self.config["access_key_secret"] = access_key_secret
        self.config["region"] = region
        if not os.path.isdir(self.aliyuncli):
            os.makedirs(self.aliyuncli, 0o755)

    def _write_file(self, cfile):
        with open(cfile["path"], 'w') as f:
            f.write(cfile["content"] % self.config)

    def update(self):
        self._write_file(self.credentials)
        self._write_file(self.configure)
        self._write_file(self.ossutilconfig)
        logging.info("Update configurations finished.")

class AlibabaSDK(object):
    def __init__(self, params):
        # Alibaba connection credentials
        access_key_id = params['Credential'].get('access_key_id')
        access_key_secret = params['Credential'].get('secretaccess_key')
        region = params['VM'].get('region')

        AliyunConfig(access_key_id=access_key_id,
                     access_key_secret=access_key_secret,
                     region=region).update()
        self.clt = AcsClient(access_key_id, access_key_secret, region)

        # VM parameters
        self.vm_params = dict()
        self.vm_params["InstanceType"] = params['Flavor'].get('name')
        self.vm_params["RegionId"] = region
        self.vm_params["InstanceName"] = params['VM'].get('vm_name').replace('_', '-')
        self.vm_params["HostName"] = self.vm_params["InstanceName"]
        self.vm_params["Username"] = params['VM'].get('username')
        self.vm_params["Password"] = params['VM'].get('password')
        self.vm_params["KeyPairName"] = params['VM'].get('keypair')
        self.vm_params["ZoneId"] = params['VM'].get('az')
        self.vm_params["ImageName"] = params['Image'].get('name')
        self.vm_params["ImageId"] = params['Image'].get('id', '*/Image/*')
        self.vm_params["SecurityGroupId"] = params['SecurityGroup'].get('id')
        self.vm_params["VSwitchId"] = params["Network"]["VSwitch"].get('id')
        self.vm_params["DiskName"] = params['Disk'].get('cloud_disk_name')
        self.vm_params["Size"] = params['Disk'].get('cloud_disk_size')
        self.vm_params["NetworkInterfaceName"] = params['NIC'].get('nic_name')

        # Assign SystemDiskCategory and DiskCategory
        self.vm_params["SystemDiskCategory"] = self.select_disk_category(
            'SystemDisk')
        self.vm_params["DiskCategory"] = self.select_disk_category('DataDisk')

        logging.info('Assigned. SystemDiskCategory="{}"; DiskCategory="{}".'.format(
            self.vm_params['SystemDiskCategory'], self.vm_params['DiskCategory']))

    def _send_request(self, request):
        request.set_accept_format('json')
        try:
            logging.debug("Run: {0}".format(request.__class__.__name__))
            #            logging.debug(
            #               "Request: %s" % request.get_query_params())
            response_str = self.clt.do_action_with_exception(request)
            response_detail = json.loads(response_str)
            #            logging.debug("Response: %s" % response_detail)
            return response_detail
        except Exception as e:
            logging.error(e)
            return e

    @staticmethod
    def _add_params(request, key_list=None, params=None):
        if params is None:
            return request
        if key_list:
            for key in key_list:
                if params.get(key) is not None:
                    value = params.get(key)
                    if "Ids" in key or "Names" in key:
                        value = str(value.split(',')).replace('\'', '"')
                    eval("request.set_{0}('{1}')".format(key, value))
        request.get_query_params()
        return request

    # Instance
    def describe_instances(self):
        request = DescribeInstancesRequest.DescribeInstancesRequest()
        key_list = ["InstanceName", "InstanceIds"]
        self.vm_params.setdefault("InstanceName",
                                  self.vm_params["InstanceName"])
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_instance(self, authentication="publickey"):
        request = CreateInstanceRequest.CreateInstanceRequest()
        key_list = [
            "InstanceChargeType", "ImageId", "InstanceType",
            "InternetChargeType", "SecurityGroupId", "VSwitchId",
            "SystemDiskCategory", "HostName", "InstanceName",
            "InternetMaxBandwidthOut", "InternetMaxBandwidthIn", "ZoneId"
        ]
        self.vm_params.setdefault("InstanceChargeType", "PostPaid")
        self.vm_params.setdefault("InternetChargeType", "PayByTraffic")
        self.vm_params.setdefault("SystemDiskCategory",
                                  self.vm_params['DiskCategory'])
        self.vm_params.setdefault("InternetMaxBandwidthIn", "5")
        self.vm_params.setdefault("InternetMaxBandwidthOut", "5")
        if authentication == "publickey":
            key_list.append("KeyPairName")
        elif authentication == "password":
            key_list.append("Password")
        request = self._add_params(request, key_list, self.vm_params)
        response = self._send_request(request)
        if isinstance(response, Exception):
            raise response
        return response

    def start_instance(self, instance_id):
        request = StartInstanceRequest.StartInstanceRequest()
        key_list = ["InstanceId"]
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def stop_instance(self, instance_id, force=False):
        request = StopInstanceRequest.StopInstanceRequest()
        key_list = ["InstanceId", "ForceStop"]
        self.vm_params["InstanceId"] = instance_id
        if force:
            self.vm_params["ForceStop"] = force
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def reboot_instance(self, instance_id, force=False):
        request = RebootInstanceRequest.RebootInstanceRequest()
        key_list = ["InstanceId", "ForceStop"]
        self.vm_params["InstanceId"] = instance_id
        if force:
            self.vm_params["ForceStop"] = force
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def delete_instance(self, instance_id):
        request = DeleteInstanceRequest.DeleteInstanceRequest()
        key_list = ["InstanceId"]
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def describe_instance_attribute(self, instance_id):
        request = DescribeInstanceAttributeRequest.\
            DescribeInstanceAttributeRequest()
        key_list = ["InstanceId"]
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def modify_instance_attribute(self, instance_id, new_password):
        request = ModifyInstanceAttributeRequest.\
            ModifyInstanceAttributeRequest()
        key_list = ["InstanceId", "Password"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["Password"] = new_password
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def modify_instance_spec(self, instance_id, new_type):
        request = ModifyInstanceSpecRequest.ModifyInstanceSpecRequest()
        key_list = [
            "InstanceId", "InstanceType", "InternetMaxBandwidthIn",
            "InternetMaxBandwidthOut"
        ]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["InstanceType"] = new_type
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Resource
    def describe_available_resource(self, destination_resource):
        # destination_resource: ['Zone', 'IoOptimized', 'InstanceType',
        #                        'SystemDisk', 'DataDisk', 'Network', 'ddh']
        request = DescribeAvailableResourceRequest.DescribeAvailableResourceRequest()
        key_list = ["DestinationResource", "ZoneId", "InstanceType"]
        self.vm_params["DestinationResource"] = destination_resource
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def select_disk_category(self, category):
        """Select Available Disk Category by ZoneId and InstanceType."""

        if category not in ('SystemDisk', 'DataDisk'):
            logging.error(
                'Unsupported category! category = {}'.format(category))
            return 'cloud_efficiency'

        _data = self.describe_available_resource(category)

        _azone = _data.get('AvailableZones', {}).get('AvailableZone', [])
        if len(_azone) != 1 or _azone[0].get('Status') != 'Available':
            logging.error('Resource unavailable! _azone = {}'.format(_azone))
            return 'cloud_efficiency'

        _resource = _azone[0].get(
            'AvailableResources', {}).get('AvailableResource', [])
        if len(_resource) != 1 or _resource[0].get('Type') != category:
            logging.error(
                'Resource unavailable! _resource = {}'.format(_resource))
            return 'cloud_efficiency'

        _disk = _resource[0].get(
            'SupportedResources', {}).get('SupportedResource', [])
        _disk_categories = [
            x.get('Value') for x in _disk if x.get('Status') == 'Available']

        if len(_disk_categories) == 0:
            logging.error('Resource unavailable! _disk_categories = []')
            return 'cloud_efficiency'

        if 'cloud_essd' in _disk_categories:
            disk_category = 'cloud_essd'
        elif 'cloud_ssd' in _disk_categories:
            disk_category = 'cloud_ssd'
        elif 'cloud_efficiency' in _disk_categories:
            disk_category = 'cloud_efficiency'
        else:
            disk_category = _disk_categories[0]

        logging.info('Selected {} Category "{}" from {}'.format(
            category, disk_category, _disk_categories))

        return disk_category

    # Public IP
    def allocate_public_ip_address(self, instance_id):
        request = AllocatePublicIpAddressRequest.\
            AllocatePublicIpAddressRequest()
        key_list = ["InstanceId"]
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # KeyPair
    def describe_keypairs(self):
        request = DescribeKeyPairsRequest.DescribeKeyPairsRequest()
        key_list = ["KeyPairName", "RegionId"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_keypair(self):
        request = CreateKeyPairRequest.CreateKeyPairRequest()
        key_list = ["KeyPairName", "RegionId"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def import_keypair(self):
        request = ImportKeyPairRequest.ImportKeyPairRequest()
        key_list = ["KeyPairName", "RegionId", "PublicKeyBody"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def delete_keypair(self):
        request = DeleteKeyPairsRequest.DeleteKeyPairsRequest()
        key_list = ["KeyPairNames", "RegionId"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Image
    def describe_images(self):
        request = DescribeImagesRequest.DescribeImagesRequest()
        key_list = ["ImageName", "ImageId"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_image(self):
        request = CreateImageRequest.CreateImageRequest()
        key_list = ["ImageName", "SnaoshotId", "Platform"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Disk
    def describe_disks(self, diskids=None):
        """Describe cloud disks.

        diskids should be a string like '"id1","id2","id3"'.
        """
        request = DescribeDisksRequest.DescribeDisksRequest()
        key_list = ["ZoneId", "DiskName", "Category", "PageSize"]
        self.vm_params.setdefault("Category", self.vm_params['DiskCategory'])
        self.vm_params.setdefault("PageSize", "100")
        if diskids:
            key_list.append("DiskIds")
            self.vm_params["DiskIds"] = diskids
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_disk(self):
        request = CreateDiskRequest.CreateDiskRequest()
        key_list = ["ZoneId", "DiskName", "DiskCategory", "Size"]
        self.vm_params.setdefault("DiskCategory",
                                  self.vm_params['DiskCategory'])
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def delete_disk(self, diskid):
        request = DeleteDiskRequest.DeleteDiskRequest()
        key_list = ["DiskId"]
        self.vm_params["DiskId"] = diskid
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def attach_disk(self, instance_id, diskid=None):
        request = AttachDiskRequest.AttachDiskRequest()
        key_list = ["InstanceId", "DiskId"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["DiskId"] = diskid
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def detach_disk(self, instance_id, diskid=None):
        request = DetachDiskRequest.DetachDiskRequest()
        key_list = ["InstanceId", "DiskId"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["DiskId"] = diskid
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_nic(self, primary_ip_address=None):
        request = CreateNetworkInterfaceRequest.CreateNetworkInterfaceRequest()
        key_list = [
            "NetworkInterfaceName", "PrimaryIpAddress", "VSwitchId",
            "SecurityGroupId"
        ]
        self.vm_params["PrimaryIpAddress"] = primary_ip_address
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def attach_nic(self, instance_id, nic_id):
        request = AttachNetworkInterfaceRequest.AttachNetworkInterfaceRequest()
        key_list = ["InstanceId", "NetworkInterfaceId"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["NetworkInterfaceId"] = nic_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def describe_nics(self,
                      instance_id=None,
                      nic_type=None,
                      nic_name="default",
                      nic_ids=None):
        request = DescribeNetworkInterfacesRequest.\
            DescribeNetworkInterfacesRequest()
        key_list = ["InstanceId", "Type"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["Type"] = nic_type
        if nic_name:
            if not nic_name == "default":
                self.vm_params["NetworkInterfaceName"] = nic_name
            key_list.append("NetworkInterfaceName")
        if nic_ids:
            if not isinstance(nic_ids, str):
                nic_ids = ','.join(nic_ids)
            key_list.append("NetworkInterfaceIds")
            self.vm_params["NetworkInterfaceIds"] = nic_ids
        key_list.append("PageSize")
        self.vm_params["PageSize"] = 500
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def detach_nic(self, instance_id, nic_id):
        request = DetachNetworkInterfaceRequest.DetachNetworkInterfaceRequest()
        key_list = ["InstanceId", "NetworkInterfaceId"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["NetworkInterfaceId"] = nic_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def delete_nic(self, nic_id):
        request = DeleteNetworkInterfaceRequest.DeleteNetworkInterfaceRequest()
        key_list = ["NetworkInterfaceId"]
        self.vm_params["NetworkInterfaceId"] = nic_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Assign Secondary Private IPs
    def assign_private_ips(self, nic_id, secondary_private_ip_count):
        request = AssignPrivateIpAddressesRequest.AssignPrivateIpAddressesRequest()
        key_list = ["NetworkInterfaceId", "SecondaryPrivateIpAddressCount"]
        self.vm_params["NetworkInterfaceId"] = nic_id
        self.vm_params["SecondaryPrivateIpAddressCount"] = secondary_private_ip_count
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Unassign Secondary Private IPs
    def unassign_private_ips(self, nic_id, secondary_private_ip_list):
        request = UnassignPrivateIpAddressesRequest.UnassignPrivateIpAddressesRequest()
        key_list = ["NetworkInterfaceId"]
        self.vm_params["NetworkInterfaceId"] = nic_id
        request = self._add_params(request, key_list, self.vm_params)
        request.set_PrivateIpAddresss(secondary_private_ip_list)
        return self._send_request(request)

    def get_console_log(self, instance_id):
        request = GetInstanceConsoleOutputRequest.GetInstanceConsoleOutputRequest(
        )
        key_list = ['InstanceId']
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)


class AlibabaVM(VMResource):
    def __init__(self, params):
        super(AlibabaVM, self).__init__(params)
        self._data = None

        # VM parameters
        self.keypair = params['VM'].get('keypair')
        self.vm_name = params['VM'].get('vm_name').replace('_', '-')
        self.user_data = None
        self.nic_name = params['NIC'].get('nic_name')

        self.flavor = params['Flavor'].get('name')
        self.cpu = params['Flavor'].get('cpu')
        self.memory = params['Flavor'].get('memory')
        self.disk_count = params['Flavor'].get('disk_count')
        self.disk_size = params['Flavor'].get('disk_size')
        self.disk_type = params['Flavor'].get('disk_type')
        self.nic_count = params['Flavor'].get('nic_count')
        self.disk_quantity = params['Flavor'].get('disk_quantity')
        self.private_ip_quantity = params['Flavor'].get('private_ip_quantity')

        # Secondary ip list
        self.secondary_ip_list = []

        # VM access parameters
        self.vm_username = params['VM'].get('username')
        self.vm_password = params['VM'].get('password')

        self.arch = params['Flavor'].get('arch')
        if not self.arch:
            self.arch = 'x86_64'

        self.ecs = AlibabaSDK(params)

    @property
    def data(self):
        if not self._data:
            self._data = []
            for ecs in self.ecs.describe_instances().get('Instances').get(
                    'Instance'):
                if ecs["InstanceName"] == self.vm_name:
                    self._data = ecs
                    break
        return self._data

    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def floating_ip(self):
        f_ip = None
        for ip in self.data.get('PublicIpAddress').get('IpAddress'):
            f_ip = ip
        return f_ip

    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def private_ip(self):
        p_ip = None
        for ip in self.data.get('VpcAttributes').get('PrivateIpAddress').get('IpAddress'):
            p_ip = ip
        return p_ip

    def wait_for_status(self, status, timeout=300):
        error_message = "Timed out waiting for server to get %s." % status
        for count in utils_lib.iterate_timeout(timeout,
                                                error_message,
                                                wait=20):
            current_status = self._get_status()
            logging.debug('Target: {0}, Current: {1}'.format(
                status, current_status))
            if current_status == status:
                return True

            # Exceptions (detect wrong status to save time)
            if status == 'Running' and current_status not in ('Stopping',
                                                              'Starting'):
                logging.error('While waiting for the server to get Running, \
its status cannot be {0} rather than Stopping or Starting.'.format(
                    current_status))
                return False

    @property
    def instance_id(self):
        return self.data.get("InstanceId")

    @property
    def is_metal(self):
        """
        return if vm is bare metal or not
        """
        return 'ebm' in self.flavor

    def create(self, wait=False):
        """
        This helps to create a VM
        """
        logging.info("Create VM")
        authentication = "publickey"
        if self.keypair is None:
            authentication = "password"
        self.ecs.create_instance(authentication=authentication)
        if wait:
            time.sleep(10)
            self.wait_for_status(status="Stopped")
        self._data = None
        self.ecs.allocate_public_ip_address(self.instance_id)
        time.sleep(5)

    def start(self, wait=False):
        """
        This helps to start a VM
        """
        logging.info("Start VM")
        self.ecs.start_instance(self.instance_id)
        time.sleep(60)
        if wait:
            self.wait_for_status(status="Running")

    def stop(self, wait=False, force=False):
        """
        This helps to stop a VM
        """
        logging.info("Stop VM")
        self.ecs.stop_instance(self.instance_id, force=force)
        if wait:
            self.wait_for_status(status="Stopped")

    def reboot(self, wait=False, force=False):
        """
        This helps to restart a VM
        """
        logging.info("Restart VM")
        self.ecs.reboot_instance(self.instance_id, force=force)
        if wait:
            self.wait_for_status(status="Running")

    def delete(self, wait=False):
        """
        This helps to delete a VM
        The VM can be deleted only if the status is stopped(sdk/cli only)
        """
        logging.info("Delete VM")
        if not self.is_stopped():
            self.stop(wait=True)
        self.ecs.delete_instance(self.instance_id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for server to get deleted.",
                    wait=10):
                if not self.exists():
                    break

    def reset_password(self, new_password):
        logging.info("Reset password for VM")
        return self.ecs.modify_instance_attribute(self.instance_id, new_password)

    def create_nic(self, wait=False):
        logging.debug("Create NIC")
        nic_id = self.ecs.create_nic().get("NetworkInterfaceId")
        if wait:
            for count in utils_lib.iterate_timeout(
                    300, "Timed out waiting for nics to be created.", wait=5):
                # nic_status = self.ecs.describe_nics(
                #     nic_ids=[nic_id]).get("Status")
                # logging.debug(
                #     'Status: {0} / Wanted: "Available"'.format(nic_status))
                # if nic_status == "Available":
                #     break

                # Cannot check status with nic_ids because of bug
                # https://github.com/aliyun/aliyun-openapi-python-sdk/issues/78
                # This is a workaround. All nics must not be Creating status
                available_count = creating_count = other_count = 0
                for nic in self.list_nics():
                    if nic.get("Status") == "Available":
                        available_count += 1
                    elif nic.get("Status") == "Creating":
                        creating_count += 1
                    else:
                        other_count += 1
                logging.debug(
                    'Status: Available/Creating/Other: "{0}/{1}/{2}"'.format(
                        available_count, creating_count, other_count))
                if creating_count == 0:
                    break

    def attach_nics(self, nic_count, wait=False):
        logging.debug("Attach %s NICs to ECS" % nic_count)
        origin_count = len(self.query_nics())
        nics_list = self.list_nics()
        if len(nics_list) >= nic_count:
            for nic in nics_list[0:nic_count]:
                self.ecs.attach_nic(self.instance_id, nic.get("NetworkInterfaceId"))
        else:
            raise Exception("No enough NICs. Need: %s; Exists: %s" %
                            (nic_count, len(nics_list)))
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for nics to be attached.",
                    wait=20):
                attached_count = len(self.query_nics()) - origin_count
                logging.debug("Attached: {0} / Wanted: {1}".format(
                    attached_count, nic_count))
                if attached_count >= nic_count:
                    break

    def detach_nics(self, nic_ids, wait=False):
        logging.info("Detach NICs from ECS")
        if nic_ids is None or nic_ids == []:
            return
        if not isinstance(nic_ids, list):
            nic_ids = [nic_ids]

        origin_count = len(self.query_nics())
        forks = 10
        if len(nic_ids) > forks:
            # When detaching more than 20 disks at the same time,
            # some of them will be failed, this is the workaround.
            logging.debug("Detaching first {0} from {1} NIC(s)...".format(
                forks, len(nic_ids)))
            self.detach_nics(nic_ids[:forks], True)
            self.detach_nics(nic_ids[forks:], True)
        else:
            for nic_id in nic_ids:
                self.ecs.detach_nic(self.instance_id, nic_id)
            if wait:
                for count in utils_misc.iterate_timeout(
                        300, "Timed out waiting for nics to be detached",
                        wait=20):
                    detached_count = origin_count - len(self.query_nics())
                    logging.debug("Detached: {0} / Wanted: {1}".format(
                        detached_count, len(nic_ids)))
                    if detached_count >= len(nic_ids):
                        break

    def query_nics(self):
        """Get NIC list of the current instance."""
        logging.info("Getting NICs attached to the ECS")
        return self.ecs.describe_nics(instance_id=self.instance_id, nic_name=None).get(
            "NetworkInterfaceSets").get("NetworkInterfaceSet")

    def query_secondary_nics(self):
        """Get Secondary NIC list of the current instance."""
        logging.info("Getting Secondary NICs attached to the ECS")
        return self.ecs.describe_nics(
            instance_id=self.instance_id, nic_type="Secondary").get(
                "NetworkInterfaceSets").get("NetworkInterfaceSet")

    # SDK issue, can not get the primary nic.
    def query_primary_nic(self):
        """Get primary NIC of the current instance."""
        logging.info("Getting Primary NIC attached to the ECS")
        logging.debug(self.instance_id)
        logging.debug(
            self.ecs.describe_nics(
                instance_id=self.instance_id, nic_type="Primary").get(
                    "NetworkInterfaceSets").get("NetworkInterfaceSet"))
        return self.ecs.describe_nics(
            instance_id=self.instance_id, nic_type="Primary").get(
                "NetworkInterfaceSets").get("NetworkInterfaceSet")[0]

    def list_nics(self):
        """List NICs with default NetworkInterfaceName in the current region.

        Returns a list of NetworkInterfaceSet.
        """
        logging.info("List all NICs in this region")
        return self.ecs.describe_nics().get("NetworkInterfaceSets").get(
            "NetworkInterfaceSet")

    def get_private_ip_address(self, nic):
        """Get private ip of the specified NIC."""
        logging.info("Getting private IP address")
        return nic.get("PrivateIpAddress")

    def get_nic_id(self, nic):
        """Get NIC ID of the specified NIC."""
        logging.info("Getting NIC ID")
        return nic.get("NetworkInterfaceId")

    def get_nic_type(self, nic):
        """Get type of the specified NIC.
        
        Returns 'Primary' or 'Secondary'.
        """
        logging.info("Getting NIC Type")
        return nic.get("Type")

    def delete_nic(self, nic_id):
        """Delete the specified NIC."""
        logging.debug("Delete NIC")
        self.ecs.delete_nic(nic_id)

    def delete_nics(self, nic_name='default', wait=False):
        """Delete the specified NICs by the name."""
        logging.debug("Delete NICs (Name: {0})".format(nic_name))
        nics = self.ecs.describe_nics(nic_name=nic_name).get(
            "NetworkInterfaceSets").get("NetworkInterfaceSet")
        for nic in nics:
            self.delete_nic(nic['NetworkInterfaceId'])
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for nics to be deleted.", wait=1):
                remaining = len(
                    self.ecs.describe_nics(nic_name=nic_name).get(
                        "NetworkInterfaceSets").get("NetworkInterfaceSet"))
                logging.debug(
                    'Remaining {0} NIC(s) to be deleted.'.format(remaining))
                if remaining == 0:
                    break

    def assign_secondary_ips(self, secondary_ip_count=1):
        nic_id = self.get_nic_id(self.query_nics()[0])
        ret = self.ecs.assign_private_ips(nic_id=nic_id,secondary_private_ip_count=secondary_ip_count)
        self.secondary_ip_list = ret.get("AssignedPrivateIpAddressesSet").get("PrivateIpSet").get("PrivateIpAddress")
        logging.info("Assigning secondary nic ips: {}".format(str(self.secondary_ip_list)))
        return self.secondary_ip_list

    def remove_secondary_ips(self):
        nic_id = self.get_nic_id(self.query_nics()[0])
        logging.info("Removing secondary nic ips: {}".format(str(self.secondary_ip_list)))
        return self.ecs.unassign_private_ips(nic_id, self.secondary_ip_list)

    def create_cloud_disk(self, wait=False, **args):
        logging.info("Create cloud disk")
        output = self.ecs.create_disk()
        diskid = output.get("DiskId").encode("ascii")
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for cloud disk to be created.",
                    wait=5):
                if self.query_cloud_disks(
                        disk_id=diskid)[0].get("Status") == u'Available':
                    break
        return output

    def delete_cloud_disk(self, disk_id, wait=False):
        """Delete specified cloud disk."""
        logging.info("Delete a cloud disk")
        disk_id = disk_id.encode('ascii')
        self.ecs.delete_disk(disk_id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for cloud disk to be deleted",
                    wait=5):
                res = self.query_cloud_disks(disk_id=disk_id)
                if res == []:
                    break

    def delete_cloud_disks(self, wait=False):
        """Delete default cloud disks."""
        logging.info('Delete cloud disks')
        disks = self.query_cloud_disks()
        for disk in disks:
            self.delete_cloud_disk(disk['DiskId'], wait)

    def query_cloud_disks(self, disk_id=None, **args):
        logging.info("Describe cloud disks")
        if disk_id is not None:
            disk_id = disk_id.encode("ascii")
        output = self.ecs.describe_disks(diskids=disk_id)
        if output:
            return output.get("Disks").get("Disk")
        return output

    def attach_cloud_disks(self, disk_id, wait=False, **args):
        logging.info("Attach cloud disk to VM")
        disk_id = disk_id.encode("ascii")
        output = self.ecs.attach_disk(self.instance_id, disk_id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    300,
                    "Timed out waiting for cloud disk to be attached.",
                    wait=5):
                if self.query_cloud_disks(
                        disk_id=disk_id)[0].get("Status") == u"In_use":
                    break
        return output

    def detach_cloud_disks(self, disk_id=None, wait=False, **args):
        logging.info("Detach cloud disk to VM")
        disk_id = disk_id.encode("ascii")
        output = self.ecs.detach_disk(self.instance_id, disk_id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    300,
                    "Timed out waiting for cloud disk to be detached.",
                    wait=5):
                if self.query_cloud_disks(
                        disk_id=disk_id)[0].get("Status") == u"Available":
                    break
        return output

    def exists(self):
        self._data = None
        count = sum(1 for i in self.data)
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self._data = None
        return self.data.get('Status')

    def get_state(self):
        return self._get_status()

    def is_started(self):
        """Return True if VM is running."""
        return self._get_status() == 'Running'

    def is_stopped(self):
        """Return True if VM is stopped."""
        return self._get_status() == 'Stopped'

    def show(self):
        logging.info("Show VM params")
        return self.data

    def modify_instance_type(self, new_type):
        """Modify Instance Type."""
        self.ecs.modify_instance_spec(self.instance_id, new_type)

    def get_console_log(self):
        """Get console log."""
        logging.info('Get console log')
        try:
            output = self.ecs.get_console_log(self.instance_id)
            b64code = output.get('ConsoleOutput')
            console_output = base64.b64decode(b64code)
            return True, console_output
        except Exception as err:
            logging.error("Failed to get console log! %s" % err)
            return False, err

    def disk_count(self):
        raise NotImplementedError

    def send_nmi(self):
        raise UnSupportedAction('No such operation in openstack')

    def send_hibernation(self):
        raise NotImplementedError

    def attach_block(self, disk, target, wait=True, timeout=120):
        raise NotImplementedError

    def detach_block(self, disk, wait=True, force=False):
        raise NotImplementedError

    def attach_nic(self, nic, wait=True, timeout=120):
        raise NotImplementedError

    def detach_nic(self, nic, wait=True, force=False):
        raise NotImplementedError

    def is_exist(self):
        return self.exists()

    def is_paused(self):
        raise NotImplementedError

    def pause(self):
        raise NotImplementedError

    def unpause(self):
        raise NotImplementedError
