"""
This module is used for converting linux 'az' commnad to python function
Please install azure-cli firstly.
https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt
"""
import json
import time
import re
import logging
import sys
import os

from os_tests.libs import utils_lib

from .resources import BaseResource, VMResource,StorageResource,NetworkResource,UnSupportedAction,UnSupportedStatus
from os_tests.libs.utils_lib import run_cmd_local

LOG = logging.getLogger('os_tests.os_tests_run')
logging.basicConfig(level=logging.INFO)

class AzureAccount(object):
    def __init__(self, params):
        self.tenant_id = params.get('Credential').get('tenant_id')
        self.username = params.get('Credential').get('username')
        self.password = params.get('Credential').get('password')
        if not self.username:
            LOG.info('Not specify azure access username or password! Try to use current session.') 
        status, _ = run_cmd_local('which az', is_log_ret=True)
        if status != 0:
            LOG.error("please install azure-cli firstly! Try 'pip install azure-cli' or see https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt")
            sys.exit(1)

    def login(self):

        cmd = 'az login --service-principal -u {} -p "{}" --tenant "{}"'.format(self.username,self.password,self.tenant_id)
        run_cmd_local(cmd, is_log_cmd=False ,is_log_ret=True)

    def logout(self):
        cmd = "az logout"
        run_cmd_local(cmd, is_log_ret=True)

    @staticmethod
    def show():
        cmd = "az account show"
        ret, out = run_cmd_local(cmd, is_log_ret=True)
        return ret, json.loads(out)

    @staticmethod
    def list():
        cmd = "az account list"
        run_cmd_local(cmd, is_log_ret=True)

    def is_login(self):
        ret, _ = self.show()
        if ret == 0:
            return True
        return False

class AzureVM(VMResource):
    def __init__(self, params, **kwargs):
        super(AzureVM, self).__init__(params)
        vm_name_prefix = params.get('VM').get("vm_name_prefix")
        self.vm_size = kwargs.get("size") if "size" in kwargs else params.get('VM').get("vm_size")
        self.vm_name = vm_name_prefix + re.sub("[_-]", "", self.vm_size.lower())
        if 'nametag' in kwargs:
            self.vm_name = self.vm_name + '-' + kwargs.get('nametag')
        self.resource_group = params.get('VM').get("resource_group")
        self.storage_account = params.get('VM').get("storage_account")
        self.region = params.get('VM').get("region")
        self.vm_image = params.get('VM').get("vm_image")
        if ".vhd" in self.vm_image:
            self.vm_image = "https://{}.blob.core.windows.net/vhds/{}"\
                         .format(self.storage_account, self.vm_image)
        self.vm_username = params.get('VM').get("vm_username")
        self.generate_ssh_keys = params.get('VM').get("generate_ssh_keys")
        self.vm_password = params.get('VM').get("vm_password")
        self.ssh_key_value = params.get('VM').get("ssh_key_value")
        self.authentication_type = "ssh" if self.generate_ssh_keys or self.ssh_key_value else "password"
        self.custom_data = params.get('VM').get("custom_data")
        self.net_bandwidth_cfg = params.get('VM').get('net_bandwidth')
        self.cvm = params['VM'].get('cvm', 'false').lower()
        self.disk_controller_type = params['VM'].get('disk_controller_type', 'false')
        self.sriov = params.get('VM').get('sriov', 'false').lower()
        self.user_data = None
        self.user_data_file = None
        self.use_unmanaged_disk = params.get('VM').get("use_unmanaged_disk")
        self.assign_identity = False
        self.run_uuid = params.get('run_uuid')
        self.account = AzureAccount(self.params)
        if not self.account.is_login():
            self.account.login()
        _, out = self.account.show()
        subscription_id = out.get("id")
        self.scope = "/subscriptions/{0}/resourceGroups/{1}"\
                     .format(subscription_id, self.resource_group)
        self.os_type = "linux"
        self.os_disk_name = self.vm_name + "_os" + \
            time.strftime('%Y%m%d%H%M%S',time.localtime())
        self.vnet_name = self.resource_group
        self.subnet = self.resource_group
        self.nics = kwargs.get("nics")
        self.os_disk_size = kwargs.get("os_disk_size")
        self.properties = {}

    def show(self):
        cmd = 'az vm show -d --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        try:
            status, out = run_cmd_local(cmd, is_log_ret=True)
        except Exception as err:
            LOG.info(err)
            return False
        if len(out) and status == 0:
            self.properties = json.loads(out)
            return True
        return False

    def create(self, wait=True, userdata=None, sshkey=None):
        if sshkey == 'DoNotSet':
            authentication_type = 'all'
        else:
            authentication_type = self.authentication_type
        vm_password = None
        vm_username = None
        cmd = 'az group show --name "{}" --query "location==\'{}\'" -o tsv'.format(self.resource_group, self.region)
        ret, out = run_cmd_local(cmd, is_log_ret=True)
        if out.strip().lower() == "true":
            print(f"Resource group '{self.resource_group}' already exists in region '{self.region}'.")
        else:
            print(f"Resource group '{self.resource_group}' does not exist in region '{self.region}'. Creating...")
            self.resource_group = self.resource_group + self.region
            cmd = 'az group create --name "{}"  --location "{}"' \
            .format(self.resource_group, self.region)
            ret, out = run_cmd_local(cmd, is_log_ret=True)

        cmd = 'az vm create --name "{}" --resource-group "{}" --image "{}" '\
            '--size "{}" --authentication-type "{}" --location "{}" '\
            ' --os-disk-name "{}" --nic-delete-option delete --os-disk-delete-option delete'\
            .format(self.vm_name, self.resource_group, self.vm_image,
                    self.vm_size, authentication_type, self.region,
                    self.os_disk_name)

        if self.ssh_key_value and sshkey != 'DoNotSet':
            cmd += ' --ssh-key-value {}'.format(self.ssh_key_value)
        elif self.generate_ssh_keys and sshkey != 'DoNotSet':
            cmd += " --generate-ssh-keys"
        if self.custom_data:
            cmd += ' --custom-data "{}"'.format(self.custom_data)
        userdata = userdata or self.user_data
        if userdata:
            self.user_data_file = '/tmp/azure_user_data_{}.txt'.format(self.run_uuid)
            with open(self.user_data_file, 'w+') as fh:
                fh.write(userdata)
            cmd += ' --user-data {}'.format(self.user_data_file)
            if re.findall('password:.*', userdata):
                vm_password = re.findall('password:.*', userdata)[0].split(':')[-1].strip()
            if re.findall('user:.*', userdata):
                vm_username = re.findall('user:.*', userdata)[0].split(':')[-1].strip()
        vm_username = vm_username or self.vm_username
        cmd += ' --admin-username "{}"'.format(vm_username)
        vm_password = vm_password or self.vm_password
        if vm_password and authentication_type != "ssh":
            cmd += ' --admin-password "{}"'.format(vm_password)
        if self.use_unmanaged_disk:
            cmd += ' --use-unmanaged-disk --storage-account {}'.format(self.storage_account)
        if self.assign_identity:
            cmd += " --assign-identity"
            cmd += ' --scope "{}"'.format(self.scope)
        if ".vhd" in self.vm_image:
            cmd += ' --os-type "{}"'.format(self.os_type)
        if self.nics:
            cmd += ' --nics {}'.format(self.nics)
        else:
            cmd += ' --vnet-name "{}" --subnet "{}"'.format(
                self.vnet_name, self.subnet)
        if self.sriov == 'true':
            cmd += ' --accelerated-networking true'
        if self.cvm == 'true':
            cmd += ' --security-type ConfidentialVM --enable-secure-boot true --enable-vtpm true --os-disk-security-encryption-type VMGuestStateOnly'
        if self.os_disk_size:
            cmd += ' --os-disk-size-gb {}'.format(self.os_disk_size)
        if self.disk_controller_type:
            cmd += ' --disk-controller-type {}'.format(self.disk_controller_type)
        if not wait:
            cmd += " --no-wait"
        _, out = run_cmd_local(cmd, timeout=720, is_log_ret=True)
        if len(out):
            return self.show()

    def delete(self, wait=True):
        if self.user_data_file and os.path.exists(self.user_data_file):
            os.unlink(self.user_data_file)
        cmd = 'az vm delete --name "{}" --resource-group "{}" --yes'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd, timeout=720, is_log_ret=True)
        # Previous os disk name will be deleted together with vm, but it still exists for a while.
        # It will fail to create new vm immediatly, so use new os disk name instead.
        self.os_disk_name = self.vm_name + "_os" + \
            time.strftime('%Y%m%d%H%M%S',time.localtime())
        # Sometimes VM still exists for a while after cli finished
        if wait:
            error_message = "Timed out waiting for server to get deleted."
            for count in utils_lib.iterate_timeout(100, error_message, wait=10):
                if not self.exists():
                    break

    def start(self, wait=True):
        cmd = 'az vm start --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd, is_log_ret=True)
        self.show()

    def reboot(self, wait=True):
        cmd = 'az vm restart --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd, is_log_ret=True)
        self.show()

    def stop(self, wait=True):
        self.deallocate(wait)

    def deallocate(self, wait=True):
        cmd = 'az vm deallocate --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd, is_log_ret=True)
        self.show()

    def redeploy(self, wait=True):
        cmd = 'az vm redeploy --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd, is_log_ret=True)
        self.show()

    def exists(self):
        return self.show()

    def is_started(self):
        return self.properties.get("powerState") == "VM running"

    def is_stopped(self):
        return self.is_deallocated()

    def is_deallocated(self):
        return self.properties.get("powerState") == "VM deallocated"

    def osdisk_resize(self, size, wait=True):
        cmd = 'az vm update --name "{}" --resource-group {} '\
              '--set storageProfile.osDisk.diskSizeGB={}'\
              .format(self.vm_name, self.resource_group, size)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd, is_log_ret=True)

    def unmanaged_disk_attach(self, name, size, new=True, disk_uri=""):
        cmd = 'az vm unmanaged-disk attach --name {} --vm-name "{}" '\
              '--resource-group {} --size-gb {}'\
              .format(name, self.vm_name, self.resource_group, size)
        if new:
            cmd += " --new"
        else:
            cmd += " --vhd-uri {}".format(disk_uri)
        run_cmd_local(cmd, is_log_ret=True)

    def unmanaged_disk_detach(self, name):
        cmd = 'az vm unmanaged-disk detach \
--name {} --vm-name "{}" --resource-group {}'.format(name, self.vm_name,
                                                     self.resource_group)
        run_cmd_local(cmd, is_log_ret=True)

    def disk_attach(self, name, size, new=True):
        cmd = 'az vm disk attach --name {} --vm-name "{}" '\
              '--resource-group {} --size-gb {}'\
              .format(name, self.vm_name, self.resource_group, size)
        if new:
            cmd += " --new"
        run_cmd_local(cmd, is_log_ret=True)

    def disk_detach(self, name):
        cmd = 'az vm disk detach --name {} --vm-name "{}" '\
              '--resource-group {}'.format(name, self.vm_name,
                                           self.resource_group)
        run_cmd_local(cmd, is_log_ret=True)

    def user_update(self, username, password=None, ssh_key_value=None):
        cmd = 'az vm user update --name "{}" \
--resource-group {} --username {}'.format(self.vm_name, self.resource_group,
                                          username)
        if ssh_key_value:
            cmd += ' --ssh-key-value "{}"'.format(ssh_key_value)
        if password:
            cmd += ' --password "{}"'.format(password)
        run_cmd_local(cmd, is_log_ret=True)

    def user_reset_ssh(self, timeout=1200):
        cmd = 'az vm user reset-ssh --name "{}" --resource-group {}'\
              .format(self.vm_name, self.resource_group)
        run_cmd_local(cmd, timeout=timeout, is_log_ret=True)

    def run_command(self,
                    command_id="RunShellScript",
                    scripts=None,
                    parameters=None):
        cmd = 'az vm run-command invoke --name "{}" --resource-group {} \
--command-id {}'.format(self.vm_name, self.resource_group, command_id)
        if scripts:
            cmd += ' --scripts \'{}\''.format(scripts)
        if parameters:
            cmd += ' --parameters \'{}\''.format(parameters)
        _, out = run_cmd_local(cmd, is_log_ret=True)
        return json.loads(out).get("value")[0].get("message")

    def extension_set(self,
                      name,
                      publisher,
                      settings='',
                      protected_settings=''):
        cmd = 'az vm extension set --name "{}" --vm-name "{}" \
--resource-group {} --publisher "{}"'.format(name, self.vm_name,
                                             self.resource_group, publisher)
        if protected_settings:
            cmd += " --protected-settings '{}'".format(protected_settings)
        if settings:
            cmd += " --settings '{}'".format(settings)
        run_cmd_local(cmd, is_log_ret=True)

    def extension_delete(self, name):
        cmd = 'az vm extension delete --name "{}" --vm-name "{}" \
--resource-group {}'.format(name, self.vm_name, self.resource_group)
        run_cmd_local(cmd, is_log_ret=True)

    @property
    def public_ip(self):
        return self.properties.get("publicIps")

    @property
    def floating_ip(self):
        return self.public_ip

    def __str__(self):
        return "[Name]:{}|[Resource_Group]:{}|[Image]:{}|[size]:{}|[Admin_username]:{}\
        ".format(self.vm_name, self.resource_group, self.vm_image, self.vm_size,
                 self.vm_username)

    def get_console_log(self, silent=False):
        '''
        az vm boot-diagnostics get-boot-log -n vmName -g resourceGroupName
        az vm boot-diagnostics enable --name MyVirtualMachine --resource-group MyResourceGroup --storage https://mystor.blob.core.windows.net/
        '''
        out = None
        try:
            LOG.info("try to retrive console log of {}".format(self.vm_name))
            cmd = 'az vm boot-diagnostics enable --name {} --resource-group {} --storage {}'.format(self.vm_name, self.resource_group, self.storage_account)
            _, out = run_cmd_local(cmd, is_log_ret=True)
            cmd = 'az vm boot-diagnostics get-boot-log -n {} --resource-group {}'.format(self.vm_name, self.resource_group)
            _, out = run_cmd_local(cmd, is_log_ret=True)
        except Exception as err:
            LOG.error(err)
            return err
        return out

    def attach_block(self):
        raise NotImplemented('please check resources_azure.py')

    def attach_nic(self):
        raise NotImplemented('please check resources_azure.py')

    def detach_block(self):
        raise NotImplemented('please check resources_azure.py')

    def detach_nic(self):
        raise NotImplemented('please check resources_azure.py')

    def disk_count(self):
        cmd = 'az vm show --name "{}" --resource-group {} -d  '\
            '--query "length(storageProfile.dataDisks)"'.format(self.vm_name, self.resource_group)
        ret, out = run_cmd_local(cmd, is_log_ret=True)
        return out

    def get_state(self):
        LOG.info(self.properties.get("powerState"))
        return self.properties.get("powerState")

    def is_exist(self):
        raise NotImplemented('please check resources_azure.py')

    def is_paused(self):
        raise NotImplemented('please check resources_azure.py')

    def pause(self):
        raise NotImplemented('please check resources_azure.py')

    def send_hibernation(self):
        raise NotImplemented('please check resources_azure.py')

    def unpause(self):
        raise NotImplemented('please check resources_azure.py')

    def send_nmi(self):
        raise NotImplemented('please check resources_azure.py')

    @property
    def net_bandwidth(self):
        return self.net_bandwidth_cfg


######################################################################
# Below code is in todo list to migrate avocado-cloud to os-tests.
# Keep them as reference for call az command.
# Some of them are not required anymore, it is pending on project.
#####################################################################
class AzureGroup(BaseResource):
    def __init__(self, params, **kwargs):
        super(AzureGroup, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.name = params.get("resource_group",
                               "*/vm_sizes/{}/*".format(size))
        self.location = params.get("location", "*/vm_sizes/{}/*".format(size))
        # After the resource group creating,below properties will be setted
        self.id = None
        self.properties = None
        # self.managedby = None
        # self.tags = None

    def create(self):
        cmd = 'az group create --location "{}" --resource-group "{}"'.format(
            self.location, self.name)
        _, out = run_cmd_local(cmd)
        if len(out):
            info = json.loads(out)
            self.id = info["id"]
            self.properties = info["properties"]
            return True

    def delete(self, wait=False):
        cmd = 'az group delete --resource-group "{}" -y'.format(self.name)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd)
        return True

    def show(self):
        cmd = 'az group show --resource-group "{}"'.format(self.name)
        try:
            _, out = run_cmd_local(cmd)
        except:
            return False
        if len(out):
            info = json.loads(out)
            self.id = info["id"]
            self.properties = info["properties"]
            return True

    def update(self):
        pass

    @staticmethod
    def list(location=None):
        cmd = "az group list"
        if location:
            cmd += " --query \"[?location=='{}']\"".format(location)
        _, out = run_cmd_local(cmd)
        return json.loads(out)

    def exists(self):
        cmd = 'az group exists --resource-group "{}"'.format(self.name)
        _, out = run_cmd_local(cmd)
        # return true or false
        return out


class AzureStorage(StorageResource):
    def __init__(self, params):
        pass


class AzureVNET(NetworkResource):
    def __init__(self, params):
        pass


class AzureSubnet(BaseResource):
    def __init__(self, params, **kwargs):
        super(AzureSubnet, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        self.vnet = self.resource_group
        self.name = kwargs.get("name", self.vnet)
        # After the subnet is created, properties below will be set
        self.id = None
        self.properties = None
        # self.tags = None


class AzureNIC(BaseResource):
    basecli = 'az network nic'

    def __init__(self, params, **kwargs):
        super(AzureNIC, self).__init__(params)
        '''
        :param: publicip: If set publicip name, this publicip will be assigned
                          to NIC while creating
        :param: sriov: true/false. If set true, accelerated-networking will be
                       enabled while creating NIC
        :param: ip_version: IPv4/IPv6
        '''
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        self.vnet = kwargs.get("vnet", self.resource_group)
        self.subnet = kwargs.get("subnet", self.vnet)
        timestamp = time.strftime("%m%d%H%M%S", time.localtime())
        self.name = kwargs.get("name", self.subnet + timestamp)
        self.publicip = kwargs.get("publicip")
        self.sriov = kwargs.get("sriov")
        self.ip_version = kwargs.get("ip_version")
        # After it is created, properties below will be set
        self.id = None
        self.properties = None
        # self.tags = None

    def create(self):
        cmd = self.basecli + ' create --name "{}" --resource-group "{}" '\
            '--vnet-name {} --subnet {}'.format(
                self.name, self.resource_group, self.vnet, self.subnet)
        if self.publicip:
            cmd += " --public-ip-address {}".format(self.publicip)
        if self.sriov:
            cmd += " --accelerated-networking {}".format(self.sriov)
        if self.ip_version:
            cmd += " --private-ip-address-version {}".format(self.ip_version)
        _, out = run_cmd_local(cmd)
        if len(out):
            info = json.loads(out).get("NewNIC")
            self.id = info["id"]
            self.properties = info
            return True

    def delete(self, wait=False):
        cmd = self.basecli + \
            ' delete --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd)
        return True

    def show(self):
        cmd = self.basecli + \
            ' show --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        try:
            _, out = run_cmd_local(cmd)
        except:
            return False
        if len(out):
            info = json.loads(out)
            self.id = info["id"]
            self.properties = info
            return True

    def update(self):
        self.show()

    def list(self):
        cmd = self.basecli + " list"
        _, out = run_cmd_local(cmd)
        return json.loads(out)

    def exists(self):
        return self.show()


class AzurePublicIP(BaseResource):
    basecli = 'az network public-ip'

    def __init__(self, params, **kwargs):
        """
        :param: name:[REQUIRED]publicip name
        :param: ip_version: IPv4/IPv6
        """
        super(AzurePublicIP, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        timestamp = time.strftime("%m%d%H%M%S", time.localtime())
        self.name = kwargs.get("name", self.resource_group + timestamp)
        self.ip_version = kwargs.get("ip_version")
        # After it is created, properties below will be set
        self.id = None
        self.properties = None
        # self.tags = None

    def create(self):
        cmd = self.basecli + \
            ' create --name "{}" --resource-group "{}"'.format(
                self.name, self.resource_group)
        _, out = run_cmd_local(cmd)
        if len(out):
            info = json.loads(out).get("publicIp")
            self.id = info["id"]
            self.properties = info
            return True

    def delete(self, wait=False):
        cmd = self.basecli + \
            ' delete --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd)
        return True

    def show(self):
        cmd = self.basecli + \
            ' show --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        try:
            _, out = run_cmd_local(cmd)
        except:
            return False
        if len(out):
            info = json.loads(out)
            self.id = info["id"]
            self.properties = info
            return True

    def update(self):
        self.show()

    def list(self):
        cmd = self.basecli + " list"
        _, out = run_cmd_local(cmd)
        return json.loads(out)

    def exists(self):
        return self.show()


class AzureNicIpConfig(BaseResource):
    basecli = 'az network nic ip-config'

    def __init__(self, params, **kwargs):
        """
        :param: name:[REQUIRED]ip-config name
        :param: nic_name:[REQUIRED]The NIC name this ip-config will be added to
        :param: ip_version: IPv4/IPv6
        """
        super(AzureNicIpConfig, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        timestamp = time.strftime("%m%d%H%M%S", time.localtime())
        self.name = kwargs.get("name", self.resource_group + timestamp)
        self.nic_name = kwargs.get("nic_name")
        self.vnet = kwargs.get("vnet", self.resource_group)
        self.subnet = kwargs.get("subnet", self.vnet)
        if not self.nic_name:
            raise Exception("Not specify NIC name")
        self.ip_version = kwargs.get("ip_version")
        # After it is created, properties below will be set
        self.id = None
        self.properties = None
        # self.tags = None

    def create(self):
        cmd = self.basecli + ' create --name "{}" --resource-group "{}" '\
            '--nic-name {} --vnet-name {} --subnet {}'.format(self.name,
                                                              self.resource_group, self.nic_name,
                                                              self.vnet, self.subnet)
        if self.ip_version:
            cmd += ' --private-ip-address-version {}'.format(self.ip_version)
        _, out = run_cmd_local(cmd)
        if len(out):
            info = json.loads(out)
            self.id = info["id"]
            self.properties = info
            return True

    def delete(self, wait=False):
        cmd = self.basecli + ' delete --name {} --resource-group "{}" '\
            '--nic-name {}'.format(self.name,
                                   self.resource_group, self.nic_name)
        if not wait:
            cmd += " --no-wait"
        run_cmd_local(cmd)
        return True

    def show(self):
        cmd = self.basecli + ' show --name {} --resource-group "{}" '\
            '--nic-name {}'.format(self.name,
                                   self.resource_group, self.nic_name)
        try:
            _, out = run_cmd_local(cmd)
        except:
            return False
        if len(out):
            info = json.loads(out)
            self.id = info["id"]
            self.properties = info
            return True

    def update(self):
        self.show()

    def list(self):
        cmd = self.basecli + " list"
        _, out = run_cmd_local(cmd)
        return json.loads(out)

    def exists(self):
        return self.show()


class AzureImage(BaseResource):
    basecli = 'az image'

    def __init__(self, params, **kwargs):
        """
        :param: name:[REQUIRED]image name
        :param: source:[REQUIRED]The source(.vhd url) of the image
        """
        super(AzureImage, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        vhd_name = params.get("image", "*/VM/*")
        storage_account = params.get("storage_account",
                                     "*/vm_sizes/{}/*".format(size))
        self.source = "https://{}.blob.core.windows.net/vhds/{}"\
                      .format(storage_account, vhd_name)
        timestamp = time.strftime("%m%d%H%M%S", time.localtime())
        self.generation = kwargs.get("generation", "V1")
        self.name = kwargs.get("name", "{}-{}-{}".format(vhd_name.replace(".vhd", ''),
                               self.generation, timestamp))
        # After it is created, properties below will be set
        self.id = None
        self.properties = None

    def create(self):
        cmd = self.basecli + ' create --name "{}" --resource-group "{}" '\
            '--source {} --hyper-v-generation {} --os-type linux'.format(
                self.name, self.resource_group, self.source, self.generation)
        _, out = run_cmd_local(cmd)
        if len(out):
            info = json.loads(out)
            self.id = info["id"]
            self.properties = info
            return True

    def delete(self):
        cmd = self.basecli + ' delete --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        run_cmd_local(cmd)
        return True

    def show(self):
        cmd = self.basecli + ' show --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        try:
            _, out = run_cmd_local(cmd)
        except:
            return False
        if len(out):
            info = json.loads(out)
            self.id = info["id"]
            self.properties = info
            return True

    def update(self):
        self.show()

    def list(self):
        cmd = self.basecli + " list"
        _, out = run_cmd_local(cmd)
        return json.loads(out)

    def exists(self):
        return self.show()



