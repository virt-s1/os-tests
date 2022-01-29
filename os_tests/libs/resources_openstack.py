from .resources import VMResource,UnSupportedAction,UnSupportedStatus
from os_tests.libs import utils_lib
import logging
import time
import sys
import logging
import base64
try:
    import openstack
    from openstack.exceptions import InvalidRequest
    openstack.enable_logging(debug=False)
except ImportError as err:
    print("Please install python-openstackclient module if run openstack test")
    sys.exit(1)

LOG = logging.getLogger('os_tests.os_tests_run')
logging.basicConfig(level=logging.DEBUG)

class OpenstackVM(VMResource):
    def __init__(self, params, **kwargs):
        super(OpenstackVM, self).__init__(params)
        self._data = None

        # Openstack connection credentials
        auth_url = params['Cloud'].get('auth_url')
        project_name = params['Cloud'].get('project_name')
        project_domain_name = params['Cloud'].get('project_domain_name')
        user_domain_name = params['Cloud'].get('user_domain_name')
        username = params['Credential'].get('username')
        password = params['Credential'].get('password')

        self.conn = openstack.connect(auth_url=auth_url,
                                      project_name=project_name,
                                      project_domain_name=project_domain_name,
                                      user_domain_name=user_domain_name,
                                      username=username,
                                      password=password)

        # VM creation parameters
        self.vm_name = params['VM'].get('vm_name')
        self.image_name = params['VM'].get('image_name')
        self.network_name = params['VM'].get('network_name')
        self.network_id = params['VM'].get('network_id')
        self.floating_network_id = params['VM'].get('floating_network_id')
        self.flavor = params['Flavor'].get('name')
        self.flavor_id = params['Flavor'].get('id')
        self.size = params['Flavor'].get('size')
        self.keypair = params['VM'].get('keypair')
        self.run_uuid = params.get('run_uuid')
        self.user_data = "#!/bin/bash\nmkdir /tmp/userdata_{}".format(self.run_uuid)
        self.config_drive = None
        self.second_nic_id = None

        # VM creation timeout
        self.create_timeout = kwargs.get("create_timeout")

        # VM access parameters
        self.vm_username = params['VM'].get('username')
        self.vm_password = params['VM'].get('password')

        self.arch = 'x86_64'

    @property
    def data(self):
        if not self._data:
            self.data = self.vm_name
        return self._data

    @data.setter
    def data(self, name):
        for server in self.conn.compute.servers(name=name):
            self._data = server

    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120, interval=10)
    def floating_ip(self):
        f_ip = None
        self.data = self.vm_name
        for net in self.data.addresses.values():
            for ip in net:
                if ip['OS-EXT-IPS:type'] == 'floating':
                    f_ip = ip['addr']
                elif ip['OS-EXT-IPS:type'] == 'fixed' and  ip['version']== 4:
                    f_ip = ip['addr']
        return f_ip

    @property
    @utils_lib.wait_for(not_ret=None, ck_not_ret=True, timeout=120)
    def ipv6_address(self):
        raise NotImplementedError

    def create(self, wait=False, auto_ip=True):
        #https://docs.openstack.org/api-ref/compute/?expanded=create-server-detail
        try:
            image_id = self.conn.compute.find_image(self.image_name).id
        except AttributeError as err:
            LOG.info("cannot retrive image id from given image_name")
            return None

        args = {
            'name': self.vm_name,
            'image_id': image_id,
            'flavor_id': self.flavor_id,
            'networks': [{
                "uuid": self.network_id
            }]
        }
        if self.keypair:
            args['key_name'] = self.keypair
        if self.user_data:
            x = base64.b64encode(self.user_data.encode())
            args['user_data'] = x.decode("ascii")
        if self.config_drive:
            args['config_drive']= True
        if self.second_nic_id:
            args['networks'].append({"uuid": self.second_nic_id })

        server = self.conn.compute.create_server(**args)

        if wait:
            if self.create_timeout:
                server = self.conn.compute.wait_for_server(
                    server=server, wait=self.create_timeout)
            else:
                server = self.conn.compute.wait_for_server(server)
            if auto_ip and self.floating_network_id != '':
                f_ip = self.conn.network.create_ip(
                    floating_network_id=self.floating_network_id)
                self.conn.compute.add_floating_ip_to_server(
                    server, f_ip.floating_ip_address)
        self._data = None

    def delete(self, wait=False):
        f_ip = self.floating_ip
        try:
            if f_ip and self.floating_network_id != '':
                f_ip_id = self.conn.network.find_ip(f_ip)
                self.conn.network.delete_ip(f_ip_id)
        except InvalidRequest as err:
            LOG.info(err)

        self.conn.compute.delete_server(self.data.id)

        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get deleted."):
                if not self.exists():
                    break

    def start(self, wait=False):
        self.conn.compute.start_server(self.data.id)
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get started."):
                if self.is_started():
                    break

    def stop(self, wait=False):
        self.conn.compute.stop_server(self.data.id)
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get stopped."):
                if self.is_stopped():
                    break

    def reboot(self, wait=False):
        self.conn.compute.reboot_server(self.data.id, 'SOFT')
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get rebooted."):
                if self.is_started():
                    break

    def pause(self, wait=False):
        self.conn.compute.pause_server(self.data.id)
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get paused."):
                if self.is_paused():
                    break

    def unpause(self, wait=False):
        self.conn.compute.unpause_server(self.data.id)
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get unpaused."):
                if self.is_started():
                    break

    def is_exist(self):
        count = sum(1 for i in self.conn.compute.servers(name=self.vm_name))
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self.data = self.vm_name
        return self.data.status

    def get_state(self):
        self.data = self.vm_name
        return self.data.status

    def is_started(self):
        return self._get_status() == 'ACTIVE'

    def is_stopped(self):
        return self._get_status() == 'SHUTOFF'

    def is_paused(self):
        return self._get_status() == 'PAUSED'

    def show(self):
        return self.data
    
    def get_console_log(self):
        try:
            output = self.conn.compute.get_server_console_output(self.data.id).get('output')
            return True, output
        except Exception as err:
            LOG.error("Failed to get console log! %s" % err)
            return False, err

    @property
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