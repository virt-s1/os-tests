"""
This module is used for converting linux 'virt-install' and 'virsh' command to python function
Please install virt-install and virsh firstly.
"""
import logging
import os
import psutil
import os_tests
import time
from .resources import BaseResource, VMResource
from os_tests.libs import utils_lib
from os_tests.libs.utils_lib import run_cmd_local,get_properties


LOG = logging.getLogger('os_tests.os_tests_run')
logging.basicConfig(level=logging.INFO)

class KvmVM(VMResource):
    def __init__(self, params, **kwargs):
        super(KvmVM, self).__init__(params)
        self.vm_name = params['VM'].get('vm_name')
        self.image_name = params['VM'].get('image_name')
        self.image_dir = params['VM'].get('image_dir')
        self.disk_path = params['VM'].get('disk_path')
        self.os_variant = params['VM'].get('os_variant')
        self.nocloud_iso_name = params['VM'].get('nocloud_iso_name')
        self.files_path = "./configs"
        #create directory
        os.makedirs(self.files_path, exist_ok=True)
        self.isofile = "{}/{}".format(self.disk_path, self.nocloud_iso_name)
        self.console_log = "/tmp/console_{}.log".format(self.vm_name)

        self.run_uuid = params.get('run_uuid')
        # VM access parameters
        self.rhel_ver = params['VM'].get('rhel_ver')
        self.vm_username = params['VM'].get('username')
        self.vm_password = params['VM'].get('password')
        self.ssh_pubkey = utils_lib.get_public_key()
        self.interface_name = params['VM'].get('interface_name')
        self.properties = {}
        self.httpport = utils_lib.HTTP_PORT
        self.static_ip = None

        # VM creation parameter user_data
        self.user_data = None

        # VM creation parameter for rhsm subscription related cases
        self.subscription_username = params['Subscription'].get('username')
        self.subscription_password = params['Subscription'].get('password')
        self.subscription_baseurl = params['Subscription'].get('baseurl')
        self.subscription_serverurl = params['Subscription'].get('serverurl')

    @property
    @utils_lib.wait_for(not_ret='', ck_not_ret=True, timeout=120, interval=10)
    def floating_ip(self):
        if self.static_ip:
            return self.static_ip
        f_ip = ''
        cmd = "sudo virsh domifaddr {} --source arp | awk '{{print $4}}' | sed -n '3p' ".format(self.vm_name)
        try:
            status, out = run_cmd_local(cmd, is_log_ret=True)
        except Exception as err:
            LOG.info(err)
        if len(out) > 1 and status == 0:
            f_ip = out.split("/")[0]
            LOG.info("ip is %s" % f_ip)
            #when using smbios, the IP is changed in init-network stage
            #sudo ip neigh flush all, Clears old ARP cache
            #ping -c 4 <IP>, Forces ARP update
            cmd1 = "sudo ip neigh flush all"
            run_cmd_local(cmd1, is_log_ret=True)
            cmd2 = "ping -c 4 {}".format(f_ip)
            run_cmd_local(cmd2, is_log_ret=True)
            #check if the IP can be ssh connected
            cmd3 = "nc -zv {} 22".format(f_ip)
            status1, _ = run_cmd_local(cmd3, is_log_ret=True)
            if status1 != 0:
                LOG.info("Clears old ARP cache and forces ARP update!")  
                run_cmd_local(cmd1, is_log_ret=True)
                run_cmd_local(cmd2, is_log_ret=True)
                f_ip = ''
        return f_ip

    def create(self, wait=True, userdata=None, sshkey=None, datasource=None, networks=[("virbr1","")]):
        # the CI job would save rhel guest image to /var/lib/libvirt/images/backup
        # copy the image from /var/lib/libvirt/images/backup to /var/lib/libvirt/images
        cmd1 = "sudo cp {0}/{1} {2}/{1}".format(self.image_dir, self.image_name, self.disk_path)
        run_cmd_local(cmd1, is_log_ret=True)
        cmd2 = "sudo virt-install --name {} --disk {}/{},device=disk,bus=virtio,format=qcow2 " \
            "--os-variant {} "\
            "--console log.file={} "\
            .format(self.vm_name, self.disk_path, self.image_name, self.os_variant, self.console_log)

        #networks including network name and mac, for example [("virbr1","")] or [("br-mgmt","")("br-prov","")]
        if networks is not None:
            for network,mac in networks:
                if mac != "":
                    cmd2 += "--network bridge={},model=virtio,mac={} ".format(network,mac)
                else:
                    cmd2 += "--network bridge={},model=virtio ".format(network)
        #--cloud-init user-data and clouduser-ssh-key can not use at the same time
        #--cloud-init do not support reboot because of missing the one time cloud-init media
        # meant for initial VM configuration,
        # that is, virt-install forcing shutdown for the first reboot is intended behavior,
        # so we cannot use --cloud-init as we have mutiple cases with reboot.
        # solution: using cdrom instead of --cloud-init

        if datasource == "cdrom":
            cmd2 += "--disk path={}/{},device=cdrom ".format(self.disk_path,self.nocloud_iso_name)
        elif datasource == "smbios":
            cmd2 += "--sysinfo system.serial='ds=nocloud;s=http://10.0.2.1:8000/' "
        else:
            #userdata, using this way to compatible with other cloud platform
            #--cloud-init,cdrom and smbios can not set at the same time,
            #now it supports user-data, meta-data, network-config and clouduser-ssh-key and so on.'
            userdata = userdata or self.user_data
            if userdata:
                self.create_datafile(
                    datasource="cdrom",
                    userdata=userdata,
                    metadata=""
                )
                cmd2 += "--disk path={}/{},device=cdrom ".format(self.disk_path,self.nocloud_iso_name)

        cmd2 += "--graphics none  --import --noautoconsole"
        run_cmd_local(cmd2, is_log_ret=True)
        time.sleep(30) 
        f_ip = self.floating_ip
        if f_ip != '':
            return self.exists()
        else:
            return False

    def delete(self, wait=True):
        cmd1 = "sudo virsh destroy {}".format(self.vm_name)
        run_cmd_local(cmd1, is_log_ret=True)
        cmd2 = "sudo virsh undefine {}".format(self.vm_name)
        run_cmd_local(cmd2, is_log_ret=True)
        if wait:
            error_message = "Timed out waiting for server to get deleted."
            for count in utils_lib.iterate_timeout(100, error_message, wait=10):
                if not self.exists():
                    break
        # remove the image
        cmd3 = "sudo rm {}/{}".format(self.disk_path, self.image_name)
        run_cmd_local(cmd3, is_log_ret=True)

        #do we need remove data file here?
        self.delete_datafile()

    def exists(self):
        cmd = "sudo virsh dominfo {} ".format(self.vm_name)
        try:
            status, out = run_cmd_local(cmd, is_log_ret=True)
            if len(out)>1 and status == 0:
                self.properties = get_properties(out)
                return True
        except Exception as err:
            LOG.info(err)
            return False
        return False

    def show(self):
        if self.exists():
            LOG.info("Instance ID: {}".format(self.properties.get("UUID")))
        else:
            LOG.info("the vm instance does not exist")

    def start(self, wait=False):
        cmd = "sudo virsh start {}".format(self.vm_name)
        run_cmd_local(cmd, is_log_ret=True)

    def stop(self, wait=False):
        cmd = "sudo virsh shutdown {}".format(self.vm_name)
        run_cmd_local(cmd, is_log_ret=True)

    def reboot(self, wait=False):
        raise NotImplementedError

    def pause(self, wait=False):
        raise NotImplementedError

    def unpause(self, wait=False):
        raise NotImplementedError

    def get_state(self):
        if self.exists():
            return self.properties.get("State")

    def is_started(self):
        if self.exists():
            return self.get_state() == "running"

    def is_stopped(self):
        if self.exists():
            return self.get_state() == "shut off"

    def is_paused(self):
        return self.get_state() == "paused"

    def get_console_log(self, silent=False):
        out = None
        cmd = "sudo cat {}".format(self.console_log)
        try:
            _, out = run_cmd_local(cmd, is_log_ret=True)
        except Exception as err:
            LOG.info(err)
        return out

    def disk_count(self):
        raise NotImplementedError

    def send_nmi(self):
        raise NotImplementedError

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

    def create_datafile(self, datasource, userdata, metadata, networkconfig=None):
        #create data file, userdata and metadata can not be None
        userdatafilename = self.files_path+"/user-data"
        with open(userdatafilename, 'w') as userdatafile:
            userdatafile.write(userdata)
        metadatafilename = self.files_path+"/meta-data"
        with open(metadatafilename, 'w') as metadatafile:
            metadatafile.write(metadata)
        networkfilename = self.files_path+"/network-config"
        if networkconfig is not None:
            with open(networkfilename, 'w') as networkconfigfile:
                networkconfigfile.write(networkconfig)
        else:
            #clean the data or it would effect other case, for example network-config would be added to the case without network-config
            if os.path.exists(networkfilename):
                os.remove(networkfilename)
            networkfilename = ""
        if datasource == "cdrom":
            #create iso file in /var/lib/libvirt/images/
            cmd = "sudo genisoimage -output {} -volid CIDATA -joliet -rock  {} {} {}".format(self.isofile, userdatafilename, metadatafilename, networkfilename)
            run_cmd_local(cmd,is_log_ret=True)
        elif datasource == "smbios":
            # check if the http server is not started, start it
            if not self.is_httpserver_running():
                cmd = "nohup python3 -m http.server {} --directory {} > httpserver.log 2>&1 &".format(self.httpport,self.files_path)
                run_cmd_local(cmd,is_log_ret=True)
        return True
    
    def delete_datafile(self):
        cmd = "sudo rm {}".format(self.isofile)
        run_cmd_local(cmd,is_log_ret=True)
        cmd = "rm {}/*".format(self.files_path)
        run_cmd_local(cmd,is_log_ret=True)
        return True

    def is_httpserver_running(self):
        """Check if a process is using the given port."""
        for conn in psutil.net_connections():
            if conn.laddr.port == self.httpport:
                return True
        return False


class KvmNet(BaseResource):
    def __init__(self, params, **kwargs):
        super(KvmNet, self).__init__(params)
        self.netname = kwargs.get("netname") if "netname" in kwargs else params.get('VM').get("net_name")
        self.netfile = os.path.dirname(os_tests.__file__) + "/data/kvm/{}.xml".format(self.netname)
        self.properties = {}

    def create(self):
        # cannot start network without root user
        cmd1 = "sudo virsh net-define {}".format(self.netfile)
        run_cmd_local(cmd1,is_log_ret=True)
        cmd2 = "sudo virsh net-start {}".format(self.netname)
        run_cmd_local(cmd2,is_log_ret=True)
        return True

    def delete(self):
        cmd1 = "sudo virsh net-destroy {}".format(self.netname)
        run_cmd_local(cmd1,is_log_ret=True)
        cmd2 = "sudo virsh net-undefine {}".format(self.netname)
        run_cmd_local(cmd2,is_log_ret=True)
        return True

    def start(self):
        cmd = "sudo virsh net-start {}".format(self.netname)
        run_cmd_local(cmd,is_log_ret=True)
        return True

    def get_state(self):
        if self.exists():
            return self.properties.get("Active")

    def exists(self):
        cmd = "sudo virsh net-info {} ".format(self.netname)
        try:
            status, out = run_cmd_local(cmd, is_log_ret=True)
            if len(out)>1 and status == 0:
                self.properties = get_properties(out)
                return True
        except Exception as err:
            LOG.info(err)
            return False
        return False

    def is_exist(self):
        return self.exists()

    def show(self):
        if self.exists():
            LOG.info("network id : {}".format(self.properties.get("UUID")))
        else:
            LOG.info("the network does not exist")
