from .resources import VMResource, StorageResource, NetworkResource, UnSupportedAction, UnSupportedStatus
from os_tests.libs import utils_lib
import sys
import re
import os
try:
    import libvirt
    import xml.etree.ElementTree as ET
except ImportError as err:
    print("Please install libvirt-python module if run libvirt test")
    sys.exit(1)


class LibvirtVM(VMResource):

    def __init__(self, params):
        super(LibvirtVM, self).__init__(params)
        self._data = None

        uri = params['Cloud'].get('uri')

        self.conn = libvirt.open(uri)

        # VM creation parameters
        self.vm_name = params['VM'].get('vm_name')
        self.image_name = params['VM'].get('image_name')
        self.nocloud_iso_name = params['VM'].get('nocloud_iso_name')
        self.image_dir = params['VM'].get('image_dir')
        self.arch = params['VM'].get('arch')
        if not self.arch:
            self.arch = re.search(r'\.([^.]+)\.[^.]+$',
                                  self.image_name).group(1)
        self.flavor = params['Flavor'].get('name')
        self.vcpus = params['Flavor'].get('cpu')
        self.memory = params['Flavor'].get('memory')
        self.size = params['Flavor'].get('size')
        self.user_data = None

        # VM access parameters
        self.vm_username = params['VM'].get('username')
        self.vm_password = params['VM'].get('password')

    @property
    def data(self):
        if not self._data:
            self.data = self.vm_name
        return self._data

    @data.setter
    def data(self, name):
        for dom in self.conn.listAllDomains():
            if dom.name() == name:
                self._data = {"uuid": dom.UUIDString()}

    @property
    def floating_ip(self):
        f_ip = None
        uuid = self.data.get("uuid")
        dom = self.conn.lookupByUUIDString(uuid)
        net = dom.interfaceAddresses(
            libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE, 0)

        for k, v in net.items():
            if v["addrs"]:
                for ipaddr in v["addrs"]:
                    f_ip = ipaddr["addr"]
        return f_ip

    def create(self, wait=True):
        root = ET.fromstring(dom_xml)
        if self.arch == "x86_64":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "pc")
        elif self.arch == "ppc64le":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "pseries")
        elif self.arch == "s390x":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "s390-ccw-virtio")
        elif self.arch == "aarch64":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "virt")
            sub_cpu = ET.fromstring(
                '<cpu mode="host-passthrough"><model fallback="allow" /></cpu>'
            )
            root.insert(3, sub_cpu)
            sub_loader = ET.fromstring('<loader readonly="yes" type="pflash">\
/usr/share/AAVMF/AAVMF_CODE.fd</loader>')
            root.find("os").insert(0, sub_loader)
            sub_nvram = ET.fromstring(
                "<nvram template='/usr/share/AAVMF/AAVMF_VARS.fd'>\
%s/OVMF_VARS.fd</nvram>" % self.image_dir)
            root.find("os").insert(0, sub_nvram)
            root.find("devices").find("rng").find(
                "backend").text = "/dev/urandom"
        else:
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "pc")
        root.find("name").text = self.vm_name
        root.find("vcpu").text = str(self.vcpus)
        root.find("memory").text = str(self.memory * 1024 * 1024)
        root.find("currentMemory").text = str(self.memory * 1024 * 1024)
        root.find("devices").find("disk[@device='disk']").find("source").set(
            "file", os.path.join(self.image_dir, self.image_name))
        root.find("devices").find("disk[@device='cdrom']").find("source").set(
            "file", os.path.join(self.image_dir, self.nocloud_iso_name))
        xmlconfig = ET.tostring(root).decode()
        dom = self.conn.defineXML(xmlconfig)
        dom.create()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get Created."):
                if self.exists() and self.floating_ip:
                    break
        self._data = None

    def delete(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        if not self.is_stopped():
            dom.destroy()
        dom.undefineFlags(libvirt.VIR_DOMAIN_UNDEFINE_NVRAM)
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get deleted."):
                if not self.exists():
                    break

    def start(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.create()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get started."):
                if self.is_started():
                    break

    def stop(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.shutdown()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get stopped."):
                if self.is_stopped():
                    break

    def reboot(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.reboot()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get rebooted."):
                if self.is_started():
                    break

    def pause(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.suspend()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get paused."):
                if self.is_paused():
                    break

    def unpause(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.resume()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get unpaused."):
                if self.is_started():
                    break

    def exists(self):
        self._data = None
        if self.data is None:
            return False
        count = sum(1 for i in self.data)
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self.data = self.vm_name
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        state, reason = dom.state()
        return state

    def is_started(self):
        return self._get_status() == libvirt.VIR_DOMAIN_RUNNING

    def is_stopped(self):
        return self._get_status() == libvirt.VIR_DOMAIN_SHUTOFF

    def is_paused(self):
        return self._get_status() == libvirt.VIR_DOMAIN_PAUSED

    def show(self):
        return self.data

    def get_console_log(self):
        raise NotImplementedError

    def disk_count(self):
        raise NotImplementedError

    def get_state(self):
        raise NotImplementedError

    def send_nmi(self):
        raise UnSupportedAction('No such operation in libvirt')

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
        raise NotImplementedError


dom_xml = """
<domain type='kvm'>
  <name>rhel</name>
  <memory unit='KiB'>1048576</memory>
  <currentMemory unit='KiB'>1048576</currentMemory>
  <vcpu>1</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough'/>
  <devices>
    <emulator>/usr/libexec/qemu-kvm</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/tmp/rhel-guest-image.qcow2'/>
      <target dev='sda' bus='scsi'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/tmp/nocloud.iso'/>
      <target dev='sdb'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='default' bridge='virbr0'/>
      <target dev='vnet0'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'/>
    <console type='pty'/>
    <channel type='unix'>
       <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <rng model='virtio'>
      <rate period='2000' bytes='1234'/>
      <backend model='random'>/dev/random</backend>
    </rng>
  </devices>
</domain>
"""
