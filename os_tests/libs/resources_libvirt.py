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
        self.rhel_ver = params['VM'].get('rhel_ver')
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

        self.console_log = '/tmp/console'+self.rhel_ver+'.log'
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

    @property
    def is_secure_boot(self):
        if self.arch == "x86_64":
            return True
        return False

    @property
    def is_uefi_boot(self):
        if self.arch == "x86_64" or self.arch == 'aarch64':
            return True
        return False

    def create(self, wait=True):
        root = ET.fromstring(dom_xml)
        acpi = ET.fromstring("<acpi/>")
        if self.arch == "x86_64":
            root.find("os").find("type").set("arch", self.arch)
            root.find("features").insert(0, acpi)
            if float(self.rhel_ver) >= 8.2:
                root.find("os").find("type").set("machine", "q35")
                sub_loader = ET.fromstring("<loader readonly='yes' \
secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.secboot.fd</loader>")
                root.find("os").insert(0, sub_loader)
                sub_nvram = ET.fromstring(
                    "<nvram template='/usr/share/OVMF/OVMF_VARS.secboot.fd'>\
%s/OVMF_VARS.secboot.fd</nvram>" % self.image_dir)
                root.find("os").insert(0, sub_nvram)
                sub_smm = ET.fromstring("<smm state='on'/>")
                root.find("features").insert(0, sub_smm)
        elif self.arch == "ppc64le":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "pseries")
            root.find("features").insert(0, acpi)
        elif self.arch == "s390x":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "s390-ccw-virtio")
        elif self.arch == "aarch64":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "virt")
            root.find("features").insert(0, acpi)
            sub_cpu = ET.fromstring(
                "<cpu mode='host-passthrough'/>"
            )
            root.insert(3, sub_cpu)
            sub_loader = ET.fromstring("<loader readonly='yes' type='pflash'>\
/usr/share/AAVMF/AAVMF_CODE.fd</loader>")
            root.find("os").insert(0, sub_loader)
            sub_nvram = ET.fromstring(
                "<nvram template='/usr/share/AAVMF/AAVMF_VARS.fd'>\
%s/AAVMF_VARS.fd</nvram>" % self.image_dir)
            root.find("os").insert(0, sub_nvram)
        else:
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "pc")
            root.find("features").insert(0, acpi)
        root.find("name").text = self.vm_name
        root.find("vcpu").text = str(self.vcpus)
        root.find("memory").text = str(self.memory * 1024 * 1024)
        root.find("currentMemory").text = str(self.memory * 1024 * 1024)
        root.find("devices").find("disk[@device='disk']").find("source").set(
            "file", os.path.join(self.image_dir, self.image_name))
        root.find("devices").find("disk[@device='cdrom']").find("source").set(
            "file", os.path.join(self.image_dir, self.nocloud_iso_name))
        root.find("devices").find("serial[@type='pty']").find("log").set(
            "file", self.console_log)
        xmlconfig = ET.tostring(root).decode()
        dom = self.conn.defineXML(xmlconfig)
        dom.create()
        if wait:
            for count in utils_lib.iterate_timeout(
                    90, "Timed out waiting for server to get Created."):
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

    def get_state(self):
        return self._get_status()

    def is_started(self):
        return self._get_status() == libvirt.VIR_DOMAIN_RUNNING

    def is_stopped(self):
        return self._get_status() == libvirt.VIR_DOMAIN_SHUTOFF

    def is_paused(self):
        return self._get_status() == libvirt.VIR_DOMAIN_PAUSED

    def show(self):
        return self.data

    def get_console_log(self):
        with open(self.console_log) as f:
            lines = f.readlines()
        LOG.info(lines)
        return lines

    def disk_count(self):
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
  <memory unit='KiB'>4194304</memory>
  <currentMemory unit='KiB'>4194304</currentMemory>
  <vcpu>2</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <apic/>
  </features>
  <cpu mode='host-model'/>
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
      <model type='virtio'/>
    </interface>
    <serial type='pty'>
      <log file='/tmp/console.log' append='off'/>
    </serial>
    <console type='pty'/>
    <channel type='unix'>
       <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <rng model='virtio'>
      <rate period='2000' bytes='1234'/>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>
"""
