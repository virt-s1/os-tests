import unittest
from os_tests.libs import utils_lib

class TestGeneralTest(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')

    def test_change_clocksource(self):
        '''
        :avocado: tags=test_change_clocksource,fast_check
        polarion_id:
        '''
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource'

        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check current clock source')
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
available_clocksource'

        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        for clocksource in output.split(' '):
            cmd = 'echo %s > /sys/devices/system/clocksource/clocksource0/\
current_clocksource' % clocksource
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Change clocksource to %s' % clocksource)
            cmd = 'cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource'

            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=clocksource,
                        msg='Check current clock source')
        utils_lib.run_cmd(self, 'dmesg|tail -30', expect_ret=0)

    def test_change_tracer(self):
        '''
        no hang/panic happen
        polarion_id:
        bz#: 1650273
        '''
        cmd = 'sudo mount -t debugfs nodev /sys/kernel/debug'
        utils_lib.run_cmd(self, cmd, msg='mount debugfs')

        cmd = 'sudo cat /sys/kernel/debug/tracing/current_tracer'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check current tracer')
        cmd = 'sudo cat /sys/kernel/debug/tracing/available_tracers'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        for tracer in output.split(' '):
            tracer = tracer.rstrip('\n')
            cmd = 'echo %s > /sys/kernel/debug/tracing/current_tracer' % tracer
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Change tracer to %s' % tracer)
            cmd = 'sudo cat /sys/kernel/debug/tracing/current_tracer'

            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=tracer,
                        msg='Check current tracer')
        utils_lib.run_cmd(self, 'dmesg|tail -30', expect_ret=0)

    def test_cpupower_exception(self):
        '''
        No exception when run cpupower command
        polarion_id: N/A
        bz#: 1626505, 1659883
        '''
        utils_lib.is_cmd_exist(self, 'cpupower')
        cmd = "sudo cpupower info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')
        cmd = "sudo cpupower idle-info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')
        cmd = "sudo cpupower frequency-info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')

    def test_dracut_f_v(self):
        '''
        case_name:
            test_dracut_f_v

        case_priority:
            1

        component:
            kernel

        bugzilla_id:
            1849082

        polarion_id:
            n/a

        maintainer:
            xiliang@redhat.com

        description:
            Test no failed items in generating an initramfs/initrd image.

        key_steps:
            1. # dracut -f -v

        expected_result:
            No failed items found.
        '''
        cmd = "sudo dracut -f -v"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Failed,FAILED')

    def test_virsh_pci_reattach(self):
        '''
        case_name:
            test_virsh_pci_reattach

        case_priority:
            1

        component:
            kernel

        bugzilla_id:
            1700254

        polarion_id:
            n/a

        maintainer:
            xiliang@redhat.com

        description:
            Test no exception when system does pci detach and attach operation in virsh.
            virsh can detach host pci device and attach it to guest.

        key_steps:
            1. #virsh  nodedev-detach $pci
            2. #virsh  nodedev-reattach $pci

        expected_result:
            No panic/crash happen.
            eg. # virsh nodedev-detach pci_0000_2b_00_0
                Device pci_0000_2b_00_0 detached
                # virsh nodedev-reattach pci_0000_2b_00_0
                Device pci_0000_2b_00_0 re-attached

        '''
        utils_lib.is_metal(self, action="cancel")
        cmd = "sudo yum install -y libvirt"
        utils_lib.run_cmd(self, cmd, msg = "install libvirt pkg")
        cmd = "sudo systemctl restart libvirtd"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "restart libvirtd")
        utils_lib.is_cmd_exist(self, cmd='virsh')
        if utils_lib.is_arch(self, arch='x86_64'):
            utils_lib.run_cmd(self,
                   'cat /proc/cmdline',
                   cancel_kw='intel_iommu=on',
                   msg='Check boot line')

        utils_lib.run_cmd(self, 'sudo lspci', msg="get pci list")
        tmp_pci = None
        cmd = "lspci|grep 'Non-Volatile memory'|wc -l"
        out = utils_lib.run_cmd(self, cmd)
        if int(out) > 0:
            cmd = 'sudo find /sys/devices -name *nvme*n1p1*'
            tmp_root = utils_lib.run_cmd(self, cmd, msg="get boot nvme pci")
            boot_pci = tmp_root.split('/')[-2]
            cmd = 'sudo find /sys/devices -name *nvme*|grep -v %s|\
grep -i pci|grep n1' % boot_pci
            ret = utils_lib.run_cmd(self, cmd, msg="get test pci", ret_status=True)
            if int(ret) == 0:
                tmp_pci = utils_lib.run_cmd(self, cmd, msg="get test pci")
                if len(tmp_pci) > 0:
                    tmp_pci = tmp_pci.split('/')[-4]
                else:
                    tmp_pci = None
            else:
                tmp_pci = None
        if tmp_pci is None:
            cmd = 'sudo find /sys/devices -name *ttyS0*'
            tmp_root = utils_lib.run_cmd(self, cmd, msg="get ttyS0 pci device")
            if len(tmp_root) == 0:
                tmp_pci = None
            else:
                serial_pci = tmp_root.split('/')[-3]
                tmp_pci = serial_pci
        if tmp_pci is not None:
            self.log.info("Get pci device: {}".format(tmp_pci))
        else:
            self.skipTest("No pci device found to detach")

        tmp_pci = tmp_pci.replace('.', '_')
        tmp_pci = tmp_pci.replace(':', '_')
        pci_dev_1 = utils_lib.run_cmd(
            self,
            'sudo virsh nodedev-list|grep %s |tail -1' % tmp_pci,
            msg='pick up device to detach')
        if pci_dev_1.endswith('1'):
            pci_dev_0 = pci_dev_1.rstrip('1') + '0'
            utils_lib.run_cmd(self,
                        'sudo virsh nodedev-detach %s' % pci_dev_0,
                        msg='detach pci device',
                        expect_ret=0)
        utils_lib.run_cmd(self,
                    'sudo virsh nodedev-detach %s' % pci_dev_1,
                    msg='detach pci device',
                    expect_ret=0)
        utils_lib.run_cmd(self,
                    'sudo virsh nodedev-reattach %s' % pci_dev_1,
                    msg='reattach pci device',
                    expect_ret=0)
        if pci_dev_1.endswith('1'):
            utils_lib.run_cmd(self,
                        'sudo virsh nodedev-reattach %s' % pci_dev_0,
                        msg='reattach pci device',
                        expect_ret=0)
        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='dmesg -T', cursor=self.dmesg_cursor)

    def test_xenfs_write_inability(self):
        '''
        polarion_id:
        BZ# 1663266
        '''
        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_kw="Xen",
                    msg="Only run in xen instance")

        utils_lib.run_cmd(self, 'sudo umount /proc/xen')
        cmd = r'sudo mount -t xenfs xenfs /proc/xen/'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        script_str = '''
#!/usr/bin/env python

import os
import struct

if __name__ == "__main__":
    fd = os.open("/proc/xen/xenbus", os.O_RDWR)
    # end a fake transaction
    os.write(fd, struct.pack("<IIII", 7, 2, 1234, 0))
        '''
        utils_lib.run_cmd(self, "echo '%s' > t.py" % script_str, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo python3 t.py')
        utils_lib.run_cmd(self, "dmesg", expect_not_kw='Call Trace')

if __name__ == '__main__':
    unittest.main()