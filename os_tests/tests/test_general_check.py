import unittest
from os_tests.libs import utils_lib

class TestGeneralCheck(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

    def test_check_avclog(self):
        '''
        polarion_id: N/A
        '''
        cmd = "sudo ausearch -m AVC -ts today"
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Checking avc log!')

    def test_check_avclog_nfs(self):
        '''
        polarion_id: N/A
        bz#: 1771856
        '''
        self.log.info("Check no permission denied at nfs server - bug1655493")
        cmd = 'sudo yum install -y nfs-utils'
        utils_lib.run_cmd(self, cmd, msg='Install nfs-utils')
        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)

        if 'el7' in output or 'el6' in output:
            cmd = "sudo systemctl start nfs"
        else:
            cmd = 'sudo systemctl start nfs-server.service'

        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, "sudo mkdir /tmp/testrw")
        cmd = "sudo chmod -R 777 /tmp/testrw"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "sudo exportfs -o rw,insecure_locks,all_squash,fsid=1 \
*:/tmp/testrw"

        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "sudo mount -t nfs 127.0.0.1:/tmp/testrw /mnt"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, "sudo umount /mnt")

        cmd = "sudo ausearch -m AVC -ts today"
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Checking avc log!')

    def test_check_available_clocksource(self):
        '''
        polarion_id:
        bz#: 1726487
        '''
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        if 'Xen' in output:
            expect_clocks = 'xen,tsc,hpet,acpi_pm'
        elif 'aarch64' in output:
            expect_clocks = 'arch_sys_counter'
        elif 'AuthenticAMD' in output and 'KVM' in output:
            expect_clocks = 'kvm-clock,tsc,acpi_pm'
        elif 'GenuineIntel' in output and 'KVM' in output:
            expect_clocks = 'kvm-clock,tsc,acpi_pm'
        else:
            expect_clocks = 'tsc,hpet,acpi_pm'

        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
available_clocksource'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw=expect_clocks,
                    msg='Checking available clocksource')

    def test_check_boot_time(self):
        '''
        polarion_id: RHEL7-93100
        bz#: 1776710
        check the boot time.
        '''
        max_boot_time = self.params.get('max_boot_time')
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=max_boot_time, ratio=0, msg="Compare with cfg specified max_boot_time")

    def test_check_dmesg_error(self):
        '''
        :avocado: tags=test_check_dmesg_error,fast_check
        polarion_id: RHEL7-103851
        '''
        utils_lib.check_log(self, 'error', log_cmd='dmesg')

    def test_check_dmesg_fail(self):
        '''
        :avocado: tags=test_check_dmesg_fail,fast_check
        polarion_id: RHEL7-103851
        '''
        utils_lib.check_log(self, 'fail', log_cmd='dmesg')

    def test_check_dmesg_warn(self):
        '''
        :avocado: tags=test_check_dmesg_warn,fast_check
        polarion_id: RHEL7-103851
        '''
        utils_lib.check_log(self, 'warn', log_cmd='dmesg')

    def test_check_dmesg_unable(self):
        '''
        :avocado: tags=test_check_dmesg_unable,fast_check
        polarion_id:
        bz#: 1779454
        '''
        utils_lib.check_log(self, 'unable', log_cmd='dmesg')

    def test_check_dmesg_calltrace(self):
        '''
        polarion_id: RHEL7-103851
        bz#: 1777179
        '''
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, expect_not_kw='Call Trace', msg="Check there is no call trace in dmesg")

    def test_check_dmesg_unknownsymbol(self):
        '''
        polarion_id:
        bz#: 1649215
        '''
        utils_lib.run_cmd(self,
                    'dmesg',
                    expect_ret=0,
                    expect_not_kw='Unknown symbol',
                    msg='Check there is no Unknown symbol in dmesg')

    def test_check_journal_calltrace(self):
        '''
        polarion_id:
        bz#: 1801999, 1736818
        '''
        # redirect journalctl output to a file as it is not get return
        # normally in RHEL7
        cmd = 'journalctl > /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'cat /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Traceback,Backtrace',
                        msg = "Check no Traceback,Backtrace in journal log")

    def test_check_journalctl_dumpedcore(self):
        '''
        polarion_id:
        bz#: 1797973
        '''
        # redirect journalctl output to a file as it is not get return
        # normally in RHEL7
        cmd = 'journalctl > /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'cat /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='dumped core',
                        msg = "Check no dumped core in journal log")
    def test_check_journalctl_error(self):
        '''
        polarion_id: RHEL7-103851
        '''
        utils_lib.check_log(self, 'error', skip_words='test_check')

    def test_check_journalctl_fail(self):
        '''
        polarion_id: RHEL7-103851
        '''
        utils_lib.check_log(self, 'fail', skip_words='test_check')

    def test_check_journalctl_warn(self):
        '''
        polarion_id: RHEL7-103851
        '''
        utils_lib.check_log(self, 'warn', skip_words='test_check')

    def test_check_journalctl_invalid(self):
        '''
        polarion_id:
        BZ#:1750417
        '''
        utils_lib.check_log(self, 'invalid', skip_words="Invalid user,invalid user,test_check")

    def test_check_journalctl_service_unknown_lvalue(self):
        '''
        polarion_id:
        BZ#:1871139
        '''
        all_services = utils_lib.get_all_systemd_service()
        for service in all_services:
            cmd = "systemctl status {}".format(service)
            utils_lib.run_cmd(self, cmd)
            cmd = "journalctl --unit {}".format(service)
            utils_lib.check_log(self,'Unknown lvalue', log_cmd=cmd)

    def test_check_memleaks(self):
        '''
        polarion_id: RHEL-117648
        '''
        self.log.info("Check memory leaks")
        utils_lib.run_cmd(self,
                    'uname -a',
                    expect_ret=0,
                    cancel_kw="debug",
                    msg="Only run in debug kernel")
        utils_lib.run_cmd(self,
                    'cat /proc/cmdline',
                    expect_ret=0,
                    cancel_kw="kmemleak=on",
                    msg="Only run with kmemleak=on")

        utils_lib.run_cmd(self, 'sudo su', expect_ret=0)
        cmd = 'echo scan > /sys/kernel/debug/kmemleak'
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)

        cmd = 'cat /sys/kernel/debug/kmemleak'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if len(output) > 0:
            self.fail('Memory leak found!')

    def test_check_nouveau(self):
        '''
        polarion_id: N/A
        BZ#: 1349927, 1645772
        '''
        utils_lib.is_aws(self, action='cancel')
        self.log.info("nouveau is not required in ec2, make sure it is \
in blacklist and not loaded bug1645772")
        utils_lib.run_cmd(self,
                    "sudo lsmod",
                    expect_ret=0,
                    expect_not_kw="nouveau",
                    msg="Checking lsmod")
        utils_lib.run_cmd(self,
                    "sudo cat /proc/cmdline",
                    expect_ret=0,
                    expect_kw="rd.blacklist=nouveau",
                    msg="Checking cmdline")

    def test_check_nvme_io_timeout(self):
        '''
        polarion_id: N/A
        bz#: 1859088
        '''
        utils_lib.is_aws(self, action='cancel')
        self.log.info("nvme_core.io_timeout=4294967295 is recommended in ec2, make sure it is \
in cmdline as bug1859088")
        utils_lib.run_cmd(self,
                    "sudo cat /sys/module/nvme_core/parameters/io_timeout",
                    msg="Checking actual value")
        utils_lib.run_cmd(self,
                    "sudo cat /proc/cmdline",
                    expect_ret=0,
                    expect_kw="nvme_core.io_timeout=4294967295",
                    msg="Checking cmdline")

    def test_check_tsc_deadline_timer(self):
        '''
        polarion_id: RHEL7-111006
        des: check TSC deadline timer enabled in dmesg
        BZ#: 1503160
        '''
        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="Xen,aarch64,AuthenticAMD", msg="Only run in intel cpu.")

        cmd = "grep tsc_deadline_timer /proc/cpuinfo"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg="check cpu flag has tsc_deadline_timer")
        cmd = "dmesg|grep 'TSC deadline timer enabled'"
        utils_lib.run_cmd(self, cmd, expect_ret=0)

        cmd = "sudo cat /sys/devices/system/clockevents/clockevent0/\
current_device"

        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='lapic-deadline',
                    msg='Check guest timer')

    def test_check_virtwhat(self):
        '''
        polarion_id: RHEL7-103857
        BZ#: 1782435
        test virt-what, not use systemd-detect-virt
        '''
        utils_lib.is_cmd_exist(self, cmd='virt-what')
        virt_what_output = utils_lib.run_cmd(self, r"sudo virt-what", expect_ret=0)
        lscpu_output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        if 'Xen' in lscpu_output:
            self.log.info("Found it is a xen system!")
            if 'full' in lscpu_output:
                self.assertIn('xen-hvm', virt_what_output)
            else:
                self.assertIn('xen-domU', virt_what_output)
        elif 'KVM' in lscpu_output:
            self.log.info("Found it is a kvm system!")
            self.assertIn('kvm', virt_what_output)
        elif 'VMware' in lscpu_output:
            self.log.info("Found it is a vmware system!")
            self.assertIn('vmware', virt_what_output)
        elif 'Microsoft' in lscpu_output:
            self.log.info("Found it is a Hyper-V system!")
            self.assertIn('hyperv', virt_what_output)
        elif utils_lib.is_metal(self):
            self.log.info("Found it is a bare metal system!")
        else:
            self.skipTest("Unknow hypervisor")

if __name__ == '__main__':
    unittest.main()