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

    def test_check_journalctl_invalid(self):
        '''
        polarion_id:
        BZ#:1750417
        '''
        # redirect journalctl output to a file as it is not get return
        # normally in RHEL7
        # skip sshd to filter out invalid user message
        cmd = 'journalctl|grep -v sshd|grep -v MTU > /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'cat /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='invalid,Invalid')

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
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Unknown lvalue')
        

if __name__ == '__main__':
    unittest.main()