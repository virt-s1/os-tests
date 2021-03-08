import unittest
import time
from os_tests.libs import utils_lib

class TestLifeCycle(unittest.TestCase):
    '''
    Only run remotely.
    '''
    def setUp(self):
        utils_lib.init_case(self)
        if self.params['remote_node'] == 'None' or len(self.params['remote_node']) < 5:
            self.skipTest("Only support to run remotely!")

    def test_boot_debugkernel(self):
        '''
        polarion_id:
        bz: 1703366
        '''
        self.old_grub_index = utils_lib.run_cmd(self, 'sudo grubby --default-index', expect_ret=0)
        self.log.info("Check kernel-debug can boot up!")
        mini_mem = utils_lib.get_memsize(self)
        if int(mini_mem) < 2:
            self.skipTest('minimal 2G memory required for debug kernel')
        if utils_lib.is_arch(self, 'aarch64') and int(mini_mem) < 4:
            self.skipTest('minimal 4G memory required in aarch64')

        kernel_ver = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if 'el7' in kernel_ver:
            debug_kernel = "/boot/vmlinuz-" + kernel_ver.strip('\n') + ".debug"
        else:
            debug_kernel = "/boot/vmlinuz-" + kernel_ver.strip('\n') + "+debug"

        utils_lib.run_cmd(self,
                    "sudo grubby --info=%s" % debug_kernel,
                    expect_ret=0,
                    msg="check kernel-debug installed")
        cmd = "sudo grubby --info=%s|grep index|cut -d'=' -f2" % debug_kernel
        debug_kernel_index = utils_lib.run_cmd(self,
                                         cmd,
                                         expect_ret=0, cancel_ret='0',
                                         msg="check kernel-debug index")
        cmd = "sudo grubby --set-default-index=%s" % debug_kernel_index
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="change default boot index")
        cmd = 'sudo grubby --update-kernel=ALL --args="kmemleak=on"'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="enable kmemleak")
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=800)
        utils_lib.run_cmd(self,
                    'uname -r',
                    expect_ret=0,
                    expect_kw='debug',
                    msg="checking debug kernel booted")
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, msg="saving dmesg output")
        cmd = 'journalctl > /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="saving journalctl output")
        utils_lib.run_cmd(self, 'cat /tmp/journalctl.log', expect_ret=0)
        utils_lib.run_cmd(self, "sudo systemd-analyze blame > /tmp/blame.log")
        utils_lib.run_cmd(self, "cat /tmp/blame.log")
        cmd = "sudo systemd-analyze "
        time_start = int(time.time())
        while True:
            output = utils_lib.run_cmd(self, cmd)
            if 'Bootup is not yet finished' not in output:
                break
            time_end = int(time.time())
            utils_lib.run_cmd(self, 'sudo systemctl list-jobs')
            if time_end - time_start > 120:
                self.fail("Bootup is not yet finished after 120s")
            self.log.info("Wait for bootup finish......")
            time.sleep(1)
        utils_lib.run_cmd(self, "dmesg", expect_not_kw="Call trace,Call Trace")
        if int(mini_mem) < 17:
            cmd = 'sudo echo scan > /sys/kernel/debug/kmemleak'
            utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)

            cmd = 'sudo cat /sys/kernel/debug/kmemleak'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0)
            if len(output) > 0:
                self.fail('Memory leak found!')

    def test_boot_fipsenabled(self):
        '''
        polarion_id:
        bz: 1787270
        '''

        self.log.info("Check system can boot with fips=1")
        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if 'el7' in output:
            utils_lib.run_cmd(self,
                       'sudo dracut -v -f',
                        msg='regenerate the initramfs!',
                        timeout=600)
            cmd = 'sudo grubby --update-kernel=ALL --args="fips=1"'
            utils_lib.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=800)
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="fips=1"'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')
        else:
            cmd = 'sudo fips-mode-setup --enable'
            utils_lib.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=800)
            utils_lib.run_cmd(self,
                        'sudo fips-mode-setup --check',
                        expect_kw='enabled')
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo fips-mode-setup --disable'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')

    def test_boot_mitigations(self):
        '''
        polarion_id:
        bz: 1896786
        '''
        cmd = 'sudo grubby --update-kernel=ALL --args="mitigations=auto,nosmt"'
        utils_lib.run_cmd(self, cmd, msg='Append mitigations=auto,nosmt to command line!', timeout=600)
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=800)
        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='mitigations=auto,nosmt')
        utils_lib.check_log(self, "error,warn,fail,trace,Trace", rmt_redirect_stdout=True)

    def test_kdump_no_specify_cpu(self):
        '''
        polarion_id: RHEL7-58669
        bz: 1654962
        '''
        cmd = 'systemctl is-active kdump'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check kdump service')
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        self.is_metal = utils_lib.is_metal(self)
        if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self):
            self.cancel("Cancel as bug 1654962 in arm guest which \
no plan to fix it in the near future!")

        utils_lib.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        utils_lib.run_cmd(self, r'sudo sync', expect_ret=0)
        self.log.info("Before system crash")
        utils_lib.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash')
        utils_lib.run_cmd(self, 'echo c > /proc/sysrq-trigger', msg='trigger crash')

        if self.is_metal:
            self.log.info("Wait 180s")
            time.sleep(180)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        utils_lib.init_connection(self)
        self.log.info("After system crash")
        utils_lib.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/1*/vmcore-dmesg.txt|tail -50'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='write_sysrq_trigger')

    def tearDown(self):
        if 'test_boot_debugkernel' in self.id():
            cmd = "sudo grubby --set-default-index=%s" % self.old_grub_index
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="restore default boot index to {}".format(self.old_grub_index))
        if 'test_boot_mitigations' in self.id():
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="mitigations=auto,nosmt"'
            utils_lib.run_cmd(self, cmd, msg='Remove "mitigations=auto,nosmt"')
        if 'test_kdump_no_specify_cpu' not in self.id():
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=800)

if __name__ == '__main__':
    unittest.main()