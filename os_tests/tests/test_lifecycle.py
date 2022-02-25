import unittest
import time
from os_tests.libs import utils_lib

import logging
from tipset.libs import rmt_ssh

class TestLifeCycle(unittest.TestCase):
    '''
    Only run in server-client mode.
    '''
    def setUp(self):
        utils_lib.init_case(self)
        if self.params['remote_node'] is None:
            self.skipTest("Only support to run in server-client mode!")
        if utils_lib.is_metal(self):
            self.ssh_timeout = 1200
            self.SSH.interval = 60
        else:
            self.ssh_timeout = 180
        self.log.info('set ssh connection timeout to {}'.format(self.ssh_timeout))

        if 'kdump' in self.id():
            timeout = 120
            interval = 5
            time_start = int(time.time())
            while True:
               cmd = 'sudo systemctl is-active kdump'
               ret = utils_lib.run_cmd(self, cmd,ret_status=True, msg='check kdump is active')
               if ret == 0: break
               time_end = int(time.time())
               if time_end - time_start > timeout:
                  self.log.info('timeout ended: {}'.format(timeout))
                  break
               self.log.info('retry after {}s'.format(interval))
               time.sleep(interval)

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

        kernel_pkg = 'kernel-debug-' + kernel_ver
        utils_lib.is_pkg_installed(self, pkg_name=kernel_pkg, timeout=360)
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
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
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
            cmd = 'sudo bash -c "echo scan > /sys/kernel/debug/kmemleak"'
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
        #self.skipTest("skip it for now because paramiko know issue when enabled fips https://github.com/paramiko/paramiko/pull/1643")

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
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="fips=1"'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')
        else:
            cmd = 'sudo fips-mode-setup --enable'
            utils_lib.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            utils_lib.run_cmd(self,
                        'sudo fips-mode-setup --check',
                        expect_kw='enabled')
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo fips-mode-setup --disable'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')

    def test_boot_hpet_mmap_enabled(self):
        '''
        bz: 1660796, 1764790
        polarion_id:
        '''
        utils_lib.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        utils_lib.is_arch(self, arch='x86', action='cancel')
        cmd = 'sudo grubby --update-kernel=ALL --args="hpet_mmap=1"'
        utils_lib.run_cmd(self, cmd, msg='Append hpet_mmap=1 to command line!', timeout=600)
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='hpet_mmap=1')
        utils_lib.run_cmd(self, 'dmesg | grep -i hpet', expect_kw='enabled', expect_not_kw='6HPET')
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/available_clocksource'
        out = utils_lib.run_cmd(self, cmd)
        if 'hpet' in out:
            utils_lib.run_cmd(self, 'sudo cat /proc/iomem|grep -i hpet', expect_kw='HPET 0')
        utils_lib.check_log(self, "error,warn,fail,trace,Trace", skip_words='ftrace', rmt_redirect_stdout=True)

    def test_boot_mitigations(self):
        '''
        bz: 1896786
        polarion_id:
        '''
        utils_lib.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        cmd = 'cat /proc/cpuinfo |grep processor|wc -l'
        cpucount = utils_lib.run_cmd(self, cmd, msg='get cpu count')
        if int(cpucount) > 36:
            self.skipTest("skip when cpu count over 36 when nosmt passing")
        cmd = 'sudo grubby --update-kernel=ALL --args="mitigations=auto,nosmt"'
        utils_lib.run_cmd(self, cmd, msg='Append mitigations=auto,nosmt to command line!', timeout=600)
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='mitigations=auto,nosmt')
        utils_lib.check_log(self, "error,warn,fail,trace,Trace", skip_words='ftrace,Failed to write ATTR', rmt_redirect_stdout=True)

    def test_boot_usbcore_quirks(self):
        '''
        bz: 1809429
        polarion_id:
        '''
        utils_lib.run_cmd(self, r'sudo rm -rf /var/crash/*',
                    expect_ret=0, msg='clean /var/crash firstly')
        option = 'usbcore.quirks=quirks=0781:5580:bk,0a5c:5834:gij'
        cmd = 'sudo grubby --update-kernel=ALL --args="{}"'.format(option)
        utils_lib.run_cmd(self, cmd, msg='Append {} to command line!'.format(option), timeout=600)
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw=option)
        cmd = r'sudo cat /var/crash/*/vmcore-dmesg.txt|tail -50'
        utils_lib.run_cmd(self, cmd, expect_kw='No such file or directory', msg='make sure there is no core generated')
        utils_lib.check_log(self, "error,warn,fail,trace,Trace", skip_words='ftrace', rmt_redirect_stdout=True)

    def test_reboot_resolve_content(self):
        """
        case_tag:
            cloudinit
        case_name:
            test_reboot_resolve_content
        case_file:
            https://github.com/liangxiao1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
        component:
            NetworkManager
        bugzilla_id:
            1748015
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Check /etc/resolv.conf content is regenerated and consistent before and after reboot
        key_steps:
            # sudo cp -f /etc/resolv.conf /etc/resolv.conf.orig
            # sudo truncate -s0 /etc/resolv.conf (skip in openstack platform)
            # sudo reboot
            # sudo diff -u /etc/resolv.conf /etc/resolv.conf.orig
        expect_result:
            diff returen 0
        debug_want:
            # rpm -q NetworkManager
        """
        utils_lib.run_cmd(self, r'sudo cat /etc/resolv.conf',
                    expect_ret=0, expect_kw='nameserver', msg='check resolv.conf content')
        utils_lib.run_cmd(self, r'sudo cp -f /etc/resolv.conf /etc/resolv.conf.orig',
                    expect_ret=0, msg='backup /etc/resolv.conf')
        if not utils_lib.is_openstack(self):
            utils_lib.run_cmd(self, r'sudo truncate -s0 /etc/resolv.conf',
                        expect_ret=0, msg='cleanup /etc/resolv.conf')
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

        utils_lib.run_cmd(self, r'sudo cat /etc/resolv.conf',
                    expect_ret=0, expect_kw='nameserver', msg='check content after reboot')
        utils_lib.run_cmd(self, r'sudo diff -u /etc/resolv.conf /etc/resolv.conf.orig',
                    expect_ret=0, msg='check if content identical after reboot')

    def test_kdump_no_specify_cpu(self):
        '''
        bz: 1654962
        polarion_id: RHEL7-58669
        '''
        cmd = 'systemctl is-active kdump'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check kdump service')
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self):
            self.skipTest("Cancel as bug 1654962 in arm guest which \
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
        utils_lib.run_cmd(self, "sudo bash -c \"echo c > /proc/sysrq-trigger\"", msg='trigger crash')

        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        self.log.info("After system crash")
        utils_lib.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/*/vmcore-dmesg.txt|tail -50'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='write_sysrq_trigger')

    def test_kdump_fastboot_systemctl_kexec(self):
        '''
        description:
            Test loading kernel via kexec with RHEL.
        testplan:
            N/A
        bugzilla_id: 
            1758323, 1841578
        is_customer_case:
            True
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            Kdump
        key_steps:
            1. Launch an instance with multi kernels installed.
            2. Load each kernel with command "sudo kexec -l /boot/vmlinuz-$version --initrd=/boot/initramfs-$version.img --reuse-cmdline"
        pass_criteria: 
            System shutdown and reboot with the specified kernel version, kernel can be loaded via kexec.
        '''
        utils_lib.run_cmd(self,'uname -r', cancel_not_kw='el7,el6', msg='Not full support earlier than el8, skip!')
        cmd = 'sudo rpm -qa|grep -e "kernel-[0-9]"'
        output = utils_lib.run_cmd(self, cmd, msg='Get kernel version')
        kernels_list = output.split('\n')
        for kernel in kernels_list:
            if kernel is None or kernel == '' or len(kernel) < 6:
                continue
            self.log.info('try to swith {}'.format(kernel))
            kernel_vmlinuz = "/boot/" + kernel.replace('kernel','vmlinuz')
            kernel_initramfs = "/boot/" + kernel.replace('kernel','initramfs') + ".img"
            cmd = "sudo kexec -l %s --initrd=%s --reuse-cmdline" % (kernel_vmlinuz, kernel_initramfs)
            utils_lib.run_cmd(self, cmd, msg='Switch kernel', expect_ret=0)
            cmd = "sudo systemctl kexec"
            utils_lib.run_cmd(self, cmd, msg='fast reboot system')
            time.sleep(10)
            self.SSH.create_connection()
            utils_lib.run_cmd(self, 'uname -r', msg='check kernel', expect_ret=0, expect_kw=kernel[7:])

    def test_kdump_fastboot_kexec_e(self):
        '''
        description:
            Test loading kernel via kexec with RHEL on AWS.
        testplan:
            N/A
        bugzilla_id: 
            1758323, 1841578
        is_customer_case:
            True
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            Kdump
        key_steps:
            1. Launch an instance with multi kernels installed.
            2. Load each kernel with command "sudo kexec -l /boot/vmlinuz-$version --initrd=/boot/initramfs-$version.img --reuse-cmdline"
            3. When the kernel is loaded, run command "sudo kexec -e".
        pass_criteria: 
            Kernel can be loaded via kexec, and system will reboot into the loaded kernel via kexec -e without calling shutdown(8).
        '''
        utils_lib.run_cmd(self,'uname -r', cancel_not_kw='el7,el6', msg='Not full support earlier than el8, skip!')
        cmd = 'sudo rpm -qa|grep -e "kernel-[0-9]"'
        output = utils_lib.run_cmd(self, cmd, msg='Get kernel version')
        kernels_list = output.split('\n')
        for kernel in kernels_list:
            if kernel is None or kernel == '' or len(kernel) < 6:
                continue
            self.log.info('try to swith {}'.format(kernel))
            kernel_vmlinuz = "/boot/" + kernel.replace('kernel','vmlinuz')
            kernel_initramfs = "/boot/" + kernel.replace('kernel','initramfs') + ".img"
            cmd = "sudo kexec -l %s --initrd=%s --reuse-cmdline" % (kernel_vmlinuz, kernel_initramfs)
            utils_lib.run_cmd(self, cmd, msg='Switch kernel', expect_ret=0)
            cmd = "sudo kexec -e"
            utils_lib.run_cmd(self, cmd, msg='fast reboot system')
            time.sleep(10)
            self.SSH.create_connection()
            utils_lib.run_cmd(self, 'uname -r', msg='check kernel', expect_ret=0, expect_kw=kernel[7:])

    def test_kickstart_install_vm(self):

        if self.vm and self.vm.provider != 'nutanix':
            self.log.info("self.vm.provider is" + self.vm.provider)
            self.skipTest("Skip this test case which is dedicate for Nutanix")

        if self.vm.exists():
            self.vm.delete(wait=True)
        self.vm.create_by_ISO_kickstart(wait=True)
        self.vm.start(wait=True)
        logging.info("wait for kickstart automatic installation")
        time.sleep(3600)

        ssh = rmt_ssh.RemoteSSH()
        ssh.rmt_node = self.vm.floating_ip
        ssh.rmt_user = "root"
        ssh.rmt_password = self.vm.vm_password
        ssh.create_connection()
        if ssh.ssh_client is None:
            logging.info("ssh_client is " + str(ssh.ssh_client))
            self.fail('failed ssh to vm installed by kickstart')

    def tearDown(self):
        reboot_require = False
        if 'test_boot_debugkernel' in self.id():
            cmd = "sudo grubby --set-default-index=%s" % self.old_grub_index
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="restore default boot index to {}".format(self.old_grub_index))
            reboot_require = True
        if 'test_boot_hpet_mmap_enabled' in self.id():
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="hpet_mmap=1"'
            utils_lib.run_cmd(self, cmd, msg='Remove "hpet_mmap=1"')
            reboot_require = True
        if 'test_boot_mitigations' in self.id():
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="mitigations=auto,nosmt"'
            utils_lib.run_cmd(self, cmd, msg='Remove "mitigations=auto,nosmt"')
            reboot_require = True
        if 'test_boot_usbcore_quirks' in self.id():
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="usbcore.quirks=quirks=0781:5580:bk,0a5c:5834:gij"'
            utils_lib.run_cmd(self, cmd, msg='Remove "usbcore.quirks=quirks=0781:5580:bk,0a5c:5834:gij"')
            reboot_require = True
        if reboot_require:
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test to restore setting')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=self.ssh_timeout)

if __name__ == '__main__':
    unittest.main()