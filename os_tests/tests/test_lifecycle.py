import unittest
import time
import random
import re
from os_tests.libs import utils_lib
from os_tests.libs.resources import UnSupportedAction

class TestLifeCycle(unittest.TestCase):
    '''
    Only run in server-client mode.
    '''
    def setUp(self):
        utils_lib.init_case(self)
        if self.params.get('remote_node') is None:
            self.skipTest("Only support to run in server-client mode!")
        if utils_lib.is_ahv(self):
            self.ssh_timeout = 1200
            self.SSH.interval = 60
        self.log.info('set ssh connection timeout to {}'.format(self.ssh_timeout))

        if 'kdump' in self.id():
            if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self) and utils_lib.is_aws(self):
                self.log.info("aws aarch64 non-metal instance found, remove irqpoll if it is used following https://access.redhat.com/articles/6562431")
                update_kdump_cfg = False
                cmd = 'sudo grep irqpoll /etc/sysconfig/kdump |grep KDUMP_COMMANDLINE_REMOVE'
                ret = utils_lib.run_cmd(self, cmd, ret_status=True)
                if ret != 0:
                    cmd = 'sudo bash -c " sed -i \'/KDUMP_COMMANDLINE_REMOVE=/s/quiet/quiet irqpoll/g\'  /etc/sysconfig/kdump"'
                    utils_lib.run_cmd(self, cmd, msg='add irqpoll to KDUMP_COMMANDLINE_REMOVE')
                    update_kdump_cfg = True
                cmd = 'sudo grep irqpoll /etc/sysconfig/kdump |grep KDUMP_COMMANDLINE_APPEND'
                ret = utils_lib.run_cmd(self, cmd, ret_status=True)
                if ret == 0:
                    cmd = 'sudo bash -c "sed -i \'/KDUMP_COMMANDLINE_APPEND=/s/irqpoll //g\'  /etc/sysconfig/kdump"'
                    utils_lib.run_cmd(self, cmd, msg='remove irqpoll from KDUMP_COMMANDLINE_APPEND')
                    update_kdump_cfg = True
                if update_kdump_cfg:
                    cmd = 'sudo cat /etc/sysconfig/kdump'
                    utils_lib.run_cmd(self, cmd, msg='updated kdump')
                    cmd = 'sudo systemctl restart kdump'
                    utils_lib.run_cmd(self, cmd, msg='restart kdump')

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
            for cmd in ['sudo kdumpctl showmem','cat /proc/cmdline','systemctl status kdump -l']:
                utils_lib.run_cmd(self, cmd, expect_ret=0)

    def test_boot_debugkernel(self):
        '''
        polarion_id:
        bz: 1703366
        '''
        if self.vm and self.vm.provider == 'nutanix' and self.vm.is_secure_boot:
            self.skipTest('''Red Hat Insights error "sed: can't read /sys/kernel/debug/sched_features: Operation not permitted" When using secure boot''')
        self.log.info("Check kernel-debug can boot up!")
        mini_mem = utils_lib.get_memsize(self)
        if int(mini_mem) < 2:
            self.skipTest('minimal 2G memory required for debug kernel')
        if utils_lib.is_arch(self, 'aarch64') and int(mini_mem) < 4:
            self.skipTest('minimal 4G memory required in aarch64')
        
        need_reboot = False
        self.default_boot_kernel  = utils_lib.run_cmd(self, "sudo grubby --default-kernel", expect_ret=0)
        self.default_cmdline = utils_lib.run_cmd(self, 'cat /proc/cmdline')
        kernel_ver = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if 'debug' in kernel_ver:
            self.log.info('already in debug kernel')
        else:
            need_reboot = True
            if 'el7' in kernel_ver:
                debug_kernel = "/boot/vmlinuz-" + kernel_ver.strip('\n') + ".debug"
            else:
                debug_kernel = "/boot/vmlinuz-" + kernel_ver.strip('\n') + "+debug"
            kernel_pkg = 'kernel-debug-' + kernel_ver
            utils_lib.is_pkg_installed(self, pkg_name=kernel_pkg, timeout=600) #Increase this timeout time for once failure against Nutanix VM
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
        cmd = 'cat /proc/cmdline'
        cmd_options = utils_lib.run_cmd(self, cmd)
        if 'kmemleak=on' not in cmd_options:
            need_reboot = True
        if need_reboot:
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
        if int(mini_mem) <= 16:
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

        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_ret=0)
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
        utils_lib.check_log(self, "error,warn,fail,CallTrace", skip_words='ftrace', rmt_redirect_stdout=True)

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
        utils_lib.check_log(self, "error,warn,fail,CallTrace", skip_words='ftrace,Failed to write ATTR', rmt_redirect_stdout=True)

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
        #remove trace for "memory used for stack traces" or "Callback from call_rcu_tasks_trace() invoked"
        utils_lib.check_log(self, "error,warn,fail,CallTrace", rmt_redirect_stdout=True)

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
        case_tag:
            kdump
        case_name:
            test_kdump_no_specify_cpu
        case_file:
            os_tests.tests.test_lifecycle.test_kdump_no_specify_cpu
        component:
            kdump
        bugzilla_id:
            1654962
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Test kdump no specify cpu
        key_steps: |
            1. Triger crash on system
            2. Check if kdump is working and dump file will be generated
        expect_result:
            kdump is working and dump file will be generated
        debug_want:
            N/A
        '''
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_not_kw="Xen", msg="Not support in xen instance")
        product_id = utils_lib.get_product_id(self)
        if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self) and float(product_id) < 8.6:
            self.skipTest("Cancel as bug 1654962 in arm guest earlier than 8.6 2082405" )
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

    def test_kdump_each_cpu(self):
        """
        case_tag:
            kdump
        case_name:
            test_kdump_each_cpu
        case_file:
            os_tests.tests.test_lifecycle.test_kdump_each_cpu
        component:
            kdump
        bugzilla_id:
            1396554
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Test kdump on each cpu core
        key_steps: |
            1. Triger crash on each cpu core
            2. Check if kdump is working and dump file will be generated
        expect_result:
            kdump is working and dump file will be generated
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_not_kw="Xen", msg="Not support in xen instance")
        product_id = utils_lib.get_product_id(self)
        if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self) and float(product_id) < 8.6:
            self.skipTest("Cancel as bug 1654962 in arm guest earlier than 8.6 2082405" )
        
        cmd = "grep processor /proc/cpuinfo | wc -l"
        cpu_counts = int(utils_lib.run_cmd(self, cmd, expect_ret=0,
                                           msg = "Get cpu counts"))
        test_cpus = range(cpu_counts)
        if utils_lib.is_aws(self) and cpu_counts > 3:
            test_cpus = random.choices(range(cpu_counts),k=2)
            self.log.info("It takes too long time in aws bare metal system or instances with tens of vcpus, pick up 2 of them to test {}".format(test_cpus))
        for core_num in test_cpus:
            self.log.info("Trigger kdump on core %d" % core_num)
            cmd = "systemctl is-active kdump || sudo systemctl start kdump"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check kdump service status")
            
            utils_lib.run_cmd(self,
                        "sudo rm -rf /var/crash/*",
                        expect_ret=0,
                        msg="clean /var/crash")
            utils_lib.run_cmd(self, "sudo sync", expect_ret=0)
            self.log.info("Before system crash")
            res_before = utils_lib.run_cmd(self,
                                           "find /var/crash",
                                           expect_ret=0,
                                           msg="list /var/crash before crash")
            cmd = "sudo bash -c 'taskset -c %d echo c > /proc/sysrq-trigger'" % core_num
            utils_lib.run_cmd(self, cmd, msg='trigger crash')
            time.sleep(30)

            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            self.log.info("After system crash")
            res_after = utils_lib.run_cmd(self,
                                          "find /var/crash",
                                          expect_ret=0,
                                          msg="list /var/crash after crash")
            self.assertNotEqual(res_after, res_before,
                                "Test failed as no crash dump file found")

            cmd = "sudo cat /var/crash/*/vmcore-dmesg.txt|tail -50"
            utils_lib.run_cmd(self, cmd, expect_ret=0,
                              expect_kw="write_sysrq_trigger",
                              msg="Check if crash happened")

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
        key_steps: |
            1. Launch an instance with multi kernels installed.
            2. Load each kernel with command "sudo kexec -s -l /boot/vmlinuz-$version --initrd=/boot/initramfs-$version.img --reuse-cmdline"
            note: kexec "-s" is recommended in 2118669 devel's comment
        pass_criteria: 
            System shutdown and reboot with the specified kernel version, kernel can be loaded via kexec.
        '''
        utils_lib.run_cmd(self,'uname -r', cancel_not_kw='el7,el6', msg='check if run in prior el8 as it is not fully supoorted in el7 or el6')
        cmd = 'sudo rpm -qa|grep -e "kernel-[0-9]"'
        output = utils_lib.run_cmd(self, cmd, msg='Get kernel version')
        kernels_list = re.findall('kernel.*',output)
        if not kernels_list:
            self.fail("No kernel found from {}".format(output))
        for kernel in kernels_list:
            self.log.info('try to swith {}'.format(kernel))
            kernel_vmlinuz = "/boot/" + kernel.replace('kernel','vmlinuz')
            kernel_initramfs = "/boot/" + kernel.replace('kernel','initramfs') + ".img"
            if self.vm and self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
                cmd = "sudo kexec -s -l %s --initrd=%s --reuse-cmdline -s" % (kernel_vmlinuz, kernel_initramfs) #kexec systems using UEFI + SecureBoot using the kexec option "-s"
            else:
                cmd = "sudo kexec -s -l %s --initrd=%s --reuse-cmdline" % (kernel_vmlinuz, kernel_initramfs)
            utils_lib.run_cmd(self, cmd, msg='Switch kernel', expect_ret=0)
            cmd = "sudo systemctl kexec"
            utils_lib.run_cmd(self, cmd, msg='fast reboot system')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
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
        key_steps: |
            1. Launch an instance with multi kernels installed.
            2. Load each kernel with command "sudo kexec -s -l /boot/vmlinuz-$version --initrd=/boot/initramfs-$version.img --reuse-cmdline"
            3. When the kernel is loaded, run command "sudo kexec -e".
        pass_criteria: 
            Kernel can be loaded via kexec, and system will reboot into the loaded kernel via kexec -e without calling shutdown(8).
        '''
        utils_lib.run_cmd(self,'uname -r', cancel_not_kw='el7,el6', msg='Not full support earlier than el8, skip!')
        cmd = 'sudo rpm -qa|grep -e "kernel-[0-9]"'
        output = utils_lib.run_cmd(self, cmd, msg='Get kernel version')
        kernels_list = re.findall('kernel.*',output)
        if not kernels_list:
            self.fail("No kernel found from {}".format(output))
        for kernel in kernels_list:
            self.log.info('try to swith {}'.format(kernel))
            kernel_vmlinuz = "/boot/" + kernel.replace('kernel','vmlinuz')
            kernel_initramfs = "/boot/" + kernel.replace('kernel','initramfs') + ".img"
            if self.vm and self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
                cmd = "sudo kexec -s -l %s --initrd=%s --reuse-cmdline -s" % (kernel_vmlinuz, kernel_initramfs) #kexec systems using UEFI + SecureBoot using the kexec option "-s"
            else:
                cmd = "sudo kexec -s -l %s --initrd=%s --reuse-cmdline" % (kernel_vmlinuz, kernel_initramfs)
            utils_lib.run_cmd(self, cmd, msg='Switch kernel', expect_ret=0)
            cmd = "sudo kexec -e"
            utils_lib.run_cmd(self, cmd, msg='fast reboot system')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            utils_lib.run_cmd(self, 'uname -r', msg='check kernel', expect_ret=0, expect_kw=kernel[7:])

    def test_check_secure_boot(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier2
        case_name:
            test_check_secure_boot
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_check_secure_boot
        component:
            lifecycle
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check secure boot state according to input paramters in yaml configure file.
        key_steps:
            1. Check command mokutil --sb-state.
        expect_result:
            1. Secure boot state check right.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("no vms found to determin vm's boot configration!")
        utils_lib.is_cmd_exist(self, cmd='mokutil')
        secure_boot_check = utils_lib.run_cmd(self, "mokutil --sb-state")
        if self.vm.is_secure_boot:
            self.assertIn("SecureBoot enabled", secure_boot_check, msg='secure boot check error: %s' % secure_boot_check)
        else:
            if self.vm.is_uefi_boot:
                self.assertRegex(secure_boot_check, "This system doesn't support Secure Boot|SecureBoot disabled", msg='secure boot check error: %s' % secure_boot_check)
            else:
                self.assertIn("EFI variables are not supported on this system", secure_boot_check, msg='secure boot check error: %s' % secure_boot_check)

    def test_reboot_vm(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier1
        case_name:
            test_reboot_vm
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_reboot_vm
        component:
            lifecycle
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check time in last reboot before and after VM reboot.
        key_steps:
            1. Check time in last reboot before and after VM reboot.
        expect_result:
            1. Check time is different in last reboot before and after VM reboot.
        debug_want:
            N/A
        """
        before = utils_lib.run_cmd(self, 'last reboot --time-format full')
        if not self.vm:
            self.skipTest('no vm provider found')
        self.vm.reboot(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami').strip()
        self.assertEqual(
            self.vm.vm_username, output,
            "Reboot VM error: output of cmd `who` unexpected -> %s" % output)
        after = utils_lib.run_cmd(self, 'last reboot --time-format full')
        self.assertNotEqual(
            before, after,
            "Reboot VM error: before -> %s; after -> %s" % (before, after))
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def test_reboot_inside_vm(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier1
        case_name:
            test_reboot_inside_vm
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_reboot_inside_vm
        component:
            lifecycle
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check time in last reboot before and after VM inside reboot.
        key_steps:
            1. Check time in last reboot before and after VM inside reboot.
        expect_result:
            1. Check time is different in last reboot before and after VM inside reboot.
        debug_want:
            N/A
        """
        before = utils_lib.run_cmd(self, 'last reboot --time-format full|wc -l')
        utils_lib.run_cmd(self, 'sudo reboot')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami')
        if self.vm:
            self.assertEqual(
                self.vm.vm_username, output.strip(),
                "Reboot VM error: output of cmd `who` unexpected -> %s" % output)
        after = utils_lib.run_cmd(self, 'last reboot --time-format full|wc -l')
        self.assertNotEqual(
            before, after,
            "Reboot VM error: before -> %s; after -> %s" % (before, after))

    def test_reboot_simultaneous(self):
        """
        case_name:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_reboot_simultaneous
        case_tags:
            Lifecycle,Lifecycle_tier2
        case_status:
            Approved
        title:
            test system reboot with two simultaneous reboot operation
        importance:
            Low
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            Automated
        linked_work_items:
            TBD
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
        setup_teardown:
            Generic case without any specific setup.
        environment:
            Generic case without any specific setup.
        component:
            kernel
        bug_id:
            bugzilla_2033214
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            Functional
        test_level:
            Component
        maintainer:
            xiliang@redhat.com
        description: |
            Trigger system simultaneous reboot, check whether system can reset normally.
        key_steps: |
            echo b > /proc/sysrq-trigger & echo b > /proc/sysrq-trigger
        expected_result: |
            system reset and boot up normally
        debug_want: |
            console output
        """
        # no new reboot record in run, so use uptime to check if system reboot
        before = utils_lib.run_cmd(self, 'uptime -s')
        utils_lib.run_cmd(self, 'sudo bash -c "echo b > /proc/sysrq-trigger & echo b > /proc/sysrq-trigger"')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami')
        if self.vm:
            self.assertEqual(
                self.vm.vm_username, output.strip(),
                "Reboot VM error: output of cmd `who` unexpected -> %s" % output)
        after = utils_lib.run_cmd(self, 'uptime -s')
        self.assertNotEqual(
            before, after,
            "Reboot VM error: before -> %s; after -> %s" % (before, after))

    def _start_vm_and_check(self):
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami').strip()
        self.assertEqual(self.vm.vm_username,
            output,
            "Start VM error: output of cmd `who` unexpected -> %s" % output)

    def test_stop_start_vm(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier1
        case_name:
            test_stop_start_vm
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_stop_start_vm
        component:
            lifecycle
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check user name after stop/start VM.
        key_steps:
            1. Check user name after stop/start VM.
        expect_result:
            1. Check user name is right after stop/start VM.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest('no vm provider found')
        self.vm.stop(wait=True)
        self.assertTrue(self.vm.is_stopped(),
                        "Stop VM error: VM status is not SHUTOFF")
        self._start_vm_and_check()
        utils_lib.run_cmd(self, 'sudo shutdown now')
        for count in utils_lib.iterate_timeout(
                120, "Timed out waiting for getting server stopped."):
            if self.vm.is_stopped(): break
        self._start_vm_and_check()

    def _update_kernel_args(self, boot_param_required):
        cmd = 'sudo grubby --update-kernel=ALL --args="{}"'.format(boot_param_required)
        utils_lib.run_cmd(self, cmd, msg="append {} to boot params".format(boot_param_required))
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        cat_proc_cmdline = utils_lib.run_cmd(self, 'cat /proc/cmdline')
        return cat_proc_cmdline

    def test_start_vm_iommu(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier2
        case_name:
            test_start_vm_iommu
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_start_vm_iommu kernel command.
        component:
            lifecycle
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check /proc/cmdline after configure intel_iommu equal on .
        key_steps:
            1. Update kernel command line using grubby command and than check /proc/cmdline.
        expect_result:
            1. Update kernel command line using grubby command and than check /proc/cmdline.
        debug_want:
            N/A
        """
        if utils_lib.is_arch(self, arch='x86_64'):
            boot_param_required = 'intel_iommu=on'
            out = utils_lib.run_cmd(self, 'cat /proc/cmdline', msg='Check boot line')
            if boot_param_required not in out:
                cat_proc_cmdline = self._update_kernel_args(boot_param_required)
                self.assertIn(boot_param_required, cat_proc_cmdline, msg='Expect intel_iommu=on in /proc/cmdline')

    def test_boot_nr_cpus(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier2
        case_name:
            test_boot_nr_cpus
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_boot_nr_cpus kernel command.
        component:
            lifecycle
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check /proc/cmdline after configure nr_cpus equal 1 and then 2 .
        key_steps:
            1. Update kernel command line using grubby command and than check /proc/cmdline.
        expect_result:
            1. Update kernel command line using grubby command and than check /proc/cmdline.
        debug_want:
            N/A
        """
        cpu_num = int(utils_lib.run_cmd(self, 'cat /proc/cpuinfo | grep processor | wc -l'))
        if cpu_num < 2:
            self.skipTest("Skip test case since need at least 2 cpus for test")
        for cpus in [1,2]:
            boot_param_required = 'nr_cpus='+str(cpus)
            cat_proc_cmdline = self._update_kernel_args(boot_param_required)
            self.assertIn(boot_param_required, cat_proc_cmdline, msg='Expect intel_iommu=on in /proc/cmdline')
            online_cpu_num = int(utils_lib.run_cmd(self, 'cat /proc/cpuinfo | grep processor | wc -l'))
            self.assertEqual(online_cpu_num, cpus, msg='Check online cpus numbers equal to nr_cpus in kernel command line. Expect: %s, Actual: %s' % (cpus, online_cpu_num))
    
    def test_kdump_nr_cpus(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier2
        case_name:
            test_kdump_nr_cpus
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_kdump_nr_cpus
        component:
            kexec-tools
        bugzilla_id:
            2123230
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Check kdump can save core file when boot system with "nr_cpus=2".
        key_steps:
            1. Boot system with args "nr_cpus=2" and trigger crash manually.
        expect_result:
            1. System can save core successfully.
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_not_kw="Xen", msg="Not support in xen instance")
        cpu_num = int(utils_lib.run_cmd(self, 'cat /proc/cpuinfo | grep processor | wc -l'))
        if cpu_num <= 2:
            self.skipTest("Skip test case since cpu number is not greater than 2")
        if cpu_num > 2:
            cpus = 2

        # Check /proc/cmdline for the nr_cpus args
        boot_param_required = 'nr_cpus=%s'%cpus
        cat_proc_cmdline = self._update_kernel_args(boot_param_required)
        self.assertIn(boot_param_required, cat_proc_cmdline, msg='Expect nr_cpus in /proc/cmdline')
        online_cpu_num = int(utils_lib.run_cmd(self, 'cat /proc/cpuinfo | grep processor | wc -l'))
        self.assertEqual(online_cpu_num, cpus,
                            msg='Check online cpus numbers equal to nr_cpus in kernel command line. Expect: %s, Actual: %s' % (
                            cpus, online_cpu_num))

        # Check kdump for the system booted with nr_cpus args
        product_id = utils_lib.get_product_id(self)
        if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self) and float(product_id) < 8.6:
            self.skipTest("Cancel as bug 1654962 in arm guest earlier than 8.6 2082405" )
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

    def test_kdump_unknown_nmi_panic_disabled(self):
        '''
        description:
            Test Diagnostic Interrupt doesn't trigger the kdump when unknown_nmi_panic is disabled with RHEL on AWS. https://aws.amazon.com/blogs/aws/new-trigger-a-kernel-panic-to-diagnose-unresponsive-ec2-instances/
        testplan:
            N/A
        bugzilla_id:
            n/a
        is_customer_case:
            False
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            Kdump
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the kdump status by command "systemctl status kdump.service".
            3. Disable kernel to trigger a kernel panic upon receiving the interrupt by set /etc/sysctl.conf and add a line : kernel.unknown_nmi_panic=0 and reboot. Or by command "sudo sysctl kernel.unknown_nmi_panic=0".
            4. Send Diagnostic Interrupt to the instance.
        pass_criteria: 
            Unknown NMI received and kernel panic isn't triggered, system is still running with no error message.
        '''
        if not self.vm:
            self.skipTest('vm not init')
        utils_lib.run_cmd(self, 'lscpu', cancel_not_kw='aarch64', msg='Not support in arm instance')
        utils_lib.run_cmd(self, r'sudo rm -rf /var/crash/*', expect_ret=0, msg='clean /var/crash firstly')
        utils_lib.run_cmd(self, r'sudo sysctl kernel.unknown_nmi_panic=0',expect_ret=0,msg='disable unknown_nmi_panic')
        utils_lib.run_cmd(self, r'sudo sysctl -a|grep -i nmi', expect_ret=0, expect_kw='kernel.unknown_nmi_panic = 0')
        try:
            is_success = self.vm.send_nmi()
        except UnSupportedAction as err:
            self.skipTest("current {} not support nmi operation".format(self.vm.provider))
        if not is_success:
            self.fail("Cannot trigger panic via nmi!")
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, r'sudo cat /var/crash/*/vmcore-dmesg.txt', expect_not_ret=0, msg='list /var/crash after crash')
        cmd = r'sudo dmesg|tail -10'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='NMI received')

    def test_kdump_unknown_nmi_panic_enabled(self):
        '''
        description:
            Test Diagnostic Interrupt triggers the kdump when unknown_nmi_panic is enabled with RHEL on AWS. https://aws.amazon.com/blogs/aws/new-trigger-a-kernel-panic-to-diagnose-unresponsive-ec2-instances/
        testplan:
            N/A
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            Kdump
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the kdump status by command "systemctl status kdump.service".
            3. Disable kernel to trigger a kernel panic upon receiving the interrupt by set /etc/sysctl.conf and add a line : kernel.unknown_nmi_panic=1 and reboot. Or by command "sudo sysctl kernel.unknown_nmi_panic=1".
            4. Send Diagnostic Interrupt to the instance.
        pass_criteria: 
            Kernel panic is triggered, system reboot after panic, and vm core is gernerated in /var/crash after crash. 
        '''
        if not self.vm:
            self.skipTest('vm not init')
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
        utils_lib.run_cmd(self, 'lscpu', cancel_not_kw='aarch64', msg='Not support in arm instance')
        utils_lib.run_cmd(self, r'sudo rm -rf /var/crash/*', expect_ret=0, msg='clean /var/crash firstly')
        utils_lib.run_cmd(self, r'sudo sysctl kernel.unknown_nmi_panic=1', expect_ret=0, msg='enable unknown_nmi_panic')
        utils_lib.run_cmd(self, r'sudo sysctl -a|grep -i nmi', expect_ret=0, expect_kw='kernel.unknown_nmi_panic = 1')
        try:
            is_success = self.vm.send_nmi()
        except UnSupportedAction as err:
            self.skipTest("current {} not support nmi operation".format(self.vm.provider))
        if not is_success:
            self.fail("Cannot trigger panic via nmi!")
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self,
                    r'sudo ls /var/crash/',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/1*/vmcore-dmesg.txt|tail -50'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='nmi_panic')

    def test_hibernate_resume(self):
        """
        case_tag:
            lifecycle
        case_name:
            test_hibernate_resume
        case_file:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_vm_operation.py
        component:
            kernel
        bugzilla_id:
            1898677
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Test system hibernation and process is still running after resumed
        key_steps: |
            1. enable hibernation on system
            2. start a test process, eg. sleep 1800
            3. hibernate system
            4. start system
            5. the test process still running
        expect_result:
            test process resume successfully
        debug_want:
            dmesg or console output
        """
        if not self.vm:
            self.skipTest('vm not init')
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_not_kw="Xen", msg="Not support in xen instance")
        utils_lib.is_cmd_exist(self,"acpid")
        if self.vm.provider == 'aws':
            product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
            if float(product_id) >= 8.0 and float(product_id) < 9.0:
                pkg_url='https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/e/ec2-hibinit-agent-1.0.4-1.el8.noarch.rpm'
            elif float(product_id) < 8.0:
                self.skipTest('not supported earlier than rhel8')
            else:
                pkg_url = "https://dl.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/e/ec2-hibinit-agent-1.0.3-5.fc34.noarch.rpm"
            utils_lib.pkg_install(self, pkg_name='ec2-hibinit-agent', pkg_url=pkg_url, force=True)
            cmd = 'sudo systemctl is-enabled hibinit-agent.service'
            output = utils_lib.run_cmd(self, cmd)
            if 'enabled' not in output:
                cmd = 'sudo systemctl enable --now hibinit-agent.service'
                utils_lib.run_cmd(self, cmd)
                utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
                timeout = 180
                interval = 5
                time_start = int(time.time())
                while True:
                    cmd = 'sudo systemctl is-active hibinit-agent.service'
                    out = utils_lib.run_cmd(self, cmd)
                    if 'inactive' in out:
                        break
                    time_end = int(time.time())
                    if time_end - time_start > timeout:
                       self.log.info('timeout ended: {}'.format(timeout))
                       break
                    self.log.info('retry after {}s'.format(interval))
                    time.sleep(interval)
                cmd = 'sudo systemctl status hibinit-agent.service'
                utils_lib.run_cmd(self, cmd)
        else:
            cmd = 'cat /proc/swaps'
            output = utils_lib.run_cmd(self, cmd, msg='check whether system has swap on')
            if '-2' not in output:
                self.log.info("No swap found, creating new one")
                cmd = """
                    sudo dd if=/dev/zero of=/swap bs=1024 count=2000000;
                    sudo chmod 0600 /swap;
                    sudo mkswap /swap;
                    sudo swapon /swap;
                    offset=$(sudo filefrag -v /swap| awk '{if($1==\"0:\"){print $4}}');
                    uuid=$(findmnt -no UUID -T /swap);
                    sudo grubby --update-kernel=ALL  --args=\"resume_offset=${offset//.} resume=UUID=$uuid\";
                    echo '/swap    swap    swap   defaults 0 0' | sudo tee -a /etc/fstab
                    """
                utils_lib.run_cmd(self, cmd, timeout=240)

        cmd = "sleep 3600 > /dev/null 2>&1 &"
        utils_lib.run_cmd(self, cmd)
        vm_hibernate_success = False
        try:
            if not self.vm.send_hibernation():
                self.skipTest('send hibernate not succeed')
            vm_hibernate_success = True
        except NotImplementedError:
            self.log.info('send_hibernation func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.log.info('send_hibernation func is not supported in {}'.format(self.vm.provider))
        if not vm_hibernate_success:
            cmd = "sudo systemctl hibernate"
            utils_lib.run_cmd(self, cmd, msg="Try to hibernate inside system!")
            time.sleep(20)

        self.vm.start()
        time.sleep(30)
        self.params['remote_node'] = self.vm.floating_ip
        utils_lib.init_connection(self, timeout=1800)
        utils_lib.run_cmd(self, 'dmesg', expect_kw="Restarting tasks", expect_not_kw='Call trace,Call Trace', msg="check the system is resumed")
        cmd = 'pgrep -a sleep'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check sleep process still exists')

    def tearDown(self):
        reboot_require = False
        addon_args = ["hpet_mmap=1", "mitigations=auto,nosmt", "usbcore.quirks=quirks=0781:5580:bk,0a5c:5834:gij",
        "nr_cpus=1","nr_cpus=2", "intel_iommu=on", "fips=1"]
        cmdline = utils_lib.run_cmd(self, 'cat /proc/cmdline')
        if cmdline:
            for arg in addon_args:
                if arg in cmdline:
                    cmd = 'sudo grubby --update-kernel=ALL  --remove-args={}'.format(arg)
                    utils_lib.run_cmd(self, cmd, msg='Remove {}'.format(arg))
                    reboot_require = True
        
        if "boot_debugkernel" in self.id():
            current_boot_kernel = utils_lib.run_cmd(self, "sudo grubby --default-kernel", expect_ret=0)
            current_cmdline = utils_lib.run_cmd(self, 'cat /proc/cmdline')
            if current_boot_kernel != self.default_boot_kernel:
                cmd = "sudo grubby --set-default %s" % self.default_boot_kernel
                utils_lib.run_cmd(self, cmd, expect_ret=0,
                                  msg="Restore default boot kernel to {}".format(self.default_boot_kernel))
                reboot_require = True
            if "kmemleak=on" not in self.default_cmdline and "kmemleak=on" in current_cmdline:
                cmd = 'sudo grubby --update-kernel=ALL --remove-args="kmemleak=on"'
                utils_lib.run_cmd(self, cmd, msg='Remove "kmemleak=on" from /proc/cmdline')
                reboot_require = True

        if reboot_require:
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test to restore setting')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            utils_lib.run_cmd(self, 'cat /proc/cmdline', msg='Check /proc/cmdline')

if __name__ == '__main__':
    unittest.main()
