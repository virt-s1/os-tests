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
        if 'fastboot' in self.id():
            utils_lib.run_cmd(self,'uname -r', cancel_not_kw='el7,el6', msg='Not full support earlier than el8, skip!')
        if 'kdump' in self.id():
            utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_not_kw="Xen", msg="Not support in xen instance")
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
        """
        case_name:
            test_boot_debugkernel
        case_tags:
            kernel
        case_status:
            approved
        title:
            check system can boot with debug kernel without call trace and memleaks found
        importance:
            medium
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            component
        bug_id:
            bugzilla_1703366
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
           Component
        maintainer:
            xiliang@redhat.com
        description: |
            check system can boot with debug kernel without call trace and memleaks found
        key_steps: |
            - set debug kernel as default boot entry
            - append "kmemleak=on"
            - reboot system
        expected_result: |
            - system can boot up successfully
            - no call trace during boot
            - no memory leaks found
        debug_want: |
            - dmesg or console output
        """
        self.default_boot_kernel  = utils_lib.run_cmd(self, "sudo grubby --default-kernel", expect_ret=0)
        self.default_cmdline = utils_lib.run_cmd(self, 'cat /proc/cmdline')
        if self.vm and self.vm.provider == 'nutanix' and self.vm.is_secure_boot:
            self.skipTest('''Red Hat Insights error "sed: can't read /sys/kernel/debug/sched_features: Operation not permitted" When using secure boot''')
        self.log.info("Check kernel-debug can boot up!")
        mini_mem = utils_lib.get_memsize(self)
        if int(mini_mem) < 2:
            self.skipTest('minimal 2G memory required for debug kernel')
        if utils_lib.is_arch(self, 'aarch64') and int(mini_mem) < 4:
            self.skipTest('minimal 4G memory required in aarch64')

        need_reboot = False
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
        utils_lib.run_cmd(self, 'sudo dmesg', expect_ret=0, msg="saving dmesg output")
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
        utils_lib.run_cmd(self, "sudo dmesg", expect_not_kw="Call trace,Call Trace")
        if int(mini_mem) <= 32:
            cmd = 'sudo bash -c "echo scan > /sys/kernel/debug/kmemleak"'
            utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)

            cmd = 'sudo cat /sys/kernel/debug/kmemleak'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0)
            if len(output) > 0:
                self.fail('Memory leak found!')

    def test_boot_fipsenabled(self):
        """
        case_name:
            test_boot_fipsenabled
        case_tags:
            fips
        case_status:
            approved
        title:
            TestLifeCycle.test_boot_fipsenabled
        importance:
            high
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            TestLifeCycle.test_boot_fipsenabled
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_lifecycle.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            bugzilla_1787270, bugzilla_1973106
        is_customer_case:
            True
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            xiliang@redhat.com
        description: |
            Test boot system with fips enabled.
        key_steps: |
            1. Start a system, enable fips in system.
               For RHEL7,
               Add the fips=1 option to the kernel command line of the boot loader, 
               e.g., "sudo grubby --update-kernel=ALL --args="fips=1""
               For RHEL8, RHEL9,
               To switch the system to FIPS mode via command "sudo fips-mode-setup --enable"
            2. Reboot system to enable FIPS mode in system.
            3. Check if the FIPS mode enabled.
               For RHEL7, there is "fips=1" in /proc/cmdline.
               For RHEL8, RHEL9, 
               There is "fips=1" in /proc/cmdline and "sudo fips-mode-setup --check" is enabled.
        expected_result: |
            System boot success with fips mode enabled without any error in dmesg.
        debug_want: |
            N/A
        """

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
            utils_lib.run_cmd(self, 'sudo dmesg', msg='save dmesg')
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="fips=1"'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')
        else:
            fips_enable_cmd = 'sudo fips-mode-setup --enable'
            out = utils_lib.run_cmd(self, fips_enable_cmd, msg='Enable fips!', timeout=600)
            if 'No space left' in out:
                utils_lib.run_cmd(self, 'df -h;dnf list installed kernel', msg='list disk space and kernel info')
                cmd = 'sudo dnf remove kernel-debug -y'
                utils_lib.run_cmd(self, cmd, msg='remove debug kernel to save space')
                utils_lib.run_cmd(self, fips_enable_cmd, msg='Enable fips again!', timeout=600)
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            utils_lib.run_cmd(self,
                        'sudo fips-mode-setup --check',
                        expect_kw='enabled')
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self, 'sudo dmesg', msg='save dmesg')
            cmd = 'sudo fips-mode-setup --disable'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')

    def test_boot_hpet_mmap_enabled(self):
        """
        case_name:
            test_boot_hpet_mmap_enabled
        case_tags:
            kernel
        case_status:
           approved
        title:
            HPET mmap enabled while booting with "hpet_mmap=1"
        importance:
            low
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            component
        bug_id:
            bugzilla_1660796, bugzilla_1764790
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
            Component
        maintainer:
            xiliang@redhat.com
        description: |
            HPET mmap enabled while booting with "hpet_mmap=1"
        key_steps: |
            $ grubby --update-kernel=ALL --args="hpet_mmap=1"
            $ dmesg|grep 'HPET mmap enabled'
        expected_result: |
            HPET mmap enabled while booting with "hpet_mmap=1"
        debug_want: |
            dmesg
        """
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
        utils_lib.run_cmd(self, 'sudo dmesg | grep -i hpet', expect_kw='enabled', expect_not_kw='6HPET')
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/available_clocksource'
        out = utils_lib.run_cmd(self, cmd)
        if 'hpet' in out:
            utils_lib.run_cmd(self, 'sudo cat /proc/iomem|grep -i hpet', expect_kw='HPET 0')
        utils_lib.check_log(self, "CallTrace", skip_words='ftrace', rmt_redirect_stdout=True)

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
        utils_lib.check_log(self, "CallTrace", skip_words='ftrace,Failed to write ATTR,nofail', rmt_redirect_stdout=True)

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
        cmd = r'sudo cat /var/crash/*/vmcore-dmesg.txt|tail -100'
        utils_lib.run_cmd(self, cmd, expect_kw='No such file or directory', msg='make sure there is no core generated')
        #remove trace for "memory used for stack traces" or "Callback from call_rcu_tasks_trace() invoked"
        utils_lib.check_log(self, "CallTrace", skip_words='nofail', rmt_redirect_stdout=True)

    def test_boot_sev_snp(self):
        """
        case_name:
            test_boot_sev_snp
        case_tags:
            lifecycle,vm_delete
        case_status:
            approved
        title:
            Check system can boot up with sev-snp enabled
        importance:
            medium
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            polarion_XXXX
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
        setup_teardown:
            N/A
        environment:
            AMD
        component:
            component
        bug_id:
            bugzilla_2241202,bugzilla_2218934
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
            Component
        maintainer:
            xiliang@redhat.com
        description: |
            Check system can boot up with sev-snp enabled on supported amd platform
        key_steps: |
            - enable sev-snp when create new vm or instances
        expected_result: |
            - system can boot up successfully without any error
            - sev-guest module loaded
        debug_want: |
            dmesg
        """
        if self.vm and self.vm.provider == 'aws':
            if self.vm.is_exist():
                self.vm.delete()
            if not self.vm.create(enable_sev_snp=True):
                self.vm.create()
                self.skipTest("Cannot create instance with sev_snp enabled")
            utils_lib.init_connection(self, timeout=self.ssh_timeout)

        utils_lib.is_sev_enabled(self)
        utils_lib.run_cmd(self, 'sudo dmesg', expect_kw="SEV-SNP")
        utils_lib.run_cmd(self, 'lsmod|grep sev',
                    expect_ret=0, msg='check whether sev-snp loaded')
        utils_lib.check_log(self, "CallTrace", rmt_redirect_stdout=True)

    def test_boot_mem_encrypt_on(self):
        """
        case_name:
            test_boot_mem_encrypt_on
        case_tags:
            lifecycle
        case_status:
            approved
        title:
            Check system can boot up with mem_encryp on
        importance:
            medium
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            polarion_XXXX
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            component
        bug_id:
            https://issues.redhat.com/browse/RHEL-15176
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
            Component
        maintainer:
            libhe@redhat.com
        description: |
            Check system can boot up with mem_encryp on 
        key_steps: |
            - add mem_encryp=on to kernel cmdline and reboot system
        expected_result: |
            - system can boot up successfully without any error
            - mem_encryp option is enabled
        debug_want: |
            dmesg
        """
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_kw="AMD", msg="Not support in non-AMD cpu")
        utils_lib.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        cmd = 'sudo grubby --update-kernel=ALL --args="mem_encrypt=on"'
        utils_lib.run_cmd(self, cmd, msg='Append mem_encrypt=on to command line!', timeout=600)
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='mem_encrypt=on')
        utils_lib.run_cmd(self, 'sudo dmesg | grep -i mem_encrypt', expect_kw='=on')
        utils_lib.check_log(self, "CallTrace", skip_words='ftrace', rmt_redirect_stdout=True)

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
        debug_want: |
            If the kdump failed due to crashkernel is missing during upgrade/pkg installation, please provide below output before and after reboot system.
            See rhbz#2212320
            # cat /proc/cmdline
            # cat /etc/kernel/cmdline
            # cat /etc/default/grub
            # cat /etc/sysconfig/kernel
            # grubby --info DEFAULT
        '''
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

        time.sleep(60)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        self.log.info("After system crash")
        utils_lib.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/*/vmcore-dmesg.txt|tail -100'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='write_sysrq_trigger')
        cmd = "sudo cat /var/crash/*/kexec-dmesg.log"
        utils_lib.run_cmd(self, cmd, expect_not_kw='Call trace,Call Trace', msg="Check if new call trace found during saving core")

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
        product_id = utils_lib.get_product_id(self)
        if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self) and float(product_id) < 8.6:
            self.skipTest("Cancel as bug 1654962 in arm guest earlier than 8.6 2082405" )
        
        cmd = "grep processor /proc/cpuinfo | wc -l"
        cpu_counts = int(utils_lib.run_cmd(self, cmd, expect_ret=0,
                                           msg = "Get cpu counts"))
        test_cpus = range(cpu_counts)
        if (utils_lib.is_aws(self) or utils_lib.is_ali(self)) and cpu_counts > 3:
            test_cpus = random.choices(range(cpu_counts),k=2)
            self.log.info("It takes too long time in bare metal system or instances with tens of vcpus, pick up 2 of them to test {}".format(test_cpus))
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
            time.sleep(60)

            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            self.log.info("After system crash")
            res_after = utils_lib.run_cmd(self,
                                          "find /var/crash",
                                          expect_ret=0,
                                          msg="list /var/crash after crash")
            self.assertNotEqual(res_after, res_before,
                                "Test failed as no crash dump file found")
            cmd = "sudo cat /var/crash/*/vmcore-dmesg.txt|tail -100"
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

    def test_launch_pingable(self):
        """
        case_name:
            test_launch_pingable
        case_tags:
            kernel
        case_status:
            approved
        title:
            check the time taken between system launch and pingable
        importance:
            low
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            jira_RHEL-40816
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
        setup_teardown:
            firewall or security group allow ping
        environment:
            N/A
        component:
            component
        bug_id:
            jira_RHEL-40816
        is_customer_case:
            True
        testplan:
            N/A
        test_type:
            functional
        test_level:
            Component
        maintainer:
            xiliang@redhat.com
        description: |
            check the time taken between system launch and pingable, kernel might take extra time at very early stage which systemd-analyze does not know.
        key_steps: |
            - record the time of create new instance
            - record the time of instance is pingable
        expected_result: |
            should be less than max_boot_time set in configuration. We can update the threshold after we have more data of this case.
        debug_want: |
            console output
        """
        if not self.vm:
            self.skipTest('vm not init')
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        self.vm.create()
        new_ip = self.vm.floating_ip
        ping_cmd = "ping -c 1 {} -W 2".format(new_ip)
        time_start = int(time.time())
        while True:
            ret, _ = utils_lib.run_cmd_local(ping_cmd,is_log_ret=True)
            time_end = int(time.time())
            time_taken = time_end - time_start
            if int(ret) == 0:
                break
            if time_taken > self.ssh_timeout:
                try:
                   self.vm.get_console_log()
                except NotImplementedError:
                    self.log.info("{} not implement this func: get_console_log".format(self.vm.provider))
                self.log.info("Please make sure your network setting allow ping before reporting bugs")
                self.fail("system is not pingable after {}s".format(self.ssh_timeout))
            time.sleep(1)
        self.log.info("time taken between launch and pingable: {}".format(time_taken))
        
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.getboottime(self)
        
        try:
           self.vm.get_console_log()
        except NotImplementedError:
            self.log.info("{} not implement this func: get_console_log".format(self.vm.provider))

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
            approved
        title:
            test system reboot with two simultaneous reboot operation
        importance:
            low
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
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
            functional
        test_level:
            component
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
        description: |
            Check system can boot up with "nr_cpus=N"
            N is from [1,2] by default.
            N is from [4,7] in metal which cpu count over 8
            N is from [8,33] when cpu count over 100.
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
        cpu_list = [1,2]
        if cpu_num > 8 and utils_lib.is_metal(self):
            cpu_list = [4,7]
        if cpu_num > 100:
            cpu_list = [8,33]
        self.log.info('Test boot with nr_cpus in {}'.format(cpu_list))
        for cpus in cpu_list:
            boot_param_required = 'nr_cpus='+str(cpus)
            cat_proc_cmdline = self._update_kernel_args(boot_param_required)
            self.assertIn(boot_param_required, cat_proc_cmdline, msg='Expect {} in /proc/cmdline'.format(boot_param_required))
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
        time.sleep(60)

        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        self.log.info("After system crash")
        utils_lib.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/*/vmcore-dmesg.txt|tail -100'
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
            self.skipTest("provider:{} {}".format(self.vm.provider, err))
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
            self.skipTest("provider:{} {}".format(self.vm.provider, err))
        if not is_success:
            self.fail("Cannot trigger panic via nmi!")
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self,
                    r'sudo ls /var/crash/',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/1*/vmcore-dmesg.txt|tail -100'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='nmi_panic')

    def test_hibernate_resume(self):
        """
        case_tag:
            lifecycle,vm_delete
        case_name:
            test_hibernate_resume
        case_file:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
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
            if not self.vm.hibernation_support:
                self.skipTest("This instance type does not support hibernation.")
            if self.vm.is_exist():
                self.vm.delete()
            if not self.vm.create(enable_hibernation=True):
                self.vm.create()
                self.skipTest("Cannot create instance with hibernation enabled")
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
            if float(product_id) >= 8.0 and float(product_id) < 9.0:
                pkg_url='https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/e/ec2-hibinit-agent-1.0.5-1.el8.noarch.rpm'
            elif float(product_id) < 8.0:
                self.skipTest('not supported earlier than rhel8')
            else:
                pkg_url = "https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages/e/ec2-hibinit-agent-1.0.5-1.el9.noarch.rpm"
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

                utils_lib.run_cmd(self, 'sudo dracut -f', msg='Regenerate initramfs')
                utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system to make updating kernel take effect')
                time.sleep(10)
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
                utils_lib.run_cmd(self, 'cat /proc/cmdline', msg='Check /proc/cmdline')

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
            for count in utils_lib.iterate_timeout(
                180, "Timed out waiting for getting server stopped."):
                if self.vm.is_stopped(): break

        self.vm.start()
        time.sleep(30)
        self.params['remote_node'] = self.vm.floating_ip
        utils_lib.init_connection(self, timeout=1800)
        utils_lib.run_cmd(self, 'sudo dmesg')
        cmd = 'pgrep -a sleep'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check sleep process still exists')
        utils_lib.run_cmd(self, 'sudo dmesg', expect_kw="Restarting tasks", expect_not_kw='Call trace,Call Trace', msg="check the system is resumed")

    def test_kdump_over_ssh(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier2
        case_name:
            test_kdump_over_ssh
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_kdump_over_ssh
        component:
            kexec-tools
        bugzilla_id:
            1672817, 2186123,2185043
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Check kdump can save core file to remote ssh server.
        key_steps:
            1.To enable SSH logoin without password
            2.To enable kdump over remote ssh server
            3.Sends a sysrq command to trigger a crash
        expect_result:
            1. System can save core to remote ssh server successfully.
        debug_want:
            N/A
        """
        if 'non_interactive' not in self.id():
            if not self.is_rmt:
                self.skipTest('only run on remote')

            if len(self.vms) > 1 and not self.vms[1].exists():
                self.vms[1].create()
                if self.vms[1].is_stopped():
                    self.vms[1].start(wait=True)
                self.params['remote_nodes'].append(self.vms[1].floating_ip)

            if len(self.vms) < 2 and len(self.params.get('remote_nodes')) < 2:
                self.skipTest('2 nodes required!')
            
            self.log.info("Current IP bucket:{}".format(self.params['remote_nodes']))
            utils_lib.init_connection(self, timeout=self.ssh_timeout, rmt_node=self.params['remote_nodes'][-1])
            self.rmt_ipv4 = utils_lib.get_active_nic(self,rmt_node=self.params['remote_nodes'][-1])

            cmd = 'sudo bash -c "mkdir -p /var/www/kdump/export/var/crash"'
            utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1])
            cmd = 'sudo bash -c "chmod -R 777 /var/www/kdump/export/"'
            utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1])
            cmd = 'sudo cat /root/.ssh/id_rsa.pub'
            out = utils_lib.run_cmd(self, cmd, msg='check if root login is enabled')
            if 'No such file' in out:
                cmd = 'sudo bash -c "echo |ssh-keygen -t rsa"'
                out = utils_lib.run_cmd(self, cmd)
                cmd = 'sudo cat /root/.ssh/id_rsa.pub'
                out = utils_lib.run_cmd(self, cmd)
                if 'No such file' in out:
                    self.log.info('Cannot get pub key from hut')
            cmd = 'sudo bash -c "echo \'{}\'>/root/.ssh/authorized_keys"'.format(out)
            utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1], msg='add pub key to test server')
            cmd = 'sudo bash -c "ssh -o StrictHostKeyChecking=no root@{} ip addr"'.format(self.rmt_ipv4)
            utils_lib.run_cmd(self, cmd, msg="test cmd execution on remote without password")

        #Configure kdump over ssh
        utils_lib.run_cmd(self, "sudo systemctl stop kdump", expect_ret=0, msg='stop kdump')
        utils_lib.run_cmd(self, "sudo cp /etc/kdump.conf /etc/kdump.conf.orig", msg='save default kdump cfg')
        cmd = 'echo -e "ssh root@{}\nsshkey /root/.ssh/id_rsa\npath /var/crash\ncore_collector makedumpfile -F -l --message-level 7 -d 31" |sudo tee /etc/kdump.conf'.format(self.rmt_ipv4)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Configure kdump using ssh')
        utils_lib.run_cmd(self, "sudo systemctl restart kdump", expect_ret=0, msg='restart kdump')

        #Enable FIPs
        #utils_lib.fips_enable(self)

        # Check kdump for the system
        product_id = utils_lib.get_product_id(self)
        if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self) and float(product_id) < 8.6:
            self.skipTest("Cancel as bug 1654962 in arm guest earlier than 8.6 2082405" )
        utils_lib.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    rmt_node=self.params['remote_nodes'][-1],
                    msg='clean /var/crash firstly')
        utils_lib.run_cmd(self, r'sudo sync', expect_ret=0)
        self.log.info("Before system crash")
        utils_lib.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    rmt_node=self.params['remote_nodes'][-1],
                    msg='list /var/crash')

        utils_lib.run_cmd(self, "sudo bash -c \"echo c > /proc/sysrq-trigger\"", msg='trigger crash')

        time.sleep(60)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        self.log.info("After system crash")
        utils_lib.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    rmt_node=self.params['remote_nodes'][-1],
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/*/vmcore-dmesg.txt|tail -100'
        utils_lib.run_cmd(self, cmd, expect_ret=0,rmt_node=self.params['remote_nodes'][-1],expect_kw='write_sysrq_trigger')

    def test_kdump_over_nfs(self):
        """
        case_tag:
            Lifecycle,Lifecycle_tier2
        case_name:
            test_kdump_over_nfs
        case_file:
            os_tests.tests.test_lifecycle.TestLifeCycle.test_kdump_over_nfs
        component:
            kexec-tools
        bugzilla_id:
            1672817, 2186123,2185043
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Check kdump can save core file to remote ssh server".
        key_steps:
            1.To enable kdump over nfs server
            2.Add inbound rule to allow nfs port 2049
            3.Add nfs port 2049 to firewall allow list if firewall is enabled
            4.Sends a sysrq command to trigger a crash.
        expect_result:
            1. System can save core to remote nfs server successfully.
        debug_want:
            N/A
        """
        if 'non_interactive' not in self.id():

            if not self.is_rmt:
                self.skipTest('only run on remote')
                
            if len(self.vms) > 1 and not self.vms[1].exists():
                self.vms[1].create()
                if self.vms[1].is_stopped():
                    self.vms[1].start(wait=True)
                self.params['remote_nodes'].append(self.vms[1].floating_ip)

            if len(self.vms) < 2 and len(self.params.get('remote_nodes')) < 2:
                self.skipTest('2 nodes required!')
                
            self.log.info("Current IP bucket:{}".format(self.params['remote_nodes']))
            utils_lib.init_connection(self, timeout=self.ssh_timeout, rmt_node=self.params['remote_nodes'][-1])
            #Get active nic
            self.rmt_ipv4 = utils_lib.get_active_nic(self,rmt_node=self.params['remote_nodes'][-1])
            #Create nfs share folder
            cmd = 'sudo bash -c "mkdir -p /var/www/export/kdump/var/crash"'
            utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1])
            cmd = 'sudo bash -c "chmod -R 777 /var/www/export/kdump"'
            utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1])
           
            #Configure nfs server
            utils_lib.run_cmd(self, "rpm -q nfs-utils||sudo yum install -y nfs-utils", expect_ret=0, timeout=180, rmt_node=self.params['remote_nodes'][-1])
            cmd = 'sudo echo "/var/www/export/kdump *(rw)"|sudo tee /etc/exports'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="configure nfs server",rmt_node=self.params['remote_nodes'][-1])
            utils_lib.run_cmd(self, "sudo systemctl restart rpcbind", expect_ret=0, msg="restart rpcbind server",rmt_node=self.params['remote_nodes'][-1])
            utils_lib.run_cmd(self, "sudo systemctl restart nfs-server", expect_ret=0, msg="start nfs server",rmt_node=self.params['remote_nodes'][-1])
                   
            #Allow inbound access on the NFS port
            if self.vm and self.vm.provider == 'aws':
                instance_id = utils_lib.run_cmd(self,"cat /var/lib/cloud/data/instance-id",msg='get instance id',rmt_node=self.params['remote_nodes'][-1])
                is_port_exist = self.nic.add_inbound_rule(instance_id.strip(),2049)
            
            if utils_lib.is_firewalld_installed_and_running(self,rmt_node=self.params['remote_nodes'][-1]):
                utils_lib.add_port_to_firewall(self,rmt_node=self.params['remote_nodes'][-1],port=2049)

        #Configure kdump over nfs
        #https://access.redhat.com/solutions/1197493
        utils_lib.run_cmd(self, "rpm -q nfs-utils||sudo yum install -y nfs-utils", expect_ret=0, timeout=180)
        utils_lib.run_cmd(self, "sudo systemctl stop kdump", expect_ret=0, msg='stop kdump')
        utils_lib.run_cmd(self, "sudo cp /etc/kdump.conf /etc/kdump.conf.orig", msg='save default kdump cfg')
        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if 'el7' in output:
           cmd = '''sudo echo -e 'dracut_args --mount \"{}:/var/www/export/kdump /var/crash nfs defaults\"\ncore_collector makedumpfile -l --message-level 7 -d 31' |sudo tee /etc/kdump.conf'''.format(self.rmt_ipv4) 
        else:
            cmd = 'sudo echo -e "nfs {}:/var/www/export/kdump\npath /var/crash\ncore_collector makedumpfile -l --message-level 7 -d 31" |sudo tee /etc/kdump.conf'.format(self.rmt_ipv4)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Configure kdump using nfs')
        utils_lib.run_cmd(self, "sudo systemctl start kdump", msg='start kdump')
        utils_lib.run_cmd(self, "sudo systemctl status kdump", expect_ret=0, msg='check kdump status')
        
        #Enable FIPs
        #utils_lib.fips_enable(self)

        # Check kdump for the system
        product_id = utils_lib.get_product_id(self)
        if utils_lib.is_arch(self, 'aarch64') and not utils_lib.is_metal(self) and float(product_id) < 8.6:
            self.skipTest("Cancel as bug 1654962 in arm guest earlier than 8.6 2082405" )
        utils_lib.run_cmd(self,
                    r'sudo rm -rf /var/www/export/kdump/var/crash/*',
                    expect_ret=0,
                    rmt_node=self.params['remote_nodes'][-1],
                    msg='clean /var/crash firstly')
        utils_lib.run_cmd(self, r'sudo sync', expect_ret=0)
        self.log.info("Before system crash")
        utils_lib.run_cmd(self,
                    r'find /var/www/export/kdump/var/crash',
                    expect_ret=0,
                    rmt_node=self.params['remote_nodes'][-1],
                    msg='list /var/crash')
        utils_lib.run_cmd(self, "sudo bash -c \"echo c > /proc/sysrq-trigger\"", msg='trigger crash')
        time.sleep(60)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.init_connection(self, timeout=self.ssh_timeout, rmt_node=self.params['remote_nodes'][-1])
        self.log.info("After system crash")
        utils_lib.run_cmd(self,
                    r'find /var/www/export/kdump/var/crash',
                    expect_ret=0,
                    rmt_node=self.params['remote_nodes'][-1],
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/www/export/kdump/var/crash/*/vmcore-dmesg.txt|tail -100'
        utils_lib.run_cmd(self, cmd, expect_ret=0,rmt_node=self.params['remote_nodes'][-1],expect_kw='write_sysrq_trigger')
        if self.vm and self.vm.provider == 'aws':
            if not is_port_exist:
                self.nic.remove_inbound_rule(instance_id.strip(),2049)

    def tearDown(self):
        utils_lib.finish_case(self)
        reboot_require = False
        addon_args = ["hpet_mmap=1", "mitigations=auto,nosmt", "usbcore.quirks=quirks=0781:5580:bk,0a5c:5834:gij",
        "nr_cpus=1","nr_cpus=2", "nr_cpus=4", "nr_cpus=5", "intel_iommu=on", "fips=1","mem_encrypt=on"]
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

        if "test_hibernate_resume" in self.id() and self.vm and self.vm.provider != 'aws':
            proc_cmdline = utils_lib.run_cmd(self, 'cat /proc/cmdline', msg='Cat /proc/cmdline')
            resume_offset_arg = re.search('(resume_offset=.+)\s', proc_cmdline)
            resume_uuid_arg = re.search('(resume=UUID=.+)$', proc_cmdline)
            for arg in [resume_offset_arg.groups()[0], resume_uuid_arg.groups()[0]]:
                cmd = 'sudo grubby --update-kernel=ALL  --remove-args={}'.format(arg)
                utils_lib.run_cmd(self, cmd, msg='Remove {}'.format(arg))
                reboot_require = True

        if "test_boot_sev_snp" in self.id():
            if self.vm and self.vm.provider == 'aws':
                if self.vm.is_exist() and self.vm.sev_snp_enabled:
                    self.vm.delete()
                    self.vm.create()
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if reboot_require:
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test to restore setting')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            utils_lib.run_cmd(self, 'cat /proc/cmdline', msg='Check /proc/cmdline')
        
        if "test_kdump_over_ssh" in self.id() or "test_kdump_over_nfs" in self.id():
            utils_lib.run_cmd(self, "sudo systemctl stop kdump",expect_ret=0, msg='stop kdump')
            utils_lib.run_cmd(self, "sudo mv -f /etc/kdump.conf.orig /etc/kdump.conf", expect_ret=0, msg='restore default kdump cfg')
            utils_lib.run_cmd(self, "sudo systemctl start kdump", expect_ret=0, msg='start kdump')
            
if __name__ == '__main__':
    unittest.main()
