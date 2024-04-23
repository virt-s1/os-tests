from multiprocessing import cpu_count
import unittest
import re
from os_tests.libs import utils_lib
import time
import os
from datetime import datetime

class TestGeneralTest(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='sudo dmesg -T')

    def test_change_clocksource(self):
        """
        case_name:
            test_change_clocksource
        component:
            kernal
        bugzilla_id:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            test if can change clock source
        key_steps:
            1.sudo cat /sys/devices/system/clocksource/clocksource0/current_clocksource
            2.sudo cat /sys/devices/system/clocksource/clocksource0/available_clocksource
            3.sudo bash -c \'echo "%s" > /sys/devices/system/clocksource/clocksource0/current_clocksource
            4.sudo cat /sys/devices/system/clocksource/clocksource0/current_clocksource
            5.dmesg|tail -30
        expect_result:
            current clock source is changed
        """
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        current_clocksource_cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/current_clocksource'
        utils_lib.run_cmd(self, current_clocksource_cmd, expect_ret=0, msg='Check current clock source')
        
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/available_clocksource'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        for clocksource in output.split():
            cmd = 'sudo bash -c \'echo "%s" > /sys/devices/system/clocksource/clocksource0/current_clocksource\'' % clocksource
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Change clocksource to %s' % clocksource)

            utils_lib.run_cmd(self, current_clocksource_cmd, expect_kw=clocksource, msg='Check current clock source')
        cmd = 'sudo bash -c \'echo "" > /sys/devices/system/clocksource/clocksource0/current_clocksource\''
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="restore to default clocksource")
        utils_lib.run_cmd(self, 'sudo dmesg|tail -30', expect_ret=0)

    def test_change_tracer(self):
        """
        case_name:
            test_change_tracer
        case_file:
            https://github.com/liangxiao1/os-tests/blob/8ec8531d5d9e58f5dc2293aa4b2c15fe209d27c6/os_tests/tests/test_general_test.py#L43
        component:
            kernel
        bugzilla_id:
            1650273
        maintainer:
            xiliang@redhat.com
        description:
            Test system can switch to available clocksource successfully
        key_steps:
            1. install one clean RHEL 8.0 guest, start it.
            2. # mount -t debugfs nodev /sys/kernel/debug
            3. # cat /sys/kernel/debug/tracing/available_tracers
            4. # echo function > /sys/kernel/debug/tracing/current_tracer
            5. # cat /sys/kernel/debug/tracing/current_tracer
            6. check the current tracer
        expect_result:
            no hang/panic happen after switched clocksource
        debug_want:
            test log and full dmesg log
        """
        cmd = 'sudo mount -t debugfs nodev /sys/kernel/debug'
        utils_lib.run_cmd(self, cmd, msg='mount debugfs')

        cmd = 'sudo cat /sys/kernel/debug/tracing/current_tracer'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check current tracer')
        cmd = 'sudo cat /sys/kernel/debug/tracing/available_tracers'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        for tracer in output.split(' '):
            tracer = tracer.rstrip('\n')
            cmd = 'sudo bash -c \'echo "%s" > /sys/kernel/debug/tracing/current_tracer\'' % tracer
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Change tracer to %s' % tracer)
            cmd = 'sudo cat /sys/kernel/debug/tracing/current_tracer'

            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=tracer,
                        msg='Check current tracer')
        utils_lib.run_cmd(self, 'sudo dmesg|tail -30', expect_ret=0)

    def test_cpupower_exception(self):
        '''
        case_name:
            test_cpupower_exception
        case_file:
            https://github.com/liangxiao1/os-tests/blob/master/os_tests/tests/test_general_test.py
        case_priority:
            2
        component:
            kernel-Platform Enablement
        bugzilla_id:
            1626505, 1659883, 1999926
        customer_case_id:
            02172487
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Run cpupower to query processor power related values. It may not support all fields, but crash is not expected.
        key_steps:
            1. # cpupower info
            2. # cpupower idle-info
            3. # cpupower frequency-info
        expected_result:
            No application crash when run cpupower command, all return 0.
        debug_want:
            1. # lscpu
            2. # rpm -q kernel-tools
            3. # uname -r
        '''
        utils_lib.is_cmd_exist(self, 'cpupower')
        debug_cmds = ['lscpu', 'rpm -q kernel-tools', 'uname -r']
        for cmd in debug_cmds:
            utils_lib.run_cmd(self, cmd, msg='please attach {} output if file bug'.format(cmd))
        cmd = "sudo cpupower info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')
        cmd = "sudo cpupower idle-info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')
        cmd = "sudo cpupower frequency-info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')

    def test_cpu_hotplug_no_workload(self):
        """
        case_name:
            test_cpu_hotplug_no_workload
        case_tags:
            kernel
        case_status:
            approved
        title:
            simple case to offline, online cpu without workload
        importance:
            low
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_general_test.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            kernel
        bug_id:
            bugzilla_2160354,bugzilla_1716271,kcs_4463681
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
            simple case to offline, online cpu without workload
        key_steps: |
            # echo 0 > /sys/devices/system/cpu/cpu1/online
            # lscpu|grep Off-line
            # echo 1 > /sys/devices/system/cpu/cpu1/online
        expected_result: |
            - can offline, online cpu1 without any error, no panic, no call trace
        debug_want: |
            - dmesg
        """
        cmd = "grep processor /proc/cpuinfo | wc -l"
        cpu_counts = int(utils_lib.run_cmd(self, cmd, expect_ret=0,
                                           msg = "Get cpu counts"))
        if int(cpu_counts) < 2:
            self.skipTest("only run when cpu count >= 2")
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        cmd = "sudo bash -c 'echo 0 > /sys/devices/system/cpu/cpu1/online'"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'lscpu'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='Off-line')
        cmd = "sudo bash -c 'echo 1 > /sys/devices/system/cpu/cpu1/online'"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'lscpu'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Off-line')
        utils_lib.run_cmd(self, 'sudo dmesg', expect_ret=0)

    def test_dracut_f_v(self):
        '''
        case_name:
            test_dracut_f_v
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1849082,1906301
        customer_case_id:
            02925130
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
        out = utils_lib.run_cmd(self, cmd, expect_not_kw='Failed,FAILED', timeout=300)
        if 'No space left' in out:
            utils_lib.run_cmd(self, 'df -h;dnf list installed kernel', msg='list disk space and kernel info')
            cmd = 'sudo dnf remove --oldinstallonly --setopt installonl_limit=1 kernel -y'
            utils_lib.run_cmd(self, cmd, msg='remove old kernel to save space')
            cmd = "sudo dracut -f -v"
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Failed,FAILED', timeout=300)


    def test_fio_cpuclock(self):
        """
        case_name:
            test_fio_cpuclock
        component:
            fio
        bugzilla_id:
            1943474,RHEL-15966
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            test if fio can run normally
        key_steps:
            1.check cpu is not aarch64
            2.sudo fio --cpuclock-test
        expect_result:
            pass the test without return
        debug_want:
            N/A
        """
        '''
        bz: 1943474
        polarion_id: N/A
        Perform test and validation of internal CPU clock.
        '''
        utils_lib.run_cmd(self, 'sudo lscpu', cancel_not_kw="aarch64")

        cmd = "grep processor /proc/cpuinfo | wc -l"
        cpu_counts = int(utils_lib.run_cmd(self, cmd, expect_ret=0,msg = "Get cpu counts"))
        if int(cpu_counts) >= 128:
            cmd = "sudo bash -c 'sysctl -w kernel.numa_balancing=0'"
            utils_lib.run_cmd(self, cmd, msg='disable the scheduler autonuma balancing feature(RHEL-15966)', expect_ret=0)

        utils_lib.is_cmd_exist(self, 'fio')
        cmd = "sudo fio --cpuclock-test"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="Pass",msg='Perform test and validation of internal CPU clock.', timeout=1200)

    def test_fips_selftest(self):
        '''
        case_name:
            test_fips_selftest
        case_priority:
            2
        component:
            openssl
        bugzilla_id:
            1940085
        customer_case_id:
            02874840
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            FIPS_selftest() pass
        key_steps:
            1. # gcc fipstest.c -o fipstest -lcrypto
            2. # ./fipstest
        expected_result:
            No fips selftest failed.
        '''
        fipstest = """
//required pkg: openssl-devel
//compile: gcc fipstest.c -o fipstest -lcrypto
//run ./fipstest
//https://www.openssl.org/docs/fips/UserGuide-2.0.pdf
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/fips.h>
#include <openssl/err.h>

int fips_test(int fipsset){
    FIPS_mode_set(fipsset);
    if (FIPS_mode()){
        fprintf(stderr, "fips mode set.\\n");
    }
    else{
        fprintf(stderr, "fips mode not set.\\n");
    }
    if (FIPS_selftest()){
        fprintf(stderr, "fips selftest pass.\\n");
    }
    else{
        fprintf(stderr, "fips selftest failed.\\n");
        ERR_print_errors_fp(stderr);
    }
}
int main(int argc, char *argv[])
{
	fips_test(0);
	fips_test(1);
}
        """
        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
        if float(product_id) >= 9.0:
            self.skipTest('openssl-3.0.0 does not provide FIPS_selftest() API bz:1969692')
        utils_lib.is_pkg_installed(self, pkg_name="openssl-devel")
        utils_lib.is_cmd_exist(self, 'gcc')
        cmd = "echo '{}' > /tmp/fipstest.c".format(fipstest)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='generate fipstest.c')
        cmd = "gcc /tmp/fipstest.c -o /tmp/fipstest -lcrypto"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='compile fipstest.c')
        cmd = "/tmp/fipstest"
        utils_lib.run_cmd(self, cmd, expect_ret=0,expect_not_kw="fips selftest failed", msg='run fipstest')

    def test_fork_pte(self):
        '''
        case_name:
            test_fork_pte
        case_priority:
            2
        component:
            kernel
        bugzilla_id:
            1908439
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Ensure dirty bit is preserved across pte_wrprotect
        key_steps:
            1. # wget https://github.com/redis/redis/files/5717040/redis_8124.c.txt
            2. # mv redis_8124.c.txt redis_8124.c
            3. # gcc -o os_tests_redis redis_8124.c
            4. # systemd-run --scope -p MemoryLimit=550M ./os_tests_redis (change to bigger to avoid OOM)
        expected_result:
            Your kernel looks fine.
        '''
        utils_lib.run_cmd(self, 'uname -r', cancel_not_kw='el7,el6', msg='not support in el7 and el6')
        if utils_lib.get_memsize(self) < 4:
            self.skipTest('skip when mem lower than 4GiB')
        utils_lib.is_cmd_exist(self, cmd='gcc', cancel_case=True)
        utils_lib.is_cmd_exist(self, cmd='wget', cancel_case=True)
        redis_src = self.utils_dir + '/redis_8124.c'
        redis_src_tmp = '/tmp/redis_8124.c'
        if self.params.get('remote_node') is not None:
            self.SSH.put_file(local_file=redis_src, rmt_file=redis_src_tmp)
        else:
            cmd = "sudo cp -f {} {}".format(redis_src, redis_src_tmp)
            utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=120)
        cmd = 'gcc -o /tmp/os_tests_redis /tmp/redis_8124.c'
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=120)
        for i in [550, 1024, 2048]:
            cmd = "sudo systemd-run --scope -p MemoryLimit={}M /tmp/os_tests_redis".format(i)
            out = utils_lib.run_cmd(self, cmd, timeout=120)
            if 'Your kernel looks fine' in out:
                break
        if 'Your kernel looks fine' not in out:
            self.fail("'Your kernel looks fine' not found in {}".format(out))

    def test_fsadm_resize(self):
        """
        case_name:
            test_fsadm_resize
        component:
            lvm2
        bugzilla_id:
            1905705
        is_customer_case:
            True
        maintainer:
            xiliang@redhat.com
        description:
            test if "fsdadm resize" can run normally
        key_steps:
            1.check cmd fsadm
            2.sudo fsadm resize $(findmnt -n -o source /)
        expect_result:
            fsadm does nothing since the filesystem is already at maximum size
        """
        utils_lib.is_cmd_exist(self, 'fsadm')
        utils_lib.run_cmd(self, 'sudo fsadm resize $(findmnt -n -o source /)', expect_ret=0,
            expect_not_kw="unbound variable", msg="fsadm should not crash")

    def test_imds_tracer(self):
        """
        case_name:
            test_imds_tracer
        case_tags:
            imdsv2
        case_status:
            approved
        title:
            check no process retrive metadata via imdsv1 on aws
        importance:
            medium
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            jira_RHEL-5024
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_general_check.py
        setup_teardown:
            aws
        environment:
            aws
        component:
            component
        bug_id:
            jira_RHEL-5024
        is_customer_case:
            True
        testplan:
            N/A
        test_type:
            functional
        test_level:
            Component
        maintainer:
            xiliang
        description: |
            Check there is no process using imdsv1 to access instance metadata
        key_steps: |
            - sudo yum -y install bcc-tools libbpf
            - git clone --branch xiliang https://github.com/liangxiao1/aws-imds-packet-analyzer.git (with the latest fix)
              source repo: https://github.com/aws/aws-imds-packet-analyzer.git
            - sudo aws-imds-packet-analyzer/activate-tracer-service.sh
            - sudo cat /var/log/imds/imds-trace.log|grep imdsv1
        expected_result: |
            No process are using imdsv1 to access instance metadata
        debug_want: |
            - cat /var/log/imds/imds-trace.log
            - journalctl -u imds_tracer_tool.service
        """
        utils_lib.imds_tracer_tool(self, is_return=False, timeout=610)

    def test_subscription_manager_auto(self):
        """
        case_name:
            test_subscription_manager_auto
        component:
            subscription-manager
        bugzilla_id:
            1932802, 1905398
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            test if subscription-manager can run normally in AWS and Azure, RHEL system without timeout.
        key_steps:
            1.sudo subscription-manager config --rhsmcertd.auto_registration=1 --rhsm.manage_repos=0 --rhsmcertd.auto_registration_interval=1
            2.sudo systemctl restart rhsmcertd
            3.sudo subscription-manager config
            4.sudo systemctl is-active rhsmcertd
            5.sudo cat /var/log/rhsm/rhsmcertd.log
            6.sudo cat /var/log/rhsm/rhsm.log
            7.sudo subscription-manager identity
            8.sudo subscription-manager list --installed
            9.sudo subscription-manager status
            10.sudo insights-client --register
        expect_result:
            all registration successfully without timeout failure.
        debug_want: |
            If you linked the test account to customer portal bug auto-reg failed,
            Please attach below log if there is new region added in aws.
            $ curl -s http://169.254.169.254/latest/dynamic/instance-identity/rsa2048
            $ curl -s http://169.254.169.254/latest/dynamic/instance-identity/document
        """
        product_name = utils_lib.get_os_release_info(self, field='NAME')
        if 'Red Hat Enterprise Linux' not in product_name:
            self.skipTest('Only for RHEL test.')
        if not (utils_lib.is_aws(self) or utils_lib.is_azure(self)):
            self.skipTest('Auto registeration only supports AWS and Azure platforms for now.')
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < 8.4:
            self.skipTest('skip in earlier than el8.4')

        self.log.info('If your aws/azure account is not linked to Red Hat customer portal, the case will fail.')
        #if utils_lib.is_aws(self):
        #    cmds = ['curl -s http://169.254.169.254/latest/dynamic/instance-identity/rsa2048','curl -s http://169.254.169.254/latest/dynamic/instance-identity/document']
        #    for cmd in cmds:
        #        utils_lib.run_cmd(self, cmd, msg='region identity data')
        cmd = "sudo subscription-manager config --rhsmcertd.auto_registration=1 --rhsm.manage_repos=0 --rhsmcertd.auto_registration_interval=1"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to enable auto_registration, disable managed_repos and change inverval from 60mins to 1min')
        cmd = "sudo systemctl restart rhsmcertd"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to restart rhsmcertd service')
        cmd = "sudo subscription-manager config"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="auto_registration = 1,manage_repos = 0", msg='try to check subscription-manager config')
        cmd = "sudo systemctl is-active rhsmcertd"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to check rhsmcertd enabled')
        start_time = time.time()
        timeout = 600
        interval = 60
        while True:
            cmd = 'sudo cat /var/log/rhsm/rhsmcertd.log'
            utils_lib.run_cmd(self, cmd, msg='try to check rhsmcertd.log')
            cmd = 'sudo cat /var/log/rhsm/rhsm.log'
            utils_lib.run_cmd(self, cmd, msg='try to check rhsm.log')
            cmd = "sudo subscription-manager identity"
            out = utils_lib.run_cmd(self, cmd, msg='try to check subscription identity')
            cmd = "sudo subscription-manager list --installed"
            out = utils_lib.run_cmd(self, cmd, msg='try to list currently installed on the system')
            cmd = "sudo subscription-manager status"
            out = utils_lib.run_cmd(self, cmd, msg='try to check subscription status')
            if 'Red Hat Enterprise Linux' in out or 'Simple Content Access' in out:
                self.log.info("auto subscription registered completed")
                cmd = "sudo insights-client --register"
                utils_lib.run_cmd(self, cmd, msg='check if insights-client can register successfully')
                break
            end_time = time.time()
            if end_time - start_time > timeout:
                cmd = "sudo insights-client --register"
                utils_lib.run_cmd(self, cmd, msg='check if insights-client can register successfully')
                self.fail("timeout({}s) to wait auto subscription registered completed".format(timeout))
            self.log.info('wait {}s and try to check again, timeout {}s'.format(interval, timeout))
            time.sleep(interval)

    def test_subscription_manager_config(self):
        """
        case_name:
            test_subscription_manager_config
        component:
            subscription-manager
        bugzilla_id:
            1862431
        is_customer_case:
            True
        maintainer:
            xiliang@redhat.com
        description:
            check if "subscription-manager config" output equals "subscription-manager config --list" output
        key_steps:
            1.sudo subscription-manager config > /tmp/sm_config.log
            2.sudo subscription-manager config --list > /tmp/sm_config_list.log
            3.sudo diff -u /tmp/sm_config.log /tmp/sm_config_list.log
        expect_result:
            These two configs are same
        debug_want:
            sm_config and sm_config_list
        """
        '''
        bz: 1862431
        des: "subscription-manager config" output should equal "subscription-manager config --list"
        '''
        utils_lib.is_cmd_exist(self, 'subscription-manager')
        utils_lib.run_cmd(self, "sudo subscription-manager config",
                          expect_ret=0,
                          msg="Run 'subscription-manager config' first to skip the yum/dnf plugins warning, \
the warning is only in qcow2 image as the plugins have been disabled by default, more info please refer to: \
https://bugzilla.redhat.com/show_bug.cgi?id=2107502")
        
        cmd1 = "sudo subscription-manager config > /tmp/sm_config.log"
        out1 = utils_lib.run_cmd(self, cmd1, expect_ret=0, msg='get {} output'.format(cmd1))
        cmd2 = "sudo subscription-manager config --list > /tmp/sm_config_list.log"
        out2 = utils_lib.run_cmd(self, cmd2, expect_ret=0, msg='get {} output'.format(cmd2))
        utils_lib.run_cmd(self, 'sudo cat /tmp/sm_config.log', expect_ret=0)
        cmd = "sudo diff -u /tmp/sm_config.log /tmp/sm_config_list.log"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check if both are identical')

    def test_systemd_coredump(self):
        """
        case_name:
            test_systemd_coredump
        case_file:
            os_tests.tests.test_general_test.TestGeneralTest.test_systemd_coredump
        component:
            systemd
        bugzilla_id:
            2025479, 1905582
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            The DefaultLimitCORESoft is set to 0 by default.
            Test systemd-coredump can save process core successfully when process crashed
        key_steps:
            1. # systemctl show | grep CORE
               DefaultLimitCORE=infinity
               DefaultLimitCORESoft=0 (rhel default set)
            2. create test.c
               #include <stdio.h>
               #include <stdlib.h>
               void main(){
               int x;
               free(&x);
               }
            3. # gcc -g -o os_tests_coretest test.c
            4. # ./pp
        expect_result:
            os_tests_coretest crashed and new core file is generated under /var/lib/systemd/coredump
        debug_want:
            - journal log
        """
        test_str = '''
        #include <stdio.h>
        #include <stdlib.h>
        void main(){
            int x;
            free(&x);
        }
        '''
        product_name = utils_lib.get_os_release_info(self, field='NAME')
        if 'Red Hat Enterprise Linux' in product_name:
            cmd = 'systemctl show | grep CORE'
            utils_lib.run_cmd(self, cmd, expect_kw='DefaultLimitCORESoft=0,DefaultLimitCORE=infinity', msg='check default limit core setting')
        utils_lib.run_cmd(self, 'ulimit -c 0;ulimit -c', expect_ret=0, expect_kw='0', msg='test user can change limit core setting')
        utils_lib.run_cmd(self, 'ulimit -c unlimited;ulimit -c', expect_ret=0, expect_kw='unlimited', msg='test user can change limit core setting')
        utils_lib.run_cmd(self, 'sudo rm -rf /var/lib/systemd/coredump/core.pp*', msg='clean up core files before testing')
        self.cursor = utils_lib.get_cmd_cursor(self, cmd='journalctl -b0', rmt_redirect_stdout=True)
        test_file = '/tmp/test.c'
        utils_lib.is_cmd_exist(self, 'gcc')
        cmd = "echo '{}' > {}".format(test_str, test_file)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='generate {}'.format(test_file))
        cmd = "gcc -g -o /tmp/os_tests_coretest {}".format(test_file)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'ulimit -c unlimited;/tmp/os_tests_coretest', msg='run it to trigger core dump')
        utils_lib.run_cmd(self, 'sudo ls /var/lib/systemd/coredump/core.os_tests_core*', expect_ret=0, msg='check core file generated')
        utils_lib.check_log(self, "warn,fail", log_cmd='journalctl -b0', cursor=self.cursor, rmt_redirect_stdout=True)

    def test_podman_build_image(self):
        '''
        case_name:
            test_podman_build_image
        case_priority:
            2
        component:
            podman
        bugzilla_id:
            1903412
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            podman can build an image using '--network container' in rootless or root mode
        key_steps:
            1. $ cat Dockerfile
               FROM registry.access.redhat.com/ubi8/ubi
               RUN touch /tmp/test.txt
            2. # podman build --network container -t build_test .
        expected_result:
            Build successfully.
        '''
        self.log.info("Test podman can build an image using '--network container'")
        utils_lib.is_cmd_exist(self, 'podman')
        dockerfile = '''
FROM registry.access.redhat.com/ubi8/ubi
RUN touch /tmp/test.txt
        '''
        cmd = "echo '{}' > Dockerfile".format(dockerfile)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='generate Dockerfile')
        cmd = "podman build --network container -t build_test ."
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='build image')
        cmd = "podman run --rm -it build_test uname -r"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check kernel')
        cmd = "podman run --rm -it build_test whoami"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check user')
        cmd = "podman run --rm -it build_test ls -l /tmp/test.txt"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check test file')

    def test_podman_dev_null_permission(self):
        '''
        case_name:
            test_podman_dev_null_permission
        case_priority:
            2
        component:
            podman
        bugzilla_id:
            1952698
        customer_case_id:
            02920986
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Make sure permission on /dev/null are not changing from 666 to 777 after running podman as root
        key_steps:
            1. # sudo podman run -d -p 80:80 httpd
            2. # ls -l /dev/null
        expected_result:
            /dev/null permission keeps 666
        '''
        utils_lib.is_cmd_exist(self, 'podman')
        cmd = "ls -l /dev/null"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check /dev/null permission before test')
        cmd = "sudo chmod 666 /dev/null"
        utils_lib.run_cmd(self, cmd, expect_ret=0,msg='change /dev/null permission to 666')
        cmd = "podman rm -a -f"
        utils_lib.run_cmd(self, cmd, msg='try to clean all containers before testing')
        cmd = "podman run --name test -d ubi"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to start a test container')
        cmd = "ls -l /dev/null"
        utils_lib.run_cmd(self, cmd, expect_ret=0,expect_kw='crw-rw-rw-.' ,msg='check /dev/null permission after test')

    def test_podman_leaks_exit(self):
        '''
        case_name:
            test_podman_leaks_exit
        case_priority:
            2
        component:
            podman
        bugzilla_id:
            1730281
        customer_case_id:
            02390622
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            podman leaks kernel memory due to return code stored in tmpfs
        key_steps:
            1. $ podman run --name test -d ubi
            2. $ sudo ls /run/libpod/exits/
        expected_result:
            Step2 return nothing.
        '''
        utils_lib.is_cmd_exist(self, 'podman')
        self.log.info("Test podman can build an image using '--network container'")
        cmd = "podman ps -a"
        utils_lib.run_cmd(self, cmd, msg='try to list all containers before testing')
        cmd = "podman rm -a -f"
        utils_lib.run_cmd(self, cmd, msg='try to clean all containers before testing')
        cmd = "podman run --name test -d ubi"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to start a test container')
        time.sleep(2)
        cmd = "podman ps -a"
        utils_lib.run_cmd(self, cmd, msg='try to list all containers after testing')
        product_name = utils_lib.get_os_release_info(self, field='NAME')
        cmd = "sudo ls /run/libpod/exits/"
        out = utils_lib.run_cmd(self, cmd,msg='check if saved exit code in tmpfs')
        if 'No such file or directory' in out:
            self.log.info('no leak found')
        else:
            if out != '':
                self.fail('leaks found')
            else:
                self.log.info('no leak found')

    def test_podman_rm_stopped(self):
        """
        case_name:
            test_podman_rm_stopped
        component:
            podman
        bugzilla_id:
            1913295
        is_customer_case:
            True
        maintainer:
            xiliang@redhat.com
        description:
            Test podman can remove a stopped container
        key_steps:
            1.podman ps -a
            2.podman rm -a -f
            3.podman run --name myctr1 -td quay.io/libpod/alpine
            4.podman run --name myctr2 -td quay.io/libpod/alpine
            5.timeout 5 podman exec myctr1 sleep 10
            6.podman kill myctr1
            7.podman inspect myctr1
            8.podman rm myctr1
            9.timeout 5 podman exec myctr2 sleep 10
            10.podman stop myctr2
            11.podman inspect myctr2
            12.podman rm myctr2
            13.podman ps
        expect_result:
            There's no myctr1 and myctr2 left after removing them
        """
        self.log.info("Test podman can remove a stopped container")
        utils_lib.is_cmd_exist(self, 'podman')
        cmd = "podman ps -a"
        utils_lib.run_cmd(self, cmd, msg='try to list all containers before testing')
        cmd = "podman rm -a -f"
        utils_lib.run_cmd(self, cmd, msg='try to clean all containers before testing')
        cmd = "podman run --name myctr1 -td quay.io/libpod/alpine"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='run myctr1', timeout=180)
        cmd = "podman run --name myctr2 -td quay.io/libpod/alpine"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='run myctr2', timeout=180)
        cmd = "timeout 5 podman exec myctr1 sleep 10"
        utils_lib.run_cmd(self, cmd)
        cmd = "podman kill myctr1"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        time.sleep(1)
        cmd = "podman inspect myctr1"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "podman rm myctr1"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to remove myctr1')
        cmd = "timeout 5 podman exec myctr2 sleep 10"
        utils_lib.run_cmd(self, cmd)
        cmd = "podman stop myctr2"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "podman inspect myctr2"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "podman rm myctr2"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to remove myctr2')
        cmd = "podman ps"
        utils_lib.run_cmd(self, cmd, expect_not_kw='myctr1,myctr2', msg='try to list all containers again after testing')

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
        utils_lib.is_pkg_installed(self, pkg_name="libvirt")
        cmd = "sudo systemctl restart libvirtd"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "restart libvirtd")
        utils_lib.is_cmd_exist(self, cmd='virsh')
        if utils_lib.is_arch(self, arch='x86_64'):
            boot_param_required = 'intel_iommu=on'
            out = utils_lib.run_cmd(self, 'cat /proc/cmdline', msg='Check boot line')
            if boot_param_required not in out:
                cmd = 'sudo grubby --update-kernel=ALL --args="{}"'.format(boot_param_required)
                utils_lib.run_cmd(self, cmd, msg="append {} to boot params".format(boot_param_required))
                utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
                time.sleep(10)
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, 'sudo lspci', msg="get pci list")
        tmp_pci = None
        cmd = "lspci|grep 'Non-Volatile memory'|wc -l"
        out = utils_lib.run_cmd(self, cmd)
        if int(out) > 0:
            cmd = 'sudo find /sys/devices -name *nvme*n1p1*'
            tmp_root = utils_lib.run_cmd(self, cmd, msg="get boot nvme pci")
            boot_pci = tmp_root.split('/')[-2]
            cmd = 'sudo find /sys/devices -name *nvme*|grep -v %s|grep -v "p[0-9]"|\
grep -i pci|grep n1' % boot_pci
            ret = utils_lib.run_cmd(self, cmd, msg="get test pci excluding exists partions", ret_status=True)
            if int(ret) == 0:
                tmp_pci = utils_lib.run_cmd(self, cmd, msg="get test nvme pci")
                if len(tmp_pci) > 0:
                    tmp_pci = tmp_pci.split('/')[-4]
                else:
                    tmp_pci = None
            else:
                tmp_pci = None
        if tmp_pci is None:
            cmd = 'sudo find /sys/devices -name *ttyS0*|grep [0-9]:[0-9]'
            tmp_root = utils_lib.run_cmd(self, cmd, msg="try to get ttyS0 pci device")
            if len(tmp_root) == 0:
                tmp_pci = None
            else:
                serial_pci = tmp_root.split('/')[-3]
                tmp_pci = serial_pci
        if tmp_pci is None:
            cmd = 'sudo find /sys/devices -name *vga*|grep [0-9]:[0-9]'
            tmp_root = utils_lib.run_cmd(self, cmd, msg="try to get vga pci device")
            if len(tmp_root) == 0:
                tmp_pci = None
            else:
                vga_pci = tmp_root.split('/')[-2]
                tmp_pci = vga_pci
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
        pci_dev_1 = re.findall('pci_.*',pci_dev_1)
        if len(pci_dev_1) > 0:
            pci_dev_1= pci_dev_1[0]
        else:
            self.fail("no {} found in output".format(tmp_pci))
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
        utils_lib.check_log(self, "error,warn,fail,trace,Trace", log_cmd='sudo dmesg -T', cursor=self.dmesg_cursor)

    def test_sys_read_capability(self):
        """
        case_name:
            test_sys_read_capability
        case_tags:
            kernel
        case_status:
            approved
        title:
            check capability under /sys is readable
        importance:
            low
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
           automated
        linked_work_items:
            jira_RHEL-22993
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_general_test.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            component
        bug_id:
            jira_RHEL-22993
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
            check capability under /sys is readable
        key_steps: |
            - find /sys -name *capabili* -type f -exec cat {} \;
        expected_result: |
            No crash or panic
        debug_want: |
            dmesg or console output
        """
        cmd = 'sudo bash -c "find /sys -name *capabili* -type f -exec echo {} \; -exec cat {} \;"'
        utils_lib.run_cmd(self, cmd, msg="test all capability files are readable and no panic found")

    def test_xenfs_write_inability(self):
        """
        case_name:
            test_xenfs_write_inability
        component:
            kernel
        bugzilla_id:
            1663266
        is_customer_case:
            True
        maintainer:
            xiliang@redhat.com
        description:
            test xen instance system stability after running specfic python script
        key_steps:
            1.use python to run t.py
            2.dmesg
        expect_result:
            no call trace return
        debug_want:
            N/A
        """
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
        utils_lib.run_cmd(self, "sudo dmesg", expect_not_kw='Call trace,Call Trace')


    def test_wipefs_cdrom(self):
        """
        case_tag:
            util
        case_name:
            test_wipefs_return
        component:
            util-linux
        bugzilla_id:
            2074486
        is_customer_case:
            False
        maintainer:
            xuazhao@redhat.com
        description:
            Check wipefs cannot erase read-only cdrom device
        key_steps:part
            1.check if machine have CDROM mounted
            2.# wipefs -a /dev/sr0
            3.# echo $?
            4.#dmesg -T | grep error
            5.check if there's error and return is 0
        expect_result:
            command "wipefs -a /dev/sr0" should return 1
        debug_want:
            "strace -o log wipefs -a /dev/srN
        """
        cmd = "lsblk | grep -E 'sr[0-9]'"
        all = utils_lib.run_cmd(self,cmd,cancel_kw="sr0",
                                msg="check if machine mounted CDROM").rstrip().split("\n")
        self.cursor = utils_lib.get_cmd_cursor(self, cmd='journalctl -b0', rmt_redirect_stdout=True)
        for i in all:
            part = i.split(" ")[0]
            cmd = "sudo wipefs -a /dev/"+part
            utils_lib.run_cmd(self,cmd,expect_ret=1,msg="erase signature")
            cmd = "sudo dmesg -T | grep %s" % part
            utils_lib.check_log(self, "error", log_cmd=cmd, cursor=self.cursor, rmt_redirect_stdout=True)

    def test_grub2_mkconfig(self):
        """
        case_tag:
            osbuild
        case_name:
            test_grub2_mkconfig
        component:
            osbuild-composer
        bugzilla_id:
            bz2056251
        is_customer_case:
            True
        maintainer:
            xuazhao@redhat.com
        description:
            check if grub2-mkconfig can generate a file with set default="${saved_entry}". Without it, system boots into index 0 kernel only.
        key_steps:|
            1.grub2-mkconfig -o /tmp/grub.cfg
            2.cat /tmp/grub.cfg
        expect_result:
            there are {saved_entry} in grub.cfg
        debug_want:
            grub.cfg
        """
        if utils_lib.is_arch(self, arch='s390x'):
            self.skipTest("Skip grub check on s390x")
        cmd = 'rpm -qa "grub2*"'
        utils_lib.run_cmd(self,cmd,msg="show grub version")
        cmd = 'grub2-mkconfig -h'
        out = utils_lib.run_cmd(self,cmd,msg="check if it has no-grubenv-update support")
        if 'no-grubenv-update' in out:
            cmd = "sudo grub2-mkconfig -o /tmp/grub.cfg --no-grubenv-update"
        else:
            cmd = "sudo grub2-mkconfig -o /tmp/grub.cfg"
        utils_lib.run_cmd(self,cmd,expect_kw="done",msg="generate file")
        cmd = 'sudo cat /tmp/grub.cfg'
        utils_lib.run_cmd(self,cmd,msg="check if there is saved_entry",expect_kw="{saved_entry"+"}")

    def test_z_nitro_enclaves(self):
        '''
        case_name:
            test_check_nitro_enclaves,vm_delete
        case_tags:
            vm_delete
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            2011739,2227177
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Test whether nitro enclave works when it is enabled.
        key_steps: |
            ref: https://github.com/aws/aws-nitro-enclaves-cli/blob/main/docs/centos_stream_8_how_to_install_nitro_cli_from_github_sources.md
            1.$ sudo dnf groupinstall "Development Tools"
            2.$ for version under 9 add centos docker repo
                and for rhel9 add fedora34 docker repo
            3.$ sudo dnf install docker-ce docker-ce-cli containerd.io -y
            4.$ sudo systemctl start docker
            5.$ sudo systemctl enable docker
            6.$ sudo usermod -aG docker $USER and re-login
            7.$ git clone https://github.com/aws/aws-nitro-enclaves-cli.git
            8.$ cd aws-nitro-enclaves-cli/ and change bootstrap/nitro-cli-config,bootstrap/env.sh,Makefile
            9.$export NITRO_CLI_INSTALL_DIR=/
            10.$make nitro-cli
            11.$make vsock-proxy
            12.$sudo make NITRO_CLI_INSTALL_DIR=/ install
            13.$source /etc/profile.d/nitro-cli-env.sh
            14.$echo source /etc/profile.d/nitro-cli-env.sh >> ~/.bashrc
            15.$nitro-cli-config -i
            16.$sudo systemctl enable nitro-enclaves-allocator.service && sudo systemctl start nitro-enclaves-allocator.service
            17.$nitro-cli build-enclave --docker-dir /usr/share/nitro_enclaves/examples/hello --docker-uri hello:latest --output-file hello.eif
            18.$nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path hello.eif --debug-mode
            19.$nitro-cli describe-enclaves
            20.$nitro-cli console --enclave-id $EnclaveID
            21.$nitro-cli terminate-enclave --enclave-id $EnclaveID
        expected_result:
            Enclave can be started and terminated successfully.
        debug_want: |
            /var/log/nitro_enclaves/nitro_enclaves.log
        '''
        if self.vm and self.vm.provider == 'aws':
            if self.vm.is_exist():
                self.vm.delete()
            if not self.vm.create(enable_enclave=True):
                self.vm.create()
                self.skipTest("Cannot create instance with enclave enabled")
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not utils_lib.is_aws(self):
            self.skipTest('encalve is only for aws platform')
        cmd = 'ls -l /sys/devices/virtual/misc/nitro_enclaves/dev'
        utils_lib.run_cmd(self, cmd, cancel_not_kw='cannot access', msg='check instance enclave is enabled')
        output = utils_lib.run_cmd(self, "sudo nitro-cli -V", msg='check if nitro-cli exists')
        if 'Nitro CLI' in output:
            cli_installed = True
        else:
            cli_installed = False
        product_name = utils_lib.get_os_release_info(self, field='NAME')
        if 'Red Hat Enterprise Linux' not in product_name and 'CentOS' not in product_name:
            self.skipTest('Only support run in RHEL or CentOS')
        update_files = ["aws-nitro-enclaves-cli/bootstrap/nitro-cli-config", "aws-nitro-enclaves-cli/bootstrap/env.sh",
                        "aws-nitro-enclaves-cli/Makefile"]
        first = ["# Remove an older driver if it is inserted.", "lsmod | grep -q nitro_enclaves || ",
                 "install: install-tools nitro_enclaves"]
        end = ['[ "$(lsmod | grep -cw $DRIVER_NAME)" -eq 1 ] || fail "The driver is not visible."',
               'sudo insmod ${NITRO_CLI_INSTALL_DIR}/lib/modules/extra/nitro_enclaves/nitro_enclaves.ko',
               '${NITRO_CLI_INSTALL_DIR}/lib/modules/$(uname -r)/extra/nitro_enclaves/nitro_enclaves.ko']
        utils_lib.run_cmd(self, 'sudo dnf groupinstall "Development Tools" -y', msg='install development tools', timeout=300)
        utils_lib.is_pkg_installed(self, pkg_name='iptables')
        utils_lib.is_pkg_installed(self, pkg_name='libcgroup')
        utils_lib.is_pkg_installed(self, pkg_name='container-selinux')
        cmds = [ "sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo",
                 "sudo dnf config-manager --set-disable 'rh*'",
                 "sudo dnf install -y docker-ce docker-ce-cli containerd.io --allowerasing",
                 "sudo systemctl enable --now docker",
                 "sudo usermod -aG docker $(whoami)" ]
        for cmd in cmds:
            utils_lib.run_cmd(self, cmd)

        utils_lib.run_cmd(self, 'sudo chmod a+rw /var/run/docker.sock')
        utils_lib.run_cmd(self, 'git clone https://github.com/aws/aws-nitro-enclaves-cli.git',
                          msg='clone nitro-enclaves-cli ')
        if not cli_installed:
            for i in range(3):
                first_row = int(utils_lib.run_cmd(self, f"grep -n '{first[i]}' {update_files[i]} | cut -f1 -d:"))
                end_row = int(utils_lib.run_cmd(self, f"grep -n '{end[i]}' {update_files[i]} | cut -f1 -d:"))
                utils_lib.run_cmd(self, f"sed -i '{first_row}, {end_row}d' {update_files[i]}")
            utils_lib.run_cmd(self, f"sed -i '{first_row}i\install: install-tools' aws-nitro-enclaves-cli/Makefile ")
            utils_lib.run_cmd(self,
                              'cd aws-nitro-enclaves-cli ; export NITRO_CLI_INSTALL_DIR=/ && make nitro-cli && make vsock-proxy;sudo make NITRO_CLI_INSTALL_DIR=/ install',
                              timeout=1800, msg='make and install nitro-cli')
            cmd = 'ls -l /etc/profile.d/nitro-cli-env.sh'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check nitro-cli-env.sh exists')
            utils_lib.run_cmd(self, 'echo source /etc/profile.d/nitro-cli-env.sh >> ~/.bashrc')
        utils_lib.run_cmd(self,
                          'source /etc/profile.d/nitro-cli-env.sh ; cd aws-nitro-enclaves-cli ; timeout 5 nitro-cli-config -i',
                          expect_not_kw='Could not')
        utils_lib.run_cmd(self,
                          'sudo systemctl enable nitro-enclaves-allocator.service && sudo systemctl start nitro-enclaves-allocator.service')
        utils_lib.run_cmd(self,
                          'nitro-cli build-enclave --docker-dir /usr/share/nitro_enclaves/examples/hello --docker-uri hello:latest --output-file hello.eif',
                          msg='build enclave')
        utils_lib.run_cmd(self, 'sudo cat /var/log/nitro_enclaves/nitro_enclaves.log', msg='attach this files content when build fail')
        utils_lib.run_cmd(self,
                          'sudo nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path hello.eif --debug-mode',
                          expect_kw='Started', msg='run enclave')
        EnclaveID = utils_lib.run_cmd(self, 'nitro-cli describe-enclaves |grep EnclaveID', msg='get EnclaveID')
        if "enc" not in EnclaveID:
            utils_lib.run_cmd(self, 'sudo dmesg|tail -50')
            self.fail("No enclave id found")
        EnclaveID = EnclaveID[18:-3]
        utils_lib.run_cmd(self, f'timeout 10 nitro-cli console --enclave-id {EnclaveID}', expect_kw='Successfully',
                          msg='get the console')
        utils_lib.run_cmd(self, f'sudo nitro-cli terminate-enclave --enclave-id {EnclaveID}',
                          expect_kw='"Terminated": true', msg='terminate enclave')

    def test_able_to_sync_chrony_server(self):
        """
        case_name:
            test_able_to_sync_chrony_server
        case_tags:
            time keeping
        case_status:
            approved
        title:
            Check guest able to sync time to chrony server
        importance:
            medium
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_general_test.py
        setup_teardown:
            Recover chrony default configure in tear down.
        environment:
            N/A
        component:
            time keeping
        bug_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            minl@redhat.com
        description: |
            Check guest able to sync time to chrony server
        key_steps: |
            # Change guest time through date command
            # edit config file: /etc/chrony.conf, then restart chrony service
                - Add "server clock.redhat.com"
                - Comment "makestep 1.0 3" line
                - Add "makestep 1 -1"
                - Restart chronyd service
            #Check guest time sync to chrony server
        expected_result: |
            - guest time can sync to chrony server.
        debug_want: |
            - N/A
        """
        utils_lib.run_cmd(self, "timedatectl status")
        utils_lib.run_cmd(self, "sudo hwclock --verbose")
        #Check if VM has chronyc command
        utils_lib.is_cmd_exist(self, 'chronyc')
        #Change VM time
        utils_lib.run_cmd(self, 'sudo date -s 00:00:00', expect_ret=0)
        utils_lib.run_cmd(self, 'date "+%H:%M:%S"', expect_kw="00:00:")
        #Check if chrony source available, if not, add available source.
        chrony_source = utils_lib.run_cmd(self, "chronyc sources -v", expect_ret=0)
        utils_lib.run_cmd(self, 'sudo cp /etc/chrony.conf /etc/chrony.conf.backup')
        if not re.search('\^\*', chrony_source):
            cmd1 = 'sudo sed -i "/Please consider joining the pool/a\server clock.redhat.com" \
                /etc/chrony.conf'
            utils_lib.run_cmd(self, cmd1, expect_ret=0)
        cmd2 = 'sudo sed -i "/makestep 1.0 3/c\makestep 1 -1" /etc/chrony.conf'
        utils_lib.run_cmd(self, cmd2, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo systemctl restart chronyd.service', expect_ret=0)
        for count in utils_lib.iterate_timeout(
            240, "check chrony server is in use", wait=10):
            chrony_source = utils_lib.run_cmd(self, "chronyc sources -v", expect_ret=0)
            if re.search('\^\*', chrony_source): break
        for count in utils_lib.iterate_timeout(
            240, "check date be synced by chrony"):
            date=utils_lib.run_cmd(self, 'date')
            if not re.search("00:0", date): break
        date_now=int(utils_lib.run_cmd(self, 'date +%s'))
        date_now_hw=int(utils_lib.run_cmd(self, "sudo hwclock --verbose | grep 'System Time' \
            | cut -d : -f 2 | cut -d ' ' -f 2 | cut -d . -f 1"))
        delta = date_now_hw - date_now
        self.assertLess(delta, 2, "delta between hwclock and date shoud less than 2 seconds")

    def _test_vm_time_sync_host(self, action):
        #check chronyd service, if enabled, disable it.
        utils_lib.run_cmd(self, 'sudo systemctl stop chronyd.service')
        chrony_check = utils_lib.run_cmd(self, 'sudo systemctl list-unit-files | grep chronyd.service')
        if re.search('enabled', chrony_check):
            utils_lib.run_cmd(self, 'sudo chkconfig chronyd off')
        if action == 'reboot':
            utils_lib.run_cmd(self, 'sudo date -s 00:00:00', expect_ret=0)
            utils_lib.run_cmd(self, 'date', expect_kw="00:00:")
            self.vm.reboot(wait=True)
            utils_lib.init_connection(self, timeout=180)
        elif action == 'migration':
            self.vm.migrate()
        cmd = 'date +%s'
        host_date = utils_lib.send_ssh_cmd(self.vm.host_ip, self.vm.host_username, \
            self.vm.host_password, cmd)[1]
        vm_date = utils_lib.run_cmd(self, cmd)
        delta = int(host_date) - int(vm_date)
        self.assertLessEqual(delta, 4, "delta shoud not bigger than 4 seconds")

    def test_vm_time_sync_host_after_boot(self):
        """
        case_name:
            test_vm_time_sync_host_after_boot
        case_tags:
            time keeping
        case_status:
            approved
        title:
            Check guest vm time synced with host after reboot
        importance:
            medium
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_general_test.py
        setup_teardown:
            Recover chrony default configure in tear down.
        environment:
            N/A
        component:
            time keeping
        bug_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            minl@redhat.com
        description: |
            Check guest vm time synced with host after reboot.
        key_steps: |
            # Stop chrony service.
            # Check if chronyd.service in systemctl list-unit-files, if yes, chkconfig off it.
            # Change VM's date.
            # Check time between guest vm and host after reboot VM.
        expected_result: |
            - guest time same as the host time.
        debug_want: |
            - N/A
        """
        if not self.vm:
            self.skipTest("Skip as no VM inited")
        for attrname in ['host_ip']:
            if not hasattr(self.vm, attrname):
                self.skipTest("no {} for {} vm".format(attrname, self.vm.provider))
        self._test_vm_time_sync_host('reboot')

    def test_vm_time_sync_host_after_migration(self):
        """
        case_name:
            test_vm_time_sync_host_after_migration
        case_tags:
            time keeping
        case_status:
            approved
        title:
            Check guest vm time synced with host after migration.
        importance:
            medium
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_general_test.py
        setup_teardown:
            Recover chrony default configure in tear down.
        environment:
            N/A
        component:
            time keeping
        bug_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            minl@redhat.com
        description: |
            Check guest vm time synced with host
        key_steps: |
            # Check chrony source, if there has available server, stop chrony service.
            # Stop chrony service.
            # Check if chronyd.service in systemctl list-unit-files, if yes, chkconfig off it.
        expected_result: |
            - guest time same as the host time.
        debug_want: |
            - N/A
        """
        if not self.vm:
            self.skipTest("Skip as no VM inited")
        for attrname in ['host_ip']:
            if not hasattr(self.vm, attrname):
                self.skipTest("no {} for {} vm".format(attrname, self.vm.provider))
        self._test_vm_time_sync_host('migration')

    def tearDown(self):
        utils_lib.finish_case(self)
        if "test_cpu_hotplug_no_workload" in self.id():
            cmd = "cat /sys/devices/system/cpu/cpu1/online"
            out = utils_lib.run_cmd(self, cmd)
            if '0' in out:
                cmd = "sudo bash -c 'echo 1 > /sys/devices/system/cpu/cpu1/online'"
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg="enable cpu1")
        if "test_able_to_sync_chrony_server" in self.id():
            cmd1 = 'sudo cp /etc/chrony.conf.backup /etc/chrony.conf'
            cmd2 = 'sudo systemctl restart chronyd.service'
            for cmd in [cmd1, cmd2]:
                utils_lib.run_cmd(self, cmd, expect_ret=0)
        if "test_vm_time_sync_host" in self.id():
            utils_lib.run_cmd(self, 'sudo chkconfig chronyd on')
            utils_lib.run_cmd(self, 'sudo systemctl start chronyd.service')
        if "test_z_nitro_enclaves" in self.id():
            # delete enclave enabled vm, because 3rd party docker installed
            if self.vm and self.vm.provider == 'aws':
                if self.vm.is_exist() and self.vm.enclave_enabled and not self.params.get('no_cleanup'):
                    self.vm.delete()
                    if not self.vm.create():
                        self.vm.create()
                utils_lib.init_connection(self, timeout=self.ssh_timeout)

if __name__ == '__main__':
    unittest.main()
