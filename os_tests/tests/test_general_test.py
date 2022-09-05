import unittest
import re
from os_tests.libs import utils_lib
import time
import os

class TestGeneralTest(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')

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
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource'

        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check current clock source')
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
available_clocksource'

        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        for clocksource in output.split(' '):
            cmd = 'sudo bash -c \'echo "%s" > /sys/devices/system/clocksource/clocksource0/\
current_clocksource\'' % clocksource
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Change clocksource to %s' % clocksource)
            cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource'

            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=clocksource,
                        msg='Check current clock source')
        utils_lib.run_cmd(self, 'dmesg|tail -30', expect_ret=0)

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
        utils_lib.run_cmd(self, 'dmesg|tail -30', expect_ret=0)

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
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Failed,FAILED', timeout=120)


    def test_fio_cpuclock(self):
        """
        case_name:
            test_fio_cpuclock
        component:
            fio
        bugzilla_id:
            1943474
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
            3. # gcc -o reproduce redis_8124.c
            4. # systemd-run --scope -p MemoryLimit=550M ./reproduce
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
        if self.params['remote_node'] is not None:
            self.log.info('Copy {} to remote'.format(redis_src))
            self.SSH.put_file(local_file=redis_src, rmt_file=redis_src_tmp)
        else:
            cmd = "sudo cp -f {} {}".format(redis_src, redis_src_tmp)
            utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=120)
        cmd_list = ['gcc -o /tmp/reproduce /tmp/redis_8124.c',
                    'sudo systemd-run --scope -p MemoryLimit=550M /tmp/reproduce']
        for cmd in cmd_list:
            out = utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=120)
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

    def test_subscription_manager_auto(self):
        """
        case_name:
            test_subscription_manager_auto
        component:
            subscription-manager
        bugzilla_id:
            1932802, 1905398
        is_customer_case:
            <optional: True or False>
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
        debug_want:
            N/A
        """
        product_name = utils_lib.get_os_release_info(self, field='NAME')
        if 'Red Hat Enterprise Linux' not in product_name:
            self.skipTest('Only for RHEL test.')
        if not (utils_lib.is_aws(self) or utils_lib.is_azure(self)):
            self.skipTest('Auto registeration only supports AWS and Azure platforms for now.')
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < 8.4:
            self.skipTest('skip in earlier than el8.4')

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
            3. # gcc -g -o pp test.c
            4. # ./pp
        expect_result:
            pp crashed and new core file is generated under /var/lib/systemd/coredump
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
        cmd = "gcc -g -o /tmp/pp {}".format(test_file)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'ulimit -c unlimited;/tmp/pp', msg='run it to trigger core dump')
        utils_lib.run_cmd(self, 'sudo ls /var/lib/systemd/coredump/core.pp*', expect_ret=0, msg='check core file generated')
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
        cmd = "sudo yum install -y libvirt"
        utils_lib.run_cmd(self, cmd, msg = "install libvirt pkg")
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
        utils_lib.check_log(self, "error,warn,fail,trace,Trace", log_cmd='dmesg -T', cursor=self.dmesg_cursor)

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
        utils_lib.run_cmd(self, "dmesg", expect_not_kw='Call trace,Call Trace')


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
        cmd = "lsblk | grep sr"
        all = utils_lib.run_cmd(self,cmd,cancel_kw="sr0",
                                msg="check if machine mounted CDROM").rstrip().split("\n")
        for i in all:
            part = i.split(" ")[0]
            cmd = "sudo wipefs -a /dev/"+part
            utils_lib.run_cmd(self,cmd,expect_ret=1,msg="erase signature")
            cmd = "dmesg -T | grep %s" % part
            utils_lib.run_cmd(self,cmd,expect_not_kw="error",msg="check if there's error")

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
        cmd='rpm -qa "grub2*"'
        utils_lib.run_cmd(self,cmd,msg="show grub version")
        cmd="sudo grub2-mkconfig -o /tmp/grub.cfg"
        utils_lib.run_cmd(self,cmd,expect_kw="done",msg="generate file")
        cmd='sudo cat /tmp/grub.cfg'
        utils_lib.run_cmd(self,cmd,msg="check if there is saved_entry",expect_kw="{saved_entry"+"}")
    def test_z_nitro_enclaves(self):
        '''
        case_name:
            test_check_nitro_enclaves
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            2011739
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Test whether nitro enclave works when it is enabled.
        key_steps:
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
        '''
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
        if 'Red Hat Enterprise Linux' not in product_name:
            self.skipTest('Only support run in RHEL for now.')
        update_files = ["aws-nitro-enclaves-cli/bootstrap/nitro-cli-config", "aws-nitro-enclaves-cli/bootstrap/env.sh",
                        "aws-nitro-enclaves-cli/Makefile"]
        first = ["# Remove an older driver if it is inserted.", "lsmod | grep -q nitro_enclaves || ",
                 "install: install-tools nitro_enclaves"]
        end = ['[ "$(lsmod | grep -cw $DRIVER_NAME)" -eq 1 ] || fail "The driver is not visible."',
               'sudo insmod ${NITRO_CLI_INSTALL_DIR}/lib/modules/extra/nitro_enclaves/nitro_enclaves.ko',
               '${NITRO_CLI_INSTALL_DIR}/lib/modules/$(uname -r)/extra/nitro_enclaves/nitro_enclaves.ko']
        utils_lib.run_cmd(self, 'sudo dnf groupinstall "Development Tools" -y', msg='install development tools', timeout=300)
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < 9:
            utils_lib.run_cmd(self,
                              'sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo',
                              msg='add docker repo')
            utils_lib.run_cmd(self, 'sudo dnf config-manager --save --setopt=*docker*.gpgcheck=0')
            utils_lib.run_cmd(self, 'sudo dnf install docker-ce docker-ce-cli containerd.io --allowerasing -y', expect_ret=0,
                              msg='install docker', timeout=300)
        else:
            utils_lib.run_cmd(self,
                              'echo -e "[fedora]\nname=Fedora 34 - \$basearch\nbaseurl=https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/\$basearch/os/" |sudo tee /etc/yum.repos.d/fedora34.repo')
            utils_lib.run_cmd(self,
                              'sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo',
                              msg='add docker repo')
            utils_lib.run_cmd(self, "sudo sed -i 's/$releasever/34/g' /etc/yum.repos.d/docker-ce.repo")
            utils_lib.run_cmd(self, 'sudo dnf config-manager --save --setopt=*docker*.gpgcheck=0')
            utils_lib.run_cmd(self, 'sudo dnf module disable container-tools -y')
            utils_lib.run_cmd(self,
                              'sudo dnf install docker-ce docker-ce-cli containerd.io --nogpgcheck --allowerasing -y', expect_ret=0,
                              msg='install docker', timeout=300)
            utils_lib.run_cmd(self, 'sudo dnf module enable container-tools -y')
            utils_lib.run_cmd(self, 'sudo dnf config-manager --disable fedora')
        utils_lib.run_cmd(self, 'sudo systemctl enable --now docker', expect_ret=0,
                          msg='enable and start docker')
        utils_lib.run_cmd(self, 'sudo usermod -aG docker $USER', msg='add to the docker group')
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
                              timeout=1200, msg='make and install nitro-cli')
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
        utils_lib.run_cmd(self,
                          'sudo nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path hello.eif --debug-mode',
                          expect_kw='Started', msg='run enclave')
        EnclaveID = utils_lib.run_cmd(self, 'nitro-cli describe-enclaves |grep EnclaveID', msg='get EnclaveID')
        EnclaveID = EnclaveID[18:-3]
        utils_lib.run_cmd(self, f'timeout 10 nitro-cli console --enclave-id {EnclaveID}', expect_kw='Successfully',
                          msg='get the console')
        utils_lib.run_cmd(self, f'sudo nitro-cli terminate-enclave --enclave-id {EnclaveID}',
                          expect_kw='"Terminated": true', msg='terminate enclave')

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
