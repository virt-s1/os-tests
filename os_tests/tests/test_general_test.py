import unittest
import re
from os_tests.libs import utils_lib
import time

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
        '''
        no hang/panic happen
        polarion_id:
        bz: 1650273
        '''
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
        No exception when run cpupower command
        polarion_id: N/A
        bz: 1626505, 1659883
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
            2. # # ./fipstest

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
        printf("fips mode set.\\n");
    }
    else{
        printf("fips mode not set.\\n");
    }
    if (FIPS_selftest()){
        printf("fips selftest pass.\\n");
    }
    else{
        printf("fips selftest failed.\\n");
        ERR_print_errors_fp(stderr);
    }
}
int main(int argc, char *argv[])
{
	fips_test(0);
	fips_test(1);
}
        """
        utils_lib.is_pkg_installed(self, pkg_name="openssl-devel")
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
        cmd_list = ['wget https://github.com/redis/redis/files/5717040/redis_8124.c.txt',
                    'mv redis_8124.c.txt redis_8124.c',
                    'gcc -o reproduce redis_8124.c',
                    'sudo systemd-run --scope -p MemoryLimit=550M ./reproduce']
        for cmd in cmd_list:
            out = utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=120)
        if 'Your kernel looks fine' not in out:
            self.fail("'Your kernel looks fine' not found in {}".format(out))

    def test_fsadm_resize(self):
        '''
        bz: 1905705
        polarion_id: N/A
        fsadm resize should not crash as below without NEW_SIZE specified
        # fsadm resize $(findmnt -n -o source /)
        /sbin/fsadm: line 818: $3: unbound variable
        expected result:
        fsadm does nothing since the filesystem is already at maximum size
        '''
        utils_lib.is_cmd_exist(self, 'fsadm')
        utils_lib.run_cmd(self, 'sudo fsadm resize $(findmnt -n -o source /)', expect_ret=0,
            expect_not_kw="unbound variable", msg="fsadm should not crash")

    def test_subscription_manager_auto(self):
        '''
        bz: 1932802, 1905398
        '''
        cmd = "sudo rpm -qa|grep rhui"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg='skip test if rhui is not installed')

        product_id = utils_lib.get_product_id(self)
        if float(product_id) < 8.4:
            self.skipTest('skip in earlier than el8.4')
        self.log.info("Auto registeration only supports aws platform for now.")

        cmd = "sudo subscription-manager config"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="auto_registration = 1,manage_repos = 0", msg='try to check subscription-manager config')
        cmd = "sudo systemctl is-enabled rhsmcertd"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to check rhsmcertd enabled')
        cmd = "sudo subscription-manager config --rhsmcertd.auto_registration_interval=1"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to change rhsmcertd.auto_registration_interval from 60min to 1min')
        cmd = "sudo systemctl restart rhsmcertd"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='restart rhsmcertd')
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
        '''
        bz: 1862431
        des: "subscription-manager config" output should equal "subscription-manager config --list"
        '''
        utils_lib.is_cmd_exist(self, 'subscription-manager')
        cmd1 = "sudo subscription-manager config"
        out1 = utils_lib.run_cmd(self, cmd1, expect_ret=0, msg='get {} output'.format(cmd1))
        cmd2 = "sudo subscription-manager config --list"
        out2 = utils_lib.run_cmd(self, cmd2, expect_ret=0, msg='get {} output'.format(cmd2))
        if out1 != out2:
            self.fail('"{}" output not same with "{}"'.format(cmd1,cmd2))

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
            2. $ ls /run/libpod/exits/

        expected_result:
            Step2 return nothing.
        '''
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
        cmd = "ls /run/libpod/exits/"
        utils_lib.run_cmd(self, cmd, expect_output='',msg='check if saved exit code in tmpfs')

    def test_podman_rm_stopped(self):
        '''
        bz: 1913295
        des: podman can remove a stopped container
        '''
        self.log.info("Test podman can remove a stopped container")
        utils_lib.is_cmd_exist(self, 'podman')
        cmd = "podman ps -a"
        utils_lib.run_cmd(self, cmd, msg='try to list all containers before testing')
        cmd = "podman rm -a -f"
        utils_lib.run_cmd(self, cmd, msg='try to clean all containers before testing')
        cmd = "podman run --name myctr1 -td quay.io/libpod/alpine"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='run myctr1')
        cmd = "podman run --name myctr2 -td quay.io/libpod/alpine"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='run myctr2')
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
        '''
        polarion_id:
        bz: 1663266
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
        utils_lib.run_cmd(self, "dmesg", expect_not_kw='Call trace,Call Trace')

if __name__ == '__main__':
    unittest.main()