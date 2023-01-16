import unittest
from os_tests.libs import utils_lib
import json
import os
import re
import time

class TestGeneralCheck(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        utils_lib.msg_to_syslog(self)
        if self.id().endswith(('test_check_rpm_V_differences', 'test_check_rpm_V_missing')):
            rpm_V_file = '/tmp/{}_rpm_V.log'.format(self.run_uuid)
            self.output = utils_lib.run_cmd(self, 'cat {}'.format(rpm_V_file), msg="check if output exists")
            if 'No such file' in self.output:
                skips = ['rhui','ltp']
                pkg = utils_lib.run_cmd(self, 'rpm -qa', msg="list the pkgs")
                pkgs = pkg.split('\n')
                import copy
                check_list = copy.deepcopy(pkgs)
                for pkg in pkgs:
                    for i in skips:
                        if i in pkg:
                            check_list.remove(pkg)
                cmd = 'sudo rpm -V {} > {} 2>&1'.format(' '.join(check_list), rpm_V_file)
                utils_lib.run_cmd(self, cmd, msg="verify pkgs", timeout=600)
                self.output = utils_lib.run_cmd(self, 'cat {}'.format(rpm_V_file), expect_ret=0, msg="check if output exists again")
        if any(x in self.id().lower() for x in ['systemd_analyze_verify', 'journalctl_service_unknown']):    
            check_file = self.utils_dir + '/systemd_analyze_services.sh'
            check_file_tmp = '/tmp/systemd_analyze_services.sh'
            if self.params.get('remote_node') is not None:
                cmd = 'ls -l {}'.format(check_file_tmp)
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='check if {} exists'.format(check_file))
                if ret != 0:
                    self.log.info('Copy {} to remote'.format(check_file))
                    self.SSH.put_file(local_file=check_file, rmt_file=check_file_tmp)
            else:
                cmd = 'sudo cp -f {} {}'.format(check_file,check_file_tmp)
                utils_lib.run_cmd(self, cmd)
            check_file = check_file_tmp
            utils_lib.run_cmd(self, 'sudo chmod 755 {}'.format(check_file_tmp))
            self.systemd_analyze_verify_file = '/tmp/{}_systemd_analyze_verify.log'.format(self.run_uuid)
            cmd = 'sudo bash -c "{} {}"'.format(check_file, self.systemd_analyze_verify_file)
            output = utils_lib.run_cmd(self, cmd, timeout=240, msg="start analyze......")

    def test_check_avclog(self):
        """
        case_name:
            test_check_avclog
        component:
            selinux-policy
        bugzilla_id:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            test if avc log exist
        key_steps:
            sudo ausearch -m AVC -ts today
        expect_result:
            no avc log returned
        debug_want:
            # rpm -qa selinux\* container\* | sort
        """
        cmd = "rpm -qa selinux\* container\* | sort"
        utils_lib.run_cmd(self, cmd, msg='please attach this log if bug is found')
        cmd = "sudo ausearch -m AVC -ts today -i"
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Checking avc log!', rmt_get_pty=True)

    def test_check_avclog_nfs(self):
        """
        case_name:
            test_check_avclog_nfs
        component:
            kernel
        bugzilla_id:
            1771856
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            Check if there's avc log after mounting
        key_steps:
            1.check if there's nfs installed
            2.# systemctl start nfs-server.service
            3.# mkdir /tmp/testrw
            4.# chmod -R 777 /tmp/testrw
            5.# exportfs -o rw,insecure_locks,all_squash,fsid=1 *:/tmp/testrw
            6.# mount -t nfs 127.0.0.1:/tmp/testrw /mnt
        expect_result:
            no new avc log generated
        debug_want:
            # rpm -qa selinux\* container\* | sort
        """
        cmd = "rpm -qa selinux\* container\* | sort"
        utils_lib.run_cmd(self, cmd, msg='please attach this log if bug is found')
        time_start = utils_lib.run_cmd(self, "date '+%T'", msg='retrive test system current time')
        self.log.info("Check no permission denied at nfs server - bug1655493")
        utils_lib.is_pkg_installed(self,pkg_name='nfs-utils')
        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
        if float(product_id) >= 8.0:
            cmd = 'sudo systemctl start nfs-server.service'
        else:
            cmd = "sudo systemctl start nfs"

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

        time.sleep(10)
        cmd = "sudo ausearch -i -m AVC -ts today {}".format(time_start)
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='check if new avc log generated', rmt_get_pty=True)

    def test_check_available_clocksource(self):
        """
        case_name:
            test_check_available_clocksource
        component:
            kernel
        bugzilla_id:
            1726487
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            Check if there is clocksource in available_clocksource
        key_steps:
            1.lscpu
            2.sudo cat /sys/devices/system/clocksource/clocksource0/available_clocksource
            3.check available_clocksource
        expect_result:
            the clocksource matched to the system is expected.
            Xen - xen,tsc,hpet,acpi_pm,
            aarch64 - arch_sys_counter,
            ppc64le - timebase,
            s390x - tod,
            Microsoft - hyperv_clocksource_tsc_page,acpi_pm,
            AuthenticAMD - kvm-clock,tsc,acpi_pm,
            GenuineIntel - kvm-clock,tsc,acpi_pm
            Others - tsc,hpet,acpi_pm'

        """
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        if 'Xen' in output:
            expect_clocks = 'xen,tsc,hpet,acpi_pm'
        elif 'aarch64' in output:
            expect_clocks = 'arch_sys_counter'
        elif 'ppc64le' in output and 'KVM' in output and not utils_lib.is_metal(self):
            expect_clocks = 'timebase'
        elif 's390x' in output and 'KVM' in output and not utils_lib.is_metal(self):
            expect_clocks = 'tod'
        elif 'Microsoft' in output:
            expect_clocks = 'hyperv_clocksource_tsc_page,acpi_pm'
        elif 'AuthenticAMD' in output and 'KVM' in output and not utils_lib.is_metal(self):
            expect_clocks = 'kvm-clock,tsc,acpi_pm'
        elif 'GenuineIntel' in output and 'KVM' in output and not utils_lib.is_metal(self):
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
        """
        case_name:
            test_check_boot_time
        component:
            rng-tools
        bugzilla_id:
            1776710
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check if there's boot time delay
        key_steps:
            1.check journal log and system bootup time,
            2.compare the bootup time with max boot time
        expect_result:
            real boot time doesn't delay compared to max_boot_time
        debug_want:
            journal log
        """
        max_boot_time = self.params.get('max_boot_time')
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=max_boot_time, ratio=0, msg="Compare with cfg specified max_boot_time")

    def test_check_dmesg_error(self):
        """
        case_name:
            test_check_dmesg_error
        component:
            kernal
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if there are error in dmesg
        key_steps:
            dmesg
        expect_result:
            no error return
        debug_want:
            dmesg
        """
        utils_lib.check_log(self, 'error', log_cmd='dmesg')

    def test_check_dmesg_fail(self):
        """
        case_name:
            test_check_dmesg_fail
        component:
            kernal
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if there are fail in dmesg
        key_steps:
            dmesg
        expect_result:
            no fail return
        debug_want:
            dmesg
        """
        utils_lib.check_log(self, 'fail', log_cmd='dmesg')

    def test_check_dmesg_warn(self):
        """
        case_name:
            test_check_dmesg_warn
        component:
            kernal
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if there are warn in dmesg
        key_steps:
            dmesg
        expect_result:
            no warn return
        debug_want:
            dmesg
        """
        utils_lib.check_log(self, 'warn', log_cmd='dmesg')

    def test_check_dmesg_unable(self):
        """
        case_name:
            test_check_dmesg_unable
        component:
            kernel
        bugzilla_id:
            1779454
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check if there's any unable in dmesg
        key_steps:
            ckeck dmesg log
        expect_result:
            There's no unable in dmesg log
        debug_want:
            dmesg log
        """
        utils_lib.check_log(self, 'unable', log_cmd='dmesg')

    def test_check_dmesg_calltrace(self):
        """
        case_name:
            test_check_dmesg_calltrace
        component:
            kernel
        bugzilla_id:
            1777179
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            Check if there is cal trace in dmesg
        key_steps:
            dmesg
        expect_result:
            no call trace returned
        debug_want:
            dmesg output
        """
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, expect_not_kw='Call trace,Call Trace', msg="Check there is no call trace in dmesg")

    def test_check_dmesg_unknownsymbol(self):
        """
        case_name:
            test_check_dmesg_unknownsymbol
        case_file:
            os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_unknownsymbol
        component:
            kernel
        bugzilla_id:
            1649215, 2018886
        customer_case_id:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Make sure there is no 'Unknown' keyword from dmesg output.
            'BOOT_IMAGE' is a know unknow command line parameters, others are not expected.
            https://lore.kernel.org/all/20210511211009.42259-1-ahalaney@redhat.com/T/#u

        key_steps:
            # dmesg|grep -i Unknow
        expect_result:
            No unknow value found
        debug_want:
            # dmesg
        """
        utils_lib.check_log(self, 'Unknown symbol,Unknown command line,Unknown,unknown', log_cmd='dmesg')

    def test_check_dmesg_nmi(self):
        '''
        case_name:
            test_check_dmesg_nmi
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1917824
        customer_case_id:
            02803548
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
           Check no "NMI received" before and after run 'perf top' in dmesg.
        key_steps:
            1.#dmesg
            2.#timeout 20 perf top
            3.#dmesg
        expected_result:
            There is no "NMI received" before and after run 'perf top' in dmesg.
        '''
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, expect_not_kw='NMI received', msg="Check there is no 'NMI received' in dmesg before run 'perf top'")
        utils_lib.run_cmd(self, 'timeout --foreground 20 perf top ', msg="Run 'perf top' for 20s. ")
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, expect_not_kw='NMI received', msg="Check there is no 'NMI received' in dmesg after run 'perf top'")


    def test_check_dmidecode_dump_segfault(self):
        '''
        case_name:
            test_check_dmidecode_dump_segfault
        case_priority:
            2
        component:
            dmidecode
        bugzilla_id:
            1885823
        customer_case_id:
            02939365
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check there is no segmentation fault while run 'dmidecode --dump'
        key_steps:
            # dmidecode --dump |grep -i Segmentation 
        expected_result:
            No segmentation fault found.
        '''
        utils_lib.is_cmd_exist(self, cmd='dmidecode')
        if self.params.get('remote_node') is not None:
            binfile = '/tmp/dmidecode_debug.bin'
            cmd = "sudo dmidecode --dump-bin {}".format(binfile)
            utils_lib.run_cmd(self, cmd, msg='save dmidecode_debug.bin for debug purpose, please attach it if file bug')
            self.log.info('retrive {} from remote'.format(binfile))
            self.SSH.get_file(rmt_file=binfile,local_file='{}/attachments/dmidecode_debug.bin'.format(self.log_dir))
        else:
            cmd = "sudo dmidecode --dump-bin {}/attachments/dmidecode_debug.bin".format(self.log_dir)
            utils_lib.run_cmd(self, cmd, msg='save dmidecode_debug.bin for debug purpose, please attach it if file bug')
        cmd = "sudo dmidecode --dump"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Segmentation')

    def test_check_dmidecode_outofspec(self):
        """
        case_name:
            test_check_dmidecode_outofspec
        component:
            dmidecode
        bugzilla_id:
            1858350
        maintainer:
            xiliang@redhat.com
        is_customer_case:
            True
        description:
            dmidecode command prints "OUT OF SPEC" messages for empty NVMe and DIMM slots
        key_steps:
            1.sudo dmidecode --dump-bin {log_dir}/attachments/dmidecode_debug.bin
            2.sudo dmidecode
        expect_result:
            It should not print "OUT OF SPEC" in output
        debug_want:
            dmidecode_debug.bin
        """
        utils_lib.is_cmd_exist(self, cmd='dmidecode')
        cmd = "sudo dmidecode --dump-bin {}/attachments/dmidecode_debug.bin".format(self.log_dir)
        utils_lib.run_cmd(self, cmd, msg='save dmidecode_debug.bin for debug purpose, please attach it if file bug')
        utils_lib.run_cmd(self,
                    'sudo dmidecode',
                    expect_ret=0,
                    expect_not_kw='OUT OF SPEC',
                    msg='Check there is no "OUT OF SPEC" in dmidecode output')

    def test_check_cpu_vulnerabilities(self):
        """
        case_name:
            test_check_cpu_vulnerabilities
        component:
            kenel
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if cpu has unexpected Vulnerable
        key_steps:
            1.rpm -qa|grep microcode
            2.rpm -qa|grep linux-firmware
            3.sudo grep . /sys/devices/system/cpu/vulnerabilities/* | sed 's/:/^/' | column -t -s^
            4.get cpu vulnerabilities according to server type
        expect_result:
            There's no vulnerable returned
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self, "rpm -qa|grep microcode", msg='Get microcode version')
        utils_lib.run_cmd(self, "rpm -qa|grep linux-firmware",msg='get linux-firmware pkg version')
        check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/* | \
sed 's/:/^/' | column -t -s^"
        utils_lib.run_cmd(self, check_cmd, expect_ret=0, msg='retrive cpu vulnerabilities statics')

        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if utils_lib.is_metal(self):
            self.log.info(
                "Bare metal instance should not have any vulnerable (microload loaded).")
            check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/* | \
sed 's/:/^/' | column -t -s^"
        elif 'el7' in output:
            self.log.info(
                "Skip spec_store_bypass,Retpoline and mds in RHEL7 vms")
            check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/* | \
grep -v spec_store_bypass|grep -v 'tsx_async_abort'|grep -v 'Vulnerable: Retpoline'|\
grep -v mds|grep -v 'no microcode'|grep -v retbleed| sed 's/:/^/' | column -t -s^"
        else:
            self.log.info(
                "Skip spec_store_bypass and mds,itlb_multihit in vms")
            check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/*|\
grep -v spec_store_bypass|grep -v 'tsx_async_abort'|grep -v mds|grep -v \
itlb_multihit|grep -v 'no microcode'|grep -v retbleed|sed 's/:/^/' | column -t -s^"

        utils_lib.run_cmd(self, check_cmd, expect_ret=0, expect_not_kw='Vulnerable')

    def test_check_cpuusage_exception(self):
        '''
        case_name:
            test_check_cpuusage_exception
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1956248
        customer_case_id:
            02929244
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check if there is a process taking high usage of CPU abnormally.
            If it shows the high usage of CPU abnormally(higher than 85% over 1min),the case fails.
        key_steps:
            1.#ps aux --sort=-%cpu|sed -n '2p'
        expected_result:
            The usage of CPU is normal(slower than 85% once in 1min).
        '''
        count=0
        for i in range(60):
            result_out = utils_lib.run_cmd(self, "ps aux --sort=-%cpu|sed -n '2p'", msg='Find process with highest usage of CPU')
            result_out = result_out.split(' ')
            while '' in result_out:
                result_out.remove('')
            if count == 0:
                lastpid = int(result_out[1])
            if float(result_out[2]) >= 85 and lastpid == int(result_out[1]):
                lastpid = int(result_out[1])
                count += 1
                time.sleep(1)
            else:
                break
        if count>=59:
            command =''
            for i in range(10, len(result_out)):
                command += result_out[i] + ' '
            self.fail(f'{command}(pid:{lastpid}) have abnormal usage of CPU.')

    def test_check_hostkey_permissions(self):
        """
        case_name:
            test_check_hostkey_permissions
        case_file:
            os_tests.tests.test_general_check.TestGeneralCheck.test_check_hostkey_permissions
        component:
            ssh
        bugzilla_id:
            2013644
        customer_case_id:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check ssh key files permission set are correct.
        key_steps:
            # ls -l /etc/ssh/{ssh_host_ecdsa_key,ssh_host_ed25519_key,ssh_host_rsa_key}
        expect_result:
            No '-rw-------' found
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self,
            "ls -l /etc/ssh/{ssh_host_ecdsa_key,ssh_host_ed25519_key,ssh_host_rsa_key}",
            expect_not_kw='-rw-------. 1 root root',
            msg='check ssh key files permission set are correct')

    def test_iostat_x(self):
        '''
        case_name:
            test_iostat_x
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1661977
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check "iostat -x" report and make sure there is no high utils when there is no obviously read/write operations.
        key_steps:
            1. # iostat -x
        expected_result: |
            No high utils reported when no obviously read/write operations.
            eg. # iostat -x
                Linux 4.18.0-236.el8.aarch64 (ip-xx-xxx-x-xxx.us-west-2.compute.internal) 	09/28/2020 	_aarch64_	(2 CPU)

                avg-cpu:  %user   %nice %system %iowait  %steal   %idle
                           7.77    0.00    1.48    0.69    0.00   90.06

                Device            r/s     w/s     rkB/s     wkB/s   rrqm/s   wrqm/s  %rrqm  %wrqm r_await w_await aqu-sz rareq-sz wareq-sz  svctm  %util
                nvme0n1         46.06    2.82   1587.81    274.62     0.00     0.23   0.00   7.52    0.50    1.32   0.00    34.47    97.31   0.86   4.19
                nvme1n1          0.15    0.00     10.43      0.00     0.00     0.00   0.00   0.00    1.00    0.00   0.00    70.40     0.00   1.50   0.02
        '''
        expect_utils = self.params.get('disk_utils')
        self.log.info("Check no disk utils lager than %s" % expect_utils)
        utils_lib.is_cmd_exist(self, cmd='iostat')
        cmd = 'sudo  iostat -x -o JSON'
        output = utils_lib.run_cmd(self, cmd)
        try:
            res_dict = json.loads(output)
            for x in res_dict["sysstat"]["hosts"][0]["statistics"][0]["disk"]:
                self.assertLessEqual(
                    x["util"],
                    expect_utils,
                    msg="Utils more than %s without any large io! act: %s" %
                    (expect_utils, x["util"]))
        except ValueError as err:
            self.log.info("cmd has no json support")
            cmd = "sudo iostat -x"
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            cmd = "sudo iostat -x|awk -F' ' '{print $NF}'"
            output = utils_lib.run_cmd(self, cmd, expect_ret=0)
            compare = False
            for util in output.split('\n'):
                if 'util' in util:
                    compare = True
                    continue
                if compare and not util == '':
                    if float(util) > expect_utils:
                        self.fail("Some disk's utils %s is larger than %s" %
                                  (util, expect_utils))

    def test_check_journal_calltrace(self):
        """
        case_name:
            test_check_journal_calltrace
        component:
            Operations
        bugzilla_id:
            1801999,1736818
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.conm
        description:
            Find if there are words like "Traceback","Backtrace" in journal
        key_steps:
            Check the journalctl log
        expect_result:
            There's no "Traceback"or"Backtrace" in journal, all scripts run without error 
        debug_want:
            journalctl log
        """
        utils_lib.check_log(self, 'Traceback,Backtrace', rmt_redirect_stdout=True)

    def test_check_journalctl_cannot(self):
        '''
        case_name:
            test_check_journalctl_cannot
        case_priority:
            2
        component:
            journal
        bugzilla_id:
            
        customer_case_id:
            
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check "journalctl |grep -i 'Could not'" reported and make sure there is 'Could not' log.
        key_steps:
            1.#journalctl |grep -i 'Could not'
        expected_result:
            No new unknown 'Could not' log found.
        '''
        utils_lib.check_log(self, 'Could not,can not', rmt_redirect_stdout=True)

    def test_check_journalctl_conflict(self):
        '''
        case_name:
            test_check_journalctl_conflict
        case_priority:
            2
        component:
            journal
        bugzilla_id:
            
        customer_case_id:
            
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check "journalctl |grep -i conflict" reported and make sure there is no conflict log.
        key_steps:
            1.#journalctl |grep -i conflict
        expected_result:
            No conflict log found.
        '''
        utils_lib.check_log(self, 'conflict', rmt_redirect_stdout=True)

    def test_check_journalctl_denied(self):
        '''
        case_name:
            test_check_journalctl_denied
        case_priority:
            2
        component:
            journal
        bugzilla_id:
            1978507
        customer_case_id:
            
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check "journalctl |grep -i denied" reported and make sure there is no unknown denied log.
        key_steps:
            1.#journalctl |grep -i denied
        expected_result:
            No new unknown denied log found.
        '''
        utils_lib.check_log(self, 'denied', rmt_redirect_stdout=True)

    def test_check_journalctl_disabled(self):
        """
        case_name:
            test_check_journalctl_disabled
        case_file:
            os_tests.tests.test_general_check.TestGeneralCheck.test_check_journalctl_disabled
        component:
            kernel
        bugzilla_id:
            N/A
        customer_case_id:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            - kaslr is enabled by default, check there is no 'KASLR disabled', please ignor this if 'nokaslr' used.
        key_steps:
            # journalctl|grep -i 'KASLR disabled'
        expect_result:
            "KASLR disabled" not found
        debug_want:
            # journalctl
        """
        expect_not_kws = 'KASLR disabled'
        utils_lib.check_log(self, expect_not_kws, rmt_redirect_stdout=True)

    def test_check_journalctl_dumpedcore(self):
        """
        case_name:
            test_check_journalctl_dumpedcore
        component:
            sssd
        bugzilla_id:
            1797973,2027674
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check if there is process core dumped during boot.
        key_steps:
            1.enable fips and reboot the system.
            2.dumped core
        expect_result:
            no core dump
        debug_want:
            attach core files under '/var/lib/systemd/coredump/' if report bz
        """
        utils_lib.check_log(self, 'dumped core', rmt_redirect_stdout=True)

    def test_check_journalctl_error(self):
        """
        case_name:
            test_check_journalctl_error
        component:
            kernel
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check the boot message
        key_steps:
            check dmesg
            check /var/log/mesages
        expect_result:
            no unexpected error
        debug_want:
            dmesg
        """
        utils_lib.check_log(self, 'error', skip_words='UpdateGSErrors', rmt_redirect_stdout=True)

    def test_check_journalctl_fail(self):
        '''
        case_name:
            test_check_journalctl_fail
        case_priority:
            1    
        component:
            kernel
        bugzilla_id:
            1879368
        polarion_id:
            RHEL7-103851
        maintainer:
            xiliang@redhat.com
        description:
            Check "journalctl |grep -i fail" reported and make sure there is nounknown fail log.
        key_steps:
            1.#journalctl |grep -i fail
        expected_result:
            No new unknown fail log found.
        '''
        utils_lib.check_log(self, 'fail', skip_words='nofail', rmt_redirect_stdout=True)

    def test_check_journalctl_not_found(self):
        '''
        case_name:
            test_check_journalctl_not_found
        case_priority:
            2
        component:
            journal
        bugzilla_id:
            1855252
        customer_case_id:
            
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check "journalctl |grep -i 'no such file'" reported and make sure there is file not found in log.
        key_steps:
            1.#journalctl |grep -i 'not found'
            2.#journalctl |grep -i 'no such file'
        expected_result:
            No new unknown not file found log found.
        '''
        utils_lib.check_log(self, 'not found,no such', rmt_redirect_stdout=True)

    def test_check_journalctl_unexpected(self):
        '''
        case_name:
            test_check_journalctl_unexpected
        case_priority:
            2
        component:
            journal
        bugzilla_id:
            1978507
        customer_case_id:
            
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check "journalctl |grep -i unexpected" reported and make sure there is no unknown unexpected log.
        key_steps:
            1.#journalctl |grep -i unexpected
        expected_result:
            No new unknown unexpected log found.
        '''
        utils_lib.check_log(self, 'unexpected', rmt_redirect_stdout=True)

    def test_check_journalctl_warn(self):
        """
        case_name:
            test_check_journalctl_warn
        component:
            kernel
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check the boot message
        key_steps:
            check dmesg
            check /var/log/mesages
        expect_result:
            no unexpected warn
        debug_want:
            dmesg
        """
        utils_lib.check_log(self, 'warn', rmt_redirect_stdout=True)

    def test_check_journalctl_invalid(self):
        """
        case_name:
            test_check_journalctl_invalid
        component:
            sg3_utils
        bugzilla_id:
            1750417
        is_customer_case:
            True
        maintainer:
            xiliang@redhat.com
        description:
            check if there's invalid in journal log
        key_steps:
            check journal log
        expect_result:
            no unexpected invalid in journal log
        debug_want:
            journal log
        """
        '''
        polarion_id:
        bz:1750417
        '''
        utils_lib.check_log(self, 'invalid', skip_words="Invalid user,invalid user", rmt_redirect_stdout=True)

    def test_check_journalctl_service_unknown_lvalue(self):
        """
        case_name:
            test_check_journalctl_service_unknown_lvalue
        case_file:
            https://github.com/liangxiao1/os-tests/blob/master/os_tests/tests/test_general_check.py
        component:
            systemd
        bugzilla_id:
            1871139,2115230
        customer_case_id:
            yes
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check service has no 'Unknown lvalue' in unit file
        key_steps:
            # systemd-analyze verify $service
        expect_result:
            # No 'Unknown lvalue' keywords in output
        debug_want:
            - service unit file content
            - output from 'systemd-analyze verify $service'
        """
        cmd = 'cat {}'.format(self.systemd_analyze_verify_file)
        utils_lib.check_log(self,'Unknown lvalue',log_cmd=cmd,rmt_redirect_stdout=True)

    def test_check_locale(self):
        '''
        case_name:
            test_check_locale
        case_file:
            https://github.com/liangxiao1/os-tests/blob/master/os_tests/tests/test_general_check.py
        case_priority:
            1
        component:
            glibc
        bugzilla_id:
            2000878
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check there are no errors on the output of 'locale'
        key_steps:
            1. # locale
        expected_result:
            No error information found.
        debug_want: |
            1. # rpm -qa | grep glibc
            2. # uname -r
        '''
        cmd = 'rpm -qa | grep glibc'
        utils_lib.run_cmd(self, cmd, msg='please attach {} output if file bug'.format(cmd))
        utils_lib.run_cmd(self, 'locale', expect_not_kw="Cannot", msg='check no errors about locale')
        cmd = "grep 'LANG=' /etc/locale.conf"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Get LANG in locale.conf")
        product_id = utils_lib.get_product_id(self)
        if float(product_id) >= 9.0:
            # workaround for the pending pkg release
            cmd = "rpm -q cloud-init"
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Get cloud-init rpm name")
            ver = output.lstrip('cloud-init-').split('-')[0]
            if (float(ver) >= 22.2):
                self.assertTrue(re.match(r'LANG="*C.UTF-8"*', output),
                                "default LANG is wrong -> %s" % output)
        else:
            self.assertTrue(re.match(r'LANG="*en_US.UTF-8"*', output),
                            "default LANG is wrong -> %s" % output)

    def test_check_lshw_mem(self):
        '''
        case_name:
            test_check_lshw_mem

        case_priority:
            1
        component:
            lshw
        bugzilla_id:
            1882157
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check "lshw -C memory -json" reported memory size is correct.
        key_steps:
            1. # lshw -C memory -json
        expected_result:
            No big gap found.
            eg. #  lshw -C memory -json|grep -i size
                    "size" : 98304,
                    "size" : 4286578688, <-- 4GiB is correct
                        "size" : 4286578688,
        '''
        if utils_lib.is_ahv(self):
            self.skipTest("Skip test as already covered in test_nutanix_vm.test_check_memory_size")

        utils_lib.is_cmd_exist(self, cmd='lshw')
        base_memory = utils_lib.get_memsize(self)
        cmd = 'sudo lshw -json'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        out = json.loads(output)['children'][0]["children"]
        for i in out:
            if i['id'] == 'memory':
                mem_in_byte = i['size']
                break
        mem_in_gib = mem_in_byte/1024/1024/1024
        self.log.info("lshw showed mem: {}".format(mem_in_gib))

        if mem_in_gib >= 4:
            utils_lib.compare_nums(self, mem_in_gib, base_memory, ratio=15)
        else:
            utils_lib.compare_nums(self, mem_in_gib, base_memory, ratio=17)

    def test_check_lsmem_segfault(self):
        '''
        case_name:
            test_check_lsmem_segfault
        case_priority:
            1
        component:
            util-linux
        bugzilla_id:
            1712768
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check there is no segmentation fault while running 'lsmem' and 'lsmem -o NODE'
        key_steps:
            # 1.lsmem
            # 2.lsmem -o NODE
        expected_result:
            No segmentation fault found.
        '''
        product_id = utils_lib.get_product_id(self)
        if utils_lib.is_arch(self,arch='aarch64') and float(product_id) < 9:
            self.skipTest('lsmem of version under el9 does not support arm platform ')
        utils_lib.run_cmd(self, 'lsmem', expect_ret=0, expect_not_kw='Segmentation', msg='check no segfault')
        utils_lib.run_cmd(self, 'lsmem -o NODE', expect_ret=0, expect_not_kw='Segmentation', msg='check no segfault')

    def test_check_lspci_invalid_domain(self):
        '''
        case_name:
            test_check_lspci_invalid_domain
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1551091
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check there is no 'Invalid domain' while running 'lspci'
        key_steps:
            # 1.lspci
        expected_result:
            'lspci' can list devices normally without "Invalid domain"
        '''
        utils_lib.is_cmd_exist(self, cmd='lspci')
        utils_lib.run_cmd(self, 'lspci', expect_ret=0, expect_not_kw='Invalid', msg='check no invalid domain')

    def test_check_lspci_nvme(self):
        '''
        case_name:
            test_check_lspci_nvme

        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1656862
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check all nvme pci devices are found by "lsblk"
        key_steps:
            1. # lspci|grep "Non-Volatile memory"|wc -l
            2. # lsblk -d|grep nvme|wc -l
        expected_result:
            The nums are equal.
        '''
        utils_lib.is_cmd_exist(self, cmd='lspci')
        lspci_cmd = "lspci|grep 'Non-Volatile memory'|wc -l"
        lsblk_cmd = "lsblk -d|grep nvme|wc -l"
        lspci_out = utils_lib.run_cmd(self, lspci_cmd,cancel_not_kw='0', msg="Check nvme pci device")
        lsblk_out = utils_lib.run_cmd(self, lsblk_cmd, msg="Check nvme block device")
        self.assertEqual(lspci_out, lsblk_out, msg="No all nvme pci device nvme driver are loaded")

    def test_check_meminfo_memfree(self):
        """
        case_name:
            test_check_meminfo_memfree
        component:
            kernel
        bugzilla_id:
            1880090
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:check if the numa information is correct
            xiliang@redhat.com
        description:
            check if the numa node memory information is correct
        key_steps:
            1.sudo cat /sys/devices/system/node/node0/meminfo
            2.compare memfree,memtotal and memused
        expect_result:
            memfree < memtotal
            memused < memtotal
        debug_want:
            /sys/devices/system/node/node0/meminfo
        """
        out = utils_lib.run_cmd(self, 'sudo cat /sys/devices/system/node/node0/meminfo', expect_ret=0,
                    msg="Check MemFree less than MemTotal")
        memtotal = re.findall('[\d]+',re.findall('MemTotal:.*[\d]*',out)[0])[0]
        memfree = re.findall('[\d]+',re.findall('MemFree:.*[\d]*',out)[0])[0]
        memused = re.findall('[\d]+',re.findall('MemUsed:.*[\d]*',out)[0])[0]

        if int(memfree) >= int(memtotal):
            self.fail("memfree:{} >= memtotal:{}".format(memfree, memtotal))
        else:
            self.log.info("memfree:{} < memtotal:{}".format(memfree, memtotal))
        if int(memused) >= int(memtotal):
            self.fail("memused:{} >= memtotal:{}".format(memused, memtotal))
        else:
            self.log.info("memused:{} < memtotal:{}".format(memused, memtotal))

    def test_check_memleaks(self):
        """
        case_name:
            test_check_memleaks
        component:
            kernel
        bugzilla_id:
            161666
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if there are memory leak
        key_steps:
            1.sudo echo scan > /sys/kernel/debug/kmemleak
            2.cat /sys/kernel/debug/kmemleak
        expect_result:
            no return
        debug_want:
            /sys/kernel/debug/kmemleak
        """
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

        cmd = 'sudo echo scan > /sys/kernel/debug/kmemleak'
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)

        cmd = 'cat /sys/kernel/debug/kmemleak'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if len(output) > 0:
            self.fail('Memory leak found!')

    def test_check_memusage_exception(self):
        '''
        case_name:
            test_check_memusage_exception
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1956248
        customer_case_id:
            02929244
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check if there is a process taking high usage of Memory abnormally.
            If it shows the high usage of Memory abnormally(higher than 60% over 1min),the case fails.
        key_steps:
            1.#ps aux --sort=-rss|sed -n '2p'
        expected_result:
            The usage of Memory is normal(slower than 60% once in 1min).
        '''
        count=0
        for i in range(60):
            result_out = utils_lib.run_cmd(self, "ps aux --sort=-rss|sed -n '2p'", msg='Find process with highest usage of Memory')
            result_out = result_out.split(' ')
            while '' in result_out:
                result_out.remove('')
            if count == 0:
                lastpid = int(result_out[1])
            if float(result_out[3]) >= 60 and lastpid == int(result_out[1]):
                lastpid = int(result_out[1])
                count += 1
                time.sleep(1)
            else:
                break
        if count>=59:
            command =''
            for i in range(10, len(result_out)):
                command += result_out[i] + ' '
            self.fail(f'{command}(pid:{lastpid}) have abnormal usage of Memory.')

    def test_check_microcode_load(self):
        """
        case_name:
            test_check_microcode_load
        component:
            kernel
        bugzilla_id:
            1607899
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if microbe performed early update in x86 metal systems
        key_steps:
            1.rpm -qa|grep microcode
            2.rpm -qa|grep linux-firmware
            3.dmesg|grep microcode
        expect_result:
            microcode loaded in metal system and microcode not loaded in virtual system.
        debug_want:
            dmesg log
        """
        cpu_info = utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="aarch64",
                    msg="Only run in x86 platform")
        utils_lib.run_cmd(self, "rpm -qa|grep microcode",msg='get microcode pkg version')
        utils_lib.run_cmd(self, "rpm -qa|grep linux-firmware",msg='get linux-firmware pkg version')
        cmd = 'dmesg|grep microcode'
        if utils_lib.is_metal(self):
            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw="microcode updated early",
                        msg='microcode should load in bare metal')
        else:
            utils_lib.run_cmd(self,
                        cmd,
                        expect_not_kw='microcode updated early',
                        msg='microcode should not load in VMs')

    def test_check_nouveau(self):
        """
        case_name:
            test_check_nouveau
        component:
            kernel
        bugzilla_id:
            1349927, 1645772
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if nouveau is in blacklist and is not loaded in aws
        key_steps:
            lsmod
            cat /proc/cmdline
        expect_result:
            nouveau is no in lsmod and is in blacklist
        debug_want:
            lsmod
        """
        utils_lib.is_aws(self, action='cancel')
        utils_lib.run_cmd(self, 'cat /etc/redhat-release', cancel_not_kw='CentOS', msg='skip this check on centos, rhbz1645772')
        self.log.info("nouveau is not required in ec2, make sure it is \
in blacklist and not loaded bug1645772")
        utils_lib.run_cmd(self,
                    "lsmod",
                    expect_ret=0,
                    expect_not_kw="nouveau",
                    msg="Checking lsmod")
        utils_lib.run_cmd(self,
                    "cat /proc/cmdline",
                    expect_ret=0,
                    expect_kw="rd.blacklist=nouveau",
                    msg="Checking cmdline")

    def test_check_nvme_io_timeout(self):
        """
        case_name:
            test_check_nvme_io_timeout
        component:
            distribution
        bugzilla_id:
            1859088
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if the nvme_core.io_timeout is 4294967295 in aws
        key_steps:
            1.sudo cat /sys/module/nvme_core/parameters/io_timeout
            2.sudo cat /proc/cmdline
        expect_result:
            nvme_core.io_timeout=4294967295
        debug_want:
            io_timeout,cmdline
        """
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

    def test_check_release_name(self):
        """
        case_name:
            test_check_release_name
        component:
            ec2-images
        bugzilla_id:
            1852657
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if the release name is correct
        key_steps:
            1.cat /etc/redhat-release
            2.uname -r
            3.compare real name and true name
        expect_result:
            no other release name found and current name is correct
        debug_want:
            redhat-release
        """
        check_cmd = "cat /etc/redhat-release"
        output = utils_lib.run_cmd(self,check_cmd, expect_ret=0, msg='check release name')
        kernel_ver = utils_lib.run_cmd(self, 'uname -r', msg="Get kernel version")
        name_map = {'el6':'Red Hat Enterprise Linux Server release 6',
                    'el7':'Red Hat Enterprise Linux Server release 7',
                    'el8':'Red Hat Enterprise Linux release 8',
                    'el9':'Red Hat Enterprise Linux release 9',
                    'el8_centos':'CentOS Stream release 8',
                    'el9_centos':'CentOS Stream release 9'}
        for key in name_map.keys():
            if key in kernel_ver:
                if 'CentOS' not in output:
                    self.assertIn(
                    name_map[key],
                    output,
                    msg="It should be like: {}.n but it is {}".format(name_map[key], output))
                    if 'el6' not in kernel_ver and 'el7' not in kernel_ver:
                        rhversion = re.findall('Red Hat Enterprise Linux release \d', output)[0]
                        cmd = "sudo grep -R 'Red Hat Enterprise Linux' /boot/grub*|grep -v '{}'".format(rhversion.replace('release ',''))
                        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='make sure no other release name found')
                else:
                    centos_key = "{}_centos".format(key)
                    self.assertIn(
                    name_map[centos_key],
                    output,
                    msg="It should be like: {}.n but it is {}".format(name_map[centos_key], output))
                break

    def test_check_proc_self_status(self):
        '''
        case_name:
            test_check_proc_self_status
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1773868
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check no 'unknown' in /proc/self/status.
        key_steps:
            1. # cat /proc/self/status
        expected_result:
            No 'unknown' in this file
        '''
        utils_lib.check_log(self, 'unknown', log_cmd='uname -r;cat /proc/self/status', msg='Check no unknown in "/proc/self/status"')

    def test_check_product_id(self):
        """
        case_name:
            test_check_product_id
        component:
            ec2-images
        bugzilla_id:
            1938930
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check if product id matches /etc/redhat-release
        key_steps:
            1.cat /etc/redhat-release
            2.rpm -qa|grep redhat-release
            3.sudo rct cat-cert /etc/pki/product-default/*.pem
        expect_result:
            product id matches the one in redhat-release
        debug_want:
            /etc/pki/product-default/*.pem
        """
        check_cmd = "cat /etc/redhat-release"
        output = utils_lib.run_cmd(self,check_cmd, expect_ret=0, cancel_not_kw='CentOS,Fedora', msg='check release name')
        product_id = re.findall('\d.\d', output)[0]
        self.log.info("Get product id: {}".format(product_id))
        cmd = 'rpm -qa|grep redhat-release'
        utils_lib.run_cmd(self,cmd, cancel_ret='0', msg='get redhat-release-server version')
        cmd = 'sudo rct cat-cert /etc/pki/product-default/*.pem'
        utils_lib.run_cmd(self,cmd, expect_ret=0, expect_kw="Version: {}".format(product_id), msg='check product certificate')

    def test_check_service(self):
        '''
        case_name:
            test_check_service
        case_priority:
            1
        component:
            systemd
        bugzilla_id:
            1740443
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check no failed service in start up.
        key_steps:
            1. # systemctl|grep failed
        expected_result:
            No failed service found.
        '''
        utils_lib.check_log(self, 'failed', log_cmd='systemctl')

    def test_check_sysfs_cpu_list(self):
        '''
        case_name:
            test_check_sysfs_cpu_list
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1741462
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check no crash when read "cpu_list" in /sys.
        key_steps:
            1. # find -H /sys -name cpu_list  -type f -perm -u=r -print -exec cat '{}' 2>&1 \;
        expected_result:
            No crash/panic happen
        '''
        cmd = "find -H /sys -name cpu_list  -type f -perm -u=r -print -exec cat '{}' 2>&1 \;"
        utils_lib.run_cmd(self, cmd, msg='Check no crash seen when read cpu_list if exists')

    def test_check_sys_modules_parameters_readable(self):
        '''
        case_name:
            test_check_sys_modules_parameters_readable
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1619602
        customer_case_id:
            02232284
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check no panic happen when read all files under "/sys/module/*/parameters/".
        key_steps:
            1. # cat /sys/module/*/parameters/* 
        expected_result:
            No panic happen
        '''
        utils_lib.run_cmd(self, 'cat /sys/module/*/parameters/*', msg='Check no panic happen when read all files under "/sys/module/*/parameters/"')

    def test_check_systemd_analyze_verify_deprecated_unsafe(self):
        '''
        case_name:
            test_check_systemd_analyze_verify_deprecated_unsafe
        case_priority:
            2
        component:
            systemd
        bugzilla_id:
            1974184
        customer_case_id:
            n/a
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check service does not use deprecated or unsafe options in unit file
        key_steps:
            1. # systemd-analyze verify $service name
        expected_result:
            No 'deprecated' or 'unsafe' found in output
        '''
        utils_lib.run_cmd(self, 'cat {}'.format(self.systemd_analyze_verify_file),expect_ret=0, expect_not_kw='deprecated,unsafe', msg='Check there is no "deprecated" or "unsafe" keyword')

    def test_check_systemd_analyze_verify_missing(self):
        """
        case_name:
            test_check_systemd_analyze_verify_missing
        case_file:
            https://github.com/liangxiao1/os-tests/blob/master/os_tests/tests/test_general_check.py
        component:
            systemd
        bugzilla_id:
            2016305
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check service has no 'Missing' config in unit file
        key_steps:
            # systemd-analyze verify $service
        expect_result:
            # No 'Missing' keywords in output
        debug_want:
            - service unit file content
            - output from 'systemd-analyze verify $service'
        """
        utils_lib.run_cmd(self, 'cat {}'.format(self.systemd_analyze_verify_file),expect_ret=0, expect_not_kw='Missing,ignoring line', msg='Check there is no Missing keyword in output')

    def test_check_systemd_analyze_verify_obsolete(self):
        '''
        case_name:
            test_check_systemd_analyze_verify_obsolete
        case_priority:
            2
        component:
            systemd
        bugzilla_id:
            1974108
        customer_case_id:
            n/a
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check service does not use obsolete options in unit file
        key_steps:
            1. # systemd-analyze verify $service name
        expected_result:
            No "is obsolete" found in output
        '''
        utils_lib.run_cmd(self, 'cat {}'.format(self.systemd_analyze_verify_file),expect_ret=0, expect_not_kw='is obsolet', msg='Check there is no obsolet keyword in output')

    def test_check_systemd_analyze_verify_ordering_cycle(self):
        '''
        description:
            Make sure there is no ordering cycle which may block boot up.
        polarion_id:
            n/a
        bugzilla_id: 
            1932614, 1998445
        customer_case_id: 
            02878130
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            systemd
        key_steps:
            # systemd-analyze verify default.target
            # journalctl -b0 |grep -i 'Found ordering cycle'
        pass_criteria: 
            No ordering cycle found
        debug_want:
            # journalctl -b0
        '''
        cmd = 'sudo journalctl -b0'
        utils_lib.run_cmd(self, cmd, expect_not_kw='ordering cycle', msg='Check there is no ordering cycle in journal log')
        utils_lib.run_cmd(self, 'cat {}'.format(self.systemd_analyze_verify_file),expect_ret=0, expect_not_kw='ordering cycle', msg='Check there is no ordering cycle which may block boot up')

    def test_check_systemd_analyze_verify_instead(self):
        """
        case_name:
            test_check_systemd_analyze_verify_instead
        case_tags:
            systemd
        case_status:
            Approved
        title:
            check service has no option which will be removed soon in unit file 
        importance:
            low
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            Automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_general_check.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            systemd
        bug_id:
            bugzilla_2155468
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
            check service unit file has no option which will be removed soon or has "legacy directory" and permission denied settings.
        key_steps: |
            # systemd-analyze verify $service
        expected_result: |
            - no instead option found
            - no "legacy directory" used
            - no "Permission denied" found
        debug_want: |
            - output from 'systemd-analyze verify $service'
            - output from 'systemctl cat $failservice'
        """
        cmd = 'cat {}'.format(self.systemd_analyze_verify_file)
        utils_lib.check_log(self,'instead,legacy directory,Permission denied',log_cmd=cmd,rmt_redirect_stdout=True)

    def test_check_tsc_deadline_timer(self):
        """
        case_name:
            test_check_tsc_deadline_timer
        component:
            kernel
        bugzilla_id:
            1503160
        is_customer_case:
            True
        maintainer:
            xiliang@redhat.com
        description:
            check if TSC deadline timer enabled in dmesg on intel cpu
        key_steps:
            1.lscpu
            2.grep tsc_deadline_timer /proc/cpuinfo
            3.dmesg|egrep 'TSC deadline timer enabled|TSC deadline timer available
            4.sudo cat /sys/devices/system/clockevents/clockevent0/current_device
        expect_result:
            deadline timer enabled and current device has lapic-deadline
        debug_want:
            current_device
        """
        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="Xen,aarch64,AuthenticAMD", msg="Only run in intel cpu.")

        cmd = "grep tsc_deadline_timer /proc/cpuinfo"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg="check cpu flag has tsc_deadline_timer")
        cmd = "dmesg|egrep 'TSC deadline timer enabled|TSC deadline timer available'"
        utils_lib.run_cmd(self, cmd, expect_ret=0)

        cmd = "sudo cat /sys/devices/system/clockevents/clockevent0/\
current_device"

        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='lapic-deadline',
                    msg='Check guest timer')

    def test_check_tuned_adm_active(self):
        '''
        case_name:
            test_check_tuned_adm_active

        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1893063
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check tuned-adm loads default "virtual-guest" in vm and does not load virtual-guest in metal instance
        key_steps:
            1. # tuned-adm active
        expected_result:
            Should not load virtual-guest in bare metal.
            Should load virtual-guest in vm by default.
        '''
        utils_lib.is_cmd_exist(self, cmd='tuned-adm', cancel_case=True)
        if 'inactive' in utils_lib.run_cmd(self, 'sudo systemctl is-active tuned'):
            utils_lib.run_cmd(self, 'sudo systemctl enable --now tuned', msg='enable tuned service')
        if utils_lib.is_metal(self):
            utils_lib.run_cmd(self, 'tuned-adm active', expect_not_kw='virtual-guest', msg='Should not load virtual-guest in bare metal')
        else:
            utils_lib.run_cmd(self, 'tuned-adm active', expect_kw='virtual-guest', msg='Should load virtual-guest in vm by default')

    def test_check_virtwhat(self):
        """
        case_name:
            test_check_virtwhat
        component:
            virt-what
        bugzilla_id:
            1782435
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            test if virt-what can run normally
        key_steps:
            1.rpm -q virt-what
            2.sudo virt-what
            3.lscpu
            4.compare virt-what result with system type
        expect_result:
            virt-what result matchs cpu type without segfault
        debug_want:
            N/A
        """
        utils_lib.is_cmd_exist(self, cmd='virt-what')
        utils_lib.run_cmd(self, "rpm -q virt-what", expect_ret=0, msg='get virt-what version')
        virt_what_output = utils_lib.run_cmd(self, r"sudo virt-what", expect_ret=0)
        lscpu_output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        if 'Xen' in lscpu_output:
            self.log.info("Found it is a xen system!")
            if 'full' in lscpu_output:
                self.assertIn('xen-hvm', virt_what_output)
            else:
                self.assertIn('xen-domU', virt_what_output)
        elif 'Microsoft' in lscpu_output and not utils_lib.is_metal(self):
            self.log.info("Found it is a Hyper-V system!")
            self.assertIn('hyperv', virt_what_output)
        elif 'VMware' in lscpu_output:
            self.log.info("Found it is a vmware system!")
            self.assertIn('vmware', virt_what_output)
        elif 'KVM' in lscpu_output:
            if utils_lib.is_ahv(self):
                self.log.info("Found it is a Nutanix AHV system!")
                self.assertIn('ahv', virt_what_output)
            elif not utils_lib.is_metal(self):
                self.log.info("Found it is a kvm system!")
                self.assertIn('kvm', virt_what_output)
        elif utils_lib.is_metal(self) and utils_lib.is_aws(self):
            self.log.info("Found it is a aws bare metal system!")
            self.assertEqual('aws', virt_what_output.strip('\n'))
        elif utils_lib.is_metal(self):
            self.log.info("Found it is a bare metal system!")
        elif utils_lib.is_aws(self) and utils_lib.is_arch(self, arch='aarch64') and utils_lib.is_metal(self):
            self.assertEqual('aws', virt_what_output.strip('\n'))
        elif utils_lib.is_aws(self) and utils_lib.is_arch(self, arch='aarch64') and not utils_lib.is_metal(self):
            self.assertEqual('kvm\naws\n', virt_what_output)
        else:
            self.skipTest("Unknow hypervisor")

    def test_check_rpm_V_differences(self):
        '''
        case_name:
            test_check_rpm_V_differences
        case_priority:
            1
        component:
            rpm
        bugzilla_id:
            n/a
        customer_case_id:
            n/a
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check the pkg differences with information from database
        key_steps:
            1. # rpm -qa
            2. # sudo rpm -V $(pkgs)
        expected_result:
            No pkg differences with information from database.
        '''
        character={'S': 'file Size differs',
              'M': 'Mode differs (includes permissions and file type)',
              '5':'digest (formerly MD5 sum) differs',
              'D':'Device major/minor number mismatch',
              'L':'readLink(2) path mismatch',
              'U':'User ownership differs',
              'G':'Group ownership differs',
              'T':'mTime differs',
              'P':'caPabilities differ',
              '?':'test could not be performed'}
        count=0
        differ=''
        for line in self.output.split('\n'):
            if line.startswith(('.','S')):
                count += 1
                pkg_file = line.split(' ')[-1]
                pkg = utils_lib.run_cmd(self, 'sudo rpm -qf {}'.format(pkg_file), timeout=600)
                differ += f'{count}.{pkg}\n'
                differ+=line+'\n'
                for k in line[0:9]:
                    if k!='.' and k in character.keys():
                        differ+=character[k]+'\n'
        self.log.info("{}".format(differ))
        allow_count = 25
        if count>=allow_count:
            self.fail("Too many ({}) differes found, please check.".format(count))
        else:
            self.log.info("Found few ({}) differs less than {}".format(count,allow_count))

    def test_check_rpm_V_efi(self):
        """
        case_name:
            test_check_rpm_V_efi
        component:
            efi-rpm-macros
        bugzilla_id:
            1845052
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            check rpm verify status
        key_steps:
            1.sudo rpm -q efi-filesystem
            2.sudo rpm -V efi-filesystem
        expect_result:
            cmd pass without err or fail
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self,
                    'sudo rpm -q efi-filesystem',
                    cancel_not_kw="not installed", msg="check if efi-filesystem is installed")

        cmd = "sudo rpm -V efi-filesystem"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check rpm verify status")

    def test_check_rpm_V_missing(self):
        '''
        case_name:
            test_check_rpm_V_missing
        case_priority:
            1
        component:
            rpm
        bugzilla_id:
            n/a
        customer_case_id:
            n/a
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check pkg missing file problem
        key_steps:
            1. # rpm -qa
            2. # sudo rpm -V $(pkg)
        expected_result:
            No missing file found in output.
        '''
        count=0
        differ=''
        for line in self.output.split('\n'):
            if 'missing' in line:
                count += 1
                pkg_file = line.split(' ')[-1]
                pkg = utils_lib.run_cmd(self, 'sudo rpm -qf {}'.format(pkg_file), timeout=600)
                differ += f'{count}.{pkg}:\n'
                differ+=line+'\n'

    def test_collect_insights_result(self):
        '''
        case_name:
            test_collect_insights_result
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1889702
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check if insights-client hits some rules.
        key_steps:
            1. #insights-client --register
            2. #insights-client --check-result
            3. #insights-client --show-results
        expected_result:
            If run in dev compose, we simply assume there is no insights rule should be hit because no pkg update available in the latest build.
            But if it is expected in dev compose, we can skip it in this case.
            If run in GAed compose, please follow rule suggestion to check manually.
        '''
        cmd="cat /etc/redhat-release"
        utils_lib.run_cmd(self, cmd, cancel_not_kw='CentOS,Fedora', msg='Not run in centos')
        if not utils_lib.is_cmd_exist(self, cmd="insights-client"):
            self.skipTest('No insights-client installation found!')
        utils_lib.run_cmd(self,
                    'lscpu',
                    msg="get cpu information")
        utils_lib.run_cmd(self,
                    'rpm -q insights-client',
                    msg="get insights-client version")
        utils_lib.run_cmd(self,
                    'sudo insights-client --register',
                    msg="try to register system", timeout=120)
        utils_lib.run_cmd(self,
                    'sudo insights-client --status',
                    cancel_kw="System is registered",
                    msg="Please register system or add user to '/etc/insights-client/insights-client.conf'")
        utils_lib.run_cmd(self,
                    'sudo insights-client --check-result',
                    expect_ret=0,
                    msg="checking system")
        result_out = utils_lib.run_cmd(self,
                    'sudo insights-client --show-result',
                    expect_ret=0,
                    msg="show insights result")
        #hit_list = json.loads(out)
        out = utils_lib.run_cmd(self,
                'sudo insights-client --no-upload --keep-archive',
                expect_ret=0, expect_kw="tar.gz",
                msg="please attach this archive if file bug", timeout=180)
        gz_file = re.findall('/var/.*tar.gz', out)[0]
        file_name = gz_file.split('/')[-1]
        if self.params.get('remote_node') is not None:
            self.log.info('retrive {} from remote'.format(file_name))
            self.SSH.get_file(rmt_file='/tmp/{}'.format(file_name),local_file='{}/attachments/{}'.format(self.log_dir,file_name))
        else:
            utils_lib.run_cmd(self, 'sudo cp {} {}'.format(gz_file, self.log_dir))
        try:
            tmp_dict = json.loads(result_out)
            if len(tmp_dict) > 0:
                self.fail("{} insights rule hit".format(len(tmp_dict)))
        except json.decoder.JSONDecodeError as exc:
            self.log.error("insights rule hit or other unexpected error")

    def test_check_sos_works(self):
        """
        case_name:
            test_check_sos_works
        component:
            sos
        bugzilla_id:
            1718087
        is_customer_case:
            True
        maintainer:
            xuazhao@redhat.com
        description:
            check if sos report can run without crash
        key_steps:
            1.sos report --batch
        expect_result:
            no Traceback in result
        debug_want:
            sos_output.txt
        """
        cmd = 'sudo rm -rf /var/tmp/sos*'
        utils_lib.run_cmd(self,cmd,msg="clean up old sos report")
        utils_lib.is_cmd_exist(self, cmd='sosreport')
        cmd = "sudo sosreport --batch"
        utils_lib.run_cmd(self,cmd,expect_ret=0,msg="test sosreport",timeout=400)
        cmd = 'sudo ls /var/tmp/sos*.xz'
        sosfile = utils_lib.run_cmd(self, cmd, expect_ret=0)
        sosfile = sosfile.strip('\n')
        cmd = 'sudo chmod 766 {}'.format(sosfile)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        if self.params.get('remote_node') is not None:
            self.log.info('retrive {} from remote to {}'.format(sosfile, self.log_dir))
            self.SSH.get_file(rmt_file=sosfile,local_file='{}/attachments/{}'.format(self.log_dir,os.path.basename(sosfile)))
        else:
            cmd = "cp {} {}/attachments/{}".format(sosfile, self.log_dir,os.path.basename(sosfile) )
            utils_lib.run_cmd(self, cmd, msg='save {} to {}'.format(sosfile, self.log_dir))

    def test_check_dmesg_sev(self):
        """
        case_name:
            test_check_dmesg_sev
        case_file:
            os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_sev
        component:
            kernel
        bugzilla_id:
            2103821
        customer_case_id:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            Make sure there is SEV keyword from dmesg output.
        key_steps:
            # dmesg|grep -i sev
        expect_result:
            AMD Memory Encryption Features active: SEV
        debug_want:
            # dmesg
        """
        try:
            if utils_lib.is_sev_enabled(self):
                utils_lib.run_cmd(self, 'dmesg', expect_ret=0,
                                  expect_kw='AMD Memory Encryption Features active: SEV',
                                  msg="Check there is 'AMD Memory Encryption Features active: SEV' in dmesg before run 'perf top'")
            else:
                self.skipTest('SEV is not enabled')
        except NotImplementedError:
                self.skipTest('SEV check is not implemented on %s' % self.vm.provider)

    def test_check_secure_ioerror(self):
        """
        case_tag:
            secure_log
        case_name:
            test_check_secure_ioerror
        case_file:
            os_tests.tests.test_general_check.test_check_secure_ioerror
        component:
            secure_log
        bugzilla_id:
            1103344
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description: |
            Check there is no io error in /var/log/secure.
            https://access.redhat.com/solutions/975803
        key_steps:
            1. Check /var/log/secure via command "sudo cat /var/log/secure".
        expect_result:
            There isn't "Input/output error" in secure log.
        debug_want:
            N/A
        """
        self.log.info("Check /var/log/secure")
        utils_lib.run_cmd(self, "sudo cat /var/log/secure", expect_ret=0)
        utils_lib.run_cmd(self, "sudo cp /var/log/secure /tmp", expect_ret=0)
        utils_lib.run_cmd(self, "sudo cat /var/log/secure", expect_not_kw="Input/output error")

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
