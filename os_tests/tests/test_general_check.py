import unittest
from os_tests.libs import utils_lib
import json
import os
import re

class TestGeneralCheck(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

    def test_check_avclog(self):
        '''
        polarion_id: N/A
        '''
        cmd = "sudo ausearch -m AVC -ts today"
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Checking avc log!', rmt_get_pty=True)

    def test_check_avclog_nfs(self):
        '''
        polarion_id: N/A
        bz: 1771856
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
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Checking avc log!', rmt_get_pty=True)

    def test_check_available_clocksource(self):
        '''
        polarion_id:
        bz: 1726487
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
        bz: 1776710
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
        bz: 1779454
        '''
        utils_lib.check_log(self, 'unable', log_cmd='dmesg')

    def test_check_dmesg_calltrace(self):
        '''
        polarion_id: RHEL7-103851
        bz: 1777179
        '''
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, expect_not_kw='Call trace,Call Trace', msg="Check there is no call trace in dmesg")

    def test_check_dmesg_unknownsymbol(self):
        '''
        polarion_id:
        bz: 1649215
        '''
        utils_lib.run_cmd(self,
                    'dmesg',
                    expect_ret=0,
                    expect_not_kw='Unknown symbol',
                    msg='Check there is no Unknown symbol in dmesg')

    def test_check_cpu_vulnerabilities(self):
        '''
        check if cpu has unexpected Vulnerable
        '''

        utils_lib.run_cmd(self, "rpm -qa|grep microcode", msg='Get microcode version')
        utils_lib.run_cmd(self, "rpm -qa|grep linux-firmware",msg='get linux-firmware pkg version')
        check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/* | \
sed 's/:/^/' | column -t -s^"
        utils_lib.run_cmd(self, check_cmd, expect_ret=0)

        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if utils_lib.is_metal(self):
            self.log.info(
                "Bare metal instance should not have any vulnerable (microload loaded).")
            cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/* | \
sed 's/:/^/' | column -t -s^"
        elif 'el7' in output:
            self.log.info(
                "Skip spec_store_bypass,Retpoline and mds in RHEL7 vms")
            check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/* | \
grep -v spec_store_bypass|grep -v 'tsx_async_abort'|grep -v 'Vulnerable: Retpoline'|\
grep -v mds| sed 's/:/^/' | column -t -s^"
        else:
            self.log.info(
                "Skip spec_store_bypass and mds,itlb_multihit in vms")
            check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/*|\
grep -v spec_store_bypass|grep -v 'tsx_async_abort'|grep -v mds|grep -v \
itlb_multihit|sed 's/:/^/' | column -t -s^"

        utils_lib.run_cmd(self, check_cmd, expect_ret=0, expect_not_kw='Vulnerable')

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

        expected_result:
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
        '''
        polarion_id:
        bz: 1801999, 1736818
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
        bz: 1797973
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
        utils_lib.check_log(self, 'error', skip_words='test_check', rmt_redirect_stdout=True)

    def test_check_journalctl_fail(self):
        '''
        polarion_id: RHEL7-103851
        '''
        utils_lib.check_log(self, 'fail', skip_words='test_check,nofail', rmt_redirect_stdout=True)

    def test_check_journalctl_warn(self):
        '''
        polarion_id: RHEL7-103851
        '''
        utils_lib.check_log(self, 'warn', skip_words='test_check',rmt_redirect_stdout=True)

    def test_check_journalctl_invalid(self):
        '''
        polarion_id:
        bz:1750417
        '''
        utils_lib.check_log(self, 'invalid', skip_words="Invalid user,invalid user,test_check", rmt_redirect_stdout=True)

    def test_check_journalctl_service_unknown_lvalue(self):
        '''
        polarion_id:
        bz:1871139
        '''
        cmd = "systemctl list-unit-files |grep -v UNIT|grep -v listed|awk -F' ' '{print $1}'"
        all_services = utils_lib.run_cmd(self, cmd, msg='Get all systemd unit files').split('\n')

        for service in all_services:
            if len(service) == 0:
                continue
            cmd = "systemctl status {}".format(service)
            utils_lib.run_cmd(self, cmd)
            cmd = "journalctl --unit {}".format(service)
            utils_lib.check_log(self,'Unknown lvalue', log_cmd=cmd, rmt_redirect_stdout=True)

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
        utils_lib.is_cmd_exist(self, cmd='lshw')
        base_memory = utils_lib.get_memsize(self)
        cmd = 'lshw -json'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        out = json.loads(output)['children'][0]["children"]
        for i in out:
            if i['id'] == 'memory':
                mem_in_byte = i['size']
                break
        mem_in_gib = mem_in_byte/1024/1024/1024
        self.log.info("lshw showed mem: {}".format(mem_in_gib))

        utils_lib.compare_nums(self, mem_in_gib, base_memory, ratio=15)

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
        '''
        rhbz: 1880090
        MemFree should less than MemTotal
        Fail output:
        # cat /sys/devices/system/node/node0/meminfo
        Node 0 MemTotal:       30774804 kB
        Node 0 MemFree:        31505560 kB
        '''
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

        cmd = 'sudo echo scan > /sys/kernel/debug/kmemleak'
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)

        cmd = 'cat /sys/kernel/debug/kmemleak'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if len(output) > 0:
            self.fail('Memory leak found!')

    def test_check_microcode_load(self):
        '''
        bz: 1607899
        des: Don't attempt to perform early microcode update on virtualized guests
        This case checks it from dmesg output.
        '''
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
        '''
        polarion_id: N/A
        bz: 1349927, 1645772
        '''
        utils_lib.is_aws(self, action='cancel')
        utils_lib.run_cmd(self, 'cat /etc/redhat-release', cancel_not_kw='CentOS', msg='skip this check on centos, rhbz1645772')
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
        bz: 1859088
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

    def test_check_release_name(self):
        '''
        polarion_id: RHEL7-103850
        bz: 1852657
        '''
        check_cmd = "sudo cat /etc/redhat-release"
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
                        cmd = "sudo grep -R 'Red Hat Enterprise Linux' /boot/grub*|grep -v '{}'".format(rhversion)
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
        utils_lib.run_cmd(self, 'cat /proc/self/status', expect_not_kw='unknown', msg='Check no unknown in "/proc/self/status"')

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
        cmd = 'systemctl'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='failed')

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

    def test_check_tsc_deadline_timer(self):
        '''
        polarion_id: RHEL7-111006
        des: check TSC deadline timer enabled in dmesg
        bz: 1503160
        '''
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
        '''
        polarion_id: RHEL7-103857
        bz: 1782435
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
        elif utils_lib.is_metal(self) and utils_lib.is_aws(self):
            self.log.info("Found it is a bare metal system!")
            self.assertEqual('aws', virt_what_output.strip('\n'))
        elif utils_lib.is_metal(self):
            self.log.info("Found it is a bare metal system!")
        elif utils_lib.is_aws(self) and utils_lib.is_arch(self, arch='aarch64'):
            self.assertEqual('aws', virt_what_output.strip('\n'))
        else:
            self.skipTest("Unknow hypervisor")

    def test_check_rpm_V_efi(self):
        '''
        bz: 1845052
        '''
        utils_lib.run_cmd(self,
                    'sudo rpm -q efi-filesystem',
                    cancel_not_kw="not installed", msg="check if efi-filesystem is installed")

        cmd = "sudo rpm -V efi-filesystem"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check rpm verify status")

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
        utils_lib.run_cmd(self, cmd, cancel_not_kw='CentOS', msg='Not run in centos')
        utils_lib.is_cmd_exist(self, cmd="insights-client")
        utils_lib.run_cmd(self,
                    'sudo lscpu',
                    msg="get cpu information")
        utils_lib.run_cmd(self,
                    'sudo rpm -q insights-client',
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
        out = utils_lib.run_cmd(self,
                    'sudo insights-client --show-result',
                    expect_ret=0,
                    msg="show insights result")
        #hit_list = json.loads(out)
        tmp_dict = json.loads(out)
        if len(tmp_dict) > 0:
            out = utils_lib.run_cmd(self,
                    'sudo insights-client --no-upload --keep-archive',
                    expect_ret=0,
                    msg="generate archive")
            gz_file = re.findall('/var/.*tar.gz', out)[0]
            file_name = gz_file.split('/')[-1]
            utils_lib.run_cmd(self, 'sudo cp {} {}'.format(gz_file, self.log_dir))
            self.fail("{} insights rule hit".format(len(tmp_dict)))

    def tearDown(self):
        self.log.info("{} test done".format(self.id()))

if __name__ == '__main__':
    unittest.main()