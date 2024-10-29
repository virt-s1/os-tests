import unittest
from os_tests.libs import utils_lib
import re
import os


class TestGuestImage(unittest.TestCase):

    def setUp(self):
        utils_lib.init_case(self)

    def test_check_rootfs_uuid_in_fstab(self):
        """
        case_name:
            test_check_rootfs_uuid_in_fstab
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            1006883
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check whether root partition is identified by UUID in fstab
        key_steps:
            1. cat /etc/fstab
        expect_result:
            root partition is identified by UUID
        debug_want:
            N/A
        """
        fs_spec = ""
        cmd = "cat /etc/fstab"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Check fstab")
        for line in output.splitlines():
            li = line.strip()
            if not li.startswith("#") and li:
                if li.split()[1] == '/':
                    fs_spec = li.split()[0]
        if fs_spec.startswith("/dev/mapper"):
            self.skipTest(
                "Root partition is a logical volume, skip UUID check.")
        else:
            self.assertTrue(
                re.match(r"UUID=\w{8}-\w{4}-\w{4}-\w{4}-\w{8}", fs_spec),
                "rootfs in /etc/fstab is not present by UUID -> %s" % fs_spec)

    def test_check_partitions(self):
        """
        case_name:
           test_check_partitions
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            1673094
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check whether root partition is identified by UUID in fstab
        key_steps:
            1. lsblk
        expect_result:
            contains /boot, /boot/efi partition
        debug_want:
            N/A
        """
        cmd = "df / | tail -n 1"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="df output for rootfs")
        m = re.search('/dev/([a-z]+)[0-9].*', output)
        self.assertTrue(m, "root dev name not found: %s" % output)
        dev_name = m.group(1)
        cmd = "sudo lsblk"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="lsblk")
        count = 0
        for line in output.splitlines():
            if re.search(dev_name, line):
                count = count + 1
        product_id = utils_lib.get_product_id(self)
        if float(product_id) >= 10.0:
            expected_partitions = 4
            if utils_lib.is_arch(self, arch='s390x'):
                expected_partitions = 2
            elif utils_lib.is_arch(self, arch='aarch64') or utils_lib.is_arch(self, arch='ppc64le'):
                expected_partitions = 3
        elif float(product_id) >= 9.0:
            expected_partitions = 5
            if utils_lib.is_arch(self, arch='s390x'):
                expected_partitions = 3
            elif utils_lib.is_arch(self, arch='aarch64') or utils_lib.is_arch(
                    self, arch='ppc64le'):
                expected_partitions = 4
        elif float(product_id) <= 7.0:
            expected_partitions = 2
        else:
            expected_partitions = 4
            if utils_lib.is_arch(self, arch='s390x'):
                expected_partitions = 2
            elif utils_lib.is_arch(self, arch='aarch64') or utils_lib.is_arch(
                    self, arch='ppc64le'):
                expected_partitions = 3
        self.assertEqual(expected_partitions, count,
                         "More than one partition exists:\n %s" % output)

    def test_check_boot_partition_guid(self):
        """
        case_name:
            test_check_boot_partition_guid
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            2057231
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check whether the GUID of boot partition is correct
        key_steps:
            1. lsblk -n -o PARTTYPE,MOUNTPOINT | grep '/boot$'
        expect_result:
            GUID = bc13c2ff-59e6-4262-a352-b275fd6f7172
        debug_want:
            N/A
        """
        product_id = utils_lib.get_product_id(self)
        if float(product_id) >= 9.0 and float(product_id) < 10.0  and (
                utils_lib.is_arch(self, arch='aarch64')
                or utils_lib.is_arch(self, arch='x86_64')):
            cmd = "lsblk -n -o PARTTYPE,MOUNTPOINT | grep '/boot$'"
            output = utils_lib.run_cmd(self,
                                       cmd,
                                       expect_ret=0,
                                       msg="Get GUID of /boot")
            self.assertIn("bc13c2ff-59e6-4262-a352-b275fd6f7172", output,
                          "Boot partition GUID incorrect: %s" % output)
        else:
            self.skipTest(
                "Only run on RHEL 9.x on x86_64 or aarch64.")

    def test_check_etc_sysconfig_kernel(self):
        """
        case_name:
            test_check_etc_sysconfig_kernel
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            Validate UPDATEDEFAULT and DEFAULTKERNEL in /etc/sysconfig/kernel
        key_steps:
            1. cat /etc/sysconfig/kernel
        expect_result:
            UPDATEDEFAULT=yes and DEFAULTKERNEL=kernel
        debug_want:
            N/A
        """
        cmd = "cat /etc/sysconfig/kernel"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="cat /etc/sysconfig/kernel")
        self.assertIn('UPDATEDEFAULT=yes', output,
                      "Missing UPDATEDEFAULT=yes in /etc/sysconfig/kernel")
        self.assertIn('DEFAULTKERNEL=kernel', output,
                      "Missing DEFAULTKERNEL=kernel in /etc/sysconfig/kernel")

    def test_check_etc_default_grub(self):
        """
        case_name:
            test_check_etc_default_grub
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            Validate GRUB_DEFAULT=saved GRUB_CMDLINE_LINUX=... in /etc/default/grub
        key_steps:
            1. cat /etc/default/grub
        expect_result:
            GRUB_DEFAULT=saved
            GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8 no_timer_check net.ifnames=0"
        debug_want:
            N/A
        """
        if utils_lib.is_arch(self, arch='s390x'):
            self.skipTest("Skip grub check on s390x")
        cmd = "cat /etc/default/grub"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="cat /etc/default/grub")
        self.assertIn('GRUB_DEFAULT=saved', output,
                      "Missing GRUB_DEFAULT=saved in /etc/default/grub")

        product_id = utils_lib.get_product_id(self)
        x = int(product_id.split(".")[0])
        y = int(product_id.split(".")[1])
        if x < 9 or x > 9 or (x == 9 and y >= 2):
            src_dir = self.data_dir + "/guest-images/"
            data_file = "cmdline_params.lst"
            lines = filter(None,
                           (line.rstrip()
                            for line in open(os.path.join(src_dir, data_file))))
            testline = ""
            for tmp in output.splitlines():
                if "GRUB_CMDLINE_LINUX=" in tmp:
                    testline = tmp
            self.assertNotEqual(
                testline, "", "GRUB_CMDLINE_LINUX is not set in /etc/default/grub")
            for line in lines:
                # For RHEL 10 and later, skip the check for 'net.ifnames=0'
                if line == "net.ifnames=0" and x >= 10:
                    continue
                self.assertIn(line, testline,
                              "%s is not in GRUB_CMDLINE_LINUX" % line)

    def test_check_default_runlevel(self):
        """
        case_name:
            test_check_default_runlevel
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check system runlevel
        key_steps:
            1. systemctl get-default
        expect_result:
            multi-user.target
        debug_want:
            N/A
        """
        cmd = "systemctl get-default"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="systemctl get-default")
        self.assertEqual('multi-user.target', output.rstrip('\n'),
                         "Default runlevel is wrong: %s" % output)

    def test_check_default_timezone(self):
        """
        case_name:
            test_check_default_timezone
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check default timezone
        key_steps:
            1. timedatectl | grep 'Time zone'
        expect_result:
            America/New_York
        debug_want:
            N/A
        """
        cmd = "timedatectl | grep 'Time zone'"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="get timezone")
        self.assertIn('America/New_York', output,
                      "Default timezone is wrong: %s" % output)

    def test_check_size_of_rootfs(self):
        """
        case_name:
            test_check_size_of_rootfs
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            1045242
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check the rootfs size
        key_steps:
            1. timedatectl | grep 'Time zone'
        expect_result:
            rootfs size nearly the same as disk size (>88%)
        debug_want:
            N/A
        """
        fs_size = 0
        cmd = "df -h"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="df -h")
        for line in output.splitlines():
            if line.split()[5] == '/':
                fs_size = float(
                    utils_lib.normalize_data_size(line.split()[1],
                                                  order_magnitude='G'))
        vm_size = float(
            utils_lib.normalize_data_size(self.vm.size, order_magnitude='G'))
        self.assertTrue(
            vm_size * 0.88 <= fs_size <= vm_size,
            "Size of rootfs is lower than 88%% of disk size -> %s" % fs_size)

    def test_check_password_hash_for_root(self):
        """
        case_name:
            test_check_password_hash_for_root
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            1032175
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check password hash for root in shadow
        key_steps:
            1. cat /etc/shadow
        expect_result:
            "!! or *"
        debug_want:
            N/A
        """
        sp_pwdp = ""
        cmd = "sudo cat /etc/shadow"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="cat /etc/shadow")
        for line in output.splitlines():
            if line.split(':')[0] == "root":
                sp_pwdp = line.split(':')[1]
        self.assertIn(
            sp_pwdp, ["!!", "*"],
            "Encrypted password for root in /etc/shadow is bad -> %s" %
            sp_pwdp)

    def test_check_selinux_status(self):
        """
        case_name:
            test_check_selinux_status
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check selinux status is enforcing
        key_steps:
            1. getenforce
            2. cat /etc/selinux/config|grep SELINUX=
        expect_result:
            Enforcing/enforcing
        debug_want:
            N/A
        """
        cmd = "getenforce"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="getenforce")
        self.assertEqual(output.rstrip('\n'), "Enforcing",
                         "SELinux is not enforcing")
        cmd = "cat /etc/selinux/config|grep SELINUX="
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="get SELINUX in /etc/selinux/config")
        keyword = ""
        for line in output.splitlines():
            if '#' not in line:
                keyword = line.split('=')[1]
        self.assertEqual(keyword, "enforcing", "SELinux is not enforcing")

    def test_check_selinux_contexts(self):
        """
        case_name:
            test_check_selinux_contexts
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check selinux contexts
        key_steps:
            1. restorecon -R -v -n
        expect_result:
            all files labeled with existing selinux contexts
        debug_want:
            N/A
        """
        selinux_now = "/tmp/" + "selinux.now"
        product_id = utils_lib.get_product_id(self)
        data_file = "selinux.el%s.lst" % product_id.split('.')[0]
        src_path = self.data_dir + '/guest-images/' + data_file
        dest_path = "/tmp/" + data_file
        self.SSH.put_file(local_file=src_path, rmt_file=dest_path)
        cmd = "sudo restorecon -R -v -n / -e /mnt -e /proc -e /sys \
-e /tmp -e /var/tmp -e /run >{0}".format(selinux_now)
        output = utils_lib.run_cmd(
            self,
            cmd,
            expect_ret=0,
            timeout=600,
            msg="check selinux label through restorecon")
        cmd = "grep -vxFf {0} {1} > /tmp/cmp".format(dest_path, selinux_now)
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   msg="check differences through grep")
        cmd = "cat /tmp/cmp"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="check diff content")
        self.assertEqual(
            "", output,
            "Found extra SELinux contexts have been modified:\n%s" % output)

    def test_check_files_controlled_by_rpm(self):
        """
        case_name:
            test_check_files_controlled_by_rpm
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check files is controlled by rpm pkg
        key_steps:
            1. rpm -ql
        expect_result:
            No unexpected orphan files
        debug_want:
            N/A
        """
        product_id = utils_lib.get_product_id(self)
        data_file = "rogue.el%s.lst" % product_id.split('.')[0]
        utils_script_py = "rogue.py"
        utils_script_sh = "rogue.sh"
        src_path_py = self.data_dir + '/guest-images/' + utils_script_py
        src_path_sh = self.data_dir + '/guest-images/' + utils_script_sh
        dest_path_py = '/tmp/' + utils_script_py
        dest_path_sh = '/tmp/' + utils_script_sh
        self.SSH.put_file(local_file=src_path_py, rmt_file=dest_path_py)
        self.SSH.put_file(local_file=src_path_sh, rmt_file=dest_path_sh)

        utils_lib.is_pkg_installed(self,"python3")
        cmd = "python3 --version"
        ret = utils_lib.run_cmd(self, cmd, msg="Check if python3 exist")
        print(f"python3 version check output: {ret}")
        if ret.strip() and "Python" in ret:
            print("python3 found; running rogue.py with python3.")
            cmd = "sudo python3 %s" % dest_path_py
            output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   timeout=1200,
                                   msg="run rogue.py")
        else:
            print("python3 not found; running rogue.sh as a shell script instead.")
            cmd = "sudo sh -c 'chmod 755 %s && %s'" % (dest_path_sh, dest_path_sh)
            output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   timeout=600,
                                   msg="run rogue.sh")
        cmd = "test -f /tmp/rogue && echo 'File exists' || echo 'File does not exist'"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Check if /tmp/rogue exists")
        self.assertEqual(output.strip(), 'File exists', "rogue.py failed to create /tmp/rogue")

        src_path = self.data_dir + '/guest-images/' + data_file
        dest_path = '/tmp/' + data_file
        self.SSH.put_file(local_file=src_path, rmt_file=dest_path)
        cmd = "grep -vxFf %s %s" % (dest_path, "/tmp/rogue")
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   msg="check differences through grep")
        self.assertEqual(
            "", output.rstrip('\n'),
            "Found extra files not controlled by rpm:\n%s" % output)

    def test_check_file_content_integrity(self):
        """
        case_name:
            test_check_file_content_integrity
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check file content integrity
        key_steps:
            1. rpm -Va
        expect_result:
            No unexpected file modifications
        debug_want:
            N/A
        """
        product_id = utils_lib.get_product_id(self)
        data_file = "rpm_va.el%s.lst" % product_id.split('.')[0]
        # cmd = "sudo prelink -amR"
        # output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="prelink -amR")
        src_path = self.data_dir + '/guest-images/' + data_file
        dest_path = '/tmp/' + data_file
        self.SSH.put_file(local_file=src_path, rmt_file=dest_path)

        cmd = "sudo rpm -Va | grep -vxFf {0} | grep -Ev \
        '/boot/initramfs|/boot/System.map'".format(dest_path)
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   timeout=240,
                                   msg="check integrity through rpm -Va")
        self.assertEqual("", output,
                         "Found extra files has been modified:\n%s" % output)
        # Continue to compare every single file under local
        # "data/vendor/file_cmp"
        src_dir = self.data_dir + "/guest-images/file_cmp.el%s/" % product_id.split(
            '.')[0]
        if os.path.isdir(src_dir):
            for f in os.listdir(src_dir):
                m = re.match(r"^(%.*%)(.*)\.el(\d)$", f)
                if m:
                    f_name = m.group(2)
                    f_ver = m.group(3)
                    f_name_l = m.group(1).replace('%', '/') + f_name
                    if self.rhel_ver.split('.')[0] != f_ver:
                        continue
                else:
                    m = re.match(r"^(%.*%)(.*)$", f)
                    f_name = m.group(2)
                    f_name_l = f.replace('%', '/')
                src_path = src_dir + f
                dest_path = '/tmp/' + f_name
                self.SSH.put_file(local_file=src_path, rmt_file=dest_path)
                cmd = "grep -xv '^[[:space:]][[:space:]]*$' %s | diff \
-wB - %s" % (f_name_l, "/tmp/" + f_name)
                output = utils_lib.run_cmd(self,
                                           cmd,
                                           msg="compare through grep")
                self.assertEqual(
                    "", output,
                    "Found %s has been modified:\n%s" % (f_name, output))

    def test_check_boot_cmdline_parameters(self):
        """
        case_name:
            test_check_boot_cmdline_parameters
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            1144155,1729869
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check cmdline parameters
        key_steps:
            1. cat /proc/cmdline
        expect_result:
            no_timer_check console=ttyS0,115200n8 net.ifnames=0 crashkernel=
        debug_want:
            N/A
        """
        for count in utils_lib.iterate_timeout(
                600, "Timed out waiting for getting IP address."):
            cmd = 'sudo systemctl is-active kdump'
            ret = utils_lib.run_cmd(self,
                                    cmd,
                                    ret_status=True,
                                    msg='check kdump is active')
            if ret == 0:
                break
        src_dir = self.data_dir + "/guest-images/"
        data_file = "cmdline_params.lst"
        lines = filter(None,
                       (line.rstrip()
                        for line in open(os.path.join(src_dir, data_file))))
        cmd = "cat /proc/cmdline"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="cat /proc/cmdline")
        # crashkernel
        product_id = utils_lib.get_product_id(self)
        for line in lines:
            if line == "net.ifnames=0" and float(product_id) >= 10.0:
                # Skip the check for net.ifnames=0 if the product is RHEL 10 or higher
                self.log.info("Skipping check for net.ifnames=0 as it is removed in RHEL 10 and later")
                continue
            self.assertIn(line, output, "%s is not in boot parameters" % line)

        if float(product_id) >= 9.0:
            cmd = "sudo kdumpctl get-default-crashkernel"
            tmp_output = utils_lib.run_cmd(
                self,
                cmd,
                expect_ret=0,
                msg="kdumpctl get-default-crashkernel")
            line = "crashkernel=" + tmp_output.rstrip('.')[0]
        else:
            line = "crashkernel=auto"
        self.assertIn(line, output, "%s is not in boot parameters" % line)

    def test_check_package_signature(self):
        """
        case_name:
            test_check_package_signature
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check packages are signed
        key_steps:
            1. "rpm -qa --qf '%{name}-%{version}-%{release}.%{arch} (%{SIGPGP:pgpsig})\\n'|grep -v 'Key ID'"
        expect_result:
            Red Hat managed packages should be signed
        debug_want:
            N/A
        """
        data_file = "rpm_sign.lst"
        src_path = self.data_dir + '/guest-images/' + data_file
        dest_path = '/tmp/' + data_file
        self.SSH.put_file(local_file=src_path, rmt_file=dest_path)
        cmd = "rpm -qa --qf '%{name}-%{version}-%{release}.%{arch} \
(%{SIGPGP:pgpsig})\n'|grep -v 'Key ID'" + "|grep -vFf %s" % dest_path
        output = utils_lib.run_cmd(self, cmd, msg="compare through grep")

        # cheshi, newline characters are not supported in aexpect, so need a
        # workaroud here
        if output.find('|grep -vFf %s' % dest_path) != -1:
            output = "".join(output.splitlines(True)[1:])

        self.assertEqual(
            "", output,
            "There're packages that are not signed.\n {0}".format(output))

    def test_check_manpage(self):
        """
        case_name:
            test_check_manpage
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            200203
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check return code of man cmd
        key_steps:
            1. man -P cat man
        expect_result:
            return code is 0
        debug_want:
            N/A
        """
        cmd = "man -P cat man"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="run man cmd")

    def test_check_services_status(self):
        """
        case_name:
            test_check_services_status
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            974554
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check service status
        key_steps:
            1. systemctl
        expect_result:
            services is active and enabled
        debug_want:
            N/A
        """
        enabled_services = ['tuned', 'rhsmcertd']
        product_id = utils_lib.get_product_id(self)
        # TODO: rhsmcertd is disabled in 10-beta
        if float(product_id) <= 7.0 or float(product_id) == 10.0:
            enabled_services = ['tuned']
        services = enabled_services
        for service in services:
            cmd = "systemctl is-active %s" % service
            output = utils_lib.run_cmd(self,
                                       cmd,
                                       expect_ret=0,
                                       msg="systemctl is-active")
            cmd = "systemctl is-enabled %s" % service
            output = utils_lib.run_cmd(self,
                                       cmd,
                                       expect_ret=0,
                                       msg="systemctl is-enabled")
        output = ""
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < 9.0:
            cmd = "cat /etc/tuned/active_profile"
            output = utils_lib.run_cmd(self,
                                       cmd,
                                       expect_ret=0,
                                       msg="check tuned active_profile")
            self.assertEqual("virtual-guest", output.rstrip('\n'),
                             "Tuned service abnormal")

    def test_check_network_cfg(self):
        """
        case_name:
            test_check_network_cfg
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            983611
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check /etc/sysconfig/network content
        key_steps:
            1. cat /etc/sysconfig/network
        expect_result:
            NOZEROCONF=yes
        debug_want:
            N/A
        """
        flag = False
        cmd = "cat /etc/sysconfig/network"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="cat /etc/sysconfig/network")
        for line in output.splitlines():
            if line == "NOZEROCONF=yes":
                flag = True
        self.assertTrue(flag, "NOZEROCONF=yes not in /etc/sysconfig/network")

        """
        case_name:
            test_check_redhat_release
        case_tag:
            Validation
        case_file:
            os_tests.tests.test_rhel_guest_image.py
        component:
            rhel-guest-image
        bugzilla_id:
            1028889
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            wshi@redhat.com
        description:
            check /etc/redhat-release content
        key_steps:
            1. cat /etc/redhat-release
        expect_result:
            release version is equal to image nvr
        debug_want:
            N/A
        """

    def test_check_redhat_release(self):
        cmd = "cat /etc/redhat-release"
        output = utils_lib.run_cmd(self,
                                   cmd,
                                   expect_ret=0,
                                   msg="cat /etc/redhat-release")
        match = re.search(r"\d+\.?\d+", output).group(0)
        self.assertEqual(
            float(self.vm.rhel_ver), float(match),
            "Release version mismatch in /etc/redhat-release -> %s" % output)
        if float(self.vm.rhel_ver) >= 8.0:
            cmd = "rpm -q redhat-release"
            output = utils_lib.run_cmd(self,
                                       cmd,
                                       expect_ret=0,
                                       msg="rpm -q redhat-release")
            match = re.search(r"redhat-release-(\d\.?\d+)", output).group(1)
        if self.vm.rhel_ver.split('.')[0] == '7':
            cmd = "rpm -q redhat-release-server"
            output = utils_lib.run_cmd(self,
                                       cmd,
                                       expect_ret=0,
                                       msg="rpm -q redhat-release-server")
            match = re.search(r"redhat-release-server-(\d\.?\d+)",
                              output).group(1)
        if self.vm.rhel_ver.split('.')[0] == '6':
            output = self.session.cmd_output("rpm -q redhat-release-server")
            cmd = "rpm -q redhat-release-server"
            output = utils_lib.run_cmd(self,
                                       cmd,
                                       expect_ret=0,
                                       msg="rpm -q redhat-release-server")
            match = re.search(r"redhat-release-server-6Server-(\d\.?\d+)",
                              output).group(1)

        self.assertEqual(
            float(self.vm.rhel_ver), float(match),
            "Release version mismatch on redhat-release-server -> %s" % output)

    def tearDown(self):
        utils_lib.finish_case(self)


if __name__ == '__main__':
    unittest.main()
