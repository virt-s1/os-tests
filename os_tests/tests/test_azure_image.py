import unittest
from os_tests.libs import utils_lib
import json
import time

class TestAzureImage(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        if not utils_lib.is_azure(self):
            self.skipTest('Only run for azure image checking.')

    @property
    def rhel_x_version(self):
        product_id = utils_lib.get_product_id(self)
        return int(product_id.split('.')[0])

    @property
    def region(self):
        cmd = 'curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"'
        metadata = utils_lib.run_cmd(self, cmd)
        return json.loads(metadata)['compute']['location']

    def test_check_bash_history(self):
        '''
        '''
        for user in ['azureuser', 'root']:
            cmd = 'sudo cat ~{}/.bash_history'.format(user)
            utils_lib.run_cmd(self, cmd, expect_not_ret='0', msg='check bash history does not exist in fresh image')

    def test_check_cloudinit_cfg_mounts_growpart(self):
        '''
        bz: 966888
        des: make sure there is mounts/growpart in cloud_init_modules group in "/etc/cloud/cloud.cfg"
        '''
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        utils_lib.run_cmd(self,
                cmd,
                expect_ret=0,
                expect_kw='- growpart,- mounts',
                msg='check /etc/cloud/cloud.cfg to make sure there is mounts/growpart in cloud_init_modules(bz966888)')

    def test_check_cloudinit_cfg_no_wheel(self):
        '''
        bz: 1549638
        cm: 01965459
        des: make sure there is no wheel in default_user's group in "/etc/cloud/cloud.cfg"
        '''
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        utils_lib.run_cmd(self,
                cmd,
                expect_ret=0,
                expect_not_kw='wheel',
                msg='check /etc/cloud/cloud.cfg to make sure no wheel in default_user group(bz1549638)')

    def test_check_cmdline_console(self):
        '''
        console=ttyS0 earlyprintk=ttyS0 rootdelay=300 should be in cmdline
        '''
        utils_lib.run_cmd(self, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='console=ttyS0,earlyprintk=ttyS0,rootdelay=300', msg='check console,earlyprintk,rootdelay in cmdline')

    def test_check_cmdline_crashkernel(self):
        '''
        crashkernel should be enabled in image
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('9'):
            expect_kw = 'crashkernel=auto'
        else:
            # rhbz: 1942398
            if utils_lib.is_arch(self, arch='x86_64'):
                expect_kw = 'crashkernel=1G-4G:192M,4G-64G:256M,64G-:512M'
            else:
                expect_kw = 'crashkernel=2G-:448M'
        utils_lib.run_cmd(self, "sudo cat /proc/cmdline", expect_ret=0, expect_kw=expect_kw, msg='check crashkernel is enabled')

    def test_check_blacklist(self):
        '''
        rhbz: 1645772
        nouveau,lbm-nouveau,floppy should be disabled
        '''
        utils_lib.run_cmd(self, "sudo lsmod|grep nouveau", expect_not_ret=0, msg='check nouveau is not loaded')
        file_check = '/lib/modprobe.d/blacklist-*.conf'
        for module in ['nouveau, lbm-nouveau, floppy']:
            utils_lib.run_cmd(self, "sudo cat {}".format(file_check), expect_ret=0, expect_kw='blacklist '+module, msg='check "{}" in {}'.format(module, file_check))

    def test_check_cmdline_rhgb_quiet(self):
        '''
        rhbz: 1122300
        check no "rhgb" and "quiet" in /proc/cmdline
        '''
        utils_lib.run_cmd(self, "sudo cat /proc/cmdline", expect_ret=0, expect_not_kw='rhgb,quiet', msg='check no rhgb and quiet in boot cmd')

    def test_check_cpu_flags(self):
        '''
        rhbz: 1061348
        check various cpu flags
        '''
        utils_lib.is_arch(self, arch='x86_64', action='cancel')
        cmd = "sudo cat /proc/cpuinfo"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='avx,xsave,pcid', msg='check avx,xsave,pcid flags')

    def test_check_pkg_wanted(self):
        '''
        Some pkgs are required in azure.
        '''
        pkgs_wanted = '''yum-utils,redhat-release-eula,cloud-init,\
tar,rsync,NetworkManager,cloud-utils-growpart,gdisk,\
grub2-tools,WALinuxAgent,firewalld,chrony,\
hypervkvpd,hyperv-daemons-license,hypervfcopyd,hypervvssd,hyperv-daemons'''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8'):
            pkgs_wanted += ''',dhclient'''
        else:
            pkgs_wanted += ''',insights-client,dhcp-client'''
        pkgs_wanted_list = pkgs_wanted.split(',')
        for pkg in pkgs_wanted_list:
            cmd = 'rpm -q {}'.format(pkg)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check {} installed'.format(pkg))

    def test_check_firewalld(self):
        '''
        firewalld should be enabled
        '''
        cmd = 'sudo systemctl is-active firewalld'
        utils_lib.run_cmd(self,cmd, expect_ret=0, msg='check firewalld is running')

    def test_check_grub(self):
        '''
        Check grub2 config for el7:
        - boot with efi or legacy bios
        - /boot/grub2/grubenv is a symlink for /boot/efi/EFI/redhat/grubenv if boot with efi
        - /boot/grub2/grubenv is a file rather than a link if boot with legacy bios
        Check grub2 config for el8:
        - boot with efi or legacy bios
        - /boot/grub2/grub.cfg exists and /boot/grub2/grubenv is a file if boot with efi
        - /boot/grub2/grubenv is a file rather than a link if boot with legacy bios
        '''
        cmd = 'sudo ls /sys/firmware/efi'
        out = utils_lib.run_cmd(self, cmd, msg='check if boot with efi')
        cmd = 'sudo readlink -e /boot/grub2/grubenv'
        if out:
            if self.rhel_x_version < 8:
                utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="/boot/efi/EFI/redhat/grubenv",
                        msg='check /boot/grub2/grubenv is symlink for /boot/efi/EFI/redhat/grubenv')
            else:
                utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="/boot/grub2/grubenv",
                        msg='check /boot/grub2/grubenv is a file rather than a link')
                utils_lib.run_cmd(self, 'sudo ls /boot/grub2', expect_ret=0, expect_kw="grub.cfg",
                        msg='check for grub.cfg')
        else:
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="/boot/grub2/grubenv",
                msg='check /boot/grub2/grubenv is a file rather than a link')

    def test_check_hosts(self):
        '''
        des: localhost ipv6 and ipv4 should be set in /etc/hosts
        '''
        expect_kws = '127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4,::1         localhost localhost.localdomain localhost6 localhost6.localdomain6'
        cmd = "sudo cat /etc/hosts"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=expect_kws, msg='check /etc/hosts')

    def test_check_inittab(self):
        '''
        check default runlevel or systemd target
        '''
        is_systemd = utils_lib.run_cmd(self, 'rpm -q systemd > /dev/null && echo True || echo False')
        self.log.info("Is systemd system:{}".format(is_systemd))
        if 'True' in is_systemd:
            utils_lib.run_cmd(self, "sudo readlink -f /etc/systemd/system/default.target", expect_ret=0, expect_kw='/lib/systemd/system/multi-user.target', 
                msg='check default runlevel or systemd target')
        else:
            utils_lib.run_cmd(self, "sudo grep '^id:' /etc/inittab", expect_ret=0, expect_kw='id:3:initdefault', 
                msg='check default runlevel or systemd target')
            out = utils_lib.run_cmd(self, 'uname -r')
            if 'el5' in out:
                utils_lib.run_cmd(self, "grep '^si:' /etc/inittab", expect_kw="si::sysinit:/etc/rc.d/rc.sysinit")

    def test_check_nameserver(self):
        '''
        check if DNS resolving works
        '''
        utils_lib.run_cmd(self, "ping -c 5 google-public-dns-a.google.com", expect_ret=0, msg='check if DNS resolving works')

    def test_check_network_setup(self):
        '''
        1. NETWORKING=yes in /etc/sysconfig/network
        2. DEVICE=eth0 in /etc/sysconfig/network-scripts/ifcfg-eth0
        '''
        utils_lib.run_cmd(self, 'grep "^NETWORKING=yes" /etc/sysconfig/network', expect_ret=0, msg='check /etc/sysconfig/network')
        utils_lib.run_cmd(self, 'egrep "^DEVICE=(|\\\")eth0(|\\\")" /etc/sysconfig/network-scripts/ifcfg-eth0', expect_ret=0, msg='check eth0 used')


    def test_check_nm_cloud_setup(self):
        '''
        rhbz: 1822853
        des: 
        <=8.4: check NetworkManager-cloud-setup is not installed
        >=8.5: check NetworkManager-cloud-setup is installed and nm-cloud-setup.timer is setup for Azure and enabled
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8.5'):
            cmd = "rpm -q NetworkManager-cloud-setup"
            utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Check if NetworkManager-cloud-setup is not installed')
        else:
            ### TODO
            self.skipTest("Not install now.")
            cmd = "rpm -q NetworkManager-cloud-setup"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check if NetworkManager-cloud-setup is installed')
            cmd = "sudo systemctl is-enabled nm-cloud-setup"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check if nm-cloud-setup is enabled')

            #COMPOSER-842
            file_check = '/usr/lib/systemd/system/nm-cloud-setup.service.d/10-rh-enable-for-azure.conf'
            expect_kw='Environment=NM_CLOUD_SETUP_AZURE=yes'
            cmd = "sudo cat {}".format(file_check)
            utils_lib.run_cmd(self, cmd, expect_kw=expect_kw, msg='Check if "{}" is set in {}'.format(expect_kw, file_check))

    def test_check_no_avc_denials(self):
        '''
        check there is no avc denials (selinux)
        '''
        cmd = "x=$(sudo ausearch -m avc 2>&1 &); echo $x"
        utils_lib.run_cmd(self, cmd, expect_kw='no matches', msg='check no avc denials')

    def test_check_numa(self):
        '''
        check if NUMA is enabled on supported machine
        '''
        cmd = "sudo lscpu|grep -i 'NUMA node(s)'|awk -F' ' '{print $NF}'"
        numa_nodes = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get numa nodes')
        utils_lib.run_cmd(self, 'dmesg|grep -i numa', expect_ret=0, msg='get numa info')
        cmd = "sudo dmesg|grep -i 'No NUMA'|wc -l"
        out = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if int(numa_nodes) > 1:
            if int(out) == 1:
                self.fail("numa seems not enabled as expected")
            else:
                self.log.info("numa seems enabled as expected")
        else:
            self.log.info("only 1 node found")

    def test_check_pkg_signed(self):
        '''
        check no pkg signature is none,
        and check that specified gpg keys are installed
        '''
        cmd = "sudo rpm -qa|grep gpg-pubkey"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check gpg-pubkey installed')
        cmd = "sudo rpm -qa|grep rhui"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='Check if it is a RHUI image')
        if ret == 0:
            # RHUI image
            gpg_pubkey_num = '3'
        else:
            gpg_pubkey_num = '2'

        cmd = "sudo rpm -q gpg-pubkey|wc -l"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=gpg_pubkey_num, msg='check {} gpg-pubkey installed'.format(gpg_pubkey_num))
        cmd = "sudo rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'|grep -v gpg-pubkey"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='none', msg='check no pkg signature is none')
        cmd = "sudo rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n'|grep -vE '(gpg-pubkey|rhui)'|awk -F' ' '{print $NF}'|sort -u|wc -l"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='1', msg='check use only one keyid')

    def test_check_product_id(self):
        '''
        bz: 1938930
        issue: RHELPLAN-60817
        check if product id matches /etc/redhat-release
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8'):
            cmd = 'sudo rpm -q redhat-release-server'
        else:
            cmd = 'sudo rpm -q redhat-release'
        utils_lib.run_cmd(self,cmd, cancel_ret='0', msg='get redhat-release-server version')
        cmd = 'sudo rct cat-cert /etc/pki/product-default/*.pem'
        utils_lib.run_cmd(self,cmd, expect_ret=0, expect_kw="Version: {}".format(product_id), msg='check product certificate')

    def test_check_rhui_cert(self):
        '''
        Verify /etc/pki/rhui/product/content.crt exists
        Check end time
        '''
        # product_id = utils_lib.get_product_id(self)
        # if float(product_id) < float('8'):
        #     cmd = 'sudo rpm -q redhat-release-server'
        # else:
        #     cmd = 'sudo rpm -q redhat-release'
        cmd = "timestamp=$(sudo rct cat-cert /etc/pki/rhui/product/content.crt|grep 'End Date'|awk '{print $3}');date -d $timestamp +%s"
        end_date = utils_lib.run_cmd(self,cmd, msg='get rhui cert end date')
        cmd = 'sudo date +%s'
        now_date = utils_lib.run_cmd(self,cmd, msg='get now date')
        self.assertTrue(int(end_date) > int(now_date), "RHUI cert has expired")

    def test_check_rhel_version(self):
        '''
        check if rhel provider matches /etc/redhat-release
        '''
        release_file = 'redhat-release'
        product_id = utils_lib.get_product_id(self)
        cmd = "echo $(sudo rpm -q --qf '%{VERSION}' --whatprovides " + release_file + ')'
        utils_lib.run_cmd(self,cmd, expect_kw=product_id, msg='check redhat-release version match')

    def test_check_rhui_pkg(self):
        """
        8.4 images should have EUS RHUI. 
        Other versions should have non-EUS RHUI.
        """
        self.log.info('RHEL image found')
        product_id = utils_lib.get_product_id(self)
        x_version = self.rhel_x_version
        if product_id in ['8.4']:
            cmd = 'sudo rpm -q rhui-azure-rhel{}-eus'.format(x_version)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Verify EUS RHUI is installed in RHEL-{}".format(product_id))
            cmd = 'sudo rpm -q rhui-azure-rhel{}'.format(x_version)
            utils_lib.run_cmd(self, cmd, expect_ret=1, msg="Verify non-EUS RHUI is not installed in RHEL-{}".format(product_id))
        else:
            cmd = 'sudo rpm -q rhui-azure-rhel{}'.format(x_version)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Verify non-EUS RHUI is installed in RHEL-{}".format(product_id))
            cmd = 'sudo rpm -q rhui-azure-rhel{}-eus'.format(x_version)
            utils_lib.run_cmd(self, cmd, expect_ret=1, msg="Verify EUS RHUI is not installed in RHEL-{}".format(product_id))

    def test_check_root_is_locked(self):
        """
        Root account should be locked
        """
        self.log.info('RHEL AMI found')
        cmd = 'sudo passwd -S root | grep -q LK'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check root is locked')

    def test_check_shells(self):
        """
        Check for bash/nologin shells in /etc/shells
        """
        utils_lib.run_cmd(self, 'sudo cat /etc/shells', expect_kw='/bin/bash', msg='check /bin/bash in /etc/shells')

    def test_check_sshd(self):
        '''
        sshd service shoud be on, password authentication shoud be disabled
        '''
        is_systemd = utils_lib.run_cmd(self, 'rpm -q systemd > /dev/null && echo True || echo False')
        self.log.info("Is systemd system:{}".format(is_systemd))
        cmd = 'sudo cat /etc/ssh/sshd_config'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='PasswordAuthentication no', msg='check if password auth disabled')

    def test_check_sysconfig_kernel(self):
        '''
        des: UPDATEDEFAULT=yes and DEFAULTKERNEL=kernel should be set in /etc/sysconfig/kernel
        '''
        expect_kws = 'UPDATEDEFAULT=yes,DEFAULTKERNEL=kernel-core'
        cmd = "sudo cat /etc/sysconfig/kernel"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=expect_kws, msg='check /etc/sysconfig/kernel')

    def test_check_timezone(self):
        '''
        rhbz: 1187669
        check that the default timezone is set to UTC
        '''
        utils_lib.run_cmd(self, 'date', expect_kw='UTC', msg='check timezone is set to UTC')

    def test_check_username(self):
        """
        Check no old username in fresh image
        """
        for user in ['fedora', 'cloud-user']:
            cmd = 'sudo cat /etc/passwd|grep {}'.format(user)
            utils_lib.run_cmd(self, cmd, expect_not_ret='0', msg='check no {} user in fresh image'.format(user))

    def test_check_yum_dnf_plugins(self):
        '''
        bz: 1932802
        Verify yum/dnf plugin. For RHUI image, should be disabled. For SCA image, should be enabled
        product-id.conf should be enabled.
        '''
        cmd = 'sudo cat /etc/yum/pluginconf.d/product-id.conf'
        utils_lib.run_cmd(self,cmd, expect_ret=0, expect_kw='enabled=1', msg='check yum product-id plugin is enabled')
        cmd = "sudo rpm -qa|grep rhui"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='Check if it is a RHUI image')
        if ret == 0:
            # RHUI image
            expect_kw = "enabled=0"
            status = "disabled"
        else:
            # SCA image
            expect_kw = "enabled=1"
            status = "enabled"
        if self.rhel_x_version >= 8:
            expect_kw += ",disable_system_repos=0"
        # Yum plugin
        cmd = "sudo cat /etc/yum/pluginconf.d/subscription-manager.conf|sed -s 's/ = /=/g'"
        utils_lib.run_cmd(self,cmd, expect_ret=0, expect_kw=expect_kw, msg='check yum subscription-manager plugin is {}'.format(status))
        # Dnf plugin
        cmd = "sudo cat /etc/dnf/plugins/subscription-manager.conf|sed -s 's/ = /=/g'"
        utils_lib.run_cmd(self,cmd, expect_ret=0, expect_kw=expect_kw, msg='check dnf subscription-manager plugin is {}'.format(status))

    def test_check_auditd(self):
        """
        Check auditd:
        - service should be on
        - config files shoud have specified checksums
        """
        out = utils_lib.run_cmd(self, 'sudo cat /etc/redhat-release', expect_ret=0, msg='get release name')
        if 'release 8' in out:
            auditd_checksum = '7bfa16d314ddb8b96a61a7f617b8cca0'
            auditd_rules_checksum = '795528bd4c7b4131455c15d5d49991bb'
        elif 'release 7' in out:
            # 7.5 onward
            auditd_checksum = '29f4c6cd67a4ba11395a134cf7538dbd'
            auditd_rules_checksum = 'f1c2a2ef86e5db325cd2738e4aa7df2c'
        elif 'release 6' in out:
            # 6.9 onward
            auditd_checksum = '306e13910db5267ffd9887406d43a3f7'
            auditd_sysconf_checksum = '0825f77b49a82c5d75bcd347f30407ab'
            utils_lib.run_cmd(self, 'sudo md5sum /etc/sysconfig/auditd', expect_kw=auditd_sysconf_checksum)
        else:
            self.skipTest('skip run in el5 and earlier than 6.9, 7.5. el9 will be added')

        utils_lib.run_cmd(self, 'sudo md5sum /etc/audit/auditd.conf', expect_kw=auditd_checksum)
        if 'release 6' not in out:
            utils_lib.run_cmd(self, 'sudo md5sum /etc/audit/audit.rules', expect_kw=auditd_rules_checksum)

    def test_check_ttyS0_conf(self):
        """
        bz: 1103344
        check no "/etc/init/ttyS0.conf" exists.
        check no "/dev/ttyS0: tcgetattr: Input/output error" in "/var/log/secure"
        """
        utils_lib.run_cmd(self, 'sudo cat /etc/init/ttyS0.conf', expect_not_ret=0, msg='make sure no /etc/init/ttyS0.conf found')
        utils_lib.run_cmd(self, 'sudo cat /etc/init/ttyS0.bak', msg='ttyS0.bak may also not in RHEL nowadays')

    def test_check_rpm_V_unsatisfied_dependencies(self):
        '''
        check unsatisfied dependencies of pkg.
        '''
        utils_lib.run_cmd(self, "sudo rpm -Va", expect_not_kw='Unsatisfied', timeout=300, msg='check unsatisfied dependencies of pkg')

    def test_check_selinux(self):
        '''
        SELinux should be in enforcing/targeted mode
        '''
        out = utils_lib.run_cmd(self, 'uname -r', msg='get kernel version')
        utils_lib.run_cmd(self, 'sudo getenforce',expect_kw='Enforcing', msg='check selinux current mode is Enforcing')
        utils_lib.run_cmd(self, 'sudo cat /etc/sysconfig/selinux',expect_kw='SELINUX=enforcing,SELINUXTYPE=targeted', msg='check selinux current setting')

    def test_check_yum_repoinfo(self):
        '''
        '''
        cmd = "sudo rpm -qa|grep rhui"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='Check if it is a RHUI image')
        if ret != 0:
            self.skipTest("Skip in non-RHUI image")
        cmd = "sudo yum repoinfo"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Repo-pkgs          : 0', timeout=1200, msg='try to get repo info')

    def test_yum_package_install(self):
        '''
        '''
        cmd = "sudo rpm -qa|grep rhui"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check if RHUI is installed')
        utils_lib.run_cmd(self, "sudo yum clean all", expect_ret=0, timeout=180)
        utils_lib.run_cmd(self, "sudo yum repolist", expect_ret=0, timeout=1200)
        utils_lib.run_cmd(self, "sudo yum check-update", timeout=1200)
        utils_lib.run_cmd(self, "sudo yum search zsh", expect_ret=0, timeout=180)
        utils_lib.run_cmd(self, "sudo yum -y install zsh", expect_ret=0, timeout=180)
        utils_lib.run_cmd(self, r"sudo rpm -q --queryformat '%{NAME}' zsh", expect_ret=0)
        utils_lib.run_cmd(self, "sudo rpm -e zsh", expect_ret=0)

    def test_check_subscription_manager_auto_config(self):
        '''
        bz: 1932802, 1905398
        Verify auto_registration is enabled in the image
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8.4'):
            self.skipTest('skip in earlier than el8.4')

        # cmd = "sudo rpm -qa|grep rhui"
        # ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='Check if it is a RHUI image')
        # if ret == 0:
        #     # RHUI image
        #     expect_kw="auto_registration = 0,manage_repos = 1"
        # else:
        #     # SCA image
        #     expect_kw="auto_registration = 1,manage_repos = 1"
        expect_kw="auto_registration = 1,manage_repos = 0"
        cmd = "sudo cat /etc/rhsm/rhsm.conf"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=expect_kw, msg='try to check subscription-manager config')
        cmd = "sudo systemctl is-enabled rhsmcertd"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to check rhsmcertd enabled')

    def test_check_pkgs(self):
        '''
        Some pkgs are required in azure.
        '''
        base_file = 'pkglist'
        test_file = '/tmp/pkglist_test'
        if self.rhel_x_version < 8:
            cmd = 'rpm -qa --qf "%{{NAME}}\n"|sort|grep -v python3 > {}'.format(test_file)
        else:
            cmd = 'rpm -qa --qf "%{{NAME}}\n"|sort > {}'.format(test_file)
        utils_lib.run_cmd(self, cmd)
        self._check_file_content(base_file, test_file, msg="Check packages list", project=self.rhel_x_version)

    def test_check_waagent_resourcedisk_format(self):
        '''
        Verify the ResourceDisk.Format is disabled in waagent.conf
        '''
        cmd = "sudo cat /etc/waagent.conf | grep ResourceDisk.Format"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='ResourceDisk.Format=n', msg='Check ResourceDisk.Format in waagent.conf')

    def test_check_services_active(self):
        '''
        Verify the services are active
        '''
        services = '''waagent,cloud-init-local,cloud-init,cloud-config,cloud-final,hypervkvpd,sshd'''
        service_list = services.split(',')
        for service in service_list:
            cmd = 'systemctl is-active {}'.format(service)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check {} is active'.format(service))

    def test_check_grub_params(self):
        '''
        Verify /etc/default/grub params
        '''
        filename = '/etc/default/grub'
        self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)

    def test_check_kdump_status(self):
        '''
        Verify the kdump is enabled
        '''
        cmd = "sudo kdumpctl status"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='Kdump is operational', msg='Check kdump status')

    def _check_log(self, filename, ignore_list=[], keyword='err|fail|warn|trace'):
        cmd = "sudo grep -iE 'err|fail|warn|trace' {}|grep -vE '{}'".format(filename, '|'.join(ignore_list))
        output = utils_lib.run_cmd(self, cmd, msg="Check {} in {}".format(keyword, filename))
        if output:
            self.log.info("Unexpected logs exist in {}.\n{}".format(filename, output))
            return False
        else:
            self.log.info("No unexpected logs in "+filename)
            return True

    def test_check_messages(self):
        '''
        Verify no error/fail/trace in /var/log/messages
        '''
        ignore_list = [
            'Failed to init entropy source hwrng',
            'Failed to register legacy timer interrupt',
            'augenrules.*failure 1',
            'cloud-init.*handlers.py.*failed to truncate kvp pool file',
            'nofail',
            'Errors: 0',
            'kernel version.*failed early load check for .*, skipping',
            'Failed determining last makecache time',
            'kernel: ftrace',
            'switching default tracing clock'
        ]
        self._check_log('/var/log/messages', ignore_list, 'error|fail|trace')

    def test_check_dmesg(self):
        '''
        Verify no err/fail/warn/trace in dmesg
        '''
        ignore_list = [
            'override',
            'ftrace',
            'deferred',
            'interrupt',
            'Failed to register legacy timer interrupt',
            'trace_clock=local'
        ]
        utils_lib.run_cmd(self, 'dmesg > /tmp/dmesg.log')
        self._check_log('/tmp/dmesg.log', ignore_list)

    def test_check_cloudinit_log(self):
        '''
        Verify no err/fail/warn/trace in /var/log/cloud-init.log
        '''
        ignore_list = [
            'failed to truncate kvp pool file',
            'finish: azure-ds/load_azure_ds_dir: FAIL: load_azure_ds_dir',
            'tracefs',
            'errors=remount-ro',
            'dhclient error stream',
            'util.py.DEBUG.: Failed mount of ./dev/sdb1. as .ntfs.',
            'Stderr: mount: .*: unknown filesystem type .ntfs.',
            'SKIPPED: device_part_info.* failed: /dev/mapper/rootvg-rootlv not a partition',
            'modules with 0 failures',
            'Failed to get raw userdata in module rightscale_userdata'
        ]
        self._check_log('/var/log/cloud-init.log', ignore_list)

    def test_check_waagent_log(self):
        '''
        Verify no err/fail/warn/trace in /var/log/waagent.log
        '''
        ignore_list = [
            'preferred',
            'Dhcp client is not running',
            'Move rules file 70-persistent-net.rules',
            'UpdateGSErrors: 0'
        ]
        self._check_log('/var/log/waagent.log', ignore_list)

    def test_check_journal_log(self):
        '''
        Verify no traceback|ordering in journalctl -xl
        '''
        ignore_list = []
        utils_lib.run_cmd(self, 'sudo journalctl -xl > /tmp/journal.log')
        self._check_log('/tmp/journal.log', ignore_list, 'traceback|ordering')

    def test_check_no_fail_service(self):
        '''
        Verify no failed service
        '''
        utils_lib.run_cmd(self, 'sudo systemctl list-units|grep -i fail', expect_not_ret=0, msg="Verify no failed service.")

    def test_get_kernel_version(self):
        '''
        Get kernel version and record in the log
        '''
        utils_lib.run_cmd(self, 'sudo uname -r')

    def test_check_boot_time(self):
        """
        check if there's boot time delay
        """
        max_boot_time = 100
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=max_boot_time, ratio=0, msg="Compare with cfg specified max_boot_time")

    def test_check_hyperv_drivers(self):
        '''
        Verify hyperv drivers are loaded
        '''
        hyperv_driver_list = [
            'hyperv_fb',
            'hv_utils',
            'hv_balloon',
            'hv_storvsc',
            'scsi_transport_fc',
            'hid_hyperv',
            'hv_netvsc',
            'hyperv_keyboard',
            'hv_vmbus'
        ]
        cmd = "/sbin/lsmod|grep -iE 'hv|hyperv'"
        utils_lib.run_cmd(self, cmd, expect_kw=','.join(hyperv_driver_list), msg="Verify hyperv drivers are loaded")

    def test_check_dracut_conf(self):
        '''
        Check /etc/dracut.conf
        '''
        cmd = "cat /etc/dracut.conf|grep -v '^#'"
        utils_lib.run_cmd(self, cmd, expect_output='', msg="Verify no config in /etc/dracut.conf")
        cmd = "ls /etc/dracut.conf.d/"
        utils_lib.run_cmd(self, cmd, expect_output='', msg="Verify no config files in /etc/dracut.conf.d/")

    def test_check_hostkey_permission(self):
        '''
        Verify /etc/ssh/ssh_host_xxx_key permission are -rw-------.
        '''
        if self.rhel_x_version < 8:
            expected = "-rw-r-----."
        else:
            expected = "-rw-------."
        cmd = "ls -l /etc/ssh/{ssh_host_ecdsa_key,ssh_host_ed25519_key,ssh_host_rsa_key}|awk '{print $1}'|uniq"

        utils_lib.run_cmd(self, cmd, expect_output=expected, msg="Verify /etc/ssh/ssh_host_xxx_key permission are -rw-------.")

    def test_check_kdump_configuration(self):
        '''
        Check /etc/sysconfig/kdump and /etc/kdump.conf
        '''
        if self.rhel_x_version < 8:
            sysconfig_kdump = '''\
KDUMP_COMMANDLINE=""
KDUMP_COMMANDLINE_APPEND="irqpoll nr_cpus=1 reset_devices cgroup_disable=memory mce=off numa=off udev.children-max=2 panic=10 acpi_no_memhotplug transparent_hugepage=never nokaslr novmcoredd hest_disable"
KDUMP_COMMANDLINE_REMOVE="hugepages hugepagesz slub_debug kaslr"
KDUMP_IMG_EXT=""
KDUMP_IMG="vmlinuz"
KDUMP_KERNELVER=""
KEXEC_ARGS=""
'''
            kdump_conf = '''\
path /var/crash
core_collector makedumpfile -l --message-level 1 -d 31
'''
        else:
            sysconfig_kdump = '''\
KDUMP_KERNELVER=""
KDUMP_COMMANDLINE=""
KDUMP_COMMANDLINE_REMOVE="hugepages hugepagesz slub_debug quiet log_buf_len swiotlb"
KDUMP_COMMANDLINE_APPEND="irqpoll nr_cpus=1 reset_devices cgroup_disable=memory mce=off numa=off udev.children-max=2 panic=10 rootflags=nofail acpi_no_memhotplug transparent_hugepage=never nokaslr novmcoredd hest_disable"
KEXEC_ARGS="-s"
KDUMP_IMG="vmlinuz"
KDUMP_IMG_EXT=""
'''
            kdump_conf = '''\
path /var/crash
core_collector makedumpfile -l --message-level 7 -d 31
'''
        # Check /etc/sysconfig/kdump
        self._check_file_content(testfile="/etc/sysconfig/kdump", expected=sysconfig_kdump, msg="Check /etc/sysconfig/kdump")
        
        # Check /etc/kdump.conf
        self._check_file_content(testfile="/etc/kdump.conf", expected=kdump_conf, msg="Check /etc/kdump.conf")

    def test_check_dnf_conf(self):
        '''
        Check /etc/dnf/dnf.conf
        '''
        if self.rhel_x_version < 8:
            self.skipTest("Only support in RHEL-8+.")
        dnf_conf = '''\
[main]
gpgcheck=1
installonly_limit=3
clean_requirements_on_remove=True
best=True
skip_if_unavailable=False            
'''
        filename = '/etc/dnf/dnf.conf'
        self._check_file_content(testfile=filename, expected=dnf_conf, msg="Check /etc/dnf/dnf.conf")

    def test_check_authselect(self):
        '''
        Check authselect current
        '''
        if self.rhel_x_version < 8:
            self.skipTest("Only support in RHEL-8+")
        cmd = 'authselect current'
        utils_lib.run_cmd(self, cmd, expect_output="No existing configuration detected.", msg="Check authselect current")

    def test_check_logging_cfg(self):
        '''
        Check /etc/cloud/cloud.cfg.d/05_logging.cfg
        * For RHEL-7 it is 06_logging_override.cfg
        '''
        if self.rhel_x_version < 8:
            filename = '/etc/cloud/cloud.cfg.d/06_logging_override.cfg'
        else:
            filename = '/etc/cloud/cloud.cfg.d/05_logging.cfg'
        self._check_file_content(filename.split('/')[-1], filename)

    def test_no_sshkeys_knownhosts(self):
        '''
        Verify no extra files under /root/.ssh/ except authorized_keys
        '''
        cmd = "sudo ls /root/.ssh/"
        utils_lib.run_cmd(self, cmd, expect_output="authorized_keys", msg="Check no extra files in /root/.ssh")

    def test_check_clientaliveinterval(self):
        '''
        Verify ClientAliveInterval 180 in /etc/ssh/sshd_config
        '''
        cmd = "sudo grep ^ClientAliveInterval /etc/ssh/sshd_config"
        utils_lib.run_cmd(self, cmd, expect_output="ClientAliveInterval 180", msg="Verify ClientAliveInterval is 180")

    def _check_file_content(self, basefile=None, testfile=None, expected=None, msg=None, project=None):
        '''
        Function to check file content.
        '''
        # Print testfile content for recording
        utils_lib.run_cmd(self, "cat "+testfile)
        # If base is a file
        if basefile:
            # Base file content is different in multiple RHEL versions
            if project:
                basefile += "_rhel{}".format(project)
            # Get the base file path
            # If remote node, copy the basefile to the remote node /tmp/
            src_file = self.data_dir + '/azure/{}'.format(basefile)
            if self.params['remote_node'] is not None:
                base_file = "/tmp/"+basefile
                self.log.info('Copy {} to remote'.format(basefile))
                self.SSH.put_file(local_file=src_file, rmt_file=base_file)
            else:
                base_file = src_file
            test_file = testfile
        # If base is a block of strings
        elif expected:
            base_file = '/tmp/basefile'
            utils_lib.run_cmd(self, "echo '''{0}''' > {1};sort {1}>{2}".format(expected, '/tmp/tmpfile', base_file))
            test_file = '/tmp/testfile'
            cmd = "sudo cat {}|grep -v '^#'|sed '/^$/d'|sort > {}".format(testfile, test_file)
            utils_lib.run_cmd(self, cmd)
        else:
            self.error('Must specify basefile or expected!')
        if not msg:
            msg = "Check "+testfile
        # Compare files ignore space, empty line and order
        output = utils_lib.run_cmd(self, "sudo diff -wB {} {}".format(base_file, test_file), msg=msg)
        self.assertEqual(output, '', "{} and {} are not the same.\n{}".format(base_file, test_file, output))

    def test_check_91_azure_datasource(self):
        '''
        Check file /etc/cloud/cloud.cfg.d/91-azure_datasource.cfg
        '''
        filename = "/etc/cloud/cloud.cfg.d/91-azure_datasource.cfg"
        self._check_file_content(filename.split('/')[-1], filename)

    def test_check_68_azure_sriov_nm_unmanaged_rules(self):
        '''
        Check file /etc/udev/rules.d/68-azure-sriov-nm-unmanaged.rules
        '''
        filename = "/etc/udev/rules.d/68-azure-sriov-nm-unmanaged.rules"
        self._check_file_content(filename.split('/')[-1], filename)

    def test_check_66_azure_storage_rules(self):
        '''
        Check file /etc/udev/rules.d/66-azure-storage.rules
        '''
        if self.rhel_x_version >= 8:
            self.skipTest('Only support in RHEL-7')
        filename = '/etc/udev/rules.d/66-azure-storage.rules'
        self._check_file_content(filename.split('/')[-1], filename)

    def test_check_99_azure_product_uuid_rules(self):
        '''
        Check file /etc/udev/rules.d/99-azure-product-uuid.rules
        '''
        if self.rhel_x_version >= 8:
            self.skipTest('Only support in RHEL-7')
        filename = '/etc/udev/rules.d/99-azure-product-uuid.rules'
        self._check_file_content(filename.split('/')[-1], filename)

    def test_check_cloud_cfg(self):
        '''
        Check file /etc/cloud/cloud.cfg
        '''
        filename = '/etc/cloud/cloud.cfg'
        self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)

    def test_check_pwquality_conf(self):
        '''
        Check file /etc/security/pwquality.conf
        '''
        filename = '/etc/security/pwquality.conf'
        expected = '''\
dcredit = 0
lcredit = 0
minclass = 3
minlen = 6
ocredit = 0
ucredit = 0
'''
        self._check_file_content(expected=expected, testfile=filename)

    # def test_check_waagent_conf(self):
    #     '''
    #     Check file /etc/waagent.conf
    #     '''
    #     self.skipTest("Inactive case.")
    #     filename = '/etc/waagent.conf'
    #     self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)

    def test_check_networkmanager_conf(self):
        '''
        Check /etc/NetworkManager/NetworkManager.conf
        '''
        expected = '''\
[main]
plugins = ifcfg-rh,
[logging]
'''
        filename = '/etc/NetworkManager/NetworkManager.conf'
        self._check_file_content(expected=expected, testfile=filename)

    def test_check_authselect_conf(self):
        '''
        Check config files under /etc/authselect
        '''
        if self.rhel_x_version < 8:
            self.skipTest("Only support in RHEL-8+")
        cmd = "ls /etc/authselect/"
        utils_lib.run_cmd(self, cmd, expect_output='custom\nuser-nsswitch.conf')
        cmd = "ls /etc/authselect/custom/"
        utils_lib.run_cmd(self, cmd, expect_output='')

    def test_check_fingerprint_auth(self):
        '''
        Check file /etc/pam.d/fingerprint-auth
        '''
        filename = '/etc/pam.d/fingerprint-auth'
        self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)

    def test_check_password_auth(self):
        '''
        Check file /etc/pam.d/password-auth
        '''
        filename = '/etc/pam.d/password-auth'
        self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)

    def test_check_postlogin(self):
        '''
        Check file /etc/pam.d/postlogin
        '''
        filename = '/etc/pam.d/postlogin'
        self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)

    def test_check_smartcard_auth(self):
        '''
        Check file /etc/pam.d/smartcard-auth
        '''
        filename = '/etc/pam.d/smartcard-auth'
        self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)

    def test_check_system_auth(self):
        '''
        Check file /etc/pam.d/system-auth
        '''
        filename = '/etc/pam.d/system-auth'
        self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)
        
    def test_check_chrony_conf(self):
        '''
        Check file /etc/chrony.conf
        '''
        filename = '/etc/chrony.conf'
        self._check_file_content(filename.split('/')[-1], filename, project=self.rhel_x_version)

    def test_check_authconfig(self):
        '''
        Verify no /etc/sysconfig/authconfig file
        '''
        if self.rhel_x_version >= 8:
            # In RHEL-8 there should be no authconfig file
            cmd = 'ls /etc/sysconfig/authconfig'
            utils_lib.run_cmd(self, cmd, expect_ret=2)
        else:
            # In RHEL-7, check authconfig content
            filename = '/etc/sysconfig/authconfig'
            self._check_file_content(filename.split('/')[-1], filename)

    def test_check_yum_conf(self):
        '''
        Check file /etc/yum.conf
        '''
        if self.rhel_x_version < 8:
            expected = '''\
cachedir=/var/cache/yum/$basearch/$releasever
debuglevel=2
exactarch=1
gpgcheck=1
http_caching=packages
installonly_limit=3
keepcache=0
logfile=/var/log/yum.log
[main]
obsoletes=1
plugins=1
'''
        else:
            expected = '''\
best=True
clean_requirements_on_remove=True
gpgcheck=1
installonly_limit=3
[main]
skip_if_unavailable=False
'''
        filename = '/etc/yum.conf'
        self._check_file_content(testfile=filename, expected=expected, project=self.rhel_x_version)

    def test_check_langpacks_conf(self):
        '''
        Verify /etc/yum/pluginconf.d/langpacks.conf
        ''' 
        if self.rhel_x_version < 8:
            # Check file content in RHEL-7
            filename = "/etc/yum/pluginconf.d/langpacks.conf"
            expected = '''\
[main]
enabled=1
langpack_locales = en_US.UTF-8
'''
            self._check_file_content(testfile=filename, expected=expected)
        else:
            # No such file in RHEL-8
            cmd = 'ls /etc/yum/pluginconf.d/langpacks.conf'
            utils_lib.run_cmd(self, cmd, expect_ret=2)

    # Inactive this case because the nss.config is always changed
    # def test_check_nss_config(self):
    #     '''
    #     Check file /etc/crypto-policies/back-ends/nss.config
    #     '''
    #     self.skipTest("Inactive case")
    #     if self.rhel_x_version < 8:
    #         self.skipTest("Only support RHEL-8+")
    #     filename = '/etc/crypto-policies/back-ends/nss.config'
    #     self._check_file_content(filename.split('/')[-1], filename)

    def test_check_osdisk_size(self):
        '''
        Verify os disk size is 64 GiB
        '''
        cmd = "sudo fdisk -l|grep 'Disk /dev/sda'|awk '{print $5}'"
        utils_lib.run_cmd(self, cmd, expect_kw='68719476736', msg="Verify os disk size is 64 GiB")

    # Inactive this case because the service list is not always the same
    # def test_check_service_list(self):
    #     '''
    #     Compare services list
    #     '''
    #     test_file = '/tmp/services_test'
    #     cmd = "sudo systemctl list-units --type=service|grep -vE 'UNIT|LOAD|ACTIVE|SUB|To show all|loaded units listed|File System Check on /dev/disk/by-uuid|^user'|awk '{print $1}'|sed '/^$/d'|sort > "+test_file
    #     utils_lib.run_cmd(self, cmd)
    #     base_file = 'services'
    #     self._check_file_content(base_file, test_file, msg="Compare services list", project=self.rhel_x_version)

    def test_check_sshd_config(self):
        '''
        Check file /etc/ssh/sshd_config
        '''
        if self.rhel_x_version < 8:
            expected = '''\
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv XMODIFIERS
AuthorizedKeysFile	.ssh/authorized_keys
ChallengeResponseAuthentication no
ClientAliveInterval 180
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PasswordAuthentication no
Subsystem	sftp	/usr/libexec/openssh/sftp-server
SyslogFacility AUTHPRIV
UsePAM yes
X11Forwarding yes
'''
        else:
            expected = '''\
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv XMODIFIERS
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
ClientAliveInterval 180
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PasswordAuthentication no
PermitRootLogin yes
PrintMotd no
Subsystem sftp	/usr/libexec/openssh/sftp-server
SyslogFacility AUTHPRIV
UsePAM yes
X11Forwarding yes
'''
        filename = "/etc/ssh/sshd_config"
        self._check_file_content(testfile=filename, expected=expected)

    def test_check_metadata(self):
        '''
        Verify can get metadata
        '''
        cmd = 'curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"'
        metadata = utils_lib.run_cmd(self, cmd)
        metadata_dict = json.loads(metadata)
        self.assertEqual(metadata_dict.get('compute').get('azEnvironment'), "AzurePublicCloud", 
            "Cannot parse metadata to get azEnvironment")

    def test_check_cds_hostnames(self):
        '''
        Check cds hostnames
        '''
        rhui_cds_hostnames = [
            "rhui-1.microsoft.com",
            "rhui-2.microsoft.com",
            "rhui-3.microsoft.com",
            "{0}-cds.{0}.cloudapp.azure.com".format(self.region),
            "rh-cds.trafficmanager.net"
        ]
        for cds in rhui_cds_hostnames:
            #there is no rhui in us-gov regions at all - all the content requests are redirected to closest standard regions
            cds_name = cds.replace('-gov','')
            cmd = "sudo getent hosts {}".format(cds_name)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check {}'.format(cds_name))

    def test_z_check_subscription_manager_auto_function(self):
        '''
        * Add "z" in the case name to make it run at last
        Verify auto_registration function works
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8.4'):
            self.skipTest('skip in earlier than el8.4')
        cmd = "sudo subscription-manager config --rhsmcertd.auto_registration_interval=1"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Check interval to 1 min")
        cmd = "sudo systemctl restart rhsmcertd.service"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Restart rhsmcertd service")
        time.sleep(60)
        for retry in range(1, 11):
            cmd = "sudo subscription-manager identity"
            output = utils_lib.run_cmd(self, cmd, msg="Checking register status...")
            if "system identity" in output:
                self.log.info("Auto register successfully!")
                break
            self.log.info("Not registered yet. Wait for 30s...{}/10".format(retry))
            time.sleep(30)
        else:
            self.fail("Fail to auto register!")

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
