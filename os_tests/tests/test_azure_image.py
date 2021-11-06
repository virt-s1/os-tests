import unittest
from os_tests.libs import utils_lib
import json
import os
import re
import time

class TestAzureImage(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        if not utils_lib.is_azure(self):
            self.skipTest('Only run for azure image checking.')

    def test_check_bash_history(self):
        '''
        :avocado: tags=basic
        '''
        for user in ['azureuser', 'root']:
            cmd = 'sudo cat ~{}/.bash_history'.format(user)
            utils_lib.run_cmd(self, cmd, expect_not_ret='0', msg='check bash history does not exist in fresh image')

    def test_check_cloudinit_cfg_growpart(self):
        '''
        bz: 966888
        des: make sure there is growpart in cloud_init_modules group in "/etc/cloud/cloud.cfg"
        :avocado: tags=basic
        '''
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        utils_lib.run_cmd(self,
                cmd,
                expect_ret=0,
                expect_kw='- growpart',
                msg='check /etc/cloud/cloud.cfg to make sure there is growpart in cloud_init_modules(bz966888)')

    def test_check_cloudinit_cfg_no_wheel(self):
        '''
        bz: 1549638
        cm: 01965459
        polarion_id:
        des: make sure there is no wheel in default_user's group in "/etc/cloud/cloud.cfg"
        :avocado: tags=basic
        '''
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        utils_lib.run_cmd(self,
                cmd,
                expect_ret=0,
                expect_not_kw='wheel',
                msg='check /etc/cloud/cloud.cfg to make sure no wheel in default_user group(bz1549638)')

    def test_check_cmdline_console(self):
        '''
        console output shoud be redirected to serial for for hvm instances
        :avocado: tags=basic
        '''
        utils_lib.run_cmd(self, "sudo cat /proc/cmdline", expect_ret=0, expect_kw='console=ttyS0', msg='check serial console is redirected to ttyS0')

    def test_check_cmdline_crashkernel(self):
        '''
        crashkernel should be enabled in image
        :avocado: tags=basic
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

    def test_check_cmdline_nouveau(self):
        '''
        rhbz: 1645772
        nouveau,lbm-nouveau,floppy should be disabled
        :avocado: tags=basic
        '''
        utils_lib.run_cmd(self, "sudo lsmod|grep nouveau", expect_not_ret=0, msg='check nouveau is not loaded')
        file_check = '/lib/modprobe.d/blacklist-*.conf'
        utils_lib.run_cmd(self, "sudo cat {}".format(file_check), expect_ret=0, expect_kw='blacklist nouveau', msg='check "{}" in {}'.format('nouveau', file_check))
        utils_lib.run_cmd(self, "sudo cat {}".format(file_check), expect_ret=0, expect_kw='blacklist lbm-nouveau', msg='check "{}" in {}'.format('lbm-nouveau', file_check))
        utils_lib.run_cmd(self, "sudo cat {}".format(file_check), expect_ret=0, expect_kw='blacklist floppy', msg='check "{}" in {}'.format('floppy', file_check))

    def test_check_cmdline_rhgb_quiet(self):
        '''
        rhbz: 1122300
        check no "rhgb" and "quiet" in /proc/cmdline
        :avocado: tags=basic
        '''
        utils_lib.run_cmd(self, "sudo cat /proc/cmdline", expect_ret=0, expect_not_kw='rhgb,quiet', msg='check no rhgb and quiet in boot cmd')

    def test_check_cpu_flags(self):
        '''
        rhbz: 1061348
        check various cpu flags
        :avocado: tags=basic
        '''
        utils_lib.is_arch(self, arch='x86_64', action='cancel')
        cmd = "sudo cat /proc/cpuinfo"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='avx,xsave', msg='check avx and xsave flags')

    def test_check_pkg_wanted(self):
        '''
        Some pkgs are required in azure.
        '''
        pkgs_wanted = '''yum-utils,redhat-release-eula,cloud-init,\
tar,rsync,NetworkManager,cloud-utils-growpart,gdisk,dracut-config-generic,\
dracut-config-rescue,grub2-tools,WALinuxAgent,firewalld,chrony,\
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

    # def test_check_firewalld(self):
    #     '''
    #     firewalld should be enabled
    #     :avocado: tags=basic
    #     '''
    #     cmd = 'sudo systemctl is-active firewalld'
    #     utils_lib.run_cmd(self,cmd, expect_ret=0, msg='check firewalld is running')

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
        :avocado: tags=basic
        '''
        product_id = utils_lib.get_product_id(self)
        cmd = 'sudo ls /sys/firmware/efi'
        out = utils_lib.run_cmd(self, cmd, msg='check if boot with efi')
        cmd = 'sudo readlink -e /boot/grub2/grubenv'
        if out:
            if float(product_id) < float('8'):
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
        :avocado: tags=basic
        '''
        expect_kws = '127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4,::1         localhost localhost.localdomain localhost6 localhost6.localdomain6'
        cmd = "sudo cat /etc/hosts"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=expect_kws, msg='check /etc/hosts')

    def test_check_inittab(self):
        '''
        check default runlevel or systemd target
        :avocado: tags=basic
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
        :avocado: tags=basic
        '''
        utils_lib.run_cmd(self, "ping -c 5 google-public-dns-a.google.com", expect_ret=0, msg='check if DNS resolving works')

    def test_check_network_setup(self):
        '''
        check for networking setup
        :avocado: tags=basic
        '''
        utils_lib.run_cmd(self, 'grep "^NETWORKING=yes" /etc/sysconfig/network', expect_ret=0, msg='check /etc/sysconfig/network')
        utils_lib.run_cmd(self, 'egrep "^DEVICE=(|\\\")eth0(|\\\")" /etc/sysconfig/network-scripts/ifcfg-eth0', expect_ret=0, msg='check eth0 used')


    def test_check_nm_cloud_setup(self):
        '''
        rhbz: 1822853
        des: 
        <=8.4: check NetworkManager-cloud-setup is not installed
        >=8.5: check NetworkManager-cloud-setup is installed and nm-cloud-setup is enabled
        :avocado: tags=basic
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8.5'):
            cmd = "rpm -q NetworkManager-cloud-setup"
            utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Check if NetworkManager-cloud-setup is not installed')
        else:
            cmd = "rpm -q NetworkManager-cloud-setup"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check if NetworkManager-cloud-setup is installed')
            cmd = "sudo systemctl is-enabled nm-cloud-setup"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check if nm-cloud-setup is enabled')

            product_id = utils_lib.get_product_id(self)
            #COMPOSER-842
            file_check = '/usr/lib/systemd/system/nm-cloud-setup.service.d/10-rh-enable-for-azure.conf'
            expect_kw='Environment=NM_CLOUD_SETUP_AZURE=yes'
            cmd = "sudo cat {}".format(file_check)
            utils_lib.run_cmd(self, cmd, expect_kw=expect_kw, msg='Check if "{}" is set in {}'.format(expect_kw, file_check))

    def test_check_no_avc_denials(self):
        '''
        check there is no avc denials (selinux)
        :avocado: tags=basic
        '''
        cmd = "x=$(sudo ausearch -m avc 2>&1 &); echo $x"
        utils_lib.run_cmd(self, cmd, expect_kw='no matches', msg='check no avc denials')

    def test_check_numa(self):
        '''
        check if NUMA is enabled on supported machine
        :avocado: tags=basic
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
        :avocado: tags=basic
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
        :avocado: tags=basic
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8'):
            cmd = 'sudo rpm -q redhat-release-server'
        else:
            cmd = 'sudo rpm -q redhat-release'
        utils_lib.run_cmd(self,cmd, cancel_ret='0', msg='get redhat-release-server version')
        cmd = 'sudo rct cat-cert /etc/pki/product-default/*.pem'
        utils_lib.run_cmd(self,cmd, expect_ret=0, expect_kw="Version: {}".format(product_id), msg='check product certificate')

    def test_check_rhel_version(self):
        '''
        check if rhel provider matches /etc/redhat-release
        :avocado: tags=basic
        '''
        release_file = 'redhat-release'
        product_id = utils_lib.get_product_id(self)
        cmd = "echo $(sudo rpm -q --qf '%{VERSION}' --whatprovides " + release_file + ')'
        utils_lib.run_cmd(self,cmd, expect_kw=product_id, msg='check redhat-release version match')

    def test_check_rhui_pkg(self):
        """
        :avocado: tags=basic
        """
        self.log.info('RHEL image found')
        rhui_pkg = 'rhui-azure-rhel'
        unwanted_rhui = 'eus'
        cmd = 'sudo rpm -qa|grep rhui'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=rhui_pkg,expect_not_kw=unwanted_rhui,msg='get rhui pkg version')

    def test_check_root_is_locked(self):
        """
        Root account should be locked
        :avocado: tags=basic
        """
        self.log.info('RHEL AMI found')
        cmd = 'sudo passwd -S root | grep -q LK'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check root is locked')

    def test_check_shells(self):
        """
        Check for bash/nologin shells in /etc/shells
        :avocado: tags=basic
        """
        utils_lib.run_cmd(self, 'sudo cat /etc/shells', expect_kw='/bin/bash', msg='check /bin/bash in /etc/shells')

    def test_check_sshd(self):
        '''
        sshd service shoud be on, password authentication shoud be disabled
        :avocado: tags=basic
        '''
        is_systemd = utils_lib.run_cmd(self, 'rpm -q systemd > /dev/null && echo True || echo False')
        self.log.info("Is systemd system:{}".format(is_systemd))
        cmd = 'sudo cat /etc/ssh/sshd_config'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='PasswordAuthentication no', msg='check if password auth disabled')

    def test_check_sysconfig_kernel(self):
        '''
        des: UPDATEDEFAULT=yes and DEFAULTKERNEL=kernel should be set in /etc/sysconfig/kernel
        :avocado: tags=basic
        '''
        expect_kws = 'UPDATEDEFAULT=yes,DEFAULTKERNEL=kernel'
        cmd = "sudo cat /etc/sysconfig/kernel"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=expect_kws, msg='check /etc/sysconfig/kernel')

    def test_check_timezone(self):
        '''
        rhbz: 1187669
        check that the default timezone is set to UTC
        :avocado: tags=basic
        '''
        utils_lib.run_cmd(self, 'date', expect_kw='UTC', msg='check timezone is set to UTC')

    def test_check_username(self):
        """
        Check no old username in fresh image
        :avocado: tags=basic
        """
        for user in ['fedora', 'cloud-user']:
            cmd = 'sudo cat /etc/passwd|grep {}'.format(user)
            utils_lib.run_cmd(self, cmd, expect_not_ret='0', msg='check no {} user in fresh image'.format(user))

    def test_check_yum_dnf_plugins(self):
        '''
        bz: 1932802
        Verify yum/dnf plugin. For RHUI image, should be disabled. For SCA image, should be enabled
        product-id.conf should be enabled.
        :avocado: tags=basic
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
        # Yum plugin
        cmd = 'sudo cat /etc/yum/pluginconf.d/subscription-manager.conf|tr -d " "'
        utils_lib.run_cmd(self,cmd, expect_ret=0, expect_kw=expect_kw, msg='check yum subscription-manager plugin is {}'.format(status))
        # Dnf plugin
        cmd = 'sudo cat /etc/dnf/plugins/subscription-manager.conf|tr -d " "'
        utils_lib.run_cmd(self,cmd, expect_ret=0, expect_kw=expect_kw, msg='check dnf subscription-manager plugin is {}'.format(status))

    def test_check_auditd(self):
        """
        Check auditd:
        - service should be on
        - config files shoud have specified checksums
        :avocado: tags=basic
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
        :avocado: tags=basic
        """
        utils_lib.run_cmd(self, 'sudo cat /etc/init/ttyS0.conf', expect_not_ret=0, msg='make sure no /etc/init/ttyS0.conf found')
        utils_lib.run_cmd(self, 'sudo cat /etc/init/ttyS0.bak', msg='ttyS0.bak may also not in RHEL nowadays')

    # def test_check_rpm_V_unsatisfied_dependencies(self):
    #     '''
    #     check unsatisfied dependencies of pkg.
    #     :avocado: tags=basic
    #     '''
    #     utils_lib.run_cmd(self, "sudo rpm -Va", expect_not_kw='Unsatisfied', timeout=300, msg='check unsatisfied dependencies of pkg')

    def test_check_selinux(self):
        '''
        SELinux should be in enforcing/targeted mode
        :avocado: tags=basic
        '''
        out = utils_lib.run_cmd(self, 'uname -r', msg='get kernel version')
        utils_lib.run_cmd(self, 'sudo getenforce',expect_kw='Enforcing', msg='check selinux current mode is Enforcing')
        utils_lib.run_cmd(self, 'sudo cat /etc/sysconfig/selinux',expect_kw='SELINUX=enforcing,SELINUXTYPE=targeted', msg='check selinux current setting')

    def test_check_yum_repoinfo(self):
        '''
        :avocado: tags=basic
        '''
        cmd = "sudo rpm -qa|grep rhui"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='Check if it is a RHUI image')
        if ret != 0:
            self.skipTest("Skip in non-RHUI image")
        cmd = "sudo yum repoinfo"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Repo-pkgs          : 0', timeout=1200, msg='try to get repo info')

    def test_yum_package_install(self):
        '''
        :avocado: tags=basic
        '''
        cmd = "sudo rpm -qa|grep rhui"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='Check if it is a RHUI image')
        if ret != 0:
            self.skipTest("Skip in non-RHUI image")
        utils_lib.run_cmd(self, "sudo yum clean all", expect_ret=0, timeout=180)
        utils_lib.run_cmd(self, "sudo yum repolist", expect_ret=0, timeout=1200)
        utils_lib.run_cmd(self, "sudo yum check-update", timeout=1200)
        utils_lib.run_cmd(self, "sudo yum search zsh", expect_ret=0, timeout=180)
        utils_lib.run_cmd(self, "sudo yum -y install zsh", expect_ret=0, timeout=180)
        utils_lib.run_cmd(self, r"sudo rpm -q --queryformat '%{NAME}' zsh", expect_ret=0)
        utils_lib.run_cmd(self, "sudo rpm -e zsh", expect_ret=0)

#     def test_test_yum_group_install(self):
#         '''
#         :avocado: tags=basic
#         '''
#         cmd = "sudo yum -y groupinstall 'Development tools'"
#         utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1200, msg='try to install Development tools group')
#         utils_lib.run_cmd(self, 'sudo rpm -q glibc-devel', expect_ret=0, msg='try to check installed pkg')

    def test_subscription_manager_auto(self):
        '''
        bz: 1932802, 1905398
        Verify auto_registration is enabled 
        :avocado: tags=basic
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8.4'):
            self.skipTest('skip in earlier than el8.4')

        cmd = "sudo rpm -qa|grep rhui"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='Check if it is a RHUI image')
        if ret == 0:
            # RHUI image
            expect_kw="auto_registration = 0,manage_repos = 1"
        else:
            # SCA image
            expect_kw="auto_registration = 1,manage_repos = 1"
        cmd = "sudo cat /etc/rhsm/rhsm.conf"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=expect_kw, msg='try to check subscription-manager config')
        cmd = "sudo systemctl is-enabled rhsmcertd"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to check rhsmcertd enabled')

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
        services = '''firewalld,waagent,cloud-init-local,cloud-init,cloud-config,cloud-final,hypervkvpd,sshd,auditd'''
        service_list = services.split(',')
        for service in service_list:
            cmd = 'systemctl is-active {}'.format(service)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check {} is active'.format(service))

    # def test_grub_params(self):
    #     '''
    #     Verify /etc/default/grub params
    #     '''
    #     expect_kw="GRUB_TIMEOUT=10"
    #     file_check = '/etc/default/grub'
    #     utils_lib.run_cmd(self, "sudo cat {}".format(file_check), expect_ret=0, expect_kw=expect_kw, msg='check grub parameters in {}'.format(file_check))

    def tearDown(self):
        self.log.info("{} test done".format(self.id()))


if __name__ == '__main__':
    unittest.main()
