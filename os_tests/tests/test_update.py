import unittest
import re
from os_tests.libs import utils_lib
import time
import os
import json
import tempfile
import string
import paramiko

class TestUpgrade(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='sudo dmesg -T')
        utils_lib.collect_basic_info(self)

    @property
    def rhel_x_version(self):
        product_id = utils_lib.get_product_id(self)
        return int(product_id.split('.')[0])

    def _confirm_answer_file(self):
        self.log.info("Find sections need to be confirmed in answer file")
        cmd = "sudo cat /var/log/leapp/answerfile"
        answer_file = utils_lib.run_cmd(self,
                                        cmd,
                                        expect_ret=0,
                                        msg='cat /var/log/leapp/answerfile')
        p = re.compile(r'[\[](.*?)[]]', re.S)
        confirm_sections = re.findall(p,answer_file)
        for confirm_section in confirm_sections:
            cmd = "sudo leapp answer --section %s.confirm=True" % confirm_section
            utils_lib.run_cmd(self,
                            cmd,
                            expect_ret=0,
                            msg='Provide answers to each question required by Leapp')

    def _config_PermitRootLogin(self):
        sshd_config = "/etc/ssh/sshd_config"
        cmd = "sudo cat %s" % sshd_config
        output = utils_lib.run_cmd(self,
                                cmd,
                                expect_ret=0,
                                msg="cat %s" % sshd_config)
        if utils_lib.is_aws(self):
            for line in output.splitlines():
                li = line.strip()
                match = re.match(r"PermitRootLogin", li)
                if match != None:
                    break
            if match == None:
                cmd = "echo 'PermitRootLogin no' >>  %s" % sshd_config
                utils_lib.run_cmd(self,
                                "sudo bash -c \"{}\"".format(cmd),
                                expect_ret=0,
                                msg='Configure PermitRootLogin')
        else:
            cmd = "echo 'PermitRootLogin yes' >> %s" % sshd_config
            utils_lib.run_cmd(self,
                            "sudo bash -c \"{}\"".format(cmd),
                            expect_ret=0,
                            msg='Edit %s to avoid inhibitor about remote login using root account' % sshd_config)
        cmd = "sudo systemctl restart sshd"
        utils_lib.run_cmd(self, 
                        cmd,
                        expect_ret=0,
                        msg='Restart sshd service to make the configuration take effect')
        
    def _remove_driver(self):
        output = utils_lib.run_cmd(self,
                                'sudo lsmod',
                                expect_ret=0,
                                msg="check loaded drivers")
        for line in output.splitlines():
            mod_list = line.split()[0]
            if mod_list in ('floppy','pata_acpi'):
                utils_lib.run_cmd(self,
                                "sudo rmmod '{}'".format(mod_list),
                                expect_ret=0, msg="Remove driver")
    def _remove_package(self):
        cmd = "sudo rpm -qa|grep kernel-devel"
        ret = utils_lib.run_cmd(self,
                                cmd,
                                ret_status=True,
                                msg='Check if there is kernel-devel package')
        if ret == 0:
            utils_lib.run_cmd(self,
                            "sudo bash -c 'yum remove `{}` -y'".format(cmd),
                            expect_ret=0,
                            msg='Remove kernel-devel package since DNF cannot produce a valid upgrade transaction when multiple kernel-devel packages are installed.')

    def _prepare_configure(self):
        if os.getenv('INFRA_PROVIDER') == 'gcp':
            cmd = "sudo sed -i 's/^AllowZoneDrifting=.*/AllowZoneDrifting=no/' /etc/firewalld/firewalld.conf"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Configure firewalld')

    def test_dnf_update(self):
        """
        case_name:
            test_yum_update
        case_tags:
            yum_update
        case_status:
            approved
        title:
            TestUpdate.test_yum_update
        importance:
            critical
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            n/a
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_update.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            system
        bug_id:
            n/a
        is_customer_case:
            False
        testplan:
            n/a
        test_type:
            functional
        test_level:
            Component
        maintainer:
            linl@redhat.com
        description: |
            Test the yum update for packages or between minor release.
        key_steps: |
            1. Start an instance on public cloud or start a RHEL system.
            2. On public cloud use the repo default set by RHUI client to do the update.
            3. You can also setup the internal repo or registerted rhsm to do the update.
            4. Use command "sudo yum update <package_name> -y" or "sudo yum update -y" to update the packages or system.
        expected_result: |
            Packages are updated or system is updated to the latest minor release.
        debug_want: |
            n/a
        """
        x_version = self.rhel_x_version

        #Prepare dnf_repo for internal update
        dnf_repo_url = self.params.get('dnf_repo_url')
        if dnf_repo_url:
            utils_lib.configure_repo(self, repo_type='dnf_repo', repo_url_param=dnf_repo_url)        
            #prepare dnf update
            cmd = "sudo yum remove -y $(rpm -qa|grep -v $(uname -r)|grep kernel-core|head -1)"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Remove kernel-core")
            utils_lib.run_cmd(self, 'sudo rm -rf /boot/initramfs*rescue*', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo yum remove -y kernel-debug', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo yum remove -y kernel-debug-core kernel-debug-modules', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo yum repolist enabled', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo bash -c "echo "" > /var/log/secure"', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo  rm -rf /var/log/cloud-init.log', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo  rm -rf /var/log/cloud-init-output.log', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo bash -c "echo "minrate=200" >> /etc/yum.conf"', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo bash -c "echo "timeout=1800" >> /etc/yum.conf"', expect_ret=0)

        #Prepare rhsm for rhsm update
        if self.params.get('subscription_username') and self.params.get('subscription_password'):
            utils_lib.rhsm_register(self, cancel_case=True)

        #run dnf update
        cmd = "sudo yum update -y"
        for i in range(1,10):
            ret_val = utils_lib.run_cmd(self,
                                      cmd,
                                      ret_status=True,
                                      timeout=600,
                                      msg='Update system to the latest version for upgrade testing')
            if ret_val > 0:
                self.log.info("Failed to update system, try again! max:20 now:%s" % i)
                ret_val = utils_lib.run_cmd(self,
                                          cmd,
                                          ret_status=True,
                                          timeout=600,
                                          msg='Update system to the latest version for upgrade testing')
                time.sleep(5)
            if ret_val > 0:
                continue
            break
        #save dnf logs
        file_dir = '/var/log/'
        file_names = ['dnf.librepo.log', 'dnf.log', 'dnf.rpm.log']
        for file_name in file_names:
            utils_lib.save_file(self, file_dir=file_dir, file_name=file_name)
        cmd = "sudo grep -e 'error' -e 'fail' /var/log/dnf*"
        utils_lib.run_cmd(self, cmd, msg='Check if there are fail/error in dnf logs')
        if ret_val != 0:
            self.FailTest('DNF update failed')
        else:
            utils_lib.run_cmd(self,
                            "sudo reboot",
                            msg='Reboot system to the latest kernel')
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            utils_lib.collect_basic_info(self)

    def test_leapp_upgrade_rhui(self):
        """
        case_name:
            TestUpgrade.test_leapp_upgrade_rhui
        case_tags:
            upgrade_rhui
        case_status:
            approved
        title:
            TestUpgrade.test_leapp_upgrade_rhui
        importance:
            high
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            n/a
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_update.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            2106904
        is_customer_case:
            True
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            linl@redhat.com
        description:
            Test leapp upgrade via RHUI.
        key_steps: |
            1. Start an instance on public cloud (e.g., AWS) with rhui client installed and enabled.
            2. Upgrade according to docs,
               https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/upgrading_from_rhel_7_to_rhel_8/
               Or https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9
            3. Update current to system the latest version and reboot: $ sudo yum update -y; $sudo reboot.
            4. Install leapp related packages,
               For RHEL7.9 system, need to enable rhui-client-config and extra repos to install leapp related packages,
                   $ sudo yum-config-manager --enable rhui-client-config-server-7
                   $ sudo yum-config-manager --enable rhel-7-server-rhui-extras-rpms
               $ sudo yum install -y leapp-rhui-aws
            5. Prepare for upgrade,
               Configure PermitRootLogin if it's not configured,
               $ sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
               $ sudo systemctl restart sshd
               Configure the auto_registration,
               $ sudo subscription-manager config --rhsmcertd.auto_registration=1 --rhsm.manage_repos=0 --rhsmcertd.auto_registration_interval=1
               $ sudo systemctl restart rhsmcertd
               Make sure system is in Content Access Mode display to get the leapp data file via below command.
               $ sudo subscription-manager status
            6. Do preupgrade and review preupgrade report via command "$ sudo leapp preupgrade --debug --no-rhsm"
               Provide answers for each section in answer file if preupgrade fails,
               $ sudo leapp answer --section <question_section>.confirm=True"
            7. Do upgrade via command "sudo leapp upgrade --debug --no-rhsm".
            8. Reboot system after upgrade.
        expected_result: |
            System boot successfully to the next RHEL major version according to supported upgrade path after upgrade. 
            No issues with the upgraded system.
        debug_want:
            n/a
        """
        #Please run test_dnf_update case to update the system to the latest before this case.
        x_version = self.rhel_x_version
        cmd = "sudo rpm -qa|grep 'rhui\|client-rhel'"
        ret = utils_lib.run_cmd(self, 
                              cmd,
                              ret_status=True,
                              msg='Check if there is rhui client in system')
        if ret != 0:
            self.skipTest('Skip test since there is no rhui client')
        #Install leapp packages:
        if os.getenv('INFRA_PROVIDER') == 'ali':
            platform = "alibaba"
        else:
            platform = os.getenv('INFRA_PROVIDER')
        if x_version == 7:
            cmd = "sudo yum-config-manager --enable rhui-client-config-server-7"
            utils_lib.run_cmd(self,
                            cmd,
                            expect_ret=0,
                            msg='Enable repos for leapp-rhui-{} package installation'.format(platform))
            cmd = "sudo yum-config-manager --enable rhel-7-server-rhui-extras-rpms"
            utils_lib.run_cmd(self,
                            cmd,
                            expect_ret=0,
                            msg='Enable repos for leapp packages installation')
        utils_lib.is_pkg_installed(self, pkg_name='leapp-rhui-{}'.format(platform), is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='leapp', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='leapp-upgrade', is_install=True, cancel_case=True)
        #Prepare for upgrade
        self._remove_driver()
        self._config_PermitRootLogin()
        self._remove_package()
        self._prepare_configure()
        #Do preupgrade
        target_version = self.params.get('target_version')
        if target_version:
            cmd_preupgrade = "sudo LEAPP_UNSUPPORTED=1 LEAPP_DEVEL_TARGET_RELEASE=%s leapp preupgrade --debug --no-rhsm" % (target_version)
            cmd_upgrade = "sudo LEAPP_UNSUPPORTED=1 LEAPP_DEVEL_TARGET_RELEASE=%s leapp upgrade --debug --no-rhsm" % (target_version)
        else:
            cmd_preupgrade = "sudo leapp preupgrade --debug --no-rhsm"
            cmd_upgrade = "sudo leapp upgrade --debug --no-rhsm"
        ret = utils_lib.run_cmd(self,
                              cmd_preupgrade,
                              ret_status=True,
                              timeout=3600,
                              msg='Preupgrade test for leapp upgrade')
        if ret != 0:
            self._confirm_answer_file()
            utils_lib.run_cmd(self,
                            "sudo cat /var/log/leapp/leapp-report.txt",
                            expect_ret=0, 
                            msg='Check leapp report')
            ret = utils_lib.run_cmd(self, 
                                  cmd_preupgrade, 
                                  ret_status=True, 
                                  timeout=3600, 
                                  msg='Retry preupgrade')
        #save preupgrade log
        file_dir = '/var/log/leapp/'
        file_names = ['leapp-preupgrade.log', 'leapp-report.txt']
        if ret != 0:
            for file_name in file_names:
                utils_lib.save_file(self, file_dir=file_dir, file_name=file_name)
            self.FailTest('Leapp preupgrade via RHUI on {} failed'.format(platform))
        else:
            ret = utils_lib.run_cmd(self,
                                  cmd_upgrade,
                                  ret_status=True,
                                  expect_ret=0, 
                                  timeout=3600,
                                  msg='Do leapp upgrade via RHUI')
            #save leapp upgrade logs
            file_names = ['leapp-upgrade.log', 'leapp-report.txt']
            for file_name in file_names:
                utils_lib.save_file(self, file_dir=file_dir, file_name=file_name)
            if ret !=0:
                self.FailTest('Leapp upgrade via RHUI on {} failed'.format(platform))
            else:
                utils_lib.run_cmd(self,
                                "sudo reboot",
                                msg='Reboot system after leapp upgrade')
                utils_lib.run_cmd(self, 'ls /boot/grub2', msg='Check grub2 configure files')
                time.sleep(600)
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
                utils_lib.collect_basic_info(self)
                #Perform post-upgrade tasks
                utils_lib.run_cmd(self,
                                "sudo rhui-set-release --unset",
                                expect_ret=0,
                                msg='use rhui to use the latest RHEL content')
                cmd = "sudo yum config-manager --save --setopt exclude=''"
                utils_lib.run_cmd(self,
                                cmd,
                                expect_ret=0,
                                msg='remove all packages from the exclude list')
                #Check if upgraded to correct version
                x_version_upgrade = self.rhel_x_version
                if x_version_upgrade != x_version + 1:
                    self.FailTest('Leapp upgrade failed since did not upgrade to target release')
    
    def test_leapp_upgrade_customrepo(self):
        """
        case_name:
            test_leapp_upgrade_customrepo
        case_tags:
            upgrade_customrepo
        case_status:
            approved
        title:
            TestUpgrade.test_leapp_upgrade_customrepo
        importance:
            high
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            polarion_"["os-tests"]"TestUpgrade.test_leapp_upgrade_customrepo
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_update.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            n/a
        is_customer_case:
            False
        testplan:
            n/a
        test_type:
            functional
        test_level:
            component
        maintainer:
            linl@redhat.com
        description:
            Test leapp upgrade via customrepo.
        key_steps: |
            1. Start a system, upgrade according to docs, 
               https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/upgrading_from_rhel_7_to_rhel_8/
               Or https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9
            2. Configure internal repo (copy rhel-internal.repo) to /etc/yum.repos.d/ for update.
            3. Update current to the latest minor release and reboot: $ sudo yum update -y; $sudo reboot.
            4. Install leapp utility,
               For RHEL7.9 system, need to enable extra repos to install leapp related packages,
                   $ sudo yum-config-manager --enable rhel-7-server-extras-rpms
               $ sudo yum install -y leapp-upgrade
            5. Prepare for upgrade,
               Configure PermitRootLogin if it's not configured,
               $ sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
               $ sudo systemctl restart sshd
               Download or copy leapp data and leapp_upgrade_repositories.repo (repo of target os) to /etc/leapp/files.
               Remove rhui client if there is installed.
            6. Do preupgrade and review preupgrade report via command "$ sudo leapp preupgrade --debug --no-rhsm"
               Provide answers for each section in answer file if preupgrade fails:
               $ sudo leapp answer --section <question_section>.confirm=True"
            7. Do upgrade via command "sudo leapp upgrade --debug --no-rhsm".
            8. Reboot system after upgrade.
        expected_result: |
            System boot successfully to the next RHEL major version according to supported upgrade path after upgrade. 
            No issues with the upgraded system.

        """
        #Please run test_dnf_update case to update the system to the latest before this case.
        x_version = self.rhel_x_version
        if os.getenv('INFRA_PROVIDER') in ['azure','google','aws','ali']:
            cmd = "sudo rpm -qa|grep rhui"
            ret = utils_lib.run_cmd(self,
                                  cmd,
                                  ret_status=True,
                                  msg='Check if there is rhui client in system')
            if ret == 0:
                utils_lib.run_cmd(self,
                                "sudo bash -c 'yum remove `{}` -y'".format(cmd),
                                expect_ret=0,
                                msg='Remove rhui client for upgrading via custom repo')
        #Install leapp packages
        utils_lib.is_pkg_installed(self, pkg_name='leapp', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='leapp-upgrade', is_install=True, cancel_case=True)
        #Prepare for leapp upgrade
        self._remove_driver()
        self._config_PermitRootLogin()
        self._remove_package()
        self._prepare_configure()
        leapp_target_repo_url = self.params.get('leapp_target_repo_url')
        if leapp_target_repo_url:
            utils_lib.configure_repo(self, repo_type='leapp_target_repo', repo_url_param=leapp_target_repo_url)
        #Peform leapp preupgrade via custom repo
        target_version = self.params.get('target_version')
        if target_version:
            cmd_preupgrade = "sudo leapp preupgrade --debug --no-rhsm --target %s" % (target_version)
            cmd_upgrade = "sudo leapp upgrade --debug --no-rhsm --target %s" % (target_version)
        else:
            cmd_preupgrade = "sudo leapp preupgrade --debug --no-rhsm"
            cmd_upgrade = "sudo leapp upgrade --debug --no-rhsm"
        ret = utils_lib.run_cmd(self,
                              cmd_preupgrade,
                              ret_status=True,
                              timeout=3600,
                              msg='Preupgrade test for leapp upgrade')
        if ret != 0:
            self._confirm_answer_file()
            utils_lib.run_cmd(self,
                            "sudo cat /var/log/leapp/leapp-report.txt",
                            expect_ret=0,
                            msg='Check leapp report')
            ret = utils_lib.run_cmd(self,
                                  cmd_preupgrade,
                                  ret_status=True,
                                  timeout=3600,
                                  msg='Retry preupgrade')
        #save preupgrade log
        file_dir = '/var/log/leapp/'
        file_names = ['leapp-preupgrade.log', 'leapp-report.txt']
        if ret !=0:
            for file_name in file_names:
                utils_lib.save_file(self, file_dir=file_dir, file_name=file_name)
            self.FailTest('Leapp upgrade via customrepo failed')
        else:        
            #Peform leapp upgrade via custom repo
            for i in range(1,10):
                ret_val = utils_lib.run_cmd(self,
                                          cmd_upgrade,
                                          ret_status=True,
                                          timeout=3000,
                                          msg='Do leapp upgrade via custom repo')
                if ret_val > 0:
                    self.log.info("Failed to upgrade system, try again! max:20 now:%s" % i)
                    ret_val = utils_lib.run_cmd(self,
                                              cmd_upgrade,
                                              ret_status=True,
                                              timeout=3000,
                                              msg='Retry leapp upgrade via custom repo')
                    time.sleep(5)
                if ret_val > 0:
                    continue
                break
            file_names = ['leapp-upgrade.log', 'leapp-report.txt']
            for file_name in file_names:
                utils_lib.save_file(self, file_dir=file_dir, file_name=file_name)
            if ret_val !=0:
                self.FailTest('Leapp upgrade via customrepo failed')
            else:
                utils_lib.run_cmd(self,
                                "sudo reboot",
                                msg='Reboot system after leapp upgrade')
                time.sleep(600)
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
                utils_lib.collect_basic_info(self)
                #Check if upgraded to correct version
                x_version_upgrade = self.rhel_x_version
                if x_version_upgrade != x_version + 1:
                    self.FailTest('Leapp upgrade failed since did not upgrade to target release')
                else:
                    #Perform post-upgrade tasks
                    cmd = "sudo yum config-manager --save --setopt exclude=''"
                    utils_lib.run_cmd(self,
                                    cmd,
                                    expect_ret=0,
                                    msg='Remove all packages from the exclude list')
                    utils_lib.run_cmd(self,
                                    "sudo bash -c 'rpm -e `rpm -qa | grep el{}`'".format(x_version),
                                    expect_ret=0,
                                    msg='Remove packages before upgraded including kernel and leapp packages')
                    utils_lib.run_cmd(self,
                                    "sudo cp /tmp/leapp_upgrade_repositories.repo /etc/yum.repos.d/",
                                    expect_ret=0,
                                    msg='Prepare rhel internal repo for leapp upgraded system')

    def test_leapp_upgrade_rhsm(self):
        """
        case_name:
            TestUpgrade.test_leapp_upgrade_rhsm
        case_tags:
            upgrade_rhsm
        case_status:
            Approved
        title:
            TestUpgrade.test_leapp_upgrade_rhsm 
        importance:
            High
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            n/a
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_update.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            n/a
        is_customer_case:
            True
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            linl@redhat.com
        description:
            Test leapp upgrade via RHSM.
        key_steps: |
            1. Start an instance on public cloud (e.g., AWS) with rhui client installed and enabled.
            2. Upgrade according to docs,
               https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/upgrading_from_rhel_7_to_rhel_8/
               Or https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9
            3. Update current to system the latest version and reboot: $ sudo yum update -y; $sudo reboot.
            4. Install leapp related packages,
               For RHEL7.9 system, need to enable rhui-client-config and extra repos to install leapp related packages,
                   $ sudo yum-config-manager --enable rhui-client-config-server-7
                   $ sudo yum-config-manager --enable rhel-7-server-rhui-extras-rpms
               $ sudo yum install -y leapp-rhui-aws
            5. Prepare for upgrade,
               Configure PermitRootLogin if it's not configured,
               $ sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
               $ sudo systemctl restart sshd
               Configure the auto_registration,
               $ sudo subscription-manager config --rhsmcertd.auto_registration=1 --rhsm.manage_repos=0 --rhsmcertd.auto_registration_interval=1
               $ sudo systemctl restart rhsmcertd
               Make sure system is in Content Access Mode display to get the leapp data file via below command.
               $ sudo subscription-manager status
            6. Do preupgrade and review preupgrade report via command "$ sudo leapp preupgrade --debug --no-rhsm"
               Provide answers for each section in answer file if preupgrade fails,
               $ sudo leapp answer --section <question_section>.confirm=True"
            7. Do upgrade via command "sudo leapp upgrade --debug --no-rhsm".
            8. Reboot system after upgrade.
        expected_result: |
            System boot successfully to the next RHEL major version according to supported upgrade path after upgrade. 
            No issues with the upgraded system.
        debug_want:
            n/a
        """
        #Please run test_dnf_update case to update the system to the latest before this case.
        x_version = self.rhel_x_version
        #Register to RHSM
        utils_lib.rhsm_register(self, cancel_case=True)
        #Install leapp packages
        if x_version == 7:
            cmd1 = "sudo subscription-manager repos --enable rhel-7-server-rpms"
            cmd2 = "sudo subscription-manager repos --enable rhel-7-server-extras-rpms"
            for cmd in [cmd1, cmd2]:
                utils_lib.run_cmd(self,
                                cmd,
                                expect_ret=0,
                                msg='Enable repos for leapp packages installation in rhel7')
        utils_lib.is_pkg_installed(self, pkg_name='leapp', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='leapp-upgrade', is_install=True, cancel_case=True)
        #Prepare for upgrade
        self._remove_driver()
        self._config_PermitRootLogin()
        self._remove_package()
        self._prepare_configure()
        #Enable yum plugins
        cmd = "sed -i 's/^plugins=0/plugins=1/' '/etc/yum.conf'; sed -i 's/^enabled.*/enabled=1/' '/etc/yum/pluginconf.d/subscription-manager.conf'; sed -i 's/^enabled=0/enabled=1/' '/etc/yum/pluginconf.d/product-id.conf'"
        utils_lib.run_cmd(self,
                        "sudo bash -c \"{}\"".format(cmd),
                        expect_ret=0,
                        msg='Enable yum plugins')
        #Do preupgrade via RHSM
        if target_version:
            cmd_preupgrade = "sudo leapp preupgrade --debug --target %s" % (target_version)
            cmd_upgrade = "sudo leapp upgrade --debug --target %s" % (target_version)
        else:
            cmd_preupgrade = "sudo leapp preupgrade --debug"
            cmd_upgrade = "sudo leapp upgrade --debug"        
        ret = utils_lib.run_cmd(self,
                              cmd_preupgrade,
                              ret_status=True, 
                              timeout=3600,
                              msg='Preupgrade test for leapp upgrade')
        if ret != 0:
            self._confirm_answer_file()
            utils_lib.run_cmd(self,
                            "sudo cat /var/log/leapp/leapp-report.txt",
                            expect_ret=0, 
                            msg='Check leapp report')
            ret = utils_lib.run_cmd(self, 
                                  cmd_preupgrade,
                                  ret_status=True, 
                                  timeout=3600, 
                                  msg='Retry preupgrade')
        #save preupgrade log
        file_dir = '/var/log/leapp/'
        file_names = ['leapp-preupgrade.log', 'leapp-report.txt']
        if ret !=0:
            for file_name in file_names:
                utils_lib.save_file(self, file_dir=file_dir, file_name=file_name)
            self.FailTest('Leapp upgrade via RHSM failed')
        else:        
            #Peform leapp upgrade via RHSM
            for i in range(1,10):
                ret_val = utils_lib.run_cmd(self,
                                          cmd_upgrade,
                                          ret_status=True,
                                          timeout=3000,
                                          msg='Do leapp upgrade via RHSM')
                if ret_val > 0:
                    self.log.info("Failed to upgrade system, try again! max:20 now:%s" % i)
                    ret_val = utils_lib.run_cmd(self,
                                              cmd_upgrade,
                                              ret_status=True,
                                              timeout=3000,
                                              msg='Retry leapp upgrade via RHSM')
                    time.sleep(5)
                if ret_val > 0:
                    continue
                break
            file_names = ['leapp-upgrade.log', 'leapp-report.txt']
            for file_name in file_names:
                utils_lib.save_file(self, file_dir=file_dir, file_name=file_name)
            if ret_val !=0:
                self.FailTest('Leapp upgrade via RHSM failed')
            else:
                utils_lib.run_cmd(self,
                                "sudo reboot",
                                msg='Reboot system after leapp upgrade')
                time.sleep(600)
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
                utils_lib.collect_basic_info(self)
                #Check if upgraded to correct version
                x_version_upgrade = self.rhel_x_version
                if x_version_upgrade != x_version + 1:
                    self.FailTest('Leapp upgrade failed since did not upgrade to target release')
                else:
                    #Perform post-upgrade tasks
                    cmd = "sudo yum config-manager --save --setopt exclude=''"
                    utils_lib.run_cmd(self,
                                    cmd,
                                    expect_ret=0,
                                    msg='Remove all packages from the exclude list')
                    utils_lib.run_cmd(self,
                                    "sudo bash -c 'rpm -e `rpm -qa | grep el{}`'".format(x_version),
                                    expect_ret=0,
                                    msg='Remove packages before upgraded including kernel and leapp packages')

    def test_pkg_install(self):
        """
        case_name:
            TestUpgrade.test_pkg_install
        case_tags:
            pkg_install
        case_status:
            Approved
        title:
            TestUpgrade.test_pkg_install 
        importance:
            High
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            n/a
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_update.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            n/a
        is_customer_case:
            True
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            linl@redhat.com
        description:
            Install test packages with by system repo, specified pkg repo or pkg url.
        key_steps: |
            1. Specified packages name and version via --pkgs, and packages repo via --pkg_rpeo_url if needed and run the test to isntall packages.
        expected_result: |
            Packages are installed.
        debug_want:
            n/a
        """
        pkg_repo_url = self.params.get('pkg_repo_url')
        if pkg_repo_url:
            utils_lib.configure_repo(self, repo_type='pkg_repo', repo_url_param=pkg_repo_url)
        if self.params.get('pkgs'):
            pkgs = self.params.get('pkgs')
            self.log.info("print pkgs %s" % (pkgs))
            pkgs_list = [pkg.strip() for pkg in pkgs.split(',')]
            self.log.info("print pkgs %s" % (pkgs))
            pkg_url = self.params.get('pkg_url')
            found_kernel_rt = any("kernel-rt" in pkg for pkg in pkgs_list)
            if found_kernel_rt:
                utils_lib.rhsm_register(self, cancel_case=True)
                cmd = "sudo subscription-manager repos --enable *-rt-rpms"
                utils_lib.run_cmd(self, cmd, msg='Enable rt repos')
            for pkg in pkgs_list:
                if not pkg_url:
                    utils_lib.run_cmd(self,
                                    "sudo yum list %s --showduplicates" % (pkg),
                                    expect_ret=0,
                                    msg='Check available pkg versions')
                utils_lib.is_pkg_installed(self, pkg_name=pkg)
            found_kernel = any("kernel" in pkg for pkg in pkgs_list)
            if found_kernel:
                utils_lib.run_cmd(self,
                                "sudo reboot",
                                msg='Reboot system to the latest kernel')
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
                utils_lib.run_cmd(self,
                                "sudo uname -r",
                                expect_ret=0,
                                msg='Check current kernel version')
        pkg_repo = '/etc/yum.repos.d/pkg.repo'
        utils_lib.run_cmd(self, "sudo rm -rf {}".format(pkg_repo), msg='delete pkg_repo')

    def tearDown(self):
        utils_lib.finish_case(self)
        pass

if __name__ == '__main__':
    unittest.main()
