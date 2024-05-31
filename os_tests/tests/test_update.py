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

    def _configure_repo(self, repo_type, repo_url_param):
        repo_urls = self.params.get(repo_url_param)
        if repo_urls is not None:
            if self.params.get('proxy_url') is not None:
                repo_temp = string.Template('''
[repo$id]
name=repo$id
baseurl=$repo_url
enabled=1
gpgcheck=0
proxy=http://127.0.0.1:8080
            ''')
            else:
                repo_temp = string.Template('''
[repo$id]
name=repo$id
baseurl=$repo_url
enabled=1
gpgcheck=0
            ''')
            fh, tmp_repo_file = tempfile.mkstemp(suffix='_rhel.repo',  dir='/tmp', text=False)
            id = 0
            with open(tmp_repo_file, 'a') as fh:
                for repo_url in self.params.get(repo_url_param).split(','):
                    repo_str = repo_temp.substitute(id=id, repo_url=repo_url)
                    self.log.info("Add new repo %s to %s" % (repo_url, tmp_repo_file))
                    fh.writelines(repo_str)
                    id += 1      
            
            self.log.info("Updated %s" % tmp_repo_file)
            with open(tmp_repo_file, 'r') as fh:
                for line in fh.readlines():
                    self.log.info(line)
            repo_file_name = "/tmp/{}.repo".format(repo_type)
            self.SSH.put_file(local_file=tmp_repo_file, rmt_file=repo_file_name)
            if repo_type == 'dnf_repo':
                dest_dir = "/etc/yum.repos.d/"
            if repo_type == 'leapp_target_repo':
                dest_dir = "/etc/leapp/"
            dest_repo_path = dest_dir + "{}.repo".format(repo_type)
            utils_lib.run_cmd(self, 
                        "sudo cp -r %s %s" % (repo_file_name,dest_repo_path),
                        expect_ret=0,
                        msg='Prepare %s' % (repo_type))
            utils_lib.run_cmd(self, 'ls -l %s' % (dest_repo_path), expect_ret=0)
            utils_lib.run_cmd(self, 'cat %s' % (dest_repo_path), expect_ret=0)
            if os.path.exists(repo_file_name):
               os.unlink(repo_file_name)
               self.log.info("delete tempfile %s", tmp_dnf_repo_file)

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
        utils_lib.run_cmd(self,
                        "sudo uname -r",
                        expect_ret=0,
                        msg='Check current kernel version')
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check current rhel release')
        x_version = self.rhel_x_version

        #Prepare dnf_repo for internal update
        if self.params.get('dnf_repo_url') is not None:
            self._configure_repo('dnf_repo', 'dnf_repo_url')
            #prepare dnf update
            cmd = "sudo yum remove -y $(rpm -qa|grep -v $(uname -r)|grep kernel-core|head -1)"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Remove kernel-core")
            utils_lib.run_cmd(self, 'sudo rm -rf /boot/initramfs*rescue*', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo yum remove -y kernel-debug', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo yum remove -y kernel-debug-core kernel-debug-modules', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo yum repolist enabled', expect_ret=0)
            utils_lib.run_cmd(self, 'sudo yum-config-manager --disable rh*', expect_ret=0)
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
        utils_lib.run_cmd(self,
                        "sudo yum update -y",
                        expect_ret=0,
                        timeout=600,
                        msg='Update system to the latest version for upgrade testing')
        utils_lib.run_cmd(self,
                        "sudo reboot",
                        msg='Reboot system to the latest kernel')
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self,
                        "sudo uname -r",
                        expect_ret=0,
                        msg='Check kernel version after updated')
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check rhel release after updated')


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
        utils_lib.run_cmd(self,
                        "sudo uname -r",
                        expect_ret=0,
                        msg='Check current kernel version')
        utils_lib.run_cmd(self, 
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check current rhel release')
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
        cmd = "sudo yum install -y leapp-rhui-{}".format(platform)
        utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Install leapp-rhui-{} packages for upgrade testing'.format(platform))
        utils_lib.run_cmd(self, 
                        "sudo yum install -y leapp leapp-upgrade",
                        expect_ret=0,
                        msg='Install leapp packages for upgrade testing')
        #Prepare for upgrade
        self._remove_driver()
        #Remove the following steps since leapp data files are now a part of the leapp-repository package, don't need to manually download these files.
        #cmd = "sudo subscription-manager config --rhsmcertd.auto_registration=1 --rhsm.manage_repos=0 --rhsmcertd.auto_registration_interval=1"
        #utils_lib.run_cmd(self,
        #                cmd,
        #                expect_ret=0,
        #                msg='Configure auto registration to get leapp utility metadata')
        #utils_lib.run_cmd(self,
        #                "sudo systemctl restart rhsmcertd",
        #                expect_ret=0, msg='Restart rhsmcertd service')
        #time.sleep(300)
        #utils_lib.run_cmd(self,
        #                "sudo subscription-manager status",
        #                expect_kw='Content Access Mode',
        #                msg='Check auto registration is enabled')
        self._config_PermitRootLogin()
        self._remove_package()
        #Do preupgrade
        ret = utils_lib.run_cmd(self,
                                "sudo leapp preupgrade --debug --no-rhsm",
                                ret_status=True, timeout=1200,
                                msg='Preupgrade test for leapp upgrade')
        if ret != 0:
            self._confirm_answer_file()
            utils_lib.run_cmd(self,
                            "sudo cat /var/log/leapp/leapp-report.txt",
                            expect_ret=0, msg='Check leapp report')
            utils_lib.run_cmd(self, "sudo leapp preupgrade --debug --no-rhsm",
            expect_ret=0, timeout=1200, msg='Retry preupgrade')
        utils_lib.run_cmd(self,
                        "sudo leapp upgrade --debug --no-rhsm",
                        expect_ret=0, timeout=1200,
                        msg='Do leapp upgrade via RHUI')
        utils_lib.run_cmd(self,
                        "sudo reboot",
                        msg='Reboot system after leapp upgrade')
        time.sleep(600)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self,
                        "sudo uname -r",
                        expect_ret=0,
                        msg='Check kernel version after leapp upgrade')
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check rhel release after leapp upgrade')
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
        kernel_version = utils_lib.run_cmd(self,
                                         "sudo uname -r",
                                         expect_ret=0,
                                         msg='Check current kernel version')             
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check current rhel release')
        x_version = self.rhel_x_version
        #Setup internal repo for update
        rhel_repo = "rhel-internal.repo"
        src_dir = self.data_dir + "/leapp-repo-rhel%s/" % x_version
        src_path = src_dir + rhel_repo
        tmp_path = "/tmp/" + rhel_repo
        dest_path_repo = "/etc/yum.repos.d/" + rhel_repo
        self.SSH.put_file(local_file=src_path, rmt_file=tmp_path)
        utils_lib.run_cmd(self, 
                        "sudo cp %s %s" % (tmp_path,dest_path_repo),
                        expect_ret=0,
                        msg='Prepare internal repo')
        utils_lib.run_cmd(self,
                        "sudo ls /etc/yum.repos.d/",
                        expect_ret=0,
                        msg='check repo file')
        if os.getenv('INFRA_PROVIDER') in ['azure','google','aws','ali']:
            cmd = "sudo sed -i '/gpgcheck=0/a\proxy=http://127.0.0.1:8080/' {}".format(dest_path_repo)
            utils_lib.run_cmd(self,
                            cmd,
                            expect_ret=0,
                            msg='Add proxy for public clouds')
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
        utils_lib.run_cmd(self,
                        'sudo cat {}'.format(dest_path_repo),
                        expect_ret=0,
                        msg='Check internal repo info')
        for i in range(1,10):
            ret_val = utils_lib.run_cmd(self,
                                      "sudo yum update -y",
                                      ret_status=True,
                                      timeout=600,
                                      msg='Update system to the latest version for upgrade testing')
            if ret_val > 0:
                self.log.info("Failed to update system, try again! max:20 now:%s" % i)
                ret_val = utils_lib.run_cmd(self,
                                          "sudo yum update -y --allowerasing",
                                          ret_status=True,
                                          timeout=600,
                                          msg='Update system to the latest version for upgrade testing')
                time.sleep(5)
            if ret_val > 0:
                continue
            break
        utils_lib.run_cmd(self,
                        "sudo reboot",
                        msg='Reboot system to the latest kernel')
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        kernel_version_updated = utils_lib.run_cmd(self,
                                                 "sudo uname -r",
                                                 expect_ret=0,
                                                 msg='Check kernel version after updated')
        if utils_lib.is_aws(self):
            if kernel_version != kernel_version_updated:
                cmd = "sudo yum -y remove --oldinstallonly --setopt installonl_limit=1 kernel"       
                utils_lib.run_cmd(self,
                                cmd,
                                expect_ret=0,
                                msg='Remove old kernel packages to avoid no space for boot partition')
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release", 
                        expect_ret=0, 
                        msg='check rhel release after updated')
        #Install leapp packages
        utils_lib.run_cmd(self, 
                        "sudo yum install -y leapp leapp-upgrade",
                        timeout=600,
                        expect_ret=0,
                        msg='Install leapp packages for upgrade testing')
        #Prepare for leapp upgrade
        self._remove_driver()
        self._config_PermitRootLogin()
        leapp_target_repo = "leapp_upgrade_repositories.repo"
        src_path = src_dir + leapp_target_repo
        tmp_path_leapp = '/tmp/' + leapp_target_repo
        dest_dir_leapp = '/etc/leapp/files/'
        dest_path_leapp = dest_dir_leapp + leapp_target_repo
        self.SSH.put_file(local_file=src_path, rmt_file=tmp_path_leapp)
        if os.getenv('INFRA_PROVIDER') in ['azure','google','aws','ali']:
            cmd = "sudo sed -i '/gpgcheck=0/a\proxy=http://127.0.0.1:8080/' {}".format(tmp_path_leapp)
            utils_lib.run_cmd(self,
                            cmd,
                            expect_ret=0,
                            msg='Add proxy for public clouds')
        utils_lib.run_cmd(self,
                        "sudo cp %s %s" % (tmp_path_leapp,dest_path_leapp),
                        expect_ret=0,
                        msg='Prepare leapp target repo')            
        utils_lib.run_cmd(self, 
                        'sudo cat {}'.format(dest_path_leapp),
                        expect_ret=0,
                        msg='Check target repo info')
#Don't need to provide leapp data
#        src_dir = self.data_dir + '/leapp-data/'
#        if os.path.isdir(src_dir):
#            for f in os.listdir(src_dir):
#                src_path = src_dir + f
#                tmp_path = '/tmp/' + f
#                dest_path = dest_dir + f
#                self.SSH.put_file(local_file=src_path, rmt_file=tmp_path)
#                utils_lib.run_cmd(self, 
#                                "sudo cp %s %s" % (tmp_path,dest_path), 
#                                expect_ret=0, 
#                                msg='Prepare leapp data')
        #Peform leapp preupgrade via custom repo
        ret = utils_lib.run_cmd(self,
                                "sudo leapp preupgrade --debug --no-rhsm",
                                ret_status=True,
                                timeout=3000,
                                msg='Preupgrade test for leapp upgrade')
        if ret != 0:
            self._confirm_answer_file()
            utils_lib.run_cmd(self,
                            "sudo cat /var/log/leapp/leapp-report.txt",
                            expect_ret=0,
                            msg='Check leapp report')
            ret1 = utils_lib.run_cmd(self,
                                   "sudo leapp preupgrade --debug --no-rhsm",
                                   expect_ret=0,
                                   timeout=3000,
                                   msg='Retry preupgrade')
            if ret1 !=0:
                self._confirm_answer_file()
                utils_lib.run_cmd(self,
                                "sudo leapp preupgrade --debug --no-rhsm",
                                expect_ret=0,
                                timeout=3000,
                                msg='Retry preupgrade again')
        #Peform leapp upgrade via custom repo
        for i in range(1,10):
            ret_val = utils_lib.run_cmd(self,
                                      "sudo leapp upgrade --debug --no-rhsm",
                                      ret_status=True,
                                      timeout=3000,
                                      msg='Do leapp upgrade via custom repo')
            if ret_val > 0:
                self.log.info("Failed to upgrade system, try again! max:20 now:%s" % i)
                ret_val = utils_lib.run_cmd(self,
                                          "sudo leapp upgrade --debug --no-rhsm",
                                          ret_status=True,
                                          timeout=3000,
                                          msg='Retry leapp upgrade via custom repo')
                time.sleep(5)
            if ret_val > 0:
                continue
            break
        utils_lib.run_cmd(self,
                        "sudo reboot",
                        msg='Reboot system after leapp upgrade')
        time.sleep(600)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self,
                        "sudo uname -r",
                        expect_ret=0,
                        msg='Check kernel version after leapp upgrade')
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check rhel release after leapp upgrade')
        #Check if upgraded to correct version
        x_version_upgrade = self.rhel_x_version
        if x_version_upgrade != x_version + 1:
            self.FailTest('Leapp upgrade failed since did not upgrade to target release')
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
                        "sudo cp %s /etc/yum.repos.d/" % (tmp_path_leapp),
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
        utils_lib.run_cmd(self,
                        "sudo uname -r",
                        expect_ret=0,
                        msg='Check current kernel version')
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check current rhel release')
        x_version = self.rhel_x_version
        #Register to RHSM
        utils_lib.rhsm_register(self, cancel_case=True)
        #Update
        utils_lib.run_cmd(self,
                        "sudo yum update -y",
                        expect_ret=0, timeout=600,
                        msg='Update system to the latest version for upgrade testing')
        utils_lib.run_cmd(self,
                        "sudo reboot",
                        msg='Reboot system to the latest kernel')
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self,
                        "sudo uname -r",
                        expect_ret=0,
                        msg='Check kernel version after updated')
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check rhel release after updated')
        #Install leapp packages
        if x_version == 7:
            cmd1 = "sudo subscription-manager repos --enable rhel-7-server-rpms"
            cmd2 = "sudo subscription-manager repos --enable rhel-7-server-extras-rpms"
            for cmd in [cmd1, cmd2]:
                utils_lib.run_cmd(self,
                                cmd,
                                expect_ret=0,
                                msg='Enable repos for leapp packages installation in rhel7')
        cmd = "sudo yum install -y leapp-upgrade"
        utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Install leapp packages for upgrade testing')
        #Prepare for upgrade
        self._remove_driver()
        self._config_PermitRootLogin()
        self._remove_package()
        #Enable yum plugins
        cmd = "sed -i 's/^plugins=0/plugins=1/' '/etc/yum.conf'; sed -i 's/^enabled.*/enabled=1/' '/etc/yum/pluginconf.d/subscription-manager.conf'; sed -i 's/^enabled=0/enabled=1/' '/etc/yum/pluginconf.d/product-id.conf'"
        utils_lib.run_cmd(self,
                        "sudo bash -c \"{}\"".format(cmd),
                        expect_ret=0,
                        msg='Enable yum plugins')
        #Do preupgrade
        ret = utils_lib.run_cmd(self,
                                "sudo leapp preupgrade --debug",
                                ret_status=True, timeout=1800,
                                msg='Preupgrade test for leapp upgrade')
        if ret != 0:
            self._confirm_answer_file()
            utils_lib.run_cmd(self,
                            "sudo cat /var/log/leapp/leapp-report.txt",
                            expect_ret=0, msg='Check leapp report')
            utils_lib.run_cmd(self, "sudo leapp preupgrade --debug",
            expect_ret=0, timeout=1800, msg='Retry preupgrade')
        utils_lib.run_cmd(self,
                        "sudo leapp upgrade --debug",
                        expect_ret=0, timeout=7200,
                        msg='Do leapp upgrade via rhsm')
        utils_lib.run_cmd(self,
                        "sudo reboot",
                        msg='Reboot system after leapp upgrade')
        time.sleep(600)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self,
                        "sudo uname -r",
                        expect_ret=0,
                        msg='Check kernel version after leapp upgrade')
        utils_lib.run_cmd(self,
                        "sudo cat /etc/redhat-release",
                        expect_ret=0,
                        msg='check rhel release after leapp upgrade')
        cmd = "sudo yum config-manager --save --setopt exclude=''"
        utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='remove all packages from the exclude list')
        #Check if upgraded to correct version
        x_version_upgrade = self.rhel_x_version
        if x_version_upgrade != x_version + 1:
            self.FailTest('Leapp upgrade failed since did not upgrade to target release')

    def tearDown(self):
        utils_lib.finish_case(self)
        pass

if __name__ == '__main__':
    unittest.main()
