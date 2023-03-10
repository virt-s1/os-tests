import unittest
import re
from os_tests.libs import utils_lib
import time
import os
import json

class TestUpgrade(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        if not utils_lib.is_aws(self):
            self.skipTest('Only run for upgrade tests for RHEL on aws.')
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')

    @property
    def rhel_x_version(self):
        product_id = utils_lib.get_product_id(self)
        return int(product_id.split('.')[0])

    def _confirm_answer_file(self):
        self.log.info("Find sections need to be confirmed in answer file")
        cmd = "sudo cat /var/log/leapp/answerfile"
        answer_file = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='cat /var/log/leapp/answerfile')
        p = re.compile(r'[[](.*?)[]]', re.S)
        confirm_sections = re.findall(p,answer_file)
        for confirm_section in confirm_sections:
            cmd = "sudo leapp answer --section %s.confirm=True" % confirm_section
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Provide answers to each question required by Leapp')

    def _config_PermitRootLogin(self):
        sshd_config = "/etc/ssh/sshd_config"
        cmd = "sudo cat %s" % sshd_config
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="cat %s" % sshd_config)
        for line in output.splitlines():
            li = line.strip()
            match = re.match(r"PermitRootLogin", li)
            if match != None:
                break
        if match == None:
            if utils_lib.is_aws(self):
                cmd = "echo 'PermitRootLogin no' >>  %s" % sshd_config
            else:
                cmd = "echo 'PermitRootLogin yes' >> %s" % sshd_config
            utils_lib.run_cmd(self, "sudo bash -c \"{}\"".format(cmd), expect_ret=0, msg='Configure PermitRootLogin')
        cmd = "sudo systemctl restart sshd"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Restart sshd service to make the configuration take effect')
        
    def _remove_driver(self):
        output = utils_lib.run_cmd(self, 'sudo lsmod', expect_ret=0, msg="check loaded drivers")
        for line in output.splitlines():
            mod_list = line.split()[0]
            if mod_list in ('floppy','pata_acpi'):
                utils_lib.run_cmd(self, "sudo rmmod '{}'".format(mod_list), expect_ret=0, msg="Remove driver")

    def test_leapp_upgrade_rhui(self):
        """
        case_name:
            [os-tests]TestUpgrade.test_leapp_upgrade_rhui
        case_tags:
            upgrade_rhui
        case_status:
            Approved
        title:
            [os-tests]TestUpgrade.test_leapp_upgrade_rhui        
        importance:
            High
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            Automated
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
            Functional
        test_level:
            Component
        maintainer:
            linl@redhat.com
        description:
            Test leapp upgrade via RHUI.
        key_steps:
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
        expected_result:
            System boot successfully to the next RHEL major version according to supported upgrade path after upgrade. No issues with the upgraded system.
        debug_want:
            n/a
        """
        utils_lib.run_cmd(self, "sudo uname -r", expect_ret=0, msg='Check current kernel version')
        utils_lib.run_cmd(self, "sudo cat /etc/redhat-release", expect_ret=0, msg='check current rhel release')
        product_id_preupgrade = utils_lib.get_product_id(self)
        x_version = self.rhel_x_version
        cmd = "sudo rpm -qa|grep rhui"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='Check if there is rhui client in system')
        if ret != 0:
            self.skipTest('Skip test since there is no rhui client')
        utils_lib.run_cmd(self, "sudo yum update -y", expect_ret=0, timeout=600, msg='Update system to the latest version for upgrade testing')
        utils_lib.run_cmd(self, "sudo reboot", msg='Reboot system to the latest kernel')
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, "sudo uname -r", expect_ret=0, msg='Check kernel version after updated')
        utils_lib.run_cmd(self, "sudo cat /etc/redhat-release", expect_ret=0, msg='check rhel release after updated')
        #Install leapp packages:
        platform = os.getenv('INFRA_PROVIDER')
        if x_version == 7:
            cmd = "sudo yum-config-manager --enable rhui-client-config-server-7"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Enable repos for leapp-rhui-{} package installation'.format(platform))
            cmd = "sudo yum-config-manager --enable rhel-7-server-rhui-extras-rpms"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Enable repos for leapp packages installation')
        cmd = "sudo yum install -y leapp-rhui-{}".format(platform)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Install leapp-rhui-{} packages for upgrade testing'.format(platform))
        #Prepare for upgrade
        self._remove_driver()
        cmd = "sudo subscription-manager config --rhsmcertd.auto_registration=1 --rhsm.manage_repos=0 --rhsmcertd.auto_registration_interval=1"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Configure auto registration to get leapp utility metadata')
        utils_lib.run_cmd(self, "sudo systemctl restart rhsmcertd", expect_ret=0, msg='Restart rhsmcertd service')
        time.sleep(300)
        utils_lib.run_cmd(self, "sudo subscription-manager status", expect_kw='Content Access Mode', msg='Check auto registration is enabled')
        self._config_PermitRootLogin()
        #Do preupgrade
        ret = utils_lib.run_cmd(self, "sudo leapp preupgrade --debug --no-rhsm", ret_status=True, timeout=600, msg='Preupgrade test for leapp upgrade')
        if ret != 0:
            self._confirm_answer_file()
            utils_lib.run_cmd(self, "sudo cat /var/log/leapp/leapp-report.txt", expect_ret=0, msg='Check leapp report')
            utils_lib.run_cmd(self, "sudo leapp preupgrade --debug --no-rhsm", expect_ret=0, timeout=600, msg='Retry preupgrade')
        utils_lib.run_cmd(self, "sudo leapp upgrade --debug --no-rhsm", expect_ret=0, timeout=600, msg='Do leapp upgrade via RHUI')
        utils_lib.run_cmd(self, "sudo reboot", msg='Reboot system after leapp upgrade')
        time.sleep(600)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, "sudo uname -r", expect_ret=0, msg='Check kernel version after leapp upgrade')
        utils_lib.run_cmd(self, "sudo cat /etc/redhat-release", expect_ret=0, msg='check rhel release after leapp upgrade')
        product_id_preupgrade = utils_lib.get_product_id(self)
        x_version_upgrade = self.rhel_x_version
        if x_version_upgrade != x_version + 1:
            self.FailTest('Leapp upgrade failed since did not upgrade to target release')

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
