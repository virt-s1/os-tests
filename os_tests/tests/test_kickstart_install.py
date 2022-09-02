import unittest
import time
from os_tests.libs import utils_lib
from tipset.libs import rmt_ssh

class TestKickstartInstall(unittest.TestCase):
    '''
    Only run in server-client mode.
    '''
    def setUp(self):
        utils_lib.init_case(self)

    def test_kickstart_install_vm(self):
        """
        case_tag:
            KickstartInstall,KickstartInstall_tier1
        case_name:
            test_kickstart_install_vm
        case_file:
            os_tests.tests.test_kickstart_install.TestKickstartInstall.test_kickstart_install_vm
        component:
            KickstartInstall
        bugzilla_id:
            1898943
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Verify kickstart installation.
        key_steps: |
            Install vm by kickstart iso image.
        expect_result:
            VM works well after kickstart install.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        elif self.vm.provider != 'nutanix':
            self.log.info("self.vm.provider is " + self.vm.provider)
            self.skipTest("Skip this test case which is dedicate for Nutanix")
        if self.vm.exists():
            self.vm.delete(wait=True)
        self.vm.create_by_ISO_kickstart(wait=True)
        self.vm.start(wait=True)
        self.log.info("wait for kickstart automatic installation")
        time.sleep(300)
        for i in range(0,10):
            self.log.info("wait for more time in %s cycle(s)." % str(i))
            time.sleep(300)
            try:
                ssh = rmt_ssh.RemoteSSH()
                ssh.rmt_node = self.vm.floating_ip
                ssh.rmt_user = "root"
                ssh.rmt_password = self.vm.vm_password
                ssh.create_connection()
            except Exception as e:
                self.log.info("ssh failed, continue to wait VM installation \n %s." % e)
            if ssh.ssh_client is not None:
                self.log.info("ssh pass, VM installation finished.")
                break
        else:
            self.log.info("ssh_client is " + ssh.ssh_client)
            self.fail('failed ssh to vm installed by kickstart')
        test_login = utils_lib.send_ssh_cmd(self.vm.floating_ip, "root", self.vm.vm_password, "whoami")
        self.assertEqual("root",
                         test_login[1].strip(),
                         "Fail to login with password: %s" % format(test_login[1].strip()))

    def tearDown(self):
        if self.vm and self.vm.provider == 'nutanix':
            self.log.info("Enter tearDown procedure")
            self.vm.delete(wait=True)
            self.vm.create()

if __name__ == '__main__':
    unittest.main()
