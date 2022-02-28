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

        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        elif self.vm.provider != 'nutanix':
            self.log.info("self.vm.provider is" + self.vm.provider)
            self.skipTest("Skip this test case which is dedicate for Nutanix")

        if self.vm.exists():
            self.vm.delete(wait=True)
        self.vm.create_by_ISO_kickstart(wait=True)
        self.vm.start(wait=True)
        self.log.info("wait for kickstart automatic installation")
        time.sleep(3600)

        ssh = rmt_ssh.RemoteSSH()
        ssh.rmt_node = self.vm.floating_ip
        ssh.rmt_user = "root"
        ssh.rmt_password = self.vm.vm_password
        ssh.create_connection()
        if ssh.ssh_client is None:
            self.log.info("ssh_client is " + str(ssh.ssh_client))
            self.fail('failed ssh to vm installed by kickstart')

    def tearDown(self):
        self.log.info("Enter tearDown procedure")
        self.vm.delete(wait=True)

if __name__ == '__main__':
    unittest.main()