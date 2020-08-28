import unittest
from os_tests.libs import utils_lib

class TestCloudInit(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

    def test_check_cloudinit_service_status(self):
        '''
        polarion_id:
        bz#: 1829713
        The 4 cloud-init services status should be "active"
        '''
        cmd = "sudo systemctl is-enabled cloud-init-local"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "check cloud-init-local is enabled")
        service_list = ['cloud-init-local',
                        'cloud-init',
                        'cloud-config',
                        'cloud-final']
        for service in service_list:
            cmd = "sudo systemctl status %s" % service
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='Active: active', msg = "check %s status" % service)
            cmd = "sudo systemctl is-active %s" % service
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='active', msg = "check %s status" % service)
        

if __name__ == '__main__':
    unittest.main()