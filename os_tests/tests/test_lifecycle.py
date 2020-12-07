import unittest
import time
from os_tests.libs import utils_lib

class TestLifeCycle(unittest.TestCase):
    '''
    Only run remotely.
    '''
    def setUp(self):
        utils_lib.init_case(self)

    def test_boot_fipsenabled(self):
        '''
        :avocado: tags=test_boot_fipsenabled
        polarion_id:
        bz#: 1787270
        '''
        if self.params['remote_node'] == 'None' or len(self.params['remote_node']) < 5:
            self.skipTest("Only support to run remotely!")

        self.log.info("Check system can boot with fips=1")
        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if 'el7' in output:
            utils_lib.run_cmd(self,
                       'sudo dracut -v -f',
                        msg='regenerate the initramfs!',
                        timeout=600)
            cmd = 'sudo grubby --update-kernel=ALL --args="fips=1"'
            utils_lib.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=800)
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="fips=1"'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')
        else:
            cmd = 'sudo fips-mode-setup --enable'
            utils_lib.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
            time.sleep(10)
            utils_lib.init_connection(self, timeout=800)
            utils_lib.run_cmd(self,
                        'sudo fips-mode-setup --check',
                        expect_kw='enabled')
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo fips-mode-setup --disable'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=800)


if __name__ == '__main__':
    unittest.main()