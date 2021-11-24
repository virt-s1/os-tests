import unittest
from os_tests.libs import utils_lib
import time
import os
import os_tests

class TestStorage(unittest.TestCase):

    def _blktests_run(self, case_name=None):
        '''
        Run specify blktests test case.
        Arguments:
            test_instance {avocado Test instance} -- avocado test instance
        '''
        cmd = "echo 'TEST_DEVS=({})' > /usr/local/blktests/config".format(self.test_dev)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "cd /usr/local/blktests/; sudo ./check {}".format(case_name)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw="failed", timeout=2400)

    def setUp(self):
        utils_lib.init_case(self)
        self.test_dev = self.params.get('blk_devs')
        if self.test_dev is None:
            self.skipTest("blk_devs not found in configure file or command line options")
        utils_dir = os.path.realpath(os_tests.__file__)
        utils_dir = os.path.dirname(utils_dir) + '/utils'
        if utils_lib.is_arch(self, arch='aarch64'):
            blktests_rpm = utils_dir + '/blktests-master.aarch64.rpm'
            blktests_rpm_tmp = '/tmp/ltp-master.aarch64.rpm'
        else:
            blktests_rpm = utils_dir + '/blktests-master.x86_64.rpm'
            blktests_rpm_tmp = '/tmp/blktests-master.x86_64.rpm'
        if not utils_lib.is_pkg_installed(self, pkg_name='ltp',is_install=False) and 'blktests' in self.id():
            if self.params['remote_node'] is not None:
                self.log.info('Copy {} to remote'.format(blktests_rpm))
                self.SSH.put_file(local_file=blktests_rpm, rmt_file=blktests_rpm_tmp)
                blktests_rpm = blktests_rpm_tmp
        if 'blktests' in self.id():
            utils_lib.pkg_install(self, pkg_name='blktests', pkg_url=blktests_rpm)
        self.cursor = utils_lib.get_cmd_cursor(self, cmd='journalctl --since today')

    def test_storage_blktests_block(self):
        '''
        case_name:
            test_storage_blktests_block
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1464851
        polarion_id:
            RHEL7-98753
        maintainer:
            xiliang@redhat.com
        description:
            Run blktests block.
        key_steps:
            1. Install blktests
            2. # cd /usr/local/blktests/
            3. # ./check block
        expected_result:
            No failure case found

        '''
        self._blktests_run(case_name="block")

    def test_storage_blktests_nvme(self):
        '''
        case_name:
            test_storage_blktests_nvme
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1464851
        polarion_id:
            RHEL7-98753
        maintainer:
            xiliang@redhat.com
        description:
            Run blktests nvme.
        key_steps:
            1. Install blktests
            2. # cd /usr/local/blktests/
            3. # ./check nvme
        expected_result:
            No failure case found
        '''
        self._blktests_run(case_name="nvme")

    def test_storage_parted_s(self):
        """
        case_name:
            test_storage_parted_s
        case_file:
            os_tests.tests.test_storage.TestStorage.test_storage_parted_s
        component:
            kernel
        bugzilla_id:
            2024355
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Test creation of a large number of partitions on a gpt disk using 'parted -s'.
        key_steps:
            # parted -s $blockdev mklabel gpt mkpart primary 1Mib 6Mib mkpart primary 6Mib 11Mib mkpart primary 11Mib 16Mib mkpart primary 16Mib 21Mib mkpart primary 21Mib 26Mib mkpart primary 26Mib 31Mib mkpart primary 31Mib 36Mib mkpart primary 36Mib 41Mib mkpart primary 41Mib 46Mib mkpart primary 46Mib 51Mib mkpart primary 51Mib 56Mib mkpart primary 56Mib 61Mib mkpart primary 61Mib 66Mib mkpart primary 66Mib 71Mib mkpart primary 71Mib 76Mib mkpart primary 76Mib 81Mib mkpart primary 81Mib 86Mib mkpart primary 86Mib 91Mib mkpart primary 91Mib 96Mib mkpart primary 96Mib 101Mib
        expect_result:
            No error threw and create all partitions.
        debug_want:
            - output from dmesg or journal
            - test debug log
        """
        cmd = 'sudo wipefs -a {}'.format(self.test_dev)
        utils_lib.run_cmd(self, cmd, msg="try to wipe all fs from {}".format(self.test_dev))
        cmd = "sudo parted -s {} mklabel gpt mkpart primary 1Mib 6Mib mkpart primary 6Mib 11Mib mkpart primary 11Mib 16Mib mkpart primary 16Mib 21Mib mkpart primary 21Mib 26Mib mkpart primary 26Mib 31Mib mkpart primary 31Mib 36Mib mkpart primary 36Mib 41Mib mkpart primary 41Mib 46Mib mkpart primary 46Mib 51Mib mkpart primary 51Mib 56Mib mkpart primary 56Mib 61Mib mkpart primary 61Mib 66Mib mkpart primary 66Mib 71Mib mkpart primary 71Mib 76Mib mkpart primary 76Mib 81Mib mkpart primary 81Mib 86Mib mkpart primary 86Mib 91Mib mkpart primary 91Mib 96Mib mkpart primary 96Mib 101Mib".format(self.test_dev)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='create 20 partitions on {}'.format(self.test_dev))
        cmd = "sudo parted -s {} print free".format(self.test_dev)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='106MB', msg="check partitions created")

    def tearDown(self):
        if 'blktests' in self.id():
            utils_lib.check_log(self, "trace", cursor=self.cursor)
        else:
            utils_lib.check_log(self, "error,warn,fail,trace", cursor=self.cursor)

if __name__ == '__main__':
    unittest.main()