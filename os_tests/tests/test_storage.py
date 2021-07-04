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
        test_dev = self.params.get('blk_devs')
        if test_dev is None:
            self.skipTest("blk_devs not found in configure file")
        cmd = "echo 'TEST_DEVS=({})' > /usr/local/blktests/config".format(test_dev)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "cd /usr/local/blktests/; sudo ./check {}".format(case_name)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw="failed", timeout=2400)

    def setUp(self):
        utils_lib.init_case(self)
        utils_dir = os.path.realpath(os_tests.__file__)
        utils_dir = os.path.dirname(utils_dir) + '/utils'
        if utils_lib.is_arch(self, arch='aarch64'):
            blktests_rpm = utils_dir + '/blktests-master.aarch64.rpm'
            blktests_rpm_tmp = '/tmp/ltp-master.aarch64.rpm'
        else:
            blktests_rpm = utils_dir + '/blktests-master.x86_64.rpm'
            blktests_rpm_tmp = '/tmp/blktests-master.x86_64.rpm'
        if not utils_lib.is_pkg_installed(self, pkg_name='ltp',is_install=False):
            if self.params['remote_node'] is not None:
                self.log.info('Copy {} to remote'.format(blktests_rpm))
                self.SSH.put_file(local_file=blktests_rpm, rmt_file=blktests_rpm_tmp)
                blktests_rpm = blktests_rpm_tmp
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

    def tearDown(self):
        if 'blktests' in self.id():
            utils_lib.check_log(self, "trace", cursor=self.cursor)
        else:
            utils_lib.check_log(self, "error,warn,fail,trace", cursor=self.cursor)

if __name__ == '__main__':
    unittest.main()