import unittest
from os_tests.libs import utils_lib
import time

class TestLTP(unittest.TestCase):

    def _ltp_run(self, case_name=None, file_name=None):
        '''
        Run specify ltp test case.
        Arguments:
            test_instance {avocado Test instance} -- avocado test instance
        '''
        utils_lib.run_cmd(self, 'sudo rm -rf /opt/ltp/results/*')
        if file_name is not None and case_name is not None:
            ltp_cmd = 'sudo /opt/ltp/runltp -f %s -s %s > /tmp/ltplog 2>&1' % (
                file_name, case_name)
        elif file_name is None and case_name is not None:
            ltp_cmd = 'sudo /opt/ltp/runltp -s %s > /tmp/ltplog 2>&1' % case_name
        elif file_name is not None and case_name is None:
            ltp_cmd = 'sudo /opt/ltp/runltp -f %s > /tmp/ltplog 2>&1' % file_name
        self.log.info("LTP cmd: %s" % ltp_cmd)
        utils_lib.run_cmd(self, '\n')
        utils_lib.run_cmd(self, ltp_cmd, timeout=600)
        time.sleep(5)
        utils_lib.run_cmd(self, 'sudo cat /tmp/ltplog')
        utils_lib.run_cmd(self,
                    'sudo cat /opt/ltp/results/*',
                    expect_kw='Total Failures: 0')

    def setUp(self):
        utils_lib.init_case(self)
        if utils_lib.is_arch(self, arch='aarch64'):
            ltp_url = self.params.get('ltp_url_aarch64')
        else:
            ltp_url = self.params.get('ltp_url_x86_64')
        utils_lib.pkg_install(self, pkg_name='ltp', pkg_url=ltp_url)
        self.cursor = utils_lib.get_cmd_cursor(self, cmd='journalctl --since today', rmt_redirect_stdout=True)

    def test_ltp_add_key02(self):
        '''
        case_name:
            test_ltp_add_key02

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
            Ran ltp syscalls add_key02.

        key_steps:
            1. Install ltp pkg
            2. # /opt/ltp/runltp -f syscalls -s add_key02

        expected_result:
            No panic or hang happen.

        '''
        self._ltp_run(case_name="add_key02")

    def test_ltp_cpuhotplug(self):
        '''
        bz: 1464095,1908550
        polarion_id: RHEL7-98752
        '''
        # ltp will considering fail if more than 1 cpus cannot be offline
        # in bare metal instance
        # but in large metal instances, it is expected. So do not do it in
        # bare metal instances
        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="Xen",
                    msg="Not run in xen instance as bug 1641510 which is very low priority")
        if utils_lib.is_aws(self) and utils_lib.is_metal(self):
            self.skipTest('Cancel test as aws bare metal needs 1+ cpus working \
at least which ltp not handle')
        else:
            self._ltp_run(case_name="cpuhotplug")

    def test_ltp_hugemmap(self):
        '''
        polarion_id: RHEL7-88729
        bz: 1312331
        '''
        utils_lib.get_memsize(self)
        if utils_lib.is_arch(self, arch='aarch64') and utils_lib.get_memsize(self) < 100:
            #Hugepagesize is big in aarch64, so not run all hugetlb case in low memory arm system
            self._ltp_run(case_name="hugemmap01", file_name="hugetlb")
        elif utils_lib.get_memsize(self) < 4:
            self._ltp_run(case_name="hugemmap01", file_name="hugetlb")
        else:
            self._ltp_run(file_name="hugetlb")

    def test_ltp_ipsec_icmp(self):
        '''
        polarion_id: RHEL7-98754
        bz: 1473593
        '''
        self._ltp_run(case_name="icmp4-uni-vti11",
                      file_name='net_stress.ipsec_icmp')
        if 'builtin' not in utils_lib.run_cmd(self, 'modinfo ccm'):
            self.log.info("Try to remove ccm module after test.")
            utils_lib.run_cmd(self, 'sudo modprobe -r ccm', expect_ret=0)

    def test_ltp_quickhit(self):
        '''
        case_name:
            test_ltp_quickhit

        case_priority:
            1

        component:
            kernel

        bugzilla_id:
            n/a

        polarion_id:
            n/a

        maintainer:
            xiliang@redhat.com

        description:
            Ran ltp quickhit senario to test kernel quickly.

        key_steps:
            1. Install ltp pkg
            2. # /opt/ltp/runltp -f quickhit

        expected_result:
            No panic or hang or other exception happen.
        '''
        self._ltp_run(file_name="quickhit")

    def tearDown(self):
        utils_lib.check_log(self, "error,warn,fail,trace", cursor=self.cursor, rmt_redirect_stdout=True)

if __name__ == '__main__':
    unittest.main()