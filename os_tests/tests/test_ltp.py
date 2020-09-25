import unittest
from os_tests.libs import utils_lib

class TestLTP(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        utils_lib.ltp_install(self)
        self.cursor = utils_lib.get_cmd_cursor(self, cmd='journalctl --since today')

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
        utils_lib.ltp_run(self, case_name="add_key02")

    def test_ltp_cpuhotplug(self):
        '''
        polarion_id: RHEL7-98752
        BZ#: 1464095
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
            utils_lib.ltp_run(self, case_name="cpuhotplug")

    def test_ltp_hugemmap(self):
        '''
        polarion_id: RHEL7-88729
        BZ#: 1312331
        '''
        utils_lib.get_memsize(self)
        if utils_lib.is_aarch64(self) and utils_lib.get_memsize(self) < 16:
            #Hugepagesize is big in aarch64, so not run all hugetlb case in low memory arm system
            utils_lib.ltp_run(self, case_name="hugemmap01", file_name="hugetlb")
        elif utils_lib.get_memsize(self) < 4:
            utils_lib.ltp_run(self, case_name="hugemmap01", file_name="hugetlb")
        else:
            utils_lib.ltp_run(self, file_name="hugetlb")

    def test_ltp_ipsec_icmp(self):
        '''
        polarion_id: RHEL7-98754
        BZ#: 1473593
        '''
        utils_lib.ltp_run(self, case_name="icmp4-uni-vti11",
                      file_name='net_stress.ipsec_icmp')
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
        utils_lib.ltp_run(self,file_name="quickhit")

    def tearDown(self):
        utils_lib.check_log(self, "error,warn,fail,trace", cursor=self.cursor)

if __name__ == '__main__':
    unittest.main()