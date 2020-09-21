import unittest
from os_tests.libs import utils_lib

class TestNetworkTest(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')

    def test_mtu_min_max_set(self):
        '''
        polarion_id: RHEL-111097
        BZ#: 1502554
        ena mtu range: 128~9216
        ixgbevf mtu range: 68~9710
        vif mtu range: 68~65535
        vmxnet3 mtu range: 60~9000
        '''
        cmd = "sudo ip link show|grep mtu|grep -v lo|awk -F':' '{print $2}'"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        nic = "eth0"
        self.log.info("Test which nic connecting to public, if no found, use {} by default".format(nic))
        for net in output.split('\n'):
            cmd = "ping {} -c 2 -I {}".format(self.params.get('ping_server'), net)
            ret = utils_lib.run_cmd(self, cmd, ret_status=True)
            if ret == 0:
                nic = net
                break

        cmd = "sudo ethtool -i {}".format(nic)
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if 'ena' in output:
            self.log.info('ena found!')
            mtu_range = [0, 127, 128, 4500, 9216, 9217]
            mtu_min = 128
            mtu_max = 9216
        elif 'ixgbe' in output:
            self.log.info('ixgbevf found!')
            mtu_range = [0, 67, 68, 4500, 9710, 9711]
            mtu_min = 68
            mtu_max = 9710
        elif 'vif' in output:
            self.log.info('vif found!')
            mtu_range = [0, 67, 68, 4500, 65535, 65536]
            mtu_min = 68
            mtu_max = 65535
        elif 'vmxnet3' in output:
            self.log.info('vmxnet3 found!')
            mtu_range = [0, 59, 60, 4500, 9000, 9001]
            mtu_min = 60
            mtu_max = 9000
        else:
            self.log.info('Did not detect network type, use default min~max mtu. %s' % output)
            mtu_range = [0, 67, 68, 4500, 65535, 65536]
            mtu_min = 68
            mtu_max = 65535

        self.log.info("Trying to change mtu to %s" % mtu_range)
        for mtu_size in mtu_range:
            mtu_cmd = "sudo ip link set dev %s mtu %s" % (nic, mtu_size)
            mtu_check = "sudo ip link show dev {}".format(nic)
            if mtu_size <= mtu_max and mtu_size >= mtu_min:
                utils_lib.run_cmd(self, mtu_cmd, expect_ret=0)
                utils_lib.run_cmd(self, mtu_check, expect_ret=0, expect_kw="mtu {}".format(mtu_size))
            elif mtu_size < mtu_min or mtu_size > mtu_max:
                utils_lib.run_cmd(self, mtu_cmd, expect_not_ret=0)
                utils_lib.run_cmd(self, mtu_check, expect_ret=0, expect_not_kw="mtu {}".format(mtu_size))
        #utils_lib.run_cmd(self, "dmesg|tail -30")
        utils_lib.check_log(self, 'fail', log_cmd='dmesg -T', cursor=self.dmesg_cursor)
        utils_lib.check_log(self, 'error', log_cmd='dmesg -T', cursor=self.dmesg_cursor)
        utils_lib.check_log(self, 'warn', log_cmd='dmesg -T', cursor=self.dmesg_cursor)

if __name__ == '__main__':
    unittest.main()