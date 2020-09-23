import re
import unittest
from os_tests.libs import utils_lib

class TestNetworkTest(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')
        cmd = "sudo ip link show|grep mtu|grep -v lo|awk -F':' '{print $2}'"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        self.nic = "eth0"
        self.log.info("Test which nic connecting to public, if no found, use {} by default".format(self.nic))
        for net in output.split('\n'):
            cmd = "ping {} -c 2 -I {}".format(self.params.get('ping_server'), net)
            ret = utils_lib.run_cmd(self, cmd, ret_status=True)
            if ret == 0:
                self.nic = net
                break

    def test_ethtool_G(self):
        '''
        case_name:
            test_ethtool_G

        case_priority:
            1

        component:
            kernel

        bugzilla_id:
            1722628

        polarion_id:
            n/a

        maintainer:
            xiliang@redhat.com

        description:
            Use ethtool to change the rx/tx ring parameters of the specified network device.

        key_steps:
            1. # ethtool -g $nic
            2. # ethtool -G $nic rx $num
            3. # ethtool -G $nic rx-mini $num
            4. # ethtool -G $nic rx-jumbo $num
            5. # ethtool -G $nic tx $num

        expected_result:
            Can change the supported rx/tx ring parameters of the specified network device.
            Cannot set the ring parameters to -1.
            eg. # ethtool -G eth0 rx 512
                # ethtool -g eth0
                Ring parameters for eth0:
                Pre-set maximums:
                RX:		2048
                RX Mini:	0
                RX Jumbo:	0
                TX:		1024
                Current hardware settings:
                RX:		512
                RX Mini:	0
                RX Jumbo:	0
                TX:		1024
                # ethtool -G eth0 rx -1
                no ring parameters changed, aborting

        '''
        self.log.info("Test change rx/tx ring setting.")
        query_cmd = "ethtool -g {}".format(self.nic)
        output = utils_lib.run_cmd(self, query_cmd, cancel_not_kw='Operation not supported', msg='Query Operation not supported')

        max_rx, max_rx_mini, max_rx_jumbo, max_tx = None, None, None, None
        for i in output.split('\n'):
            if "RX:" in i:
                max_rx = i.split('\t')[-1]
            if "RX Mini:" in i:
                max_rx_mini = i.split('\t')[-1]
            if "RX Jumbo:" in i:
                max_rx_jumbo = i.split('\t')[-1]
            if "TX:" in i:
                max_tx = i.split('\t')[-1]
            if max_tx is not None:
                break
        self.log.info("Got max_rx:{} max_rx_mini:{} max_rx_jumbo:{} max_tx:{}".format(max_rx, max_rx_mini, max_rx_jumbo, max_tx))
        if max_rx is not None and 'n/a' not in max_rx and int(max_rx) > 0:
            if int(max_rx) >= 1024:
                rx = 512
            elif int(max_rx) <= 256:
                rx = 128
            else:
                rx = 256
            cmd = "sudo ethtool -G {} rx {}".format(self.nic, rx)
            output = utils_lib.run_cmd(self, cmd, msg="Set rx")
            if "not supported" not in output:
                utils_lib.run_cmd(self, query_cmd, expect_kw="RX:\t\t{}".format(rx), msg="Check rx")
                #cmd = "sudo ethtool -G {} rx 0".format(self.nic)
                #utils_lib.run_cmd(self, cmd, expect_kw="Invalid argument", msg="Check rx cannot set to 0")
                cmd = "sudo ethtool -G {} rx -1".format(self.nic)
                utils_lib.run_cmd(self, cmd, expect_kw="aborting", msg="Check rx cannot set to -1")
        if max_rx_mini is not None and 'n/a' not in max_rx_mini and int(max_rx_mini) > 0:
            if int(max_rx_mini) >= 1024:
                rx_mini = 512
            elif int(max_rx_mini) <= 256:
                rx_mini = 128
            else:
                rx_mini = 256
            cmd = "sudo ethtool -G {} rx-mini {}".format(self.nic, rx_mini )
            output = utils_lib.run_cmd(self, cmd, msg="Set rx-mini")
            if "not supported" not in output:
                out = utils_lib.run_cmd(self, query_cmd, expect_kw="RX Mini:\t{}".format(rx_mini), msg="Check rx-mini")
                if "RX Mini:\t0" not in out:
                    cmd = "sudo ethtool -G {} rx-mini 0".format(self.nic)
                    utils_lib.run_cmd(self, cmd)
                    utils_lib.run_cmd(self, query_cmd, expect_kw="RX Mini:\t0", msg="Check rx-mini canset to 0")
                cmd = "sudo ethtool -G {} rx-mini -1".format(self.nic)
                utils_lib.run_cmd(self, cmd, expect_kw="aborting", msg="Check rx cannot rx-mini to -1")
        if max_rx_jumbo is not None and 'n/a' not in max_rx_jumbo and int(max_rx_jumbo) > 0:
            if int(max_rx_jumbo) >= 1024:
                rx_jumbo = 512
            elif int(max_rx_jumbo) <= 256:
                rx_jumbo = 128
            else:
                rx_jumbo = 256
            cmd = "sudo ethtool -G {} rx-jumbo {}".format(self.nic, rx_jumbo)
            output = utils_lib.run_cmd(self, cmd, msg="Set rx_jumbo")
            if "not supported" not in output:
                out = utils_lib.run_cmd(self, query_cmd, expect_kw="RX Jumbo:\t{}".format(rx_jumbo), msg="Check rx_jumbo")
                if "RX Jumbo:\t0" not in out:
                    cmd = "sudo ethtool -G {} rx-jumbo 0".format(self.nic)
                    utils_lib.run_cmd(self, cmd, expect_kw="Invalid argument", msg="Check rx-jumbo can set to 0")
                cmd = "sudo ethtool -G {} rx-jumbo -1".format(self.nic)
                utils_lib.run_cmd(self, cmd, expect_kw="aborting", msg="Check rx-jumbo cannot set to -1")
        if max_tx is not None and 'n/a' not in max_tx and int(max_tx) > 0:
            if int(max_tx) >= 1024:
                tx = 512
            elif int(max_tx) <= 256:
                tx = 128
            else:
                tx = 256
            cmd = "sudo ethtool -G {} tx {}".format(self.nic, tx)
            output = utils_lib.run_cmd(self, cmd, msg="Set tx")
            if "not supported" not in output:
                utils_lib.run_cmd(self, query_cmd, expect_kw="TX:\t\t{}".format(tx), msg="Check tx")
                #cmd = "sudo ethtool -G {} tx 0".format(self.nic)
                #utils_lib.run_cmd(self, cmd, expect_kw="Invalid argument", msg="Check tx cannot set to 0")
                cmd = "sudo ethtool -G {} tx -1".format(self.nic)
                utils_lib.run_cmd(self, cmd, expect_kw="aborting", msg="Check tx cannot set to -1")

        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='dmesg -T', cursor=self.dmesg_cursor)

    def test_ethtool_P(self):
        '''
        case_name:
            test_ethtool_P

        case_priority:
            1

        component:
            kernel

        bugzilla_id:
            1704435

        polarion_id:
            n/a

        maintainer:
            xiliang@redhat.com

        description:
            Use ethtool to query the specified network device for permanent hardware address.

        key_steps:
            1. # ethtool -P $nic

        expected_result:
            Mac address is not "00:00:00:00:00:00"
            eg. # ethtool -P eth0
                Permanent address: 00:16:3d:fb:78:34

        '''
        cmd = "ethtool -P {}".format(self.nic)
        output = utils_lib.run_cmd(self,
                             cmd,
                             expect_not_kw='00:00:00:00:00:00',
                             msg='ethtool can read mac successfully')
        mac = ''.join(
            re.findall(
                '[0-9a-z]{2}:[0-9a-z]{2}:[0-9a-z]{2}:[0-9a-z]{2}:\
[0-9a-z]{2}:[0-9a-z]{2}', output))
        self.log.info("Get mac: %s" % mac)
        cmd = "ip addr show {}".format(self.nic)
        output = utils_lib.run_cmd(self,
                             cmd,
                             expect_kw=mac,
                             msg='compare with ip showed mac')

    def test_mtu_min_max_set(self):
        '''
        polarion_id: RHEL-111097
        BZ#: 1502554, 1497228
        ena mtu range: 128~9216
        ixgbevf mtu range: 68~9710
        vif mtu range: 68~65535
        vmxnet3 mtu range: 60~9000
        '''

        utils_lib.is_cmd_exist(self, cmd='ethtool')
        cmd = "sudo ethtool -i {}".format(self.nic)
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
            self.log.info("vmxnet3 min mtu is 60, because of bz1503193, skip test lower value than 68")
            mtu_range = [68, 4500, 9000, 9001]
            mtu_min = 60
            mtu_max = 9000
        else:
            self.log.info('Did not detect network type, use default min~max mtu. %s' % output)
            mtu_range = [0, 67, 68, 4500, 65535, 65536]
            mtu_min = 68
            mtu_max = 65535

        self.log.info("Trying to change mtu to %s" % mtu_range)
        for mtu_size in mtu_range:
            mtu_cmd = "sudo ip link set dev %s mtu %s" % (self.nic, mtu_size)
            mtu_check = "sudo ip link show dev {}".format(self.nic)
            if mtu_size <= mtu_max and mtu_size >= mtu_min:
                utils_lib.run_cmd(self, mtu_cmd, expect_ret=0)
                utils_lib.run_cmd(self, mtu_check, expect_ret=0, expect_kw="mtu {}".format(mtu_size))
            elif mtu_size < mtu_min or mtu_size > mtu_max:
                utils_lib.run_cmd(self, mtu_cmd, expect_not_ret=0)
                utils_lib.run_cmd(self, mtu_check, expect_ret=0, expect_not_kw="mtu {}".format(mtu_size))
        cmd = "ping {} -c 2 -I {}".format(self.params.get('ping_server'), self.nic)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='dmesg -T', cursor=self.dmesg_cursor)

if __name__ == '__main__':
    unittest.main()