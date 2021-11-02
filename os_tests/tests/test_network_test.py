import re
import unittest
import time
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
            cmd = "ping {} -c 6 -I {}".format(self.params.get('ping_server'), net)
            ret = utils_lib.run_cmd(self, cmd, ret_status=True)
            if ret == 0:
                self.nic = net
                break
        cmd = "ip addr show {}".format(self.nic)
        output = utils_lib.run_cmd(self, cmd, msg='try to get {} ipv4 address'.format(self.nic))
        self.ipv4 = re.findall('[\d.]{7,16}', output)[0]


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
                utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check rx cannot set to -1")
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
                utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check rx cannot rx-mini to -1")
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
                    #utils_lib.run_cmd(self, cmd, expect_kw="Invalid argument", msg="Check rx-jumbo cannot set to 0")
                    utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check rx-jumbo cannot set to 0")
                cmd = "sudo ethtool -G {} rx-jumbo -1".format(self.nic)
                utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check rx-jumbo cannot set to -1")
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
                utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check tx cannot set to -1")

        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='dmesg -T', skip_words='ftrace', cursor=self.dmesg_cursor)

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
    def test_ethtool_S_xdp(self):
        '''
        case_name:
            test_ethtool_S_xdp
        case_file:
            https://github.com/liangxiao1/os-tests/blob/master/os_tests/tests/test_network_test.py
        case_priority:
            2
        component:
            kernel
        bugzilla_id:
            1908542, 2000400
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Use ethtool to query the specified network device xdp statistics.
        key_steps:
            1. # ethtool -S $nic |grep xdp
            2. # xdp-loader status (xdp-tools is required and it is only support x86_64 for now)
            3. # xdp-loader unload -a
            4. # xdp-filter load --mode skb $nic
        expected_result:
            1. xdp data found
            eg. # ethtool -S eth0 |grep xdp
                  queue_0_rx_xdp_aborted: 0
                  queue_0_rx_xdp_drop: 0
                  queue_0_rx_xdp_pass: 0
                  queue_0_rx_xdp_tx: 0
                  queue_0_rx_xdp_invalid: 0
                  queue_0_rx_xdp_redirect: 0
            2. xdp-loader works on x86_64 platform
        debug_want:
            1. # uname -r
            2. # ethtool -i $nic
            3. # rpm -q xdp-tools (if fail at xdp-tools)
            4. # xdp-loader $cmd -vv

        '''
        product_id = utils_lib.get_product_id(self)
        cmd = "sudo ethtool -i {}".format(self.nic)
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if 'ena' in output:
            self.log.info('ena driver found!')
            if float(product_id) > 8.4:
                cmd = "ethtool -S {}|grep xdp".format(self.nic)
                utils_lib.run_cmd(self, cmd, expect_ret=0,msg='Check if have xdp information')
            else:
                self.skipTest('ena driver does not support xdp prior to 8.4')
        else:
            cmd = "ethtool -S {}|grep xdp".format(self.nic)
            utils_lib.run_cmd(self, cmd, cancel_ret='0', msg='Check if have xdp support')
        if float(product_id) > 8.3 and utils_lib.is_arch(self, arch='x86_64'):
            utils_lib.is_cmd_exist(self, 'xdp-loader')
            self.log.info('please attach debug log with -vv appended when report xdp-tools issue')
            cmd = 'sudo xdp-loader status'
            utils_lib.run_cmd(self, cmd, expect_ret=0,msg='Check xdp-loader status')
            cmd = 'sudo xdp-loader unload -a {}'.format(self.nic)
            utils_lib.run_cmd(self, cmd,msg='unload xdp-filter if have')
            cmd = 'sudo xdp-filter load --mode skb {}'.format(self.nic)
            utils_lib.run_cmd(self, cmd, expect_ret=0,msg='load xdp-filter')
            cmd = 'sudo xdp-loader status'
            utils_lib.run_cmd(self, cmd, expect_ret=0,expect_kw='XDP_PASS',msg='Check xdp-loader status again')
            cmd = 'sudo xdp-loader unload -a {}'.format(self.nic)
            utils_lib.run_cmd(self, cmd, expect_ret=0,msg='unload xdp-filter')
            cmd = 'sudo xdp-loader status'
            utils_lib.run_cmd(self, cmd, expect_ret=0,expect_not_kw='XDP_PASS',msg='Check xdp-loader status again')

    def test_mtu_min_max_set(self):
        '''
        polarion_id: RHEL-111097
        bz: 1502554, 1497228
        ena mtu range: 128~9216
        ixgbevf mtu range: 68~9710
        vif mtu range: 68~65535
        vmxnet3 mtu range: 60~9190
        hv_netvsc mtu range: 68~65521
        '''

        utils_lib.is_cmd_exist(self, cmd='ethtool')
        utils_lib.msg_to_syslog(self)
        cmd = 'ip link show {}'.format(self.nic)
        out = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='save the mtu before change')
        self.mtu_old = re.findall('mtu [0-9]+',out)[0].split(' ')[1]
        self.log.info("Get old mtu: {}".format(self.mtu_old))
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
            if self.params['remote_node'] is not None:
                self.skipTest("Skip mtu test while running remotely with vmxnet3")
            self.log.info("vmxnet3 min mtu is 60, because of bz1503193, skip test lower value than 68")
            mtu_range = [68, 4500, 9190, 9192]
            mtu_min = 60
            mtu_max = 9190
        elif 'igb' in output:
            self.log.info('igb found!')
            mtu_range = [0, 67, 68, 4500, 9216, 9217]
            mtu_min = 68
            mtu_max = 9216
        elif 'tg3' in output:
            self.log.info('tg3 found!')
            mtu_range = [0, 59, 60, 4500, 9000, 9001]
            mtu_min = 60
            mtu_max = 9000
        elif 'virtio_net' in output:
            self.log.info('virtio_net found!')
            mtu_range = [0, 67, 68, 1500,1600]
            mtu_min = 68
            mtu_max = 1500
        elif 'hv_netvsc' in output:
            self.log.info('hv_netvsc found, linux/drivers/net/hyperv/netvsc_drv.c  MTU range: 68 - 1500 or 65521')
            mtu_range = [0, 67, 68, 4500, 65521, 65525]
            mtu_min = 68
            mtu_max = 65521
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
        cmd = "ping {} -c 10 -I {}".format(self.params.get('ping_server'), self.nic)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='dmesg -T', cursor=self.dmesg_cursor, skip_words='ftrace')

    def test_persistent_route(self):
        '''
        case_name:
            test_persistent_route
        case_priority:
            2
        component:
            NetworkManager
        bugzilla_id:
            1971527
        customer_case_id:
            02957058
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check if can add persistent static route
        key_steps:
            1. # nmcli connection modify 'System eth0' +ipv4.routes "10.8.8.0/24 10.7.9.5"
            2. # nmcli connection down 'System eth0';nmcli connection up 'System eth0'
            3. # ip r
        expected_result:
            New static route added.
            eg. 10.8.8.0/24 via 10.7.9.5 dev eth0 proto static metric 100
        '''
        if utils_lib.is_pkg_installed(self, pkg_name='NetworkManager-cloud-setup', is_install=False):
            cmd = 'sudo systemctl status nm-cloud-setup.timer'
            utils_lib.run_cmd(self, cmd, msg='get nm-cloud-setup.timer status')
        cmd = 'ip r'
        utils_lib.run_cmd(self, cmd, msg='print route before testing')
        cmd = "sudo nmcli |grep 'connected to'|grep {}|awk -F'to' '{{print $NF}}'".format(self.nic)
        con_name = utils_lib.run_cmd(self, cmd, msg='try to get connection name')
        con_name = con_name.strip('\n')
        con_name = con_name.lstrip(' ')
        cmd = "sudo nmcli connection modify '{}' +ipv4.routes '10.8.8.0/24 {}'".format(con_name, self.ipv4)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to add static route name')
        utils_lib.run_cmd(self, 'ip r', msg='print route after added')
        cmd = "sudo bash -c 'nmcli connection down \"{con}\";nmcli connection up \"{con}\"'".format(con=con_name)
        utils_lib.run_cmd(self, cmd, msg='down and up the connection')
        time.sleep(10)
        cmd = 'ip r'
        utils_lib.run_cmd(self, cmd, expect_kw='10.8.8.0', msg='check new route again after down and up connection')

    def test_route_interfere(self):
        """
        case_name:
            test_route_interfere
        case_file:
            https://github.com/liangxiao1/os-tests/blob/master/os_tests/tests/test_network_test.py
        component:
            NetworkManager
        bugzilla_id:
            1977984
        customer_case_id:
            02984023
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Check the route working if system has other IP that have routes in the "main" table.
        key_steps:
            # mkdir -p /tmp/test
            # echo 'hello new site!' > /tmp/test/hello
            # podman run -dit --name httpd_site -p 8188:80 -v "/tmp/test":/usr/local/apache2/htdocs/ httpd:2.4
            # systemctl restart nm-cloud-setup (if enabled)
            # curl http://$serverip:8188/hello (with NetworkManager-cloud-setup installed, curl failed, without nm-cloud, curl ok)
        expect_result:
            - curl return "hello new site"
        debug_want:
            # ip -4 route show table all
        """
        is_cloud_setup_installed = False
        if utils_lib.is_pkg_installed(self, pkg_name='NetworkManager-cloud-setup', is_install=False):
            cmd = 'sudo systemctl status nm-cloud-setup.timer'
            utils_lib.run_cmd(self, cmd, msg='get nm-cloud-setup.timer status')
            is_cloud_setup_installed = True
        cmd = "podman rm -a -f"
        utils_lib.run_cmd(self, cmd, msg='try to clean all containers before testing')
        cmd = 'sudo ip -4 route show table all|sort'
        utils_lib.run_cmd(self, cmd, msg='get ip routes')
        cmd = 'sudo mkdir -p /tmp/test'
        utils_lib.run_cmd(self, cmd, msg='create /tmp/test')
        cmd = "sudo echo 'hello new site!' > /tmp/test/hello"
        utils_lib.run_cmd(self, cmd, msg='create /tmp/test/hello')
        registries = ['docker.io/library/httpd:2.4','docker.mirrors.ustc.edu.cn/library/httpd:2.4']
        for registry in registries:
            cmd = 'sudo podman run -dit --name httpd_site -p 8188:80 -v "/tmp/test":/usr/local/apache2/htdocs/ {}'.format(registry)
            ret = utils_lib.run_cmd(self, cmd, timeout=600, msg='start container httpd_site', ret_status=True)
            if ret == 0:
                break
            cmd = "podman rm -a -f"
            utils_lib.run_cmd(self, cmd, msg='try to clean all containers before testing')
        cmd = "podman ps -a"
        utils_lib.run_cmd(self, cmd, msg='list all running containers')
        if is_cloud_setup_installed:
            cmd = 'sudo systemctl restart nm-cloud-setup'
            utils_lib.run_cmd(self, cmd, msg='restart nm-cloud-setup')
        cmd = 'sudo ip -4 route show table all|sort'
        utils_lib.run_cmd(self, cmd, msg='get ip routes')
        cmd = "curl --connect-timeout 5 http://{}:8188/hello".format(self.ipv4)
        utils_lib.run_cmd(self, cmd, expect_kw='new site', msg='test site is available')

    def tearDown(self):
        if 'test_mtu_min_max_set' in self.id():
            mtu_cmd = "sudo ip link set dev %s mtu %s" % (self.nic, self.mtu_old)
            utils_lib.run_cmd(self, mtu_cmd, expect_ret=0, msg='restore mtu')

if __name__ == '__main__':
    unittest.main()