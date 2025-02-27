import re
import unittest
import time
import random
import os

from os_tests.libs import utils_lib
from os_tests.libs.utils_lib import run_cmd
from os_tests.libs.resources import UnSupportedAction,UnSupportedStatus

class TestNetworkTest(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='sudo dmesg -T')
        cmd = "ip link show|grep mtu|grep -v lo|awk -F':' '{print $2}'"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        self.active_nic  = "eth0"
        self.log.info("Test which nic connects to public")
        nic_found = False
        for net in output.split('\n'):
            if len(net) < 3:
                continue
            cmd = "sudo ping {} -c 6 -I {}".format(self.params.get('ping_server'), net)
            ret = utils_lib.run_cmd(self, cmd, ret_status=True)
            if ret == 0:
                self.active_nic  = net
                nic_found = True
                break
        if not nic_found:
            for net in output.split('\n'):
                #man systemd.net-naming-scheme
                if net.startswith(('eth','en')):
                    self.active_nic  = net
                    break
        self.active_nic = self.active_nic.strip()
        self.log.info("Pick up nic {}".format(self.active_nic))
        cmd = "ip addr show {}".format(self.active_nic )
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to get {} ipv4 address'.format(self.active_nic ))
        pat = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        self.ipv4 = pat.findall(output)[0]

    @property
    def rhel_x_version(self):
        product_id = utils_lib.get_product_id(self)
        return int(product_id.split('.')[0])

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
        key_steps: |
            1. # ethtool -g $nic
            2. # ethtool -G $nic rx $num
            3. # ethtool -G $nic rx-mini $num
            4. # ethtool -G $nic rx-jumbo $num
            5. # ethtool -G $nic tx $num
        expected_result: |
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
        query_cmd = "ethtool -g {}".format(self.active_nic )
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
            cmd = "sudo ethtool -G {} rx {}".format(self.active_nic , rx)
            output = utils_lib.run_cmd(self, cmd, msg="Set rx")
            if "not supported" not in output:
                utils_lib.run_cmd(self, query_cmd, expect_kw="RX:.*{}".format(rx), msg="Check rx")
                #cmd = "sudo ethtool -G {} rx 0".format(self.active_nic )
                #utils_lib.run_cmd(self, cmd, expect_kw="Invalid argument", msg="Check rx cannot set to 0")
                cmd = "sudo ethtool -G {} rx -1".format(self.active_nic )
                utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check rx cannot set to -1")
        if max_rx_mini is not None and 'n/a' not in max_rx_mini and int(max_rx_mini) > 0:
            if int(max_rx_mini) >= 1024:
                rx_mini = 512
            elif int(max_rx_mini) <= 256:
                rx_mini = 128
            else:
                rx_mini = 256
            cmd = "sudo ethtool -G {} rx-mini {}".format(self.active_nic , rx_mini )
            output = utils_lib.run_cmd(self, cmd, msg="Set rx-mini")
            if "not supported" not in output:
                out = utils_lib.run_cmd(self, query_cmd, expect_kw="RX Mini:.*{}".format(rx_mini), msg="Check rx-mini")
                if "RX Mini:\t0" not in out:
                    cmd = "sudo ethtool -G {} rx-mini 0".format(self.active_nic )
                    utils_lib.run_cmd(self, cmd)
                    utils_lib.run_cmd(self, query_cmd, expect_kw="RX Mini:.*0", msg="Check rx-mini canset to 0")
                cmd = "sudo ethtool -G {} rx-mini -1".format(self.active_nic )
                utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check rx cannot rx-mini to -1")
        if max_rx_jumbo is not None and 'n/a' not in max_rx_jumbo and int(max_rx_jumbo) > 0:
            if int(max_rx_jumbo) >= 1024:
                rx_jumbo = 512
            elif int(max_rx_jumbo) <= 256:
                rx_jumbo = 128
            else:
                rx_jumbo = 256
            cmd = "sudo ethtool -G {} rx-jumbo {}".format(self.active_nic , rx_jumbo)
            output = utils_lib.run_cmd(self, cmd, msg="Set rx_jumbo")
            if "not supported" not in output:
                out = utils_lib.run_cmd(self, query_cmd, expect_kw="RX Jumbo:.*{}".format(rx_jumbo), msg="Check rx_jumbo")
                if "RX Jumbo:\t0" not in out:
                    cmd = "sudo ethtool -G {} rx-jumbo 0".format(self.active_nic )
                    #utils_lib.run_cmd(self, cmd, expect_kw="Invalid argument", msg="Check rx-jumbo cannot set to 0")
                    utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check rx-jumbo cannot set to 0")
                cmd = "sudo ethtool -G {} rx-jumbo -1".format(self.active_nic )
                utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check rx-jumbo cannot set to -1")
        if max_tx is not None and 'n/a' not in max_tx and int(max_tx) > 0:
            if int(max_tx) >= 1024:
                tx = 512
            elif int(max_tx) <= 256:
                tx = 128
            else:
                tx = 256
            cmd = "sudo ethtool -G {} tx {}".format(self.active_nic , tx)
            output = utils_lib.run_cmd(self, cmd, msg="Set tx")
            if "not supported" not in output:
                utils_lib.run_cmd(self, query_cmd, expect_kw="TX:.*{}".format(tx), msg="Check tx")
                #cmd = "sudo ethtool -G {} tx 0".format(self.active_nic )
                #utils_lib.run_cmd(self, cmd, expect_kw="Invalid argument", msg="Check tx cannot set to 0")
                cmd = "sudo ethtool -G {} tx -1".format(self.active_nic )
                utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="Check tx cannot set to -1")

        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='sudo dmesg -T', \
            skip_words='ftrace,Adding Red Hat flag eBPF/rawtrace', cursor=self.dmesg_cursor)

    def test_ethtool_L(self):
        """
        case_tags:
            network
        title:
            Test change the numbers of channels of the specified network device.
        importance:
            low
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py
        setup_teardown:
            N/A
        environment:
            N/A
        case_name:
            test_ethtool_L
        component:
            kernel
        bug_id:
            N/A
        is_customer_case:
            False 
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description: |
            Use ethtool to query and change the numbers of channels of the specified network device.
        key_steps: |
            # ethtool -l $nic
            # ethtool -L $nic rx|tx|other|combined N
        expected_result: |
            Can change the numbers of channels of the specified network device successfully.
        debug_want: |
            # ethtool -i $nic
            # ethtool -l $nic
            # dmesg
        """
        utils_lib.is_cmd_exist(self, 'ethtool')
        cmd = "ethtool -i {}".format(self.active_nic)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        query_cmd = "ethtool -l {}".format(self.active_nic)
        utils_lib.run_cmd(self, query_cmd, cancel_not_kw='not supported')

        for i in ['rx', 'tx', 'other','combined']:
            cmd = "ethtool -l {}|grep -i {}|head -1".format(self.active_nic,i)
            out = utils_lib.run_cmd(self, cmd)
            max_val = re.findall('[\d]+',out)
            cmd = "ethtool -l {}|grep -i {}|tail -1".format(self.active_nic,i)
            out = utils_lib.run_cmd(self, cmd)
            init_val = re.findall('[\d]+',out)
            if not max_val or not init_val:
                self.log.info("Not specified in max or current:{}".format(i))
                continue
            max_val = int(max_val[0])
            init_val = int(init_val[0])
            if max_val <= 1:
                self.log.info("do not change any thing when value is less or equal 1:{}".format(i))
                continue
            set_val = random.randint(1,max_val)
            cmd = "sudo ethtool -L {} {} {}".format(self.active_nic, i, set_val)
            out = utils_lib.run_cmd(self, cmd)
            if out and "supported" in out:
                self.log.info("continue next option as cannot change this option")
                continue
            utils_lib.run_cmd(self, query_cmd, expect_kw=str(set_val))
            cmd = "sudo ethtool -L {} {} {}".format(self.active_nic, i, init_val)
            utils_lib.run_cmd(self, cmd,msg='restore it to default setting')
            utils_lib.run_cmd(self, query_cmd, expect_kw=str(init_val))
        utils_lib.run_cmd(self, 'sudo dmesg')

    def test_ethtool_P(self):
        """
        case_tags:
            network
        title:
            Test ethtool query nic's mac address
        importance:
            low
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py
        setup_teardown:
            N/A
        environment:
            N/A
        case_name:
            test_ethtool_P
        component:
            kernel
        bug_id:
            bugzilla_1704435
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description: |
            Use ethtool to query the specific network device for permanent hardware address.
        key_steps: |
            # ethtool -P $nic
        expected_result: |
            Mac address is not "00:00:00:00:00:00"
            eg. # ethtool -P eth0
                Permanent address: 00:16:3d:fb:78:34
        debug_want: |
            N/A
        """
        cmd = "ethtool -P {}".format(self.active_nic )
        output = utils_lib.run_cmd(self,
                             cmd,
                             expect_not_kw='00:00:00:00:00:00',
                             msg='ethtool can read mac successfully')
        mac = ''.join(
            re.findall(
                '[0-9a-z]{2}:[0-9a-z]{2}:[0-9a-z]{2}:[0-9a-z]{2}:\
[0-9a-z]{2}:[0-9a-z]{2}', output))
        self.log.info("Get mac: %s" % mac)
        cmd = "ip addr show {}".format(self.active_nic )
        output = utils_lib.run_cmd(self,
                             cmd,
                             expect_kw=mac,
                             msg='compare with ip showed mac')

    def test_ethtool_S_xdp(self):
        """
        case_name:
            test_ethtool_S_xdp
        case_tags:
            network
        case_status:
            approved
        title:
            TestNetworkTest.test_ethtool_S_xdp
        importance:
            high
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            n/a
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py/#L317
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            2038158, 2038056, 2038079, 1908542, 2000400, 2128252
        is_customer_case:
            True
        testplan:
            n/a
        test_type:
            functional
        test_level:
            component
        maintainer:
            xiliang@redhat.com
        description: |
            Use ethtool to query the specified network device xdp statistics.
        key_steps: |
            1. # ethtool -S $nic |grep xdp
            2. # xdp-loader status
            3. # xdp-loader unload -a
            4. # xdp-filter load --mode skb $nic
        expected_result: |
            xdp data found
            eg. # ethtool -S eth0 |grep xdp
                  queue_0_rx_xdp_aborted: 0
                  queue_0_rx_xdp_drop: 0
                  queue_0_rx_xdp_pass: 0
                  queue_0_rx_xdp_tx: 0
                  queue_0_rx_xdp_invalid: 0
                  queue_0_rx_xdp_redirect: 0
        debug_want: |
            1. # uname -r
            2. # ethtool -i $nic
            3. # rpm -q xdp-tools (if fail at xdp-tools)
            4. # xdp-loader $cmd -vv
        """

        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
        cmd = "sudo ethtool -i {}".format(self.active_nic )
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if 'ena' in output:
            self.log.info('ena driver found!')
            if float(product_id) > 8.4 or product_id == '8.10':
                cmd = "ethtool -S {}|grep xdp".format(self.active_nic )
                utils_lib.run_cmd(self, cmd, expect_ret=0,msg='Check if have xdp information')
            else:
                self.skipTest('ena driver does not support xdp prior to 8.4')
        else:
            cmd = "ethtool -S {}|grep xdp".format(self.active_nic )
            utils_lib.run_cmd(self, cmd, cancel_ret='0', msg='Check if have xdp support')
        if float(product_id) < 9.0 and utils_lib.is_arch(self, arch='aarch64'):
            self.log.info("xdp-tools does not supports aarch64 before rhel-9")
        else:
            utils_lib.is_cmd_exist(self, 'xdp-loader')
            self.log.info('please attach debug log with -vv appended when report xdp-tools issue')
            modes = ['skb']
            for mode in modes:
                cmd = 'sudo xdp-loader status'
                utils_lib.run_cmd(self, cmd, expect_ret=0,msg='Check xdp-loader status')
                cmd = 'sudo xdp-loader unload -a {}'.format(self.active_nic )
                utils_lib.run_cmd(self, cmd,msg='unload xdp-filter if have')
                cmd = 'sudo xdp-filter load --mode {} {}'.format(mode, self.active_nic )
                utils_lib.run_cmd(self, cmd, expect_ret=0,msg='load xdp-filter with {} mode'.format(mode))
                cmd = 'sudo xdp-loader status'
                utils_lib.run_cmd(self, cmd, expect_ret=0,expect_kw='XDP_PASS',msg='Check xdp-loader status again')
                cmd = 'sudo xdp-loader unload -a {}'.format(self.active_nic )
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
        cmd = 'ip link show {}'.format(self.active_nic )
        out = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='save the mtu before change')
        self.mtu_old = re.findall('mtu [0-9]+',out)[0].split(' ')[1]
        self.log.info("Get old mtu: {}".format(self.mtu_old))
        cmd = "sudo ethtool -i {}".format(self.active_nic )
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
            if self.params.get('remote_node') is not None:
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
            if self.vm.provider == 'nutanix' or self.vm.provider == 'ali' or self.vm.provider == 'google':
                mtu_range = [0, 67, 68, 65535,65536]
                mtu_max = 65535
        elif 'hv_netvsc' in output and not utils_lib.is_azure(self):
            self.log.info('hv_netvsc found on azure, rhbz#2017612')
            mtu_range = [0, 67, 68, 1600, 4500]
            mtu_min = 68
            mtu_max = 4500
        elif 'hv_netvsc' in output:
            self.log.info('hv_netvsc found, linux/drivers/net/hyperv/netvsc_drv.c  MTU range: 68 - 1500 or 65521')
            mtu_range = [0, 67, 68, 4500, 65521, 65525]
            mtu_min = 68
            mtu_max = 65521
        elif 'gve' in output:
            self.log.info('gve found!')
            mtu_range = [0, 67, 68, 1460, 1461]
            mtu_min = 68
            mtu_max = 1460
        else:
            self.log.info('Did not detect network type, use default min~max mtu. %s' % output)
            mtu_range = [0, 67, 68, 4500, 65535, 65536]
            mtu_min = 68
            mtu_max = 65535

        self.log.info("Trying to change mtu to %s" % mtu_range)
        for mtu_size in mtu_range:
            mtu_cmd = "sudo ip link set dev %s mtu %s" % (self.active_nic , mtu_size)
            mtu_check = "sudo ip link show dev {}".format(self.active_nic )
            if mtu_size <= mtu_max and mtu_size >= mtu_min:
                utils_lib.run_cmd(self, mtu_cmd, expect_ret=0)
                utils_lib.run_cmd(self, mtu_check, expect_ret=0, expect_kw="mtu {}".format(mtu_size))
            elif mtu_size < mtu_min or mtu_size > mtu_max:
                utils_lib.run_cmd(self, mtu_cmd, expect_not_ret=0)
                utils_lib.run_cmd(self, mtu_check, expect_ret=0, expect_not_kw="mtu {}".format(mtu_size))
        cmd = "sudo ping {} -c 10 -I {}".format(self.params.get('ping_server'), self.active_nic ) #add sudo here or it will fail against 8.7
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=180)
        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='sudo dmesg -T', cursor=self.dmesg_cursor, skip_words='ftrace')

    def test_persistent_route(self):
        '''
        case_name:
            test_persistent_route
        case_priority:
            2
        component:
            NetworkManager
        bug_id:
            bugzilla_1971527
        is_customer_case:
            True
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            check if can add persistent static route
        key_steps: |
            1. # nmcli connection modify 'System eth0' +ipv4.routes "10.8.8.0/24 10.7.9.5"
            2. # nmcli connection down 'System eth0';nmcli connection up 'System eth0'
            3. # ip r
        expected_result: |
            New static route added.
            eg. 10.8.8.0/24 via 10.7.9.5 dev eth0 proto static metric 100
        '''
        if utils_lib.is_pkg_installed(self, pkg_name='NetworkManager-cloud-setup', is_install=False):
            cmd = 'sudo systemctl status nm-cloud-setup.timer'
            utils_lib.run_cmd(self, cmd, msg='get nm-cloud-setup.timer status')
        cmd = 'ip r'
        utils_lib.run_cmd(self, cmd, msg='print route before testing')
        cmd = "sudo nmcli -f NAME connection show|grep {}|head -1".format(self.active_nic )
        con_name = utils_lib.run_cmd(self, cmd, msg='try to get connection name')
        con_name = con_name.strip('\n')
        con_name = con_name.strip(' ')
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
        utils_lib.is_cmd_exist(self, 'podman')
        cmd = "podman rm -a -f"
        utils_lib.run_cmd(self, cmd, msg='try to clean all containers before testing')
        cmd = 'sudo ip -4 route show table all|sort'
        utils_lib.run_cmd(self, cmd, msg='get ip routes')
        cmd = 'sudo mkdir -p /tmp/test'
        utils_lib.run_cmd(self, cmd, msg='create /tmp/test')
        cmd = "sudo bash -c \"echo 'hello new site!' > /tmp/test/hello\""
        utils_lib.run_cmd(self, cmd, msg='create /tmp/test/hello')
        registries = ['docker.io/library/httpd:2.4','docker.mirrors.ustc.edu.cn/library/httpd:2.4']
        for registry in registries:
            cmd = 'sudo podman run -dit --name httpd_site -p 8188:80 -v "/tmp/test":/usr/local/apache2/htdocs/:z {}'.format(registry)
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

    def test_iptables_restore_hangs(self):
        """
        case_tag:
            N/A
        case_name:
            test_iptables_restore_hangs
        component:
            iptables
        bugzilla_id:
            1840936
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xuazhao@redhat.com
        description:
            test if iptables-restore can run normally
        key_steps:
            1. Create a very simple multi-table iptables file to restore.
            2. iptables-restore --test <file>
        expect_result:
            run to completion as documented
        debug_want:
            N/A
        """
        cmd = "touch /tmp/iptable.txt"
        utils_lib.run_cmd(self,cmd,msg="create a txt file")
        tablestr = '''
*filter
:FORWARD ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
*mangle
:FORWARD ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:PREROUTING ACCEPT [0:0]
COMMIT
'''
        utils_lib.run_cmd(self,"echo '%s'>/tmp/iptable.txt" % tablestr)
        utils_lib.run_cmd(self,'iptables-restore --test /tmp/iptable.txt',timeout=20,msg="run restore test")
        utils_lib.run_cmd(self,"rm -f /tmp/iptable.txt")

    def _test_add_remove_multi_nics(self, nic_num, network_uuid, ip_subnet, driver='virtio'):
        '''
        Add remove multi nics according to specific parameters.
        '''
        self.log.info("Enter _test_add_remove_multi_nics procedure")
        #record origin nic's mac and name
        origin_nic_mac = utils_lib.run_cmd(self, "cat /sys/class/net/%s/address" % self.active_nic).strip()
        #stop vm to add nic if vm is secure boot and record the set ip list
        if self.vm.provider == 'nutanix' and self.vm.if_secure_boot:
            self.vm.stop(wait=True)
        try:
            used_ip_list = self.vm.list_networks_address(self.vm.private_network_uuid)
        except AttributeError:
            self.skipTest('list_networks_address not found in {} vm'.format(self.vm.provider))
        set_ip_list = []
        for i in range(nic_num):
            if ip_subnet == None:
                ip_address = None
            else:
                ip_subnet = re.search(r'((\d+\.){2}\d+\.)', ip_subnet).groups()[0]
                while True:
                    ip_address = ip_subnet + str(random.randint(10,100))
                    if ip_address not in set_ip_list and ip_address not in used_ip_list:
                        set_ip_list.append(ip_address)
                        break
            self.log.info("Add nic for %s time(s)" % str(i+1))
            self.vm.attach_nic(network_uuid, ip_address, driver)
        time.sleep(10)
        set_ip_list.sort()
        if self.vm.provider == 'nutanix' and self.vm.if_secure_boot:
            #start vm
            self.vm.start(wait=True)
            time.sleep(30)
            utils_lib.init_connection(self, timeout=180)
        #check nic number
        vm_nic_num = int(utils_lib.run_cmd(self, "ls /sys/class/net | grep e | wc -l").strip())
        self.assertEqual(vm_nic_num, nic_num+1, msg="Number of nics is not right, Expect: %s, real: %s" % (nic_num+1, vm_nic_num))
        #check nic driver
        nic_name_list = (utils_lib.run_cmd(self, "ls /sys/class/net | grep e")).split()
        for nic_name in nic_name_list:
            nic_driver = utils_lib.run_cmd(self, "ethtool -i %s | grep driver | awk '{print $2}'" % nic_name).strip()
            if nic_name == self.active_nic:
                self.assertEqual(nic_driver, 'virtio_net', msg="Default nic dirver is not virtio_net, real: %s" % nic_driver)
            else:
                if driver == 'virtio':
                    driver_check = 'virtio_net'
                else:
                    driver_check = driver
                self.assertEqual(nic_driver, driver_check, msg="Driver of %s is not right, Expect: %s, real: %s" % (nic_name, driver, nic_driver))
        #record nic mac list
        nic_mac_list = utils_lib.run_cmd(self, "ip a | grep link/ether | awk '{print $2}'").split()
        time.sleep(5)
        #check nic ip
        if ip_subnet != None:
            ip_subnet = re.search(r'((\d+\.){2}\d+\.)', self.vm.private_network_subnet).groups()[0]
            vm_ip_list = utils_lib.run_cmd(self, "ip a | grep 'inet ' | grep %s | awk '{print $2}' | sed 's/\/24//'" \
                % ip_subnet).split()
            vm_ip_list.sort()
            self.assertEqual(vm_ip_list, set_ip_list, msg="IP configure is not right, \
                Expect: %s, real: %s" % (str(set_ip_list), str(vm_ip_list)))
        if self.vm.provider == 'nutanix' and self.vm.if_secure_boot:
            self.vm.stop(wait=True)
        #delete nic by mac
        for mac in nic_mac_list:
            if mac != origin_nic_mac:
                self.vm.detach_nic(mac)
        if self.vm.provider == 'nutanix' and self.vm.if_secure_boot:
            self.vm.start(wait=True)
            time.sleep(30)
            utils_lib.init_connection(self, timeout=180)
        vm_nic_num = int(utils_lib.run_cmd(self, "ip a | grep 'inet ' | grep global | wc -l").strip())
        self.assertEqual(vm_nic_num, 1, msg="Number of nics is not right, Expect: %s, real: %s" % (1, vm_nic_num))

    def test_add_remove_multi_virtio_no_ip_spec(self):
        """
        case_tag:
            Network,Network_tier1
        case_name:
            test_add_remove_multi_virtio_no_ip_spec
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_add_remove_multi_virtio_no_ip_spec
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Add/Remove multi NICs without IP, check nic number and driver.
        key_steps:
            Add/Remove multi NICs without IP.
        expect_result:
            Check nic number and driver without error.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest('vm not init')
        utils_lib.check_attribute(self.vm, 'private_network_uuid',test_instance=self, cancel_case=True)
        if self.vm.provider == 'nutanix' and self.vm.prism.machine_type == 'q35':
            multi_num = 1
        else:
            multi_num = 2
        self._test_add_remove_multi_nics(multi_num, self.vm.private_network_uuid, None, 'virtio')

    def test_add_remove_multi_virtio_ip_spec(self):
        """
        case_tag:
            Network,Network_tier1
        case_name:
            test_add_remove_multi_virtio_ip_spec
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_add_remove_multi_virtio_ip_spec
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Add/Remove multi NICs with IP, check nic number and driver.
        key_steps:
            Add/Remove multi NICs with IP.
        expect_result:
            Check nic number and driver without error.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest('vm not init')
        utils_lib.check_attribute(self.vm, 'private_network_uuid,private_network_subnet',test_instance=self, cancel_case=True)
        if self.vm.provider == 'nutanix' and self.vm.machine_type == 'q35':
            multi_num = 1
        else:
            multi_num = 2
        self._test_add_remove_multi_nics(multi_num, self.vm.private_network_uuid, self.vm.private_network_subnet, 'virtio')

    def test_add_remove_multi_e1000_nic(self):
        """
        case_tag:
            Network,Network_tier1
        case_name:
            test_add_remove_multi_e1000_nic
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_add_remove_multi_e1000_nic
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Add/Remove four e1000 NICs, two with IP and the other two without IP, check nic number, nic ip and driver.
        key_steps:
            Add/Remove four e1000 NICs, two with IP and the other two without IP.
        expect_result:
            Check nic number, nic ip and driver.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        if self.vm.provider == 'nutanix' and self.vm.prism.machine_type == 'q35':
            self.skipTest('e1000 should not be supported by pcie-root-port')
        self._test_add_remove_multi_nics(2, None, None, 'e1000')
        self._test_add_remove_multi_nics(2, self.vm.private_network_uuid, self.vm.private_network_subnet, 'e1000')

    def _test_unload_load_nic_driver(self, driver):
        self.log.info("Enter _test_unload_load_nic_driver procedure")
        #record the first nic
        origin_nic_mac = utils_lib.run_cmd(self, "cat /sys/class/net/%s/address" % self.active_nic).strip()
        #atach the second nic
        if self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
            self.vm.stop(wait=True)
        self.vm.attach_nic(None, None, driver)
        self.vm.detach_nic(origin_nic_mac)
        if self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
            self.vm.start(wait=True)
            time.sleep(60)
        self.vm.refresh_data()
        utils_lib.init_connection(self, timeout=180)
        new_nic_mac = utils_lib.run_cmd(self, "cat /sys/class/net/%s/address" % self.active_nic).strip()
        self.assertNotEqual(origin_nic_mac, new_nic_mac, msg="Second nic name changed after detaching the first nic, Expect not: %s, real: %s" % (origin_nic_mac, new_nic_mac))
        if driver == 'virtio':
            driver_check = 'virtio_net'
        else:
            driver_check = driver
        for i in range (2):
            self.log.info("Unload and load nic driver for %s time(s)." % i)
            utils_lib.run_cmd(self, "sudo modprobe -r %s && sudo modprobe %s" % (driver_check, driver_check), expect_ret=0)
        new_nic_name = utils_lib.run_cmd(self, "ls /sys/class/net/ | grep -Ev 'lo|podman|veth'").strip()
        self.assertEqual(self.active_nic, new_nic_name, msg="Second nic name changed after unload/load nic driver three times, Expect: %s, real: %s" % (self.active_nic, new_nic_name))

    def _create_vm1(self):
        create_vm_name = self.vm.vm_name+'_nework_script_create'
        self.vm.create(vm_name=create_vm_name)
        vm1 = self.vm.get_vm_by_filter('vm_name', create_vm_name)
        self.vms.append(vm1)
        self.vm.prism.start_vm(vm1['uuid'])
        time.sleep(60)
        self.vm.vm1_ip = self.vms[1]['vm_nics'][0]['ip_address']
        self.log.info("IP of new created VM is %s " % self.vm.vm1_ip)
        return vm1

    def test_ping_arp_ping(self):
        """
        case_tag:
            Network,Network_tier2
        case_name:
            test_ping_arp_ping
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_ping_arp_ping
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test arping and ping -f between guests.
        key_steps: |
            1. Create 1 more guest.
            2. Test arping and ping -f between guests.
        expect_result:
            No package lost
        debug_want:
            N/A
        """
        if len(self.vms) == 1 and self.vm.provider == 'nutanix':
            self._create_vm1()
            if self.vm.vm1_ip not in self.params['remote_nodes']:
                self.params['remote_nodes'].append(self.vm.vm1_ip)
        if len(self.vms) > 1 and self.vm.provider != 'nutanix':
            if not self.vms[1].exists():
                self.vms[1].create()
            if self.vms[1].is_stopped():
                self.vms[1].start(wait=True)
            if self.vm.provider == 'aws' or self.vm.provider == 'ali':
                if self.vms[1].private_ip and self.vms[1].private_ip not in self.params['remote_nodes']:
                    self.params['remote_nodes'].append(self.vms[1].private_ip)
            else:
                if self.vms[1].floating_ip and self.vms[1].floating_ip not in self.params['remote_nodes']:
                    self.params['remote_nodes'].append(self.vms[1].floating_ip)
        if len(self.params['remote_nodes']) < 2:
            self.skipTest("2 nodes required, current IP bucket:{}".format(self.params['remote_nodes']))
        self.log.info("Current IP bucket:{}".format(self.params['remote_nodes']))
        #Found case will fail after vm boot time became more long, change to loop check
        for count in utils_lib.iterate_timeout(
            60, "Check VM1 has started and can arping", wait=10):
            res = utils_lib.run_cmd(self, \
                'arping -I %s %s -c 2' % (self.active_nic, self.params['remote_nodes'][-1]))
            if not re.search('Received\s+0\s+response', res): break
        arp_result = utils_lib.run_cmd(self, \
            'arping -I %s %s -c 10' % (self.active_nic, self.params['remote_nodes'][-1]))
        arp_response = int(re.search('Received\s+(\d+)\s+response', \
            arp_result, re.I).groups()[0])
        self.assertEqual(first=int(arp_response), second=10, \
            msg='check arping response error, expect:%s, real:%s')
        utils_lib.run_cmd(self, 'sudo ping -f %s -c 2' % (self.params['remote_nodes'][-1]), \
            expect_ret=0)
        utils_lib.run_cmd(self, 'sudo ping -f %s -c 600' % (self.params['remote_nodes'][-1]), \
            expect_kw='0% packet loss')

    def test_iperf(self):
        """
        case_tag:
            Network,Network_tier2
        case_name:
            test_iperf
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_iperf
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test arping and ping -f between guests.
        key_steps: |
            1. Create 1 more guest.
            2. Test arping and ping -f between guests.
        expect_result:
            No package lost
        debug_want:
            N/A
        """
        if self.vm and self.vm.provider == 'nutanix':
            if len(self.vm.prism.list_hosts_detail()["entities"])==1:
                self.skipTest('Need to test between VMs on different hosts')
            if len(self.vms) == 1:
                self._create_vm1()
            vm1_host_uuid = self.vm.prism.get_vm_by_uuid(self.vms[1]['uuid'])['host_uuid']
            if self.vms[0].vm_host_uuid() == vm1_host_uuid:
                self.log.info('vm1 host uuid %s is same with vm2: %s, do migration' % (self.vms[0].vm_host_uuid(), vm1_host_uuid))
                self.vm.migrate()
            if self.vm.vm1_ip not in self.params['remote_nodes']:
                self.params['remote_nodes'].append(self.vm.vm1_ip)
        if len(self.vms) > 1 and self.vm.provider != 'nutanix':
            if not self.vms[1].exists():
                self.vms[1].create()
            if self.vms[1].is_stopped():
                self.vms[1].start(wait=True)
            if self.vms[1].floating_ip and self.vms[1].floating_ip not in self.params['remote_nodes']:
                self.params['remote_nodes'].append(self.vms[1].floating_ip)
        if len(self.params['remote_nodes']) < 2:
            self.skipTest("2 nodes required, current IP bucket:{}".format(self.params['remote_nodes']))
        self.log.info("Current IP bucket:{}".format(self.params['remote_nodes']))
        self.log.info('Install iperf3 on vm[0]')
        utils_lib.is_cmd_exist(self,"iperf3")
        self.log.info('Install iperf3 on vm[1]')
        utils_lib.init_connection(self, timeout=180, rmt_node=self.params['remote_nodes'][-1])
        utils_lib.run_cmd(self, "rpm -q iperf3||sudo yum install -y iperf3", expect_ret=0, timeout=180, rmt_node=self.params['remote_nodes'][-1])
        self.log.info('Start iperf testing')
        iperf_srv_cmd = 'sudo bash -c "iperf3 -s >/dev/null 2>&1 &"'
        utils_lib.run_cmd(self, iperf_srv_cmd, rmt_node=self.params['remote_nodes'][-1])
        cmd = "ip addr show {}".format(self.active_nic )
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, \
            msg='try to get {} ipv4 address'.format(self.active_nic ),rmt_node=self.params['remote_nodes'][-1])
        srv_ipv4 = re.findall('[\d.]{7,16}', output)[0]
        iperf_cli_cmd = 'iperf3 -P 10 -c {} -t 60'.format(srv_ipv4)
        res = utils_lib.run_cmd(self, iperf_cli_cmd, expect_ret=0, timeout=120)
        if not re.search('(\d+)\s+Mbits/sec.+sender', res):
            res = utils_lib.run_cmd(self, iperf_cli_cmd, expect_ret=0, timeout=120)
        bandwidth_map = {'default':1000}
        if self.vm and hasattr(self.vm, 'net_bandwidth'):
            if self.vm.net_bandwidth>100:
                self.log.info("Guess bandwidth in M: {}".format(self.vm.net_bandwidth))
                bandwidth_map[self.vm.provider] = self.vm.net_bandwidth
            else:
                self.log.info("Guess bandwidth in G:{}".format(self.vm.net_bandwidth))
                bandwidth_map[self.vm.provider] = self.vm.net_bandwidth*1000
        if self.vm:
            perf_spec = float(bandwidth_map.get(self.vm.provider) or bandwidth_map.get('default'))
            if perf_spec > 40*1000:
                # needs to start multiple iperf process to cover 40G+ network
                self.log.info('do not check when bandwidth {} > 40G'.format(perf_spec))
            else:
                for line in res.split("\n"):
                    if 'sender' in line and 'SUM' in line:
                        sender_ipv4_unit = re.findall('[\d.]+ [GM]',line)[-1]
                        sender_ipv4 = float(sender_ipv4_unit.split(' ')[0])
                        if sender_ipv4_unit.endswith('G'):
                            sender_ipv4 = sender_ipv4 * 1000
                    elif 'receiver' in line and 'SUM' in line:
                        receiver_ipv4_unit = re.findall('[\d.]+ [GM]',line)[-1]
                        receiver_ipv4 = float(receiver_ipv4_unit.split(' ')[0])
                        if receiver_ipv4_unit.endswith('G'):
                            receiver_ipv4 = receiver_ipv4 * 1000
                self.log.info("sender:{} receiver:{}".format(sender_ipv4_unit,receiver_ipv4_unit))
                expect_ratio = 30
                utils_lib.compare_nums(self, perf_spec, sender_ipv4, expect_ratio, msg="Sender")
                utils_lib.compare_nums(self, perf_spec, receiver_ipv4, expect_ratio, msg="Receiver")

    def test_tcp_checksum_offload(self):
        """
        case_name:
            test_tcp_checksum_offload
        case_tags:
            network
        case_status:
            approved
        title:
            TCP checksum offload check
        importance:
            low
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            polarion_XXXX
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            integration
        bug_id:
            bugzilla_2211258
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
           component
        maintainer:
            xiliang@redhat.com
        description: |
            TCP checksum offload check
        key_steps: |
            # ethtool -k eth0|grep checksum
            # yum install nmap-ncat or nc
            # yum install kernel-modules-extra
            # nc -l 2233 > data2 (node 2)
            # nc ${IPv6/4 adress of guest2} 2233 < data1 (node 1)
            # nc -6 fe80::215:5dff:fec4:172c%eth0 2233 < data1
            # tc qdisc add dev eth0 root netem corrupt 1% (node 1)
            # md5sum data2 == md5sum data1

        expected_result: |
            data2 and data1 has same md5sum
        debug_want: |
            # ethtool -i eth0
        """
        if self.vm and self.vm.provider == 'nutanix':
            if len(self.vm.prism.list_hosts_detail()["entities"])==1:
                self.skipTest('Need to test between VMs on different hosts')
            if len(self.vms) == 1:
                self._create_vm1()
            vm1_host_uuid = self.vm.prism.get_vm_by_uuid(self.vms[1]['uuid'])['host_uuid']
            if self.vms[0].vm_host_uuid() == vm1_host_uuid:
                self.log.info('vm1 host uuid %s is same with vm2: %s, do migration' % (self.vms[0].vm_host_uuid(), vm1_host_uuid))
                self.vm.migrate()
            if self.vm.vm1_ip not in self.params['remote_nodes']:
                self.params['remote_nodes'].append(self.vm.vm1_ip)
        if len(self.vms) > 1 and self.vm.provider != 'nutanix':
            if not self.vms[1].exists():
                self.vms[1].create()
            if self.vms[1].is_stopped():
                self.vms[1].start(wait=True)
            if self.vms[1].floating_ip and self.vms[1].floating_ip not in self.params['remote_nodes']:
                self.params['remote_nodes'].append(self.vms[1].floating_ip)
        if len(self.params['remote_nodes']) < 2:
            self.skipTest("2 nodes required, current IP bucket:{}".format(self.params['remote_nodes']))
        self.log.info("Current IP bucket:{}".format(self.params['remote_nodes']))
        k_ver = utils_lib.run_cmd(self,'uname -r').strip('\n')
        cmd = "sudo ethtool -k {} | grep checksum".format(self.active_nic)
        utils_lib.run_cmd(self, cmd)
        if 'not found' in utils_lib.run_cmd(self,'modinfo sch_netem'):
            if not 'debug' in k_ver:
                utils_lib.is_pkg_installed(self,'kernel-modules-extra-{}'.format(k_ver))
            else:
                utils_lib.is_pkg_installed(self,'kernel-debug-modules-extra-{}'.format(k_ver.rstrip('+debug')))
        utils_lib.is_cmd_exist(self,"nc")
        utils_lib.is_cmd_exist(self,"tc")
        utils_lib.init_connection(self, timeout=180, rmt_node=self.params['remote_nodes'][-1])
        utils_lib.is_cmd_exist(self,"nc", rmt_node=self.params['remote_nodes'][-1])
        utils_lib.is_cmd_exist(self,"tc", rmt_node=self.params['remote_nodes'][-1])
        cmd = "ip addr show {}".format(self.active_nic )
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, \
            msg='try to get {} ipv4 address'.format(self.active_nic ),rmt_node=self.params['remote_nodes'][-1])
        srv_ipv4 = re.findall('[\d.]{7,16}', output)[0]
        testfile_s = "/tmp/test_tcp_checksum_offload_s.data"
        testfile_c = "/tmp/test_tcp_checksum_offload_c.data"
        for i in [False, True]:
            nc_srv_cmd = 'sudo bash -c "nc -l 2233 > {} 2>&1 &"'.format(testfile_s)
            utils_lib.run_cmd(self, nc_srv_cmd, rmt_node=self.params['remote_nodes'][-1])
            cmd = "dd if=/dev/urandom of={} bs=1M count=500 status=progress".format(testfile_c)
            utils_lib.run_cmd(self,cmd,timeout=300,msg='create a 500M file')
            if i:
                utils_lib.run_cmd(self,'sudo modprobe sch_netem', msg='manually load sch_netem due to RHEL-52279')
                cmd = "sudo tc qdisc add dev {} root netem corrupt 1%".format(self.active_nic)
                utils_lib.run_cmd(self,cmd,expect_ret=0,msg='Test again with network corrupt 1%')
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
            nc_cli_cmd = 'nc {} 2233 < {}'.format(srv_ipv4,testfile_c)
            utils_lib.run_cmd(self, nc_cli_cmd, expect_ret=0, timeout=600)
            utils_lib.run_cmd(self,'ls -lai {}'.format(testfile_c))
            utils_lib.run_cmd(self,'ls -lai {}'.format(testfile_s),rmt_node=self.params['remote_nodes'][-1])
            cmd = "md5sum {}".format(testfile_c)
            md5_client = utils_lib.run_cmd(self, cmd).split(' ')[0]
            cmd = "md5sum {}".format(testfile_s)
            md5_server = utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1]).split(' ')[0]
            self.assertEqual(md5_client, md5_server)
            utils_lib.run_cmd(self,'rm -rf {}'.format(testfile_c),msg='delete the test data file')
            if i:
                cmd = "sudo tc qdisc delete dev {} root netem corrupt 1%".format(self.active_nic)
                utils_lib.run_cmd(self,cmd,msg='remove network corrupt setting')
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
            self.log.info("test {} tcp corrupt done".format(i and 'with' or 'without'))

    def test_unload_load_virtio(self):
        """
        case_tag:
            Network,Network_tier1
        case_name:
            test_unload_load_virtio
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_unload_load_virtio
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check nic name after unload and load nic driver.
        key_steps: |
            1. Add a new nic and remove the new .
            2. unload and load nic driver virtio_net and restart NetworkManager.
            3. Nic name will not change.
        expect_result:
            Nic name will not change after unload and load nic driver.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        if self.vm.provider in ['aws']:
            self.skipTest("No need to test on {}".format(self.vm.provider))
        self._test_unload_load_nic_driver('virtio')

    def test_unload_load_e1000(self):
        """
        case_tag:
            Network,Network_tier1
        case_name:
            test_unload_load_e1000
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_unload_load_e1000
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check nic name after unload and load nic driver.
        key_steps: |
            1. Add a new nic and remove the new .
            2. unload and load nic driver e1000 and restart NetworkManager.
            3. Nic name will not change.
        expect_result:
            Nic name will not change after unload and load nic driver.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        if self.vm.provider == 'nutanix' and self.vm.prism.machine_type == 'q35':
            self.skipTest('e1000 should not be supported by pcie-root-port')
        if self.vm.provider in ['aws']:
            self.skipTest("No need to test on {}".format(self.vm.provider))
        self._test_unload_load_nic_driver('e1000')

    def test_ethtool_K_offload(self):
        """
        case_tag:
            Network,Network_tier2
        case_name:
            test_ethtool_K_offload
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_ethtool_K_offload
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test use ethtool to change the offload parameters and other features of the specified network device in RHEL
        key_steps: |
            1. Launch a guest VM.
            2. Use command "$ sudo  ethtool -k eth0" to query currently state of protocol offload and other features.
            3. Use ethtool to turn off offload parameters and other features via command "$ sudo ethtool -K eth0 $feature off".
            4. Check currently state of offload and other features again.
            5. Use ethtool to turn on offload parameters and other features via command "$ sudo ethtool -K eth0 $feature on".
            6. Check currently state of offload and other features.
        expect_result:
            Each offload and features could be turned off and turned on again, and no exception, warn, fail or call trace in dmesg.
        debug_want:
            N/A
        """
        cmd = ' sudo  ethtool -k eth0'
        setting_out = utils_lib.run_cmd(self, cmd, msg='Show current settings.')
        cmd = 'sudo ethtool -i eth0'
        output = utils_lib.run_cmd(self, cmd, msg='Check network driver!')
        if 'driver: ena' in output:
            option_dict = {
                'tx': 'tx-checksumming',
                'sg': 'scatter-gather',
                'gso': 'generic-segmentation-offload',
                'gro': 'generic-receive-offload',
                'tx-nocache-copy': 'tx-nocache-copy',
                'rxhash': 'receive-hashing',
                'highdma': 'highdma'
            }
        elif 'driver: vif' in output:
            option_dict = {
                'sg': 'scatter-gather',
                'tso': 'tcp-segmentation-offload',
                'gso': 'generic-segmentation-offload',
                'gro': 'generic-receive-offload',
                'tx-nocache-copy': 'tx-nocache-copy'
            }
        elif 'driver: virtio_net' in output:
            option_dict = {
                'tx': 'tx-checksumming',
                'sg': 'scatter-gather',
                'tso': 'tcp-segmentation-offload',
                'gso': 'generic-segmentation-offload',
                'gro': 'generic-receive-offload',
                'tx-nocache-copy': 'tx-nocache-copy',
                'rx-gro-list': 'rx-gro-list',
                'rx-udp-gro-forwarding': 'rx-udp-gro-forwarding'
            }
        elif 'driver: gve' in output:
            option_dict = {
                'rx': 'rx-checksumming',
                'tx': 'tx-checksumming',
                'sg': 'scatter-gather',
                'tso': 'tcp-segmentation-offload',
                'gso': 'generic-segmentation-offload',
                'gro': 'generic-receive-offload',
                'tx-nocache-copy': 'tx-nocache-copy',
                'rx-gro-list': 'rx-gro-list',
                'rx-udp-gro-forwarding': 'rx-udp-gro-forwarding',
                'rxhash': 'receive-hashing',
                'highdma': 'highdma'
            }
        else:
            option_dict = {
                'rx': 'rx-checksumming',
                'tx': 'tx-checksumming',
                'sg': 'scatter-gather',
                'tso': 'tcp-segmentation-offload',
                'gso': 'generic-segmentation-offload',
                'gro': 'generic-receive-offload',
                'tx-gre-segmentation': 'tx-gre-segmentation',
                'tx-nocache-copy': 'tx-nocache-copy',
                'tx-ipip-segmentation': 'tx-ipip-segmentation',
                'tx-sit-segmentation': 'tx-sit-segmentation',
                'tx-udp_tnl-segmentation': 'tx-udp_tnl-segmentation',
                'tx-gre-csum-segmentation': 'tx-gre-csum-segmentation',
                'tx-udp_tnl-csum-segmentation': 'tx-udp_tnl-csum-segmentation',
                'tx-gso-partial': 'tx-gso-partial'
            }

        for option in option_dict.keys():
            if option_dict[option] not in setting_out:
                continue
            cmd = 'sudo ethtool -K eth0 %s off' % option
            utils_lib.run_cmd(self, cmd)
            cmd = 'sudo ethtool -k eth0'
            utils_lib.run_cmd(self, cmd, expect_kw="%s: off" % option_dict[option])
            cmd = 'sudo ethtool -K eth0 %s on' % option
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            cmd = 'sudo ethtool -k eth0'
            utils_lib.run_cmd(self, cmd, expect_kw="%s: on" % option_dict[option])

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') == 'aws', 'aws dedicated feature')
    def test_check_efa_device_driver(self):
        """
        case_tag:
            network,efa
        case_name:
            test_check_efa_device_driver
        case_file:
            test_network_test.py
        component:
            kernel
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Check EFA device can be listed and efa driver is loaded for the EFA enabled instance
        key_steps:
            1.# lspci|grep EFA
            2.# lsmod|grep efa
        expect_result:
            EFA device is listed and efa driver is loaded for the EFA enabled instance.
        debug_want:
            N/A
        """
        if not self.vm or self.vm.provider != "aws":
            self.skipTest("Skip test case since instance is not aws vm")
        run_cmd(self, 'modinfo efa', expect_ret=0, msg='get efa module info')
        run_cmd(self, 'modinfo ena', expect_ret=0, msg='get efa module info')
        if not self.vm.efa_support:
            self.skipTest('EFA is not supported on the instance ' + self.vm.instance_type)
        cmd = 'lspci|grep EFA && lsmod|grep efa'
        run_cmd(self, cmd, expect_ret=0, msg='check if EFA device exist and efa module is loaded')
        self.log.info('EFA device is found and efa driver is loaded on the instance ' + self.vm.instance_type)
            
    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') == 'aws', 'aws dedicated feature')
    def test_install_libfabric_check_efa_provider(self):
        """
        case_tag:
            network,efa
        case_name:
            test_install_libfabric_check_efa_driver_provider
        case_file:
            test_network_test.py
        component:
            kernel
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Install libfabric package and check if EFA provider exist in EFA-enabled instance
        key_steps: |
            1.# sudo yum install libfabric
            2.# fi_info -p efa
            3.# fi_pingpong -e rdm -p efa -I 100 & sleep 2; fi_pingpong -e rdm -p efa localhost -I 100
        expect_result:
            libfabric package is installed successfully and fi_info command should return information about the Libfabric EFA interfaces.
        debug_want:
            efa,libfabric
        """
        if not self.vm or self.vm.provider != "aws":
            self.skipTest("Skip test case since instance is not vm or aws")
        if not self.vm.efa_support:
            self.skipTest('EFA is not supported on the instance ' + self.vm.instance_type)
        if utils_lib.is_pkg_installed(self,'libfabric'):
            cmd = 'fi_info -p efa'
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="provider: efa", msg='Check the Libfabric EFA interfaces')
            cmd = "sudo  bash -c 'fi_pingpong -e rdm -p efa -I 100 & sleep 2; fi_pingpong -e rdm -p efa localhost -I 100'"
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='run pingpong test')

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') == 'aws', 'aws dedicated feature')        
    def test_load_unload_efa_driver(self):
        """
        case_tag:
            network,efa
        case_name:
            test_efa04_load_unload_efa_driver
        case_file:
            test_network_test.py
        component:
            kernel
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Check EFA driver can be unloaded and loaded again successfully
        key_steps:
            1.# sudo modprobe rdma_ucm
            2.# sudo modprobe -r efa && modprobe efa
            3.# sudo modprobe rdma_ucm
        expect_result:
            EFA driver can be unloaded and loaded again successfully
        debug_want:
            N/A
        """
        if not self.vm or self.vm.provider != "aws":
            self.skipTest("Skip test case since instance is not vm or aws")
        if not self.vm.efa_support:
            self.skipTest('EFA is not supported on the instance ' + self.vm.instance_type)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='sudo dmesg -T')
        cmd = 'sudo modprobe -r efa'
        run_cmd(self, cmd, ret_status=True, msg='unload efa driver')
        cmd = 'lsmod|grep efa'
        ret = run_cmd(self, cmd, ret_status=True, msg='check if efa driver is unloaded')
        if ret == 1:
            self.log.info('efa driver is unloaded successfully')
        cmd = 'sudo modprobe efa'
        run_cmd(self, cmd, ret_status=True, msg='reload efa driver')
        cmd = 'lsmod|grep efa'
        ret = run_cmd(self, cmd, ret_status=True, msg='check if EFA driver is loaded')
        utils_lib.check_log(self, "error,warn,fail,trace,Trace", log_cmd='sudo dmesg -T', cursor=self.dmesg_cursor)
        if ret == 0:
            self.log.info('efa driver is loaded successfully')

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') == 'aws', 'aws dedicated feature')
    def test_attach_detach_efa_device(self):
        """
        case_tag:
            network,efa
        case_name:
            test_attach_detach_efa_device
        case_file:
            test_network_test.py
        component:
            kernel
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Check EFA device can be attached and detached
        key_steps: |
            1.# Create an EFA network interface
            2.# Allocate an Elastic IP
            3.# Launch an instance which supports EFA but EFA is not enabled, check EFA is disabled
            4.# Stop the instance, Associate Elastic IP to the instance
            5.# Attach EFA network interface to the instance,
            6.# Start the instance, check EFA is enabled for the instance
            7.# Stop the instance, detach EFA Network Interface
            8.# Start the instance,check EFA is disabled for the instance
            9.# Delete EFA network Interface and release Elastic IP
        expect_result:
            EFA driver can be attached and detached successfully
        debug_want:
            N/A
    	"""
        if not self.vm:
            self.skipTest("Skip test case since instance is not vm")
        if not self.vm.efa_support:
            self.skipTest('EFA is not supported on the instance ' + self.vm.instance_type)
        if self.vms:
            self.vms[1].create(enable_efa=False)
            if self.vms[1].is_stopped():
                self.vms[1].start(wait=True)
            utils_lib.init_connection(self, timeout=self.ssh_timeout, vm=self.vms[1])
            run_cmd(self, 'lspci|grep EFA', expect_ret=1, vm=self.vms[1])

            # Create EFA network interface and allocate elastic ip
            self.nic.create(interfaceType='efa')
            self.nic.allocate_eip()

            # Associate elastic ip  and attach EFA network interface to the instance
            instance_id = run_cmd(self, 'cat /var/lib/cloud/data/instance-id', vm=self.vms[1])
            self.vms[1].stop(wait=True)
            self.log.info('start associating elastic ip to the instance')
            self.nic.associate_eip(instance_id.strip())
            self.log.info('start attaching network interface')
            self.nic.attach_to_instance(instance_id.strip(),1)

            # Check if EFA network interface is attached successfully
            self.log.info('start vms[1]')
            self.vms[1].start(wait=True)
            utils_lib.init_connection(self, timeout=self.ssh_timeout, vm=self.vms[1])
            run_cmd(self, 'lspci|grep EFA', expect_ret=0, vm=self.vms[1])

            # Release elastic ip
            self.vms[1].stop(wait=True)
            self.vms[1].delete(wait=True)
            self.nic.release_eip()

    def test_scp_mtu_9000(self):
        """
        case_tag:
            Network,Network_tier2
        case_name:
            test_scp_mtu_9000
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_scp_mtu_9000
        component:
            Network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test SCP a large file (size 5G) with MTU = 9000.
        key_steps:
            SCP a large file (size 5G) with MTU = 9000.
        expect_result:
            SCP a large file (size 5G) with MTU = 9000 successful.
        debug_want:
            N/A
        """
        for attrname in ['host_ip']:
            if not hasattr(self.vm, attrname):
                self.skipTest("no {} for {} vm".format(attrname, os.getenv('INFRA_PROVIDER')))
        #change vm's mtu
        vm_host_ip = self.vm.host_ip
        self.log.info("vm host ip is %s" %vm_host_ip)
        host_mtu_check = utils_lib.send_ssh_cmd(vm_host_ip, self.vm.host_username, self.vm.host_password, "ifconfig | grep 9000")
        if 'mtu 9000' not in host_mtu_check[1]:
            self.skipTest("MTU of the vm host is not 9000")
        utils_lib.is_pkg_installed(self,"net-tools")
        utils_lib.run_cmd(self, 'sudo ifconfig %s mtu 9000' % self.active_nic, expect_ret=0)
        if len(self.vms) == 1:
            self._create_vm1()
        vm1_host_uuid = self.vm.prism.get_vm_by_uuid(self.vms[1]['uuid'])['host_uuid']
        if self.vms[0].vm_host_uuid() != vm1_host_uuid:
            self.log.info('vm1 host uuid %s is different with vm2: %s, do migration' % (self.vms[0].vm_host_uuid(), vm1_host_uuid))
            self.vm.migrate(host_uuid=vm1_host_uuid, wait=True)
        utils_lib.init_connection(self, timeout=180, rmt_node=self.vm.vm1_ip)
        utils_lib.run_cmd(self, 'sudo yum install -y net-tools', rmt_node=self.vm.vm1_ip, timeout=180)
        utils_lib.run_cmd(self, 'sudo ifconfig %s mtu 9000' % self.active_nic, expect_ret=0, rmt_node=self.vm.vm1_ip)
        #create key
        key_file_check = utils_lib.run_cmd(self, "ls ~/.ssh/id_rsa.pub")
        if 'No such file or directory' in key_file_check:
            utils_lib.run_cmd(self, "ssh-keygen -f ~/.ssh/id_rsa -N ''", expect_ret=0)
        id_rsa_pub_key = utils_lib.run_cmd(self, 'cat ~/.ssh/id_rsa.pub')
        utils_lib.run_cmd(self,"echo '''%s''' > ~/.ssh/authorized_keys" % id_rsa_pub_key, rmt_node=self.vm.vm1_ip)
        utils_lib.run_cmd(self, 'dd if=/dev/zero of=5G.img bs=1M count=5222', timeout=600)
        scp_cmd = 'scp -o StrictHostKeyChecking=no 5G.img {}@{}:~'.format(self.vm.vm_username, self.vm.vm1_ip)
        utils_lib.run_cmd(self, scp_cmd, expect_ret=0, timeout=900)
        file_size = int(utils_lib.run_cmd(self, "ls -l ~/5G.img | awk '{print $5}'", expect_ret=0).strip())/(1024*1024*1024)
        self.assertAlmostEqual(first=5, second=file_size, delta=0.1, msg="Value of copied file is not right, Expect: 5, real: %s" % (file_size))

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') == 'aws', 'aws dedicated feature')
    def test_mpi_app_via_efa_provider(self):
        """
        case_tag:
            network,efa
        case_name:
            test_mpi_app_via_efa_provider
        case_file:
            test_network_test.py
        component:
            kernel
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Check MPI app run via efa provider
        key_steps: |
            1.# sudo yum install libfabric
            2.# sudo yum install openmpi
            3.# git clone https://github.com/mpitutorial/mpitutorial && cd mpitutorial/tutorials/mpi-hello-world/code/
            4.# export PATH=$PATH:/usr/lib64/openmpi/bin && cd ~/mpitutorial/tutorials/mpi-hello-world/code/
            5.# make
            6.# export OMPI_MCA_mtl_base_verbose=100 && /usr/lib64/openmpi/bin/mpirun ~/mpitutorial/tutorials/mpi-hello-world/code/mpi_hello_world
        expect_result:
            MPI application run via efa provider
        debug_want:
            efa,libfabric
        """
        if not self.vm:
            self.skipTest("Skip test case since instance is not vm")

        if not self.vm.efa_support:
            self.skipTest('EFA is not supported on the instance ' + self.vm.instance_type)
        if utils_lib.is_pkg_installed(self, 'libfabric'):
            if utils_lib.is_pkg_installed(self,'openmpi'):
                if utils_lib.is_pkg_installed(self,'git'):
                    cmd = 'git clone https://github.com/mpitutorial/mpitutorial && cd mpitutorial/tutorials/mpi-hello-world/code/'
                    utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Download OPENMPI Hello_world App')
                    if utils_lib.is_pkg_installed(self,'make'):
                        cmd = 'export PATH=$PATH:/usr/lib64/openmpi/bin && cd ~/mpitutorial/tutorials/mpi-hello-world/code/ && make && export OMPI_MCA_mtl_base_verbose=100 && /usr/lib64/openmpi/bin/mpirun ~/mpitutorial/tutorials/mpi-hello-world/code/mpi_hello_world'
                        utils_lib.run_cmd(self, cmd, expect_ret=0,expect_kw="provider: efa_0-rdm",msg='Check MPI app run via efa provider')

    def test_pktgen_sh(self):
        """
        case_tag:
            Network,Network_tier2
        case_name:
            test_pktgen_sh
        case_file:
            os_tests.tests.test_netwrok_test.TestNetworkTest.test_pktgen_sh
        component:
            network
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test pktgen script.
        key_steps:
            Run pktgen script.
        expect_result:
            All cases passed.
        debug_want:
            N/A
        """
        if utils_lib.is_aws(self) or utils_lib.is_gcp(self):
            self.skipTest("Unable to download pkg from internal site now")
        check_file = self.utils_dir + '/nw_pktgen.sh'
        check_file_tmp = '/tmp/nw_pktgen.sh'
        if self.params.get('remote_node') is not None:
            cmd = 'ls -l {}'.format(check_file_tmp)
            ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='check if {} exists'.format(check_file))
            if ret != 0:
                self.SSH.put_file(local_file=check_file, rmt_file=check_file_tmp)
        else:
            cmd = 'sudo cp -f {} {}'.format(check_file,check_file_tmp)
            utils_lib.run_cmd(self, cmd)
        utils_lib.run_cmd(self,"sudo chmod 755 %s" % check_file_tmp)
        res = utils_lib.run_cmd(self,"sudo /tmp/nw_pktgen.sh %s" % self.rhel_x_version)
        self.assertIn("INFO: Case passed", res, "nw_pktgen.sh check failed.")

    def test_network_device_hotplug(self):
        """
        case_tag:
            network
        case_name:
            test_network_device_hotplug
        case_file:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_vm_operation.py
        component:
            network
        bugzilla_id:
            2004072
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Test hotplug network interface to RHEL.
        key_steps: |
            1. Launch an instance.
            2. Attach a network interface to the instance, check the network appears in guest, e.g., "$ sudo lspci", "$ sudo ip addr show".
            3. Detach the network interface from the instance, check the network disappears in guest again.
            4. Check dmesg log of the instance.
        expect_result: |
            When the second network interface is attached in step 2, there are 2 Elastic Network Adapters displays in PCI devices, and the IP address are auto assigned to the device.
            When the second network interface is detached in step 3, there are 1 Elastic Network Adapters displays in PCI devices, and only 1 NIC displays when showing ip information.
            No crash or panic in system, no related error message or call trace in dmesg.
        debug_want: |
            network driver type and version
            dmesg
        """
        if not self.nic:
            self.skipTest('nic device not init')
        try:
            if not self.nic.create():
                self.fail("network interface create failed")
        except NotImplementedError:
            self.skipTest('nic create func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('nic create func is not supported in {}'.format(self.vm.provider))

        cmd = "ip -o link show|wc -l"
        nic_num_1 = utils_lib.run_cmd(self,cmd)
        self.vm.attach_nic(self.nic,device_index=1, wait=True)
        for i in range(1, 4):
            time.sleep(5)
            self.log.info('Check network in guest, loop {}'.format(i))
            utils_lib.run_cmd(self, 'lspci')
            utils_lib.run_cmd(self, 'ip addr show')
            nic_num_2 = utils_lib.run_cmd(self,cmd)
            if nic_num_2 == nic_num_1:
                self.log.info("Added nic not found")
        timeout = 120
        interval = 5
        time_start = int(time.time())
        while True:
           if self.vm.detach_nic(self.nic):
               break
           time_end = int(time.time())
           if time_end - time_start > timeout:
              self.log.info('timeout ended: {}'.format(timeout))
              break
           self.log.info('retry after {}s'.format(interval))
           time.sleep(interval)
        time.sleep(5)
        cmd = "ip addr show"
        utils_lib.run_cmd(self,cmd)
        self.nic.delete()
        self.assertGreater(nic_num_2,nic_num_1,msg='New added network device not found after attached nic')
        cmd = 'sudo dmesg'
        utils_lib.run_cmd(self, cmd, expect_not_kw='Call Trace')

    def test_second_ip_hotplug(self):
        '''
        description:
            [RHEL8.4] Test 2nd ip hotplug on primary nic, nm-cloud-setup can assign/remove it automatically
        bug_id:
            bugzilla_1623084,bugzilla_1642461,bugzilla_2179718
        is_customer_case:
            True
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            network
        key_steps: |
            1. Launch an instance on AWS EC2/Alicloud/Azure/GCP.
            2. Check if package NetworkManager-cloud-setup is installed via command "$ sudo rpm -q NetworkManager-cloud-setup", if not, use yum install to install it.
            3. Check the service status via command "$ sudo systemctl status nm-cloud-setup.timer".
            4. Assign the second IP to the NIC of instance.
            5. Check the ip address of the NIC for several times via command "$ sudo ip addr show eth0".
            6. Remove the second IP from the NIC of instance.
            7. Check if the second IP address is removed from the NIC.
        pass_criteria: |
            After the second IP is assigned to the NIC of instance in step 4, there will be 2 IP address shows in step5.
            After the second IP is removed from the NIC of instance 6, there will be only 1 IP address shows in the step7.
        debug_want: |
            Attach trace log from nm-cloud-setup when case fail.
            - Run "systemctl edit nm-cloud-setup" uncomment "Environment=NM_CLOUD_SETUP_LOG=TRACE"
            - "systemctl daemon-reload"
            - systemctl restart nm-cloud-setup.service
            - journalctl -u nm-cloud-setup.service
            - AWS only(ensure infra assign it): curl 169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/local-ipv4s
            imdsv2: TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
            curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/local-ipv4s
            https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html

        '''
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        utils_lib.is_pkg_installed(self, pkg_name='NetworkManager-cloud-setup', is_install=True, cancel_case=True)
        for attrname in ['assign_secondary_ips','remove_secondary_ips']:
            if not hasattr(self.vm, attrname):
                self.skipTest("no {} for {} vm".format(attrname, self.vm.provider))

        utils_lib.imds_tracer_tool(self, timeout=10, interval=5, log_check=False)
        if self.vm.provider == 'ali':
            config_file = self.utils_dir + '/nm_cloud_setup.sh'
            config_file_tmp = '/tmp/nm_cloud_setup.sh'
            if self.params.get('remote_node') is not None:
                cmd = 'ls -l {}'.format(config_file_tmp)
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='check if {} exists'.format(config_file))
                if ret != 0:
                    self.SSH.put_file(local_file=config_file, rmt_file=config_file_tmp)
            else:
                cmd = 'sudo cp -f {} {}'.format(config_file,config_file_tmp)
                utils_lib.run_cmd(self, cmd)
            utils_lib.run_cmd(self,'sudo chmod 755 {}'.format(config_file_tmp))
            utils_lib.run_cmd(self,'sudo {} ALIYUN'.format(config_file_tmp), rmt_get_pty=True)

        utils_lib.run_cmd(self, 'systemctl cat nm-cloud-setup')
        cmd = 'sudo systemctl enable --now nm-cloud-setup.timer'
        utils_lib.run_cmd(self, cmd)
        cmd = 'sudo systemctl status nm-cloud-setup.timer'
        utils_lib.run_cmd(self, cmd)
        self.vm.assign_secondary_ips()
        if not self.vm.secondary_ip_list:
            self.fail('assign single secondary ip failed on {}'.format(self.vm.provider))

        cmd = 'sudo ip addr show {}'.format(self.active_nic)
        start_time = time.time()
        tmp_ip = self.vm.secondary_ip_list[0]
        while True:
            out = utils_lib.run_cmd(self, cmd)
            if tmp_ip in out:
                break
            end_time = time.time()
            if end_time - start_time > 330:
                cmd = 'sudo systemctl status nm-cloud-setup.timer'
                utils_lib.run_cmd(self, cmd)
                cmd = 'journalctl -u nm-cloud-setup'
                utils_lib.run_cmd(self, cmd)
                utils_lib.imds_tracer_tool(self, timeout=10, interval=5, log_check=False)
                self.fail("expected secondary ip {} is not found in guest".format(tmp_ip))
            time.sleep(25)
        cmd = "sudo ip addr show {}|grep -oP 'inet \K[^/]+'".format(self.active_nic)
        start_time = time.time()
        self.vm.remove_secondary_ips()
        while True:
            out = utils_lib.run_cmd(self, cmd)
            if tmp_ip not in out.split('\n'):
                break
            end_time = time.time()
            if end_time - start_time > 330:
                cmd = 'sudo systemctl status nm-cloud-setup.timer'
                utils_lib.run_cmd(self, cmd)
                cmd = 'journalctl -u nm-cloud-setup'
                utils_lib.run_cmd(self, cmd)
                self.fail("expected secondary ip {} is not removed from guest".format(tmp_ip))
            time.sleep(25)
        utils_lib.imds_tracer_tool(self, timeout=10, interval=5)

    def test_second_ip_hotplug_multi(self):
        """
        case_name:
            test_second_ip_hotplug_multi
        case_tags:
            network
        case_status:
            approved
        title:
            assign/remove multiple secondary ip addresses
        importance:
            medium
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            N/A
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            component
        bug_id:
            bugzilla_1623084,bugzilla_1642461,bugzilla_2179718
        is_customer_case:
            False
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            yoguo@redhat.com
        description: |
            Test multiple secondary IPs hotplug on primary nic, nm-cloud-setup can assign/remove them automatically
        key_steps: |
            1. Launch an instance on AWS EC2/AliCloud/Azure/GCP.
            2. Check if package NetworkManager-cloud-setup is installed via command "$ sudo rpm -q NetworkManager-cloud-setup", if not, use yum to install it.
            3. Check the service status via command "$ sudo systemctl status nm-cloud-setup.timer".
            4. Assign multiple secondary IPs to the NIC of instance.
            5. Check the ip addresses of the NIC for several times via command "$ sudo ip addr show eth0".
            6. Remove the secondary IPs from the NIC of instance.
            7. Check if the secondary IPs are removed from the NIC.
        pass_criteria: |
            After multiple secondary IPs are assigned to the NIC of instance in step 4, there will be corresponding IP addresses that show in step 5.
            After multiple secondary IPs are removed from the NIC of instance in step 6, there will be only 1 primary IP address that shows in step 7.
        debug_want: |
            Attach trace log from nm-cloud-setup when case fail.
            - Run "systemctl edit nm-cloud-setup" uncomment "Environment=NM_CLOUD_SETUP_LOG=TRACE"
            - systemctl daemon-reload
            - systemctl restart nm-cloud-setup.service
            - journalctl -u nm-cloud-setup.service
            - AWS only(ensure infra assign it): curl 169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/local-ipv4s
            - AliCloud only: curl 100.100.100.200/latest/meta-data/network/interfaces/macs/$MAC/private-ipv4s
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        utils_lib.is_pkg_installed(self, pkg_name='NetworkManager-cloud-setup', is_install=True, cancel_case=True)
        for attrname in ['assign_secondary_ips','remove_secondary_ips']:
            if not hasattr(self.vm, attrname):
                self.skipTest("no {} for {} vm".format(attrname, self.vm.provider))

        utils_lib.imds_tracer_tool(self, timeout=10, interval=5, log_check=False)
        # Default value
        secondary_ip_count = 10
        if self.vm.provider == 'ali':
            secondary_ip_count = self.vm.private_ip_quantity - 1
            config_file = self.utils_dir + '/nm_cloud_setup.sh'
            config_file_tmp = '/tmp/nm_cloud_setup.sh'
            if self.params.get('remote_node') is not None:
                cmd = 'ls -l {}'.format(config_file_tmp)
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='check if {} exists'.format(config_file))
                if ret != 0:
                    self.SSH.put_file(local_file=config_file, rmt_file=config_file_tmp)
            else:
                cmd = 'sudo cp -f {} {}'.format(config_file,config_file_tmp)
                utils_lib.run_cmd(self, cmd)
            utils_lib.run_cmd(self,'sudo chmod 755 {}'.format(config_file_tmp))
            utils_lib.run_cmd(self,'sudo {} ALIYUN'.format(config_file_tmp), rmt_get_pty=True)

        utils_lib.run_cmd(self, 'systemctl cat nm-cloud-setup')
        cmd = 'sudo systemctl status nm-cloud-setup.timer'
        utils_lib.run_cmd(self, cmd)
        self.vm.assign_secondary_ips(secondary_ip_count)
        if not self.vm.secondary_ip_list:
            self.fail('assign multiple secondary ips failed on {}'.format(self.vm.provider))

        cmd = 'sudo ip addr show {}'.format(self.active_nic)
        start_time = time.time()
        ip_count = 0
        while True:
            out = utils_lib.run_cmd(self, cmd)
            for ip in self.vm.secondary_ip_list:
                if not ip in out:
                    break
                else:
                    ip_count += 1
                    continue
            if ip_count == len(self.vm.secondary_ip_list):
                break
            end_time = time.time()
            if end_time - start_time > 330:
                cmd = 'sudo systemctl status nm-cloud-setup.timer'
                utils_lib.run_cmd(self, cmd)
                cmd = 'journalctl -u nm-cloud-setup'
                utils_lib.run_cmd(self, cmd)
                utils_lib.imds_tracer_tool(self, timeout=10, interval=5, log_check=False)
                self.fail("expected secondary ips {} are not found completely in guest".format(str(self.vm.secondary_ip_list)))
            time.sleep(25)

        cmd = "sudo ip addr show {}|grep -oP 'inet \K[^/]+'".format(self.active_nic)
        start_time = time.time()
        tmp_ips = self.vm.secondary_ip_list
        self.vm.remove_secondary_ips()
        ip_count = len(tmp_ips)
        while ip_count > 0: 
            out = utils_lib.run_cmd(self, cmd)
            for ip in tmp_ips:  
                for network in out.split('\n'):  
                    if ip == network:    
                        break  
                else:  
                    ip_count -= 1   
                    continue   

            if ip_count == 0:  
                break
        end_time = time.time()
        
        self.log.info('------finally ip address list------')
        utils_lib.run_cmd(self, cmd)

        if end_time - start_time > 330:
            cmd = 'sudo systemctl status nm-cloud-setup.timer'
            utils_lib.run_cmd(self, cmd)
            cmd = 'journalctl -u nm-cloud-setup'
            utils_lib.run_cmd(self, cmd)
            self.fail("expected secondary ips {} are not removed completely from guest".format(str(tmp_ips)))
        time.sleep(25)
        utils_lib.imds_tracer_tool(self, timeout=10, interval=5)

    def test_network_device_hotplug_multi(self):
        """
        case_tag:
            network
        case_name:
            test_network_device_hotplug_multi
        case_file:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py
        component:
            network
        bugzilla_id:
            2207812
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            libhe@redhat.com
        description:
            Test hotplug multiple network interface to RHEL.
        key_steps: |
            1. Launch an instance.
            2. Attach multiple network interfaces to the instance, check the network appears in guest, e.g., "$ sudo lspci", "$ sudo ip addr show".
            3. Detach the network interfaces from the instance, check the network disappears in guest again.
            4. Check network connection
            5. Check dmesg log of the instance.
        expect_result: |
            When multiple network interfaces are attached in step 2, there are multiple Elastic Network Adapters displays in PCI devices, and the IP address are auto assigned to the device.
            When multiple network interfaces are detached in step 3, there are 1 Elastic Network Adapters displays in PCI devices, and only 1 NIC displays when showing ip information.
            No crash or panic in system, no related error message or call trace in dmesg.
            No network connection lost when attach network interfaces 
        debug_want: |
            network driver type and version
            nm-cloud-setup
            dmesg
        """
        if not self.nics:
            self.skipTest('nic device not init')
        
        i = 1
        for nic in self.nics: 
            try:
                if not nic.is_exist():
                    if not nic.create():
                        self.fail("network interface create failed")
            except NotImplementedError:
                self.skipTest('nic create func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('nic create func is not supported in {}'.format(self.vm.provider))

            cmd = "ip -o link show|wc -l"
            nic_num_1 = int(utils_lib.run_cmd(self,cmd))
            utils_lib.run_cmd(self,'ip rule show')

            if not self.vm.attach_nic(nic, device_index=i, wait=True):
                nic_num_1 = nic_num_1 - 1
                break
            else:
                i = i + 1
            
            for j in range(1, 4):
                time.sleep(5)
                self.log.info('Check network in guest, loop {}'.format(j))
                utils_lib.run_cmd(self, 'lspci')
                utils_lib.run_cmd(self, 'ip addr show')
                nic_num_2 = int(utils_lib.run_cmd(self, cmd))
                if nic_num_2 == nic_num_1:
                    self.log.info("Added nic not found")

            utils_lib.run_cmd(self,'ip rule show')
            time.sleep(60)
            if utils_lib.init_connection(self,timeout=60):
                self.log.info("Network connection is live when attach NO.{} network interface.".format(i))

        for nic in self.nics:
            self.vm.detach_nic(nic)
            utils_lib.run_cmd(self, 'lspci')
            utils_lib.run_cmd(self, 'ip addr show')

        self.assertGreater(nic_num_2,nic_num_1,msg='New added network device not found after attached nic')
        cmd = 'sudo dmesg'
        utils_lib.run_cmd(self, cmd, expect_not_kw='Call Trace')

    def test_veth_nic_rx(self):
        """
        case_name:
            test_veth_nic_rx
        case_tags:
            network,kernel
        case_status:
            approved
        title:
            make sure no log spam produced when veth and nic has different rx setting
        importance:
            low
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            jira_RHEL-14286
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py
        setup_teardown:
            N/A
        environment:
            N/A
        component:
            component
        bug_id:
            jira_RHEL-14286
        is_customer_case:
            True
        testplan:
            N/A
        test_type:
            functional
        test_level:
           component
        maintainer:
            xiliang@redhat.com
        description: |
            make sure no log spam produced when veth and nic has different rx setting
        key_steps: |
            - Create a veth pair and set the number of TX queues to 16.
            - Create a bridge interface.
            - Attach one of the veth interfaces to the bridge.
            - Attach the ena/other interface to the bridge.
            - run ping.
        expected_result: |
            no "but real number of TX queues" continusly produced
        debug_want: |
            dmesg
        """
        veth_nic_rx = self.utils_dir + '/veth_nic_rx.sh'
        veth_nic_rx_run = '/tmp/veth_nic_rx.sh'
        if self.params.get('remote_node') is not None:
            self.SSH.put_file(local_file=veth_nic_rx, rmt_file=veth_nic_rx_run)
        else:
            cmd = 'sudo cp -f {} {}'.format(veth_nic_rx,veth_nic_rx_run)
            utils_lib.run_cmd(self, cmd)
        utils_lib.run_cmd(self,"sudo chmod 755 %s" % veth_nic_rx_run)
        utils_lib.run_cmd(self,'sudo bash -c "{} {}"'.format(veth_nic_rx_run, self.active_nic), timeout=500, msg='the system might loss connection if the script cannot finish normally.')
        utils_lib.init_connection(self, timeout=180)
        utils_lib.run_cmd(self,"sudo dmesg", expect_not_kw="but real number of TX queues")

    def test_xdp_tools_run_tests(self):
        """
        case_name:
            test_xdp_tools_run_tests
        case_tags:
            network
        case_status:
            approved
        title:
            call /usr/share/xdp-tools/run_tests.sh to sanity test xdp module
        importance:
            low
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            n/a
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            N/A
        is_customer_case:
            False
        testplan:
            n/a
        test_type:
            functional
        test_level:
            component
        maintainer:
            xiliang@redhat.com
        description: |
            call /usr/share/xdp-tools/run_tests.sh to sanity test xdp module
        key_steps: |
            # yum install -y xdp-tools wireshark-cli tcpdump nmap-ncat
            # ethtool -L eth0 combined 2
            # ip link set eth0 mtu 2000
            # nc -6 -l 5000 -v
            # xdp-trafficgen tcp -p 5000 -i eth0 2600:1f14:5b3:ec11:5dd6:bdce:172c:f322
        expected_result: |
            all tests pass
            #/usr/share/xdp-tools/run_tests.sh
            Running all tests from /usr/share/xdp-tools/tests
                Running tests from /usr/share/xdp-tools/tests/xdp-bench/test-xdp-bench.sh
                 [test_drop]                   PASS
                 [test_pass]                   PASS
                 [test_tx]                     PASS
                 [test_xdp_load_bytes]         PASS
            ........
            ........

        debug_want: |
            1. # uname -r
            2. # ethtool -i $nic
            3. # rpm -q xdp-tools (if fail at xdp-tools)
            4. # xdp-loader $cmd -vv
        """
        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
        if float(product_id) < 9.0 and utils_lib.is_arch(self, arch='aarch64'):
            self.skipTest("xdp-tools does not supports aarch64 before rhel-9")
        utils_lib.is_pkg_installed(self, pkg_name='xdp-tools', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='wireshark-cli', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='tcpdump', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='nmap-ncat', is_install=True, cancel_case=True)

        utils_lib.run_cmd(self, 'sudo /usr/share/xdp-tools/run_tests.sh', expect_not_kw='fail,FAIL', timeout=900)

    def test_xdp_tools_xdp_trafficgen(self):
        """
        case_name:
            test_xdp_tools_xdp_trafficgen
        case_tags:
            network
        case_status:
            approved
        title:
            Use xdp-trafficgen to test xdp over 2 nodes
        importance:
            low
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            n/a
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_network_test.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            jira_RHEL-28811
        is_customer_case:
            False
        testplan:
            n/a
        test_type:
            functional
        test_level:
            component
        maintainer:
            xiliang@redhat.com
        description: |
            Use xdp-trafficgen to test xdp over 2 nodes
        key_steps: |
            # yum install -y xdp-tools wireshark-cli tcpdump nmap-ncat
            # ethtool -L eth0 combined 2
            # ip link set eth0 mtu 2000
            # nc -6 -l 5000 -v
            # xdp-trafficgen tcp -p 5000 -i eth0 2600:1f14:5b3:ec11:5dd6:bdce:172c:f322
        expected_result: |
            there is xdp traffic between 2 nodes
            eg. [root@ip-10-116-1-146 ec2-user]# timeout 60 xdp-trafficgen tcp -p 5000 -i eth0 2600:1f14:5b3:ec11:a63:5c40:1ab4:bc45
              Connected to 2600:1f14:5b3:ec11:a63:5c40:1ab4:bc45 port 5000 from 2600:1f14:5b3:ec11:43ad:1e65:2e34:41fa port 45492
              lo->eth0                        0 err/s             2,648 xmit/s       
              lo->eth0                        0 err/s                37 xmit/s       
              lo->eth0                        0 err/s                 0 xmit/s         
        debug_want: |
            1. # uname -r
            2. # ethtool -i $nic
            3. # rpm -q xdp-tools (if fail at xdp-tools)
            4. # xdp-loader $cmd -vv
        """
        cmd = "sudo ethtool -l {}|grep Combined|uniq".format(self.active_nic )
        out = utils_lib.run_cmd(self, cmd)
        if 'not supported' in out:
            self.skipTest("skip as {}:{}".format(self.active_nic,out))
        queue_count = out.split()[-1]
        if int(queue_count) < 2:
            self.skipTest("skip when queue count smaller than 2, current {}".format(queue_count))
        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
        if float(product_id) < 9.0 and utils_lib.is_arch(self, arch='aarch64'):
            self.skipTest("xdp-tools does not supports aarch64 before rhel-9")
        if not self.vm:
            self.skipTest('this case requires vms currently')
        if self.vm and not self.vm.ipv6_address:
            self.skipTest('only supports with ipv6 assigned')

        if self.vm and self.vm.provider == 'nutanix':
            if len(self.vm.prism.list_hosts_detail()["entities"])==1:
                self.skipTest('Need to test between VMs on different hosts')
            if len(self.vms) == 1:
                self._create_vm1()
            vm1_host_uuid = self.vm.prism.get_vm_by_uuid(self.vms[1]['uuid'])['host_uuid']
            if self.vms[0].vm_host_uuid() == vm1_host_uuid:
                self.log.info('vm1 host uuid %s is same with vm2: %s, do migration' % (self.vms[0].vm_host_uuid(), vm1_host_uuid))
                self.vm.migrate()
            if self.vm.vm1_ip not in self.params['remote_nodes']:
                self.params['remote_nodes'].append(self.vm.vm1_ip)
        if len(self.vms) > 1 and self.vm.provider != 'nutanix':
            if not self.vms[1].exists():
                self.vms[1].create()
            if self.vms[1].is_stopped():
                self.vms[1].start(wait=True)
            if self.vms[1].floating_ip and self.vms[1].floating_ip not in self.params['remote_nodes']:
                self.params['remote_nodes'].append(self.vms[1].floating_ip)
        if len(self.params['remote_nodes']) < 2:
            self.skipTest("2 nodes required, current IP bucket:{}".format(self.params['remote_nodes']))
        self.log.info("Current IP bucket:{}".format(self.params['remote_nodes']))

        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
        cmd = "sudo ethtool -i {}".format(self.active_nic )
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if 'ena' in output:
            self.log.info('ena driver found!')
            if float(product_id) > 8.4 or product_id == '8.10':
                cmd = "ethtool -S {}|grep xdp".format(self.active_nic )
                utils_lib.run_cmd(self, cmd, expect_ret=0,msg='Check if have xdp information')
            else:
                self.skipTest('ena driver does not support xdp prior to 8.4')
        else:
            cmd = "ethtool -S {}|grep xdp".format(self.active_nic )
            utils_lib.run_cmd(self, cmd, cancel_ret='0', msg='Check if have xdp support')
        utils_lib.is_pkg_installed(self, pkg_name='xdp-tools', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='wireshark-cli', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='tcpdump', is_install=True, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='nmap-ncat', is_install=True, cancel_case=True)
        utils_lib.init_connection(self, timeout=180, rmt_node=self.params['remote_nodes'][-1])
        utils_lib.is_pkg_installed(self, pkg_name='xdp-tools', is_install=True, cancel_case=True, rmt_node=self.params['remote_nodes'][-1])
        utils_lib.is_pkg_installed(self, pkg_name='wireshark-cli', is_install=True, cancel_case=True, rmt_node=self.params['remote_nodes'][-1])
        utils_lib.is_pkg_installed(self, pkg_name='tcpdump', is_install=True, cancel_case=True, rmt_node=self.params['remote_nodes'][-1])
        utils_lib.is_pkg_installed(self, pkg_name='nmap-ncat', is_install=True, cancel_case=True, rmt_node=self.params['remote_nodes'][-1])

        utils_lib.run_cmd(self, 'sudo ethtool -L {} combined 1'.format(self.active_nic), rmt_node=self.params['remote_nodes'][-1])
        utils_lib.run_cmd(self, 'sudo ip link set {} mtu 2000'.format(self.active_nic), rmt_node=self.params['remote_nodes'][-1])
        utils_lib.run_cmd(self, ' sudo xdp-filter load --mode native {}'.format(self.active_nic), rmt_node=self.params['remote_nodes'][-1])
        srv_cmd = 'sudo bash -c "nc -6 -l 5000 -v >/dev/null 2>&1 &"'
        utils_lib.run_cmd(self, srv_cmd, rmt_node=self.params['remote_nodes'][-1])
        srv_addr = self.vms[1].ipv6_address
        utils_lib.run_cmd(self, 'sudo ethtool -L {} combined 1'.format(self.active_nic))
        utils_lib.run_cmd(self, 'sudo ip link set {} mtu 2000'.format(self.active_nic))
        utils_lib.run_cmd(self, 'sudo xdp-filter load --mode native {}'.format(self.active_nic))
        utils_lib.run_cmd(self, 'sudo timeout 60 xdp-trafficgen tcp -p 5000 -i {} {}'.format(self.active_nic, srv_addr))
        cmd = "ethtool -S {}|grep xdp".format(self.active_nic )
        utils_lib.run_cmd(self, cmd, msg='check xdp counter')

    def tearDown(self):
        utils_lib.finish_case(self)
        if 'test_mtu_min_max_set' in self.id():
            mtu_cmd = "sudo ip link set dev %s mtu %s" % (self.active_nic , self.mtu_old)
            utils_lib.run_cmd(self, mtu_cmd, expect_ret=0, msg='restore mtu')
        if 'test_ping_arp_ping' in self.id() or 'test_iperf' in self.id() or 'test_scp_mtu_9000' in self.id():
            if self.vm and self.vm.provider == 'aws' or self.vm.provider == 'ali':
                if self.vms[1].private_ip in self.params['remote_nodes']:
                    self.params['remote_nodes'].remove(self.vms[1].private_ip)
            if self.vm and self.vm.provider == 'nutanix':
                if self.vm.vm1_ip in self.params['remote_nodes']:
                    self.params['remote_nodes'].remove(self.vm.vm1_ip)
                self.vm.prism.delete_vm(self.vms[1]['uuid'])
                self.vms.pop()
        if 'test_network_device_hotplug_multi' in self.id():
            for nic in self.nics:
                self.vm.detach_nic(nic)
        if 'test_second_ip_hotplug_multi' in self.id():
            utils_lib.imds_tracer_tool(self, timeout=10, interval=5, cleanup=True, log_check=False)
        if self.nic and self.nic.is_exist():
            self.nic.delete()
        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='sudo dmesg -T', skip_words='ftrace,rawtrace', cursor=self.dmesg_cursor)

if __name__ == '__main__':
    unittest.main()
