import re
import unittest
import time
import random

from os_tests.libs import utils_lib
from os_tests.libs.utils_lib import run_cmd, init_connection

class TestNetworkTest(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')
        cmd = "ip link show|grep mtu|grep -v lo|awk -F':' '{print $2}'"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        self.nic = "eth0"
        self.log.info("Test which nic connects to public")
        nic_found = False
        for net in output.split('\n'):
            if len(net) < 3:
                continue
            cmd = "ping {} -c 6 -I {}".format(self.params.get('ping_server'), net)
            ret = utils_lib.run_cmd(self, cmd, ret_status=True)
            if ret == 0:
                self.nic = net
                nic_found = True
                break
        if not nic_found:
            for net in output.split('\n'):
                #man systemd.net-naming-scheme
                if net.startswith(('eth','en')):
                    self.nic = net
                    break
        self.log.info("Pick up nic {}".format(self.nic))
        cmd = "ip addr show {}".format(self.nic)
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to get {} ipv4 address'.format(self.nic))
        self.ipv4 = re.findall('[\d.]{7,16}', output)[0]
        if utils_lib.is_metal(self):
            self.ssh_timeout = 1200
            self.SSH.interval = 60
        else:
            self.ssh_timeout = 180

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
        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
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
            if self.vm.provider == 'nutanix':
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
        cmd = "sudo ping {} -c 10 -I {}".format(self.params.get('ping_server'), self.nic) #add sudo here or it will fail against 8.7
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
            cmd = 'podman run -dit --name httpd_site -p 8188:80 -v "/tmp/test":/usr/local/apache2/htdocs/ {}'.format(registry)
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
*testfilter
:FORWARD ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:PREROUTING ACCEPT [0:0]
COMMIT
        '''
        utils_lib.run_cmd(self,"echo'%s'>/tmp/iptable.txt"%tablestr)
        utils_lib.run_cmd(self,'iptable-restore --test /tmp/iptable.txt',timeout=20,msg="run restore test")
        utils_lib.run_cmd(self,"rm -f /tmp/iptable.txt")

    def _test_add_remove_multi_nics(self, nic_num, network_uuid, ip_subnet, driver='virtio'):
        '''
        Add remove multi nics according to specific parameters.
        '''
        #record origin nic's mac and name
        origin_nic_name = utils_lib.run_cmd(self, "ls /sys/class/net/ | grep -v lo").strip()
        origin_nic_mac = utils_lib.run_cmd(self, "cat /sys/class/net/%s/address" % origin_nic_name).strip()
        #stop vm to add nic if vm is secure boot and record the set ip list
        if self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
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
                while True:
                    ip_address = ip_subnet + str(random.randint(10,100))
                    if ip_address not in set_ip_list and ip_address not in used_ip_list:
                        set_ip_list.append(ip_address)
                        break
            self.log.info("Add nic for %s time(s)" % i)
            self.vm.attach_nic(network_uuid, ip_address, driver)
        set_ip_list.sort()
        if self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
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
            if nic_name == origin_nic_name:
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
            vm_ip_list = utils_lib.run_cmd(self, "ip a | grep 'inet ' | grep %s | awk '{print $2}' | sed 's/\/24//'" % self.vm.private_network_subnet).split()
            vm_ip_list.sort()
            self.assertEqual(vm_ip_list, set_ip_list, msg="IP configure is not right, Expect: %s, real: %s" % (str(set_ip_list), str(vm_ip_list)))
        if self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
            self.vm.stop(wait=True)
        #delete nic by mac
        for mac in nic_mac_list:
            if mac != origin_nic_mac:
                self.vm.detach_nic(mac)
        if self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
            self.vm.start(wait=True)
            time.sleep(30)
            utils_lib.init_connection(self, timeout=180)
        vm_nic_num = int(utils_lib.run_cmd(self, "ip a | grep 'inet ' | grep global | wc -l").strip())
        self.assertEqual(vm_nic_num, 1, msg="Number of nics is not right, Expect: %s, real: %s" % (1, vm_nic_num))

    def test_add_remove_multi_virtio_no_ip_spec(self):
        """
        case_tag:
            Network
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
            Add/Remove four NICs without IP, check nic number and driver.
        key_steps:
            Add/Remove four NICs without IP.
        expect_result:
            Check nic number and driver without error.
        debug_want:
            N/A
        """
        if self.vm.provider == 'nutanix' and self.vm.prism.machine_type == 'q35':
            multi_num = 1
        else:
            multi_num = 2
        self._test_add_remove_multi_nics(multi_num, None, None, 'virtio')

    def test_add_remove_multi_virtio_ip_spec(self):
        """
        case_tag:
            Network
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
            Add/Remove four NICs with IP, check nic number and driver.
        key_steps:
            Add/Remove four NICs with IP.
        expect_result:
            Check nic number and driver without error.
        debug_want:
            N/A
        """
        if self.vm.provider == 'nutanix' and self.vm.prism.machine_type == 'q35':
            multi_num = 1
        else:
            multi_num = 2
        self._test_add_remove_multi_nics(multi_num, self.vm.private_network_uuid, self.vm.private_network_subnet, 'virtio')

    def test_add_remove_multi_e1000_nic(self):
        """
        case_tag:
            Network
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
        if self.vm.provider == 'nutanix' and self.vm.prism.machine_type == 'q35':
            self.skipTest('e1000 should not be supported by pcie-root-port')
        self._test_add_remove_multi_nics(2, None, None, 'e1000')
        self._test_add_remove_multi_nics(2, self.vm.private_network_uuid, self.vm.private_network_subnet, 'e1000')

    def _test_unload_load_nic_driver(self, driver):
        #record the first nic
        origin_nic_name = utils_lib.run_cmd(self, "ls /sys/class/net/ | grep -v lo").strip()
        origin_nic_mac = utils_lib.run_cmd(self, "cat /sys/class/net/%s/address" % origin_nic_name).strip()
        #atach the second nic
        if self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
            self.vm.stop(wait=True)
        self.vm.attach_nic(None, None, driver)
        self.vm.detach_nic(origin_nic_mac)
        if self.vm.provider == 'nutanix' and self.vm.prism.if_secure_boot:
            self.vm.start(wait=True)
        self.vm.refresh_data()
        utils_lib.init_connection(self, timeout=180)
        new_nic_mac = utils_lib.run_cmd(self, "cat /sys/class/net/%s/address" % origin_nic_name).strip()
        self.assertNotEqual(origin_nic_mac, new_nic_mac, msg="Second nic name changed after detaching the first nic, Expect not: %s, real: %s" % (origin_nic_mac, new_nic_mac))
        if driver == 'virtio':
            driver_check = 'virtio_net'
        else:
            driver_check = driver
        for i in range (2):
            self.log.info("Unload and load nic driver for %s time(s)." % i)
            utils_lib.run_cmd(self, "sudo modprobe -r %s && sudo modprobe %s" % (driver_check, driver_check), expect_ret=0)
        new_nic_name = utils_lib.run_cmd(self, "ls /sys/class/net/ | grep -v lo").strip()
        self.assertEqual(origin_nic_name, new_nic_name, msg="Second nic name changed after unload/load nic driver three times, Expect: %s, real: %s" % (origin_nic_name, new_nic_name))

    def test_ping_arp_ping(self):
        """
        case_tag:
            Network
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
        dest_ip = self.vms[0].floating_ip
        if len(self.vms) == 1:
            self.vm.create(vm_name='ScriptCreateVM1')
            vm1 = self.vm.get_vm_by_filter('vm_name', 'ScriptCreateVM1')
            self.vms.append(vm1)
            self.vm.prism.start_vm(vm1['uuid'])
        for nic in vm1.get('vm_nics'):
            if nic['network_uuid'] == self.vm.network_uuid:
                VM1_ip = nic['ip_address']
        init_connection(self, timeout=self.ssh_timeout, rmt_node=VM1_ip)
        vm1_nic_name = utils_lib.run_cmd(self, "ls /sys/class/net/ | grep -v lo", rmt_node=VM1_ip).strip()
        utils_lib.run_cmd(self, 'arping -I %s %s -c 2' % (vm1_nic_name, dest_ip), rmt_node=VM1_ip) #To avoid broadcast packet in the first time.
        utils_lib.run_cmd(self, 'arping -I %s %s -c 10' % (vm1_nic_name, dest_ip), rmt_node=VM1_ip, expect_kw='Received 10 response')
        utils_lib.run_cmd(self, 'sudo ping -f %s -c 600' % (dest_ip), rmt_node=VM1_ip, expect_kw='0% packet loss')
        #tear down - delete cloned VM
        self.vm.prism.delete_vm(vm1['uuid'])

    def test_iperf(self):
        """
        a simple case to run iperf between 2 nodes
        """
        iperf_srv_cmd = 'sudo bash -c "iperf3 -s >/dev/null 2>&1 &"'
        if self.vms:
            if not self.vms[1].exists():
                self.vms[1].create()
                if self.vms[1].is_stopped():
                    self.vms[1].start(wait=True)
            init_connection(self, timeout=self.ssh_timeout, vm=self.vms[1])
            self.params['remote_nodes'].append(self.vms[1].floating_ip)
            run_cmd(self, iperf_srv_cmd, vm=self.vms[1])
        elif not self.vms and self.params['remote_nodes']:
            init_connection(self, timeout=self.ssh_timeout, rmt_node=self.params['remote_nodes'][1])
            run_cmd(self, iperf_srv_cmd, rmt_node=self.params['remote_nodes'][1])
        else:
            self.skipTest('2 nodes required')
        cmd = "ip addr show {}".format(self.nic)
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='try to get {} ipv4 address'.format(self.nic),rmt_node=self.params['remote_nodes'][-1])
        srv_ipv4 = re.findall('[\d.]{7,16}', output)[0]
        iperf_cli_cmd = 'iperf3 -c {} -t 60'.format(srv_ipv4)
        run_cmd(self, iperf_cli_cmd, expect_ret=0, timeout=120)

    def test_unload_load_virtio(self):
        """
        case_tag:
            Network
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
        self._test_unload_load_nic_driver('virtio')

    def test_unload_load_e1000(self):
        """
        case_tag:
            Network
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
        if self.vm.provider == 'nutanix' and self.vm.prism.machine_type == 'q35':
            self.skipTest('e1000 should not be supported by pcie-root-port')
        self._test_unload_load_nic_driver('e1000')

    def test_ethtool_K_offload(self):
        """
        case_tag:
            Network
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
        else:
            instance_type = self.vm.instance_type
            if not self.vm.efa_support:
                self.skipTest('EFA is not supported on the instance ' + instance_type)
            cmd = 'lspci|grep EFA && lsmod|grep efa'
            run_cmd(self, cmd, expect_ret=0, msg='check if EFA device exist and efa module is loaded')
            self.log.info('EFA device is found and efa driver is loaded on the instance ' + instance_type)
            
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
        key_steps:
            1.# sudo yum install libfabric
            2.# fi_info -p efa
        expect_result:
            libfabric package is installed successfully and fi_info command should return information about the Libfabric EFA interfaces.
        debug_want:
            efa,libfabric
        """
        if not self.vm or self.vm.provider != "aws":
            self.skipTest("Skip test case since instance is not vm or aws")
        else:
            instance_type = self.vm.instance_type
            if not self.vm.efa_support:
                self.skipTest('EFA is not supported on the instance ' + instance_type)
            if utils_lib.is_pkg_installed(self,'libfabric'):
                cmd = 'fi_info -p efa'
                utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="provider: efa", msg='Check the Libfabric EFA interfaces')
            
   
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
        else:
            instance_type = self.vm.instance_type
            if not self.vm.efa_support:
                self.skipTest('EFA is not supported on the instance ' + instance_type)
            self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')
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
            utils_lib.check_log(self, "error,warn,fail,trace,Trace", log_cmd='dmesg -T', cursor=self.dmesg_cursor)
            if ret == 0:
                self.log.info('efa driver is loaded successfully')


    def tearDown(self):
        if 'test_mtu_min_max_set' in self.id():
            mtu_cmd = "sudo ip link set dev %s mtu %s" % (self.nic, self.mtu_old)
            utils_lib.run_cmd(self, mtu_cmd, expect_ret=0, msg='restore mtu')
        utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='dmesg -T', skip_words='ftrace', cursor=self.dmesg_cursor)

if __name__ == '__main__':
    unittest.main()
