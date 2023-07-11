# this file run rhcert test suite and collect the required cert log
# 2 vms or 2 hosts are required to run full test
import unittest
from os_tests.libs import utils_lib
import time
import os
import re

class TestRHELCert(unittest.TestCase):


    def _wait_cert_done(self, timeout=600, interval=30):
        timeout = timeout
        interval = interval
        time_start = int(time.time())
        while True:
           cmd = 'sudo ls /var/lock/subsys/rhcert'
           ret = utils_lib.run_cmd(self,cmd,ret_status=True)
           if int(ret) != 0:
                cmd = 'sudo bash -c "rhcert-cli print"'
                out = utils_lib.run_cmd(self,cmd, timeout=1800, msg='print cert result')
                if 'INCOMPLETE' in out:
                   self.log.info("INCOMPLETE task found, wait it done")
                else:
                    break
           time_end = int(time.time())
           if time_end - time_start > timeout:
              self.log.info('timeout ended: {}'.format(timeout))
              break
           self.log.info('wait rhcert finish, retry after {}s'.format(interval))
           time.sleep(interval)
        cmd = 'sudo bash -c "yes|rhcert-cli print"'
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='print cert result')

    def setUp(self):
        utils_lib.init_case(self)
        utils_lib.is_cmd_exist(self, cmd='rhcert-cli', cancel_case=True)
        cmd = 'sudo bash -c "rm -rf /var/rhcert/*"'
        utils_lib.run_cmd(self,cmd, msg='cleanup prior test result')
        self.is_cert_done = False
        if 'non_interactive' not in self.id():
            if not self.is_rmt:
                self.skipTest('only run on remote')
            if len(self.vms) < 2 and len(self.params.get('remote_nodes')) < 2:
                self.skipTest('2 nodes required!')
            if len(self.vms) > 1 and not self.vms[1].exists():
                self.vms[1].create()
                self.params['remote_nodes'].append(self.vms[1].floating_ip)
            
            utils_lib.init_connection(self, timeout=self.ssh_timeout, rmt_node=self.params['remote_nodes'][-1])
            cmd = 'sudo bash -c "mkdir -p /var/www/rhcert/export/var/crash"'
            utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1])
            cmd = 'sudo bash -c "chmod -R 777 /var/www/rhcert/export/"'
            utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1])
            cmd = "ip link show|grep mtu|grep -v lo|awk -F':' '{print $2}'"
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1])
            self.active_nic  = "eth0"
            self.log.info("Test which nic connects to public")
            nic_found = False
            for net in output.split('\n'):
                if len(net) < 3:
                    continue
                cmd = "sudo ping {} -c 6 -I {}".format(self.params.get('ping_server'), net)
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, rmt_node=self.params['remote_nodes'][-1])
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
            self.log.info("Pick up nic {}".format(self.active_nic ))
            cmd = "ip addr show {}".format(self.active_nic )
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1], msg='try to get {} ipv4 address'.format(self.active_nic ))
            self.rmt_ipv4 = re.findall('[\d.]{7,16}', output)[0]
            cmd = 'sudo bash -c "rhcertd start"'
            utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1], msg="start rhcertd on test server")
            cmd = 'sudo cat /root/.ssh/id_rsa.pub'
            out = utils_lib.run_cmd(self, cmd, msg='check if root login is enabled')
            if 'No such file' in out:
                cmd = 'sudo bash -c "echo |ssh-keygen -t rsa"'
                out = utils_lib.run_cmd(self, cmd)
                cmd = 'sudo cat /root/.ssh/id_rsa.pub'
                out = utils_lib.run_cmd(self, cmd)
                if 'No such file' in out:
                    self.log.info('Cannot get pub key from hut')
            cmd = 'sudo bash -c "echo \'{}\'>/root/.ssh/authorized_keys"'.format(out)
            utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1], msg='add pub key to test server')
            cmd = 'sudo bash -c "ssh -o StrictHostKeyChecking=no root@{} ip addr"'.format(self.rmt_ipv4)
            utils_lib.run_cmd(self, cmd, msg="test cmd execution on remote without password")
            cmd = 'sudo bash -c "systemctl disable --now firewalld"'.format(out)
            utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1], msg='disable firewalld')

        if self.id().endswith(('test_rhcert_non_interactive','test_rhcert_pcie_nvme')):   
            cmd = 'sudo lsblk -d|wc -l'
            out = utils_lib.run_cmd(self,cmd, msg='check disk count')
            if int(out) <= 2:
                if not self.vm:
                    self.skipTest("Skip this test case as no vm inited to attach disk")
                online_disk_1 = utils_lib.get_disk_online(self)
                if not self.disk:
                    self.skipTest('Skip as lacking of storage provision support.')
                if not self.disk.is_exist():
                    self.disk.create()
                time.sleep(20)
                if not self.vm.attach_block(self.disk, '/dev/sdz'):
                    self.fail('attach failed')
                timeout = 60
                interval = 2
                time_start = int(time.time())
                while True:
                   if not self.disk.is_free():
                       break
                   time_end = int(time.time())
                   if time_end - time_start > timeout:
                      self.log.info('timeout ended: {}'.format(timeout))
                      break
                   self.log.info('retry after {}s'.format(interval))
                   time.sleep(interval)
                time.sleep(5)

    def test_rhcert_non_interactive(self):
        """
        case_tags:
            certification
        title:
            Run rhcert test suite
        importance:
            Low
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            jira_RHELBU-1991
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_rhel_cert.py
        setup_teardown: |
            os-tests do not deploy the cert environment itself, it only run and collect the test result.
            1. Download required cert pkgs from https://access.redhat.com/downloads/content/282/ver=9/rhel---9/9/x86_64/packages.
            'redhat-certification' and 'redhat-certification-hardware' are must required for instance type cert.
            'redhat-certification-cloud' is for image certification which is not used.
               - test files: /usr/lib/python3.9/site-packages/rhcert/suites/hwcert/tests
            2. Install the required pkgs:
               - yum update -y
               - yum install -y kernel-abi-stablelists lvm2 libvirt
               - yum -q -y --enablerepo=* install kernel-debuginfo
            3. Disable firewall if it is enabled.
               - systemctl disable firewalld
        environment:
            see setup_teardown
        case_name:
            test_rhcert
        component:
            certification
        bug_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description: |
            Run RHEL hwcert test.
        key_steps: |
            1. 2 nodes with the same cert pkgs installed from setup_teardown.
               this step is done during test run.
               - 2 nodes can login each with root
               - node1 acts as sut and node2 act as test server(nfs, network endpoints......)
               - node1: rhcert-provision <path_to_test_plan_document>
               - node2: rhcert-provision --role test-server <path_to_test_plan_document>
            2. Run test on node1
               -rhcert-cli run
               -rhcert-cli continue(not needed)
               -rhcert-cli save (save test result to xml)
        expected_result: |
            The test will copy result xml to local result dir.
            It is in node1 system with below format.
            /var/rhcert/save/rhcert-results-xxxxxx.internal-20221010070227.xml
        debug_want: |
            N/A
        """
        test_disk = 'nvme1n1'
        test_disk = utils_lib.get_test_disk(self) or test_disk

        cmds = ['sudo bash -c "dd if=/dev/zero of=/swap bs=1024 count=2000000"',
        'sudo bash -c "chmod 0600 /swap"',
        'sudo bash -c "mkswap /swap"',
        'sudo bash -c "swapon /swap"' ]
        for cmd in cmds:
            utils_lib.run_cmd(self,cmd, timeout=180)
        cmd = 'sudo bash -c "yes|rhcert-cli plan"'
        utils_lib.run_cmd(self,cmd, timeout=3600, msg='create test plan')
        cmd = 'sudo bash -c "yes|rhcert-cli run --tag non-interactive --device {}"'.format(test_disk)
        utils_lib.run_cmd(self,cmd, timeout=28800, msg='start to run non-interactive cert test')
        self._wait_cert_done()
        self.is_cert_done = True

    def test_rhcert_kdump(self):
        
        cmd = 'sudo bash -c "yes|rhcert-cli plan"'
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='create test plan')
        cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device local"'
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='run kdump local test')
        if not self.SSH.is_active():
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
        time.sleep(30)
        self._wait_cert_done()
        utils_lib.is_pkg_installed(self,'nfs-utils')
        cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device nfs --server {}"'.format(self.rmt_ipv4)
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='run kdump nfs test')
        if not self.SSH.is_active():
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
        time.sleep(30)
        self._wait_cert_done()
        self.is_cert_done = True

    def test_rhcert_kdump_aws_arm_irqpoll(self):
        '''
        run the same test with test_rhcert_kdump, if test_rhcert_kdump fail and this case pass, that means they are the same issue with https://access.redhat.com/articles/6562431.

        '''
        if not utils_lib.is_aws(self):
            self.skipTest("No need to run it because it is aws specified")
        if not utils_lib.is_arch(self, 'aarch64'):
            self.skipTest("Only for arm instances")
        if utils_lib.is_metal(self):
            self.skipTest("Only for virtual arm instances")
        self.log.info("aws aarch64 non-metal instance found, remove irqpoll if it is used following https://access.redhat.com/articles/6562431")
        update_kdump_cfg = False
        cmd = 'sudo grep irqpoll /etc/sysconfig/kdump |grep KDUMP_COMMANDLINE_REMOVE'
        ret = utils_lib.run_cmd(self, cmd, ret_status=True)
        if ret != 0:
            cmd = 'sudo bash -c " sed -i \'/KDUMP_COMMANDLINE_REMOVE=/s/quiet/quiet irqpoll/g\'  /etc/sysconfig/kdump"'
            utils_lib.run_cmd(self, cmd, msg='add irqpoll to KDUMP_COMMANDLINE_REMOVE')
            update_kdump_cfg = True
        cmd = 'sudo grep irqpoll /etc/sysconfig/kdump |grep KDUMP_COMMANDLINE_APPEND'
        ret = utils_lib.run_cmd(self, cmd, ret_status=True)
        if ret == 0:
            cmd = 'sudo bash -c "sed -i \'/KDUMP_COMMANDLINE_APPEND=/s/irqpoll //g\'  /etc/sysconfig/kdump"'
            utils_lib.run_cmd(self, cmd, msg='remove irqpoll from KDUMP_COMMANDLINE_APPEND')
            update_kdump_cfg = True
        if update_kdump_cfg:
            cmd = 'sudo cat /etc/sysconfig/kdump'
            utils_lib.run_cmd(self, cmd, msg='updated kdump')
            cmd = 'sudo systemctl restart kdump'
            utils_lib.run_cmd(self, cmd, msg='restart kdump')
        cmd = 'sudo bash -c "yes|rhcert-cli plan"'
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='create test plan')
        cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device local"'
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='run kdump local test')
        if not self.SSH.is_active():
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
        time.sleep(30)
        self._wait_cert_done()
        utils_lib.is_pkg_installed(self,'nfs-utils')
        cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device nfs --server {}"'.format(self.rmt_ipv4)
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='run kdump nfs test')
        if not self.SSH.is_active():
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
        time.sleep(30)
        self._wait_cert_done()
        self.is_cert_done = True

    def test_rhcert_ethernet(self):
        
        net_bandwidth = 50
        if self.vm and hasattr(self.vm, 'net_bandwidth'):
            net_bandwidth = self.vm.net_bandwidth
        if net_bandwidth <= 5:
            net_bandwidth = 5
        elif net_bandwidth <= 10:
            net_bandwidth = 10
        elif net_bandwidth <= 20:
            net_bandwidth = 20
        elif net_bandwidth <= 25:
            net_bandwidth = 25
        elif net_bandwidth <= 40:
            net_bandwidth = 40
        elif net_bandwidth <= 50:
            net_bandwidth = 50
        elif net_bandwidth <= 100:
            net_bandwidth = 100
        elif net_bandwidth <= 200:
            net_bandwidth = 200
        cmd = 'sudo bash -c "yes|rhcert-cli plan --add --test {}GigEthernet --device {} --server {}"'.format(net_bandwidth,self.active_nic,self.rmt_ipv4)
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='create test plan')
        cmd = 'sudo bash -c "yes|rhcert-cli run --test {}GigEthernet --device {} --server {}"'.format(net_bandwidth,self.active_nic,self.rmt_ipv4)
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='run ethernet test')
        time.sleep(20)
        self._wait_cert_done()
        self.is_cert_done = True

    def test_rhcert_pcie_nvme(self):
        cmd = 'sudo bash -c "yes|rhcert-cli plan"'
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='create test plan')
        test_disk = 'nvme1n1'
        test_disk = utils_lib.get_test_disk(self) or test_disk
        if 'nvme' in test_disk:
            cmd = 'sudo bash -c "yes|rhcert-cli run --test PCIE_NVMe --device {}"'.format(test_disk)
            utils_lib.run_cmd(self,cmd, timeout=1800, msg='run ethernet test')
        else:
            self.skipTest("No nvme device found")
        self._wait_cert_done()
        self.is_cert_done = True

    def tearDown(self):
        if self.is_cert_done:
            cmd = 'sudo bash -c "yes|rhcert-cli save"'
            out = utils_lib.run_cmd(self,cmd, msg='save test result')
            if 'xml' not in out:
                self.fail("xml format result expected")
            result_path = re.findall("/.*xml", out)[0]
            local_file='{}/attachments/{}_{}'.format(self.log_dir,self.id().split('.')[-1],os.path.basename(result_path))
            self.log.info('retrive {} from remote to {}'.format(result_path,local_file))
            self.SSH.get_file(rmt_file=result_path,local_file=local_file)
            cmd = 'sudo bash -c "rm -rf /var/rhcert/*"'
            utils_lib.run_cmd(self,cmd, msg='cleanup the test result')

if __name__ == '__main__':
    unittest.main()
