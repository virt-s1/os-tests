import unittest
import time
from os_tests.libs import utils_lib

class TestVMOperation(unittest.TestCase):
    '''
    Only run in mode 3 with vm provision capbility.
    '''
    def setUp(self):
        utils_lib.init_case(self)
        if not self.vm:
            self.skipTest("no vm found!")
        if self.params['remote_node'] is None:
            self.skipTest("Only support to run in server-client mode!")
        if utils_lib.is_metal(self):
            self.ssh_timeout = 1200
            self.SSH.interval = 60
        else:
            self.ssh_timeout = 180
        self.log.info('set ssh connection timeout to {}'.format(self.ssh_timeout))

    def test_cloud_init_config_ipv6(self):
        '''
        description:
            Check the IPv6 is configured by default for guests.
        testplan:
            N/A
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            cloud-init
        key_steps:
            1. Launch an instance which support IPv6 with IPv6 auto assigned.
            2. Check the IPv6 is configured and auto assigned for NIC and can be connected via IPv6 address after system boot up.
        pass_criteria: 
            The IPv6 address shows in NIC and can be connected.
        '''
        if not self.vm.ipv6_address:
            self.skipTest("current instance setup not support ipv6, skip check!")
        cmd = 'ip addr show eth0'
        utils_lib.run_cmd(self, cmd, expect_kw=self.vm.ipv6_address)
        cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth0'
        utils_lib.run_cmd(self, cmd, expect_kw='IPV6INIT=yes')

    def test_cloud_init_lineoverwrite(self):
        '''
        description:
            This is a specific case of openstack, because the cloud guest images need to have "NOZEROCONF=yes" in /etc/sysconfig/network so that it works well as an openstack guest. (Bug 983611 - Cloud guest images needs to have "NOZEROCONF=yes" in /etc/sysconfig/network)
            cloud-init removed user configuration in /etc/sysconfig/network and rewrite the default configuration in every prevision before cloud-init-18.2-4.el7, after this version, certain lines in network configuration isn't removed after re-provision. linked case RHEL-152730
        testplan:
            N/A
        bugzilla_id:
            1653131
        is_customer_case:
            True
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Add "NOZEROCONF=yes" to top of network config /etc/sysconfig/network.
            3. Add "NETWORKING_IPV6=no" to top of network config /etc/sysconfig/network.
            4. Clean cloud-init with command: "rm /run/cloud-init/ /var/lib/cloud/* -rf" and reboot instance.
            5. Check the new network configuration /etc/sysconfig/network after boot.
        pass_criteria:
            "NETWORKING_IPV6=no" and "NOZEROCONF=yes" should be in the network configuration.
        '''
        utils_lib.run_cmd(self,
                    'uname -r',
                     msg='Get instance kernel version')
        cmd = 'ifconfig eth0'
        utils_lib.run_cmd(self, cmd, msg="Previous ifconfig status")
        cmd = 'cat /etc/sysconfig/network'
        output = utils_lib.run_cmd(self, cmd, msg="Previous network configuration.")
        if "NOZEROCONF=yes" not in output:
            cmd = r"sudo sed -i '1s/^/NOZEROCONF=yes\n/' \
/etc/sysconfig/network"

            utils_lib.run_cmd(self,
                        cmd,
                        msg='add NOZEROCONF=yes to top of network config')
        if "NETWORKING_IPV6=no" not in output:
            cmd = r"sudo sed -i '1s/^/NETWORKING_IPV6=no\n/' \
/etc/sysconfig/network"

            utils_lib.run_cmd(self,
                        cmd,
                        msg='add NETWORKING_IPV6=no top of network config')
        cmd = 'cat /etc/sysconfig/network'
        output = utils_lib.run_cmd(self, cmd, msg="Updated network configuration.")
        cmd = 'sudo rm /run/cloud-init/ /var/lib/cloud/* -rf'
        utils_lib.run_cmd(self, cmd, msg='clean cloud-init and redo it')
        self.vm.reboot()
        time.sleep(20)
        self.SSH.create_connection()
        cmd = 'cat /etc/sysconfig/network'
        output = utils_lib.run_cmd(self, cmd, msg="New network configuration.")
        if "NETWORKING_IPV6=no" in output:
            self.fail("NETWORKING_IPV6=no is not expected")
        if "NOZEROCONF=yes" not in output:
            self.fail("NOZEROCONF=yes is expected")

    def test_check_disk_count(self):
        '''
        description:
            check disk count in vm matches the vm assigned
        testplan:
            N/A
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an vm.
            2. Check online disks count via command "$ sudo lsblk -d".
        pass_criteria: 
            The online disks count is the same with attached disks.
        '''
        assigned_disk = self.vm.disk_count
        online_disk = utils_lib.get_disk_online(self)
        if assigned_disk != online_disk:
            self.fail('disk assigned:{} not match disk online:{}'.format(assigned_disk, online_disk))

    def test_disk_hotplug(self):
        '''
        description:
            Check hotplug disks when vm is running. Linked case RHEL7-93570.
            Will add disk read&write in auto test later.
        testplan:
            N/A
        bugzilla_id:
            2004072
        is_customer_case:
            False
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an vm.
            2. Check online disks count via command "$ lsblk -d".
            3. When instance is in running state, attach 4 disks to this instance.
            4. Connect instance via ssh, check online disks count again.
            5. Create partition and filesystem for the attached disks, format and mount the disks, check read and write in the attached disks.
            6. Detach the disks.
        pass_criteria: 
            Disks can be attached to the running instance successfully.
            The online disks count is the same with the orignial disks in spec plus attached disks.
            Read and write in attached disks work well.
            And no error, hang or crash in system.
            Disks can be detached successfully in step 6.
        '''
        online_disk_1 = utils_lib.get_disk_online(self)
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
        utils_lib.run_cmd(self, 'dmesg|tail -20', msg="Get the last dmesg")
        online_disk_2 = utils_lib.get_disk_online(self)
        if online_disk_2 == online_disk_1:
            self.fail('Online disk count - before:{} after attach:{}'.format(online_disk_1,online_disk_2))
        if not self.vm.detach_block(self.disk):
            self.fail('detach failed')
        timeout = 120
        interval = 2
        time_start = int(time.time())
        while True:
           if self.disk.is_free():
               break
           time_end = int(time.time())
           if time_end - time_start > timeout:
              self.log.info('timeout ended: {}'.format(timeout))
              break
           self.log.info('retry after {}s'.format(interval))
           time.sleep(interval)
        utils_lib.run_cmd(self, 'dmesg|tail -20', msg="Get the last dmesg")
        online_disk_2 = utils_lib.get_disk_online(self)
        if online_disk_2 != online_disk_1:
            self.fail('Online disk count - before:{} after detach:{}'.format(online_disk_1,online_disk_2))

    def test_cloud_init_userdata(self):
        '''
        description:
            Check the userdata can be passed when creating instance. Linked case RHEL7-87120
        testplan:
            N/A
        bugzilla_id:
            n/a
        is_customer_case:
            False
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2 with passing userdata, e.g., passing an script like this:
                #!/bin/bash
                 date > /home/ec2-user/time.log
            2. Connect the instance and check time.log appears after system boot up.
        pass_criteria: 
            The passed userdata (time.log) should exist and can be edit and remove.
        '''
        user_name = self.params.get('remote_user')
        user_dir = "/home/%s/instance_create_%s" % (user_name,
                                                    self.vm.instance_type)
        cmd = "ls -l %s" % user_dir
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "rm -rf %s" % user_dir
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_kdump_unknown_nmi_panic_disabled(self):
        '''
        description:
            Test Diagnostic Interrupt doesn't trigger the kdump when unknown_nmi_panic is disabled with RHEL on AWS. https://aws.amazon.com/blogs/aws/new-trigger-a-kernel-panic-to-diagnose-unresponsive-ec2-instances/
        testplan:
            N/A
        bugzilla_id:
            n/a
        is_customer_case:
            False
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            Kdump
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the kdump status by command "systemctl status kdump.service".
            3. Disable kernel to trigger a kernel panic upon receiving the interrupt by set /etc/sysctl.conf and add a line : kernel.unknown_nmi_panic=0 and reboot. Or by command "sudo sysctl kernel.unknown_nmi_panic=0".
            4. Send Diagnostic Interrupt to the instance.
        pass_criteria: 
            Unknown NMI received and kernel panic isn't triggered, system is still running with no error message.
        '''
        utils_lib.run_cmd(self, 'lscpu', cancel_not_kw='aarch64', msg='Not support in arm instance')
        utils_lib.run_cmd(self, r'sudo rm -rf /var/crash/*', expect_ret=0, msg='clean /var/crash firstly')
        utils_lib.run_cmd(self, r'sudo sysctl kernel.unknown_nmi_panic=0',expect_ret=0,msg='disable unknown_nmi_panic')
        utils_lib.run_cmd(self, r'sudo sysctl -a|grep -i nmi', expect_ret=0, expect_kw='kernel.unknown_nmi_panic = 0')
        if not self.vm.send_nmi():
            self.fail("Cannot trigger panic via nmi!")
        time.sleep(10)
        self.SSH.create_connection()
        utils_lib.run_cmd(self, r'sudo cat /var/crash/*/vmcore-dmesg.txt', expect_not_ret=0, msg='list /var/crash after crash')
        cmd = r'sudo dmesg|tail -10'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='NMI received')

    def test_kdump_unknown_nmi_panic_enabled(self):
        '''
        description:
            Test Diagnostic Interrupt triggers the kdump when unknown_nmi_panic is enabled with RHEL on AWS. https://aws.amazon.com/blogs/aws/new-trigger-a-kernel-panic-to-diagnose-unresponsive-ec2-instances/
        testplan:
            N/A
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            Kdump
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the kdump status by command "systemctl status kdump.service".
            3. Disable kernel to trigger a kernel panic upon receiving the interrupt by set /etc/sysctl.conf and add a line : kernel.unknown_nmi_panic=1 and reboot. Or by command "sudo sysctl kernel.unknown_nmi_panic=1".
            4. Send Diagnostic Interrupt to the instance.
        pass_criteria: 
            Kernel panic is triggered, system reboot after panic, and vm core is gernerated in /var/crash after crash. 
        '''
        timeout = 120
        interval = 5
        time_start = int(time.time())
        while True:
           cmd = 'sudo systemctl is-active kdump'
           ret = utils_lib.run_cmd(self, cmd,ret_status=True, msg='check kdump is active')
           if ret == 0: break
           time_end = int(time.time())
           if time_end - time_start > timeout:
              self.log.info('timeout ended: {}'.format(timeout))
              break
           self.log.info('retry after {}s'.format(interval))
           time.sleep(interval)
        utils_lib.run_cmd(self, 'lscpu', cancel_not_kw='aarch64', msg='Not support in arm instance')
        utils_lib.run_cmd(self, r'sudo rm -rf /var/crash/*', expect_ret=0, msg='clean /var/crash firstly')
        utils_lib.run_cmd(self, r'sudo sysctl kernel.unknown_nmi_panic=1', expect_ret=0, msg='enable unknown_nmi_panic')
        utils_lib.run_cmd(self, r'sudo sysctl -a|grep -i nmi', expect_ret=0, expect_kw='kernel.unknown_nmi_panic = 1')
        if not self.vm.send_nmi():
            self.fail("Cannot trigger panic via nmi!")
        time.sleep(10)
        self.SSH.create_connection()
        utils_lib.run_cmd(self,
                    r'sudo ls /var/crash/',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/1*/vmcore-dmesg.txt|tail -50'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='nmi_panic')

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()