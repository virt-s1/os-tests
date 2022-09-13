import unittest
import time
import re
from os_tests.libs import utils_lib
from os_tests.libs.resources import UnSupportedAction,UnSupportedStatus

class TestVMOperation(unittest.TestCase):
    '''
    Only run in mode 3 with vm provision supported.
    '''
    def setUp(self):
        utils_lib.init_case(self)
        if not self.vm:
            self.skipTest("no vm found!")
        if self.params['remote_node'] is None:
            self.skipTest("Only support to run in server-client mode!")

    def test_cloud_init_config_ipv6(self):
        '''
        case_tag:
            cloudinit
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
        ipv6 = None
        try:
            ipv6 = self.vm.ipv6_address
        except NotImplementedError:
            self.skipTest("current {} not bring out this ipv6_address property".format(self.vm.provider))

        if not ipv6:
            self.skipTest("current instance setup might not support ipv6, skip checking.")
        cmd = 'ip addr show eth0'
        utils_lib.run_cmd(self, cmd, expect_kw=ipv6)
        out = utils_lib.run_cmd(self, 'rpm -q cloud-init', expect_ret=0)
        cloudinit_ver = re.findall('\d+.\d',out)[0]
        if float(cloudinit_ver) < 22.1:
            self.log.info('no ifcfg-eth0 from cloudinit 22.1, render profile was changed to networkmanager')
            cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth0'
            utils_lib.run_cmd(self, cmd, expect_kw='IPV6INIT=yes')

    def test_cloud_init_lineoverwrite(self):
        '''
        case_tag:
            cloudinit
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
        out = utils_lib.run_cmd(self, 'rpm -q cloud-init', expect_ret=0)
        cloudinit_ver = re.findall('\d+.\d',out)[0]
        if float(cloudinit_ver) >= 22.1:
            self.skipTest('not supported from cloudinit 22.1, render profile changed to networkmanager')
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
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        cmd = 'cat /etc/sysconfig/network'
        output = utils_lib.run_cmd(self, cmd, msg="New network configuration.")
        if "NETWORKING_IPV6=no" in output:
            self.fail("NETWORKING_IPV6=no is not expected")
        if "NOZEROCONF=yes" not in output:
            self.fail("NOZEROCONF=yes is expected")

    def test_cloud_init_userdata(self):
        '''
        case_tag:
            cloudinit
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
            1. Launch an instance with custom scrtip, eg. passing an script to create a dir:
                #!/bin/bash
                mkdir /tmp/userdata_${uuid}
            2. Connect the instance and check /tmp/userdata_${uuid} appears after system boot up.
        pass_criteria: 
            The passed userdata /tmp/userdata_${uuid} exists and can be edit and remove.
        '''
        user_name = self.params.get('remote_user')
        user_dir =  "/tmp/userdata_{}".format(self.run_uuid)
        cmd = "ls -l %s" % user_dir
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "sudo rm -rf %s" % user_dir
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_hibernate_resume(self):
        """
        case_tag:
            lifecycle
        case_name:
            test_hibernate_resume
        case_file:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_vm_operation.py
        component:
            kernel
        bugzilla_id:
            1898677
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Test system hibernation and process is still running after resumed
        key_steps: |
            1. enable hibernation on system
            2. start a test process, eg. sleep 1800
            3. hibernate system
            4. start system
            5. the test process still running
        expect_result:
            test process resume successfully
        debug_want:
            dmesg or console output
        """
        if not self.vm:
            self.skipTest('vm not init')
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_not_kw="Xen", msg="Not support in xen instance")
        utils_lib.is_cmd_exist(self,"acpid")
        if self.vm.provider == 'aws':
            product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
            if float(product_id) >= 8.0 and float(product_id) < 9.0:
                pkg_url='https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/e/ec2-hibinit-agent-1.0.4-1.el8.noarch.rpm'
            elif float(product_id) < 8.0:
                self.skipTest('not supported earlier than rhel8')
            else:
                pkg_url = "https://dl.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/e/ec2-hibinit-agent-1.0.3-5.fc34.noarch.rpm"
            utils_lib.pkg_install(self, pkg_name='ec2-hibinit-agent', pkg_url=pkg_url, force=True)
            cmd = 'sudo systemctl is-enabled hibinit-agent.service'
            output = utils_lib.run_cmd(self, cmd)
            if 'enabled' not in output:
                cmd = 'sudo systemctl enable --now hibinit-agent.service'
                utils_lib.run_cmd(self, cmd)
                utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
                utils_lib.init_connection(self, timeout=self.ssh_timeout)
                timeout = 180
                interval = 5
                time_start = int(time.time())
                while True:
                    cmd = 'sudo systemctl is-active hibinit-agent.service'
                    out = utils_lib.run_cmd(self, cmd)
                    if 'inactive' in out:
                        break
                    time_end = int(time.time())
                    if time_end - time_start > timeout:
                       self.log.info('timeout ended: {}'.format(timeout))
                       break
                    self.log.info('retry after {}s'.format(interval))
                    time.sleep(interval)
                cmd = 'sudo systemctl status hibinit-agent.service'
                utils_lib.run_cmd(self, cmd)
        else:
            cmd = 'cat /proc/swaps'
            output = utils_lib.run_cmd(self, cmd, msg='check whether system has swap on')
            if '-2' not in output:
                self.log.info("No swap found, creating new one")
                cmd = """
                    sudo dd if=/dev/zero of=/swap bs=1024 count=2000000;
                    sudo chmod 0600 /swap;
                    sudo mkswap /swap;
                    sudo swapon /swap;
                    offset=$(sudo filefrag -v /swap| awk '{if($1==\"0:\"){print $4}}');
                    uuid=$(findmnt -no UUID -T /swap);
                    sudo grubby --update-kernel=ALL  --args=\"resume_offset=${offset//.} resume=UUID=$uuid\";
                    echo '/swap    swap    swap   defaults 0 0' | sudo tee -a /etc/fstab
                    """
                utils_lib.run_cmd(self, cmd, timeout=240)

        cmd = "sleep 360 > /dev/null 2>&1 &"
        utils_lib.run_cmd(self, cmd)
        vm_hibernate_success = False
        try:
            if not self.vm.send_hibernation():
                self.skipTest('send hibernate not succeed')
            vm_hibernate_success = True
        except NotImplementedError:
            self.log.info('send_hibernation func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.log.info('send_hibernation func is not supported in {}'.format(self.vm.provider))
        if not vm_hibernate_success:
            cmd = "sudo systemctl hibernate"
            utils_lib.run_cmd(self, cmd, msg="Try to hibernate inside system!")
            time.sleep(20)

        self.vm.start()
        time.sleep(10)
        self.params['remote_node'] = self.vm.floating_ip
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, 'dmesg', expect_kw="Restarting tasks", expect_not_kw="Call", msg="check the system is resumed")
        cmd = 'pgrep -a sleep'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check sleep process still exists')

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
        try:
            is_success = self.vm.send_nmi()
        except UnSupportedAction as err:
            self.skipTest("current {} not support nmi operation".format(self.vm.provider))
        if not is_success:
            self.fail("Cannot trigger panic via nmi!")
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
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
        try:
            is_success = self.vm.send_nmi()
        except UnSupportedAction as err:
            self.skipTest("current {} not support nmi operation".format(self.vm.provider))
        if not is_success:
            self.fail("Cannot trigger panic via nmi!")
        time.sleep(10)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self,
                    r'sudo ls /var/crash/',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/1*/vmcore-dmesg.txt|tail -50'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='nmi_panic')

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

        netdev_index = 1
        self.vm.attach_nic(self.nic,device_index=1, wait=True)
        for i in range(1, 4):
            time.sleep(5)
            self.log.info('Check network in guest, loop {}'.format(i))
            cmd = "lspci"
            output1 = utils_lib.run_cmd(self, cmd)
            cmd = "ip addr show"
            output1 = utils_lib.run_cmd(self, cmd)
            if 'eth%s' % netdev_index not in output1:
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
        utils_lib.run_cmd(self, cmd)
        self.nic.delete()
        self.assertIn('eth%d' % netdev_index,
                      output1,
                      msg='eth{} not found after attached nic'.format(netdev_index))
        cmd = 'dmesg'
        utils_lib.run_cmd(self, cmd, expect_not_kw='Call Trace')

    def tearDown(self):
        if self.nic and self.nic.is_exist():
            self.nic.delete()

if __name__ == '__main__':
    unittest.main()