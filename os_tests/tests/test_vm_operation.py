import unittest
import time
from os_tests.libs import utils_lib

class TestVMOperation(unittest.TestCase):
    '''
    Only run in server-client mode.
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

    def test_kdump_unknown_nmi_panic_enabled(self):
        '''
        :avocado: tags=test_kdump_unknown_nmi_panic_enabled,acceptance,outposts
        description:
            Test Diagnostic Interrupt triggers the kdump when unknown_nmi_panic is enabled with RHEL on AWS. https://aws.amazon.com/blogs/aws/new-trigger-a-kernel-panic-to-diagnose-unresponsive-ec2-instances/
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]KdumpTest.test_kdump_unknown_nmi_panic_enabled"
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