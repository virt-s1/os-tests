import unittest
from os_tests.libs import utils_lib
from os_tests.libs.resources import UnSupportedAction
import time

class TestCloudInit(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

        cmd = "sudo systemctl is-enabled cloud-init-local"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "check cloud-init-local is enabled")

    def test_check_cloudinit_cfg_no_wheel(self):
        '''
        case_tag:
            cloudinit
        bz: 1549638
        cm: 01965459
        polarion_id:
        description:
            make sure there is no wheel in default_user's group in "/etc/cloud/cloud.cfg"
        '''
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='wheel',
                    msg='check /etc/cloud/cloud.cfg to make sure no wheel in default_user group(bz1549638)')

    def test_check_cloudinit_ds_identify_found(self):
        '''
        case_tag:
            cloudinit,cloudinit_tier1
        bz:
            1746627
        description:
            check ds-identify run and ret found
        '''
        cmd = 'rpm -q cloud-init'
        utils_lib.run_cmd(self, cmd, cancel_not_kw='el8_0')
        cmd = 'sudo cat /run/cloud-init/cloud-init-generator.log'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='ds-identify _RET=found',
                    msg='check /run/cloud-init/cloud-init-generator.log')

    def test_check_cloudinit_fingerprints(self):
        '''
        case_tag:
            cloudinit
        bz: 1957532
        cm: 02905983
        polarion_id:
        description:
            check fingerprints is saved in /var/log/messages.
        expect_result: |
            # grep -A 4 'BEGIN SSH HOST KEY FINGERPRINTS' /var/log/messages
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: -----BEGIN SSH HOST KEY FINGERPRINTS-----
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: 256 SHA256:n+iS6HUI/ApfkE/ZveBzBrIFSsmcL1YR/c3RsbPShd8 no comment (ECDSA)
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: 256 SHA256:lZSyEuxf421H9y2DnoadjIvidZWXvGL3wfRlwAFBnms no comment (ED25519)
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: 3072 SHA256:gysD1LLAkwZIovBEZdzX7s/dCJBegc+jnCtH7cJkIOo no comment (RSA)
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: -----END SSH HOST KEY FINGERPRINTS-----
        '''
        # cmd = "sudo grep -A 4 'BEGIN SSH HOST KEY FINGERPRINTS' /var/log/messages"
        cmd = "sudo awk '/BEGIN/,/END/' /var/log/messages"
        out = utils_lib.run_cmd(self, cmd, msg='get fingerprints in /var/log/messages')
        if out.count('BEGIN') != out.count('SHA256')/3:
            self.fail('fingerprints count {} does not match expected {}'.format(out.count('SHA256')/3,out.count('BEGIN')))

    def test_check_cloudinit_log_imdsv2(self):
        '''
        case_name:
            test_check_cloudinit_log_imdsv2
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1810704
        customer_case_id:
            02601864
        polarion_id:
            n/a
        maintainer:
            xiliang@redhat.com
        description:
            Check cloud-init use imdsv2 in aws.
        key_steps:
            1.#sudo grep -Ri amazon /sys/devices/virtual/dmi/id/bios*
            2.#sudo rpm -ql cloud-init|grep -w DataSourceEc2.py
            3.#sudo cat "output of step2"|grep IMDSv2
            4.#sudo cat /var/log/cloud-init.log
        expected_result:
            There is keyword "Fetching Ec2 IMDSv2 API Token,X-aws-ec2-metadata-token' in /var/log/cloud-init.log.
        '''
        cmd = "sudo grep -Ri amazon /sys/devices/virtual/dmi/id/bios*"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "Only used in EC2 platform")
        cmd = "sudo rpm -ql cloud-init|grep -w DataSourceEc2.py"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Get DataSourceEc2.py')
        cmd = "sudo cat " + output + "|grep IMDSv2"
        utils_lib.run_cmd(self, cmd,
                    cancel_kw="Fetching Ec2 IMDSv2 API Token",
                    msg='Check IMDSv2 support')
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_kw='Fetching Ec2 IMDSv2 API Token,X-aws-ec2-metadata-token',
                    msg='check /var/log/cloud-init.log')

    def test_check_cloudinit_log_unexpected(self):
        '''
        case_tag:
            cloudinit
        polarion_id:
        bz: 1827207
        description:
            check no unexpected error log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='unexpected',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='unexpected',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_critical(self):
        '''
        case_tag:
            cloudinit
        polarion_id:
        bz: 1827207
        description:
            check no critical log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='CRITICAL',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='CRITICAL',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_warn(self):
        '''
        case_tag:
            cloudinit
        polarion_id:
        bz: 1821999
        description:
            check no warning log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='WARNING',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='WARNING',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_error(self):
        '''
        case_tag:
            cloudinit
        polarion_id:
        bz: 1821999
        description:
            check no error log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='ERROR',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='ERROR',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_traceback(self):
        '''
        case_tag:
            cloudinit
        polarion_id:
        description:
            check no traceback log in cloudinit logs
        '''
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='Traceback',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='Traceback',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_metadata(self):
        '''
        case_tag:
            cloudinit
        polarion_id:
        description:
            https://cloudinit.readthedocs.io/en/latest/topics/datasources/ec2.html
        '''
        if self.vm.provider == 'nutanix':
            self.skipTest('skip run for nutanix platform on which use config drive to fetch metadata but not http service')
        cmd = r"curl http://169.254.169.254/latest/meta-data/instance-type"

        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw="Not Found")

    def test_check_output_isexist(self):
        '''
        case_tag:
            cloudinit
        polarion_id:
        bz: 1626117
        description:
            check whether /var/log/cloud-init-output.log exists
        '''
        utils_lib.run_cmd(self,
                    'uname -r',
                    cancel_not_kw='el7,el6',
                    msg='cancel it in RHEL7')
        datasource = None
        if utils_lib.is_ali(self):
            datasource = 'Datasource DataSourceAliYun'
        if utils_lib.is_aws(self):
            datasource = 'Datasource DataSourceEc2'
        cmd = 'sudo cat /var/log/cloud-init-output.log'
        if datasource is not None:    
            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=datasource,
                        msg='check /var/log/cloud-init-output.log exists status')
        else:
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='check /var/log/cloud-init-output.log exists status')

    def test_check_cloudinit_service_status(self):
        '''
        case_tag:
            cloudinit
        polarion_id:
        bugzilla_id:
            1829713
        description:
            The 4 cloud-init services status should be "active"
        '''
        service_list = ['cloud-init-local',
                        'cloud-init',
                        'cloud-config',
                        'cloud-final']
        for service in service_list:
            cmd = "sudo systemctl status %s" % service
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='Active: active', msg = "check %s status" % service)
            cmd = "sudo systemctl is-active %s" % service
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='active', msg = "check %s status" % service)

    def test_cloudinit_sshd_keypair(self):
        '''
        case_tag:
            cloudinit
        case_file:
            https://github.com/liangxiao1/os-tests/blob/master/os_tests/tests/test_cloud_init.py
        description:
            The '/etc/ssh/sshd_config' allows key value empty, this case check if cloud-init can handle such situation.
        testplan:
            n/a
        bugzilla_id: 
            1527649, 1862933
        is_customer_case: 
            True
        maintainer: 
            xiliang
        case_priority: 
            2
        component: 
            cloud-init
        key_steps: |
            # sudo echo 'DenyUsers'>>/etc/ssh/sshd_config
            # sudo cloud-init clean
            # sudo grep 'SSH credentials failed' /var/log/cloud-init.log
        expect_result: 
            No 'SSH credentials failed' found
        debug_want:
            Please attach /var/log/cloud-init.log
        '''
        cmd = 'cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak'
        utils_lib.run_cmd(self, cmd, msg='backup .ssh/authorized_keys')
        cmd = 'sudo cp -f /etc/ssh/sshd_config /etc/ssh/sshd_config.bak'
        utils_lib.run_cmd(self, cmd, msg='backup /etc/ssh/sshd_config')
        cmd = "sudo sed -i '/DenyUsers/d' /etc/ssh/sshd_config"
        utils_lib.run_cmd(self, cmd, msg='delete old config if has')
        cmd = "sudo bash -c 'echo DenyUsers >> /etc/ssh/sshd_config'"
        utils_lib.run_cmd(self, cmd, msg='append empty DenyUsers filed')
        cmd = "sudo cloud-init clean"
        utils_lib.run_cmd(self, cmd, msg='clean cloud-init')
        cmd = "sudo cloud-init init"
        utils_lib.run_cmd(self, cmd, msg='init cloud-init again')
        cmd = 'sudo cp -f /etc/ssh/sshd_config.bak /etc/ssh/sshd_config'
        utils_lib.run_cmd(self, cmd, msg='restore /etc/ssh/sshd_config')  
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='SSH credentials failed',
                    expect_kw='value pair',
                    msg='check /var/log/cloud-init.log')  

    def _get_boot_temp_devices(self):
        boot_dev = utils_lib.run_cmd(self,
                        "mount|grep 'boot'|head -1|cut -c1-8")
        temp_dev = '/dev/sda' if boot_dev == '/dev/sdb' else '/dev/sdb'
        return(boot_dev, temp_dev)

    def test_cloudinit_auto_extend_root_partition_and_filesystem(self):
        """
        case_tag:
            cloudinit
        case_priority:
            1
        component:
            cloud-init,cloud_utils_growpart
        description:
            RHEL7-103839 - CLOUDINIT-TC: Auto extend root partition and filesystem
        key_steps:
            1. Install cloud-utils-growpart gdisk if not installed(bug 1447177)
            2. Check os disk and fs capacity
            3. Enlarge os disk
            4. Check os disk and fs capacity
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")

        self.log.info("RHEL7-103839 - CLOUDINIT-TC: Auto extend root partition and filesystem")
        # 1. Install cloud-utils-growpart gdisk
        utils_lib.is_cmd_exist(self, cmd='growpart')
        utils_lib.is_cmd_exist(self, cmd='gdisk')
        
        # 2. Check os disk and fs capacity
        boot_dev = self._get_boot_temp_devices()[0].split('/')[-1].replace('\n', '')
        dev_size = utils_lib.run_cmd(self, "lsblk /dev/{0} --output NAME,SIZE -r |grep -o -P '(?<={0} ).*(?=G)'".format(boot_dev))
        os_disk_size = int(self.vm.show()['vm_disk_info'][0]['size'])/(1024*1024*1024)
        self.assertAlmostEqual(
            first=float(dev_size),
            second=float(os_disk_size),
            delta=1,
            msg="Device size is incorrect. Raw disk: %s, real: %s" %(dev_size, os_disk_size)
        )
        # 3. Enlarge os disk size
        try:
            self.disk.modify_disk_size(os_disk_size, 2)
        except NotImplementedError:
            self.skipTest('modify disk size func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('modify disk size is not supported in {}'.format(self.vm.provider))
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=1200)
        boot_dev = self._get_boot_temp_devices()[0].split('/')[-1].replace('\n', '')
        partition = utils_lib.run_cmd(self,
            "find /dev/ -name {}[0-9]|sort|tail -n 1".format(boot_dev)).replace('\n', '')
        new_dev_size = utils_lib.run_cmd(self,
            "lsblk /dev/{0} --output NAME,SIZE -r"
            "|grep -o -P '(?<={0} ).*(?=G)'".format(boot_dev))
        new_fs_size = utils_lib.run_cmd(self,
            "df {} --output=size -h|grep -o '[0-9]\+'".format(partition))
        new_os_disk_size=os_disk_size+2
        self.assertEqual(
            int(new_dev_size), int(new_os_disk_size),
            "New device size is incorrect. "
            "Device: %s, real: %s" % (new_dev_size, new_os_disk_size)
        )
        self.assertAlmostEqual(
            first=float(new_fs_size),
            second=float(new_os_disk_size),
            delta=1.5,
            msg="New filesystem size is incorrect. "
                "FS: %s, real: %s" %
                (new_fs_size, new_os_disk_size)
        )

    def tearDown(self):
        if 'test_cloudinit_sshd_keypair' in self.id():
            cmd = 'cp -f ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys'
            utils_lib.run_cmd(self, cmd, msg='restore .ssh/authorized_keys')
            cmd= 'sudo systemctl restart  sshd'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='restart sshd service')
        #utils_lib.finish_case(self)

if __name__ == '__main__':
    unittest.main()