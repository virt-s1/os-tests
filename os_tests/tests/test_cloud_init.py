import unittest
from os_tests.libs import utils_lib

class TestCloudInit(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

        cmd = "sudo systemctl is-enabled cloud-init-local"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "check cloud-init-local is enabled")

    def test_check_cloudinit_cfg_no_wheel(self):
        '''
        bz: 1549638
        cm: 01965459
        polarion_id:
        des: make sure there is no wheel in default_user's group in "/etc/cloud/cloud.cfg"
        '''
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='wheel',
                    msg='check /etc/cloud/cloud.cfg to make sure no wheel in default_user group(bz1549638)')

    def test_check_cloudinit_ds_identify_found(self):
        '''
        polarion_id:
        bz: 1746627
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
        bz: 1957532
        cm: 02905983
        polarion_id:
        check fingerprints is saved in /var/log/messages.
        expected:
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
        polarion_id:
        bz: 1810704
        check cloud-init use imdsv2 in aws
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
        polarion_id:
        bz: 1827207
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
        polarion_id:
        bz: 1827207
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
        polarion_id:
        bz: 1821999
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
        polarion_id:
        bz: 1821999
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
        polarion_id:
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
        polarion_id:
        https://cloudinit.readthedocs.io/en/latest/topics/datasources/ec2.html
        '''
        cmd = r"curl http://169.254.169.254/latest/meta-data/instance-type"

        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw="Not Found")

    def test_check_output_isexist(self):
        '''
        polarion_id:
        bz: 1626117
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
        polarion_id:
        bz: 1829713
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
        description:
            '/etc/ssh/sshd_config' allows key value empty, this case check if cloud-init can handle such situation.
            This bz is reported by customer.
        polarion_id:
            n/a
        bugzilla_id: 
            1527649, 1862933
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            2
        case_component: 
            cloud-init
        key_steps:
            # sudo echo 'DenyUsers'>>/etc/ssh/sshd_config
            # sudo cloud-init clean
            # sudo grep 'SSH credentials failed' /var/log/cloud-init.log
        pass_criteria: 
            No 'SSH credentials failed' found
        debug_want:
            # cat /var/log/cloud-init.log
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

    def tearDown(self):
        if 'test_cloudinit_sshd_keypair' in self.id():
            cmd = 'cp -f ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys'
            utils_lib.run_cmd(self, cmd, msg='restore .ssh/authorized_keys')
            cmd= 'sudo systemctl restart  sshd'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='restart sshd service')

if __name__ == '__main__':
    unittest.main()