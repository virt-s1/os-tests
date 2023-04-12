import unittest
from os_tests.libs import utils_lib
from os_tests.libs.resources import UnSupportedAction
import time
import re
import json
import os

class TestCloudInit(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        cmd = "sudo systemctl is-enabled cloud-init-local"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "check cloud-init-local is enabled")
        if 'test_cloudinit_no_networkmanager' in self.id():
            self.NM_install = utils_lib.run_cmd(self, "rpm -q NetworkManager", ret_status=True)
            self.network_install = utils_lib.run_cmd(self, "rpm -q network-scripts", ret_status=True)

    @property
    def rhel_x_version(self):
        product_id = utils_lib.get_product_id(self)
        return int(product_id.split('.')[0])

    def test_check_cloudinit_cfg_no_wheel(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_check_cloudinit_cfg_no_wheel
        component:
            cloud-init
        bugzilla_id:
            1549638
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            make sure there is no wheel in default_user's group in "/etc/cloud/cloud.cfg"
        key_steps:
            1. check cloud config file
        expect_result:
            there's no 'wheel' saved in log file
        debug_want:
            cloud.cfg
        """
        cmd = 'sudo cat /etc/cloud/cloud.cfg'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='wheel',
                    msg='check /etc/cloud/cloud.cfg to make sure no wheel in default_user group(bz1549638)')

    def test_check_cloudinit_ds_identify_found(self):
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_name:
            test_check_cloudinit_ds_identify_found
        component:
            cloud-init
        bugzilla_id:
            1746627
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check if ds-identify can run and ret is found
        key_steps:
            1.rpm -q cloud-init
            2.check cloud-init-generator log 
        expect_result:
            no error and return 0
        debug_want:
            cloud init log file
        """
        cmd = 'rpm -q cloud-init'
        utils_lib.run_cmd(self, cmd, cancel_not_kw='el8_0')
        cmd = 'sudo cat /run/cloud-init/cloud-init-generator.log'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='ds-identify rc=0',
                    msg='check /run/cloud-init/cloud-init-generator.log')

    def test_check_cloudinit_fingerprints(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_check_cloudinit_fingerprints
        component:
            cloud-init
        bugzilla_id:
            1957532
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check if fingerprints is saved in /var/log/messages.
        key_steps:
            1.sudo awk '/BEGIN/,/END/' /var/log/messages
            2.check result
        expect_result:
            # grep -A 4 'BEGIN SSH HOST KEY FINGERPRINTS' /var/log/messages
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: -----BEGIN SSH HOST KEY FINGERPRINTS-----
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: 256 SHA256:n+iS6HUI/ApfkE/ZveBzBrIFSsmcL1YR/c3RsbPShd8 no comment (ECDSA)
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: 256 SHA256:lZSyEuxf421H9y2DnoadjIvidZWXvGL3wfRlwAFBnms no comment (ED25519)
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: 3072 SHA256:gysD1LLAkwZIovBEZdzX7s/dCJBegc+jnCtH7cJkIOo no comment (RSA)
            May  6 02:57:58 ip-10-116-2-239 ec2[1441]: -----END SSH HOST KEY FINGERPRINTS-----
        debug_want:
            /var/log/messages
        """
        # cmd = "sudo grep -A 4 'BEGIN SSH HOST KEY FINGERPRINTS' /var/log/messages"
        cmd = "sudo awk '/BEGIN/,/END/' /var/log/messages"
        out = utils_lib.run_cmd(self, cmd, msg='get fingerprints in /var/log/messages')
        if out.count('BEGIN') != out.count('SHA256')/3:
            self.fail('fingerprints count {} does not match expected {}'.format(out.count('SHA256')/3,out.count('BEGIN')))

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') == 'aws', 'aws dedicated feature')
    def test_check_cloudinit_log_imdsv2(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_check_cloudinit_log_imdsv2
        case_file:
            test_cloud_init.py
        component:
            kernel
        bugzilla_id:
            1810704
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Check cloud-init use imdsv2 in aws
        key_steps:
            1.#sudo grep -Ri amazon /sys/devices/virtual/dmi/id/bios*
            2.#sudo rpm -ql cloud-init|grep -w DataSourceEc2.py
            3.#sudo cat "output of step2"|grep IMDSv2
            4.#sudo cat /var/log/cloud-init.log
        expect_result:
            There is keyword "Fetching Ec2 IMDSv2 API Token,X-aws-ec2-metadata-token' in /var/log/cloud-init.log.
        debug_want:
            cloud-init
        """
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
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_check_cloudinit_log_unexpected
        component:
            cloud-init
        bugzilla_id:
            1827207
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check no unexpected error log in cloudinit logs
        key_steps:
            1.check there is no unexpected saved in cloud init log
        expect_result:
            no token saved in log
        debug_want:
            cloud init log
        """
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
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_name:
            test_check_cloudinit_log_critical
        case_file:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_cloud_init.py
        component:
            cloud-init
        bugzilla_id:
            1827207
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check if there is CRITICAL saved in log file
        key_steps:
            1. check cloud init log file
        expect_result:
            no CRITICAL saved in log file
        debug_want:
            cloud init log file
        """
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
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_check_cloudinit_log_warn
        component:
            cloud-init
        bugzilla_id:
            1821999
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check no warning log in cloudinit logs
        key_steps:
            1.check if there are WARNING in cloud-init.log
        expect_result:
            no WARNING saved in log file
        debug_want:
            cloud init log file
        """
        #define string to avoid /dev/console issue on nutanix
        plus_grep = ' | grep WARNING | grep -Pvo "scripts-user|console|cc_ssh_authkey_fingerprints"'
        if self.vm.provider == 'nutanix':
            cmd='sudo cat /var/log/cloud-init.log' + plus_grep
        else:
            cmd='sudo cat /var/log/cloud-init.log'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_not_kw='WARNING',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            if self.vm.provider == 'nutanix':
                cmd='sudo cat /var/log/cloud-init-output.log' + plus_grep
            else:
                cmd='sudo cat /var/log/cloud-init-output.log'
            utils_lib.run_cmd(self,
                        cmd,
                        expect_not_kw='WARNING',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_error(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_check_cloudinit_log_error
        component:
            cloud-init
        bugzilla_id:
            1821999
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check if there is error log in cloud init log file
        key_steps:
            1.check cloud init log file
        expect_result:
            there is no ERROR saved in log file
        debug_want:
            cloud init log file
        """
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
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_check_cloudinit_log_traceback
        component:
            cloud-init
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            check if there's no traceback log in cloudinit logs
        key_steps:
            1.check cloud-init log file
        expect_result:
            no Traceback saved in log file
        debug_want:
            cloud-init log file
        """
        #workaround nutanix dev console issue
        if self.vm and self.vm.provider == 'nutanix':
            cmd = '''cat /var/log/cloud-init.log | grep -Pzo "Traceback.*\\n\s+File.*" | \
grep -Pzv "stages.py\\",\s+line\s+[1088|1087]|util.py\\",\s+line\s+[399|400]"'''
        else:
            cmd = 'sudo cat /var/log/cloud-init.log'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_not_kw='Traceback',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='Traceback',
                        msg='check /var/log/cloud-init-output.log')

    @unittest.skipIf(os.getenv('INFRA_PROVIDER') == 'nutanix', 'nutanix platform on which use config drive to fetch metadata but not http service')
    def test_check_metadata(self):
        '''
        case_tag:
            cloudinit,cloudinit_tier2
        polarion_id:
        description:
            https://cloudinit.readthedocs.io/en/latest/topics/datasources/ec2.html
        '''
        if utils_lib.is_ali(self):
            cmd = r"curl http://100.100.100.200/latest/meta-data"
        else:
            cmd = r"curl http://169.254.169.254/latest/meta-data/instance-type"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw="Not Found")

    def test_check_output_isexist(self):
        '''
        case_tag:
            cloudinit,cloudinit_tier1
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
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_name:
            test_check_cloudinit_service_status
        component:
            cloud-init
        bugzilla_id:
            1829713
        is_customer_case:
            False
        maintainer:
            xiliang@redhat.com
        description:
            The 4 cloud-init services status should be "active"
        key_steps:
            1.start a RHEL-7.9 AMI on aws and check service status
        expect_result:
            cloud-final.service not failed
        debug_want:
            N/A
        """
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
            cloudinit,cloudinit_tier2
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
        out = utils_lib.run_cmd(self,"lsblk -d|awk -F' ' '{print $1}'", msg='get all disks')
        disks = out.split('\n')
        boot_dev = '/dev/sda'
        boot_part = utils_lib.run_cmd(self,'mount|grep boot|head -1', msg='get boot part')
        for disk in disks:
            if disk in boot_part:
                boot_dev = disk
                break
        self.log.info("Detected boot device:{}".format(boot_dev))
        return boot_dev

    def test_cloudinit_auto_extend_root_partition_and_filesystem(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_auto_extend_root_partition_and_filesystem
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_auto_extend_root_partition_and_filesystem
        component:
            cloud-init,cloud_utils_growpart
        bugzilla_id:
            1447177
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            RHEL7-103839 - CLOUDINIT-TC: Auto extend root partition and filesystem
        key_steps: |
            1. Install cloud-utils-growpart gdisk if not installed(bug 1447177)
            2. Check os disk and fs capacity
            3. Enlarge os disk
            4. Check os disk and fs capacity
        expect_result:
            1. OS disk and fs capacity check right.
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")

        # 1. Install cloud-utils-growpart gdisk
        utils_lib.is_cmd_exist(self, cmd='growpart')
        utils_lib.is_cmd_exist(self, cmd='gdisk')
        
        # 2. Check os disk and fs capacity
        boot_dev = self._get_boot_temp_devices()
        dev_size = utils_lib.run_cmd(self, "lsblk /dev/{0} --output NAME,SIZE -r |grep -o -P '(?<={0} ).*(?=G)'".format(boot_dev))
        is_support = True
        try:
            os_disk_size = int(self.vm.show()['vm_disk_info'][0]['size'])/(1024*1024*1024)
        except Exception as err:
            is_support = False
            self.log.info(err)
        if not is_support:
            self.skipTest("This might not be supported in your platform to get vm_disk_info")
        self.assertAlmostEqual(
            first=float(dev_size),
            second=float(os_disk_size),
            delta=1,
            msg="Device size is incorrect. Raw disk: %s, real: %s" %(dev_size, os_disk_size)
        )
        # 3. Enlarge os disk size
        try:
            self.disk.modify_disk_size(os_disk_size, 'scsi', 0, 2)
        except NotImplementedError:
            self.skipTest('modify disk size func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('modify disk size func is not supported in {}'.format(self.vm.provider))
        utils_lib.run_cmd(self, 'sudo reboot', msg='reboot system under test')
        time.sleep(10)
        utils_lib.init_connection(self, timeout=1200)
        boot_dev = self._get_boot_temp_devices()
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

    def test_cloudinit_login_with_password(self):
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_name:
            test_cloudinit_login_with_password
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_login_with_password
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description: |
            VM can successfully login after provisioning(with password authentication).
            Linked case: test_cloudinit_remove_cache_and_reboot_password
        key_steps:
            1. Create a VM with only password authentication
        expect_result:
            1. Login with password, should have sudo privilege
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        if self.vm.provider == 'openstack':
            self.skipTest('skip run as openstack uses userdata to config the password')
        for attrname in ['ssh_pubkey', 'get_vm_by_filter', 'prism']:
            if not hasattr(self.vm, attrname):
                self.skipTest("no {} for {} vm".format(attrname, self.vm.provider))
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        save_ssh_pubkey = self.vm.ssh_pubkey
        self.vm.ssh_pubkey = None
        self.vm.create(wait=True)
        #test passwork login to new vm
        NewVM = self.vm.get_vm_by_filter("vm_name", self.vm.vm_name)
        start_task = self.vm.prism.start_vm(NewVM['uuid'])
        self.log.info("start task status is %s" % format(start_task))
        time.sleep(60)
        for nic in NewVM.get('vm_nics'):
            if nic['network_uuid'] == self.vm.network_uuid:
                NewVM_ip = nic['ip_address']
        test_login = utils_lib.send_ssh_cmd(NewVM_ip, self.vm.vm_username, self.vm.vm_password, "whoami")
        self.assertEqual(self.vm.vm_username,
                         test_login[1].strip(),
                         "Fail to login with password: %s" % format(test_login[1].strip()))
        test_sudo = utils_lib.send_ssh_cmd(NewVM_ip, self.vm.vm_username, self.vm.vm_password, "sudo cat /etc/sudoers.d/90-cloud-init-users")
        self.assertIn(self.vm.vm_username,
                         test_sudo[1].strip(),
                         "Fail to check login user name: %s" % format(test_sudo[1].strip()))
        self.log.info("Test case test_cloudinit_remove_cache_and_reboot_password together")
        cmd = "sudo rm -rf /var/lib/cloud/instances/* \n sudo reboot"
        utils_lib.send_ssh_cmd(NewVM_ip, self.vm.vm_username, self.vm.vm_password, cmd)
        time.sleep(40)
        test_login = utils_lib.send_ssh_cmd(NewVM_ip, self.vm.vm_username, self.vm.vm_password, "whoami")
        self.assertEqual(self.vm.vm_username,
                         test_login[1].strip(),
                         "Fail to login with password: %s" % format(test_login[1].strip()))
        #teardown
        self.vm.ssh_pubkey=save_ssh_pubkey
        self.vm.delete()
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def test_cloudinit_verify_hostname(self):
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_name:
            test_cloudinit_verify_hostname
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_verify_hostname
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Successfully set VM hostname
        key_steps:
            1. Check hostname is correct
        expect_result:
            1. Host name is correct
        debug_want:
            N/A
        """
        output = utils_lib.run_cmd(self, "hostname", expect_ret=0).rstrip('\n')
        self.assertEqual(output, self.vm.vm_name.replace('_', '-'),
                         "The hostname is wrong")
        
    def _cloudinit_auto_resize_partition(self, label):
        """
        :param label: msdos/gpt
        """
        utils_lib.run_cmd(self, "sudo su -")
        utils_lib.run_cmd(self, "which growpart", expect_ret=0, msg="test growpart command.")
        device = "/tmp/testdisk"
        if "/dev" not in device:
            utils_lib.run_cmd(self, "rm -f {}".format(device))
        utils_lib.run_cmd(self, "truncate -s 2G {}".format(device))
        utils_lib.run_cmd(self, "parted -s {} mklabel {}".format(device, label))
        part_type = "primary" if label == "msdos" else ""
         # 1 partition
        utils_lib.run_cmd(self, "parted -s {} mkpart {} xfs 0 1000".format(device, part_type))
        utils_lib.run_cmd(self, "parted -s {} print".format(device))
        utils_lib.run_cmd(self, "growpart {} 1".format(device), expect_ret=0, msg="test to run growpart")
        self.assertEqual(
            "2147MB",
            utils_lib.run_cmd(self,
                "parted -s %s print|grep ' 1 '|awk '{print $3}'" % device, expect_ret=0).strip(),
            "Fail to resize partition")
        # 2 partitions
        utils_lib.run_cmd(self, "parted -s {} rm 1".format(device))
        utils_lib.run_cmd(self,
            "parted -s {} mkpart {} xfs 0 1000".format(device, part_type))
        utils_lib.run_cmd(self,
            "parted -s {} mkpart {} xfs 1800 1900".format(device, part_type))
        utils_lib.run_cmd(self, "parted -s {} print".format(device))
        utils_lib.run_cmd(self, "growpart {} 1".format(device), expect_ret=0)
        self.assertEqual(
            "1800MB",
            utils_lib.run_cmd(self,
                "parted -s %s print|grep ' 1 '|awk '{print $3}'" % device, expect_ret=0).strip(),
            "Fail to resize partition")

    def test_cloudinit_auto_resize_partition_in_gpt(self):
        """
        case_tag:
            cloud_utils_growpart,cloud_utils_growpart_tier1
        case_name:
            test_cloudinit_auto_resize_partition_in_gpt
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_auto_resize_partition_in_gpt
        component:
            cloudinit
        bugzilla_id:
            1695091
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Auto resize partition in gpt
        key_steps:
            1. parted and growpart command
        expect_result:
            1. Successfully resize partition in gpt
        debug_want:
            N/A
        """
        self._cloudinit_auto_resize_partition("gpt")

    def test_cloudinit_auto_resize_partition_in_mbr(self):
        """
        case_tag:
            cloud_utils_growpart,cloud_utils_growpart_tier1
        case_name:
            test_cloudinit_auto_resize_partition_in_mbr
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_auto_resize_partition_in_mbr
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Auto resize partition in mbr
        key_steps:
            1. parted and growpart command
        expect_result:
            1. Successfully resize partition in mbr
        debug_want:
            N/A
        """
        self._cloudinit_auto_resize_partition("msdos")

    def test_cloudinit_start_sector_equal_to_partition_size(self):
        """
        case_tag:
            cloud_utils_growpart,cloud_utils_growpart_tier1
        case_name:
            test_cloudinit_start_sector_equal_to_partition_size
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_start_sector_equal_to_partition_size
        component:
            cloudinit
        bugzilla_id:
            1593451
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Start sector equal to partition size
        key_steps:
            1. Check start sector
        expect_result:
            1. Start sector equal to partition size
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self, "sudo su -")
        utils_lib.run_cmd(self, "which growpart", expect_ret=0, msg="test growpart command.")
        device = "/tmp/testdisk"
        if "/dev" not in device:
            utils_lib.run_cmd(self, "rm -f {}".format(device), expect_ret=0)
        utils_lib.run_cmd(self, "truncate -s 2G {}".format(device), expect_ret=0)
        size = "1026048"
        utils_lib.run_cmd(self, """
cat > partitions.txt <<EOF
# partition table of {0}
unit: sectors

{0}1 : start= 2048, size= 1024000, Id=83
{0}2 : start= {1}, size= {1}, Id=83
EOF""".format(device, size), expect_ret=0)
        utils_lib.run_cmd(self, "sfdisk {} < partitions.txt".format(device), expect_ret=0)
        utils_lib.run_cmd(self, "growpart {} 2".format(device), expect_ret=0)
        start = utils_lib.run_cmd(self,
            "parted -s %s unit s print|grep ' 2 '|awk '{print $2}'" % device, expect_ret=0)
        end = utils_lib.run_cmd(self,
            "parted -s %s unit s print|grep ' 2 '|awk '{print $3}'" % device, expect_ret=0)
        self.assertEqual(start.strip(), size + 's', "Start size is not correct")
        self.assertEqual(end.strip(), '4194270s', "End size is not correct")

    @unittest.skipIf(os.getenv('INFRA_PROVIDER') != 'nutanix', 'needs to configure vm_custom_file which is configured on nutanix')
    def test_cloudinit_save_and_handle_customdata_script(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_save_and_handle_customdata_script
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_save_and_handle_customdata_script
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description: |
            Test if custom data as script can be executed. File man-page-day.sh has be pre-uploaded and configured when provision VM.
            Linked case test_cloudinit_man_page.
        key_steps: |
            1. Create VM with custom data.
            2. Check if custom data as script can be executed.
        expect_result:
            Custom data as script can be executed.
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self,"sudo chmod 777 /tmp/%s" % self.vm.vm_custom_file)
        res = utils_lib.run_cmd(self,"sudo /tmp/%s cloud-init" % self.vm.vm_custom_file)
        self.assertIn("13x OK", res, "man-page-day.sh check failed.")

    @unittest.skipIf(os.getenv('INFRA_PROVIDER') != 'nutanix', 'needs to configure single_nic which is configured on nutanix')
    def test_cloudinit_provision_vm_with_multiple_nics(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_provision_vm_with_multiple_nics
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_provision_vm_with_multiple_nics
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Provision VM with multiple NICs
        key_steps: |
            1. Create a VM with 2 NICs.
            2. Check if can provision and connect to the VM successfully.
        expect_result:
            VM can provision and connect successfully
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        self.vm.delete(wait=True)
        self.vm.create(single_nic=False, wait=True)
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        ip_list_vm = utils_lib.run_cmd(self,
            "ip addr|grep -Po 'inet \\K.*(?=/)'|grep -v '127.0.0.1'").strip().split('\n')
        ip_list_vm.sort()
        ip_list_host = []
        for nic in self.vm.show()["vm_nics"]:
            ip_list_host.append(nic["ip_address"])
        ip_list_host.sort()
        self.assertGreater(len(ip_list_vm), 1, "VM not create by multi nics")
        self.assertEqual(
            ip_list_vm, ip_list_host, "The private IP addresses are wrong.\n"
            "Expect: {}\nReal: {}".format(ip_list_host, ip_list_vm))
        #tear down
        self.vm.delete(wait=True)
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def test_cloudinit_login_with_publickey(self):
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_priority:
            1
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            VIRT-103831 - CLOUDINIT-TC: VM can successfully login after provisioning(with public key authentication)
        key_steps:        
        1. Create a VM with only public key authentication
        2. Login with publickey, should have sudo privilege
        """
        output=utils_lib.run_cmd(self, "whoami", expect_ret=0)
        self.assertEqual(
            self.vm.vm_username, output.rstrip('\n'),
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output.rstrip('\n'))
        sudooutput=utils_lib.run_cmd(self, "sudo cat /etc/sudoers.d/90-cloud-init-users", expect_ret=0)
        self.assertIn(
            "%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
            sudooutput,
            "No sudo privilege")

    def test_cloudinit_datasource(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_priority:
            1
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-286739 - CLOUDINIT-TC: Check the datasource on openstack, aws, nutanix, Ali
        key_steps:        
        1. Launch instance with cloud-init installed
        2. Check the datasource is correct
        # cat /run/cloud-init/cloud.cfg
        """
        datasource={'openstack':'OpenStack',
                    'aws':'Ec2',
                    'nutanix':'ConfigDrive',
                    'Ali':'AliYun'}
        if self.vm.provider not in datasource.keys():
            self.skipTest('skip run as no such provider in datasource list')
        for provider,name in datasource.items():
            if self.vm.provider == provider:
                utils_lib.run_cmd(self,
                                  'cat /run/cloud-init/cloud.cfg',
                                  expect_ret=0,
                                  expect_kw='{}, None'.format(name),
                                  msg='check if the datasource is correct')
                utils_lib.run_cmd(self,
                                  'cat /run/cloud-init/ds-identify.log | grep datasource',
                                  expect_ret=0,
                                  expect_kw='Found single datasource: {}'.format(name),
                                  msg='check if found the datasource')

    def test_cloudinit_check_instance_data_json(self):         
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            bz#: 1744526
            RHEL-182312 - CLOUDINIT-TC:cloud-init can successfully write data to instance-data.json
        key_steps:        
        1. Launch instance with cloud-init installed
        2. Check instance-data.json
        """
        cmd = 'ls -l /run/cloud-init/instance-data.json'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='No such file or directory',
                          msg='check /run/cloud-init/instance-data.json')

    def test_cloudinit_check_config_ipv6(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-189023 - CLOUDINIT-TC: check ipv6 configuration
        key_steps:        
        1. Launch instance with cloud-init installed
        2. Check there is dynamic IPv6 address
        Note: will add nm keyfiles configuration check after BZ2098624 is fixed
        """        
        cmd = "ip addr show | grep inet6 | grep 'scope global'"
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw='scope global',
                          msg='check ipv6 scope global address')

    def test_cloudinit_check_random_password_len(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-189226 - CLOUDINIT-TC: checking random password and its length
        key_steps:
        """
        if self.vm.provider != 'openstack':
            self.skipTest('skip run as this needs to configure user-date, configured on openstack')
        #security check: random password only output to openstack console log, 
        #no password output in cloud-init-output.log and /var/log/messages
        cmd = 'sudo cat /var/log/messages'
        utils_lib.run_cmd(self, 
                          cmd, 
                          expect_ret=0,
                          expect_not_kw="the following 'random' passwords", 
                          msg='check /var/log/messages')
        cmd = 'cat /var/log/cloud-init-output.log'
        utils_lib.run_cmd(self, 
                          cmd, 
                          expect_ret=0,
                          expect_not_kw="the following 'random' passwords", 
                          msg='check /var/log/cloud-init-output.log')
        #check /var/log/cloud-init-output.log mode is 640 and group is adm
        cmd = 'ls -l /var/log/cloud-init-output.log '
        utils_lib.run_cmd(self, 
                          cmd, 
                          expect_ret=0,
                          expect_kw='-rw-r-----. 1 root adm', 
                          msg='cloud-init-output.log mode should be 640 and group adm')

        #get openstack console log
        status, output= self.vm.get_console_log()
        if status and output is not None:
            self.assertIn("the following 'random' passwords", output, "Failed to get random password from console log")
            output = output.split("cloud-user:",1)[1]
            randompass = output.split("\n",1)[0]
            self.log.info("Get the random password is:"+randompass)
            self.assertEqual(len(randompass), 20, "Random password length is not 20")
        else:
            self.fail("Failed to get console log")
           
    def test_cloudinit_check_runcmd(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_priority:
            1
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-186183 - CLOUDINIT-TC:runcmd module:execute commands
        key_steps:
        """
        if self.vm.provider != 'openstack':
            self.skipTest('skip run as this needs to configure user-data, configured on openstack')
        cmd = 'sudo cat /var/log/messages'
        utils_lib.run_cmd(self, 
                          cmd, 
                          expect_ret=0,
                          expect_kw=': hello today!', 
                          msg='runcmd executed successfully')

    def test_cloudinit_show_full_version(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-196547	- CLOUDINIT-TC: cloud-init version should show full specific version
        key_steps:
            cloud-init --version should show version and release
        """
        utils_lib.run_cmd(self, "cloud-init --version>/tmp/1 2>&1")
        output = utils_lib.run_cmd(self, "cat /tmp/1").rstrip('\n')
        package = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
        cloudinit_path = utils_lib.run_cmd(self, "which cloud-init").rstrip('\n')
        expect = package.rsplit(".", 1)[0].replace("cloud-init-", cloudinit_path+' ')
        self.assertEqual(output, expect, 
            "cloud-init --version doesn't show full version. Real: {}, Expect: {}".format(output, expect))

    def test_check_hostkey_permissions(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_priority:
            1
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL7-103836 - CLOUDINIT-TC: Default configuration can regenerate sshd keypairs
            bz: 2013644
        key_steps:
            This auto case only check host key permissions
            expected:  
            $ ls -l /etc/ssh/ssh_host*.pub | awk '{print $1,$3,$4,$9}'
            -rw-r--r--. root root /etc/ssh/ssh_host_ecdsa_key.pub
            -rw-r--r--. root root /etc/ssh/ssh_host_ed25519_key.pub
            -rw-r--r--. root root /etc/ssh/ssh_host_rsa_key.pub
            $ ls -l /etc/ssh/ssh_host*key| awk '{print $1,$3,$4,$9}'
            -rw-r-----. root ssh_keys /etc/ssh/ssh_host_ecdsa_key
            -rw-r-----. root ssh_keys /etc/ssh/ssh_host_ed25519_key
            -rw-r-----. root ssh_keys /etc/ssh/ssh_host_rsa_key
        """
        self.log.info("check host key permissions")
        self.log.info("Public host key permissions should be 644 and owner/group should be root.")
        cmd = "ls -l /etc/ssh/ssh_host*.pub | awk '{print $1,$3,$4,$9}'"
        public_keys = utils_lib.run_cmd(self, cmd, msg='Get all public host keys').split('\n')
        for key in public_keys:
            if len(key) == 0:
                continue
            self.assertIn('-rw-r--r--. root root', key,
                    msg=" Unexpected permissions -> %s" % key)
        self.log.info("Private host key permissions should be 640 and owner/group should be root/ssh_keys.")
        cmd = "ls -l /etc/ssh/ssh_host*key | awk '{print $1,$3,$4,$9}'"
        private_keys = utils_lib.run_cmd(self, cmd, msg='Get all private host keys').split('\n')  
        for key in private_keys:
            if len(key) == 0:
                continue
            self.assertIn('-rw-r-----. root ssh_keys', key,
                    msg=" Unexpected permissions -> %s" % key)

    def test_check_cloudinit_fingerprints(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL7-103836 - CLOUDINIT-TC: Default configuration can regenerate sshd keypairs
            bz: 1957532
        key_steps:
            This auto case only check fingerprints is saved in /var/log/messages.
            expected:  
                # awk '/BEGIN/,/END/' /var/log/messages
                Sep 17 10:39:26 xiachen-testvm-rhel8 ec2[5447]: -----BEGIN SSH HOST KEY FINGERPRINTS-----
                Sep 17 10:39:26 xiachen-testvm-rhel8 ec2[5447]: 256 SHA256:USGMs+eQW403mILvsE5deVxZ2TC7IdQnUySEZFszlK4 root@xiachen-testvm-rhel8 (ECDSA)
                Sep 17 10:39:26 xiachen-testvm-rhel8 ec2[5447]: 256 SHA256:B/drC+5wa6xDhPaKwBNWj2Jw+lUsjpr8pEm67PG8HtM root@xiachen-testvm-rhel8 (ED25519)
                Sep 17 10:39:26 xiachen-testvm-rhel8 ec2[5447]: 3072 SHA256:6sCV1CusDhQzuoTO2FQFyyf9PmsclAd38zhkGs3HaUk root@xiachen-testvm-rhel8 (RSA)
                Sep 17 10:39:26 xiachen-testvm-rhel8 ec2[5447]: -----END SSH HOST KEY FINGERPRINTS-----
        """
        self.log.info("check fingerprints is saved in /var/log/messages")
        cmd = "sudo awk '/BEGIN/,/END/' /var/log/messages"
        out = utils_lib.run_cmd(self, cmd, msg='get fingerprints in /var/log/messages')
        # change 'SHA256' to ' SHA256' for exact match
        # change != to > for fault tolerance
        if out.count('BEGIN') > out.count(' SHA256')/3:
            self.fail('fingerprints count {} does not match expected {}'.format(out.count(' SHA256')/3,out.count('BEGIN')))

    def test_cloudinit_no_duplicate_swap(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-205128 - CLOUDINIT-TC: Can deal with the conflict of having swap configured 
            on /etc/fstab *and* having cloud-init duplicating this configuration automatically
        key_steps:
            1. Deploy a VM, attach an additional volume(or dd a file) to mkswap. 
            Add it to /etc/fstab, swapon, then check the free -m
            2. Configure cloud-init, /etc/cloud/cloud.cfg.d/cc_mount.cfg
            3. Use this VM as a template and create a new VM_new based on this VM
            4. Login VM_new and check /etc/fstab, no duplicate swap entry
        """
        utils_lib.run_cmd(self, "dd if=/dev/zero of=/tmp/swapfile01 bs=1M count=1024")
        utils_lib.run_cmd(self, "chmod 600 /tmp/swapfile01")
        utils_lib.run_cmd(self, "mkswap -L swap01 /tmp/swapfile01")
        cmd = 'echo "/tmp/swapfile01    swap    swap    defaults    0 0" >> /etc/fstab'
        utils_lib.run_cmd(self, "sudo bash -c '{}'".format(cmd))
        old_fstab = utils_lib.run_cmd(self, "cat /etc/fstab")
        utils_lib.run_cmd(self, "sudo swapon -a")
        old_swap = utils_lib.run_cmd(self, "free -m|grep Swap|awk '{print $2}'").rstrip('\n')

        cmd = 'echo -e "mounts:\n  - ["/tmp/swapfile01"]" > /etc/cloud/cloud.cfg.d/cc_mount.cfg'
        utils_lib.run_cmd(self, "sudo bash -c '{}'".format(cmd))
        utils_lib.run_cmd(self, "sudo rm -rf /var/lib/cloud/instance/sem")
        utils_lib.run_cmd(self, "sudo cloud-init single --name cc_mounts")
        utils_lib.run_cmd(self, "sudo swapoff -a")
        utils_lib.run_cmd(self, "sudo swapon -a")
        new_swap = utils_lib.run_cmd(self, "free -m|grep Swap|awk '{print $2}'").rstrip('\n')
        new_fstab = utils_lib.run_cmd(self, "cat /etc/fstab")
        # clean the swap config
        utils_lib.run_cmd(self, "sudo swapoff -a")
        utils_lib.run_cmd(self, "sudo rm -rf /etc/cloud/cloud.cfg.d/cc_mount.cfg")
        utils_lib.run_cmd(self, "sudo sed -i '/swapfile01/d' /etc/fstab")
        utils_lib.run_cmd(self, "sudo rm -rf /tmp/swapfile01")
        #utils_lib.run_cmd(self, "exit")
        self.assertNotEqual(old_swap, '0',
            "Swap size is 0 before cloud-init config")
        self.assertEqual(old_swap, new_swap,
            "Swap size is not same before and after cloud-init config")
        self.assertEqual(old_fstab, new_fstab,
            "The /etc/fstab is not same before and after cloud-init config")

    def _verify_authorizedkeysfile(self, keyfiles):
        # 1. Modify /etc/ssh/sshd_config
        utils_lib.run_cmd(self, 
            "sudo sed -i 's/^AuthorizedKeysFile.*$/AuthorizedKeysFile {}/g' /etc/ssh/sshd_config".format(keyfiles.replace('/', '\/')))
        utils_lib.run_cmd(self, 
                          "sudo grep '{}' /etc/ssh/sshd_config".format(keyfiles),
                          expect_ret=0,
                          expect_kw=keyfiles, 
                          msg='Check if change sshd_config successful')
        utils_lib.run_cmd(self, "sudo systemctl restart sshd")
        # 2. Remove cc_ssh flag and authorized_keys
        utils_lib.run_cmd(self, 
            "sudo rm -f /var/lib/cloud/instance/sem/config_ssh /home/{}/.ssh/authorized_keys".format(self.vm.vm_username))
        utils_lib.run_cmd(self, "sudo rm -rf {}".format(keyfiles))
        # 3. Run module ssh
        utils_lib.run_cmd(self, "sudo cloud-init single -n ssh")
        # 4. Verify can login
        utils_lib.init_connection(self, timeout=20)
        output=utils_lib.run_cmd(self, "whoami", expect_ret=0)
        self.assertEqual(
            self.vm.vm_username, output.rstrip('\n'),
            "Verify can login")

    def test_cloudinit_verify_multiple_files_in_authorizedkeysfile(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-189026	CLOUDINIT-TC: Verify multiple files in AuthorizedKeysFile
        key_steps:
            1. Launch VM/instance with cloud-init. Modify /etc/ssh/sshd_config:
            AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/userkeys/%u
            2. Remove cc_ssh module flag and authorized_keys
            3. Run module ssh
            # cloud-init single -n ssh
            4. Verify can login successful and AuthorizedKeysFile has correct authority
            5. Set customized keyfile at the front:
            AuthorizedKeysFile /etc/ssh/userkeys/%u.ssh/authorized_keys
            Restart sshd service and rerun step2-4
        """
        # AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/userkeys/%u
        self._verify_authorizedkeysfile(
            ".ssh/authorized_keys /etc/ssh/userkeys/%u")
        # Check the AuthorizedKeysFile authority is correct
        self.assertEqual(
            "-rw-------.",
            utils_lib.run_cmd(self, 
                "ls -al /home/%s/.ssh/authorized_keys | awk '{print $1}'" %(self.vm.vm_username)).rstrip('\n'),
            "The authority of the AuthorizedKeysFile is wrong!")
        self.assertEqual(
            self.vm.vm_username,
            utils_lib.run_cmd(self, 
                "ls -al /home/%s/.ssh/authorized_keys | awk '{print $3}'" %(self.vm.vm_username)).rstrip('\n'),
            "The owner of the AuthorizedKeysFile is wrong!")
        # AuthorizedKeysFile /etc/ssh/userkeys/%u .ssh/authorized_keys
        self._verify_authorizedkeysfile(
            "/etc/ssh/userkeys/%u .ssh/authorized_keys")
        # Check the AuthorizedKeysFile authority is correct
        self.assertEqual(
            "-rw-------.",
            utils_lib.run_cmd(self, 
                "ls -al /etc/ssh/userkeys/%s | awk '{print $1}'" %(self.vm.vm_username)).rstrip('\n'),
            "The authority of the AuthorizedKeysFile is wrong!")
        self.assertEqual(
            self.vm.vm_username,
            utils_lib.run_cmd(self, 
                "ls -al /etc/ssh/userkeys/%s | awk '{print $3}'" %(self.vm.vm_username)).rstrip('\n'),
            "The owner of the AuthorizedKeysFile is wrong!")
        # Recover the config to default: AuthorizedKeysFile .ssh/authorized_keys               
        self._verify_authorizedkeysfile(".ssh/authorized_keys")

    def test_cloudinit_verify_customized_file_in_authorizedkeysfile(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-189027	CLOUDINIT-TC: Verify customized file in AuthorizedKeysFile
            bz1862967
        key_steps:
            1. Launch VM/instance with cloud-init. Modify /etc/ssh/sshd_config:
            AuthorizedKeysFile .ssh/authorized_keys2
            2. Remove cc_ssh module flag and authorized_keys
            3. Run module ssh
            # cloud-init single -n ssh
            4. Verify can login successfully and AuthorizedKeysFile has correct authority
        """
        cloudinit_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')        
        cloudinit_ver = float(re.search('cloud-init-(\d+.\d+)-', cloudinit_ver).group(1))
        if cloudinit_ver < 21.1:
            self.skipTest('skip run as this case is suitable for rhel higher than rhel-8.5 and rhel-9.0, bz1862967')
        self.log.info(
            "RHEL-189027 CLOUDINIT-TC: Verify customized file in AuthorizedKeysFile")
        self._verify_authorizedkeysfile(".ssh/authorized_keys2")
        # Check the AuthorizedKeysFile authority is correct
        self.assertEqual(
            "-rw-------.",
            utils_lib.run_cmd(self,
                "ls -al /home/%s/.ssh/authorized_keys2 | awk '{print $1}'" %(self.vm.vm_username)).rstrip('\n'),
            "The authority of the AuthorizedKeysFile is wrong!")
        self.assertEqual(
            self.vm.vm_username,
            utils_lib.run_cmd(self,
                "ls -al /home/%s/.ssh/authorized_keys2 | awk '{print $3}'" %(self.vm.vm_username)).rstrip('\n'),
            "The owner of the AuthorizedKeysFile is wrong!")        
        # Recover the config to default: AuthorizedKeysFile .ssh/authorized_keys
        # Remove ~/.ssh and check the permissions of the directory
        utils_lib.run_cmd(self,
            "sudo rm -rf /home/{}/.ssh".format(self.vm.vm_username))
        self._verify_authorizedkeysfile(".ssh/authorized_keys")
        # Check ~/.ssh authority is correct, bug 1995840
        self.assertEqual(
            "drwx------. {0} {0}".format(self.vm.vm_username),
            utils_lib.run_cmd(self,
                "ls -ld /home/%s/.ssh | awk '{print $1,$3,$4}'" %(self.vm.vm_username)).rstrip('\n'),
            "The authority .ssh is wrong!")

    def test_cloudinit_check_NOZEROCONF(self):       
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-152730 - CLOUDINIT-TC: Check 'NOZEROCONF=yes' in /etc/sysconfig/network
            cannot be removed by cloud-init
        key_steps:
            1. Create a VM with rhel-guest-image
            2. Login and check /etc/sysconfig/network
            3. There is "NOZEROCONF=yes" in /etc/sysconfig/network
        """
        self.log.info(
            "RHEL-152730 - CLOUDINIT-TC: Check 'NOZEROCONF=yes' in /etc/sysconfig/network")
        cmd = 'sudo cat /etc/sysconfig/network'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw='NOZEROCONF=yes',
                          msg='check if NOZEROCONF=yes in /etc/sysconfig/network')

    @unittest.skipIf(os.getenv('INFRA_PROVIDER') == 'nutanix', 'skip run for nutanix platform on which authorized_keys be modified.')
    def test_cloudinit_root_exit_code(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-287348 - CLOUDINIT-TC: Using root user error should 
            cause a non-zero exit code
        key_steps:
            1. Launch instance with cloud-init installed
            2. Check the /root/.ssh/authorized_keys, the exit code is 142
            # cat /root/.ssh/authorized_keys" 
        """
        self.log.info(
            "RHEL-287348 - CLOUDINIT-TC: Using root user error should cause a non-zero exit code")
        cmd = 'sudo cat /root/.ssh/authorized_keys'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw='echo;sleep 10;exit 142',
                          msg='check if the exit code correct')

    @unittest.skipIf(os.getenv('INFRA_PROVIDER') in ['nutanix','aws'], 'skip run on {} platform which there is no ip route append command used'.format(os.getenv('INFRA_PROVIDER')))
    def test_cloudinit_ip_route_append(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-288020 - CLOUDINIT-TC: Using "ip route append" 
            when config static ip route via cloud-init
        key_steps:
            1. Launch instance with cloud-init installed on OpenStack PSI
            2. Check /var/log/cloud-init.log
            cloud-init should config static ip route via "ip route append" 
        """
        cmd = 'cat /var/log/cloud-init.log | grep append'

        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw="Running command \['ip', '-4', 'route', 'append',",
                          msg="check if using ip route append")

    def test_cloudinit_dependency(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-288482 - CLOUDINIT-TC: Check cloud-init dependency: openssl, gdisk,
            python3-configobj, python3-jinja2, python3-pyserial
        key_steps:
            1. Launch instance with cloud-init installed
            2. Check the cloud-init denpendency
            # rpm -qR cloud-init 
        """       
        dep_list = 'openssl,gdisk,python3-configobj,python3-jinja2,python3-pyserial'
        cmd = 'sudo rpm -qR cloud-init'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw='%s' % dep_list,
                          msg='check if %s are cloud-init dependency' % dep_list)

    def test_cloudinit_removed_dependency(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-198795 - CLOUDINIT-TC: Check cloud-init removed dependency,
            net-tools, python3-mock, python3-nose, python3-tox
            Note: For rhel-9.0, the python3-jsonschema is also removed
        key_steps:
            1. Launch instance with cloud-init installed
            2. Check the cloud-init denpendency
            # rpm -qR cloud-init
        """
        rm_dep_list = 'net-tools,python3-mock,python3-nose,python3-tox'
        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
        if float(product_id) >= 9.0:
            rm_dep_list = 'net-tools,python3-mock,python3-nose,python3-tox,python3-jsonschema'
        cmd = 'sudo rpm -qR cloud-init'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='%s' % rm_dep_list,
                          msg='check if %s are removed from cloud-init dependency' % rm_dep_list)

    def _check_cloudinit_done_and_service_isactive(self):
        # if cloud-init status is running, waiting
        cmd = 'sudo cloud-init status'
        output=utils_lib.run_cmd(self, cmd).rstrip('\n')
        while output=='status: running':
            time.sleep(20) # waiting for cloud-init done
            output = utils_lib.run_cmd(self, cmd).rstrip('\n')        
        # check cloud-init status is done        
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='status: done', msg='Get cloud-init status')
        # check cloud-init services status are active
        service_list = ['cloud-init-local',
                        'cloud-init',
                        'cloud-config',
                        'cloud-final']
        for service in service_list:
            cmd = "sudo systemctl is-active %s" % service
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='active', msg = "check %s status" % service)

    def test_cloudinit_create_vm_config_drive(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-189225 - CLOUDINIT-TC: launch vm with config drive
        key_steps:
            basic case of config drive
            1. Create a VM with datasource 'Config Drive'
            2. Login and check user sudo privilege
            3. check data source in /run/cloud-init/cloud.cfg
        """
        if self.vm.provider != 'openstack':
            self.skipTest('skip run as this is openstack specific case')
        self.log.info(
            "RHEL-189225 - CLOUDINIT-TC: launch vm with config drive")        
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        self.vm.config_drive = True
        self.vm.create()
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami').rstrip('\n')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)
        sudooutput=utils_lib.run_cmd(self, "sudo cat /etc/sudoers.d/90-cloud-init-users", expect_ret=0) 
        self.assertIn(
            "%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
            sudooutput,
            "No sudo privilege")
        cmd = 'sudo cat /run/cloud-init/cloud.cfg'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw='ConfigDrive',
                          msg='check if ConfigDrive in /run/cloud-init/cloud.cfg')
        # check cloud-init status is done and services are active
        self._check_cloudinit_done_and_service_isactive()
        #teardown        
        self.vm.delete()
        self.vm.config_drive = None
        self.vm.create()
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def test_cloudinit_login_with_password_userdata(self):
        """
        case_tag:
            cloudinit,cloudinit_tier1
        case_priority:
            1
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL7-103830 - CLOUDINIT-TC: VM can successfully login
            after provisioning(with password authentication)
        key_steps:
            1. Create a VM with only password authentication
            2. Login with password, should have sudo privilege
        """
        if not self.vms:
            self.skipTest("No vm found")
        if self.vm.provider == 'nutanix':
            self.skipTest('skip run as nutanix test this in case test_cloudinit_login_with_password')
        for attrname in ['vm_password', 'keypair']:
            if not hasattr(self.vm, attrname):
                self.skipTest("no {} for {} vm".format(attrname, self.vm.provider))
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        save_userdata = self.vm.user_data
        save_keypair = self.vm.keypair
        self.vm.user_data = """\
#cloud-config

user: {0}
password: {1}
chpasswd: {{ expire: False }}
ssh_pwauth: 1
""".format(self.vm.vm_username, self.vm.vm_password)       
        self.vm.keypair = None
        self.vm.create()
        time.sleep(30)
        self.params['remote_node'] = self.vm.floating_ip
        test_login = utils_lib.send_ssh_cmd(self.vm.floating_ip, self.vm.vm_username, self.vm.vm_password, "whoami")
        self.assertEqual(self.vm.vm_username,
                         test_login[1].strip(),
                         "Fail to login with password: %s" % format(test_login[1].strip()))        
        test_sudo = utils_lib.send_ssh_cmd(self.vm.floating_ip, self.vm.vm_username, self.vm.vm_password, "sudo cat /etc/sudoers.d/90-cloud-init-users")
        self.assertIn("%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
                         test_sudo[1].strip(),
                         "No sudo privilege")
        #teardown        
        self.vm.delete()
        self.vm.keypair = save_keypair
        self.vm.user_data = save_userdata
        self.vm.create()
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def _reboot_inside_vm(self, sleeptime=10):       
        before = utils_lib.run_cmd(self, 'last reboot --time-format full')
        utils_lib.run_cmd(self, 'sudo reboot')
        time.sleep(sleeptime)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami')
        self.assertEqual(
            self.vm.vm_username, output.strip(),
            "Reboot VM error: output of cmd `who` unexpected -> %s" % output)
        after = utils_lib.run_cmd(self, 'last reboot --time-format full')
        self.assertNotEqual(
            before, after,
            "Reboot VM error: before -> %s; after -> %s" % (before, after))

    def test_cloudinit_check_resolv_conf_reboot(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-196518 - CLOUDINIT-TC: check dns configuration on openstack instance
            RHEL-182309 - CLOUDINIT-TC: /etc/resolv.conf will not lose config after reboot
        key_steps:
            1. check dns configuration in /etc/resolv.conf
            2. check /etc/NetworkManager/conf.d/99-cloud-init.conf
            3. run hostnamectl command and then check resolv.conf again
            4. reboot
            5. Check /etc/resolv.conf
        """
        cmd = 'cat /etc/resolv.conf'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw='nameserver',
                          msg='check if there is dns information in /etc/resolv.conf')
        #get network dns information
        output = utils_lib.run_cmd(self, 'cloud-init query ds.network_json.services').rstrip('\n')
        is_support = True
        try:
            services = json.loads(output)  
        except Exception:
            is_support = False
        if not is_support:
            self.skipTest("Unable to load output as json, might be not supported.{}".format(output))
        for service in services:
            expect_dns_addr=service.get("address")
            utils_lib.run_cmd(self,
                           cmd,
                           expect_ret=0,
                           expect_kw=expect_dns_addr,
                           msg='check dns configuration %s in /etc/resolv.conf' % expect_dns_addr)
        cmd2 = 'cat /etc/NetworkManager/conf.d/99-cloud-init.conf'
        utils_lib.run_cmd(self,
                          cmd2,
                          expect_ret=0,
                          expect_kw='dns = none',
                          msg='check dns configuration of NM')
        utils_lib.run_cmd(self, 'cp /etc/resolv.conf  ~/resolv_bak.conf')
        cmd1 = 'sudo hostnamectl set-hostname host1.test.domain'                  
        utils_lib.run_cmd(self, cmd1, expect_ret=0, msg='set hostname')
        diff = utils_lib.run_cmd(self, "diff ~/resolv_bak.conf /etc/resolv.conf").rstrip('\n')
        self.assertEqual(diff, '', 
            "After setting hostname, resolv.conf is changed:\n"+diff)
        self._reboot_inside_vm()
        diff = utils_lib.run_cmd(self, "diff ~/resolv_bak.conf /etc/resolv.conf").rstrip('\n')
        self.assertEqual(diff, '', 
            "After reboot, resolv.conf is changed:\n"+diff)

    def _get_service_startup_time(self, servicename):
        output = utils_lib.run_cmd(self, "sudo systemd-analyze blame | grep %s | awk '{print $1}'" % servicename).rstrip('\n')
        if 'ms' in output:
            return 1
        if 'min' in output:
            boot_time_min = re.findall('[0-9]+min', output)[0]
            boot_time_min = boot_time_min.strip('min')
            boot_time_sec = int(boot_time_min) * 60
            return boot_time_sec
        service_time_sec = output.strip('s')
        return service_time_sec

    def test_cloudinit_boot_time(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-189580 - CLOUDINIT-TC: Check VM first launch boot time and cloud-init startup time
        key_steps:
            1. Launch a VM with cloud-init installed
            2. Login VM on the VM first boot
            3. Check boot time and cloud-init services startup time
            # systemd-analyze
            # systemd-analyze blame
            4. The boot time should be less than 50s, cloud-init services startup time should less than 18s
        """
        max_boot_time = 60
        cloud_init_startup_time = 20
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        self.vm.create()
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        boot_time_sec = utils_lib.getboottime(self)
        # check cloud-init status is done and services are active
        self._check_cloudinit_done_and_service_isactive()      
        # Check cloud-init services time
        service_list = ['cloud-init-local.service',
                        'cloud-init.service',
                        'cloud-config.service',
                        'cloud-final.service']
        service_time_list = []
        for service in service_list:
            service_time_sec = self._get_service_startup_time("%s" % service)
            self.log.info("Service boot time for {0} is {1}".format(service,service_time_sec))
            service_time_list.append(service_time_sec)
        for service_time_sec in service_time_list:
            self.assertLess(
                float(service_time_sec), float(cloud_init_startup_time), 
                "{0} startup time is greater than {1}".format(service, cloud_init_startup_time))
        # Check overal boot time
        if float(boot_time_sec) > float(max_boot_time):
            utils_lib.run_cmd(self, cmd='sudo journalctl -b0')
        self.assertLess(
            float(boot_time_sec), float(max_boot_time), 
            "First boot time is greater than {}".format(max_boot_time))  

    def test_cloudinit_reboot_time(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-282359 - CLOUDINIT-TC: Check VM subsequent boot time and cloud-init startup time
        key_steps:
            1. Launch a VM with cloud-init installed
            2. Login VM and reboot VM
            3. Check reboot time and cloud-init services startup time
            # systemd-analyze
            # systemd-analyze blame
            4. The reboot time should be less than 30s, cloud-init services startup time should less than 5s
        """
        max_boot_time = 40
        cloud_init_startup_time = 5
        # Reboot VM
        self._reboot_inside_vm()
        boot_time_sec = utils_lib.getboottime(self)
        # Check cloud-init services time
        service_list = ['cloud-init-local.service',
                        'cloud-init.service',
                        'cloud-config.service',
                        'cloud-final.service']
        service_time_list = []
        for service in service_list:
            service_time_sec = self._get_service_startup_time("%s" % service)
            self.log.info("Service boot time for {0} is {1}".format(service,service_time_sec))
            service_time_list.append(service_time_sec)
        for service_time_sec in service_time_list:
            self.assertLess(
                float(service_time_sec), float(cloud_init_startup_time), 
                "{0} startup time is greater than {1}".format(service, cloud_init_startup_time))
        # Check overall boot time
        self.assertLess(
            float(boot_time_sec), float(max_boot_time), 
            "Reboot time is greater than {}".format(max_boot_time))

    def test_cloudinit_disable_cloudinit(self):        
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-287483: CLOUDINIT-TC: cloud-init dhclient-hook script shoud exit
            while cloud-init services are disabled
        key_steps:
            1. Install cloud-init package in VM, disable cloud-init and related services:
               # systemctl disable cloud-{init-local,init,config,final}
            2. Clean the VM and reboot VM
            3. Check the VM status after reboot
            The cloud-init should not run , and the related services are disabled
            4. Recover the VM config(enable cloud-init), reboot VM, check the cloud-init is enabled
        """
        self.log.info("RHEL-287483: CLOUDINIT-TC: check cloud-init disable")
        # Disable cloud-init
        utils_lib.run_cmd(self, "sudo systemctl disable cloud-{init-local,init,config,final}")
        time.sleep(1)
        self.assertNotIn("enabled",
                    utils_lib.run_cmd(self, "sudo systemctl is-enabled cloud-{init-local,init,config,final}"),
                    "Fail to disable cloud-init related services")
        # Clean the VM
        utils_lib.run_cmd(self, "sudo rm -rf /var/lib/cloud /var/log/cloud-init* \
            /var/log/messages /run/cloud-init")    
        # Reboot VM
        self._reboot_inside_vm()        
        # Check the new VM status
        self.assertNotIn("enabled",
                    utils_lib.run_cmd(self, "sudo systemctl is-enabled cloud-{init-local,init,config,final}"),
                    "Fail to disable cloud-init related services!")
        self.assertIn("status: not run",
                    utils_lib.run_cmd(self, "sudo cloud-init status"),
                    "cloud-init status is wrong!")
        self.assertIn("inactive",
                    utils_lib.run_cmd(self, "sudo systemctl is-active cloud-init-local"),
                    "cloud-init-local service status is wrong!")
        # Recover the VM config
        utils_lib.run_cmd(self, "sudo systemctl enable cloud-{init-local,init,config,final}")
        time.sleep(1)
        # Reboot VM
        self._reboot_inside_vm()
        # Check the VM status
        self.assertNotIn("disabled",
                    utils_lib.run_cmd(self, "sudo systemctl is-enabled cloud-{init-local,init,config,final}"),
                    "Fail to disable cloud-init related services!")
        #teardown        
        self.vm.delete()
        self.vm.create()
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def test_cloudinit_create_vm_two_nics(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-186186 - CLOUDINIT-TC: launch an instance with 2 interfaces
            basic case of two nics, the second nic is default ipv6 mode slaac
        key_steps:
            1. Create a VM with two nics
            2. Login and check user
            3. check network config file
        """
        if self.vm.provider != 'openstack':
            self.skipTest('skip run as this case is openstack specific which using openstack PSI NIC uuid')        
        # The second nic uses hard code (the second network only contains ipv6, network name provider_net_ipv6_only, ipv6 slaac)
        # if the second nic has ipv4, the ssh login may select it but it could not be connected
        # this solution ensure ssh using eth0 ipv4
        self.vm.second_nic_id = "10e45d6d-5924-48ee-9f5a-9713f5facc36"
        gateway = "2620:52:0:9c::fe"
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        self.vm.create()
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami').rstrip('\n')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)
        cmd = 'ip addr show eth1'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=',UP,')
        cloudinit_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')        
        cloudinit_ver = float(re.search('cloud-init-(\d+.\d+)-', cloudinit_ver).group(1))
        # Check ping gateway successful
        cmd = "ping6 {} -c 3".format(gateway)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='0% packet loss')
        # check cloud-init status is done and services are active
        self._check_cloudinit_done_and_service_isactive()

    def test_cloudinit_create_vm_stateless_ipv6(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-186180 - CLOUDINIT-TC: correct config for dhcp-stateless openstack subnets
        key_steps:
            1. Create a VM with two nics, the second nic is stateless ipv6 mode
            2. Login and check user
            3. check network config file
        """
        if self.vm.provider != 'openstack':
            self.skipTest('skip run as this case is openstack specific.')
        # The second nic uses hard code (net-ipv6-stateless-test, only subnet ipv6, dhcp-stateless)
        self.vm.second_nic_id = "21f1d63a-197c-4f36-957a-4c8f4a24bb73"
        gateway = "2020:1:1:1::1"
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        self.vm.create()
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami').rstrip('\n')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)
        # change command to ip addr because of no net-tool by default in rhel8.4
        cmd = 'ip addr show eth1'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=',UP,')
        cloudinit_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')        
        cloudinit_ver = float(re.search('cloud-init-(\d+.\d+)-', cloudinit_ver).group(1))
        if cloudinit_ver < 22.1:
            cmd = 'sudo cat /etc/sysconfig/network-scripts/ifcfg-eth1'
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='DHCPV6C_OPTIONS=-S,IPV6_AUTOCONF=yes')
        # Check ping gateway successful
        cmd = "ping6 {} -c 3".format(gateway)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='0% packet loss')
        # check cloud-init status is done and services are active
        self._check_cloudinit_done_and_service_isactive()

    def test_cloudinit_create_vm_stateful_ipv6(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-186181 - CLOUDINIT-TC: correct config for dhcp-stateful openstack subnets
        key_steps:
            1. Create a VM with two nics, the second nic is dhcp-stateful ipv6 mode
            2. Login and check user
            3. check network config file
        """
        if self.vm.provider != 'openstack':
            self.skipTest('skip run as this case is openstack specific')
        # The second nic uses hard code (net-ipv6-stateful-test, only subnet ipv6, dhcp-stateful)
        self.vm.second_nic_id = "c0020823-5d4c-444a-aee7-b0fe6b3219cc"
        gateway = "2010:1:1:1::1"
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        self.vm.create()
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami').rstrip('\n')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)
        cmd = 'ip addr show eth1'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=',UP,')
        cloudinit_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')        
        cloudinit_ver = float(re.search('cloud-init-(\d+.\d+)-', cloudinit_ver).group(1))
        if cloudinit_ver < 22.1:
            cmd = 'sudo cat /etc/sysconfig/network-scripts/ifcfg-eth1'
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='IPV6_FORCE_ACCEPT_RA=yes')
        # Check ping gateway successful
        cmd = "ping6 {} -c 3".format(gateway)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='0% packet loss')
        # check cloud-init status is done and services are active
        self._check_cloudinit_done_and_service_isactive()

    def test_cloudinit_auto_install_package_with_subscription_manager(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-186182	CLOUDINIT-TC:auto install package with subscription manager
        key_steps:
            1. Add content to user data config file
            rh_subscription:
            username: ******
            password: ******
            auto-attach: True
            packages:
            - dos2unix
            2. create VM
            3. Verify register with subscription-manager and install package by cloud-init successfully
        """
        if self.vm.provider != 'openstack' and self.vm.provider != 'nutanix':
            self.skipTest('skip run as this case need connect rhsm stage server, not suitable for public cloud')
        self.log.info("RHEL-186182 CLOUDINIT-TC:auto install package with subscription manager")
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        package = "dos2unix"        
        save_userdata = self.vm.user_data
        self.vm.user_data = """\
#cloud-config

rh_subscription:
  username: {0}
  password: {1}
  rhsm-baseurl: {2}
  server-hostname: {3}
  auto-attach: true
  disable-repo: []
packages:
  - {4}
""".format(self.vm.subscription_username, self.vm.subscription_password, 
    self.vm.subscription_baseurl, self.vm.subscription_serverurl, package)
        self.vm.create()
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        # check login
        output = utils_lib.run_cmd(self, 'whoami').rstrip('\n')
        self.assertEqual(
            self.vm.vm_username, output,
            "Create VM error: output of cmd `who` unexpected -> %s" % output)
        self.log.info("Waiting 30s for subscription-manager done...")
        time.sleep(30) # waiting for subscription-manager register done.
        # no error because of disable-repo null
        # check cloud-init status is done and services are active
        self._check_cloudinit_done_and_service_isactive()
        # check register
        cmd = "sudo grep 'Registered successfully' /var/log/cloud-init.log"
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='Registered successfully',
                    msg='Check Registered successfully log in cloud-init.log')
        cmd = "sudo subscription-manager identity"
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    msg='Register with subscription-manager')
        # check auto-attach
        output = utils_lib.run_cmd(self, "sudo subscription-manager list --consumed --pool-only").rstrip('\n')
        self.assertNotEqual("", output, "Cannot auto-attach pools")
        # check package installed
        time.sleep(30) # waiting for package install done.
        cmd = "rpm -q {}".format(package)
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='{}'.format(package),
                    msg="Fail to install package {} by cloud-init".format(package))
        #teardown        
        self.vm.delete()
        if self.vm.provider == 'nutanix':
            self.vm.user_data = None
        else:
            self.vm.user_data = save_userdata
        self.vm.create()
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def test_cloudinit_verify_rh_subscription_enablerepo_disablerepo(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description:
            RHEL-189134 - CLOUDINIT-TC: Verify rh_subscription enable-repo and disable-repo
        key_steps:
            1. Add content to user data config file
            rh_subscription:
            username: ******
            password: ******
            auto-attach: True
            enable-repo: ['rhel-*-baseos-*rpms','rhel-*-supplementary-*rpms']
            disable-repo: ['rhel-*-appstream-*rpms']
            2. create VM
            3. Verify register with subscription-manager and enabled repos and disabled repos successfully
        """
        if self.vm.provider != 'openstack' and self.vm.provider != 'nutanix':
            self.skipTest('skip run as this case need connect rhsm stage server, not suitable for public cloud')
        rhel_ver = utils_lib.run_cmd(self, "sudo cat /etc/redhat-release").rstrip('\n')
        rhel_ver = float(re.search('release\s+(\d+.\d+)\s+', rhel_ver).group(1))
        if rhel_ver >= 9.0 or rhel_ver < 8.0:
            self.skipTest('skip run as this case is only test rhel-8')        
        self.log.info("RHEL-189134 - CLOUDINIT-TC: Verify rh_subscription enable-repo and disable-repo")
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        save_userdata = self.vm.user_data
        self.vm.user_data = """\
#cloud-config

rh_subscription:
  username: {0}
  password: {1}
  rhsm-baseurl: {2}
  server-hostname: {3}
  auto-attach: true
  enable-repo: ['rhel-8-for-x86_64-baseos-beta-rpms','rhel-8-for-x86_64-supplementary-beta-rpms']
  disable-repo: ['rhel-8-for-x86_64-appstream-beta-rpms']
""".format(self.vm.subscription_username, self.vm.subscription_password, 
    self.vm.subscription_baseurl, self.vm.subscription_serverurl)
        self.vm.create()
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        # check login
        output = utils_lib.run_cmd(self, 'whoami').rstrip('\n')
        self.assertEqual(
            self.vm.vm_username, output,
            "Reboot VM error: output of cmd `who` unexpected -> %s" % output)
        # waiting for subscription-manager register done.
        # 51.55900s (modules-config/config-rh_subscription)
        self.log.info("Waiting 60s for subscription-manager done...")
        time.sleep(60) 
        # check cloud-init status is done and services are active
        self._check_cloudinit_done_and_service_isactive()
        # check register
        cmd = "sudo grep 'Registered successfully' /var/log/cloud-init.log"
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='Registered successfully',
                    msg='Check registered successfully log in cloud-init.log')
        cmd = "sudo subscription-manager identity"
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    msg='Register with subscription-manager')
        # check auto-attach
        output = utils_lib.run_cmd(self, "sudo subscription-manager list --consumed --pool-only").rstrip('\n')
        self.assertNotEqual("", output, "Cannot auto-attach pools")
        # check enabled/disabled repos
        enable_repo_1 = 'rhel-8-for-x86_64-baseos-beta-rpms'
        enable_repo_2 = 'rhel-8-for-x86_64-supplementary-beta-rpms'
        disable_repo = 'rhel-8-for-x86_64-appstream-beta-rpms'
        repolist = utils_lib.run_cmd(self, "yum repolist|awk '{print $1}'").split('\n')
        self.assertIn(enable_repo_1, repolist,
            "Repo of {} is not enabled".format(enable_repo_1))
        self.assertIn(enable_repo_2, repolist,
            "Repo of {} is not enabled".format(enable_repo_2))
        self.assertNotIn(disable_repo, repolist,
            "Repo of {} is not disabled".format(disable_repo))
        #teardown        
        self.vm.delete()
        if self.vm.provider == 'nutanix':
            self.vm.user_data = None
        else:
            self.vm.user_data = save_userdata
        self.vm.create()
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def _verify_rh_subscription(self, config):
        utils_lib.run_cmd(self,"sudo subscription-manager unregister")
        utils_lib.run_cmd(self,
            "sudo rm -f /var/lib/cloud/instance/sem/config_rh_subscription /var/log/cloud-init*.log")
        utils_lib.run_cmd(self,"echo '''%s''' | sudo tee /etc/cloud/cloud.cfg.d/test_rh_subscription.cfg" % config)
        utils_lib.run_cmd(self,"sudo cloud-init single -n rh_subscription", timeout=600)
        cmd="sudo grep 'Registered successfully' /var/log/cloud-init.log"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="No 'Registered successfully log in cloud-init.log")
        utils_lib.run_cmd(self,"sudo subscription-manager identity", expect_ret=0, msg="Fail to register with subscription-manager")

    def test_cloudinit_auto_register_with_subscription_manager(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_auto_register_with_subscription_manager
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_auto_register_with_subscription_manager
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Auto register by cloud-init
        key_steps: |
            1. Add content to /etc/cloud/cloud.cfg.d/test_rh_subscription.cfg
            2. Run rh_subscription module
            3. Verify can register with subscription-manager
            4. Verify can auto-attach manually
        expect_result:
            register with subscription-manager successfully.
        debug_want:
            N/A
        """
        for attrname in ['subscription_username', 'subscription_password']:
            if not hasattr(self.vm, attrname):
                self.skipTest("no {} for {} vm".format(attrname, self.vm.provider))
        CONFIG='''rh_subscription:
    username: {}
    password: {}
    rhsm-baseurl: {}
    server-hostname: {}
    '''.format(self.vm.subscription_username, self.vm.subscription_password,
               self.vm.subscription_baseurl, self.vm.subscription_serverurl)
        self._verify_rh_subscription(CONFIG)

    def _get_test_disk(self):
        '''
        Look for non-boot disk to do test
        '''
        test_disk = None
        cmd = "lsblk -r --output NAME,MOUNTPOINT|awk -F' ' '{if($2) printf\"%s \",$1}'"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        mount_disks = output.split(' ')
        cmd = 'lsblk -d --output NAME|grep -v NAME'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        disk_list = output.split('\n')
        for disk in disk_list:
            disk_in_use = False
            if not disk:
                continue
            for mount_disk in mount_disks:
                if disk in mount_disk:
                    self.log.info('Disk is mounted: {}'.format(disk))
                    disk_in_use = True
                    break
            if not disk_in_use:
                cmd = 'sudo mkfs.ext3 /dev/{} -F'.format(disk)
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='test can clean fs on {}'.format(disk))
                if ret == 0:
                    test_disk = disk
                    break
                else:
                    self.log.info('Cannot clean fs on {} - skip'.format(disk))
                    continue
        if test_disk:
            self.log.info('Test disk is found: {}'.format(test_disk))
        else:
             self.skipTest("No free disk for testing.")
        return '/dev/' + test_disk

    def test_cloudinit_swapon_with_xfs_filesystem(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_swapon_with_xfs_filesystem
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_swapon_with_xfs_filesystem
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test swapon when created on a xfs filesystem by cloud-init.
        key_steps: |
            1. Add additional data disk and format to xfs, mount to /datatest and add to /etc/fstab
            2. Configure cloud-config and run mounts module
            # cat /etc/cloud/cloud.cfg.d/test_swap.cfg
            swap:
              filename: /datatest/swap.img
              size: "auto" # or size in bytes
              maxsize: 2G
            3. Check the swap, verify /datadisk/swap.img exists, verify no error logs in cloud-init.log
            expect_result:
                register with subscription-manager successfully.
        debug_want:
            N/A
        """
        # Get previous swap size
        old_swap = utils_lib.run_cmd(self, "free -m|grep Swap|awk '{print $2}'")
        # Attach data disk
        if(not self._get_test_disk()):
            self.skipTest("test disk not found, provision VM should has at least 1 attached disk")
        test_disk = self._get_test_disk()
        utils_lib.run_cmd(self, "ls {}".format(test_disk), expect_ret=0, msg="check if there is attached disk to be tested.")
        utils_lib.run_cmd(self, "sudo parted {} rm 1 -s".format(test_disk))
        utils_lib.run_cmd(self, "sudo parted {} mklabel msdos -s".format(test_disk))
        utils_lib.run_cmd(self, "sudo parted {} mkpart primary xfs 1048k 4000M -s".format(test_disk))
        cmd = " lsblk -l {}|grep part|sort|uniq|cut -f1 -d' '|head -n1".format(test_disk)
        test_part = '/dev/' + utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get test part')
        test_part = test_part.strip('\n')
        utils_lib.run_cmd(self, "sudo mkfs.xfs {} -f".format(test_part))
        utils_lib.run_cmd(self, "sudo mkdir -p /datatest")
        utils_lib.run_cmd(self, "sudo mount {} /datatest".format(test_part))
        utils_lib.run_cmd(self, "sudo mount|grep /datatest", expect_ret=0, msg="Fail to mount datadisk")
        # Test begin
        CONFIG='''\
swap:
  filename: /datatest/swap.img
  size: "8M" # or size in bytes
  maxsize: 2G'''
        utils_lib.run_cmd(self,'sudo tail /var/log/cloud-init.log')
        utils_lib.run_cmd(self,"echo '''%s''' | sudo tee /etc/cloud/cloud.cfg.d/test_swap.cfg" % CONFIG)
        utils_lib.run_cmd(self, "sudo rm -f /var/lib/cloud/instance/sem/config_mounts /var/log/cloud-init*.log")
        utils_lib.run_cmd(self, "sudo cloud-init single --name mounts")
        new_swap = utils_lib.run_cmd(self, "free -m|grep Swap|awk '{print $2}'")
        self.assertAlmostEqual(first=int(old_swap)+7, second=int(new_swap), delta=1,
            msg="The enabled swap size does not correct.")
        utils_lib.run_cmd(self, "ls /datatest/swap.img", expect_ret=0, msg="/datatest/swap.img doesn't exist.")
        utils_lib.run_cmd(self, "grep swap.img /etc/fstab", expect_ret=0, msg="Fail to add swap to /etc/fstab")
        cmd = "grep 'Permission denied' /var/log/cloud-init-output.log"
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg="There are Permission denied logs in /var/log/cloud-init-output.log")
        #teardown
        utils_lib.run_cmd(self, "sudo swapoff /datatest/swap.img")
        utils_lib.run_cmd(self, "sudo umount /datatest")
        utils_lib.run_cmd(self, "sudo rm -rf /datatest")
        utils_lib.run_cmd(self, "sudo bash -c \"sed -i '/.*\/datatest.*/d' /etc/fstab\"")

    def _generate_password(self, password, hash, salt=''):
        import crypt
        if hash == 'md5':
            crypt_type = '$1$'
        elif hash == 'sha-256':
            crypt_type = '$5$'
        elif hash == 'sha-512':
            crypt_type = '$6$'
        else:
            assert False, 'Unhandled hash option: {}'.format(hash)
        # Generate a random salt
        if salt == '':
            with open('/dev/urandom', 'rb') as urandom:
                while True:
                    byte = urandom.read(1)

                    if byte in (b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                                b'./0123456789'):
                        salt += byte.decode("utf8","ignore")
                        if len(salt) == 16:
                            break
        salt = crypt_type + salt
        hashed = crypt.crypt(password, salt)
        return hashed

    def test_cloudinit_chpasswd_with_hashed_passwords(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_chpasswd_with_hashed_passwords
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_chpasswd_with_hashed_passwords
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
           chpasswd in cloud-init should support hashed passwords.
        key_steps: |
            1. Add 6 users in the VM
            2. Add different passwords to /etc/cloud/cloud.conf.d/test_hash_passwords.cfg
            3. Verify if cloud-init can handle these passwords
        expect_result:
            cloud-init can handle these passwords
        debug_want:
            N/A
        """
        for i in range(1, 7):
            user = "test{}".format(str(i))
            utils_lib.run_cmd(self, "sudo userdel -r {}".format(user))
            utils_lib.run_cmd(self, "sudo useradd {}".format(user))
            utils_lib.run_cmd(self, "sudo id {}".format(user), expect_ret=0, msg="Fail to create user {}".format(user))
        # Run set_passwords module
        base_pw = "RedHat@2019"
        pw_config_dict = {
            "test1": self._generate_password(base_pw, "md5"),
            "test2": self._generate_password(base_pw, "sha-256"),
            "test3": self._generate_password(base_pw, "sha-512"),
            "test4": base_pw,
            "test5": "R",
            "test6": "RANDOM"
        }
        CONFIG='''\
chpasswd:
  list:
    - test1:{test1}
    - test2:{test2}
    - test3:{test3}
    - test4:{test4}'''.format(**pw_config_dict)
        utils_lib.run_cmd(self,"echo '''%s''' | sudo tee /etc/cloud/cloud.cfg.d/test_hash_passwords.cfg" % CONFIG)
        utils_lib.run_cmd(self, "sudo rm -f /var/lib/cloud/instance/sem/config_set_passwords /var/log/cloud-init*.log")
        output = utils_lib.run_cmd(self, "sudo cloud-init single --name set_passwords")
        test4_salt = utils_lib.run_cmd(self, "sudo getent shadow test4").split('$')[2]
        shadow_dict = {
            "test1": pw_config_dict['test1'],
            "test2": pw_config_dict['test2'],
            "test3": pw_config_dict['test3'],
            "test4": "test4:{}:".format(self._generate_password(base_pw, "sha-512", test4_salt)),
        }
        for user in shadow_dict:
            real = utils_lib.run_cmd(self, "sudo getent shadow {}".format(user))
            expect = shadow_dict.get(user)
            self.assertIn(expect, real,
                "The {} password in /etc/shadow doesn't meet the expectation. Real:{} Expect:{}".format(user, real, expect))
        #Move this step after checking test4 pwd
        for line in output.split('\n'):
            if "test5" in line:
                test5_pw = line.split(':')[1]
            elif "test6" in line:
                test6_pw = line.split(':')[1]
            elif "failed" in line:
                self.fail("Failed to set password, analyze:  conpath = \"/dev/console\",wfh.flush(), OSError: [Errno 5] Input/output error; root cause:  should same with BZ2034588")
        # From cloud-init-21.1-3.el8 or cloud-init-21.1-4.el9 the password should not in the output and cloud-init-output.log
        if "test5_pw" in vars() or "test6_pw" in vars():
            self.fail("Should not show random passwords in the output")

    def test_cloudinit_check_default_config(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_check_default_config
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_check_default_config
        component:
            cloudinit
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description: |
           Check the cloud-init default config file /etc/cloud/cloud.cfg is not changed.
           It is recommended to add specific setting to /etc/cloud/cloud.cfg.d instead of 
           changing /etc/cloud/cloud.cfg directly.
        key_steps: |
            1. rpm -V cloud-init
        expect_result:
            No change in cloud.cfg
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self, 'cat /etc/cloud/cloud.cfg')
        utils_lib.run_cmd(self, 'rpm -V cloud-init', expect_not_kw='/etc/cloud/cloud.cfg')

    def test_cloudinit_lang_is_not_en_us_utf8(self):
        """
        case_tag:
            cloud_utils_growpart,cloud_utils_growpart_tier2
        case_name:
            test_cloudinit_lang_is_not_en_us_utf8
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_lang_is_not_en_us_utf8
        component:
            cloudinit
        bugzilla_id:
            1885992
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
           Verify cloud-utils-growpart works well when LANG is not en_US.UTF-8
        key_steps: |
            1. Verify cloud-utils-growpart works well when LANG is not en_US.UTF-8
        expect_result:
            cloud-utils-growpart works well when LANG is not en_US.UTF-8
        debug_want:
            N/A
        """
        if(not self._get_test_disk()):
            self.skipTest("test disk not found, provision VM should has at least 1 attached disk")
        else:
            test_disk = self._get_test_disk()
        res = utils_lib.run_cmd(self, "LANG=cs_CZ.UTF-8 growpart %s -v -N" % test_disk)
        self.assertNotIn("unexpected output", res, msg="BZ#1885992 growpart doesn't work when LANG=cs_CZ.UTF-8")

    def test_cloudinit_mount_with_noexec_option(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_mount_with_noexec_option
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_mount_with_noexec_option
        component:
            cloudinit
        bugzilla_id:
            1857309
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
           Verify cloud-init runs well when VM mounts /var/tmp with noexec option
        key_steps: |
            1. Mount /tmp /var/tmp with noexec option
        expect_result:
            cloud-init runs well when VM mounts /var/tmp with noexec option
        debug_want:
            N/A
        """
        # Mount /tmp /var/tmp with noexec option
        utils_lib.run_cmd(self, "sudo dd if=/dev/zero of=/var/tmp.partition bs=1024 count=1024000")
        utils_lib.run_cmd(self, "sudo /sbin/mke2fs /var/tmp.partition ")
        utils_lib.run_cmd(self, "sudo mount -o loop,noexec,nosuid,rw /var/tmp.partition /tmp")
        utils_lib.run_cmd(self, "sudo chmod 1777 /tmp")
        utils_lib.run_cmd(self, "sudo mount -o rw,noexec,nosuid,nodev,bind /tmp /var/tmp")
        utils_lib.run_cmd(self, "sudo echo '/var/tmp.partition /tmp ext2 loop,noexec,nosuid,rw 0 0' >> /etc/fstab")
        utils_lib.run_cmd(self, "sudo echo '/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0' >> /etc/fstab")
        utils_lib.run_cmd(self, "sudo rm -rf /var/lib/cloud/instance /var/lib/cloud/instances/* /var/log/cloud-init.log")
        # Restart VM
        self.vm.reboot(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=1200)
        # Verify cloud-init.log
        utils_lib.run_cmd(self, "sudo grep 'Permission denied' /var/log/cloud-init.log",expect_ret=1, msg="BZ#1857309. Should not have 'Permission denied'")

    def test_cloudinit_no_networkmanager(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_no_networkmanager
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_no_networkmanager
        component:
            cloudinit
        bugzilla_id:
            1898943
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Verify cloud-init works well if NetworkManager not installed
        key_steps: |
            Install network-scripts and remve NetworkManager then check cloud-init final service.
        expect_result:
            cloud-init final service works well
        debug_want:
            N/A
        """
        if float(self.rhel_x_version) >= 9.0:
            self.skipTest('skip run this case, network-script is not be supported by rhel 9 any more')
        pkg_install_check = utils_lib.is_pkg_installed(self,"network-scripts")
        if not pkg_install_check and self.vm.provider == 'openstack':
            # Register to rhsm stage
            reg_cmd = "sudo subscription-manager register --username {0} --password {1} --serverurl {2} --baseurl {3}".format(
                self.vm.subscription_username, 
                self.vm.subscription_password, 
                self.vm.subscription_serverurl,
                self.vm.subscription_baseurl)
            utils_lib.run_cmd(self, reg_cmd)
            utils_lib.run_cmd(self, "sudo subscription-manager attach --auto")
        utils_lib.is_pkg_installed(self,"network-scripts",cancel_case=True)
        utils_lib.run_cmd(self, "sudo /usr/lib/systemd/systemd-sysv-install enable network")
        # Remove ifcfg files other than eth0 and lo
        utils_lib.run_cmd(self, "sudo rm -f $(find /etc/sysconfig/network-scripts/ifcfg-*|grep -vE '(eth0|lo)')")
        utils_lib.run_cmd(self, "sudo systemctl start network", expect_ret=0, msg="Fail to start network.service")
        utils_lib.run_cmd(self, "systemctl status network")
        utils_lib.run_cmd(self, "sudo systemctl enable network")
        utils_lib.run_cmd(self, "sudo yum remove -y NetworkManager", timeout=300)
        utils_lib.run_cmd(self, "rpm -q NetworkManager", expect_ret=1, msg="Fail to remove NetworkManager")
        # Need to delete /tmp/userdata_run_uuid created by userdata(not all platforms create this file)
        # Or will cause cloud-final fail after reboot as failed to create same file
        try:
            utils_lib.run_cmd(self, "sudo rm -rf /var/lib/cloud/instance \
                                             /var/lib/cloud/instances/* \
                                             /var/log/cloud-init.log \
                                             /tmp/userdata_{0}".format(self.vm.run_uuid))
        except Exception as err:
            utils_lib.run_cmd(self, "sudo rm -rf /var/lib/cloud/instance \
                                             /var/lib/cloud/instances/* \
                                             /var/log/cloud-init.log")
            self.log.info(err)
        # Restart VM and verify connection
        self.vm.reboot(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=1200)
        #saw activating (start) in CI log, change to loop check.
        for count in utils_lib.iterate_timeout(
            60, "check cloud-final status", wait=10):
            res = utils_lib.run_cmd(self, "sudo systemctl status cloud-final")
            if re.search('active \(exited\)', res): break

    def test_cloudinit_puppet_in_correct_stage(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_puppet_in_correct_module
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_puppet_in_correct_module
        component:
            cloudinit
        bugzilla_id:
            2081435
        is_customer_case:
            True
        testplan:
            VIRT-294934
        maintainer:
            huzhao@redhat.com
        description:
           Cloud-init should place the puppet, power-state-change modules in cloud_final_modules
        key_steps: |
            1. Check /etc/cloud/cloud.cfg
        expect_result:
            The puppet, chef, salt-minion, mcollective, package-update-upgrade-install, power-state-change 
            should be in cloud_final_modules
        debug_want:
            N/A
        """
        module_list = 'puppet,chef,salt-minion,mcollective,package-update-upgrade-install,power-state-change'
        cmd = "sed -n '/cloud_final_modules:/,/system_info:/p' /etc/cloud/cloud.cfg"
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw='%s' % module_list,
                          msg='check if %s are in correct stage' % module_list)

    def test_cloudinit_rules_location(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_rules_location
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_rules_location
        component:
            cloudinit
        bugzilla_id:
            2096269
        is_customer_case:
            False
        testplan:
            VIRT-294949
        maintainer:
            huzhao@redhat.com
        description:
           Cloud-init should place the rules files in /usr/lib on rhel
        key_steps: |
            1. # ls /usr/lib/udev/rules.d/66-azure-ephemeral.rules
        expect_result:
            There should be rules file 66-azure-ephemeral.rules
        debug_want:
            N/A
        """
        utils_lib.run_cmd(self, 
                          "ls /usr/lib/udev/rules.d/66-azure-ephemeral.rules", 
                          expect_ret=0, 
                          msg="Check rules file location is /usr/lib/udev/rules.d/")

    def test_cloudinit_generator_location_permission(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_generator_location
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_generator_location
        component:
            cloudinit
        bugzilla_id:
            1971480,1897528
        is_customer_case:
            False
        testplan:
            VIRT-294956
        maintainer:
            huzhao@redhat.com
        description:
           Check cloud-init-generator location
        key_steps: |
            1. # ls -al /usr/lib/systemd/system-generators/cloud-init-generator
        expect_result:
            cloud-init-generator should be located in /usr/lib/systemd/system-generators
            The permission is 755
        debug_want:
            N/A
        """
        cmd = "ls -l /usr/lib/systemd/system-generators/cloud-init-generator | awk '{print $1,$9}'"
        output = utils_lib.run_cmd(self, cmd, msg='Check generator location and permission')
        self.assertIn('-rwxr-xr-x. /usr/lib/systemd/system-generators/cloud-init-generator', 
                      output,
                      msg=" Unexpected location or permission -> {0}".format(output))

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
        if not self.vm:
            self.skipTest('vm not init')
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
        if not self.vm:
            self.skipTest('vm not init')
        user_name = self.params.get('remote_user')
        user_dir =  "/tmp/userdata_{}".format(self.run_uuid)
        cmd = "ls -l %s" % user_dir
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "sudo rm -rf %s" % user_dir
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_cloudinit_query_instancemetadatatags(self):
        '''
        case_tag:
            cloudinit,cloudinit_tier2
        case_name:
            test_cloudinit_query_instancemetadatatags
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_query_instancemetadatatags
        component:
            cloudinit
        bugzilla_id:
            2082686, 2091640
        is_customer_case:
            True
        testplan:
            VIRT-296699
        maintainer:
            xiachen@redhat.com
        description:
           test cloud-init package upgrade, this auto case only works for openstack now
        key_steps:
            1. Enable tags on metadata when launch the EC2 instance
            2. verify that tags are available: cloud-init query ds.meta_data.tags
        debug_want:
            N/A
        '''
        #support version is 22.1-3
        if not utils_lib.is_aws(self):
            self.skipTest('skip run as this case is aws specific.')
        out = utils_lib.run_cmd(self, 'rpm -q cloud-init', expect_ret=0)
        cloudinit_ver = re.findall('\d+.\d',out)[0]
        if float(cloudinit_ver) < 22.1:
            self.skipTest('This feature is not supported before cloud-init 22.1')
        self.log.info("check if cloud-init code contains metadata_version 2021-03-23")
        # cloud-init code contains metadata_version 2021-03-23 which can support quering EC2 tags
        cmd = "sudo rpm -ql cloud-init |grep -w DataSourceEc2.py"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Get DataSourceEc2.py')
        # checking code changes is almost same as verifying function
        cmd = "sudo grep extended_metadata_versions " + output
        utils_lib.run_cmd(self, cmd,
                    expect_kw="2021-03-23",
                    msg='Check if metadata versions contains 2021-03-23')
        self.log.info("check if cloud-init can query EC2 tags in instance metadata")
        # verifying function
        cmd = "cloud-init query ds.meta_data.tags"
        utils_lib.run_cmd(self, cmd, expect_ret=0)

    def test_cloudinit_package_upgrade(self):
        '''
        case_tag:
            cloudinit,cloudinit_tier3
        case_name:
            test_cloudinit_package_upgrade
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_package_upgrade
        component:
            cloudinit
        bugzilla_id:
        is_customer_case:
            False
        testplan:
            VIRT-103841
        maintainer:
            xiachen@redhat.com
        description:
           test cloud-init package upgrade, this auto case only works for openstack now
        key_steps: |
            1. upgrade cloud-init to specific version
            2. check cloud-init services status
        debug_want:
            N/A
        '''
        if self.vm.provider != 'openstack':
            self.skipTest('skip run as this case is openstack specific.')

        self.log.info("check cloud-init works well after package upgrade")
        #for y stream   self.vm.rhel_ver=8.7  target_v=7  base_v=target_v-1
        #for z stream   self.vm.rhel_ver=8.6   target_v=6   base_v=target_v
        #if target_v=0, skip this case (or leapp upgrade)
        self.rhel_branch=int(self.vm.rhel_ver.split('.')[0])
        if self.vm.y_stream == '1' :   
            self.base_v= int(self.vm.rhel_ver.split('.')[1])-1
        else: 
            self.base_v= int(self.vm.rhel_ver.split('.')[1])
        if self.base_v <0 : self.cancel("need run leapp upgrade. Skip this case.") 

        #For RHEL7
        if self.rhel_branch == 7 :
            self.composepath="Server"
        #For RHEL8 RHEL9
        else:
            self.composepath="BaseOS"

        #create VM
        self.base_version=str(self.rhel_branch)+'.'+str(self.base_v)
        self.vm.image_name='rhel-guest-image-'+self.base_version+'-base.qcow2'
        self.log.info("create VM with image "+ self.vm.image_name)
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        self.vm.create()
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami').rstrip('\n')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)

        self._check_cloudinit_done_and_service_isactive()
        #show old package version
        cmd = "rpm -q {}".format(self.vm.package_name)
        output = utils_lib.run_cmd(self, cmd).rstrip('\n')
        self.log.info("old package version is "+output+", run successfully.")
        #install/upgrade new version
        #set base repo
        utils_lib.run_cmd(self, """
cat << EOF |sudo tee /etc/yum.repos.d/redhat.repo
[rhel-base-upgrade]
name=rhel-base-upgrade
baseurl=http://download.eng.bos.redhat.com/rhel-{0}/rel-eng/RHEL-{0}/latest-RHEL-{1}/compose/{2}/x86_64/os/
enabled=1
gpgcheck=0
[rhel-appstream-upgrade]
name=rhel-appstream-upgrade
baseurl=http://download.eng.bos.redhat.com/rhel-{0}/rel-eng/RHEL-{0}/latest-RHEL-{1}/compose/AppStream/x86_64/os/
enabled=1
gpgcheck=0
EOF
""".format(self.rhel_branch, self.base_version, self.composepath))
        cmd = 'sudo yum install -y {}'.format(self.vm.package_url)
        utils_lib.run_cmd(self, 
                          cmd, 
                          expect_ret=0,
                          msg='upgrade successfully')
        #check if version is correct, [:-4] not include '.rpm'
        self.new_pkg = self.vm.package_url.split('/')[-1][:-4]
        cmd = "rpm -q {}".format(self.vm.package_name)
        output = utils_lib.run_cmd(self, cmd).rstrip('\n')
        self.assertEqual(output, self.new_pkg, 
            "Does not upgrade to expect version. Real: {}, Expect: {}".format(output, self.new_pkg))
            #check cloud-init status is done, and no 'Traceback' in log
        self._check_cloudinit_done_and_service_isactive()
        self.log.info("Upgrade package successfully for rhel " + self.base_version)
            #reboot
        self._reboot_inside_vm(sleeptime=30)
            #check cloud-init status again, and no 'Traceback' in log
        self._check_cloudinit_done_and_service_isactive()
        self.log.info("Reboot successfully after upgrade package" + self.base_version)

    def test_cloudinit_os_upgrade(self):
        '''
        case_tag:
            cloudinit,cloudinit_tier3
        case_name:
            test_cloudinit_os_upgrade
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_os_upgrade
        component:
            cloudinit
        bugzilla_id:
        is_customer_case:
            False
        testplan:
            RHEL-187159
        maintainer:
            xiachen@redhat.com
        description:
           cloud-init works well after OS upgrade, this auto case only works for openstack now
        key_steps: |
            1. upgrade OS to specific version
            2. check cloud-init services status
        debug_want:
            N/A
        '''
        if self.vm.provider != 'openstack':
            self.skipTest('skip run as this case is openstack specific.')
        self.log.info("check cloud-init works well after OS upgrade")
        #for y stream   self.project=8.7  target_v=7  base_v=target_v-1
        #for z stream   self.project=8.6   target_v=6   base_v=target_v
        #if target_v=0, skip this case (or leapp upgrade)
        #For RHEL7

        self.rhel_branch=int(self.vm.rhel_ver.split('.')[0])
        if self.vm.y_stream == '1' :   
            self.base_v= int(self.vm.rhel_ver.split('.')[1])-1
            self.repopath="nightly"
        else: 
            self.base_v= int(self.vm.rhel_ver.split('.')[1])
            self.repopath="nightly/updates"
        if self.base_v <0 : self.cancel("need run leapp upgrade. Skip this case.") 

        #For RHEL7
        if self.rhel_branch == 7 :
            self.composepath="Server"
        #For RHEL8 RHEL9
        else:
            self.composepath="BaseOS"
            
        #create VM and upgrade OS
        self.base_version=str(self.rhel_branch)+'.'+str(self.base_v)
        self.vm.image_name='rhel-guest-image-'+self.base_version+'-base.qcow2'
        self.log.info("create VM with image "+ self.vm.image_name)
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        self.vm.create()
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        output = utils_lib.run_cmd(self, 'whoami').rstrip('\n')
        self.assertEqual(
                self.vm.vm_username, output,
                "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
                % output)
        self._check_cloudinit_done_and_service_isactive()
        #show old package version
        output = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
        self.log.info("old cloud-init package version is "+output+", run successfully.")
        #install/upgrade new version
        #set target repo
        utils_lib.run_cmd(self,"""
cat << EOF |sudo tee /etc/yum.repos.d/redhat.repo
[rhel-base-upgrade]
name=rhel-base-upgrade
baseurl=http://download.eng.bos.redhat.com/rhel-{0}/{1}/RHEL-{0}/latest-RHEL-{2}/compose/{3}/x86_64/os/
enabled=1
gpgcheck=0
[rhel-appstream-upgrade]
name=rhel-appstream-upgrade
baseurl=http://download.eng.bos.redhat.com/rhel-{0}/{1}/RHEL-{0}/latest-RHEL-{2}/compose/AppStream/x86_64/os/
enabled=1
gpgcheck=0
EOF
""".format(self.rhel_branch, self.repopath, self.vm.rhel_ver, self.composepath))
        cmd = 'sudo yum update -y --allowerasing'
        utils_lib.run_cmd(self, 
                          cmd, 
                          expect_ret=0,
                          msg='upgrade os successfully',
                          timeout=600)
        #check if version is correct, [:-4] not include '.rpm'
        self.new_pkg = self.vm.package_url.split('/')[-1][:-4]
        output = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
        self.assertEqual(output, self.new_pkg, 
            "cloud-init does not upgrade to expect version. Real: {}, Expect: {}".format(output, self.new_pkg))
        #check cloud-init status is done, and no 'Traceback' in log
        self._check_cloudinit_done_and_service_isactive()
        self.log.info("Upgrade cloud-init successfully for rhel " + self.base_version)
        #reboot
        self._reboot_inside_vm(sleeptime=120)
        #check cloud-init status again, and no 'Traceback' in log
        self._check_cloudinit_done_and_service_isactive()
        self.log.info("Reboot successfully after upgrade cloud-init for rhel " + self.base_version)

    def test_cloudinit_network_ready(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        title:
            CLOUDINIT-TC: Ensure network ready before cloud-init runs
        bug_id:
            bugzilla_2151861        
        testplan:
            https://polarion.engineering.redhat.com/polarion/#/project/RHELVIRT/wiki/Cloud-init/        
        maintainer:
            huzhao@redhat.com
        description: |
            Check the /usr/lib/systemd/system/cloud-init.service
        key_steps: |
            1. cat /usr/lib/systemd/system/cloud-init.service
        expected_result: |
            1. There should be After=NetworkManager-wait-online.service
        """
        cmd = "cat /usr/lib/systemd/system/cloud-init.service | grep -i 'After=NetworkManager-wait-online.service'"
        utils_lib.run_cmd(self, 
                          cmd, 
                          expect_ret=0,
                          msg='There should be After=NetworkManager-wait-online.service')

    def test_cloudinit_check_no_change(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2
        title:
            CLOUDINIT-TC: Check no change for the path /run/cloud-init permission
        bug_id:
            bugzilla_1728625        
        testplan:
            https://polarion.engineering.redhat.com/polarion/#/project/RHELVIRT/wiki/Cloud-init/        
        maintainer:
            huzhao@redhat.com
        description: |
            Check the path /run/cloud-init/ permission is not changed
        key_steps: |
            1. rpm -V cloud-init
        expected_result: |
            No /run/cloud-init/ in the output
        """
        utils_lib.run_cmd(self, 'ls -dl /run/cloud-init/')
        utils_lib.run_cmd(self, 'sudo rpm -V cloud-init', expect_not_kw='/run/cloud-init')

    def tearDown(self):
        utils_lib.finish_case(self)
        if 'test_cloudinit_sshd_keypair' in self.id():
            cmd = 'cp -f ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys'
            utils_lib.run_cmd(self, cmd, msg='restore .ssh/authorized_keys')
            cmd= 'sudo systemctl restart  sshd'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='restart sshd service')
        if 'test_cloudinit_no_networkmanager' in self.id():
            if float(self.rhel_x_version) < 9.0:
                NM_check = utils_lib.run_cmd(self, "rpm -q NetworkManager", ret_status=True)
                network_check = utils_lib.run_cmd(self, "rpm -q network-scripts", ret_status=True)
                if self.NM_install == 0 and NM_check == 1:
                    utils_lib.run_cmd(self, "sudo yum install -y NetworkManager", msg='Restore NM config')
                    utils_lib.run_cmd(self, "sudo systemctl start NetworkManager")
                    utils_lib.run_cmd(self, "sudo systemctl enable NetworkManager")
                if self.network_install == 1 and network_check == 0:
                    utils_lib.run_cmd(self, "sudo yum remove -y network-scripts", msg='Restore network-scripts config')
                if self.vm.provider == 'openstack':
                    utils_lib.run_cmd(self, "sudo subscription-manager unregister")
        case_list = ['test_cloudinit_create_vm_two_nics',
                     'test_cloudinit_create_vm_stateless_ipv6',
                     'test_cloudinit_create_vm_stateful_ipv6']
        for case_name in case_list:
            if case_name in self.id() and self.vm.provider == 'openstack':
                self.vm.delete()
                self.vm.second_nic_id = None
                self.vm.create()
                time.sleep(30)
                utils_lib.init_connection(self, timeout=self.ssh_timeout)        
        #utils_lib.finish_case(self)

if __name__ == '__main__':
    unittest.main()