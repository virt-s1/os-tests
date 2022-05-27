import unittest
from os_tests.libs import utils_lib
from os_tests.libs.resources import UnSupportedAction
import time

class TestCloudInit(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

        cmd = "sudo systemctl is-enabled cloud-init-local"
        utils_lib.run_cmd(self, cmd, cancel_ret='0', msg = "check cloud-init-local is enabled")
        self.timeout = 180

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
        """
        case_tag:
            cloudinit
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
            Cloudinit
        case_name:
            test_cloudinit_auto_extend_root_partition_and_filesystem
        case_file:
            os_tests.tests.test_cloud_init.TestCloudInit.test_cloudinit_auto_extend_root_partition_and_filesystem
        component:
            cloud-init,cloud_utils_growpart
        bugzilla_id:
            1447177
        is_customer_case:
            N/A
        testplan:
            N/A
        maintainer:
            minl@redha.tcom
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

        self.log.info("RHEL7-103839 - CLOUDINIT-TC: Auto extend root partition and filesystem")
        # 1. Install cloud-utils-growpart gdisk
        utils_lib.is_cmd_exist(self, cmd='growpart')
        utils_lib.is_cmd_exist(self, cmd='gdisk')
        
        # 2. Check os disk and fs capacity
        boot_dev = self._get_boot_temp_devices()
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
            Cloudinit
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
        description:
            VM can successfully login after provisioning(with password authentication)
        key_steps:
            1. Create a VM with only password authentication
        expect_result:
            1. Login with password, should have sudo privilege
        debug_want:
            N/A
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
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
        #teardown
        self.vm.ssh_pubkey=save_ssh_pubkey
        self.vm.delete()
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        time.sleep(30)
        self.params['remote_node'] = self.vm.floating_ip
        utils_lib.init_connection(self, timeout=self.timeout)

    def test_cloudinit_verify_hostname(self):
        """
        case_tag:
            Cloudinit
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
            1. Check hostname by different command
        expect_result:
            1. Host name is correct
        debug_want:
            N/A
        """
        for cmd in ['hostname', 'nmcli general hostname', 'hostnamectl|grep Static']:
            check_hostname = utils_lib.run_cmd(self, 'sudo cat /var/log/cloud-init.log', expect_ret=0)
            self.assertIn(self.vm.vm_name, check_hostname, "'%s': Hostname is not correct" % cmd)

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
            Cloudinit
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
            Cloudinit
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
            Cloudinit
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

    def tearDown(self):
        if 'test_cloudinit_sshd_keypair' in self.id():
            cmd = 'cp -f ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys'
            utils_lib.run_cmd(self, cmd, msg='restore .ssh/authorized_keys')
            cmd= 'sudo systemctl restart  sshd'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='restart sshd service')
        #utils_lib.finish_case(self)

if __name__ == '__main__':
    unittest.main()