import unittest
from os_tests.libs import utils_lib
import time
import re

class TestVtpm(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        #check platform version
        if  self.vm.provider == 'nutanix':
            ahv_version = utils_lib.send_ssh_cmd(self.vm.host_ip, self.vm.host_username, self.vm.host_password, \
                        "cat /etc/nutanix-release")[1]
            ahv_match = 'el\d+.nutanix.(\d{8})'
            ahv_date = time.strptime(re.search(ahv_match, ahv_version, re.I).groups()[0], "%Y%m%d")
            if ahv_date < time.strptime('20220304', "%Y%m%d"):
                self.skipTest("Platform version is too old to run vtpm test!")
        #check boot configuration
        cmd='[ -d /sys/firmware/efi ] && echo UEFI || echo BIOS'
        bios_or_uefi = utils_lib.run_cmd(self, cmd, expect_ret=0).strip()
        self.log.info("Boot configuration is %s" % bios_or_uefi)
        if bios_or_uefi == 'BIOS':
            self.skipTest("Only support to run for VM with UEFI boot configuration!")
        #get dmesg cursor
        self.cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')
        #define sh script
        self.tpm_test_sh = '''tpm2_createprimary -c primary.ctx
tpm2_create -C primary.ctx -Gaes128 -u key.pub -r key.priv
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
echo "This is some secret text." > secret.dat
tpm2_encryptdecrypt -c key.ctx -o secret.enc secret.dat
tpm2_encryptdecrypt -d -c key.ctx -o secret.dec secret.enc
cat secret.dec'''

    def _add_vtpm_device(self):
        self.log.info("Update VM by acli command to add vtpm device.")
        self.vm.stop(wait=True)
        time.sleep(60)
        cvm_cmd_res = self.vm.cvm_cmd("acli vm.update %s virtual_tpm=true" % self.vm.vm_name)
        self.assertIn('complete', cvm_cmd_res,
            msg="Cannot complete adding vtpm device, Expect: complete, real: %s" % cvm_cmd_res)
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def _check_vtpm_log_and_version(self, rmt_node=None):
        if rmt_node == None:
            rmt_node = self.vm.floating_ip
        self.log.info("Check vtpm device info, dmesg log and version info.")
        for cmd, key_word, msg in zip(['ls /dev/tpm*','dmesg | grep TPM',\
            'cat /sys/class/tpm/tpm0/tpm_version_major'], \
            ['/dev/tpm0,/dev/tpmrm0', 'TPMFinalLog,TPMEventLog,TPM2', '2'], \
            ['check vtpm device info', 'check vtpm log info','check vtpm version info']):
            utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw=key_word, msg=msg, rmt_node=rmt_node)

    def _test_vtpm_encryption_decryption(self, rmt_node=None):
        if rmt_node == None:
            rmt_node = self.vm.floating_ip
        self.log.info('Test encryption/decryption with TPM2')
        utils_lib.is_pkg_installed(self,"tpm2-tools")
        self.log.info("Run vtpm test script")
        utils_lib.run_cmd(self,"echo '''%s''' | sudo tee /tmp/tpm_test.sh" % self.tpm_test_sh, expect_ret=0, rmt_node=rmt_node)
        utils_lib.run_cmd(self,"sudo chmod 777 /tmp/tpm_test.sh", expect_ret=0, rmt_node=rmt_node)
        utils_lib.run_cmd(self,"sudo /tmp/tpm_test.sh", expect_ret=0, rmt_node=rmt_node)
        tpm_test_res = utils_lib.run_cmd(self, "sudo cat secret.dec")
        tpm_test_expect = 'This is some secret text'
        self.assertIn(tpm_test_expect, tpm_test_res,
            msg="Test encryption/decryption with TPM2 failed, Expect: %s, real: %s" % (tpm_test_expect,tpm_test_res))
        #tear down
        utils_lib.run_cmd(self, "rm -f key.* primary.ctx secret.*")

    def test_add_vtpm_device_to_guest(self):
        """
        case_tag:
            VTPM,VTPM_tier1
        case_name:
            test_add_vtpm_device_to_guest
        case_file:
            os_tests.tests.test_vtpm.TestVTPM.test_add_vtpm_device_to_guest
        component:
            VTPM
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Add vTPM device to an exist RHEL guest and check status.
        key_steps: |
            1. Add vTPM device by acli command.
            2. Check device info and log and encryption/decryption.
        expect_result:
            No error threw.
        debug_want:
            output from dmesg or journal
        """
        self.log.info("check if need to add vtpm device or not")
        if 'No such file or directory' in utils_lib.run_cmd(self, 'ls /dev/tpm*'):
            self._add_vtpm_device()
        self._check_vtpm_log_and_version()
        self._test_vtpm_encryption_decryption()
        
    def test_reboot_vtpm_vm(self):
        """
        case_tag:
            VTPM,VTPM_tier2
        case_name:
            test_reboot_vtpm_vm
        case_file:
            os_tests.tests.test_vtpm.TestVTPM.test_reboot_vtpm_vm
        component:
            VTPM
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check VTPM status after reboot VM.
        key_steps: |
            1. Check VTPM status after reboot VM.
        expect_result:
            No error threw.
        debug_want:
            output from dmesg or journal
        """
        self.log.info("check if need to add vtpm device or not")
        if 'No such file or directory' in utils_lib.run_cmd(self, 'ls /dev/tpm*'):
            self._add_vtpm_device()
        self.vm.reboot(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        self._check_vtpm_log_and_version()
        self._test_vtpm_encryption_decryption()

    def test_shutdown_power_on_vtpm_vm(self):
        """
        case_tag:
            VTPM,VTPM_tier2
        case_name:
            test_shutdown_power_on_vtpm_vm
        case_file:
            os_tests.tests.test_vtpm.TestVTPM.test_shutdown_power_on_vtpm_vm
        component:
            VTPM
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Check VTPM status after shutdown and then power on VM.
        key_steps: |
            1. Check VTPM status after shutdown and then power on VM.
        expect_result:
            No error threw.
        debug_want:
            output from dmesg or journal
        """
        self.log.info("check if need to add vtpm device or not")
        if 'No such file or directory' in utils_lib.run_cmd(self, 'ls /dev/tpm*'):
            self._add_vtpm_device()
        utils_lib.run_cmd(self, 'sudo shutdown now')
        for count in utils_lib.iterate_timeout(
                60, "Timed out waiting for getting server stopped."):
            if self.vm.is_stopped(): break
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        self._check_vtpm_log_and_version()
        self._test_vtpm_encryption_decryption()

    def test_deploy_vm_with_vtpm(self):
        """
        case_tag:
            VTPM,VTPM_tier1
        case_name:
            test_deploy_vm_with_vtpm
        case_file:
            os_tests.tests.test_vtpm.TestVTPM.test_deploy_vm_with_vtpm
        component:
            VTPM
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Add vTPM device when creating a RHEL guest and check status.
        key_steps: |
            1. Create a new VM with vtpm device.
            2. Check device info and log and encryption/decryption.
        expect_result:
            No error threw.
        debug_want:
            output from dmesg or journal
        """
        if len(self.vms) == 1:
            new_vm = self.vm.create_vm_by_acli(self.vm.vm_name+'_'+'scriptCreateVtpmVM', str(self.vm.memory)+'G', '2', self.vm.cpu, 'true', 'true')
            self.vms.append(new_vm)
        new_vm_ip = self.vms[1]['vm_nics'][0]['ip_address']
        for cmd, key_word_list, msg in zip(['ls /dev/tpm*','dmesg | grep TPM',\
            'cat /sys/class/tpm/tpm0/tpm_version_major'], \
            [['/dev/tpm0', '/dev/tpmrm0'], ['TPMFinalLog','TPMEventLog','TPM2'], '2'], \
            ['check vtpm device info', 'check vtpm log info','check vtpm version info']):
            for key_word in key_word_list:
                cmd_res = utils_lib.send_ssh_cmd(new_vm_ip, self.vm.vm_username, self.vm.vm_password, cmd)
                self.assertIn(key_word, cmd_res[1], msg="%s failed" % msg)
        utils_lib.send_ssh_cmd(new_vm_ip, self.vm.vm_username, self.vm.vm_password, \
            "sudo yum install -y tpm2-tools", timeout=180)
        utils_lib.send_ssh_cmd(new_vm_ip, self.vm.vm_username, self.vm.vm_password, \
            "echo '''%s''' | sudo tee /tmp/tpm_test.sh" % self.tpm_test_sh)
        utils_lib.send_ssh_cmd(new_vm_ip, self.vm.vm_username, self.vm.vm_password, "sudo chmod 777 /tmp/tpm_test.sh")
        tpm_test_res = utils_lib.send_ssh_cmd(new_vm_ip, self.vm.vm_username, self.vm.vm_password,"sudo /tmp/tpm_test.sh")[1]
        tpm_test_expect = 'This is some secret text'
        self.assertIn(tpm_test_expect, tpm_test_res,
            msg="Test encryption/decryption with TPM2 failed, Expect: %s, real: %s" % (tpm_test_expect,tpm_test_res))

    def _basic_validation(self, rmt_node=None):
        if rmt_node == None:
            rmt_node = self.vm.floating_ip
        self._check_vtpm_log_and_version()
        #basic validation
        for cmd in ["clevis", "tpm2-abrmd", "tpm2-tools"]:
            utils_lib.is_cmd_exist(self, cmd=cmd, cancel_case=True)
        utils_lib.run_cmd(self, "sudo systemctl enable tpm2-abrmd")
        utils_lib.run_cmd(self, "tpm2_getrandom 20", expect_ret=0)
        utils_lib.run_cmd(self, "echo 'hello world!' > input.txt && \
            sudo clevis encrypt tpm2 '{}' < input.txt > secret.jwe", expect_ret=0)
        utils_lib.run_cmd(self, "ls secret.jwe", expect_ret=0)
        utils_lib.run_cmd(self, "rm -f input.txt && \
            sudo clevis decrypt < secret.jwe > output.txt && cat output.txt", expect_ret=0, \
                expect_output="hello world!")
        #tear down
        utils_lib.run_cmd(self, "rm -f output.txt secret.jwe", expect_ret=0)

    def test_add_vtpm_device_basic_validation(self):
        """
        case_tag:
            VTPM,VTPM_tier1
        case_name:
            test_add_vtpm_device_basic_validation
        case_file:
            os_tests.tests.test_vtpm.TestVTPM.test_add_vtpm_device_basic_validation
        component:
            VTPM
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Add vTPM device to an exist RHEL guest and test basic validation.
        key_steps: |
            1. Add vTPM device by acli command.
            2. Test basic validation.
        expect_result:
            No error threw.
        debug_want:
            output from dmesg or journal
        """
        self.log.info("check if need to add vtpm device or not")
        if 'No such file or directory' in utils_lib.run_cmd(self, 'ls /dev/tpm*'):
            self._add_vtpm_device()
        self._basic_validation()

    def test_deploy_vtpm_vm_basic_validation(self):
        """
        case_tag:
            VTPM,VTPM_tier1
        case_name:
            test_deploy_vtpm_vm_basic_validation
        case_file:
            os_tests.tests.test_vtpm.TestVTPM.test_deploy_vtpm_vm_basic_validation
        component:
            VTPM
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Add vTPM device when creating a RHEL guest and test basic validation.
        key_steps: |
            1. Add vTPM device by acli command.
            2. Test basic validation.
        expect_result:
            No error threw.
        debug_want:
            output from dmesg or journal
        """
        if len(self.vms) == 1:
            new_vm = self.vm.create_vm_by_acli(self.vm.vm_name+'_'+'scriptCreateVtpmVM', str(self.vm.memory)+'G', '2', self.vm.cpu, 'true', 'true')
            self.vms.append(new_vm)
        new_vm_ip = self.vms[1]['vm_nics'][0]['ip_address']
        self._basic_validation(rmt_node=new_vm_ip)

    def tearDown(self):
        utils_lib.check_log(self, "error,warn,fail,Call trace,Call Trace", log_cmd='dmesg -T', cursor=self.cursor)
        if 'test_deploy' in self.id():
            vm1 = self.vm.get_vm_by_filter('vm_name', self.vm.vm_name+'_'+'scriptCreateVtpmVM')
            if vm1 != None:
                self.vm.delete(uuid=vm1['uuid'])
                self.vms.pop()

if __name__ == '__main__':
    unittest.main()