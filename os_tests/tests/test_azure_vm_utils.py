import unittest
from os_tests.libs import utils_lib
import json
import time
import os
import re

class TestAzureVMUtils(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        if not utils_lib.is_azure(self):
            self.skipTest('Only run for azure image checking.')

    @property
    def rhel_x_version(self):
        product_id = utils_lib.get_product_id(self)
        return int(product_id.split('.')[0])

    def test_azure_vm_utils_installed(self):
        """
        case_tag:
            azure_vm_utils,azure_vm_utils_tier1
        case_name:
            test_azure_vm_utils_installed
        component:
            azure-vm-utils
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            xxiong@redhat.com
        description:
            Check if azure-vm-utils package is installed and azure-nvme-id command is available
        key_steps:
            1. Check azure-vm-utils package installation with rpm -qa
            2. Check azure-nvme-id command is available and shows version
        expect_result:
            azure-vm-utils package should be installed and azure-nvme-id command should work
        debug_want:
            package installation status and command availability
        """
        # Check azure-vm-utils package installation using rpm -qa
        cmd = 'rpm -qa azure-vm-utils'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check azure-vm-utils package is installed')

        # Check if package is installed (output should not be empty)
        if not output.strip():
            self.fail('azure-vm-utils package is not installed. Expected output from "rpm -qa azure-vm-utils" but got empty result.')

        # Verify the package name appears in output (ignoring version part)
        self.assertIn('azure-vm-utils', output, 'azure-vm-utils package should be listed in rpm output')
        self.log.info(f'azure-vm-utils package found: {output.strip()}')

        # Check azure-nvme-id command is available and shows version
        cmd = 'azure-nvme-id --version'
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='check azure-nvme-id command availability')

        if ret != 0:
            self.fail('azure-nvme-id command is not available or failed to execute')

        # Get the actual output for verification
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get azure-nvme-id version output')

        # Verify the command output contains azure-nvme-id (ignoring version part)
        self.assertIn('azure-nvme-id', output, 'azure-nvme-id command should show version information')
        self.log.info(f'azure-nvme-id version: {output.strip()}')

    def test_azure_vm_utils_log_no_errors(self):
        """
        case_tag:
            azure_vm_utils,azure_vm_utils_tier2
        case_name:
            test_azure_vm_utils_log_no_errors
        component:
            azure-vm-utils
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            testuser@example.com
        description:
            Check azure-vm-utils logs for errors
        key_steps:
            1. Check systemd journal for azure-vm-utils errors
            2. Check /var/log/messages for azure-vm-utils errors
        expect_result:
            No critical errors in azure-vm-utils logs
        debug_want:
            azure-vm-utils logs
        """
        # Check dmesg no crash errors
        cmd = "sudo dmesg | grep 'Call Trace'"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg="Check azure-vm-utils Call Trace logs")

        if ret == 0:
            # If service exists, check for errors
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        expect_not_kw='ERROR,CRITICAL,FATAL',
                        msg='check azure-vm-utils dmesg logs for Call Trace')

        # Check systemd journal for azure-vm-utils related errors
        cmd = "sudo journalctl -u azure-vm-utils --no-pager -l"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg="Check azure-vm-utils journal logs")

        if ret == 0:
            # If service exists, check for errors
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        expect_not_kw='ERROR,CRITICAL,FATAL',
                        msg='check azure-vm-utils journal logs for errors')

        # Check system logs for azure-vm-utils related messages
        cmd = "sudo grep -i azure-vm-utils /var/log/messages"
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg="Check system logs for azure-vm-utils")

        if ret == 0:
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        expect_not_kw='error,failed,critical',
                        msg='check system logs for azure-vm-utils errors')   
          
    def test_azure_disk_rules_in_initramfs(self):
        """
        case_tag:
            azure_vm_utils,azure_vm_utils_tier2
        case_name:
            test_azure_disk_rules_in_initramfs
        component:
            azure-vm-utils
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            xxiong@redhat.com
        description:
            Check if 80-azure-disk.rules is included in initramfs after dracut rebuild
        key_steps:
            1. Rebuild initramfs with dracut -f
            2. Check if 80-azure-disk.rules is present in initramfs using lsinitrd
        expect_result:
            80-azure-disk.rules should be present in the initramfs
        debug_want:
            initramfs contents and dracut process
        """
        # Get current kernel version
        cmd = 'uname -r'
        kernel_version = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get current kernel version').strip()
        self.log.info(f'Current kernel version: {kernel_version}')

        # Rebuild initramfs with dracut -f
        cmd = 'sudo dracut -f'
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=300, msg='rebuild initramfs with dracut -f')

        # Check if 80-azure-disk.rules is present in initramfs
        initramfs_path = f'/boot/initramfs-{kernel_version}.img'

        # First verify the initramfs file exists
        cmd_check = f'ls -l {initramfs_path}'
        utils_lib.run_cmd(self, cmd_check, expect_ret=0, msg=f'verify initramfs file exists: {initramfs_path}')

        # Use lsinitrd with grep to search for azure-related files
        cmd = f'sudo lsinitrd {initramfs_path} | grep azure'
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg='search for azure-related files in initramfs')

        if ret != 0:
            # No azure files found, this is a failure
            self.fail('No azure-related files found in initramfs. Expected to find 80-azure-disk.rules or other azure components.')

        # Get the actual output to verify content
        output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='list azure-related files in initramfs')
        self.log.info(f'Azure-related files found in initramfs: {output}')

        # Check specifically for 80-azure-disk.rules
        if '80-azure-disk.rules' not in output:
            self.fail(f'80-azure-disk.rules not found in initramfs. Found azure files: {output.strip()}')

        self.log.info('80-azure-disk.rules successfully found in initramfs')

        # Log the specific rules entry for verification
        rules_lines = [line for line in output.split('\n') if '80-azure-disk.rules' in line]
        for rule_line in rules_lines:
            self.log.info(f'Found 80-azure-disk.rules entry: {rule_line.strip()}')
    
    def test_azure_vm_utils_selftest(self):
        """
        case_tag:
            azure_vm_utils,azure_vm_utils_tier1
        case_name:
            test_azure_vm_utils_selftest
        component:
            azure-vm-utils
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            xxiong@redhat.com
        description:
            Run azure-vm-utils selftest to validate functionality
        key_steps:
            1. Upload selftest.py script to the test VM
            2. Run selftest with skip options for imds and udev validation
            3. Check that result output ends with 'success!'
        expect_result:
            Selftest should complete successfully and output should end with 'success!'
        debug_want:
            selftest script output and execution logs
        """
        # Check if we're in remote mode (required for this test)
        if not hasattr(self, 'SSH') or self.SSH is None:
            # Try to get connection info from params or vm object
            if hasattr(self, 'vm') and hasattr(self.vm, 'floating_ip'):
                test_vm_ip = self.vm.floating_ip
                username = getattr(self.vm, 'vm_username', 'azureuser')
            elif self.params.get('remote_node'):
                test_vm_ip = self.params.get('remote_node')
                username = self.params.get('remote_user', 'azureuser')
            else:
                self.skipTest('This test requires remote VM access with IP address')
        else:
            test_vm_ip = self.params.get('remote_node')
            username = self.params.get('remote_user', 'azureuser')

        if not test_vm_ip:
            self.skipTest('Cannot determine test VM IP address for selftest')

        self.log.info(f'Running selftest on VM: {username}@{test_vm_ip}')

        # Step 1: Upload the selftest script
        selftest_script_path='/tmp/selftest.py'
        remote_script_path = f'/home/{username}/selftest.py'

        # Check if selftest script exists on LOCAL HOST machine
        import subprocess
        import os as local_os

        if not local_os.path.exists(selftest_script_path):
            # Download selftest.py from GitHub if not found locally
            self.log.info(f'Selftest script not found at {selftest_script_path}, downloading from GitHub')
            github_url = 'https://github.com/Azure/azure-vm-utils/blob/main/selftest/selftest.py'
            raw_url = 'https://raw.githubusercontent.com/Azure/azure-vm-utils/main/selftest/selftest.py'

            # Create /root directory if it doesn't exist on LOCAL HOST
            try:
                local_os.makedirs('/tmp', exist_ok=True)
            except PermissionError:
                result = subprocess.run(['sudo', 'mkdir', '-p', '/tmp'], capture_output=True)
                if result.returncode != 0:
                    self.fail('Failed to create /root directory on local host')

            # Download the script using wget or curl on LOCAL HOST
            try:
                result = subprocess.run(['wget', '-O', selftest_script_path, raw_url],
                                      capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    # Try with curl if wget fails
                    result = subprocess.run(['curl', '-L', '-o', selftest_script_path, raw_url],
                                          capture_output=True, text=True, timeout=60)
                    if result.returncode != 0:
                        self.fail(f'Failed to download selftest.py from GitHub: {result.stderr}')

                # Make the script executable on LOCAL HOST
                try:
                    local_os.chmod(selftest_script_path, 0o755)
                except PermissionError:
                    subprocess.run(['sudo', 'chmod', '+x', selftest_script_path], check=True)

            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
                self.fail(f'Failed to download selftest.py from GitHub to local host: {e}')

            self.log.info(f'Successfully downloaded selftest.py from {github_url}')
        else:
            self.log.info(f'Using existing selftest.py at {selftest_script_path}')

        # Upload the script using scp FROM LOCAL HOST
        try:
            self.log.info(f'Uploading selftest.py from local host to {username}@{test_vm_ip}')
            result = subprocess.run(['scp', '-o', 'StrictHostKeyChecking=no', selftest_script_path, f'{username}@{test_vm_ip}:{remote_script_path}'],
                                  capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                self.fail(f'Failed to upload selftest.py via scp: {result.stderr}')

            # Verify the script was uploaded successfully
            result = subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', f'{username}@{test_vm_ip}', '--', 'ls', '-l', remote_script_path],
                                  capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                self.fail(f'Failed to verify uploaded selftest.py: {result.stderr}')

            # Make the script executable on remote VM
            result = subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', f'{username}@{test_vm_ip}', '--', 'chmod', '+x', remote_script_path],
                                  capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                self.fail(f'Failed to make selftest.py executable: {result.stderr}')

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.fail(f'Failed during script upload process: {e}')

        # Step 2: Run the selftest with skip options FROM LOCAL HOST via SSH
        try:
            self.log.info(f'Running selftest on remote VM: {username}@{test_vm_ip}')

            # First, let's verify the script exists and is executable
            result = subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', f'{username}@{test_vm_ip}', '--', 'ls', '-la', remote_script_path],
                                  capture_output=True, text=True, timeout=30)
            self.log.info(f'Script file details: {result.stdout}')
            if result.returncode != 0:
                self.log.warning(f'Script verification failed: {result.stderr}')

            # Test if the script can be executed directly
            result = subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', f'{username}@{test_vm_ip}', '--', 'python3', '--version'],
                                  capture_output=True, text=True, timeout=30)
            self.log.info(f'Python3 version on VM: {result.stdout.strip()}')

            # Run the selftest and capture both stdout and stderr
            result = subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', f'{username}@{test_vm_ip}', '--', 'sudo', 'python3', remote_script_path,
                                   '--skip-imds-validation', '--skip-udev-validation'],
                                  capture_output=True, text=True, timeout=300)

            self.log.info(f'Selftest return code: {result.returncode}')
            self.log.info(f'Selftest stdout: {result.stdout}')
            self.log.info(f'Selftest stderr: {result.stderr}')

            if result.returncode != 0:
                self.fail(f'Selftest execution failed with return code {result.returncode}. stderr: {result.stderr}')

            # Use both stdout and stderr for output analysis
            output = result.stdout if result.stdout.strip() else result.stderr

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.fail(f'Failed to execute selftest via SSH: {e}')

        self.log.info(f'Selftest output:\n{output}')

        # Step 3: Check that the result ends with 'success!'
        output_lines = output.strip().split('\n')
        last_line = output_lines[-1].strip() if output_lines else ''

        if not last_line.endswith('success!'):
            self.fail(f'Selftest did not end with "success!". Last line was: "{last_line}"')

        self.log.info('Azure-vm-utils selftest completed successfully!')

        # Additional verification: check for any error patterns in output
        error_patterns = ['error', 'fail', 'exception', 'traceback']
        output_lower = output.lower()

        for pattern in error_patterns:
            if pattern in output_lower and 'success!' not in output_lower.split(pattern)[-1]:
                self.log.warning(f'Potential issue detected in selftest output: found "{pattern}"')

        # Clean up the uploaded script
        cmd = f'ssh {username}@{test_vm_ip} -- rm -f {remote_script_path}'
        utils_lib.run_cmd(self, cmd, ret_status=True, msg='cleanup selftest.py from test VM')
    
    def test_azure_vm_utils_standard_d2s_v4(self):
        """
        case_tag:
            azure_vm_utils,azure_vm_utils_tier2
        case_name:
            test_azure_vm_utils_standard_d2s_v4
        component:
            azure-vm-utils
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            xxiong@redhat.com
        description:
            Test azure-vm-utils functionality on Standard_D2s_v4 VMs
        key_steps:
            1. Check VM size is Standard_D2s_v4 via metadata service
            2. Test azure-nvme-id --format command
            3. Test azure-nvme-id --udev command
            4. Test azure-nvme-id --debug command
            5. Check /dev/disk/azure symlinks
        expect_result:
            All azure-nvme-id commands should work properly on Standard_D2s_v4
        debug_want:
            azure-nvme-id command outputs and disk symlinks
        """
        # Check VM size via Azure metadata service
        cmd = 'curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text"'
        vm_size = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get VM size from Azure metadata service').strip()

        self.log.info(f'Current VM size: {vm_size}')

        if vm_size != 'Standard_D2s_v4':
            self.skipTest(f'This test is only for Standard_D2s_v4 VMs. Current VM size is {vm_size}')

        self.log.info('VM size is Standard_D2s_v4, proceeding with azure-nvme-id tests')

        # Subtest 1: Check azure-nvme-id --format
        with self.subTest('azure-nvme-id --format'):
            # Test azure-nvme-id --format json (should output [])
            cmd = 'azure-nvme-id --format json'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id --format json command')
            self.log.info(f'azure-nvme-id --format json output: {output}')

            output_stripped = output.strip()
            if output_stripped != '[]':
                self.fail(f'azure-nvme-id --format json should output "[]", but got: "{output_stripped}"')

            # Test azure-nvme-id --format plain (should output empty)
            cmd = 'azure-nvme-id --format plain'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id --format plain command')
            self.log.info(f'azure-nvme-id --format plain output: "{output}"')

            if output.strip():
                self.fail(f'azure-nvme-id --format plain should output empty, but got: "{output.strip()}"')

            self.log.info('azure-nvme-id --format commands validated successfully')

        # Subtest 2: Check azure-nvme-id --debug
        with self.subTest('azure-nvme-id --debug'):
            cmd = 'azure-nvme-id --debug'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id --debug command')
            self.log.info(f'azure-nvme-id --debug output: {output}')

            expected_text = "DEBUG: found 0 controllers"
            if expected_text not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_text}", but output was: {output}')

            self.log.info('azure-nvme-id --debug command validated successfully')

        # Subtest 3: Check azure-nvme-id (should output empty)
        with self.subTest('azure-nvme-id'):
            cmd = 'azure-nvme-id'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id command')
            self.log.info(f'azure-nvme-id output: "{output}"')

            if output.strip():
                self.fail(f'azure-nvme-id should output empty, but got: "{output.strip()}"')

            self.log.info('azure-nvme-id command validated successfully')

        # Subtest 4: Check /dev/disk/azure symlinks
        with self.subTest('/dev/disk/azure symlinks'):
            # First perform disk partitioning
            disks = ['/dev/sda', '/dev/sdb', '/dev/sdc', '/dev/sdd']

            for disk in disks:
                self.log.info(f'Partitioning {disk}...')

                # Check if disk exists before partitioning
                cmd = f'test -b {disk}'
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg=f'check if {disk} exists')
                if ret != 0:
                    self.log.info(f'Disk {disk} does not exist, skipping')
                    continue

                # Create GPT partition table
                cmd = f'sudo parted --script {disk} mklabel gpt'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create GPT partition table on {disk}')

                # Create first partition (0% - 50%)
                cmd = f'sudo parted --script {disk} mkpart primary xfs 0% 50%'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create first partition on {disk}')

                # Create second partition (50% - 100%)
                cmd = f'sudo parted --script {disk} mkpart primary xfs 50% 100%'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create second partition on {disk}')

                # Wait for partitions to appear
                cmd = f'sudo partprobe {disk}'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'refresh partition table for {disk}')

                self.log.info(f'Successfully partitioned {disk}')

            # Wait a bit for udev to process the new partitions
            cmd = 'sleep 2'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='wait for udev to process new partitions')

            # Now check the azure disk symlinks
            cmd = 'find /dev/disk/azure -type l | sort'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='list azure disk symlinks')
            self.log.info(f'/dev/disk/azure symlinks:\n{output}')

            # Expected symlinks after partitioning
            expected_symlinks = [
                "/dev/disk/azure/data/by-lun/0",
                "/dev/disk/azure/data/by-lun/0-part1",
                "/dev/disk/azure/data/by-lun/0-part2",
                "/dev/disk/azure/data/by-lun/1",
                "/dev/disk/azure/data/by-lun/1-part1",
                "/dev/disk/azure/data/by-lun/1-part2",
                "/dev/disk/azure/data/by-lun/2",
                "/dev/disk/azure/data/by-lun/2-part1",
                "/dev/disk/azure/data/by-lun/2-part2",
                "/dev/disk/azure/data/by-lun/3",
                "/dev/disk/azure/data/by-lun/3-part1",
                "/dev/disk/azure/data/by-lun/3-part2",
                "/dev/disk/azure/os",
                "/dev/disk/azure/os-part1",
                "/dev/disk/azure/os-part2",
                "/dev/disk/azure/os-part3",
                "/dev/disk/azure/os-part4",
                "/dev/disk/azure/root",
                "/dev/disk/azure/root-part1",
                "/dev/disk/azure/root-part2",
                "/dev/disk/azure/root-part3",
                "/dev/disk/azure/root-part4",
                "/dev/disk/azure/scsi1/lun0",
                "/dev/disk/azure/scsi1/lun0-part1",
                "/dev/disk/azure/scsi1/lun0-part2",
                "/dev/disk/azure/scsi1/lun1",
                "/dev/disk/azure/scsi1/lun1-part1",
                "/dev/disk/azure/scsi1/lun1-part2",
                "/dev/disk/azure/scsi1/lun2",
                "/dev/disk/azure/scsi1/lun2-part1",
                "/dev/disk/azure/scsi1/lun2-part2",
                "/dev/disk/azure/scsi1/lun3",
                "/dev/disk/azure/scsi1/lun3-part1",
                "/dev/disk/azure/scsi1/lun3-part2"
            ]

            # Parse actual symlinks
            actual_symlinks = [link.strip() for link in output.strip().split('\n') if link.strip()]

            # Validate that we have the expected symlinks
            self.log.info(f'Found {len(actual_symlinks)} azure disk symlinks')

            # Check for missing expected symlinks
            missing_symlinks = []
            for expected in expected_symlinks:
                if expected not in actual_symlinks:
                    missing_symlinks.append(expected)

            if missing_symlinks:
                self.log.warning(f'Missing expected symlinks: {missing_symlinks}')

            # Check for unexpected symlinks
            unexpected_symlinks = []
            for actual in actual_symlinks:
                if actual not in expected_symlinks:
                    unexpected_symlinks.append(actual)

            if unexpected_symlinks:
                self.log.info(f'Additional symlinks found: {unexpected_symlinks}')

            # Basic validation: should have at least some core symlinks
            core_symlinks = [link for link in actual_symlinks if '/dev/disk/azure/' in link]
            if not core_symlinks:
                self.fail('No azure disk symlinks found in /dev/disk/azure')

            # Validate critical symlinks exist
            critical_patterns = [
                '/dev/disk/azure/data/by-lun/',
                '/dev/disk/azure/scsi1/lun'
            ]

            for pattern in critical_patterns:
                matching_links = [link for link in actual_symlinks if pattern in link]
                if not matching_links:
                    self.log.warning(f'No symlinks found matching pattern: {pattern}')

            self.log.info('Azure disk symlinks validation completed')

    def test_azure_vm_utils_standard_e2bds_v5(self):
        """
        case_tag:
            azure_vm_utils,azure_vm_utils_tier2
        case_name:
            test_azure_vm_utils_standard_e2bds_v5
        component:
            azure-vm-utils
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            xxiong@redhat.com
        description:
            Test azure-vm-utils functionality on Standard_E2bds_v5 VMs
        key_steps:
            1. Check VM size is Standard_E2bds_v5 via metadata service
            2. Test azure-nvme-id --format command
            3. Test azure-nvme-id --debug command
            4. Test azure-nvme-id command
            5. Check /dev/disk/azure symlinks
        expect_result:
            All azure-nvme-id commands should work properly on Standard_E2bds_v5
        debug_want:
            azure-nvme-id command outputs and disk symlinks
        """
        # Check VM size via Azure metadata service
        cmd = 'curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text"'
        vm_size = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get VM size from Azure metadata service').strip()

        self.log.info(f'Current VM size: {vm_size}')

        if vm_size != 'Standard_E2bds_v5':
            self.skipTest(f'This test is only for Standard_E2bds_v5 VMs. Current VM size is {vm_size}')

        self.log.info('VM size is Standard_E2bds_v5, proceeding with azure-nvme-id tests')

        # Subtest 1: Check azure-nvme-id --format
        with self.subTest('azure-nvme-id --format'):
            # Test azure-nvme-id --format json (should include NVMe device info)
            cmd = 'sudo azure-nvme-id --format json'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test sudo azure-nvme-id --format json command')
            self.log.info(f'sudo azure-nvme-id --format json output: {output}')

            # Check if required strings are present in the JSON output
            if '/dev/nvme0n1' not in output:
                self.fail(f'sudo azure-nvme-id --format json should include "/dev/nvme0n1", but output was: {output}')

            if 'MSFT NVMe Accelerator v1.0' not in output:
                self.fail(f'sudo azure-nvme-id --format json should include "MSFT NVMe Accelerator v1.0", but output was: {output}')

            self.log.info('Found required device path and model in JSON output')

            # Test azure-nvme-id --format plain (should include OS disk info)
            cmd = 'sudo azure-nvme-id --format plain'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test sudo azure-nvme-id --format plain command')
            self.log.info(f'azure-nvme-id --format plain output:\n{output}')

            # Check if required OS disk line is in the output
            expected_line = "/dev/nvme0n1: type=os"
            if expected_line not in output:
                self.fail(f'azure-nvme-id --format plain should include "{expected_line}", but output was:\n{output}')

            self.log.info('Found required OS disk line in plain format output')

            self.log.info('azure-nvme-id --format commands validated successfully')
 
         # Subtest 2: Check azure-nvme-id --debug
         # Subtest 2: Check azure-nvme-id --debug
        with self.subTest('azure-nvme-id --debug'):
            cmd = 'sudo azure-nvme-id --debug'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id --debug command')
            self.log.info(f'azure-nvme-id --debug output:\n{output}')

            # Check for required debug message 1: controllers found
            expected_text1 = "DEBUG: found 1 controllers"
            if expected_text1 not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_text1}", but output was:\n{output}')

            self.log.info('Found expected controller count in debug output')

            # Check for required debug message 2: model name and device info
            expected_model_text = 'DEBUG: read model name="MSFT NVMe Accelerator v1.0"'
            expected_device_text = '/dev/nvme0n1: type=os'
            if expected_model_text not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_model_text}", but output was:\n{output}')

            if expected_device_text not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_device_text}", but output was:\n{output}')
            self.log.info('Found expected model name and device info in debug output')

            self.log.info('azure-nvme-id --debug command validated successfully')
        # Subtest 3: Check azure-nvme-id (should include OS disk info)
        with self.subTest('azure-nvme-id'):
            cmd = 'sudo azure-nvme-id'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id command')
            self.log.info(f'azure-nvme-id output:\n{output}')

            # Check if required OS disk line is in the output
            expected_line = "/dev/nvme0n1: type=os"
            if expected_line not in output:
                self.fail(f'azure-nvme-id should include "{expected_line}", but output was:\n{output}')

            self.log.info('Found required OS disk line in azure-nvme-id output')

            self.log.info('azure-nvme-id command validated successfully')

        # Subtest 4: Check /dev/disk/azure symlinks
        with self.subTest('/dev/disk/azure symlinks'):
            # First perform disk partitioning on NVMe data disks
            disks = ['/dev/nvme0n2', '/dev/nvme0n3', '/dev/nvme0n4', '/dev/nvme0n5']

            for disk in disks:
                self.log.info(f'Partitioning {disk}...')

                # Check if disk exists before partitioning
                cmd = f'sudo test -b {disk}'
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg=f'check if {disk} exists')
                if ret != 0:
                    self.log.info(f'Disk {disk} does not exist, skipping')
                    continue

                # Create GPT partition table
                cmd = f'sudo parted --script {disk} mklabel gpt'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create GPT partition table on {disk}')

                # Create first partition (0% - 50%)
                cmd = f'sudo parted --script {disk} mkpart primary xfs 0% 50%'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create first partition on {disk}')

                # Create second partition (50% - 100%)
                cmd = f'sudo parted --script {disk} mkpart primary xfs 50% 100%'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create second partition on {disk}')

                # Wait for partitions to appear
                cmd = f'sudo partprobe {disk}'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'refresh partition table for {disk}')

                self.log.info(f'Successfully partitioned {disk}')

            # Wait a bit for udev to process the new partitions
            cmd = 'sleep 2'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='wait for udev to process new partitions')

            # Now check the azure disk symlinks
            cmd = 'find /dev/disk/azure -type l | sort'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='list azure disk symlinks')
            self.log.info(f'/dev/disk/azure symlinks:\n{output}')

            # Expected symlinks after partitioning
            expected_symlinks = [
                "/dev/disk/azure/data/by-lun/0",
                "/dev/disk/azure/data/by-lun/0-part1",
                "/dev/disk/azure/data/by-lun/0-part2",
                "/dev/disk/azure/data/by-lun/1",
                "/dev/disk/azure/data/by-lun/1-part1",
                "/dev/disk/azure/data/by-lun/1-part2",
                "/dev/disk/azure/data/by-lun/2",
                "/dev/disk/azure/data/by-lun/2-part1",
                "/dev/disk/azure/data/by-lun/2-part2",
                "/dev/disk/azure/data/by-lun/3",
                "/dev/disk/azure/data/by-lun/3-part1",
                "/dev/disk/azure/data/by-lun/3-part2",
                "/dev/disk/azure/os",
                "/dev/disk/azure/os-part1",
                "/dev/disk/azure/os-part2",
                "/dev/disk/azure/os-part3",
                "/dev/disk/azure/os-part4",
                "/dev/disk/azure/resource",
                "/dev/disk/azure/resource-part1"
            ]

            # Parse actual symlinks
            actual_symlinks = [link.strip() for link in output.strip().split('\n') if link.strip()]

            # Validate that we have the expected symlinks
            self.log.info(f'Found {len(actual_symlinks)} azure disk symlinks')

            # Check for missing expected symlinks
            missing_symlinks = []
            for expected in expected_symlinks:
                if expected not in actual_symlinks:
                    missing_symlinks.append(expected)

            if missing_symlinks:
                self.log.warning(f'Missing expected symlinks: {missing_symlinks}')

            # Check for unexpected symlinks
            unexpected_symlinks = []
            for actual in actual_symlinks:
                if actual not in expected_symlinks:
                    unexpected_symlinks.append(actual)

            if unexpected_symlinks:
                self.log.info(f'Additional symlinks found: {unexpected_symlinks}')

            # Basic validation: should have at least some core symlinks
            core_symlinks = [link for link in actual_symlinks if '/dev/disk/azure/' in link]
            if not core_symlinks:
                self.fail('No azure disk symlinks found in /dev/disk/azure')

            self.log.info('Azure disk symlinks validation completed')

    def test_azure_vm_utils_standard_l8s_v3(self):
        """
        case_tag:
            azure_vm_utils,azure_vm_utils_tier2
        case_name:
            test_azure_vm_utils_standard_l8s_v3
        component:
            azure-vm-utils
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            xxiong@redhat.com
        description:
            Test azure-vm-utils functionality on Standard_L8s_v3 VMs
        key_steps:
            1. Check VM size is Standard_L8s_v3 via metadata service
            2. Test azure-nvme-id --format command
            3. Test azure-nvme-id --debug command
            4. Test azure-nvme-id command
            5. Check /dev/disk/azure symlinks
        expect_result:
            All azure-nvme-id commands should work properly on Standard_L8s_v3--Microsoft NVMe Direct Disk
        debug_want:
            azure-nvme-id command outputs and disk symlinks
        """
        # Check VM size via Azure metadata service
        cmd = 'curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text"'
        vm_size = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get VM size from Azure metadata service').strip()

        self.log.info(f'Current VM size: {vm_size}')

        if vm_size != 'Standard_L8s_v3':
            self.skipTest(f'This test is only for Standard_L8s_v3 VMs. Current VM size is {vm_size}')

        self.log.info('VM size is Standard_L8s_v3, proceeding with azure-nvme-id tests')

        # Subtest 1: Check azure-nvme-id --format
        with self.subTest('azure-nvme-id --format'):
            # Test azure-nvme-id --format json (should include NVMe device info)
            cmd = 'sudo azure-nvme-id --format json'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test sudo azure-nvme-id --format json command')
            self.log.info(f'sudo azure-nvme-id --format json output: {output}')

            # Check if required strings are present in the JSON output
            if '/dev/nvme0n1' not in output:
                self.fail(f'sudo azure-nvme-id --format json should include "/dev/nvme0n1", but output was: {output}')

            if 'Microsoft NVMe Direct Disk' not in output:
                self.fail(f'sudo azure-nvme-id --format json should include "MSFT NVMe Accelerator v1.0", but output was: {output}')

            self.log.info('Found required device path and model in JSON output')

            # Test azure-nvme-id --format plain (should include OS disk info)
            cmd = 'sudo azure-nvme-id --format plain'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test sudo azure-nvme-id --format plain command')
            self.log.info(f'azure-nvme-id --format plain output:\n{output}')

            # Check if required OS disk line is in the output
            expected_line = "/dev/nvme0n1: type=local"
            if expected_line not in output:
                self.fail(f'azure-nvme-id --format plain should include "{expected_line}", but output was:\n{output}')

            self.log.info('Found required OS disk line in plain format output')

            self.log.info('azure-nvme-id --format commands validated successfully')

        # Subtest 2: Check azure-nvme-id --debug
        with self.subTest('azure-nvme-id --debug'):
            cmd = 'sudo azure-nvme-id --debug'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id --debug command')
            self.log.info(f'azure-nvme-id --debug output:\n{output}')

            # Check for required debug message 1: controllers found
            expected_text1 = "DEBUG: found 1 controllers"
            if expected_text1 not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_text1}", but output was:\n{output}')

            self.log.info('Found expected controller count in debug output')

            # Check for required debug message 2: model name and device info
            expected_model_text = 'DEBUG: read model name="Microsoft NVMe Direct Disk"'
            expected_device_text = '/dev/nvme0n1: type=local'

            if expected_model_text not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_model_text}", but output was:\n{output}')

            if expected_device_text not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_device_text}", but output was:\n{output}')

            self.log.info('Found expected model name and device info in debug output')

            self.log.info('azure-nvme-id --debug command validated successfully')

        # Subtest 3: Check azure-nvme-id (should include OS disk info)
        with self.subTest('azure-nvme-id'):
            cmd = 'sudo azure-nvme-id'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id command')
            self.log.info(f'azure-nvme-id output:\n{output}')

            # Check if required OS disk line is in the output
            expected_line = "/dev/nvme0n1: type=local"
            if expected_line not in output:
                self.fail(f'azure-nvme-id should include "{expected_line}", but output was:\n{output}')

            self.log.info('Found required OS disk line in azure-nvme-id output')

            self.log.info('azure-nvme-id command validated successfully')

        # Subtest 4: Check /dev/disk/azure symlinks
        with self.subTest('/dev/disk/azure symlinks'):
            # First perform disk partitioning on NVMe data disks
            disks = ['/dev/sda', '/dev/sdb', '/dev/sdc', '/dev/sdd']

            for disk in disks:
                self.log.info(f'Partitioning {disk}...')

                # Check if disk exists before partitioning
                cmd = f'sudo test -b {disk}'
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg=f'check if {disk} exists')
                if ret != 0:
                    self.log.info(f'Disk {disk} does not exist, skipping')
                    continue

                # Create GPT partition table
                cmd = f'sudo parted --script {disk} mklabel gpt'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create GPT partition table on {disk}')

                # Create first partition (0% - 50%)
                cmd = f'sudo parted --script {disk} mkpart primary xfs 0% 50%'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create first partition on {disk}')

                # Create second partition (50% - 100%)
                cmd = f'sudo parted --script {disk} mkpart primary xfs 50% 100%'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create second partition on {disk}')

                # Wait for partitions to appear
                cmd = f'sudo partprobe {disk}'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'refresh partition table for {disk}')

                self.log.info(f'Successfully partitioned {disk}')

            # Wait a bit for udev to process the new partitions
            cmd = 'sleep 2'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='wait for udev to process new partitions')

            # Now check the azure disk symlinks
            cmd = 'find /dev/disk/azure -type l | sort'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='list azure disk symlinks')
            self.log.info(f'/dev/disk/azure symlinks:\n{output}')

            # Expected symlinks after partitioning
            expected_symlinks = [
                "/dev/disk/azure/data/by-lun/0",
                "/dev/disk/azure/data/by-lun/0-part1",
                "/dev/disk/azure/data/by-lun/0-part2",
                "/dev/disk/azure/data/by-lun/1",
                "/dev/disk/azure/data/by-lun/1-part1",
                "/dev/disk/azure/data/by-lun/1-part2",
                "/dev/disk/azure/data/by-lun/2",
                "/dev/disk/azure/data/by-lun/2-part1",
                "/dev/disk/azure/data/by-lun/2-part2",
                "/dev/disk/azure/data/by-lun/3",
                "/dev/disk/azure/data/by-lun/3-part1",
                "/dev/disk/azure/data/by-lun/3-part2",
                "/dev/disk/azure/local/by-serial/*",
                "/dev/disk/azure/os",
                "/dev/disk/azure/os-part1",
                "/dev/disk/azure/os-part2",
                "/dev/disk/azure/os-part3",
                "/dev/disk/azure/os-part4",
                "/dev/disk/azure/resource",
                "/dev/disk/azure/resource-part1",
                "/dev/disk/azure/root",
                "/dev/disk/azure/root-part1",
                "/dev/disk/azure/root-part2",
                "/dev/disk/azure/root-part3",
                "/dev/disk/azure/root-part4",
                "/dev/disk/azure/scsi1/lun0",
                "/dev/disk/azure/scsi1/lun0-part1",
                "/dev/disk/azure/scsi1/lun0-part2",
                "/dev/disk/azure/scsi1/lun1",
                "/dev/disk/azure/scsi1/lun1-part1",
                "/dev/disk/azure/scsi1/lun1-part2",
                "/dev/disk/azure/scsi1/lun2",
                "/dev/disk/azure/scsi1/lun2-part1"
            ]

            # Parse actual symlinks
            actual_symlinks = [link.strip() for link in output.strip().split('\n') if link.strip()]

            # Validate that we have the expected symlinks
            self.log.info(f'Found {len(actual_symlinks)} azure disk symlinks')

            # Check for missing expected symlinks
            missing_symlinks = []
            for expected in expected_symlinks:
                if expected not in actual_symlinks:
                    missing_symlinks.append(expected)

            if missing_symlinks:
                self.log.warning(f'Missing expected symlinks: {missing_symlinks}')

            # Check for unexpected symlinks
            unexpected_symlinks = []
            for actual in actual_symlinks:
                if actual not in expected_symlinks:
                    unexpected_symlinks.append(actual)

            if unexpected_symlinks:
                self.log.info(f'Additional symlinks found: {unexpected_symlinks}')

            # Basic validation: should have at least some core symlinks
            core_symlinks = [link for link in actual_symlinks if '/dev/disk/azure/' in link]
            if not core_symlinks:
                self.fail('No azure disk symlinks found in /dev/disk/azure')

            # Validate critical symlinks exist
            critical_patterns = [
                '/dev/disk/azure/data/by-lun/',
                '/dev/disk/azure/scsi1/lun',
                '/dev/disk/azure/os',
                '/dev/disk/azure/root',
                '/dev/disk/azure/resource'
            ]

            for pattern in critical_patterns:
                matching_links = [link for link in actual_symlinks if pattern in link]
                if not matching_links:
                    self.log.warning(f'No symlinks found matching pattern: {pattern}')

            self.log.info('Azure disk symlinks validation completed')

    def test_azure_vm_utils_standard_d16alds_v6(self):
        """
        case_tag:
            azure_vm_utils,azure_vm_utils_tier2
        case_name:
            test_azure_vm_utils_standard_d16alds_v6
        component:
            azure-vm-utils
        bugzilla_id:
            N/A
        is_customer_case:
            False
        maintainer:
            xxiong@redhat.com
        description:
            Test azure-vm-utils functionality on Standard_D16alds_v6 VMs
        key_steps:
            1. Check VM size is Standard_D16alds_v6 via metadata service
            2. Test azure-nvme-id --format command
            3. Test azure-nvme-id --debug command
            4. Test azure-nvme-id command
            5. Check /dev/disk/azure symlinks
        expect_result:
            All azure-nvme-id commands should work properly on Standard_D16alds_v6--MSFT NVMe Accelerator v1.0/Microsoft NVMe Direct Disk v2
        debug_want:
            azure-nvme-id command outputs and disk symlinks
        """
        # Check VM size via Azure metadata service
        cmd = 'curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text"'
        vm_size = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get VM size from Azure metadata service').strip()

        self.log.info(f'Current VM size: {vm_size}')

        if vm_size != 'Standard_D16alds_v6':
            self.skipTest(f'This test is only for Standard_D16alds_v6 VMs. Current VM size is {vm_size}')

        self.log.info('VM size is Standard_D16alds_v6, proceeding with azure-nvme-id tests')

        # Subtest 1: Check azure-nvme-id --format
        with self.subTest('azure-nvme-id --format'):
            # Test azure-nvme-id --format json (should include NVMe device info)
            cmd = 'sudo azure-nvme-id --format json'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test sudo azure-nvme-id --format json command')
            self.log.info(f'sudo azure-nvme-id --format json output: {output}')

            # Check if required strings are present in the JSON output
            if '/dev/nvme0n1' not in output:
                self.fail(f'sudo azure-nvme-id --format json should include "/dev/nvme0n1", but output was: {output}')

            if 'MSFT NVMe Accelerator v1.0' not in output:
                self.fail(f'sudo azure-nvme-id --format json should include "MSFT NVMe Accelerator v1.0", but output was: {output}')

            if 'Microsoft NVMe Direct Disk v2' not in output:
                self.fail(f'sudo azure-nvme-id --format json should include "Microsoft NVMe Direct Disk v2", but output was: {output}')

            self.log.info('Found required device path and model in JSON output')

            # Test azure-nvme-id --format plain (should include OS disk info)
            cmd = 'sudo azure-nvme-id --format plain'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test sudo azure-nvme-id --format plain command')
            self.log.info(f'azure-nvme-id --format plain output:\n{output}')

            # Check if required OS disk line is in the output
            expected_line = "/dev/nvme0n1: type=os"
            if expected_line not in output:
                self.fail(f'azure-nvme-id --format plain should include "{expected_line}", but output was:\n{output}')

            self.log.info('Found required OS disk line in plain format output')

            self.log.info('azure-nvme-id --format commands validated successfully')

        # Subtest 2: Check azure-nvme-id --debug
        with self.subTest('azure-nvme-id --debug'):
            cmd = 'sudo azure-nvme-id --debug'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id --debug command')
            self.log.info(f'azure-nvme-id --debug output:\n{output}')

            # Check for required debug message 1: controllers found
            expected_text1 = "DEBUG: found 3 controllers"
            if expected_text1 not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_text1}", but output was:\n{output}')

            self.log.info('Found expected controller count in debug output')

            # Check for required debug message 2: model name and device info
            expected_model_text = 'DEBUG: read model name="MSFT NVMe Accelerator v1.0"'
            expected_device_text = '/dev/nvme0n1: type=os'

            if expected_model_text not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_model_text}", but output was:\n{output}')

            if expected_device_text not in output:
                self.fail(f'azure-nvme-id --debug should include "{expected_device_text}", but output was:\n{output}')

            self.log.info('Found expected model name and device info in debug output')

            self.log.info('azure-nvme-id --debug command validated successfully')

        # Subtest 3: Check azure-nvme-id (should include OS disk info)
        with self.subTest('azure-nvme-id'):
            cmd = 'sudo azure-nvme-id'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='test azure-nvme-id command')
            self.log.info(f'azure-nvme-id output:\n{output}')

            # Check if required OS disk line is in the output
            expected_line = "/dev/nvme0n1: type=os"
            if expected_line not in output:
                self.fail(f'azure-nvme-id should include "{expected_line}", but output was:\n{output}')

            self.log.info('Found required OS disk line in azure-nvme-id output')

            self.log.info('azure-nvme-id command validated successfully')

        # Subtest 4: Check /dev/disk/azure symlinks
        with self.subTest('/dev/disk/azure symlinks'):
            # First perform disk partitioning on NVMe data disks
            disks = ['/dev/nvme0n2', '/dev/nvme0n3', '/dev/nvme0n4', '/dev/nvme0n5', '/dev/nvme1n1', '/dev/nvme2n1']

            for disk in disks:
                self.log.info(f'Partitioning {disk}...')

                # Check if disk exists before partitioning
                cmd = f'sudo test -b {disk}'
                ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg=f'check if {disk} exists')
                if ret != 0:
                    self.log.info(f'Disk {disk} does not exist, skipping')
                    continue

                # Create GPT partition table
                cmd = f'sudo parted --script {disk} mklabel gpt'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create GPT partition table on {disk}')

                # Create first partition (0% - 50%)
                cmd = f'sudo parted --script {disk} mkpart primary xfs 0% 50%'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create first partition on {disk}')

                # Create second partition (50% - 100%)
                cmd = f'sudo parted --script {disk} mkpart primary xfs 50% 100%'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'create second partition on {disk}')

                # Wait for partitions to appear
                cmd = f'sudo partprobe {disk}'
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg=f'refresh partition table for {disk}')

                self.log.info(f'Successfully partitioned {disk}')

            # Wait a bit for udev to process the new partitions
            cmd = 'sleep 2'
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='wait for udev to process new partitions')

            # Now check the azure disk symlinks
            cmd = 'find /dev/disk/azure -type l | sort'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='list azure disk symlinks')
            self.log.info(f'/dev/disk/azure symlinks:\n{output}')

            # Expected symlinks after partitioning
            expected_symlinks = [
                "/dev/disk/azure/data/by-lun/0",
                "/dev/disk/azure/data/by-lun/0-part1",
                "/dev/disk/azure/data/by-lun/0-part2",
                "/dev/disk/azure/data/by-lun/1",
                "/dev/disk/azure/data/by-lun/1-part1",
                "/dev/disk/azure/data/by-lun/1-part2",
                "/dev/disk/azure/data/by-lun/2",
                "/dev/disk/azure/data/by-lun/2-part1",
                "/dev/disk/azure/data/by-lun/2-part2",
                "/dev/disk/azure/data/by-lun/3",
                "/dev/disk/azure/data/by-lun/3-part1",
                "/dev/disk/azure/data/by-lun/3-part2",
                "/dev/disk/azure/local/by-index/1",
                "/dev/disk/azure/local/by-index/1-part1",
                "/dev/disk/azure/local/by-index/1-part2",
                "/dev/disk/azure/local/by-index/2",
                "/dev/disk/azure/local/by-index/2-part1",
                "/dev/disk/azure/local/by-index/2-part2",
                "/dev/disk/azure/local/by-name/nvme-440G-1",
                "/dev/disk/azure/local/by-name/nvme-440G-1-part1",
                "/dev/disk/azure/local/by-name/nvme-440G-1-part2",
                "/dev/disk/azure/local/by-name/nvme-440G-2",
                "/dev/disk/azure/local/by-name/nvme-440G-2-part1",
                "/dev/disk/azure/local/by-name/nvme-440G-2-part2",
                "/dev/disk/azure/local/by-serial/*"
            ]

            # Parse actual symlinks
            actual_symlinks = [link.strip() for link in output.strip().split('\n') if link.strip()]

            # Validate that we have the expected symlinks
            self.log.info(f'Found {len(actual_symlinks)} azure disk symlinks')

            # Check for missing expected symlinks (excluding wildcard patterns)
            missing_symlinks = []
            for expected in expected_symlinks:
                if '*' in expected:
                    # For wildcard patterns, check if any actual symlink matches the pattern
                    pattern_prefix = expected.replace('*', '')
                    matching = [link for link in actual_symlinks if link.startswith(pattern_prefix)]
                    if not matching:
                        missing_symlinks.append(expected)
                else:
                    if expected not in actual_symlinks:
                        missing_symlinks.append(expected)

            if missing_symlinks:
                self.log.warning(f'Missing expected symlinks: {missing_symlinks}')

            # Check for unexpected symlinks (excluding local NVMe serial patterns)
            unexpected_symlinks = []
            for actual in actual_symlinks:
                # Skip local NVMe serial symlinks as they vary by hardware
                if '/dev/disk/azure/local/by-serial/' in actual:
                    continue
                if actual not in expected_symlinks:
                    unexpected_symlinks.append(actual)

            if unexpected_symlinks:
                self.log.info(f'Additional symlinks found: {unexpected_symlinks}')

            # Basic validation: should have at least some core symlinks
            core_symlinks = [link for link in actual_symlinks if '/dev/disk/azure/' in link]
            if not core_symlinks:
                self.fail('No azure disk symlinks found in /dev/disk/azure')

            # Validate critical symlinks exist
            critical_patterns = [
                '/dev/disk/azure/data',
                '/dev/disk/azure/local',
                '/dev/disk/azure/os'
            ]

            for pattern in critical_patterns:
                matching_links = [link for link in actual_symlinks if pattern in link]
                if not matching_links:
                    self.log.warning(f'No symlinks found matching pattern: {pattern}')

            self.log.info('Azure disk symlinks validation completed')
    
    def tearDown(self):
        utils_lib.finish_case(self)


if __name__ == '__main__':
    unittest.main()
