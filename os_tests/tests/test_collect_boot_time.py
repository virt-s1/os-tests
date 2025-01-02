import unittest
import time
import os
import csv
from os_tests.libs import utils_lib
from os_tests.libs.resources import UnSupportedAction

class TestCollectBootTime(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='sudo dmesg -T')
        utils_lib.collect_basic_info(self)

    def test_collect_boot_time(self):
        """
        case_name:
            test_boot_reboot_stop_start_time
        case_tags:
            kernel
        case_status:
            approved
        title:
            collect and update the boot,reboot,stop-start time
        importance:
            low
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            jira_VIRTCLOUD-889
        automation_field:
            https://github.com/virt-s1/os-tests/blob/master/os_tests/tests/test_lifecycle.py
        setup_teardown:
            firewall or security group allow ping
        environment:
            N/A
        component:
            component
        bug_id:
            jira_VIRTCLOUD-889
        is_customer_case:
            True
        testplan:
            N/A
        test_type:
            functional
        test_level:
            component
        maintainer:
            libhe@redhat.com
        description: |
            collect and update the boot,reoot,stop,start,stop-start time to a csv file.
        key_steps: |
            - record the time of instance is pingable
            - record the time of rebooting instance reboot
            - record the time of stoping instance
            - record the time of starting instance 
        expected_result: |
            should be less than max_boot_time set in configuration. We can update the threshold after we have more data of this case.
        debug_want: |
            console output
        """
        if not self.vm:
            self.skipTest('No VM provider found')

        # Ensure VM is stopped if it exists
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)

        # Create VM
        self.vm.create()
        new_ip = self.vm.floating_ip
        ping_cmd = f"ping -c 1 {new_ip} -W 2"

        # Measure time to become pingable
        self.log.info("Measuring time for VM to become pingable...")
        time_start = int(time.time())
        while True:
            ret, _ = utils_lib.run_cmd_local(ping_cmd, is_log_ret=True)
            time_end = int(time.time())
            time_to_ping = time_end - time_start
            if int(ret) == 0:
                break
            if time_to_ping > self.ssh_timeout:
                try:
                    self.vm.get_console_log()
                except NotImplementedError:
                    self.log.info(f"{self.vm.provider} does not implement get_console_log")
                self.log.info("Ensure your network settings allow ping before reporting bugs")
                self.fail(f"System is not pingable after {self.ssh_timeout}s")
            time.sleep(1)
        self.log.info(f"Time to become pingable: {time_to_ping}s")

        # Initialize SSH and collect boot time
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        first_launch_time = utils_lib.getboottime(self)

         # Measure reboot time
        self.vm.reboot(wait=True)
        reboot_start = int(time.time())
        new_ip = self.vm.floating_ip
        while True:
            ret, _ = utils_lib.run_cmd_local(ping_cmd, is_log_ret=True)
            reboot_end = int(time.time())
            reboot_time = reboot_end - reboot_start
            if int(ret) == 0:
                break
        self.log.info(f"Time for VM reboot: {reboot_time}s")

        time.sleep(60)

        # Measure VM stop time
        self.log.info("Stopping the VM...")
        stop_start_time = int(time.time())
        self.vm.stop(wait=True)
        for _ in utils_lib.iterate_timeout(120, "Timed out waiting for VM to stop."):
            if self.vm.is_stopped():
                break
            time.sleep(30)
        stop_end_time = int(time.time())
        stop_time = stop_end_time - stop_start_time
        self.log.info(f"Time to stop VM: {stop_time}s")

        # Measure VM start time
        self.log.info("Starting the VM...")
        start_start_time = int(time.time())
        self.vm.start(wait=True)
        new_ip = self.vm.floating_ip  
        ping_cmd = f"ping -c 1 {new_ip} -W 2"
        while True:
            ret, _ = utils_lib.run_cmd_local(ping_cmd, is_log_ret=True)
            start_end_time = int(time.time())
            start_time = start_end_time - start_start_time
            if int(ret) == 0:
                break
        self.log.info(f"Time for VM start: {start_time}s")

        # Initialize SSH and collect VM information
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
    
        release = str(utils_lib.run_cmd(self, "cat /etc/system-release"))
        kernelVersion = str(utils_lib.run_cmd(self, "uname -r"))
        arch = str(utils_lib.run_cmd(self, "uname -m"))

        # Log the values
        self.log.info(f"Release: {release}")
        self.log.info(f"Kernel Version: {kernelVersion}")
        self.log.info(f"Architecture: {arch}")

        vm_info = {
            "Release": release,
            "ImageID": self.vm.ami_id,
            "KernelVersion": kernelVersion,
            "Region": self.vm.region,
            "Arch": arch,
            "InstanceType": self.vm.instance_type,
            "FirstLaunchTime(s)": first_launch_time,
            "RebootTime(s)": reboot_time,
            "StopTime(s)": stop_time,
            "StartTime(s)": start_time,
            "Stop-StartTime(s)": stop_time + start_time
        }

        # Save information to a CSV file
        csv_file = "vm_boot_reboot_stop_start_time.csv"
        write_header = not os.path.exists(csv_file)
        with open(csv_file, mode="a", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=vm_info.keys())
            if write_header:
                writer.writeheader()
            writer.writerow(vm_info)
        self.log.info(f"VM lifecycle information saved to {csv_file}")

        # Try to fetch console log
        try:
            self.vm.get_console_log()
        except NotImplementedError:
            self.log.info(f"{self.vm.provider} does not implement get_console_log")

    def tearDown(self):
        utils_lib.finish_case(self)
        pass

if __name__ == '__main__':
    unittest.main()
