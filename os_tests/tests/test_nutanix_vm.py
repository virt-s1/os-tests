import unittest
import re
import time
from os_tests.libs import utils_lib

class TestNutanixVM(unittest.TestCase):
    '''
    1. Only run in Mode 3
    2. Dedicate for Nutanix VM test
    '''
    def setUp(self):
        if not self.vm:
            self.skipTest("Skip as no VM inited")
        if not self.vm.provider == 'nutanix':
            self.skipTest("Skip as not Nutanix AHV platform")
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='dmesg -T')

    def _verify_live_migration(self, host_list):
        if len(host_list) < 2:
            self.skipTest("Skip run as only 1 host in Nutanix AHV cluster")
        if not self.vm.allow_live_migrate():
            self.skipTest("Skip run as VM does not allowed to live migrate")

    def _live_migration(self, host_list):
        source_host = self.vm.vm_host_uuid()
        self.log.info("VM is running on Host: %s, start to live migrate" % source_host)
        host_list.remove(source_host)
        for destination_host in host_list:
            self.vm.migrate(host_uuid=destination_host, wait=True)
            self.log.info("VM has migrated to Host: %s" % destination_host)
            time.sleep(60)
            self.assertEqual(self.vm.vm_host_uuid(), destination_host,
                            "Test failed as VM host hasn't changed after migration")
            if self.vm.is_stopped():
                self.fail("Failed as VM has stopped after live migration")

        utils_lib.run_cmd(self, "uptime", expect_ret=0,
                        msg="Verify RHEL guest is still alive")
        self.log.info("Live migration has completed")
    
    def _fio_test(self, test_log):
        '''
        Initial fio test and put into background for processing.
        '''
        self.log.info("Initial fio test and put into background for processing")
        cmd = "[[ -d /tmp/fio_test ]] || mkdir /tmp/fio_test"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Create test dir")
        utils_lib.is_cmd_exist(self, cmd='fio')
        cmd = "setsid fio --group_reporting=1 --name=nutanix-fio-test \
--numjobs=4 --iodepth=4 --size=500m --bs=4k --rw=randrw -rwmixread=70 \
--ioengine=psync --time_based=1 --runtime=300 \
--directory=/tmp/fio_test --filename=test01:test02:test03:test04:test05 > %s" % test_log
        utils_lib.run_cmd(self, cmd, msg="Start fio test", timeout=2)

        cmd = "ps -ef | grep -v grep | grep fio-test"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="nutanix",
                                     msg="Check if all fio test jobs have started")

    def _verify_fio_test(self, test_log):
        '''
        Check if fio test is still alive.
        '''
        self.log.info("Verify fio test")
        utils_lib.run_cmd(self, "cat %s" % test_log, expect_ret=0, expect_kw="nutanix",
                                     msg="Check fio test log")        
        cmd = "ps -ef | grep -v grep | grep fio-test"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="nutanix",
                                     msg="Check if all fio test jobs are still alive")
        
        cmd = "ps -ef | grep -v grep | grep fio-test | wc -l"
        for count in utils_lib.iterate_timeout(
                240, "Timed out waiting for complete fio test", wait=5):
            fio_jobs = int(utils_lib.run_cmd(self, cmd, expect_ret=0,
                                        msg="Check if all fio test jobs are still alive").strip())
            if fio_jobs == 0:
                break

        cmd = "cat %s" % test_log
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Check fio test log")

    def _ping_test(self, test_ip, test_log):
        '''
        Initial ping test and put into background for processing.
        '''
        self.log.info("Initial ping test and put into background for processing")
        test_log = "/tmp/live_migrate_ping_test.log"
        cmd = "setsid ping %s > %s" % (test_ip, test_log)
        utils_lib.run_cmd(self, cmd, msg="Start ping test", timeout=2)

    def _verify_ping_test(self, test_ip, test_log):
        '''
        Check if ping test is still alive, and verify package loss rate of ping test.
        '''
        self.log.info("Verify ping test")
        cmd = "ps -ef | grep -v grep | grep 'ping %s'" % test_ip
        utils_lib.run_cmd(self, cmd, expect_ret=0,
                          msg="Check if ping test is still alive")
        cmd = "ps -ef | grep -v grep | grep 'ping %s' | awk '{print $2}' | xargs kill -s SIGINT" % test_ip
        utils_lib.run_cmd(self, cmd, expect_ret=0,
                          msg="Send sigint to ping test")
        time.sleep(10)
        cmd = "cat %s" % test_log
        utils_lib.run_cmd(self, cmd, expect_ret=0,
                          msg="Check ping test log")

        cmd = "grep 'packets transmitted' %s" % test_log
        res = utils_lib.run_cmd(self, cmd, expect_ret=0,
                                msg="Check packet loss rate of ping test")
        pkgs_trans = int(re.findall(r'(\d+).packets.transmitted', res)[0])
        pkgs_rec = int(re.findall(r'(\d+).received', res)[0])
        
        cmd = "grep 'min/avg/max' %s" % test_log
        res = utils_lib.run_cmd(self, cmd, expect_ret=0,
                                    msg="Check average round-trip time of ping test").strip()
        rrt_avg = re.findall(r'(\d*\W?\d+)/', res)[1]

        self.assertLessEqual(pkgs_trans - pkgs_rec, 2,
                             "ping test failed. Packges received/transmitted: %s/%s, average round-trip time: %sms" %
                             (pkgs_rec, pkgs_trans, rrt_avg))

    def _verify_cpu_cores(self):
        '''
        Verify total CPU cores between Nutanix AHV and RHEL guest.
        '''
        self.log.info("Verify total CPU cores between Nutanix AHV and RHEL guest")
        cores_in_ahv = self.vm.get_core_total()
        cmd = "grep processor /proc/cpuinfo | wc -l"
        cores_in_guest = int(utils_lib.run_cmd(self, cmd, expect_ret=0,
                                           msg = "Check CPU cores number on RHEL guest"))
        
        self.assertEqual(cores_in_guest, cores_in_ahv,
                         "Test failed, CPU core number on RHEL guest: %s does not match with Nutanix AHV: %s" %
                         (cores_in_guest, cores_in_ahv))

    def _verify_memory_size(self, expect_ratio=None):
        '''
        Verify memory capacity (GB) between Nutanix AHV and RHEL guest.
        '''
        self.log.info("Verify memory capacity (GB) between Nutanix AHV and RHEL guest")
        mem_in_ahv = float(self.vm.get_memory_size())
        if not expect_ratio:
            if mem_in_ahv <= 1:
                expect_ratio = 0.75
            elif mem_in_ahv in range(2, 4):
                expect_ratio = 0.8
            elif mem_in_ahv in range(4, 8):
                expect_ratio = 0.88
            elif mem_in_ahv >= 8:
                expect_ratio = 0.92
        mem_in_guest = float(round(utils_lib.get_memsize(self), 2))
        
        self.assertLess(mem_in_guest, mem_in_ahv,
                        "Test failed, memory capacity on RHEL guest: %s is more than on Nutanix AHV: %s" %
                        (mem_in_guest, mem_in_ahv))
        
        self.assertGreater(mem_in_guest / mem_in_ahv, float(expect_ratio),
                           "Test failed, memory capacity on RHEL guest: %s does not match with Nutanix AHV: %s" %
                           (mem_in_guest, mem_in_ahv))

    def _verify_memory_vnuma(self):
        '''
        Verify memory vnuma nodes number between Nutanix AHV and RHEL guest.
        '''
        self.log.info("Verify memory vnuma nodes number between Nutanix AHV and RHEL guest")
        vnuma_in_ahv = self.vm.get_memory_vnuma()
        if vnuma_in_ahv == 0:
            vnuma_in_ahv += 1
        utils_lib.is_cmd_exist(self, cmd='numactl')
        cmd = "numactl --hardware | grep available:"
        res = utils_lib.run_cmd(self, cmd, expect_ret=0,
                                msg="Check numa nodes number on RHEL guest")
        numa_in_guest = int(re.findall(r'available: (\d)', res)[0])

        self.assertEqual(numa_in_guest, vnuma_in_ahv,
                         "Test failed, memory vnuma nodes number on RHEL guest: %s does not match with Nutanix AHV: %s" %
                         (numa_in_guest, vnuma_in_ahv))

    def _recover_memory(self, mem_gb_current):
        self.log.info("Recover VM memory")
        self.vm.update_memory_size(mem_gb_current)
        self.assertEqual(self.vm.get_memory_size(), mem_gb_current,
                         "Test failed as recover VM memory failed")
        utils_lib.init_connection(self)
        self._verify_memory_size()

    def _reboot_os_cycles(self, reboot_cycles, time_wait=10):
        for cycle in range(1, reboot_cycles+1):
            self.log.info("Reboot cycle: %d" % cycle)
            res_before = utils_lib.run_cmd(self, "last reboot", expect_ret=0,
                                           msg="Check reboot log before reboot")
            utils_lib.run_cmd(self, "sudo reboot", 
                        msg="Reboot OS")
            time.sleep(time_wait)
            utils_lib.init_connection(self)
            res_after = utils_lib.run_cmd(self, "last reboot", expect_ret=0,
                                          msg="Check reboot log after reboot")
            
            self.assertNotEqual(res_after, res_before,
                                "Test failed as VM is still alive after reboot")

    def test_live_migration(self):
        '''
        case_tag:
            Live Migration
        case_name:
            test_live_migration
        case_file:
            os_tests.tests.test_nutanix_vm.test_live_migration
        component:
            Live Migration
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Migrate a powered on VM
        key_steps: |
            1. Migrate a powered on VM
            2. Check VM status after migration
        expect_result:
            VM running normally during/after live migration
        debug_want:
            N/A
        '''
        host_list = self.vm.host_uuid
        self._verify_live_migration(host_list)
        self._live_migration(host_list)

    def test_live_migration_io(self):
        '''
        case_tag:
            Live Migration
        case_name:
            test_live_migration_io
        case_file:
            os_tests.tests.test_nutanix_vm.test_live_migration_io
        component:
            Live Migration
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Migrate a powered on VM with disk IO process
        key_steps: |
            1. Migrate a powered on VM
            2. While migration in progress, verify disk IO on VM
            3. Check VM status and disk IO process after migration
        expect_result:
            VM and disk IO process running normally during/after live migration
        debug_want:
            N/A
        '''
        test_log = "/tmp/live_migrate_fio_test.log"
        host_list = self.vm.host_uuid

        self._verify_live_migration(host_list)
        self._fio_test(test_log)
        self._live_migration(host_list)
        self._verify_fio_test(test_log)

    def test_live_migration_network(self):
        '''
        case_tag:
            Live Migration
        case_name:
            test_live_migration_network
        case_file:
            os_tests.tests.test_nutanix_vm.test_live_migration_network
        component:
            Live Migration
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Migrate a powered on VM with network IO process
        key_steps: |
            1. Migrate a powered on VM
            2. While migration in progress, verify network IO on VM
            3. Check VM status and network IO quality after migration
        expect_result:
            VM running normally and network IO quality should be stable during/after live migration
        debug_want:
            N/A
        '''
        host_list = self.vm.host_uuid
        cvmIP = self.vm.params['Cloud']['cvm_ip']
        test_log = "/tmp/live_migrate_ping_test.log"

        self._verify_live_migration(host_list)
        self._ping_test(cvmIP, test_log)
        self._live_migration(host_list)
        self._verify_ping_test(cvmIP, test_log)

    def test_check_cpu_model(self):
        '''
        case_tag:
            CPU
        case_name:
            test_check_cpu_model
        case_file:
            os_tests.tests.test_nutanix_vm.test_check_cpu_model
        component:
            CPU
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Verify CPU model is consistent between Nutanix AHV and RHEL guest OS
        key_steps: |
            1. Check CPU model on Nutanix AHV host
            2. Check CPU model on RHEL guest OS
        expect_result:
            CPU model is consistent between Nutanix AHV and RHEL guest OS
        debug_want:
            N/A
        '''
        self.log.info("Check CPU model on RHEL guest is match with Nutanix AHV")
        model_in_ahv = self.vm.host_cpu_model()
        cmd = "grep -i 'model name' /proc/cpuinfo | uniq | cut -f2 -d:"
        model_in_guest = utils_lib.run_cmd(self, cmd, expect_ret=0,
                                           msg = "Check CPU model on RHEL guest").strip()
        
        self.assertEqual(model_in_guest, model_in_ahv,
                         "Test failed, CPU model on RHEL guest: %s does not match with Nutanix AHV: %s" %
                         (model_in_guest, model_in_ahv))

    def test_check_cpu_num(self):
        '''
        case_tag:
            CPU
        case_name:
            test_check_cpu_num
        case_file:
            os_tests.tests.test_nutanix_vm.test_check_cpu_num
        component:
            CPU
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Verify CPU numbers is consistent between Nutanix AHV and RHEL guest OS
        key_steps: |
            1. Check CPU numbers on Nutanix AHV
            2. Check CPU numbers on RHEL guest OS
        expect_result:
            CPU numbers is consistent between Nutanix AHV and RHEL guest OS
        debug_want:
            N/A
        '''
        self._verify_cpu_cores()

    def test_check_memory_size(self):
        '''
        case_tag:
            Memory
        case_name:
            test_check_memory_size
        case_file:
            os_tests.tests.test_nutanix_vm.test_check_memory_size
        component:
            Memory
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Verify memory size is consistent between Nutanix AHV and RHEL guest OS
        key_steps: |
            1. Check memory size on Nutanix AHV
            2. Check memory size on RHEL guest OS
        expect_result:
            Memory size is consistent between Nutanix AHV and RHEL guest OS
        debug_want:
            N/A
        '''
        self._verify_memory_size()

    def test_hot_add_vcpu(self):
        '''
        case_tag:
            CPU
        case_name:
            test_hot_add_vcpu
        case_file:
            os_tests.tests.test_nutanix_vm.test_hot_add_vcpu
        component:
            CPU
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Add vCPU to a powered on VM
        key_steps: |
            1. Add vCPU to a powered on VM
            2. Verify CPU numbers on RHEL guest OS
        expect_result:
            CPU numbers is consistent between Nutanix AHV and RHEL guest OS
        debug_want:
            N/A
        '''
        vcpu_num_current = self.vm.get_vcpu_num()
        vcpu_num_target = vcpu_num_current * 2
        self.log.info("Hot add VM vCPUs")
        self.vm.update_vcpu_num(vcpu_num_target)
        self.assertEqual(self.vm.get_vcpu_num(), vcpu_num_target,
                         "Test failed as hot add VM vCPUs failed")
        time.sleep(10)
        self._verify_cpu_cores()
        
        self.log.info("Recover VM vCPUs")
        self.vm.update_vcpu_num(vcpu_num_current)
        self.assertEqual(self.vm.get_vcpu_num(), vcpu_num_current,
                         "Test failed as recover VM vCPUs failed")
        utils_lib.init_connection(self)
        self._verify_cpu_cores()
        
    def test_hot_add_memory(self):
        '''
        case_tag:
            Memory
        case_name:
            test_hot_add_memory
        case_file:
            os_tests.tests.test_nutanix_vm.test_hot_add_memory
        component:
            Memory
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Add memory to a powered on VM
        key_steps: |
            1. Add memory to a powered on VM
            2. Verify memory size on RHEL guest OS
        expect_result:
            Memory size is consistent between Nutanix AHV and RHEL guest OS
        debug_want:
            N/A
        '''
        mem_gb_current = self.vm.get_memory_size()
        mem_gb_target = mem_gb_current * 2
        self.log.info("Hot add VM memory")
        self.vm.update_memory_size(mem_gb_target)
        self.assertEqual(self.vm.get_memory_size(), mem_gb_target,
                         "Test failed as hot add VM memory failed")
        time.sleep(10)
        self._verify_memory_size()
        self._recover_memory(mem_gb_current)

    def test_add_vcpu(self):
        '''
        case_tag:
            CPU
        case_name:
            test_add_vcpu
        case_file:
            os_tests.tests.test_nutanix_vm.test_add_vcpu
        component:
            CPU
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Add vCPU to a powered off VM
        key_steps: |
            1. Add vCPU to a powered off VM
            2. Verify CPU numbers on RHEL guest OS
        expect_result:
            CPU numbers is consistent between Nutanix AHV and RHEL guest OS
        debug_want:
            N/A
        '''
        if self.vm.is_started():
            self.vm.stop(wait=True)

        vcpu_num_current = self.vm.get_vcpu_num()
        vcpu_num_target = vcpu_num_current * 2
        self.log.info("Add VM vCPUs")
        self.vm.update_vcpu_num(vcpu_num_target)
        self.assertEqual(self.vm.get_vcpu_num(), vcpu_num_target,
                         "Test failed as add VM vCPUs failed")
        utils_lib.init_connection(self)
        self._verify_cpu_cores()
        
        self.log.info("Recover VM vCPUs")
        self.vm.update_vcpu_num(vcpu_num_current)
        self.assertEqual(self.vm.get_vcpu_num(), vcpu_num_current,
                         "Test failed as recover VM vCPUs failed")
        utils_lib.init_connection(self)
        self._verify_cpu_cores()
        
    def test_add_vcpu_core(self):
        '''
        case_tag:
            CPU
        case_name:
            test_add_vcpu_core
        case_file:
            os_tests.tests.test_nutanix_vm.test_add_vcpu_core
        component:
            CPU
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Add vCPU cores to a powered off VM
        key_steps: |
            1. Add vCPU cores to a powered off VM
            2. Verify CPU numbers on RHEL guest OS
        expect_result:
            CPU numbers is consistent between Nutanix AHV and RHEL guest OS
        debug_want:
            N/A
        '''
        core_num_current = self.vm.get_core_num()
        core_num_target = core_num_current * 2
        self.log.info("Add VM vCPU cores")
        self.vm.update_core_num(core_num_target)
        self.assertEqual(self.vm.get_core_num(), core_num_target,
                         "Test failed as add VM cpu cores failed")
        utils_lib.init_connection(self)
        self._verify_cpu_cores()
        
        self.log.info("Recover VM vCPU cores")
        self.vm.update_core_num(core_num_current)
        self.assertEqual(self.vm.get_core_num(), core_num_current,
                         "Test failed as recover VM cpu cores failed")
        utils_lib.init_connection(self)
        self._verify_cpu_cores()
        
    def test_add_memory(self):
        '''
        case_tag:
            Memory
        case_name:
            test_add_memory
        case_file:
            os_tests.tests.test_nutanix_vm.test_add_memory
        component:
            Memory
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Add memory to a powered off VM
        key_steps: |
            1. Add memory to a powered off VM
            2. Verify memory size on RHEL guest OS
        expect_result:
            Memory size is consistent between Nutanix AHV and RHEL guest OS
        '''
        if self.vm.is_started():
            self.vm.stop(wait=True)        

        mem_gb_current = self.vm.get_memory_size()
        mem_gb_target = mem_gb_current * 2
        self.log.info("Add VM memory")
        self.vm.update_memory_size(mem_gb_target)
        self.assertEqual(self.vm.get_memory_size(), mem_gb_target,
                         "Test failed as add VM memory failed")
        utils_lib.init_connection(self)
        self._verify_memory_size()
        self._recover_memory(mem_gb_current)

    def test_cpu_passthrough(self):
        '''
        case_tag:
            CPU
        case_name:
            test_cpu_passthrough
        case_file:
            os_tests.tests.test_nutanix_vm.test_cpu_passthrough
        component:
            CPU
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Verify CPU passthrough features
        key_steps: |
            1. Enable CPU passthrough, and check CPU info on RHEL guest OS
            2. Disable CPU passthrough, and check CPU info on RHEL guest OS
        expect_result:
            CPU passthrough can be enable or disable and take effect on RHEL guest OS
        debug_want:
            N/A
        '''
        pt_is_disabled = self.vm.get_cpu_passthrough(enabled=False)
        if pt_is_disabled:
            self.vm.set_cpu_passthrough(enabled=True)
            utils_lib.init_connection(self)
            self.assertTrue(self.vm.get_cpu_passthrough(enabled=True),
                            "Test failed as setup CPU passthrough failed")
        else:
            self.fail(
                "Expecte CPU passthrough set as disabled by default, need more investigation here")
        
        cmd = "grep -i vmx /proc/cpuinfo"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw="vmx",
                          msg="Verify if cpu vmx has take effected on RHEL guest OS")

        self.log.info("Recover VM cpu passthrough")
        self.vm.set_cpu_passthrough(enabled=False)
        self.assertTrue(self.vm.get_cpu_passthrough(enabled=False),
                        "Test failed as recover CPU passthrough failed")
        utils_lib.init_connection(self)
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, expect_not_kw="vmx",
                          msg="Verify if cpu vmx has disabled on RHEL guest OS")

    def test_memory_vnuma(self):
        '''
        case_tag:
            Memory
        case_name:
            test_memory_vnuma
        case_file:
            os_tests.tests.test_nutanix_vm.test_memory_vnuma
        component:
            Memory
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Verify memory vnuma features
        key_steps: |
            1. Setup memory vnuma nodes number, and verify on RHEL guest OS
        expect_result:
            vnuma numbers is consistent between Nutanix AHV and RHEL guest OS
        debug_want:
        '''
        vnuma_num_current = self.vm.get_memory_vnuma()
        vnuma_num_target = self.vm.host_cpu_num()
        if vnuma_num_target < 2:
            self.skipTest("Skip as AHV host only has 1 physical CPU")

        if vnuma_num_target != vnuma_num_current:
            self.vm.set_memory_vnuma(vnuma_num_target)
            utils_lib.init_connection(self)
        self._verify_memory_vnuma()
        self.assertEqual(self.vm.get_memory_vnuma(), vnuma_num_target,
                         "Test failed as setup VM vnuma failed")

        if vnuma_num_target != vnuma_num_current:
            self.log.info("Recover VM memory vnuma")
            self.vm.set_memory_vnuma(vnuma_num_current)
            utils_lib.init_connection(self)
            self._verify_memory_vnuma()
            self.assertEqual(self.vm.get_memory_vnuma(), vnuma_num_current,
                            "Test failed as recover VM vnuma failed")

    def test_check_firstlaunch_time(self):
        """
        case_tag:
            GeneralVerification
        case_name:
            test_check_firstlaunch_time
        case_file:
            os_tests.tests.test_nutanix_vm.test_check_firstlaunch_time
        component:
            GeneralVerification
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Verify VM first launch time
        key_steps: |
            1. Get system boot time via "systemd-analyze"
            2. Compare with first_launch in nutanix.yaml
        expect_result:
            Boot time less than first_launch in nutanix.yaml
        debug_want:
            systemd-analyze
        debug_want:
            N/A
        """
        firstlaunch_time = self.vm.params['BootTime']['first_launch']
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=firstlaunch_time, ratio=0,
                               msg="Compare with cfg specified firstlaunch_time")

    def test_check_reboot_time(self):
        """
        case_tag:
            GeneralVerification
        case_name:
            test_check_reboot_time
        case_file:
            os_tests.tests.test_nutanix_vm.test_check_reboot_time
        component:
            GeneralVerification
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Verify VM reboot time
        key_steps: |
            1. Reboot VM gracefully
            1. Get system boot time via "systemd-analyze"
            2. Compare with acpi_reboot in nutanix.yaml
        expect_result:
            Boot time less than acpi_reboot in nutanix.yaml
        debug_want:
            systemd-analyze
        debug_want:
            N/A
        """
        self.vm.reboot(wait=True)
        utils_lib.init_connection(self)
        reboot_time = self.vm.params['BootTime']['acpi_reboot']
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=reboot_time, ratio=0,
                               msg="Compare with cfg specified reboot_time")
        
    def test_reboot_vm_12Gmem(self):
        """
        case_tag:
            GeneralVerification
        case_name:
            test_reboot_vm_12Gmem
        case_file:
            os_tests.tests.test_nutanix_vm.test_reboot_vm_12Gmem
        component:
            GeneralVerification
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Reboot VM with more than 12G memory for 3 times in UEFI mode
        key_steps: |
            1. Prepare a VM with more than 12G UEFI in UEFI mode
            2. Reboot VM for 3 times
        expect_result:
            1. VM should be working after reboot
            2. No unexpected error
        debug_want:
            N/A
        debug_want:
            N/A
        """
        is_uefi_boot = self.vm.params['VM']['if_uefi_boot']
        if not is_uefi_boot:
            self.skipTest("Skip as VM is not in UEFI boot mode")
        
        mem_gb_current = self.vm.get_memory_size()
        mem_gb_target = 12
        self.log.info("Add VM memory to %sGB" % mem_gb_target)
        self.vm.update_memory_size(mem_gb_target)
        self.assertEqual(self.vm.get_memory_size(), mem_gb_target,
                         "Test failed as add VM memory failed")
        time.sleep(10)
        self._verify_memory_size()
               
        reboot_cycles = 3
        self._reboot_os_cycles(reboot_cycles)
        self._recover_memory(mem_gb_current)

    def test_reboot_vm_cycles(self):
        """
        case_tag:
            GeneralVerification
        case_name:
            test_reboot_vm_cycles
        case_file:
            os_tests.tests.test_nutanix_vm.test_reboot_vm_cycles
        component:
            GeneralVerification
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Reboot VM for hundreds of times and check VM status
        key_steps: |
            1. Reboot VM for more than 100 times
            2. Check VM status
            3. Check OS status
        expect_result:
            1. VM working normally after reboot
            2. No unexpected error
        debug_want:
            N/A
        debug_want:
            N/A
        """
        reboot_cycles = self.vm.params['Stress']['reboot_cycles']
        if not reboot_cycles or reboot_cycles < 1:
            self.skipTest("Skip as reboot_cycles is not defined in .yaml file")

        self._reboot_os_cycles(reboot_cycles)

    def test_reboot_vm_debugkernel(self):
        """
        case_tag:
            GeneralVerification
        case_name:
            test_reboot_vm_debugkernel
        case_file:
            os_tests.tests.test_nutanix_vm.test_reboot_vm_debugkernel
        component:
            GeneralVerification
        bugzilla_id:
            N/A
        is_customer_case:
            False
        customer_case_id:
            N/A
        testplan:
            N/A
        maintainer:
            shshang@redhat.com
        description:
            Reboot VM for 10 times with debug kernel and check VM status
        key_steps: |
            1. Boot VM with debug kernel
            2. Reboot VM for more than 100 times
            2. Check VM status
            3. Check OS status
        expect_result:
            1. VM working normally after reboot
            2. No unexpected error
        debug_want:
            N/A
        debug_want:
            N/A
        """
        if_secure_boot = self.vm.params['VM']['if_secure_boot']
        if if_secure_boot:
            self.skipTest('''Red Hat Insights error \
"sed: can't read /sys/kernel/debug/sched_features: Operation not permitted" When using secure boot''')
        
        mem_gb_current = self.vm.get_memory_size()
        if mem_gb_current < 2:
            self.skipTest("Skip test as minimal 2G memory is required for debug kernel")        

        default_kernel = utils_lib.run_cmd(self, "sudo grubby --default-kernel",
                                              expect_ret=0)
        kernel_version = utils_lib.run_cmd(self, "uname -r", expect_ret=0)
        if "debug" in kernel_version:
            self.log.info("Already in debug kernel")
        else:
            debug_kernel = "/boot/vmlinuz-" + kernel_version.strip('\n') + "+debug"
            debug_kernel_pkg = "kernel-debug-" + kernel_version
            utils_lib.is_pkg_installed(self, pkg_name=debug_kernel_pkg, timeout=300)
            utils_lib.run_cmd(self,
                              "sudo grubby --info=%s" % debug_kernel,
                              expect_ret=0,
                              msg="check kernel-debug installed")
            cmd = "sudo grubby --info=%s|grep index|cut -d'=' -f2" % debug_kernel
            debug_kernel_index = utils_lib.run_cmd(self, cmd,
                                                   expect_ret=0, cancel_ret='0',
                                                   msg="check kernel-debug index")
            cmd = "sudo grubby --set-default-index=%s" % debug_kernel_index
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="change default boot index")

        utils_lib.run_cmd(self, "sudo reboot", msg='Reboot OS to boot to debug kernel')
        time.sleep(60)
        utils_lib.init_connection(self)
        utils_lib.run_cmd(self, "uname -r",
                          expect_ret=0, expect_kw="debug",
                          msg="checking debug kernel booted")

        cmd = "sudo systemd-analyze"
        time_start = int(time.time())
        while True:
            output = utils_lib.run_cmd(self, cmd)
            if 'Bootup is not yet finished' not in output:
                break
            time_end = int(time.time())
            utils_lib.run_cmd(self, 'sudo systemctl list-jobs')
            if time_end - time_start > 120:
                self.fail("Bootup is not yet finished after 120s")
            self.log.info("Wait for bootup finish......")
            time.sleep(1)
        
        reboot_cycles = 10
        self._reboot_os_cycles(reboot_cycles, time_wait=30)
        
        cmd = "sudo grubby --set-default %s" % default_kernel
        utils_lib.run_cmd(self, cmd,
                          expect_ret=0,
                          msg="Recover kernel to origin: %s" % default_kernel)
        utils_lib.run_cmd(self, "sudo reboot",
                          msg='Reboot OS to boot to default kernel')
        time.sleep(30)
        utils_lib.init_connection(self)
        utils_lib.run_cmd(self, "uname -r",
                          expect_ret=0, expect_not_kw="debug",
                          msg="Verifying default kernel has recovered")

    def tearDown(self):
        utils_lib.check_log(self, "error,warn,fail,unable,unknown,Unknown,Call trace,Call Trace",
                            log_cmd='dmesg -T', cursor=self.dmesg_cursor)

if __name__ == '__main__':
    unittest.main()
