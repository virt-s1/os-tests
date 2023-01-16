import unittest
from os_tests.libs import utils_lib
from os_tests.libs.resources import UnSupportedAction
import time
import os
import os_tests
import random
import json
from tipset.libs import rmt_ssh

class TestStorage(unittest.TestCase):

    def _blktests_run(self, case_name=None):
        '''
        Run specify blktests test case.
        Arguments:
            test_instance {avocado Test instance} -- avocado test instance
        '''
        test_disk = self._get_test_disk()
        cmd = "sudo bash -c \"echo 'TEST_DEVS=({})' > /usr/local/blktests/config\"".format(test_disk)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "cd /usr/local/blktests/; sudo ./check {}".format(case_name)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw="failed", timeout=2400)

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
                #cmd = 'sudo wipefs -a /dev/{}'.format(disk) #comment this line for bz2074486
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

    def setUp(self):
        utils_lib.init_case(self)
        utils_dir = os.path.realpath(os_tests.__file__)
        utils_dir = os.path.dirname(utils_dir) + '/utils'
        if utils_lib.is_arch(self, arch='aarch64'):
            blktests_rpm = utils_dir + '/blktests-master.aarch64.rpm'
            blktests_rpm_tmp = '/tmp/blktests-master.aarch64.rpm'
        else:
            blktests_rpm = utils_dir + '/blktests-master.x86_64.rpm'
            blktests_rpm_tmp = '/tmp/blktests-master.x86_64.rpm'
        if not utils_lib.is_pkg_installed(self, pkg_name='blktests',is_install=False) and 'blktests' in self.id():
            if self.params['remote_node']:
                self.log.info('Copy {} to remote'.format(blktests_rpm))
                self.SSH.put_file(local_file=blktests_rpm, rmt_file=blktests_rpm_tmp)
                blktests_rpm = blktests_rpm_tmp
        if 'blktests' in self.id():
            utils_lib.pkg_install(self, pkg_name='blktests', pkg_url=blktests_rpm,force=True)
        self.cursor = utils_lib.get_cmd_cursor(self, timeout=120)

    def test_storage_blktests_block(self):
        '''
        case_name:
            test_storage_blktests_block
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1464851
        polarion_id:
            RHEL7-98753
        maintainer:
            xiliang@redhat.com
        description:
            Run blktests block.
        key_steps:
            1. Install blktests
            2. # cd /usr/local/blktests/
            3. # ./check block
        expected_result:
            No failure case found

        '''
        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="Xen",
                    msg="Not run in xen instance(cpuhotplug) as bug 1641510 which is very low priority")
        self._blktests_run(case_name="block")

    def test_storage_blktests_nvme(self):
        '''
        case_name:
            test_storage_blktests_nvme
        case_priority:
            1
        component:
            kernel
        bugzilla_id:
            1464851
        polarion_id:
            RHEL7-98753
        maintainer:
            xiliang@redhat.com
        description:
            Run blktests nvme.
        key_steps:
            1. Install blktests
            2. # cd /usr/local/blktests/
            3. # ./check nvme
        expected_result:
            No failure case found
        '''
        self._blktests_run(case_name="nvme")

    def test_growpart(self):
        """
        case_tag:
            cloudinit,storage
        case_name:
            test_growpart
        component:
            cloud-utils-growpart
        bugzilla_id:
            2063921
        is_customer_case:
            True
        maintainer:
            xuazhao@redhat.com
        description:
            check if pvs can work after growpart
        key_steps:
            1.make disk parted
            2.pvcreate vgcreate
            3.growpart
            4.check if pvs and vgs still exists after growpart
        expect_result:
            pvs can show normally,e.g:
            PV VG Fmt Attr PSize PFree
        debug_want:
            N/A
        """
        if(not self._get_test_disk()):
            self.skipTest("test disk not found")
        else:
            test_disk = self._get_test_disk()
        utils_lib.is_cmd_exist(self,"growpart")
        utils_lib.is_pkg_installed(self,"lvm2")

        cmd = 'sudo wipefs -a {}'.format(test_disk)
        utils_lib.run_cmd(self,cmd,msg="wipe all fs from {}".format(test_disk))
        cmd = " sudo parted -s {} mklabel gpt mkpart primary ext4 1MB 1024MB".format(test_disk)
        utils_lib.run_cmd(self,cmd,msg = "make disk part")
        cmd = " lsblk -l {}|grep part|sort|uniq|cut -f1 -d' '|head -n1".format(test_disk)
        test_part = '/dev/' + utils_lib.run_cmd(self, cmd, expect_ret=0, msg='get test part')
        test_part = test_part.strip('\n')

        cmd = "sudo pvcreate {} -ff -y".format(test_part)
        utils_lib.run_cmd(self,cmd,msg= "create lvm on disk")
        time.sleep(2)

        cmd = "sudo vgcreate datavga {}".format(test_part)
        utils_lib.run_cmd(self,cmd,msg="create vg group")
        time.sleep(2)

        cmd = "sudo growpart {} 1".format(test_disk)
        utils_lib.run_cmd(self,cmd,msg="run growpart")
        time.sleep(2)

        utils_lib.run_cmd(self,"sudo pvs",expect_kw="datavga",msg="check if pv exists")
        utils_lib.run_cmd(self,"sudo vgs",expect_kw="datavga",msg="check if vg exists")

        utils_lib.run_cmd(self,"sudo vgremove datavga",msg="remove vg group")
        utils_lib.run_cmd(self,"sudo pvremove {}".format(test_part),msg="remove pv")

    def test_storage_parted_s(self):
        """
        case_name:
            test_storage_parted_s
        case_file:
            os_tests.tests.test_storage.TestStorage.test_storage_parted_s
        component:
            kernel
        bugzilla_id:
            2024355
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description:
            Test creation of a large number of partitions on a gpt disk using 'parted -s'.
        key_steps:
            # parted -s $blockdev mklabel gpt mkpart primary 1Mib 6Mib mkpart primary 6Mib 11Mib mkpart primary 11Mib 16Mib mkpart primary 16Mib 21Mib mkpart primary 21Mib 26Mib mkpart primary 26Mib 31Mib mkpart primary 31Mib 36Mib mkpart primary 36Mib 41Mib mkpart primary 41Mib 46Mib mkpart primary 46Mib 51Mib mkpart primary 51Mib 56Mib mkpart primary 56Mib 61Mib mkpart primary 61Mib 66Mib mkpart primary 66Mib 71Mib mkpart primary 71Mib 76Mib mkpart primary 76Mib 81Mib mkpart primary 81Mib 86Mib mkpart primary 86Mib 91Mib mkpart primary 91Mib 96Mib mkpart primary 96Mib 101Mib
        expect_result:
            No error threw and create all partitions.
        debug_want:
            - output from dmesg or journal
            - test debug log
        """
        test_disk = self._get_test_disk()
        cmd = 'sudo wipefs -a {}'.format(test_disk)
        utils_lib.run_cmd(self, cmd, msg="try to wipe all fs from {}".format(test_disk))
        cmd = "sudo parted -s {} mklabel gpt mkpart primary 1Mib 6Mib mkpart primary 6Mib 11Mib mkpart primary 11Mib 16Mib mkpart primary 16Mib 21Mib mkpart primary 21Mib 26Mib mkpart primary 26Mib 31Mib mkpart primary 31Mib 36Mib mkpart primary 36Mib 41Mib mkpart primary 41Mib 46Mib mkpart primary 46Mib 51Mib mkpart primary 51Mib 56Mib mkpart primary 56Mib 61Mib mkpart primary 61Mib 66Mib mkpart primary 66Mib 71Mib mkpart primary 71Mib 76Mib mkpart primary 76Mib 81Mib mkpart primary 81Mib 86Mib mkpart primary 86Mib 91Mib mkpart primary 91Mib 96Mib mkpart primary 96Mib 101Mib".format(test_disk)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='create 20 partitions on {}'.format(test_disk))
        cmd = "sudo parted -s {} print free".format(test_disk)
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='106MB', msg="check partitions created")

    def _get_disk_num(self, disk_or_rom):
        cmd = 'lsblk -d --output TYPE | grep {} | wc -l'.format(disk_or_rom)
        disk_num = utils_lib.run_cmd(self, cmd, expect_ret=0)
        return disk_num

    def test_add_ide_empty_cdrom(self):
        """
        case_tag:
            Storage,Storage_tier1
        case_name:
            test_add_ide_empty_cdrom
        case_file:
            os_tests.tests.test_storage.TestStorage.test_add_ide_empty_cdrom
        component:
            storage
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test attach empty ide cdrom.
        key_steps:
            Attach empty ide cdrom.
        expect_result:
            Number of rom increased and no error threw.
        debug_want:
            output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        if self.vm.provider == 'nutanix':
            if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                self.skipTest("Cannot attach an IDE Disk when secure boot is enabled or when vm machine type is q35")
        origin_disk_num = self._get_disk_num('rom')
        utils_lib.check_attribute(self.vm, 'attach_disk',test_instance=self, cancel_case=True)
        self.vm.stop(wait=True)
        try:
            self.vm.attach_disk('ide', disk_size=0, is_cdrom=True, device_index=1, wait=True, is_empty=True)
        except NotImplementedError:
            self.skipTest('attach_disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('attach_disk func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        new_disk_num = self._get_disk_num('rom')
        new_add_num = int(new_disk_num) - int(origin_disk_num)
        self.assertEqual(new_add_num, 1, msg="Number of new attached rom is not right, Expect: %s, real: %s" % (1, new_add_num))
        #teardown
        self.vm.stop(wait=True)
        disk_uuid = self.vm.get_disk_uuid('ide', device_index=1)
        try:
            self.vm.detach_disk('ide', disk_uuid, device_index=1, wait=True)
        except NotImplementedError:
            self.skipTest('detach disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('detach disk func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def _test_add_clone_cdrom(self, cdrom_type, clone_type):
        origin_disk_num = self._get_disk_num('rom')
        utils_lib.check_attribute(self.vm, 'attach_disk',test_instance=self, cancel_case=True)
        self.vm.stop(wait=True)
        try:
            self.vm.attach_disk(cdrom_type, disk_size=0, is_cdrom=True, device_index=0, wait=True, \
                is_empty=False, clone=clone_type)
        except NotImplementedError:
            self.skipTest('attch disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('attch disk func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        new_disk_num = self._get_disk_num('rom')
        new_add_num = int(new_disk_num) - int(origin_disk_num)
        self.assertEqual(new_add_num, 1, "Number of new attached rom is not right Expect: %s, real: %s" % (1, new_add_num))
        new_add_device_name=utils_lib.run_cmd(self, 'blkid --label cidata', expect_ret=0).split('\n')[0]
        cmd = "sudo mkdir /mnt/mnt_new_cdrom \n sudo mount {} /mnt/mnt_new_cdrom".format(new_add_device_name)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        read_new_device = utils_lib.run_cmd(self, "sudo ls /mnt/mnt_new_cdrom", expect_ret=0)
        self.assertIn("meta-data\nuser-data\n", read_new_device, msg="Read files from new added cdrom failed")
        #tear down
        disk_uuid = self.vm.get_disk_uuid(cdrom_type, device_index=0)
        self.vm.stop(wait=True)
        try:
            self.vm.detach_disk(cdrom_type, disk_uuid, device_index=0, wait=True)
        except NotImplementedError:
            self.skipTest('detach disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('detach disk func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
    
    def test_add_sata_clone_cdrom_from_img_service(self):
        """
        case_tag:
            Storage,Storage_tier2
        case_name:
            test_add_sata_clone_cdrom_from_img_service
        case_file:
            os_tests.tests.test_storage.TestStorage.test_add_sata_clone_cdrom_from_img_service
        component:
            storage
         bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test attach sata cdrom clone from image service and then read the content in VM.
        key_steps:
            Attach sata cdrom and then read it's content
        expect_result:
            No error threw and cdrom content right.
        debug_want:
            output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        self._test_add_clone_cdrom('sata', 'clone_from_img_service')

    def test_add_ide_clone_cdrom_from_adsf_file(self):
        """
        case_tag:
            Storage,Storage_tier2
        case_name:
            test_add_ide_clone_cdrom_from_adsf_file
        case_file:
            os_tests.tests.test_storage.TestStorage.test_add_ide_clone_cdrom_from_adsf_file
        component:
            storage
         bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test attach ide cdrom clone from asdf file and then read the content in VM.
        key_steps:
            Attach ide cdrom and then read it's content
        expect_result:
            No error threw and cdrom content right.
        debug_want:
            output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        self._test_add_clone_cdrom('ide', 'clone_from_adsf_file')

    def test_add_remove_multi_scsi(self):
        """
        case_tag:
            Storage,Storage_tier1
        case_name:
            test_add_remove_multi_scsi
        case_file:
            os_tests.tests.test_storage.TestStorage.test_add_remove_multi_scsi
        component:
            storage
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test add and remove scsi disk of random size for 10 times in the VM.
        key_steps:
            Attach/detach scsi disk with random size and check in 10 cycles.
        expect_result:
            No error threw and size check right.
        debug_want:
            output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        if self.vm.provider == 'nutanix':
            if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                self.skipTest("Skip this test case as q35 machine type or secure boot not support IDE")

        utils_lib.check_attribute(self.vm, 'attach_disk',test_instance=self, cancel_case=True)
        for i in range(10):
            #get random device size
            random_dev_size = random.randint(1,10)
            self.log.info('test add remove scsi for {} time(s), and test size is {}'.format(i+1,random_dev_size))
            cmd = 'lsblk -d --output NAME|grep -v NAME'
            origin_lsblk_name_list = utils_lib.run_cmd(self, cmd, expect_ret=0).split('\n')
            origin_disk_num = self._get_disk_num('disk')
            try:
                self.vm.attach_disk('scsi', disk_size=random_dev_size, is_cdrom=False, device_index=3, wait=True, is_empty=True)
            except NotImplementedError:
                self.skipTest('attch disk func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('attch disk func is not supported in {}'.format(self.vm.provider))
            new_disk_num = self._get_disk_num('disk')
            new_add_num = int(new_disk_num) - int(origin_disk_num)
            self.assertEqual(new_add_num, 1, msg = "Number of new attached disk is not right. Expect: %s, real: %s" % (1, new_add_num))
            new_lsblk_name_list = utils_lib.run_cmd(self, cmd, expect_ret=0).split('\n')
            new_dev = [x for x in new_lsblk_name_list if x not in origin_lsblk_name_list][0]
            cmd = 'sudo fdisk -s /dev/{}'.format(new_dev)
            new_dev_size = utils_lib.run_cmd(self, cmd, expect_ret=0).split('\n')[0]
            self.assertEqual(
                int(new_dev_size), random_dev_size*1024*1024,
                msg="Device size for new disk is not right, Expect: %s, real: %s" % (random_dev_size*1024*1024, new_dev_size)
            )
            origin_disk_num = self._get_disk_num('disk')
            disk_uuid = self.vm.get_disk_uuid('scsi', device_index=1)
            try:
                self.vm.detach_disk('scsi', disk_uuid, device_index=3, wait=True)
            except NotImplementedError:
                self.skipTest('detach disk func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('detach disk func is not supported in {}'.format(self.vm.provider))
            new_disk_num = self._get_disk_num('disk')
            detach_num = int(origin_disk_num) - int(new_disk_num)
            self.assertEqual(detach_num, 1, msg="Number of detached disk is not right. Expect: %s, real: %s" % (1, detach_num))
    
    def _test_take_restore_snapshot(self, is_offline):
        """
        Take snapshot against a running VM or a stopped VM
        """
        cmd = "touch ~/snpst.txt \n ls ~/snpst.txt"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.check_attribute(self.vm, 'take_snapshot',test_instance=self, cancel_case=True)
        if is_offline:
            self.vm.stop(wait=True)
        try:
            time.sleep(30)
            self.vm.take_snapshot('snpst_api', wait=True)
        except NotImplementedError:
            self.skipTest('take snapshot func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('take snapshot func is not supported in {}'.format(self.vm.provider))
        time.sleep(90)
        vm_snpst_list = self.vm.list_snapshots()
        self.assertEqual(
            'snpst_api',
            vm_snpst_list['entities'][0]['snapshot_name'],
            msg="snapshot file not found in snapshot list, expect: {}, real:{}".format('snpst_api',vm_snpst_list)
        )
        snapshot_uuid=vm_snpst_list['entities'][0]['uuid']
        if is_offline:
            self.vm.start(wait=True)
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
        self.log.info('delete the test file after taking snapshong and before restoring VM')
        cmd = "rm ~/snpst.txt \n ls ~/snpst.txt"
        check_file = utils_lib.run_cmd(self, cmd, expect_ret=2, msg='check No such file or directory')
        try:
            self.vm.restore_vm(snapshot_uuid, wait=True)
        except NotImplementedError:
            self.skipTest("restore vm func is not implemented in {}".format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest("restore vm func is not supported in {}".format(self.vm.provider))
        time.sleep(90)
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        check_file = utils_lib.run_cmd(self, "ls ~/snpst*", expect_ret=0)
        self.assertIn(
                    "/home/cloud-user/snpst.txt",
                    check_file,
                    msg="~/snpst_root.txt not be recovered after VM restore")

    def test_online_take_restore_snapshot(self):
        """
        case_tag:
            Storage,Storage_tier1
        case_name:
            test_online_take_restore_snapshot
        case_file:
            os_tests.tests.test_storage.TestStorage.test_online_take_restore_snapshot
        component:
            storage
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test take snapshot from VM and then restore it after removing file action.
        key_steps: |
            1. Create a file ~/snp.test.
            2. Take VM snapshot.
            3. Remove the fail ~/snp.test.
            4. Restore VM by the new snapshot, start VM, check the removed file exists after restore
        expect_result:
            No error threw and size check right.
        debug_want:
            output from dmesg or journal
        """
        self._test_take_restore_snapshot(False)

    def test_offline_take_restore_snapshot_clone_snapshot(self):
        """
        case_tag:
            Storage,Storage_tier1
        case_name:
            test_offline_take_restore_snapshot_clone_snapshot
        case_file:
            os_tests.tests.test_storage.TestStorage.test_offline_take_restore_snapshot_clone_snapshot
        component:
            storage
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test take snapshot from VM and then restore it after removing file action.
        key_steps: |
            1. Create a file ~/snp.test
            2. Stop VM and then take VM snapshot
            3. Start VM an then remove the fail ~/snp.test
            4. Restore VM by the new snapshot, start VM, check the removed file exists after restore
            5. Clone VM from snapshot and check specific memory value, vcpus number, custom data and user data.
        expect_result:
            No error threw and snapshot/VM cloned from snapshot check right.
        debug_want:
            output from dmesg or journal
        """
        self._test_take_restore_snapshot(True)
        cloneVM_set_Memory = 2048
        cloneVM_set_Cores_per_CPU = 1
        cloneVM_set_vcpus = 1
        self._test_clone("clone_from_snapshot", "ClonedByScriptFromSnapshot", cloneVM_set_Memory, cloneVM_set_Cores_per_CPU, cloneVM_set_vcpus)

    def test_expand_scsi_disk_online(self):
        """
        case_tag:
            Storage,Storage_tier1
        case_name:
            test_expand_scsi_disk_online
        case_file:
            os_tests.tests.test_storage.TestStorage.test_expand_scsi_disk_online
        component:
            storage
         bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Expand SCSI disk when guest is running.Test add large file after expanding disk. Linked case: test_add_large_file.
        key_steps: |
            1. Login the guest and get the size of the SCSI disk.
            2. Expand the SCSI disk to a larger size.
            3. Check the disk size.
            4. Check the disk that should be readable and writeable.
            5. Check big file can be created without error.
        expect_result:
            No error threw.
        debug_want:
            output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        if(not self._get_test_disk()):
            self.skipTest("test disk not found, provision VM should has at least 1 scsi disk")
        else:
            test_disk = self._get_test_disk()
        #Get init size of test disk
        cmd='sudo fdisk -s {}'.format(test_disk)
        test_disk_origin_size = int(utils_lib.run_cmd(self, cmd, expect_ret=0))/(1024*1024)
        utils_lib.check_attribute(self.vm, 'prism',test_instance=self, cancel_case=True)
        self.assertEqual(self.vm.prism.attach_disk_size, test_disk_origin_size, msg='disk size is not the same with init value')
        #Expand size of test disk when VM running
        try:
            self.disk.modify_disk_size(test_disk_origin_size, 'scsi', disk_index=1, expand_size=5)
        except NotImplementedError:
            self.skipTest('modify disk size func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('modify disk size func is not supported in {}'.format(self.vm.provider))
        #Get new size of test disk
        test_disk_new_size = int(utils_lib.run_cmd(self, cmd, expect_ret=0))/(1024*1024)
        self.assertEqual(10, int(test_disk_new_size), msg='disk size is not the same with expanded value, expect: {}, real: {}'.format(10*1024*1024, test_disk_new_size))
        #Test expanded disk can be read and write
        test_part = test_disk + "1"
        cmd = " sudo parted -s {} mklabel gpt mkpart primary xfs 1MB 10240MB".format(test_disk)
        utils_lib.run_cmd(self,cmd,msg = "make disk part")
        cmd = "sudo mkfs.xfs -f {}&&sudo mkdir /mnt/mnt_disk&&sudo mount {} /mnt/mnt_disk&&cd /mnt/mnt_disk&&sudo dd if=/dev/zero of=10G.img count=1024 bs=10M".format(test_part, test_part, test_part)
        utils_lib.run_cmd(self, cmd, expect_ret=1, msg='No space left on device')
        file_size = int(utils_lib.run_cmd(self, "sudo ls -l /mnt/mnt_disk/10G.img | awk '{print $5}'", expect_ret=0).strip())/(1024*1024*1024)
        self.assertAlmostEqual(
            first=10,
            second=float(file_size),
            delta=0.6,
            msg="Gap is two much between file size and create size Expect: %s, real: %s" %('10', file_size)
        )
        #tear down
        utils_lib.run_cmd(self, 'sudo umount {}\n'.format(test_part), expect_ret=0)

    def test_multi_disk(self):
        """
        case_tag:
            Storage,Storage_tier1
        case_name:
            test_multi_disk
        case_file:
            os_tests.tests.test_storage.TestStorage.test_multi_disk
        component:
            storage
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Add all four kinds of disk and test. linked case cp_big_file_between_disks,scp_big_file_between_disks,test_disk_info,test_multi_disk_hotplug
        key_steps: |
            1. Login the guest and add scsi/pci/ide/sata disk.
            2. Check bus type by lshw.
            3. Check the disks' size.
            4. Check the disks that should be readable and writeable.
        expect_result:
            No error threw and all check right.
        debug_want:
            output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        utils_lib.check_attribute(self.vm, 'attach_disk',test_instance=self, cancel_case=True)
        scsi_set_size = random.randint(6,10)
        pci_set_size = random.randint(6,10)
        ide_set_size = random.randint(6,10)
        sata_set_size = random.randint(6,10)
        #attach scsi and pci disk
        for disk_type, disk_size in zip(['scsi','pci'],[scsi_set_size, pci_set_size]):
            try:
                self.vm.attach_disk(disk_type, disk_size, is_cdrom=False, device_index=2, wait=True, is_empty=True)
            except NotImplementedError:
                self.skipTest('attach disk size func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('attach disk size func is not supported in {}'.format(self.vm.provider))
        #attach ide and sata disk
        self.vm.stop(wait=True)
        time.sleep(60)
        for disk_type, disk_size in zip(['ide','sata'],[ide_set_size, sata_set_size]):
            if disk_type == 'ide':
                if self.vm.provider == 'nutanix':
                    if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                        continue
            try:
                self.vm.attach_disk(disk_type, disk_size, is_cdrom=False, device_index=2, wait=True, is_empty=True)
            except NotImplementedError:
                self.skipTest('attach disk size func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('attach disk size func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        #check disk number
        num_fdisk=int(utils_lib.run_cmd(self, "sudo fdisk -l | grep 'Disk /dev' | wc -l", expect_ret=0))
        num_lsblk=int(utils_lib.run_cmd(self, "sudo lsblk -d | grep disk | wc -l", expect_ret=0))
        total_num=6
        if self.vm.provider == 'nutanix':
            if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                total_num=5
        self.assertEqual(num_fdisk, total_num, msg='Disk number get from fdisk is not right')
        self.assertEqual(num_lsblk, total_num, msg='Disk number get from lsblk is not right')
        #check disk bustype and size
        utils_lib.run_cmd(self, "sudo lshw -C disk -C storage", expect_ret=0)
        scsi_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-scsi' -A 63 | grep '*-disk:2' -A 13 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip().split()[-1]
        pci_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-scsi' -A 63  | grep '*-virtio' -A 7 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip()
        sata_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-sata' -A 37 | grep 'description: ATA Disk' -A 9 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip()
        scsi_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+scsi_dev_name, expect_ret=0))/(1024*1024)
        pci_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+pci_dev_name, expect_ret=0))/(1024*1024)
        sata_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+sata_dev_name, expect_ret=0))/(1024*1024)
        if self.vm.provider == 'nutanix':
            if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                ide_dev_name = None
                ide_dev_size = 0
            else:
                ide_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-ide' -A 38 | grep 'description: ATA Disk' -A 8 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip()
                ide_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+ide_dev_name, expect_ret=0))/(1024*1024)
        else:
            ide_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-ide' -A 38 | grep 'description: ATA Disk' -A 8 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip()
            ide_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+ide_dev_name, expect_ret=0))/(1024*1024)
        for bus_type, set_size, real_size in zip(['scsi', 'pci', 'ide','sata'], [scsi_set_size, pci_set_size, ide_set_size, sata_set_size],[scsi_dev_size, pci_dev_size, ide_dev_size, sata_dev_size]):
            if bus_type == 'ide':
                if self.vm.provider == 'nutanix':
                    if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                        continue
            self.assertEqual(set_size, real_size, msg="Size of %s disk is not right, Expect: %s, real: %s" % (bus_type, set_size, real_size))
        #check disk can be read and write, and test cp big file between different disk in on VM
        utils_lib.run_cmd(self, 'sudo dd if=/dev/zero of=5G.img count=1024 bs=5M')
        for device_type, device_name in zip(['scsi','pci','ide','sata'], [scsi_dev_name, pci_dev_name, ide_dev_name, sata_dev_name]):
            if device_type == 'ide':
                if self.vm.provider == 'nutanix':
                    if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                        continue
            create_file = '/mnt/mnt_{}/{}_touch_test.txt'.format(device_type, device_type)
            cmd = 'sudo mkfs.xfs {}\n sudo mkdir /mnt/mnt_{}\nsudo mount {} /mnt/mnt_{}\n sudo touch {}'.format(device_name, device_type, device_name, device_type, create_file)
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            check_file = utils_lib.run_cmd(self, 'ls {}'.format(create_file), expect_ret=0)
            self.assertIn(create_file, check_file, msg="Read files from new added disk failed")
            #test cp big files between different disk types
        for device_type in ('scsi','pci','ide','sata'):
            if device_type == 'ide':
                if self.vm.provider == 'nutanix':
                    if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                        continue
            utils_lib.run_cmd(self, 'sudo cp 5G.img /mnt/mnt_{}'.format(device_type))
            file_size = int(utils_lib.run_cmd(self, "sudo ls -l /mnt/mnt_%s/5G.img | awk '{print $5}'" % (device_type), expect_ret=0).strip())/(1024*1024*1024)
            self.assertEqual(5, file_size, msg="Value of created file is not right, Expect: 5, real: %s" % (file_size))
            #remove file and install sshpass before clone vm
            utils_lib.run_cmd(self, "sudo rm -f /mnt/mnt_%s/5G.img" % (device_type), expect_ret=0)
        utils_lib.is_cmd_exist(self,"sshpass")
        #clone VM, and test scp big file between different disk between different VM
        VMBecloned = self._clone_vm('clone_from_vm', 'ScriptCloneFromVM', 2048, 2, 2)
        for nic in VMBecloned.get('vm_nics'):
            if nic['network_uuid'] == self.vm.network_uuid:
                VMBecloned_ip = nic['ip_address']
        self.params['remote_nodes'].append(VMBecloned_ip)
        self.log.info('init connetcion to VM be cloned, VM IP is %s' % VMBecloned_ip)
        self.params['remote_nodes'].append(VMBecloned_ip)
        utils_lib.init_connection(self, timeout=self.ssh_timeout,rmt_node=self.params['remote_nodes'][-1])
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        for device_type, device_name in zip(['scsi','pci','ide','sata'], [scsi_dev_name, pci_dev_name, ide_dev_name, sata_dev_name]):
            if device_type == 'ide':
                if self.vm.provider == 'nutanix':
                    if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                        continue
            #mount disk on cloned VM
            cmd = 'sudo mount {} /mnt/mnt_{}'.format(device_name, device_type)
            utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1])
            scp_cmd = 'sudo sshpass -p {} scp -o StrictHostKeyChecking=no 5G.img root@{}:/mnt/mnt_{}'.format(self.vm.vm_password, VMBecloned_ip,device_type)
            utils_lib.run_cmd(self, scp_cmd, timeout=600)
            file_size = int(utils_lib.run_cmd(self, "sudo ls -l /mnt/mnt_%s/5G.img | awk '{print $5}'" % (device_type), expect_ret=0, rmt_node=VMBecloned_ip).strip())/(1024*1024*1024)
            self.assertEqual(5, file_size, msg="Value of created file is not right, Expect: 5, real: %s" % (file_size))
        #hot detach scsi
        try:
            disk_uuid = self.vm.get_disk_uuid('scsi', device_index=2)
            self.vm.detach_disk('scsi', disk_uuid, device_index=2, wait=True)
        except NotImplementedError:
            self.skipTest('detach disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('detach disk func is not supported in {}'.format(self.vm.provider))
        utils_lib.run_cmd(self, "ls " + scsi_dev_name, expect_ret=2, expect_kw='No such file or directory')
        #tear down - dettach ide, sata and pci disk
        self.vm.stop(wait=True)
        time.sleep(60)
        for device_type in ['ide','sata', 'pci']:
            if device_type == 'ide' and self.vm.provider == 'nutanix':
                if self.vm.if_secure_boot or self.vm.machine_type == 'q35':
                   continue
            try:
                disk_uuid = self.vm.get_disk_uuid(device_type, device_index=2)
                self.vm.detach_disk(device_type, disk_uuid, device_index=2, wait=True)
            except NotImplementedError:
                self.skipTest('detach disk size func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('detach disk size func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if self.vm.provider == 'nutanix':
            if not self.vm.if_secure_boot and not self.vm.machine_type == 'q35':
                utils_lib.run_cmd(self, "ls " + ide_dev_name, expect_ret=2, expect_kw='No such file or directory')
        utils_lib.run_cmd(self, "ls " + sata_dev_name, expect_ret=2, expect_kw='No such file or directory')
        utils_lib.run_cmd(self, "ls " + pci_dev_name, expect_ret=2, expect_kw='No such file or directory')

    def _clone_vm(self,clone_from_vm_or_snapshot, vm_name, cloneVM_set_Memory, cloneVM_set_Cores_per_CPU, cloneVM_set_vcpus):
        utils_lib.check_attribute(self.vm, 'prism',test_instance=self, cancel_case=True)
        try:
            self.log.info('Delete ide.3 for refresh user data')
            self.vm.stop(wait=True)
            time.sleep(60)
            if self.vm.machine_type == 'pc':
                disk_uuid = self.vm.get_disk_uuid('ide', device_index=3)
                self.vm.detach_disk('ide', disk_uuid, device_index=3, wait=True)
            else:
                disk_uuid = self.vm.get_disk_uuid('sata', device_index=3)
                self.vm.detach_disk('sata', disk_uuid, device_index=3, wait=True)
            self.vm.clone_vm(clone_from_vm_or_snapshot, vm_name, cloneVM_set_Memory, cloneVM_set_Cores_per_CPU, cloneVM_set_vcpus, override_network_config=False, fresh_install=True, vm_custom_file="test.sh", vm_userdata_file="userdata.yaml")
        except NotImplementedError:
            self.skipTest('Related func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('Related func is not supported in {}'.format(self.vm.provider))
        VMBecloned = self.vm.get_vm_by_filter("vm_name", self.vm.vm_name+'_'+vm_name)
        self.vms.append(VMBecloned)
        self.vm.prism.start_vm(VMBecloned['uuid'])
        time.sleep(180)
        return VMBecloned

    def _test_clone(self, clone_from_vm_or_snapshot, vm_name, cloneVM_set_Memory, cloneVM_set_Cores_per_CPU, cloneVM_set_vcpus):
        VMBecloned = self._clone_vm(clone_from_vm_or_snapshot, vm_name, cloneVM_set_Memory, cloneVM_set_Cores_per_CPU, cloneVM_set_vcpus)
        for nic in VMBecloned.get('vm_nics'):
            if nic['network_uuid'] == self.vm.network_uuid:
                VMBecloned_ip = nic['ip_address']
        #clone from snapshot not support to refresh install
        if clone_from_vm_or_snapshot == "clone_from_vm":
            self.log.info("Testing password login on cloned VM %s" % VMBecloned_ip)
            ssh = rmt_ssh.RemoteSSH()
            ssh.rmt_node = VMBecloned_ip
            ssh.rmt_user = self.vm.vm_username
            ssh.rmt_password = self.vm.vm_password
            ssh.create_connection()
            if ssh.ssh_client is None:
                self.fail('Failed to login to cloned VM by user/password specified in new user data')
        #connect cloned vm
        self.log.info('init connetcion to VM be cloned, VM IP is %s' % VMBecloned_ip)
        self.params['remote_nodes'].append(VMBecloned_ip)
        utils_lib.init_connection(self, timeout=self.ssh_timeout,rmt_node=self.params['remote_nodes'][-1])
        dmidecode_cmd = '''sudo dmidecode -t memory | grep "Memory Device" -A5 | grep Size \
            | awk '$3 ~ /GB/ {sum += $2} $3 ~ /MB/ {sum += $2/1024} END {printf sum}' '''
        cloneVM_actual_Memory = int(utils_lib.run_cmd(self, dmidecode_cmd, rmt_node=self.params['remote_nodes'][-1]))
        self.assertEqual(cloneVM_set_Memory/1024, cloneVM_actual_Memory, msg="Value of memory is not right, \
            Expect: %s, real: %s" % (cloneVM_set_Memory/1024, cloneVM_actual_Memory))
        cloneVM_actual_vcpus = int(utils_lib.run_cmd(self, "cat /proc/cpuinfo | grep processor | wc -l", \
            rmt_node=self.params['remote_nodes'][-1]))
        cloneVM_set_vcpus_num = cloneVM_set_Cores_per_CPU * cloneVM_set_vcpus
        self.assertEqual(cloneVM_actual_vcpus, cloneVM_set_vcpus_num, msg="Number of vcpus is not right, \
            Expect: %s, real: %s" % (cloneVM_set_vcpus_num, cloneVM_actual_vcpus))
        #clone from snapshot not support to refresh install
        if clone_from_vm_or_snapshot == "clone_from_vm":
            custome_data = utils_lib.run_cmd(self, "sudo chmod 755 /tmp/test.sh \n sudo /tmp/test.sh \n \
                sudo cat /tmp/test.txt", expect_ret=0, rmt_node=self.params['remote_nodes'][1])
            expect_cusome_data = "Test files to copy"
            self.assertIn(expect_cusome_data,
                          custome_data,
                          msg="Custome data is not right, Expect: %s, real: %s" % (expect_cusome_data, custome_data))
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.ssh_timeout,rmt_node=self.params['remote_nodes'][0])

    def test_clone_from_vm(self):
        """
        case_tag:
            Storage,Storage_tier1
        case_name:
            test_clone_from_vm
        case_file:
            os_tests.tests.test_storage.TestStorage.test_clone_from_vm
        component:
            storage
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Clone VM from specific VM uuid with specific memory value, vcpus number, custom data and user data.
        key_steps: |
            1. Clone VM from specific VM uuid with specific memory value, vcpus number, custom data and user data.
            2. Check the specific memory value.
            3. Check the specific vcpus number.
            4. Check the specific custom data.
            5. Check the specific user data.
        expect_result:
            No error threw and all check right.
        debug_want:
            output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        cloneVM_set_Memory = 16384
        cloneVM_set_Cores_per_CPU = 2
        cloneVM_set_vcpus = 2
        self._test_clone("clone_from_vm", "ClonedByScriptFromVM", cloneVM_set_Memory, cloneVM_set_Cores_per_CPU, cloneVM_set_vcpus)

    def test_add_remove_multi_cdrom(self):
        """
        case_tag:
            Storage,Storage_tier2
        case_name:
            test_add_remove_multi_cdrom
        case_file:
            os_tests.tests.test_storage.TestStorage.test_add_remove_multi_cdrom
        component:
            storage
         bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            minl@redhat.com
        description:
            Test attach and distach multi ide and sata cdrom in VM.
        key_steps:
            Attach and distach ide and sata cdrom.
        expect_result:
            No error threw and cdrom number is right.
        debug_want:
            output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        origin_disk_num = self._get_disk_num('rom')
        utils_lib.check_attribute(self.vm, 'attach_disk',test_instance=self, cancel_case=True)
        self.vm.stop(wait=True)
        for i in range(0,6):
            try:
                self.vm.attach_disk('sata', disk_size=0, is_cdrom=True, device_index=i, wait=True, is_empty=True)
            except NotImplementedError:
                self.skipTest('attch disk func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('attch disk func is not supported in {}'.format(self.vm.provider))
            if  self.vm.provider == 'nutanix' and (self.vm.if_secure_boot or self.vm.machine_type == 'q35'):
                    total_num = 5
            else:
                for i in range(0,3):
                    try:
                        self.vm.attach_disk('ide', disk_size=0, is_cdrom=True, device_index=i, wait=True, is_empty=True)
                    except NotImplementedError:
                        self.skipTest('attch disk func is not implemented in {}'.format(self.vm.provider))
                    except UnSupportedAction:
                        self.skipTest('attch disk func is not supported in {}'.format(self.vm.provider))
                total_num = 9
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        new_disk_num = self._get_disk_num('rom')
        new_add_num = int(new_disk_num) - int(origin_disk_num)
        self.assertEqual(new_add_num, total_num, "Number of new attached total rom is not right Expect: %s, real: %s" % (total_num, new_add_num))
        sata_dev_num = int(utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-sata' -A 80 | grep '*-cdrom' | wc -l", expect_ret=0).strip())
        self.assertEqual(sata_dev_num, 6, "Number of new attached sata rom is not right Expect: %s, real: %s" % (6, sata_dev_num))
        if self.vm.provider == 'nutanix':
            if not self.vm.if_secure_boot and not self.vm.machine_type == 'q35':
                ide_dev_num = int(utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-ide' -A 56 | grep '*-cdrom' | wc -l", expect_ret=0).strip())
                self.assertEqual(ide_dev_num, 4, "Number of new attached sata rom is not right Expect: %s, real: %s" % (3, ide_dev_num))
        #tear down
        self.vm.stop(wait=True)
        for i in range(0,6):
            disk_uuid = self.vm.get_disk_uuid('sata', device_index=i)
            try:
                self.vm.detach_disk('sata', disk_uuid, device_index=i, wait=True)
            except NotImplementedError:
                self.skipTest('detach disk func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('detach disk func is not supported in {}'.format(self.vm.provider))
        if self.vm.provider == 'nutanix':
            if not self.vm.if_secure_boot and not self.vm.machine_type == 'q35':
                for i in range(0,3):
                    disk_uuid = self.vm.get_disk_uuid('ide', device_index=i)
                    try:
                        self.vm.detach_disk('ide', disk_uuid, device_index=i, wait=True)
                    except NotImplementedError:
                        self.skipTest('detach disk func is not implemented in {}'.format(self.vm.provider))
                    except UnSupportedAction:
                        self.skipTest('detach disk func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.ssh_timeout)

    def test_check_disk_count(self):
        '''
        description:
            check disk count in vm matches the vm assigned
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
            Storage
        key_steps:
            1. Launch an vm.
            2. Check online disks count via command "$ sudo lsblk -d".
        pass_criteria: 
            The online disks count is the same with attached disks.
        '''
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        utils_lib.check_attribute(self.vm, 'disk_count',test_instance=self, cancel_case=True)
        online_disk = utils_lib.get_disk_online(self)
        if self.vm.disk_count != online_disk:
            self.fail('disk assigned:{} not match disk online:{}'.format(self.vm.disk_count, online_disk))

    def test_disk_hotplug(self):
        '''
        description:
            Check hotplug disks when vm is running. Linked case RHEL7-93570.
            Will add disk read&write in auto test later.
        testplan:
            N/A
        bugzilla_id:
            2004072
        is_customer_case:
            False
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an vm.
            2. Check online disks count via command "$ lsblk -d".
            3. When instance is in running state, attach 4 disks to this instance.
            4. Connect instance via ssh, check online disks count again.
            5. Create partition and filesystem for the attached disks, format and mount the disks, check read and write in the attached disks.
            6. Detach the disks.
        pass_criteria: 
            Disks can be attached to the running instance successfully.
            The online disks count is the same with the orignial disks in spec plus attached disks.
            Read and write in attached disks work well.
            And no error, hang or crash in system.
            Disks can be detached successfully in step 6.
        '''
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        if self.vm.provider == 'nutanix':
            self.skipTest("Skip this test case as already covered in test_multi_disk")
        online_disk_1 = utils_lib.get_disk_online(self)
        if not self.disk:
            self.skipTest('Skip as lacking of storage provision support.')
        if not self.disk.is_exist():
            self.disk.create()
        time.sleep(20)
        if not self.vm.attach_block(self.disk, '/dev/sdz'):
            self.fail('attach failed')
        timeout = 60
        interval = 2
        time_start = int(time.time())
        while True:
           if not self.disk.is_free():
               break
           time_end = int(time.time())
           if time_end - time_start > timeout:
              self.log.info('timeout ended: {}'.format(timeout))
              break
           self.log.info('retry after {}s'.format(interval))
           time.sleep(interval)
        time.sleep(5)
        utils_lib.run_cmd(self, 'dmesg|tail -20', msg="Get the last dmesg")
        online_disk_2 = utils_lib.get_disk_online(self)
        if online_disk_2 == online_disk_1:
            self.fail('Online disk count - before:{} after attach:{}'.format(online_disk_1,online_disk_2))
        if not self.vm.detach_block(self.disk):
            self.fail('detach failed')
        timeout = 120
        interval = 2
        time_start = int(time.time())
        while True:
           if self.disk.is_free():
               break
           time_end = int(time.time())
           if time_end - time_start > timeout:
              self.log.info('timeout ended: {}'.format(timeout))
              break
           self.log.info('retry after {}s'.format(interval))
           time.sleep(interval)
        utils_lib.run_cmd(self, 'dmesg|tail -20', msg="Get the last dmesg")
        online_disk_2 = utils_lib.get_disk_online(self)
        if online_disk_2 != online_disk_1:
            self.fail('Online disk count - before:{} after detach:{}'.format(online_disk_1,online_disk_2))

    def test_fio_crctest(self):
        """
        case_tag:
            Storage,Storage_tier2
        case_name:
            test_fio_crctest
        case_file:
            os_tests.tests.test_storage.TestStorage.test_fio_crctest
        component:
            storage
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            testplan
        maintainer:
            minl@redhat.com
        description:
            Use fio to test the speed of the built-in checksumming functions in RHEL
        key_steps:
            Connect the instance, Use "$ sudo fio --crctest" to test the speed of the built-in checksumming functions.
        expect_result:
            crc test pass.
        debug_want:
            N/A
        """
        utils_lib.is_cmd_exist(self,"fio")
        cmd = 'sudo fio --crctest'
        utils_lib.run_cmd(
            self,
            cmd,
            expect_ret=0,
            msg='Test  the  speed  of  the built-in checksumming functions.', timeout=1200)

    def test_ssd_trim(self):
        """
        case_tag:
            Storage,Storage_tier2
        case_name:
            test_ssd_trim
        case_file:
            os_tests.tests.test_storage.TestStorage.test_ssd_trim
        component:
            storage
        bugzilla_id:
            N/A
        is_customer_case:
            False
        testplan:
            testplan
        maintainer:
            minl@redhat.com
        description:
            Test ssd trim in RHEL.
        key_steps: |
            1. Launch an instance which supports SSD volumes with TRIM.
            2. Check block devices information via command "$ sudo lsblk -d -O -J".
        expect_result:
            Block devices can be mount and trimmed infomation displays, no error message or any exception.
        debug_want:
            N/A
        """
        cmd = 'sudo lsblk -d -O -J'
        disk_discard = None
        try:
            output = utils_lib.run_cmd(self, cmd)
            disks_dict = json.loads(output)
            disk_discard = None
            for disk in disks_dict["blockdevices"]:
                if disk["disc-max"] is not None and '0B' not in disk[
                        "disc-max"]:
                    disk_discard = disk["name"]
                    self.log.info("%s supports discard %s" %
                                  (disk_discard, disk["disc-max"]))
        except ValueError as err:
            self.log.info("lsblk no json support")
            cmd = 'sudo lsblk -o NAME,DISC-MAX -d|grep -v NAME'
            output = utils_lib.run_cmd(self, cmd)
            for disk in output.split('\n'):
                if '0B' not in disk:
                    disk_discard = disk.split(' ')[0]
                    self.log.info("%s supports discard" % disk)
        if disk_discard is None:
            self.skipTest("No disk supports discard found.")
        cmd = 'sudo lsblk |grep -i part'
        output = utils_lib.run_cmd(self, cmd)
        if disk_discard not in output:
            cmd = "sudo mkfs.xfs -f /dev/%s" % disk_discard
            utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'mount'
        output = utils_lib.run_cmd(self, cmd)
        self.is_mounted = False
        if disk_discard not in output:
            cmd = "sudo mkfs.xfs -f /dev/%s" % disk_discard
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            cmd = "sudo mount /dev/%s /mnt" % disk_discard
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            self.is_mounted = True

        cmd = "sudo fstrim -v /mnt"
        utils_lib.run_cmd(self, cmd, expect_ret=0)

    def tearDown(self):
        if 'test_ssd_trim' in self.id():
            if self.is_mounted:
                utils_lib.run_cmd(self,'sudo umount /mnt')
        if 'blktests' in self.id():
            utils_lib.check_log(self, "trace", log_cmd='dmesg -T', cursor=self.cursor)
        else:
            utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='dmesg -T', cursor=self.cursor)
        if 'test_multi_disk' in self.id() or 'test_offline_take_restore_snapshot_clone_snapshot' in self.id() \
            or 'test_clone_from_vm' in self.id():
            self.log.info('Delete clone vm in tearDown.')
            if self.vm.provider == 'nutanix':
                self.vm.prism.delete_vm(self.vms[1]['uuid'])
                self.vms.pop()
                self.params['remote_nodes'].pop()

if __name__ == '__main__':
    unittest.main()