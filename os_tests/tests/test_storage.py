from cgi import test
import unittest
from os_tests.libs import utils_lib
from os_tests.libs.resources import UnSupportedAction
import time
import os
import os_tests
import random

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
            if self.params['remote_node'] is not None:
                self.log.info('Copy {} to remote'.format(blktests_rpm))
                self.SSH.put_file(local_file=blktests_rpm, rmt_file=blktests_rpm_tmp)
                blktests_rpm = blktests_rpm_tmp
        if 'blktests' in self.id():
            utils_lib.pkg_install(self, pkg_name='blktests', pkg_url=blktests_rpm)
        self.cursor = utils_lib.get_cmd_cursor(self, timeout=120)
        self.timeout = 180

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
        test_part = test_disk + "1"

        cmd = 'sudo wipefs -a {}'.format(test_disk)
        utils_lib.run_cmd(self,cmd,msg="wipe all fs from {}".format(test_disk))
        cmd = " sudo parted -s {} mklabel gpt mkpart primary ext4 1MB 1024MB".format(test_disk)
        utils_lib.run_cmd(self,cmd,msg = "make disk part")

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
        case_name:
            test_add_ide_empty_cdrom
        case_file:
            os_tests.tests.test_storage.TestStorage.test_add_ide_empty_cdrom
        component:
            storage
        maintainer:
            mingli@redhat.com
        description:
            Test attach empty ide cdrom.
        key_steps:
            # Attach empty ide cdrom
        expect_result:
            No error threw.
        debug_want:
            - output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        origin_disk_num = self._get_disk_num('rom')
        self.vm.stop(wait=True)
        try:
            self.vm.attach_disk('ide', 0, True, 1, True, wait=True)
        except NotImplementedError:
            self.skipTest('attch disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('attch disk func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.timeout)
        new_disk_num = self._get_disk_num('rom')
        new_add_num = int(new_disk_num) - int(origin_disk_num)
        self.assertEqual(new_add_num, 1, msg="Number of new attached rom is not right, Expect: %s, real: %s" % (1, new_add_num))
    
    def test_add_sata_clone_cdrom_from_img_service(self):
        """
        case_name:
            test_add_sata_clone_cdrom_from_img_service
        case_file:
            os_tests.tests.test_storage.TestStorage.test_add_sata_clone_cdrom_from_img_service
        component:
            storage
        maintainer:
            mingli@redhat.com
        description:
            Test attach sata cdrom clone from image service and then read the content in VM.
        key_steps:
            # Attach sata cdrom and then read it's content
        expect_result:
            No error threw and cdrom content right.
        debug_want:
            - output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        origin_disk_num = self._get_disk_num('rom')
        self.vm.stop(wait=True)
        try:
            self.vm.attach_disk('sata', 0, True, 0, False, 'clone_from_img_service', wait=True)
        except NotImplementedError:
            self.skipTest('attch disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('attch disk func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.timeout)
        new_disk_num = self._get_disk_num('rom')
        new_add_num = int(new_disk_num) - int(origin_disk_num)
        self.assertEqual(new_add_num, 1, "Number of new attached rom is not right Expect: %s, real: %s" % (1, new_add_num))
        new_add_device_name=utils_lib.run_cmd(self, 'blkid --label OEMDRV', expect_ret=0).split('\n')[0]
        cmd = "sudo mkdir /mnt/mnt_new_cdrom \n sudo mount {} /mnt/mnt_new_cdrom".format(new_add_device_name)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        read_new_device = utils_lib.run_cmd(self, "sudo ls /mnt/mnt_new_cdrom", expect_ret=0)
        self.assertIn("ks.cfg", read_new_device, msg="Read files from new added cdrom failed")
        #tear down
        disk_uuid = self.vm.get_disk_uuid('sata', 0)
        self.vm.stop(wait=True)
        try:
            self.vm.detach_disk('sata', disk_uuid, 0, wait=True)
        except NotImplementedError:
            self.skipTest('detach disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('detach disk func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        utils_lib.init_connection(self, timeout=self.timeout)

    def test_add_remove_multi_scsi(self):
        """
        case_name:
            test_add_remove_multi_scsi
        case_file:
            os_tests.tests.test_storage.TestStorage.test_add_remove_multi_scsi
        component:
            storage
        maintainer:
            mingli@redhat.com
        description:
            Test add and remove scsi disk of random size for 10 times in the VM.
        key_steps:
            # Attach/detach scsi disk with random size and check in 10 cycles.
        expect_result:
            No error threw and size check right.
        debug_want:
            - output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        for i in range(10):
            #get random device size
            random_dev_size = random.randint(1,10)
            self.log.info('test add remove scsi for {} time(s), and test size is {}'.format(i+1,random_dev_size))
            cmd = 'lsblk -d --output NAME|grep -v NAME'
            origin_lsblk_name_list = utils_lib.run_cmd(self, cmd, expect_ret=0).split('\n')
            origin_disk_num = self._get_disk_num('disk')
            try:
                self.vm.attach_disk('scsi', random_dev_size, False, 3, True, wait=True)
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
            disk_uuid = self.vm.get_disk_uuid('scsi', 1)
            try:
                self.vm.detach_disk('scsi', disk_uuid, 3, wait=True)
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
        time.sleep(30)
        if is_offline:
            self.vm.stop(wait=True)
        try:
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
            utils_lib.init_connection(self, timeout=self.timeout)
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
        utils_lib.init_connection(self, timeout=self.timeout)
        check_file = utils_lib.run_cmd(self, "ls ~/snpst*", expect_ret=0)
        self.assertIn(
                    "/home/cloud-user/snpst.txt",
                    check_file,
                    msg="~/snpst_root.txt not be recovered after VM restore")

    def test_online_take_restore_snapshot(self):
        """
        case_name:
            test_take_restore_snapshot
        case_file:
            os_tests.tests.test_storage.TestStorage.test_take_restore_snapshot
        component:
            storage
        maintainer:
            mingli@redhat.com
        description:
            Test take snapshot from VM and then restore it after removing file action.
        key_steps:
            1. Create a file ~/snp.test
            2. Take VM snapshot
            3. Remove the fail ~/snp.test
            4. Restore VM by the new snapshot, start VM, check the removed file exists after restore
        expect_result:
            No error threw and size check right.
        debug_want:
            - output from dmesg or journal
        """
        self._test_take_restore_snapshot(False)

    def test_offline_take_restore_snapshot(self):
        """
        case_name:
            test_take_restore_snapshot
        case_file:
            os_tests.tests.test_storage.TestStorage.test_take_restore_snapshot
        component:
            storage
        maintainer:
            mingli@redhat.com
        description:
            Test take snapshot from VM and then restore it after removing file action.
        key_steps:
            1. Create a file ~/snp.test
            2. Stop VM and then take VM snapshot
            3. Start VM an then remove the fail ~/snp.test
            4. Restore VM by the new snapshot, start VM, check the removed file exists after restore
        expect_result:
            No error threw and snapshot check right.
        debug_want:
            - output from dmesg or journal
        """
        self._test_take_restore_snapshot(True)

    def test_expand_scsi_disk_online(self):
        """
        case_name:
            test_expand_scsi_disk_online
        case_file:
            os_tests.tests.test_storage.TestStorage.test_expand_scsi_disk_online
        component:
            storage
        maintainer:
            mingli@redhat.com
        description:
            Expand SCSI disk when guest is running.
        key_steps:
            1. Login the guest and get the size of the SCSI disk.
            2. Expand the SCSI disk to a larger size.
            3. Check the disk size.
            4. Check the disk that should be readable and writeable
        expect_result:
            No error threw.
        debug_want:
            - output from dmesg or journal
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
        self.assertEqual(1, test_disk_origin_size, msg='disk size is not the same with init value, expect: {}, real: {}'.format(1*1024*1024, test_disk_origin_size))
        #Expand size of test disk when VM running
        try:
            self.disk.modify_disk_size(test_disk_origin_size, 'scsi', 1, 1)
        except NotImplementedError:
            self.skipTest('modify disk size func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('modify disk size func is not supported in {}'.format(self.vm.provider))
        #Get new size of test disk
        test_disk_new_size = int(utils_lib.run_cmd(self, cmd, expect_ret=0))/(1024*1024)
        self.assertEqual(2, int(test_disk_new_size), msg='disk size is not the same with init value, expect: {}, real: {}'.format(2*1024*1024, test_disk_new_size))
        #Test expanded disk can be read and write
        cmd='fallocate -l 2G 2G.img \n sudo mkfs -t xfs -f {} \n sudo mkdir /mnt/mnt_disk \n sudo mount {} /mnt/mnt_disk \n'.format(test_disk, test_disk)
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo cp 2G.img /mnt/mnt_disk', expect_ret=1, msg='No space left on device')
        init_file_size = int(utils_lib.run_cmd(self, "ls -l 2G.img | awk '{print $5}'", expect_ret=0).strip())/(1024*1024*1024)
        cp_file_size = int(utils_lib.run_cmd(self, "ls -l /mnt/mnt_disk/2G.img | awk '{print $5}'", expect_ret=0).strip())/(1024*1024*1024)
        self.assertAlmostEqual(
            first=float(init_file_size),
            second=float(cp_file_size),
            delta=0.1,
            msg="Gap is two much between copied file and origin file, Expect: %s, real: %s" %('0.1', init_file_size-cp_file_size)
        )
        #tear down
        utils_lib.run_cmd(self, 'sudo umount {}\n'.format(test_disk), expect_ret=0)

    def test_multi_disk(self):
        """
        case_name:
            test_multi_disk
        case_file:
            os_tests.tests.test_storage.TestStorage.test_multi_disk
        component:
            storage
        maintainer:
            mingli@redhat.com
        description:
            Add all four kinds of disk and test.
        key_steps:
            1. Login the guest and add scsi/pci/ide/sata disk
            2. Check bus type by lshw
            3. Check the disks' size.
            4. Check the disks that should be readable and writeable
        expect_result:
            No error threw and all check right.
        debug_want:
            - output from dmesg or journal
        """
        if not self.vm:
            self.skipTest("Skip this test case as no vm inited")
        scsi_set_size = random.randint(1,10)
        pci_set_size = random.randint(1,10)
        ide_set_size = random.randint(1,10)
        sata_set_size = random.randint(1,10)
        #attach scsi and pci disk
        for disk_type, disk_size in zip(['scsi','pci'],[scsi_set_size, pci_set_size]):
            try:
                self.vm.attach_disk(disk_type, disk_size, False, 2, True, wait=True)
            except NotImplementedError:
                self.skipTest('attach disk size func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('attach disk size func is not supported in {}'.format(self.vm.provider))
        #attach ide and sata disk
        self.vm.stop(wait=True)
        time.sleep(60)
        for disk_type, disk_size in zip(['ide','sata'],[ide_set_size, sata_set_size]):
            try:
                self.vm.attach_disk(disk_type, disk_size, False, 2, True, wait=True)
            except NotImplementedError:
                self.skipTest('attach disk size func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('attach disk size func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.timeout)
        #check disk number
        num_fdisk=int(utils_lib.run_cmd(self, "sudo fdisk -l | grep 'Disk /dev' | wc -l", expect_ret=0))
        num_lsblk=int(utils_lib.run_cmd(self, "sudo lsblk -d | grep disk | wc -l", expect_ret=0))
        self.assertEqual(num_fdisk, 6, msg='Disk number get from fdisk is not right')
        self.assertEqual(num_lsblk, 6, msg='Disk number get from lsblk is not right')
        #check disk bustype and size
        utils_lib.run_cmd(self, "sudo lshw -C disk -C storage", expect_ret=0)
        scsi_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-scsi:0' -A 63 | grep 'description: SCSI Disk' -A 13 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip().split()[-1]
        pci_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-scsi:1' -A 19 | grep '*-virtio' -A 7 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip()
        ide_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-ide' -A 38 | grep 'description: ATA Disk' -A 8 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip()
        sata_dev_name = utils_lib.run_cmd(self, "sudo lshw -C disk -C storage | grep '*-sata' -A 37 | grep 'description: ATA Disk' -A 9 | grep 'logical name:' | awk '{print $3}'", expect_ret=0).strip()
        scsi_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+scsi_dev_name, expect_ret=0))/(1024*1024)
        pci_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+pci_dev_name, expect_ret=0))/(1024*1024)
        ide_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+ide_dev_name, expect_ret=0))/(1024*1024)
        sata_dev_size = int(utils_lib.run_cmd(self, "sudo fdisk -s "+sata_dev_name, expect_ret=0))/(1024*1024)
        for bus_type, set_size, real_size in zip(['scsi', 'pci', 'ide','sata'], [scsi_set_size, pci_set_size, ide_set_size, sata_set_size],[scsi_dev_size, pci_dev_size, ide_dev_size, sata_dev_size]):
            self.assertEqual(set_size, real_size, msg="Size of %s disk is not right, Expect: %s, real: %s" % (bus_type, set_size, real_size))
        #check disk can be read and write
        for device_type, device_name in zip(['scsi','pci','ide','sata'], [scsi_dev_name, pci_dev_name, ide_dev_name, sata_dev_name]):
            create_file = '/mnt/mnt_{}/{}_touch_test.txt'.format(device_type, device_type)
            cmd = 'sudo mkfs.xfs {}\n sudo mkdir /mnt/mnt_{}\nsudo mount {} /mnt/mnt_{}\n sudo touch {}'.format(device_name, device_type, device_name, device_type, create_file)
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            check_file = utils_lib.run_cmd(self, 'ls {}'.format(create_file), expect_ret=0)
            self.assertIn(create_file, check_file, msg="Read files from new added disk failed")
        #hot detach scsi and pci disk
        disk_uuid = self.vm.get_disk_uuid('scsi', 2)
        try:
            self.vm.detach_disk('scsi', disk_uuid, 2, wait=True)
        except NotImplementedError:
            self.skipTest('detach disk func is not implemented in {}'.format(self.vm.provider))
        except UnSupportedAction:
            self.skipTest('detach disk func is not supported in {}'.format(self.vm.provider))
        utils_lib.run_cmd(self, "ls " + scsi_dev_name, expect_ret=2, expect_kw='No such file or directory')
        #dettach ide and sata disk
        self.vm.stop(wait=True)
        time.sleep(60)
        for device_type in ['ide','sata', 'pci']:
            disk_uuid = self.vm.get_disk_uuid(device_type, 2)
            try:
                self.vm.detach_disk(device_type, disk_uuid, 2, wait=True)
            except NotImplementedError:
                self.skipTest('detach disk size func is not implemented in {}'.format(self.vm.provider))
            except UnSupportedAction:
                self.skipTest('detach disk size func is not supported in {}'.format(self.vm.provider))
        self.vm.start(wait=True)
        time.sleep(30)
        utils_lib.init_connection(self, timeout=self.timeout)
        utils_lib.run_cmd(self, "ls " + ide_dev_name, expect_ret=2, expect_kw='No such file or directory')
        utils_lib.run_cmd(self, "ls " + sata_dev_name, expect_ret=2, expect_kw='No such file or directory')
        utils_lib.run_cmd(self, "ls " + pci_dev_name, expect_ret=2, expect_kw='No such file or directory')

    def tearDown(self):
        if 'blktests' in self.id():
            utils_lib.check_log(self, "trace", log_cmd='dmesg -T', cursor=self.cursor)
        else:
            utils_lib.check_log(self, "error,warn,fail,trace", log_cmd='dmesg -T', cursor=self.cursor)

if __name__ == '__main__':
    unittest.main()