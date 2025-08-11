# this file run rhcert test suite and collect the required cert log
# 2 vms or 2 hosts are required to run full test
import unittest
from os_tests.libs import utils_lib
from datetime import datetime
import time
import os
import re

class TestRHELCert(unittest.TestCase):


    def _collect_debug_log(self, prefix=''):
        self.log.info("Collect run logs for further debug")
        utils_lib.run_cmd(self, 'sudo ls -l /var/rhcert/*')
        debug_run_file = "{}_{}_rhcert_run.tar".format(self.id().split('.')[-1],prefix.replace('/','_'))
        rmt_file = "/tmp/{}".format(debug_run_file)
        utils_lib.run_cmd(self, "sudo bash -c 'cd /var/log;tar -zcf {} rhcert/runs/'".format(rmt_file))
        utils_lib.run_cmd(self, "sudo chmod 777 {}".format(rmt_file))
        local_file='{}/attachments/{}'.format(self.log_dir,debug_run_file)
        self.SSH.get_file(rmt_file=rmt_file,local_file=local_file)

    def _wait_cert_done(self, timeout=1200, interval=30, prefix=''):
        timeout = timeout
        interval = interval
        prefix = str(prefix)
        time_start = int(time.time())
        while True:
           cmd = 'sudo ls /var/lock/subsys/rhcert'
           ret = utils_lib.run_cmd(self,cmd,ret_status=True)
           if int(ret) != 0:
                cmd = 'sudo bash -c "rhcert-cli print"'
                out = utils_lib.run_cmd(self,cmd, timeout=1800, msg='print cert result')
                if 'INCOMPLETE' in out:
                   self.log.info("INCOMPLETE task found, wait it done")
                elif 'Traceback' in out:
                    self._collect_debug_log(prefix)
                    return False
                else:
                    break
           time_end = int(time.time())
           if time_end - time_start > timeout:
              self.log.info('timeout ended: {}'.format(timeout))
              self._collect_debug_log(prefix)
              cmd = 'sudo bash -c "rm -rf /var/rhcert/*"'
              utils_lib.run_cmd(self,cmd, msg='cleanup the test result to avoid impact other result')
              return False
           self.log.info('wait rhcert finish, retry after {}s'.format(interval))
           time.sleep(interval)
        cmd = 'sudo bash -c "yes|rhcert-cli save"'
        out = utils_lib.run_cmd(self,cmd, msg='save test result')
        if 'xml' not in out:
            self.fail("xml format result expected")
        result_path = re.findall("/.*xml", out)[0]
        local_file='{}/attachments/{}_{}_{}'.format(self.log_dir,self.id().split('.')[-1],prefix.replace('/','_'),os.path.basename(result_path))
        self.SSH.get_file(rmt_file=result_path,local_file=local_file)
        cmd = 'sudo bash -c "rm -rf /var/rhcert/*"'
        utils_lib.run_cmd(self,cmd, msg='cleanup the test result')
        return True

    def _parted_swap_partition(self, root_vol):
        swap_start = root_vol.size + 4
        swap_end = root_vol.size + 18
        if not root_vol.modify_disk_size(expand_num=20):
            self.fail("cannot extend disk size")
        parts = utils_lib.run_cmd(self, "lsblk -r -o NAME,TYPE|grep part|sort|awk -F' ' '{print $1}'")
        tmp_parts_list = parts.split('\n')
        parts_list = [ i for i in tmp_parts_list if i ]
        parts_list.sort()
        new_part = parts_list[-1][:-1] + str(len(parts_list) + 1)
        disks = utils_lib.run_cmd(self, "lsblk -d -o NAME")
        root_disk = '/dev/nvme0n1'
        for disk in disks.split('\n'):
            if disk and disk in parts:
                root_disk = '/dev/{}'.format(disk)
                break
        self.log.info("boot disk:{}, new part:{}".format(root_disk,new_part))
        part_count = utils_lib.run_cmd(self, "lsblk|grep part|wc -l")
        part_count = int(part_count.strip('\n')) + 1
        utils_lib.run_cmd(self,'sudo sgdisk {} -e'.format(root_disk), timeout=180)
        utils_lib.run_cmd(self,'sudo parted -f -s {} print'.format(root_disk), timeout=180, msg='run with -f option in case sgdisk not found')
        utils_lib.run_cmd(self,'sudo parted -s {} print'.format(root_disk), timeout=180, msg='run again in case parted not support -f option')
        cmds = ['sudo parted -s {} mkpart swap xfs {}G {}G'.format(root_disk,swap_start,swap_end),
            'sudo parted -s {} print'.format(root_disk),
            'lsblk',
            'swapoff -a',
            'sudo mkswap /dev/{}'.format(new_part),
            'sudo swapon /dev/{}'.format(new_part),
            'sudo cat /proc/swaps',
            'sudo cat /proc/partitions']
        for cmd in cmds:
            utils_lib.run_cmd(self,cmd, expect_ret=0, timeout=180)

    def setUp(self):
        utils_lib.init_case(self)
        if not self.is_rmt:
            self.skipTest('only run on remote')
        if len(self.vms) < 2 and len(self.params.get('remote_nodes')) < 2:
            self.skipTest('2 nodes required!')
        if len(self.vms) > 1:
           if not self.vms[1].exists():
               self.vms[1].create()
           utils_lib.init_connection(self, timeout=self.ssh_timeout, rmt_node=self.vms[1].floating_ip)
           self.params['remote_nodes'].append(self.vms[1].floating_ip)
        utils_lib.init_connection(self, timeout=self.ssh_timeout, rmt_node=self.params['remote_nodes'][-1])
        #Install redhat certification packages
        cmd = 'sudo rpm -qa | grep redhat-certification'
        ret1 = utils_lib.run_cmd(self, cmd, ret_status=True)
        ret2 = utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1], ret_status=True)
        if ret1 == 0 and ret2 == 0:
            cmd = 'sudo bash -c "rm -rf /var/rhcert/*"'
            utils_lib.run_cmd(self, cmd, msg='cleanup prior test result')
        else:
            utils_lib.rhsm_register(self, cancel_case=True)
            utils_lib.rhsm_register(self, cancel_case=True, rmt_node=self.params['remote_nodes'][-1])
            cmds_enablerepo = [ "sudo subscription-manager status",
                                "sudo sleep 10",
                                "sudo subscription-manager config --rhsm.manage_repos=1",
                                "sudo sleep 10",
                                "sudo dnf repolist all | grep cert",
                                "sudo sleep 10",
                                "sudo subscription-manager repos --enable cert-1-for-rhel*",
                                "sudo sleep 10",
                                "sudo subscription-manager repos --enable *baseos-debug-rpms" ]
            for cmd in cmds_enablerepo:
                utils_lib.run_cmd(self, cmd, timeout=600, expect_ret=0)
                utils_lib.run_cmd(self, cmd, timeout=600, rmt_node=self.params['remote_nodes'][-1], expect_ret=0)
            rpm_pkgs_rhcert = ["redhat-certification", "redhat-certification-hardware", "redhat-certification-cloud"]
            for rpm_pkg in rpm_pkgs_rhcert:
                utils_lib.is_pkg_installed(self, timeout=600, pkg_name=rpm_pkg, is_install=True, cancel_case=True)
                utils_lib.is_pkg_installed(self, timeout=600, pkg_name=rpm_pkg, is_install=True, cancel_case=True, rmt_node=self.params['remote_nodes'][-1])
        cmd = 'sudo bash -c "mkdir -p /var/www/rhcert/export/var/crash"'
        utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1])
        cmd = 'sudo bash -c "chmod -R 777 /var/www/rhcert/export/"'
        utils_lib.run_cmd(self, cmd, rmt_node=self.params['remote_nodes'][-1])
        # net.ifnames=0 is not recommended in RHEL-10 COMPOSER-2289, so the nic name is dynamically.
        # the 2 clients might have different interfacenames, so look for them separetly  
        self.active_nic = utils_lib.get_active_nic(self,rmt_node=self.params['remote_nodes'][0], ret_nic_name=True)
        self.rmt_ipv4 = utils_lib.get_active_nic(self,rmt_node=self.params['remote_nodes'][-1], ret_nic_name=False)
        cmd = 'sudo bash -c "rhcertd start"'
        utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1], msg="start rhcertd on test server")
        cmd = 'sudo cat /root/.ssh/id_rsa.pub'
        out = utils_lib.run_cmd(self, cmd, msg='check if root login is enabled')
        if 'No such file' in out:
            cmd = 'sudo bash -c "echo |ssh-keygen -t rsa"'
            out = utils_lib.run_cmd(self, cmd)
            cmd = 'sudo cat /root/.ssh/id_rsa.pub'
            out = utils_lib.run_cmd(self, cmd)
            if 'No such file' in out:
                self.log.info('Cannot get pub key from hut')
        cmd = 'sudo bash -c "echo \'{}\' >> /root/.ssh/authorized_keys"'.format(out)
        utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1], msg='add pub key to test server')
        cmd = 'sudo bash -c "ssh -o StrictHostKeyChecking=no root@{} ip addr"'.format(self.rmt_ipv4)
        utils_lib.run_cmd(self, cmd, msg="test cmd execution on remote without password")
        cmd = 'sudo bash -c "systemctl disable --now firewalld"'.format(out)
        utils_lib.run_cmd(self, cmd, expect_ret=0, rmt_node=self.params['remote_nodes'][-1], msg='disable firewalld')

        if self.id().endswith(('test_rhcert_pcie_nvme','test_rhcert_non_interactive')):
            if os.getenv('INFRA_PROVIDER') == 'aws':
            #if 'aws' in self.vm.provider:
                root_id = self.vm.get_volume()
                root_vol = None
                for disk in self.disks:
                    if not disk.is_exist() or disk.is_free():
                        root_vol = disk
                        break
                if not root_vol:
                    self.fail("No free disk to pick up")
                root_vol.load(root_id)
                self._parted_swap_partition(root_vol)

            if os.getenv('INFRA_PROVIDER') == 'ali':
                root_vol = None
                for disk in self.disks:
                    if not disk.is_exist():
                        root_vol = disk
                        break
                if not root_vol:
                    self.fail("No free disk to pick up")
                root_id,root_size = self.vm.get_system_disk()
                root_vol.id = root_id
                root_vol.size = root_size
                self._parted_swap_partition(root_vol)
            if os.getenv('INFRA_PROVIDER') == 'azure':
                # Add 1G swap
                # dd if=/dev/zero of=/root/swapfile01 bs=1M count=1024
                # chmod 600 /root/swapfile01
                # mkswap -L swap01 /root/swapfile01
                # swapon /root/swapfile01

                cmd = "sudo free -g | awk '/^Mem:/ {print $2}'"
                mem_output = utils_lib.run_cmd(self, cmd).rstrip('\n')
                self.log.info("Current total mem is {}G".format(mem_output))

                if int(mem_output) <= 800 :
                    count = 4096   # 4G
                elif int(mem_output) <= 10000:
                    count = 10240   # 10G
                elif int(mem_output) > 10000:
                    count = 32768  # 32G
                self.log.info("The swap will be set as {}M".format(count))

                new_part="swapfile01"
                cmds = ['sudo dd if=/dev/zero of=/root/{} bs=1M count={}'.format(new_part,count),
                'sudo chmod 600 /root/{}'.format(new_part),
                'sudo mkswap -L swap01 /root/{}'.format(new_part),
                'sudo swapon /root/{}'.format(new_part),
                'sudo cat /proc/swaps']
                for cmd in cmds:
                    utils_lib.run_cmd(self,cmd,timeout=720)
                
                cmd = "sudo free -g"
                memnew_output = utils_lib.run_cmd(self, cmd).rstrip('\n')
                self.log.info("The free -g status is \n {}".format(memnew_output))

                # Add a 4G size data disk if without data disk which is required by Azure storage case
                if int(self.vm.disk_count()) == 0:
                    time_filename = datetime.now().strftime("%Y%m%d_%H%M%S")
                    data_disk_name ='date_disk_{}_{}'.format(self.vm.vm_name,time_filename)
                    self.vm.disk_attach(data_disk_name, 4)
 
    def test_rhcert_non_interactive(self):
        """
        case_tags:
            certification
        title:
            Run rhcert test suite
        importance:
            Low
        subsystem_team:
            rhel-sst-virtualization-cloud
        automation_drop_down:
            automated
        linked_work_items:
            jira_RHELBU-1991
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_rhel_cert.py
        setup_teardown: |
            os-tests do not deploy the cert environment itself, it only run and collect the test result.
            1. Download required cert pkgs from https://access.redhat.com/downloads/content/282/ver=9/rhel---9/9/x86_64/packages.
            'redhat-certification' and 'redhat-certification-hardware' are must required for instance type cert.
            'redhat-certification-cloud' is for image certification which is not used.
               - test files: /usr/lib/python3.9/site-packages/rhcert/suites/hwcert/tests
            2. Install the required pkgs:
               - yum update -y
               - yum install -y kernel-abi-stablelists lvm2 libvirt
               - yum -q -y --enablerepo=* install kernel-debuginfo
            3. Disable firewall if it is enabled.
               - systemctl disable firewalld
        environment:
            see setup_teardown
        case_name:
            test_rhcert
        component:
            certification
        bug_id:
            N/A
        is_customer_case:
            False
        testplan:
            N/A
        maintainer:
            xiliang@redhat.com
        description: |
            Run RHEL hwcert test.
        key_steps: |
            1. 2 nodes with the same cert pkgs installed from setup_teardown.
               this step is done during test run.
               - 2 nodes can login each with root
               - node1 acts as sut and node2 act as test server(nfs, network endpoints......)
               - node1: rhcert-provision <path_to_test_plan_document>
               - node2: rhcert-provision --role test-server <path_to_test_plan_document>
            2. Run test on node1
               -rhcert-cli run
               -rhcert-cli continue(not needed)
               -rhcert-cli save (save test result to xml)
        expected_result: |
            The test will copy result xml to local result dir.
            It is in node1 system with below format.
            /var/rhcert/save/rhcert-results-xxxxxx.internal-20221010070227.xml
        debug_want: |
            N/A
        """
        test_disk = 'nvme1n1'
        #test_disk = utils_lib.get_test_disk(self) or test_disk

        #cmds = ['sudo bash -c "dd if=/dev/zero of=/swap bs=1024 count=2000000"',
        #'sudo bash -c "chmod 0600 /swap"',
        #'sudo bash -c "mkswap /swap"',
        #'sudo bash -c "swapon /swap"' ]
        #for cmd in cmds:
        #    utils_lib.run_cmd(self,cmd, timeout=180)
        self.log.info("Please make sure you have swap partition in your disk")
        cmd = 'sudo bash -c "yes|rhcert-cli plan"'
        auto_plan = utils_lib.run_cmd(self,cmd, timeout=3600, msg='create test plan')
        subtests = []
        subtests.append('hwcert/memory')
        # case name denpends on cert pkg version, the latest cert tool cannot recognize hwcert/xxx cases
        subtests.append('memory')
        subtests.append('hwcert/core')
        subtests.append('core')
        subtests.append('hwcert/profiler_hardware_core')
        subtests.append('profiler_hardware_core')
        if 'profiler_hardware_core' not in auto_plan:
            subtests.append('hwcert/profiler_software')
            subtests.append('profiler_software')
        if 'profiler_hardware_uncore' in auto_plan:
            subtests.append('hwcert/profiler_hardware_uncore')
            subtests.append('profiler_hardware_uncore')
        if 'NVMe' in auto_plan:
            subtests.append('PCIE_NVMe')
        if 'STORAGE' in auto_plan:
            subtests.append('STORAGE')
        if not utils_lib.is_arch(self, 'aarch64' ) and os.getenv('INFRA_PROVIDER') != 'azure':
            subtests.append('hwcert/cpuscaling')
            subtests.append('cpuscaling')

        if self.params.get('subtests'):
            self.log.info('Found subtests in params:{}'.format(self.params.get('subtests')))
            subtests = self.params.get('subtests').split()
        self.log.info("Will run subtests: {}".format(subtests))
        for case in subtests:
            cmd = 'sudo bash -c "yes|rhcert-cli run --test {}"'.format(case)
            out = utils_lib.run_cmd(self,cmd, timeout=7200, msg='run {}'.format(case))
            if "No such test" in out:
                self.log.info("the case might not in plan and support:{}".format(case))
                continue
            self._wait_cert_done(prefix=case)
        #else:
        #    #cmd = 'sudo bash -c "yes|rhcert-cli run --tag non-interactive --device {}"'.format(test_disk)
        #    cmd = 'sudo bash -c "yes|rhcert-cli run --tag non-interactive"'
        #    utils_lib.run_cmd(self,cmd, timeout=28800, msg='start to run non-interactive cert test')
        #    self._wait_cert_done()

    def test_rhcert_kdump(self):
        """
        This case will not run in xen.
        Not support in xen instance, https://access.redhat.com/solutions/2890881
        """
        cmd = 'sudo bash -c "yes|rhcert-cli plan"'
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='create test plan')
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_not_kw="Xen", msg="Not support in xen instance")
        run_local = True
        run_nfs = True
        if self.params.get('subtests'):
            self.log.info('Found subtests in params:{}'.format(self.params.get('subtests')))
            if 'local' not in self.params.get('subtests'):
                run_local = False
            if 'nfs' not in self.params.get('subtests'):
                run_nfs = False
        if run_local:
            cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device local"'
            utils_lib.run_cmd(self,cmd, timeout=3600, msg='run kdump local test')
            if not self.SSH.is_active():
                utils_lib.init_connection(self, timeout=self.ssh_timeout*2)
            time.sleep(30)
            self._wait_cert_done(prefix='local')
        if run_nfs:
            utils_lib.is_pkg_installed(self,'nfs-utils')
            kdump_nfs_server = self.params.get('kdump_nfs_server')
            if kdump_nfs_server:
                self.log.info('Found kdump_nfs_server in params:{}'.format(kdump_nfs_server))
                cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device nfs --server {}"'.format(kdump_nfs_server)
            else:
                cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device nfs --server {}"'.format(self.rmt_ipv4)
            utils_lib.run_cmd(self,cmd, timeout=3600, msg='run kdump nfs test')
            if not self.SSH.is_active():
                utils_lib.init_connection(self, timeout=self.ssh_timeout*2)
            time.sleep(30)
            self._wait_cert_done(prefix='nfs')

    def test_rhcert_kdump_aws_arm_irqpoll(self):
        '''
        run the same test with test_rhcert_kdump, if test_rhcert_kdump fail and this case pass, that means they are the same issue with https://access.redhat.com/articles/6562431.
        Not support in xen instance, https://access.redhat.com/solutions/2890881
        '''
        if not self.SSH.is_active() and self.vm:
            self.vm.stop(wait=True)
            self.vm.start()
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not utils_lib.is_aws(self):
            self.skipTest("No need to run it because it is aws specified")
        if not utils_lib.is_arch(self, 'aarch64'):
            self.skipTest("Only for arm instances")
        if utils_lib.is_metal(self):
            self.skipTest("Only for virtual arm instances")
        product_id = utils_lib.get_os_release_info(self, field='VERSION_ID')
        if float(product_id) >= 10.0:
            self.skipTest('kdump-utils integrated the workaround in RHEL-10, no need to re-test')
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0, cancel_not_kw="Xen", msg="Not support in xen instance")

        self.log.info("aws aarch64 non-metal instance found, remove irqpoll if it is used following https://access.redhat.com/articles/6562431")
        update_kdump_cfg = False
        cmd = 'sudo grep irqpoll /etc/sysconfig/kdump |grep KDUMP_COMMANDLINE_REMOVE'
        ret = utils_lib.run_cmd(self, cmd, ret_status=True)
        if ret != 0:
            cmd = 'sudo bash -c " sed -i \'/KDUMP_COMMANDLINE_REMOVE=/s/quiet/quiet irqpoll/g\'  /etc/sysconfig/kdump"'
            utils_lib.run_cmd(self, cmd, msg='add irqpoll to KDUMP_COMMANDLINE_REMOVE')
            update_kdump_cfg = True
        cmd = 'sudo grep irqpoll /etc/sysconfig/kdump |grep KDUMP_COMMANDLINE_APPEND'
        ret = utils_lib.run_cmd(self, cmd, ret_status=True)
        if ret == 0:
            cmd = 'sudo bash -c "sed -i \'/KDUMP_COMMANDLINE_APPEND=/s/irqpoll //g\'  /etc/sysconfig/kdump"'
            utils_lib.run_cmd(self, cmd, msg='remove irqpoll from KDUMP_COMMANDLINE_APPEND')
            update_kdump_cfg = True
        if update_kdump_cfg:
            cmd = 'sudo cat /etc/sysconfig/kdump'
            utils_lib.run_cmd(self, cmd, msg='updated kdump')
            cmd = 'sudo systemctl restart kdump'
            utils_lib.run_cmd(self, cmd, msg='restart kdump')
        cmd = 'sudo bash -c "yes|rhcert-cli plan"'
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='create test plan')
        cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device local"'
        utils_lib.run_cmd(self,cmd, timeout=3600, msg='run kdump local test')
        if not self.SSH.is_active():
            utils_lib.init_connection(self, timeout=self.ssh_timeout*8)
        time.sleep(30)
        self._wait_cert_done(prefix='local_irqpoll')
        utils_lib.is_pkg_installed(self,'nfs-utils')
        cmd = 'sudo bash -c "yes|rhcert-cli run --test kdump --device nfs --server {}"'.format(self.rmt_ipv4)
        utils_lib.run_cmd(self,cmd, timeout=3600, msg='run kdump nfs test')
        if not self.SSH.is_active():
            utils_lib.init_connection(self, timeout=self.ssh_timeout*2)
        time.sleep(30)
        self._wait_cert_done(prefix='nfs_irqpoll')

    def test_rhcert_ethernet(self):
        
        net_bandwidth = self.params.get('net_bandwidth') or 50

        if self.vm and hasattr(self.vm, 'net_bandwidth'):
            net_bandwidth = self.vm.net_bandwidth
        if net_bandwidth <= 5:
            net_bandwidth = 5
        elif net_bandwidth <= 10:
            net_bandwidth = 10
        elif net_bandwidth <= 20:
            net_bandwidth = 20
        elif net_bandwidth <= 25:
            net_bandwidth = 25
        elif net_bandwidth <= 40:
            net_bandwidth = 40
        elif net_bandwidth <= 50:
            net_bandwidth = 50
        elif net_bandwidth <= 100:
            net_bandwidth = 100
        elif net_bandwidth <= 200:
            net_bandwidth = 200
        elif net_bandwidth <= 400:
            net_bandwidth = 400
        else:
            # cert test suite max support 400
            net_bandwidth = 400
        cmd = 'sudo bash -c "yes|rhcert-cli plan --add --test {}GigEthernet --device {} --server {}"'.format(net_bandwidth,self.active_nic,self.rmt_ipv4)
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='create test plan')
        cmd = 'sudo bash -c "yes|rhcert-cli run --test {}GigEthernet --device {} --server {}"'.format(net_bandwidth,self.active_nic,self.rmt_ipv4)
        utils_lib.run_cmd(self,cmd, timeout=1800, msg='run ethernet test')
        time.sleep(20)
        self._wait_cert_done(prefix=net_bandwidth)

    def test_rhcert_only_metal(self):
        """
        metal instance only
        """
        if not utils_lib.is_metal(self):
            self.skipTest("Only run on metal instance")
        cmd = "sudo rm -rf /etc/libvirt/qemu/hwcert-x86_64.xml"
        utils_lib.run_cmd(self,cmd, msg='delete it if exists')
        cmd = 'sudo bash -c "yes|rhcert-cli plan"'
        auto_plan = utils_lib.run_cmd(self,cmd, timeout=3600, msg='create test plan')
        # case name denpends on cert pkg version, the latest cert tool cannot recognize hwcert/xxx cases
        subtests = []
        if 'fv_core' in auto_plan:
            subtests.append('hwcert/fvtest/fv_core')
            subtests.append('fv_core')
        if 'fv_memory' in auto_plan:
            subtests.append('hwcert/fvtest/fv_memory')
            subtests.append('fv_memory')
        if self.params.get('subtests'):
            self.log.info('Found subtests in params:{}'.format(self.params.get('subtests')))
            subtests = self.params.get('subtests').split()

        self.log.info("Will run subtests: {}".format(subtests))
        for case in subtests:
            cmd = 'sudo bash -c "yes|rhcert-cli run --test {}"'.format(case)
            #out = utils_lib.run_cmd(self,cmd, timeout=3600, msg='run {}'.format(case),rmt_redirect_stdout=True, rmt_redirect_stderr=True,rmt_get_pty=True)
            out = utils_lib.run_cmd(self,cmd, timeout=7200, msg='run {}'.format(case),rmt_get_pty=True)
            if "No such test" in out:
                self.log.info("the case might not in plan and support")
                continue
            self._wait_cert_done(prefix=case)

    def tearDown(self):
        # Only ethernet and kdump over nfs require the 2nd vm.
        # Stop the 2nd vm after test done on azure for saving cost.
        # aws keeps the 2nd vm because it takes long time to restart a metal insatnce over 20mins
        #if os.getenv('INFRA_PROVIDER') == 'azure':
        #    if len(self.vms) > 1:
        #       if self.vms[1].exists():
        #           self.vms[1].delete()
        utils_lib.finish_case(self)

if __name__ == '__main__':
    unittest.main()
