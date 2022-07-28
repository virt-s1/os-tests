import unittest
from os_tests.libs import utils_lib


class TestAzureUpgradeCheck(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        if not utils_lib.is_azure(self):
            self.skipTest('Only run for azure leapp checking.')

    @property
    def rhel_x_version(self):
        product_id = utils_lib.get_product_id(self)
        return int(product_id.split('.')[0])

    def _get_generation(self):
        '''
        Get genenration from dmesg. Return gen1/gen2.
        '''
        ret = utils_lib.run_cmd(self, 'dmesg|grep -w EFI', ret_status=True)
        if ret == 0:
            return 'gen2'
        else:
            return 'gen1'

    def _check_log(self, filename, ignore_list=[], keyword='err|fail|warn|trace'):
        cmd = "sudo grep -iE 'err|fail|warn|trace' {}|grep -vE '{}'".format(filename, '|'.join(ignore_list))
        output = utils_lib.run_cmd(self, cmd, msg="Check {} in {}".format(keyword, filename))
        if output:
            self.log.info("Unexpected logs exist in {}.\n{}".format(filename, output))
            return False
        else:
            self.log.info("No unexpected logs in "+filename)
            return True


    ######## Test cases ########
    def test_check_cmdline_crashkernel(self):
        '''
        crashkernel should be enabled in image
        '''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('9'):
            expect_kw = 'crashkernel=auto'
        else:
            # rhbz: 1942398
            if utils_lib.is_arch(self, arch='x86_64'):
                expect_kw = 'crashkernel=1G-4G:192M,4G-64G:256M,64G-:512M'
            else:
                expect_kw = 'crashkernel=2G-:448M'
        utils_lib.run_cmd(self, "sudo cat /proc/cmdline", expect_ret=0, expect_kw=expect_kw, msg='check crashkernel is enabled')

    def test_check_cmdline_rhgb_quiet(self):
        '''
        rhbz: 1122300
        check no "rhgb" and "quiet" in /proc/cmdline
        '''
        utils_lib.run_cmd(self, "sudo cat /proc/cmdline", expect_ret=0, expect_not_kw='rhgb,quiet', msg='check no rhgb and quiet in boot cmd')

    def test_check_cpu_flags(self):
        '''
        rhbz: 1061348
        check various cpu flags
        '''
        utils_lib.is_arch(self, arch='x86_64', action='cancel')
        cmd = "sudo cat /proc/cpuinfo"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='avx,xsave,pcid', msg='check avx,xsave,pcid flags')

    def test_check_pkg_wanted(self):
        '''
        Verify requied pkgs are installed.
        '''
        pkgs_wanted = '''cloud-init,NetworkManager,cloud-utils-growpart,gdisk,WALinuxAgent,\
hypervkvpd,hyperv-daemons-license,hypervfcopyd,hypervvssd,hyperv-daemons'''
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < float('8'):
            pkgs_wanted += ''',dhclient'''
        else:
            pkgs_wanted += ''',insights-client,dhcp-client'''
        pkgs_wanted_list = pkgs_wanted.split(',')
        for pkg in pkgs_wanted_list:
            cmd = 'rpm -q {}'.format(pkg)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check {} installed'.format(pkg))

    def test_check_no_avc_denials(self):
        '''
        check there is no avc denials (selinux)
        '''
        cmd = "x=$(sudo ausearch -m AVC,USER_AVC -ts boot 2>&1 &); echo $x"
        utils_lib.run_cmd(self, cmd, expect_kw='no matches', msg='check no avc denials')

    def test_check_timezone(self):
        '''
        check that the default timezone is EDT
        '''
        utils_lib.run_cmd(self, 'date', expect_kw='EDT', msg='check timezone is EDT')

    # def test_check_selinux(self):
    #     '''
    #     SELinux should be in enforcing/targeted mode
    #     '''
    #     utils_lib.run_cmd(self, 'uname -r', msg='get kernel version')
    #     utils_lib.run_cmd(self, 'sudo getenforce',expect_kw='Enforcing', msg='check selinux current mode is Enforcing')
    #     utils_lib.run_cmd(self, 'sudo cat /etc/sysconfig/selinux',expect_kw='SELINUX=enforcing,SELINUXTYPE=targeted', msg='check selinux current setting')

    def test_check_services_active(self):
        '''
        Verify the necessary services are active
        '''
        services = '''waagent,cloud-init-local,cloud-init,cloud-config,cloud-final,hypervkvpd,sshd'''
        service_list = services.split(',')
        for service in service_list:
            cmd = 'systemctl is-active {}'.format(service)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check {} is active'.format(service))

    def test_check_kdump_status(self):
        '''
        Verify the kdump is enabled
        '''
        cmd = "sudo kdumpctl status"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='Kdump is operational', msg='Check kdump status')

    def test_check_messages(self):
        '''
        Verify no error/fail/trace in /var/log/messages
        '''
        ignore_list = [
            'Failed to init entropy source hwrng',
            'Failed to register legacy timer interrupt',
            'augenrules.*failure 1',
            'cloud-init.*handlers.py.*failed to truncate kvp pool file',
            'nofail',
            'Errors: 0',
            'kernel version.*failed early load check for .*, skipping',
            'Failed determining last makecache time',
            'kernel: ftrace',
            'switching default tracing clock'
        ]
        self._check_log('/var/log/messages', ignore_list, 'error|fail|trace')

    def test_check_dmesg(self):
        '''
        Verify no err/fail/warn/trace in dmesg
        '''
        ignore_list = [
            'override',
            'ftrace',
            'deferred',
            'interrupt',
            'Failed to register legacy timer interrupt',
            'trace_clock=local'
        ]
        utils_lib.run_cmd(self, 'dmesg > /tmp/dmesg.log')
        self._check_log('/tmp/dmesg.log', ignore_list)

    def test_check_cloudinit_log(self):
        '''
        Verify no err/fail/warn/trace in /var/log/cloud-init.log
        '''
        ignore_list = [
            'failed to truncate kvp pool file',
            'finish: azure-ds/load_azure_ds_dir: FAIL: load_azure_ds_dir',
            'tracefs',
            'errors=remount-ro',
            'dhclient error stream',
            'util.py.DEBUG.: Failed mount of ./dev/sdb1. as .ntfs.',
            'Stderr: mount: .*: unknown filesystem type .ntfs.',
            'SKIPPED: device_part_info.* failed: /dev/mapper/rootvg-rootlv not a partition',
            'modules with 0 failures',
            'Failed to get raw userdata in module rightscale_userdata'
        ]
        self._check_log('/var/log/cloud-init.log', ignore_list)

    def test_check_waagent_log(self):
        '''
        Verify no err/fail/warn/trace in /var/log/waagent.log
        '''
        ignore_list = [
            'preferred',
            'Dhcp client is not running',
            'Move rules file 70-persistent-net.rules',
            'UpdateGSErrors: 0'
        ]
        self._check_log('/var/log/waagent.log', ignore_list)

    def test_check_journal_log(self):
        '''
        Verify no traceback|ordering in journalctl -xl
        '''
        ignore_list = []
        utils_lib.run_cmd(self, 'sudo journalctl -xl > /tmp/journal.log')
        self._check_log('/tmp/journal.log', ignore_list, 'traceback|ordering')

    def test_check_no_fail_service(self):
        '''
        Verify no failed service
        '''
        utils_lib.run_cmd(self, 'sudo systemctl list-units|grep -i fail', expect_not_ret=0, msg="Verify no failed service.")

    def test_check_hyperv_drivers(self):
        '''
        Verify hyperv drivers are loaded
        '''
        hyperv_driver_list = [
            'hv_utils',
            'hv_balloon',
            'hv_storvsc',
            'scsi_transport_fc',
            'hid_hyperv',
            'hv_netvsc',
            'hyperv_keyboard',
            'hv_vmbus'
        ]
        if self.rhel_x_version <= 8:
            hyperv_driver_list.append('hyperv_fb')
        else:
            hyperv_driver_list.append('hyperv_drm')
        cmd = "/sbin/lsmod|grep -iE 'hv|hyperv'"
        utils_lib.run_cmd(self, cmd, expect_kw=','.join(hyperv_driver_list), msg="Verify hyperv drivers are loaded")

    def test_check_hostkey_permission(self):
        '''
        bz: 2013644
        Verify /etc/ssh/ssh_host_xxx_key permission are 640, group is ssh_keys.
        '''
        expected = "-rw-r-----.rootssh_keys"
        cmd = "ls -l /etc/ssh/{ssh_host_ecdsa_key,ssh_host_ed25519_key,ssh_host_rsa_key}|awk '{print $1$3$4}'|uniq"
        utils_lib.run_cmd(self, cmd, expect_output=expected, msg="Verify /etc/ssh/ssh_host_xxx_key permission is 640, group is ssh_keys")

    def test_check_image_generation(self):
        '''
        Check generation according to vm name
        '''
        hostname = utils_lib.run_cmd(self, 'hostname')
        if 'gen1' in hostname:
            self.assertEqual(self._get_generation(), 'gen1', "Expected: gen1; Real: gen2")
        else:
            self.assertEqual(self._get_generation(), 'gen2', "Expected: gen2; Real: gen1")
