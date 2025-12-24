import unittest
import os
import secrets
import time
import re
from os_tests.libs import utils_lib
from os_tests.libs import version_util
from os_tests.libs.resources import UnSupportedAction
from parameterized import parameterized
from os_tests.libs.resources_azure import AzurePublicIP
from os_tests.libs.resources_azure import AzureNIC
from os_tests.libs.resources_azure import AzureNicIpConfig
from os_tests.libs.resources_azure import AzureImage
from os_tests.libs.resources_azure import AzureNSG

#this class is the collection of cases that require new vm
class TestCloudInitNewVM(unittest.TestCase):
    def setUp(self):
        #do not create vm in init_case, because it will create new vm in test case
        self.createvm = False
        self.cloudinit_version = None
        utils_lib.init_case(self)

    @property
    def rhel_x_version(self):
        #not all resources support this parameter rhel_ver now, only openstack, kvm and azure
        if self.vm.rhel_ver:
            return int(self.vm.rhel_ver.split('.')[0])

    def _check_cloudinit_done(self):
        # if cloud-init status is running, waiting
        # set timeout to prevent the infinite loop when loud-init is kept in running status
        for count in utils_lib.iterate_timeout(
            600, "check cloud-init status", wait=20):
            res = utils_lib.run_cmd(self, "sudo cloud-init status")
            if not re.search('status: running', res): break
        # check cloud-init status is done
        cmd = 'sudo cloud-init status'
        utils_lib.run_cmd(self, cmd, expect_kw='status: done', msg='Get cloud-init status')
        #output cloud-init version
        package_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
        version = version_util.get_version(package_ver,'cloud-init-')
        self.cloudinit_version =  version

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

    def check_cloudinit_version(self):

        user_data = """\
#cloud-config
user: {}
password: {}
chpasswd:
  expire: False
ssh_authorized_keys:
 - "{}"
""".format(self.vm.vm_username, self.vm.vm_password, self.vm.ssh_pubkey)

        meta_data ="""\
instance-id: example
local-hostname: myhost
"""
        #remove vm if it exists
        if self.vm.exists():
            self.vm.delete()

        #create iso or start http server
        datasource = "cdrom"
        self.vm.create_datafile(
            datasource=datasource,
            userdata=user_data,
            metadata=meta_data
        )
        #create vm
        status = self.vm.create(datasource=datasource)
        if not status:
            self.fail("Create vm failed, please check!")

        #login and check, successfully login means ssh key is configured well
        self.ssh_timeout = 30
        status = utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not status:
            self.fail("Login failed, please check!")
        #get cloud-init version from somketests
        package_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
        version = version_util.get_version(package_ver,'cloud-init-')
        self.cloudinit_version =  version

    #the datasource of cloud-init for cdrom and smbios are different, using parameterized to expand the test case
    @parameterized.expand(["cdrom","smbios"])
    def test_cloudinit_staticip_dns_metric(self, datasource):
        """
        with parameter:
        case_name:
            test_cloudinit_staticip_dns_metric
        case_tag:
            cloudinit,cloudinit_tier2,vm_delete
        case_file:
            test_cloud_init_newvm.py
        component:
            cloud-init
        bugzilla_id:
            RHEL-81896,RHEL-81703,RHEL-44334,RHEL-59980,RHEL-65016,RHEL-61224
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiachen@redhat.com
        description:
            Check cloud-init can configure static IP, nameservers and metric
        key_steps: |
            1.#prepare user-data,meta-data and network-data
            2.#launch a KVM instance
            3.#login and check IP,nameservers and metric
        expect_result: |
            ip is the static IP
            nameservers configured in /etc/resolv.conf
            metric value is same as network-config
        """
        #When @unittest.skipUnless is placed before @parameterized.expand, it does not work as expected. 
        #This happens because @parameterized.expand modifies the test method before @unittest.skipUnless applies, 
        #so skipping does not apply to the expanded test cases
        #solution: skipping inside the test method
        if os.getenv('INFRA_PROVIDER') != 'kvm':
            self.skipTest('skip test as it is the specific test case for kvm.')

        #cannot connect if the version is not supported
        if datasource == "smbios":
            support_cases = self.vm.support_cases
            main_support_versions = ["24.4-5.el9","24.4-4.el10"]#Bug fix RHEL-81896,RHEL-81703
            backport_versions = ["24.4-4.el9_6.1","24.4-3.el10_0.1"]#backport bug RHEL-83636,RHEL-83639
            if self.cloudinit_version is None:
                self.check_cloudinit_version()
            version = self.cloudinit_version
            if not version_util.is_support(version,"test_cloudinit_staticip_dns_metric",support_cases,main_support_versions,backport_versions):
                self.skipTest("Skip test_cloudinit_staticip_dns_metric_smbios because it does not support network-config for cloud-init-"+version)

        # create vm and then do test
        interface_name = self.vm.interface_name or "eth0"
        if self.rhel_x_version >= 10:
            # for rhel 10, interface name is ens2
            interface_name = self.vm.interface_name or "ens2"

        user_data = """\
#cloud-config
user: {}
password: {}
chpasswd:
  expire: False
ssh_authorized_keys:
 - "{}"
""".format(self.vm.vm_username, self.vm.vm_password, self.vm.ssh_pubkey)

        meta_data ="""\
"""
        network_config ="""\
#cloud-config
network:
  config:
    - name: {0}
      subnets:
        - address: 10.0.2.2/24
          gateway: 10.0.2.1
          type: static
          routes:
            - destination: 0.0.0.0/0
              gateway: 10.0.2.1
              metric: 99
            - destination: 192.168.122.1/24
              gateway: 10.0.2.1
              metric: 98
            - destination: 10.0.1.1/24
              gateway: 10.0.2.1
      type: physical
    - type: nameserver
      interface: {0}
      address:
        - 8.8.8.8
        - 4.4.4.4
      search:
        - example.com
  version: 1
""".format(interface_name)

        #remove vm if it exists
        if self.vm.exists():
            self.vm.delete()

        #create iso or start http server
        self.vm.static_ip = "10.0.2.2"
        self.vm.create_datafile(
            datasource=datasource,
            userdata=user_data,
            metadata=meta_data,
            networkconfig=network_config
        )
        #create vm
        status = self.vm.create(datasource=datasource)
        if not status:
            self.fail("create vm failed, please check")
        #login and check
        self.ssh_timeout = 30
        status = utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not status:
            self.fail("Login failed, please check!")

        # cloud-init 24.3+ support network-config with smbios
        package_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
        version = version_util.get_version(package_ver,'cloud-init-')

        failures = []
        #step1 checking IP configuration
        ipkeywords = ["10.0.2.2/24"]
        step = "check IP configuration is "+ str(ipkeywords)
        cmd = "ip a s"
        failures += utils_lib.check_cmd_output(self,step,cmd,keywords=ipkeywords)

        if datasource == "cdrom":
            support_cases = self.vm.support_cases
            #the max version of step2 and step3
            main_support_versions = ["24.4-1.el9","24.1.4-21.el10"]
            backport_versions = ["23.4-7.el9_4.11","23.4-19.el9_5.4"]
            if not version_util.is_support(version,"test_cloudinit_staticip_dns_metric",support_cases,main_support_versions,backport_versions):
                self.skipTest("Skip test_cloudinit_staticip_dns_metric_cdrom because it does not support dns and metric configuration for "+package_ver)

        #step2 checking dns configuration
        #nameserver 24.1 for rhel 10(RHEL-44334), and 24.4 rebase for rhel9.6 (RHEL-59980)
        #cloud-init config dns cloud-init-24.1.4-21.el10(RHEL-65769), cloud-init-23.4-22.el9(RHEL-657680)
        #backport cloud-init-23.4-19.el9_5.4(RHEL-65778,RHEL-68409), cloud-init-23.4-7.el9_4.11(RHEL-65777,RHEL-68408)
        dnskeywords = ["nameserver 8.8.8.8","nameserver 4.4.4.4"]
        #for example search virt.pnr.lab.eng...com example.com
        dnspatterns = [r"search .*example\.com"]
        step = "check dns configuration contains "+ str(dnskeywords)+str(dnspatterns)
        cmd = "cat /etc/resolv.conf"
        failures += utils_lib.check_cmd_output(self,step,cmd,keywords=dnskeywords,patterns=dnspatterns)

        #step3 checking metric configuration
        #cloud-init-24.1.4-19.el10(RHEL-65016), cloud-init-23.4-20.el9(RHEL-61224)
        #backport cloud-init-23.4-19.el9_5.1(RHEL-65018), cloud-init-23.4-7.el9_4.8(RHEL-65017)
        checks = [("default","metric 99"),
                  ("to 10.0.1.0/24","metric 99"),
                  ("to 10.0.2.0/24","metric 99"),
                  ("to 192.168.122.0/24","metric 98")]
        for destination,metricvalue in checks:
            step = "check {} metric value is {}".format(destination,metricvalue)
            metrickeywords = [metricvalue]
            cmd = "ip route show {}".format(destination)
            failures += utils_lib.check_cmd_output(self,step,cmd,keywords=metrickeywords)

        if failures:
            self.fail("\n"+"\n".join(failures))

    @parameterized.expand(["cdrom","smbios"])
    def test_cloudinit_smoketests_kvm(self, datasource):
        """
        with parameter:
        case_name:
            test_cloudinit_smoketests_kvm
        case_tag:
            cloudinit,cloudinit_tier2,vm_delete
        case_file:
            test_cloud_init_newvm.py
        component:
            cloud-init
        bugzilla_id:
            RHEL-66128
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiachen@redhat.com
        description:
            the basic check for cloud-init on KVM
        key_steps: |
            1.#prepare user-data and meta-data
            2.#launch a KVM instance
            3.#login to check the configuration, e.g. hostname, datasource, cloud-init status
        expect_result: |
            ssh login is success
            hostname is configured
            datasource is recognized correctly
        """
        #When @unittest.skipUnless is placed before @parameterized.expand, it does not work as expected. 
        #solution: skipping inside the test method
        if os.getenv('INFRA_PROVIDER') != 'kvm':
            self.skipTest('skip test as it is the specific test case for kvm.')

        user_data = """\
#cloud-config
user: {}
password: {}
chpasswd:
  expire: False
ssh_authorized_keys:
 - "{}"
""".format(self.vm.vm_username, self.vm.vm_password, self.vm.ssh_pubkey)
 
        meta_data ="""\
instance-id: example
local-hostname: myhost
"""

        #remove vm if it exists
        if self.vm.exists():
            self.vm.delete()

        #create iso or start http server
        self.vm.create_datafile(
            datasource=datasource,
            userdata=user_data,
            metadata=meta_data
        )
        #create vm
        status = self.vm.create(datasource=datasource)
        if not status:
            self.fail("Create vm failed, please check!")

        #login and check, successfully login means ssh key is configured well
        self.ssh_timeout = 30
        status = utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not status:
            self.fail("Login failed, please check!")

        # cloud-init 24.1 started to support smbios
        if datasource == "smbios":
            support_cases = self.vm.support_cases
            main_support_versions = ["24.4-1.el9","24.1.4.el10"] # RHEL-66128 for rhel9.6
            backport_versions = ["23.4-7.el9_4.12","23.4-19.el9_5.5"] # RHEL-79773, RHEL-79774
            package_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
            version = version_util.get_version(package_ver,'cloud-init-')
            if not version_util.is_support(version,"test_cloudinit_smoketests_kvm",support_cases,main_support_versions,backport_versions):
                self.skipTest("Skip test_cloudinit_staticip_dns_metric_smbios because it does not support network-config for "+package_ver)

        failures = []
        #check host name is myhost
        hostnamekws = ["myhost"]
        step = "check hostname configuration is "+ str(hostnamekws)
        cmd = "hostname"
        failures += utils_lib.check_cmd_output(self,step,cmd,keywords=hostnamekws)

        #check datasource
        if datasource == "smbios":
            datasourcekws = ["DataSourceNoCloudNet"]
        elif datasource == "cdrom":
            datasourcekws = ["DataSourceNoCloud [seed=/dev/sr0]"]
        step ="check datasource is "+ str(datasourcekws)
        cmd = "cat /var/lib/cloud/instance/datasource"
        failures += utils_lib.check_cmd_output(self,step,cmd,keywords=datasourcekws)

        #check cloud-init status
        if failures:
            self.fail("\n"+"\n".join(failures))

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') == 'kvm', 'it is a specific case for kvm')
    def test_cloudinit_bridges(self):
        """
        case_name:
            test_cloudinit_bridges
        case_tag:
            cloudinit,cloudinit_tier2,vm_delete
        case_file:
            test_cloud_init_newvm.py
        component:
            cloud-init
        bugzilla_id:
            RHEL-38927
        is_customer_case:
            True
        testplan:
            N/A
        maintainer:
            xiachen@redhat.com
        description:
            test the bridge configuration on KVM
        key_steps: |
            1.#prepare user-data and meta-data
            2.#launch a KVM instance
            3.#login to check the network configuration
        expect_result:
            Both IPs can ssh login means network configuration is correct.
        """

        # cannot connect if the version is not supported
        # so get cloud-init version by creating a VM
        support_cases = self.vm.support_cases
        main_support_versions = ["23.4-21.el9","24.1.4-19.el10"] # RHEL-38927 for rhel9.6
        backport_versions = ["23.4-7.el9_4.9","23.4-19.el9_5.2"] # RHEL-65020, RHEL-65021
        if self.cloudinit_version is None:
            self.check_cloudinit_version()
        version = self.cloudinit_version
        if not version_util.is_support(version,"test_cloudinit_bridges",support_cases,main_support_versions,backport_versions):
            self.skipTest("Skip test_cloudinit_bridges because it does not support bridge set-name for cloud-init-"+version)

        # create vm and then do test
        user_data = """\
#cloud-config
user: {}
password: {}
chpasswd:
  expire: False
ssh_authorized_keys:
 - "{}"
""".format(self.vm.vm_username, self.vm.vm_password, self.vm.ssh_pubkey)

        meta_data ="""\
instance-id: example
local-hostname: provisioner.ocp.openstack.lab
"""

        network_config ="""\
#cloud-config
network:
  bridges:
    baremetal:
      addresses:
      - fc00:1:1::2/64
      interfaces:
      - baremetalport
      nameservers:
        addresses:
        - fc00:1:1::1
      routes:
      - on-link: true
        to: ::/0
        via: fc00:1:1::1
    provisioning:
      addresses:
      - fc00:1:2::2/64
      interfaces:
      - provisionport
      routes: []
  ethernets:
    baremetalport:
      match:
        macaddress: 52:54:00:bd:8f:cb
      set-name: baremetal0
    provisionport:
      match:
        macaddress: 52:54:00:25:ae:12
      set-name: provisioning0
  version: 2
"""

        #remove vm if it exists
        if self.vm.exists():
            self.vm.delete()

        #create iso or start http server
        self.vm.static_ip = "fc00:1:1::2"
        self.vm.create_datafile(
            datasource="cdrom",
            userdata=user_data,
            metadata=meta_data,
            networkconfig=network_config
        )
        #create vm
        status = self.vm.create(datasource="cdrom",networks=[("br-mgmt","52:54:00:25:ae:12"),("br-prov","52:54:00:bd:8f:cb")])
        if not status:
            self.fail("Create vm failed, please check!")
        #login and check
        self.ssh_timeout = 30
        status = utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not status:
            self.fail("Login failed, please check!")

        self._check_cloudinit_done()

        # check login with another IP, cannot login if the configuration fail.
        self.vm.static_ip = "fc00:1:2::2"
        self.vm.floating_ip
        #login and check
        self.ssh_timeout = 30
        status = utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not status:
            self.fail("Login failed with another IP, please check!")
        #tear down

    #moved the test method which require new VM into this test class
    @unittest.skipIf(os.getenv('INFRA_PROVIDER') == 'libvirt', 'skip run as this needs to configure user-data')
    def test_cloudinit_login_with_password_userdata(self):
        """
        case_tag:
            cloudinit,cloudinit_tier1,vm_delete
        case_priority:
            1
        component:
            cloud-init
        maintainer:
            huzhao@redhat.com
        description: |
            RHEL7-103830 - CLOUDINIT-TC: VM can successfully login
            after provisioning(with password authentication)
        key_steps: |
            1. Create a VM with only password authentication
            2. Login with password, should have sudo privilege
        """
        if self.vm.provider == 'azure':
            vm_username = self.vm.vm_username
            vm_password = self.vm.vm_password
        else:
            password_length = 10
            vm_password = secrets.token_urlsafe(password_length)
            vm_username = "test-user"
        self.log.info(vm_username)
        self.log.info(vm_password)
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        user_data = """\
#cloud-config

user: {0}
password: {1}
chpasswd: {{ expire: False }}
ssh_pwauth: True
""".format(vm_username, vm_password)
        status = self.vm.create(userdata=user_data,sshkey="DoNotSet")
        if not status:
            self.fail("Create vm failed, please check!")
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        self.params['remote_node'] = self.vm.floating_ip
        test_login = utils_lib.send_ssh_cmd(self.vm.floating_ip, vm_username, vm_password, "whoami", log=self.log)
        self.assertEqual(vm_username,
                         test_login[1].strip(),
                         "Fail to login with password: %s" % format(test_login[1].strip()))
        test_sudo = utils_lib.send_ssh_cmd(self.vm.floating_ip, vm_username, vm_password, "sudo cat /etc/sudoers.d/90-cloud-init-users", log=self.log)
        self.assertIn("%s ALL=(ALL) NOPASSWD:ALL" % vm_username,
                         test_sudo[1].strip(),
                         "No sudo privilege")

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['openstack','nutanix','kvm'], 'skip run as this case need connect rhsm stage server, not suitable for public cloud')
    def test_cloudinit_auto_install_package_with_subscription_manager(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2,vm_delete
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            xiachen@redhat.com
        description:
            RHEL-186182	CLOUDINIT-TC:auto install package with subscription manager
        key_steps: |
            1. Add content to user data config file
            rh_subscription:
            username: ******
            password: ******
            packages:
            - dos2unix
            2. create VM
            3. Verify register with subscription-manager and install package by cloud-init successfully
        """
        self.log.info("RHEL-186182 CLOUDINIT-TC:auto install package with subscription manager")
        if self.vm.exists():
            # Skip if it is image mode or CenOS Stream
            utils_lib.init_connection(self, timeout=self.ssh_timeout)
            out = utils_lib.run_cmd(self, 'ls /ostree/ | grep -i bootc')
            if 'bootc' in out:
                self.skipTest('skip run as this case is not supported for image mode')
            out = utils_lib.run_cmd(self, 'cat /etc/redhat-release | grep -i CentOS')
            if 'CentOS Stream' in out:
                self.skipTest('skip run as this case is not supported for CentOS Stream')

            self.vm.delete()
            time.sleep(30)
        package = "dos2unix"
        user_data = """\
#cloud-config

rh_subscription:
  username: {0}
  password: {1}
  rhsm-baseurl: {2}
  server-hostname: {3}
  disable-repo: []
packages:
  - {4}

ssh_authorized_keys:
    - {5}
""".format(self.vm.subscription_username, self.vm.subscription_password,
    self.vm.subscription_baseurl, self.vm.subscription_serverurl, package, utils_lib.get_public_key())
        status = self.vm.create(userdata=user_data)
        if not status:
            self.fail("Create vm failed, please check!")
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        time.sleep(30)
        # check login
        status = utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not status:
            self.fail("Login failed, please check!")
        # Skip if it is image mode or CenOS Stream
        out = utils_lib.run_cmd(self, 'ls /ostree/ | grep -i bootc')
        if 'bootc' in out:
            self.skipTest('skip run as this case is not supported for image mode')
        out = utils_lib.run_cmd(self, 'cat /etc/redhat-release | grep -i CentOS')
        if 'CentOS Stream' in out:
            self.skipTest('skip run as this case is not supported for CentOS Stream')

        self.log.info("Waiting 30s for subscription-manager done...")
        time.sleep(30) # waiting for subscription-manager register done.
        # run unregister in teardown.
        # no error because of disable-repo null

        # do not check package install when rhel version is beta, the repo does not contain package
        if 'Beta' in utils_lib.run_cmd(self,'sudo cat /etc/redhat-release'):
            self.skipTest('skip run as this case is not supported for Beta release')

        # check cloud-init status is done and services are active
        self._check_cloudinit_done()
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
        # SCA enabled ignoring auto-attach
        # check package installed
        time.sleep(30) # waiting for package install done.
        cmd = "rpm -q {}".format(package)
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='{}'.format(package),
                    msg="Check if package {} is installed by cloud-init".format(package))

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['openstack','kvm'], 'now support openstack and kvm')
    def test_cloudinit_recoverable_change(self):
        """
        case_tag:
            cloudinit,cloudinit_tier2,vm_delete
        case_priority:
            2
        component:
            cloud-init
        maintainer:
            xiachen@redhat.com
        description: |
            downstream: Retain exit code in cloud-init status for recoverable errors
            it is downstream only patch and only for rhel9
            so when recoverable errors, to check that rhel9 return 0 and rhel10 return 2
        key_steps: |
            1. Add content to user data config file
            2. Create VM
            3. Verify the return code of 'cloud-init status'
        """
        self.log.info("checking downstream: Retain exit code in cloud-init status for recoverable errors")
        if self.vm.exists():
            self.vm.delete()
            time.sleep(30)
        #If using users:{}, it would block ssh login.
        #so using another data chpasswd.list which can also cause recoverable error.
        user_data = """\
#cloud-config
chpasswd:
  list:

ssh_authorized_keys:
    - {}
""".format(utils_lib.get_public_key())
        status = self.vm.create(userdata=user_data)
        if not status:
            self.fail("Create vm failed, please check!")
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        # check login
        status = utils_lib.init_connection(self, timeout=self.ssh_timeout)
        if not status:
            self.fail("Login failed, please check!")
        # check cloud-init status return value
        cmd = "sudo cloud-init status"
        # for cloud-init el_9, expect is 0, while for el_10, expect is 2
        if self.rhel_x_version <= 9:
            expect_code = 0
        else:
            expect_code = 2
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=expect_code,
                    msg="Check the return code of cloud-init status")

    @unittest.skipIf(os.getenv('INFRA_PROVIDER') != 'openstack', 'skip as it is the specific case for openstack')
    def test_cloudinit_package_upgrade(self):
        '''
        case_tag:
            cloudinit,test_cloudinit_package_upgrade,cloudinit_tier3,vm_delete
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

        self._check_cloudinit_done()
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
baseurl=http://download.devel.redhat.com/rhel-{0}/rel-eng/RHEL-{0}/latest-RHEL-{1}/compose/{2}/x86_64/os/
enabled=1
gpgcheck=0
[rhel-appstream-upgrade]
name=rhel-appstream-upgrade
baseurl=http://download.devel.redhat.com/rhel-{0}/rel-eng/RHEL-{0}/latest-RHEL-{1}/compose/AppStream/x86_64/os/
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
        self._check_cloudinit_done()
        self.log.info("Upgrade cloud-init package successfully for rhel " + self.base_version)
            #reboot
        self._reboot_inside_vm(sleeptime=30)
            #check cloud-init status again, and no 'Traceback' in log
        self._check_cloudinit_done()
        self.log.info("Reboot successfully after upgrade cloud-init for" + self.base_version)

    @unittest.skipIf(os.getenv('INFRA_PROVIDER') != 'openstack', 'skip as it is the specific case for openstack')
    def test_cloudinit_os_upgrade(self):
        '''
        case_tag:
            cloudinit,test_cloudinit_os_upgrade,cloudinit_tier3,vm_delete
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
        self._check_cloudinit_done()
        #show old package version
        output = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
        self.log.info("old cloud-init package version is "+output+", run successfully.")
        #install/upgrade new version
        #set target repo
        utils_lib.run_cmd(self,"""
cat << EOF |sudo tee /etc/yum.repos.d/redhat.repo
[rhel-base-upgrade]
name=rhel-base-upgrade
baseurl=http://download.devel.redhat.com/rhel-{0}/{1}/RHEL-{0}/latest-RHEL-{2}/compose/{3}/x86_64/os/
enabled=1
gpgcheck=0
[rhel-appstream-upgrade]
name=rhel-appstream-upgrade
baseurl=http://download.devel.redhat.com/rhel-{0}/{1}/RHEL-{0}/latest-RHEL-{2}/compose/AppStream/x86_64/os/
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
        self._check_cloudinit_done()
        self.log.info("Upgrade cloud-init successfully via OS upgrade for rhel " + self.base_version)
        #reboot
        self._reboot_inside_vm(sleeptime=120)
        #check cloud-init status again, and no 'Traceback' in log
        self._check_cloudinit_done()
        self.log.info("Reboot successfully after upgrade OS for rhel " + self.base_version)

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_provision_vm_with_ipv6(self):        
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
            RHEL-176198 - CLOUDINIT-TC: [Azure]Provision VM with IPv6 address
        key_steps: | 
            1. Create a VM with NIC in IPv6 subnet
            2. Check if can provision and connect to the VM successfully
            3. Restart the VM. Check if this NIC is up and can get ip address
        """ 
        # 1. Create a VM with NIC in IPv6 subnet
        if self.vm.exists():
            self.vm.delete()
        # Save original VM name to restore later (in tearDown)
        self._original_vm_name = self.vm.vm_name
        self.vm.vm_name += "ipv6"        
        publicip_name = self.vm.vm_name + "publicip"
        publicip = AzurePublicIP(self.params,
                                name=publicip_name)
        if not publicip.exists():
            if not publicip.create():
                self.fail("Failed to create public IP: {}".format(publicip_name))
        # Verify public IP exists
        if not publicip.exists():
            self.fail("Public IP does not exist after creation: {}".format(publicip_name))
        
        # Create NSG with SSH rule
        nsg_name = self.vm.vm_name + "nsg"
        nsg = AzureNSG(self.params, name=nsg_name)
        if not nsg.exists():
            if not nsg.create():
                self.fail("Failed to create NSG: {}".format(nsg_name))
            # Wait a moment for NSG to be fully provisioned
            time.sleep(2)
        # Verify NSG exists
        if not nsg.exists():
            self.fail("NSG does not exist after creation: {}".format(nsg_name))
        # Add SSH rule to NSG
        if not nsg.add_ssh_rule():
            self.fail("Failed to add SSH rule to NSG: {}".format(nsg_name))
        
        self.vm.nics = "{}nic".format(self.vm.vm_name)
        nic = AzureNIC(self.params,
                        name=self.vm.nics,
                        subnet=self.vm.subnet,
                        vnet=self.vm.vnet_name,
                        publicip=publicip_name,
                        nsg=nsg_name)
        if not nic.exists():
            if not nic.create():
                self.fail("Failed to create NIC: {}".format(self.vm.nics))
        # Verify NIC exists
        if not nic.exists():
            self.fail("NIC does not exist after creation: {}".format(self.vm.nics))
        
        ipv6_config = AzureNicIpConfig(self.params,
                                       name=self.vm.nics+"ipv6",
                                       nic_name=self.vm.nics,
                                       ip_version="IPv6")
        if not ipv6_config.exists():
            if not ipv6_config.create():
                self.fail("Failed to create IPv6 config for NIC: {}".format(self.vm.nics))
        # Verify IPv6 config exists
        if not ipv6_config.exists():
            self.fail("IPv6 config does not exist after creation for NIC: {}".format(self.vm.nics))

        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))
        utils_lib.init_connection(self, timeout=60)
        utils_lib.run_cmd(self, "sudo su -")
        # 2. Verify can get IPv6 IP
        # Get IPv6 IP from Azure properties (second IP should be IPv6)
        self.vm.show()
        azure_ip = self.vm.properties.get("privateIps")
        if azure_ip:
            azure_ip = azure_ip.split(',')[1] if ',' in azure_ip else azure_ip
        # Get IPv6 IP from VM
        cmd = "ip addr|grep global|grep -Po 'inet6 \\K.*(?=/)'"
        vm_ip = utils_lib.run_cmd(self, cmd).strip()
        if azure_ip:
            self.assertEqual(
                vm_ip, azure_ip,
                "The private IPv6 address is wrong.\n"
                "Expect: {}\nReal: {}".format(azure_ip, vm_ip))
        # Test ping6 connectivity
        # cmd = "ping6 ace:cab:deca::fe -c 1"
        # utils_lib.run_cmd(self,
        #                   cmd,
        #                   expect_ret=0,
        #                   msg='Cannot ping6 though vnet')
        # 3. Restart VM
        self._reboot_inside_vm(sleeptime=10)
        # Verify IPv6 IP after restart
        vm_ip_list = utils_lib.run_cmd(self,
                                      "ip addr|grep global|grep -Po 'inet6 \\K.*(?=/)'").strip()
        if azure_ip:
            self.assertEqual(
                vm_ip_list, azure_ip,
                "The private IPv6 address is wrong after restart.\n"
                "Expect: {}\nReal: {}".format(azure_ip, vm_ip_list))
        # Test ping6 connectivity after restart
        # cmd = "ping6 ace:cab:deca::fe -c 1"
        # utils_lib.run_cmd(self,
        #                   cmd,
        #                   expect_ret=0,
        #                   msg='Cannot ping6 though vnet after restart')

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_provision_vm_with_multiple_nics_azure(self):
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
            RHEL-176196 - CLOUDINIT-TC: [Azure]Provision VM with multiple NICs
        key_steps: |
            1. Create a VM with 2 NICs
            2. Check if can provision and connect to the VM successfully
            3. Verify all private IP addresses match Azure properties
        """
        # 1. Create a VM with 2 NICs
        if self.vm.exists():
            self.vm.delete()
        # Save original VM name to restore later (in tearDown)
        self._original_vm_name = self.vm.vm_name
        self.vm.vm_name += "2nics"        
        # Create public IP
        publicip_name = self.vm.vm_name + "publicip"
        publicip = AzurePublicIP(self.params,
                                name=publicip_name)
        if not publicip.exists():
            if not publicip.create():
                self.fail("Failed to create public IP: {}".format(publicip_name))
        # Verify public IP exists
        if not publicip.exists():
            self.fail("Public IP does not exist after creation: {}".format(publicip_name))        
        # Create NSG with SSH rule
        nsg_name = self.vm.vm_name + "nsg"
        nsg = AzureNSG(self.params, name=nsg_name)
        if not nsg.exists():
            if not nsg.create():
                self.fail("Failed to create NSG: {}".format(nsg_name))
            # Wait a moment for NSG to be fully provisioned
            time.sleep(2)
        # Verify NSG exists
        if not nsg.exists():
            self.fail("NSG does not exist after creation: {}".format(nsg_name))
        # Add SSH rule to NSG
        if not nsg.add_ssh_rule():
            self.fail("Failed to add SSH rule to NSG: {}".format(nsg_name))        
        # Create 2 NICs
        nic_name_list = []
        for n in range(0, 2):
            nic_name = "{}nic{}".format(self.vm.vm_name, n)
            # First NIC uses default subnet, second NIC uses subnet + "1"
            subnet = self.vm.subnet if n == 0 else self.vm.subnet + str(n)
            # Only first NIC gets the public IP
            n_publicip = publicip_name if n == 0 else None
            
            nic = AzureNIC(self.params,
                          name=nic_name,
                          subnet=subnet,
                          vnet=self.vm.vnet_name,
                          publicip=n_publicip,
                          nsg=nsg_name)
            if not nic.exists():
                if not nic.create():
                    self.fail("Failed to create NIC: {}".format(nic_name))
            # Verify NIC exists
            if not nic.exists():
                self.fail("NIC does not exist after creation: {}".format(nic_name))
            nic_name_list.append(nic_name)        
        # Set VM to use both NICs (space-separated)
        self.vm.nics = ' '.join(nic_name_list)
        
        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))
        
        time.sleep(30)  # Give some time for cloud-init/SSH to be ready
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, "sudo su -")        
        # 2. Verify all private IP addresses match Azure properties
        self.vm.show()
        azure_ip_list = self.vm.properties.get("privateIps")
        if azure_ip_list:
            # Split and sort Azure IPs
            azure_ips = sorted([ip.strip() for ip in azure_ip_list.split(',')])
        else:
            azure_ips = []        
        # Get IPs from VM (excluding loopback)
        cmd = "ip addr|grep -Po 'inet \\K.*(?=/)'|grep -v '127.0.0.1'"
        vm_ip_output = utils_lib.run_cmd(self, cmd).strip()
        if vm_ip_output:
            vm_ips = sorted([ip.strip() for ip in vm_ip_output.split('\n') if ip.strip()])
        else:
            vm_ips = []        
        self.assertEqual(
            vm_ips, azure_ips,
            "The private IP addresses are wrong.\n"
            "Expect: {}\nReal: {}".format(azure_ips, vm_ips))

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_provision_vm_with_sriov_nic(self):
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
            RHEL-171394 - CLOUDINIT-TC: [Azure]Provision VM with SR-IOV NIC
        key_steps: |
            1. Create a VM with 1 SR-IOV NIC
            2. Check if can provision and connect to the VM successfully
            3. Verify private IP address matches Azure properties
        """
        # 1. Create a VM with SR-IOV NIC
        if self.vm.exists():
            self.vm.delete()
        # Save original VM name to restore later (in tearDown)
        self._original_vm_name = self.vm.vm_name
        self.vm.vm_name += "sriov"        
        # Create public IP
        publicip_name = self.vm.vm_name + "publicip"
        publicip = AzurePublicIP(self.params,
                                name=publicip_name)
        if not publicip.exists():
            if not publicip.create():
                self.fail("Failed to create public IP: {}".format(publicip_name))
        # Verify public IP exists
        if not publicip.exists():
            self.fail("Public IP does not exist after creation: {}".format(publicip_name))        
        # Create NSG with SSH rule
        nsg_name = self.vm.vm_name + "nsg"
        nsg = AzureNSG(self.params, name=nsg_name)
        if not nsg.exists():
            if not nsg.create():
                self.fail("Failed to create NSG: {}".format(nsg_name))
            # Wait a moment for NSG to be fully provisioned
            time.sleep(2)
        # Verify NSG exists
        if not nsg.exists():
            self.fail("NSG does not exist after creation: {}".format(nsg_name))
        # Add SSH rule to NSG
        if not nsg.add_ssh_rule():
            self.fail("Failed to add SSH rule to NSG: {}".format(nsg_name))        
        # Create NIC with SR-IOV enabled
        self.vm.nics = "{}nic".format(self.vm.vm_name)
        nic = AzureNIC(self.params,
                      name=self.vm.nics,
                      subnet=self.vm.subnet,
                      vnet=self.vm.vnet_name,
                      publicip=publicip_name,
                      nsg=nsg_name,
                      sriov=True)
        if not nic.exists():
            if not nic.create():
                self.fail("Failed to create NIC: {}".format(self.vm.nics))
        # Verify NIC exists
        if not nic.exists():
            self.fail("NIC does not exist after creation: {}".format(self.vm.nics))        
        # Set VM size to Standard_D3_v2 (required for SR-IOV)
        original_vm_size = self.vm.vm_size
        self.vm.vm_size = "Standard_D3_v2"        
        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        time.sleep(30)  # Give some time for cloud-init/SSH to be ready
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, "sudo su -")        
        # 2. Verify private IP address matches Azure properties
        self.vm.show()
        azure_ip = self.vm.properties.get("privateIps")
        if azure_ip:
            azure_ip = azure_ip.strip()        
        # Get IP from VM (excluding loopback)
        cmd = "ip addr|grep -Po 'inet \\K.*(?=/)'|grep -v '127.0.0.1'"
        vm_ip = utils_lib.run_cmd(self, cmd).strip()        
        if azure_ip:
            self.assertEqual(
                vm_ip, azure_ip,
                "The private IP address is wrong.\n"
                "Expect: {}\nReal: {}".format(azure_ip, vm_ip))        
        # Restore original VM size
        self.vm.vm_size = original_vm_size

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_provision_gen2_vm(self):
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
            RHEL-176836 - CLOUDINIT-TC: [Azure]Provision UEFI VM (Gen2)
        key_steps: |
            1. Create a Gen2 VM image and VM
            2. Check if can provision and connect to the VM successfully
            3. Verify hostname, DNS publishing, and resource disk mount
        """
        # Skip if RHEL version is less than 7.8 (Gen2 not supported)
        # Check version from VM params (available before VM creation)
        if self.vm.rhel_ver:
            try:
                rhel_major = int(self.vm.rhel_ver.split('.')[0])
                rhel_minor = int(self.vm.rhel_ver.split('.')[1]) if '.' in self.vm.rhel_ver else 0
                rhel_version_float = float("{}.{}".format(rhel_major, rhel_minor))
                if rhel_version_float < 7.8:
                    self.skipTest("Skip case because RHEL-{} ondemand image doesn't support gen2".format(self.vm.rhel_ver))
            except (ValueError, AttributeError):
                # If version parsing fails, skip the check
                pass        
        # 1. Create a Gen2 VM
        if self.vm.exists():
            self.vm.delete()
        # Save original VM name and settings to restore later (in tearDown)
        # Ensure we're starting with the base VM name (remove any previous suffixes)
        base_vm_name = self.vm.vm_name
        # Remove common suffixes that might have been added by previous tests
        for suffix in ['-gen2', 'sriov', '2nics', 'ipv6']:
            if base_vm_name.endswith(suffix):
                base_vm_name = base_vm_name[:-len(suffix)]
                break
        self._original_vm_name = base_vm_name
        self._original_vm_size = self.vm.vm_size
        self._original_use_unmanaged_disk = self.vm.use_unmanaged_disk
        # Set VM name with -gen2 suffix
        self.vm.vm_name = base_vm_name + "-gen2"
        self.vm.vm_size = "Standard_DS2_v2"
        self.vm.use_unmanaged_disk = False        
        # Create Gen2 image
        gen2_image = AzureImage(self.params, generation="V2")
        if not gen2_image.exists():
            if not gen2_image.create():
                self.fail("Failed to create Gen2 image: {}".format(gen2_image.name))
        # Verify image exists
        if not gen2_image.exists():
            self.fail("Gen2 image does not exist after creation: {}".format(gen2_image.name))        
        # Set VM to use the Gen2 image (use image name, Azure will resolve it)
        # Save original image to restore later
        self._original_vm_image = self.vm.vm_image
        self.vm.vm_image = gen2_image.name        
        # Create NSG with SSH rule (needed for SSH access)
        nsg_name = self.vm.vm_name + "nsg"
        nsg = AzureNSG(self.params, name=nsg_name)
        if not nsg.exists():
            if not nsg.create():
                self.fail("Failed to create NSG: {}".format(nsg_name))
            # Wait a moment for NSG to be fully provisioned
            time.sleep(2)
        # Verify NSG exists
        if not nsg.exists():
            self.fail("NSG does not exist after creation: {}".format(nsg_name))
        # Add SSH rule to NSG
        if not nsg.add_ssh_rule():
            self.fail("Failed to add SSH rule to NSG: {}".format(nsg_name))        
        # Set NSG for VM (when creating VM without pre-existing NIC)
        self.vm.nsg = nsg_name        
        # Set user_data with fqdn to ensure hostname matches VM name (with -gen2 suffix)
        # Always update user_data to ensure fqdn matches the current VM name
        from os_tests.libs.utils_lib import get_public_key
        self.vm.user_data = """#cloud-config
fqdn: {}
ssh_authorized_keys:
  - {}
""".format(self.vm.vm_name, get_public_key())        
        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        time.sleep(30)  # Give some time for cloud-init/SSH to be ready
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, "sudo su -")        
        # 2. Verify hostname is correct
        error_msg = ""
        try:
            vm_hostname = utils_lib.run_cmd(self, "hostname").strip()
            self.assertEqual(
                vm_hostname, self.vm.vm_name,
                "Hostname is not the one we set. Expected: {}, Got: {}".format(self.vm.vm_name, vm_hostname))
        except Exception as e:
            error_msg += "Verify hostname failed: {}\n".format(str(e))        
        # 3. Verify hostname is published to DNS
        try:
            nslookup_output = utils_lib.run_cmd(self, "nslookup {}".format(self.vm.vm_name))
            self.assertNotIn(
                "NXDOMAIN", nslookup_output,
                "Fail to publish hostname to DNS")
        except Exception as e:
            error_msg += "Verify publish to DNS failed: {}\n".format(str(e))        
        # 4. Verify resource disk is mounted at /mnt
        try:
            mount_output = utils_lib.run_cmd(self, "mount|grep /mnt")
            self.assertNotEqual(
                "", mount_output.strip(),
                "Resource Disk is not mounted after provisioning")
        except Exception as e:
            error_msg += "Verify mountpoint failed: {}\n".format(str(e))        
        if error_msg:
            self.fail(error_msg)        
        # Restore original settings
        self.vm.vm_size = self._original_vm_size
        self.vm.use_unmanaged_disk = self._original_use_unmanaged_disk
        if hasattr(self, '_original_vm_image'):
            self.vm.vm_image = self._original_vm_image

    def _check_in_link(self, device, links):
        """Helper method to check if a device is in the disk links"""
        self.assertIn(device, links,
                      "No {} link in disk links".format(device))
        self.log.info("{} is in disk links. Pass.".format(device))

    def _verify_storage_rule(self):
        """Verify storage rule: check /dev/disk/cloud/ has correct links"""
        links = utils_lib.run_cmd(self, "ls -l /dev/disk/cloud")
        devices_list = re.findall(r"\w+",
                                  utils_lib.run_cmd(self, "cd /dev;ls sd*"))
        for device in devices_list:
            self._check_in_link(device, links)
        # There should be azure_root and azure_resource links
        self._check_in_link('azure_root', links)
        self._check_in_link('azure_resource', links)
        # Verify the azure_root and azure_resource link to the correct disks
        root_disk_output = utils_lib.run_cmd(self, "df|grep boot").strip()
        root_disk = root_disk_output[:8] if len(root_disk_output) >= 8 else root_disk_output
        resource_disk_output = utils_lib.run_cmd(self,
            "find /dev/sd*|grep -v '{}'".format(root_disk)).strip()
        resource_disk = resource_disk_output[:8] if len(resource_disk_output) >= 8 else resource_disk_output
        self.log.info("Root disk: {}".format(root_disk))
        self.log.info("Resource disk: {}".format(resource_disk))
        azure_root_path = utils_lib.run_cmd(self, "realpath /dev/disk/cloud/azure_root").strip()
        azure_resource_path = utils_lib.run_cmd(self, "realpath /dev/disk/cloud/azure_resource").strip()
        self.assertEqual(azure_root_path, root_disk,
                         "The azure_root link disk is incorrect. Expected: {}, Got: {}".format(root_disk, azure_root_path))
        self.assertEqual(azure_resource_path, resource_disk,
                         "The azure_resource link disk is incorrect. Expected: {}, Got: {}".format(resource_disk, azure_resource_path))

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_verify_storage_rule_gen2(self):
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
            RHEL-188924 - CLOUDINIT-TC: [Azure]Verify storage rule - Gen2
        key_steps: |
            1. Prepare Gen2 VM
            2. Check /dev/disk/cloud/, there should be azure_root and azure_resource
               soft links to sda and sdb
            3. Verify the links point to the correct disks
        """
        # Skip if RHEL version is less than 7.8 (Gen2 not supported)
        # Check version from VM params (available before VM creation)
        if self.vm.rhel_ver:
            try:
                rhel_major = int(self.vm.rhel_ver.split('.')[0])
                rhel_minor = int(self.vm.rhel_ver.split('.')[1]) if '.' in self.vm.rhel_ver else 0
                rhel_version_float = float("{}.{}".format(rhel_major, rhel_minor))
                if rhel_version_float < 7.8:
                    self.skipTest("Skip case because RHEL-{} ondemand image doesn't support gen2".format(self.vm.rhel_ver))
            except (ValueError, AttributeError):
                # If version parsing fails, skip the check
                pass        
        # 1. Prepare Gen2 VM (same setup as test_cloudinit_provision_gen2_vm)
        if self.vm.exists():
            self.vm.delete()
        # Save original VM name and settings to restore later (in tearDown)
        self._original_vm_name = self.vm.vm_name
        self._original_vm_size = self.vm.vm_size
        self._original_use_unmanaged_disk = self.vm.use_unmanaged_disk
        self.vm.vm_name += "-gen2"
        self.vm.vm_size = "Standard_DS2_v2"
        self.vm.use_unmanaged_disk = False        
        # Create Gen2 image
        gen2_image = AzureImage(self.params, generation="V2")
        if not gen2_image.exists():
            if not gen2_image.create():
                self.fail("Failed to create Gen2 image: {}".format(gen2_image.name))
        # Verify image exists
        if not gen2_image.exists():
            self.fail("Gen2 image does not exist after creation: {}".format(gen2_image.name))        
        # Set VM to use the Gen2 image (use image name, Azure will resolve it)
        # Save original image to restore later
        self._original_vm_image = self.vm.vm_image
        self.vm.vm_image = gen2_image.name        
        # Create NSG with SSH rule (needed for SSH access)
        nsg_name = self.vm.vm_name + "nsg"
        nsg = AzureNSG(self.params, name=nsg_name)
        if not nsg.exists():
            if not nsg.create():
                self.fail("Failed to create NSG: {}".format(nsg_name))
            # Wait a moment for NSG to be fully provisioned
            time.sleep(2)
        # Verify NSG exists
        if not nsg.exists():
            self.fail("NSG does not exist after creation: {}".format(nsg_name))
        # Add SSH rule to NSG
        if not nsg.add_ssh_rule():
            self.fail("Failed to add SSH rule to NSG: {}".format(nsg_name))        
        # Set NSG for VM (when creating VM without pre-existing NIC)
        self.vm.nsg = nsg_name        
        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        time.sleep(30)  # Give some time for cloud-init/SSH to be ready
        utils_lib.init_connection(self, timeout=self.ssh_timeout)
        utils_lib.run_cmd(self, "sudo su -")        
        # 2. Verify storage rule
        self._verify_storage_rule()        
        # Restore original settings
        self.vm.vm_size = self._original_vm_size
        self.vm.use_unmanaged_disk = self._original_use_unmanaged_disk
        if hasattr(self, '_original_vm_image'):
            self.vm.vm_image = self._original_vm_image

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_save_and_handle_customdata_script_azure(self):
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
            RHEL7-103837 - CLOUDINIT-TC: Save and handle customdata(script)
        key_steps: |
            1. Create VM with custom data (script)
            2. Get CustomData from ovf-env.xml, decode it and compare with user-data.txt
            3. Check if custom data script is executed
        """        
        # Prepare custom script
        script = """#!/bin/bash
echo 'teststring' >> /var/log/test.log
"""
        customdata_file = "/tmp/customdata.sh"
        with open(customdata_file, 'w') as f:
            f.write(script)        
        # 1. Create VM with custom data
        if self.vm.exists():
            self.vm.delete()        
        # Set custom_data and create VM with the pre-existing NIC
        self.vm.custom_data = customdata_file
        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        time.sleep(30)  # Give some time for cloud-init/SSH to be ready
        utils_lib.init_connection(self, timeout=self.ssh_timeout)        
        # 2. Compare custom data
        # Get CustomData from ovf-env.xml and decode it
        custom_data_from_ovf = utils_lib.run_cmd(
            self,
            "sudo grep -o -P '(?<=CustomData>).*(?=<.*CustomData>)' /var/lib/waagent/ovf-env.xml | base64 -d"
        ).strip()        
        # Get user-data.txt content
        user_data_content = utils_lib.run_cmd(
            self,
            "sudo cat /var/lib/cloud/instance/user-data.txt"
        ).strip()        
        self.assertEqual(
            custom_data_from_ovf,
            user_data_content,
            "Custom data in ovf-env.xml is not equal to user-data.txt"
        )        
        # 3. Check if custom data script is executed
        # Wait for the script to execute (retry up to 10 times, 10 seconds each)
        script_executed = False
        for retry in range(1, 11):
            # Check if file exists using ls command (non-fatal)
            result = utils_lib.run_cmd(
                self,
                "ls /var/log/test.log 2>/dev/null && echo 'exists' || echo 'not_exists'",
                msg="Checking if /var/log/test.log exists (attempt {}/10)".format(retry)
            )
            if 'exists' in result:
                script_executed = True
                break
            self.log.info("/var/log/test.log doesn't exist. Wait for 10s and retry...({}/10)".format(retry))
            time.sleep(10)        
        if not script_executed:
            self.fail("The custom data script was not executed - /var/log/test.log does not exist after 100 seconds")        
        # Verify the content of test.log
        test_log_content = utils_lib.run_cmd(
            self,
            "cat /var/log/test.log"
        ).strip()        
        self.assertEqual(
            "teststring",
            test_log_content,
            "The custom data script is not executed correctly. Expected 'teststring', got: {}".format(test_log_content)
        )

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_save_and_handle_customdata_cloudinit_config(self):
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
            RHEL7-103838 - CLOUDINIT-TC: Save and handle customdata(cloud-init configuration)
        key_steps: |
            1. Create VM with custom data (cloud-config)
            2. Get CustomData from ovf-env.xml, decode it and compare with user-data.txt
            3. Check if the new cloud-init configuration is handled correctly
        """        
        # Prepare custom data (cloud-config)
        customdata_content = """#cloud-config
cloud_config_modules:
 - mounts
 - locale
 - set-passwords
 - yum-add-repo
 - disable-ec2-metadata
 - runcmd
"""
        customdata_file = "/tmp/customdata.conf"
        with open(customdata_file, 'w') as f:
            f.write(customdata_content)        
        # 1. Create VM with custom data
        if self.vm.exists():
            self.vm.delete()
        self.vm.custom_data = customdata_file
        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        time.sleep(30)  # Give some time for cloud-init/SSH to be ready
        utils_lib.init_connection(self, timeout=self.ssh_timeout)        
        # 2. Compare custom data
        # Get CustomData from ovf-env.xml and decode it
        custom_data_from_ovf = utils_lib.run_cmd(
            self,
            "sudo grep -o -P '(?<=CustomData>).*(?=<.*CustomData>)' /var/lib/waagent/ovf-env.xml | base64 -d"
        ).strip()        
        # Get user-data.txt content
        user_data_content = utils_lib.run_cmd(
            self,
            "sudo cat /var/lib/cloud/instance/user-data.txt"
        ).strip()        
        self.assertEqual(
            custom_data_from_ovf,
            user_data_content,
            "Custom data in ovf-env.xml is not equal to user-data.txt"
        )        
        # 3. Check if the new cloud-init configuration is handled correctly
        # (There should be 6 modules ran in cloud-init.log for versions < 23.1, or 3 modules for >= 23.1)
        output = utils_lib.run_cmd(
            self,
            "sudo grep 'running modules for config' /var/log/cloud-init.log -B 100"
        )
        version_output = utils_lib.run_cmd(self, "cloud-init -v|awk '{print $2}'").strip()        
        # Compare version - check if version >= 23.1
        version_parts = version_output.split('.')
        version_major = int(version_parts[0]) if version_parts[0].isdigit() else 0
        version_minor = int(version_parts[1]) if len(version_parts) > 1 and version_parts[1].isdigit() else 0        
        if version_major < 23 or (version_major == 23 and version_minor < 1):
            # For versions < 23.1, expect 6 modules
            self.assertIn(
                "Ran 6 modules",
                output,
                "The user data is not handled correctly. Expected 'Ran 6 modules' for version < 23.1"
            )
        else:
            # For versions >= 23.1, expect 3 modules and skipping message
            self.assertIn(
                "Ran 3 modules",
                output,
                "The user data is not handled correctly. Expected 'Ran 3 modules' for version >= 23.1"
            )
            self.assertIn(
                "Skipping modules 'yum-add-repo,disable-ec2-metadata,runcmd' because no applicable config is provided",
                output,
                "The user data is not handled correctly. Expected skipping message for version >= 23.1"
            )

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_save_and_handle_userdata_script(self):
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
            RHEL-286797 - CLOUDINIT-TC: Save and handle userdata(script)
        key_steps: |
            1. Create VM with user data (script)
            2. Check if user data script is executed
        """        
        # Prepare user script
        script = """#!/bin/bash
echo 'teststring' >> /var/log/test.log
"""
        userdata_file = "/tmp/userdata.sh"
        with open(userdata_file, 'w') as f:
            f.write(script)        
        # 1. Create VM with user data
        if self.vm.exists():
            self.vm.delete()
        # Read the script file content and set as user_data (AzureVM expects string, not file path)
        with open(userdata_file, 'r') as f:
            self.vm.user_data = f.read()
        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        time.sleep(30)  # Give some time for cloud-init/SSH to be ready
        utils_lib.init_connection(self, timeout=self.ssh_timeout)        
        # 2. Check if user data script is executed
        # Wait for the script to execute (retry up to 10 times, 10 seconds each)
        script_executed = False
        for retry in range(1, 11):
            # Check if file exists using ls command (non-fatal)
            result = utils_lib.run_cmd(
                self,
                "ls /var/log/test.log 2>/dev/null && echo 'exists' || echo 'not_exists'",
                msg="Checking if /var/log/test.log exists (attempt {}/10)".format(retry)
            )
            if 'exists' in result:
                script_executed = True
                break
            self.log.info("/var/log/test.log doesn't exist. Wait for 10s and retry...({}/10)".format(retry))
            time.sleep(10)        
        if not script_executed:
            self.fail("The user data script was not executed - /var/log/test.log does not exist after 100 seconds")        
        # Verify the content of test.log
        test_log_content = utils_lib.run_cmd(
            self,
            "cat /var/log/test.log"
        ).strip()        
        self.assertEqual(
            "teststring",
            test_log_content,
            "The user data script is not executed correctly. Expected 'teststring', got: {}".format(test_log_content)
        )

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_save_and_handle_userdata_cloudinit_config(self):
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
            RHEL-286798 - CLOUDINIT-TC: Save and handle userdata(cloud-init configuration)
        key_steps: |
            1. Create VM with user data (cloud-config)
            2. Check if the new cloud-init configuration is handled correctly
        """
        # Prepare user data (cloud-config)
        userdata_content = """#cloud-config
cloud_config_modules:
 - mounts
 - locale
 - set-passwords
 - yum-add-repo
 - disable-ec2-metadata
 - runcmd
"""
        userdata_file = "/tmp/userdata.conf"
        with open(userdata_file, 'w') as f:
            f.write(userdata_content)        
        # 1. Create VM with user data
        if self.vm.exists():
            self.vm.delete()
        # Read the file content and set as user_data (AzureVM expects string, not file path)
        with open(userdata_file, 'r') as f:
            self.vm.user_data = f.read()
        if not self.vm.create():
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        time.sleep(30)  # Give some time for cloud-init/SSH to be ready
        utils_lib.init_connection(self, timeout=self.ssh_timeout)        
        # 2. Check if the new cloud-init configuration is handled correctly
        # (There should be 6 modules ran in cloud-init.log for versions < 23.1, or 3 modules for >= 23.1)
        output = utils_lib.run_cmd(
            self,
            "sudo grep 'running modules for config' /var/log/cloud-init.log -B 100"
        )
        version_output = utils_lib.run_cmd(self, "cloud-init -v|awk '{print $2}'").strip()        
        # Compare version - check if version >= 23.1
        version_parts = version_output.split('.')
        version_major = int(version_parts[0]) if version_parts[0].isdigit() else 0
        version_minor = int(version_parts[1]) if len(version_parts) > 1 and version_parts[1].isdigit() else 0        
        if version_major < 23 or (version_major == 23 and version_minor < 1):
            # For versions < 23.1, expect 6 modules
            self.assertIn(
                "Ran 6 modules",
                output,
                "The user data is not handled correctly. Expected 'Ran 6 modules' for version < 23.1"
            )
        else:
            # For versions >= 23.1, expect 3 modules and skipping message
            self.assertIn(
                "Ran 3 modules",
                output,
                "The user data is not handled correctly. Expected 'Ran 3 modules' for version >= 23.1"
            )
            self.assertIn(
                "Skipping modules 'yum-add-repo,disable-ec2-metadata,runcmd' because no applicable config is provided",
                output,
                "The user data is not handled correctly. Expected skipping message for version >= 23.1"
            )

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_remove_cache_and_reboot_password(self):
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
            RHEL-189049 - CLOUDINIT-TC: Reboot with no instance cache - password authentication
        key_steps: |
            1. Create a VM on Azure with password authentication
            2. Remove the instance cache folder and reboot
            3. Verify can login successfully with password
        """        
        # Save original VM name to restore later (in tearDown)
        self._original_vm_name = self.vm.vm_name
        # Add "-pw" suffix to VM name (following avocado-cloud pattern)
        self.vm.vm_name += "-pw"        
        # Configure password authentication (disable SSH key)
        original_ssh_key_value = self.vm.ssh_key_value
        original_generate_ssh_keys = self.vm.generate_ssh_keys
        self.vm.ssh_key_value = None
        self.vm.generate_ssh_keys = None
        self.vm.authentication_type = "password"        
        # Create VM with password authentication if it doesn't exist
        if self.vm.exists():
            self.vm.delete()
        if not self.vm.create(wait=True, sshkey="DoNotSet"):
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        # Wait for VM to be ready
        time.sleep(30)        
        # Verify password is set
        if not self.vm.vm_password:
            self.fail("VM password is not set. This test requires password authentication.")        
        # Connect using password authentication to remove cache
        self.params['remote_node'] = self.vm.floating_ip
        utils_lib.send_ssh_cmd(
            self.vm.floating_ip,
            self.vm.vm_username,
            self.vm.vm_password,
            "sudo rm -rf /var/lib/cloud/instances/*",
            log=self.log
        )        
        # Reboot VM
        self.vm.reboot(wait=True)        
        # Wait for VM to be running
        self.vm.show()
        error_message = "Timed out waiting for VM to be running after reboot."
        for count in utils_lib.iterate_timeout(100, error_message, wait=10):
            self.vm.show()  # Refresh VM state
            if self.vm.is_started():
                break        
        # Wait for SSH to be ready
        time.sleep(30)        
        # Verify can login with password authentication
        if not self.vm.vm_password:
            self.fail("VM password is not set. This test requires password authentication.")        
        self.params['remote_node'] = self.vm.floating_ip
        test_login = utils_lib.send_ssh_cmd(
            self.vm.floating_ip,
            self.vm.vm_username,
            self.vm.vm_password,
            "whoami",
            log=self.log
        )
        self.assertEqual(
            self.vm.vm_username,
            test_login[1].strip(),
            "Fail to login with password after reboot: {}".format(test_login[1].strip())
        )        
        # Restore original settings (for tearDown)
        self.vm.ssh_key_value = original_ssh_key_value
        self.vm.generate_ssh_keys = original_generate_ssh_keys
        self.vm.authentication_type = "ssh"

    @unittest.skipUnless(os.getenv('INFRA_PROVIDER') in ['azure'], 'skip as it is the specific case for azure')
    def test_cloudinit_update_existing_password(self):
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
            RHEL-198376: [Azure]Update existing user password
        key_steps: |
            1. Create a VM with user azuredebug and new password (different from password in image)
            2. Login with the new password, should have sudo privilege
        """        
        # Save original VM name to restore later (in tearDown)
        self._original_vm_name = self.vm.vm_name
        # Add "-pw" suffix to VM name (following avocado-cloud pattern)
        self.vm.vm_name += "-pw"        
        # 1. Create a VM with password authentication (not SSH key)
        if self.vm.exists():
            self.vm.delete()        
        # Set password authentication (disable SSH key)
        original_ssh_key_value = self.vm.ssh_key_value
        original_generate_ssh_keys = self.vm.generate_ssh_keys
        self.vm.ssh_key_value = None
        self.vm.generate_ssh_keys = None
        self.vm.authentication_type = "password"                
        if not self.vm.create(wait=True, sshkey="DoNotSet"):
            self.fail("Failed to create VM: {}".format(self.vm.vm_name))        
        # Wait for VM to be ready
        time.sleep(30)        
        # 2. Login with the new password
        self.params['remote_node'] = self.vm.floating_ip
        test_login = utils_lib.send_ssh_cmd(
            self.vm.floating_ip,
            self.vm.vm_username,
            self.vm.vm_password,
            "whoami",
            log=self.log
        )
        self.assertEqual(
            self.vm.vm_username,
            test_login[1].strip(),
            "Fail to login with password: {}".format(test_login[1].strip())
        )        
        # Verify sudo privilege
        test_sudo = utils_lib.send_ssh_cmd(
            self.vm.floating_ip,
            self.vm.vm_username,
            self.vm.vm_password,
            "sudo cat /etc/sudoers.d/90-cloud-init-users",
            log=self.log
        )
        self.assertIn(
            "{} ALL=(ALL) NOPASSWD:ALL".format(self.vm.vm_username),
            test_sudo[1].strip(),
            "No sudo privilege"
        )        
        # Restore original settings (for tearDown)
        self.vm.ssh_key_value = original_ssh_key_value
        self.vm.generate_ssh_keys = original_generate_ssh_keys
        self.vm.authentication_type = "ssh"

    def tearDown(self):
        utils_lib.finish_case(self)
        casegroup = ('test_cloudinit_auto_install_package_with_subscription_manager')
        if self.id().endswith(casegroup):
            utils_lib.run_cmd(self, "sudo subscription-manager unregister")
        #remove the vm in teardown as it is specific and may can not be connected by other cases
        if not self.params.get('no_cleanup') and self.vm.exists():
            self.vm.static_ip = None
            self.vm.delete(wait=True)
        # Restore VM name and settings if they were modified
        if hasattr(self, '_original_vm_name'):
            self.vm.vm_name = self._original_vm_name
            self.vm.nics = None  # Clear nics to avoid reusing deleted NIC
            delattr(self, '_original_vm_name')
        if hasattr(self, '_original_vm_size'):
            self.vm.vm_size = self._original_vm_size
            delattr(self, '_original_vm_size')
        if hasattr(self, '_original_use_unmanaged_disk'):
            self.vm.use_unmanaged_disk = self._original_use_unmanaged_disk
            delattr(self, '_original_use_unmanaged_disk')
        if hasattr(self, '_original_vm_image'):
            self.vm.vm_image = self._original_vm_image
            delattr(self, '_original_vm_image')
        # Clear user_data to avoid carrying over fqdn from previous test
        self.vm.user_data = None
        # Clear custom_data to avoid carrying over from previous test
        self.vm.custom_data = None

if __name__ == '__main__':
    unittest.main()
