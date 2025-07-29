import unittest
import os
import secrets
import time
import re
from os_tests.libs import utils_lib
from os_tests.libs import version_util
from os_tests.libs.resources import UnSupportedAction
from parameterized import parameterized

#this class is the collection of cases that require new vm
class TestCloudInitNewVM(unittest.TestCase):
    def setUp(self):
        #do not create vm in init_case, because it will create new vm in test case
        self.createvm = False
        utils_lib.init_case(self)

    @property
    def rhel_x_version(self):
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

    #the datasource of cloud-init for cdrom and smbios are different, using parameterized to expand the test case
    @parameterized.expand(["cdrom","smbios"])
    def test_cloudinit_staticip_dns_metric(self, datasource):
        """
        case_tag:
            cloudinit,cloudinit_tier2,vm_delete
        case_name:
            test_cloudinit_staticip_dns_metric
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
        key_steps:
            1.#prepare user-data,meta-data and network-data
            2.#launch a KVM instance
            3.#login and check IP,nameservers and metric
        expect_result:
            ip is the static IP
            nameservers configured in /etc/resolv.conf
            metric value is same as network-config
        debug_want:
            cloud-init
        """
        #When @unittest.skipUnless is placed before @parameterized.expand, it does not work as expected. 
        #This happens because @parameterized.expand modifies the test method before @unittest.skipUnless applies, 
        #so skipping does not apply to the expanded test cases
        #solution: skipping inside the test method
        if os.getenv('INFRA_PROVIDER') != 'kvm':
            self.skipTest('skip test as it is the specific test case for kvm.')

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
        if datasource == "smbios":
            support_cases = self.vm.support_cases
            main_support_versions = ["24.4-5.el9","24.4-4.el10"]#Bug fix RHEL-81896,RHEL-81703
            backport_versions = ["24.4-4.el9_6.1","24.4-3.el10_0.1"]#backport bug RHEL-83636,RHEL-83639
            if not version_util.is_support(version,"test_cloudinit_staticip_dns_metric",support_cases,main_support_versions,backport_versions):
                self.skipTest("Skip test_cloudinit_staticip_dns_metric_smbios because it does not support network-config for "+package_ver)

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
        case_tag:
            cloudinit,cloudinit_tier2,vm_delete
        case_name:
            test_cloudinit_smoketests_kvm
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
        key_steps:
            1.#prepare user-data and meta-data
            2.#launch a KVM instance
            3.#login to check the configuration, e.g. hostname, datasource, cloud-init status
        expect_result:
            ssh login is success
            hostname is configured
            datasource is recognized correctly
        debug_want:
            cloud-init
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
        case_tag:
            cloudinit,cloudinit_tier2,vm_delete
        case_name:
            test_cloudinit_bridges
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
        key_steps:
            1.#prepare user-data and meta-data
            2.#launch a KVM instance
            3.#login to check the network configuration
        expect_result:
            Both IPs can ssh login means network configuration is correct.
        debug_want:
            cloud-init
        """
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

        support_cases = self.vm.support_cases
        main_support_versions = ["23.4-21.el9","24.1.4-19.el10"] # RHEL-38927 for rhel9.6
        backport_versions = ["23.4-7.el9_4.9","23.4-19.el9_5.2"] # RHEL-65020, RHEL-65021
        package_ver = utils_lib.run_cmd(self, "rpm -q cloud-init").rstrip('\n')
        version = version_util.get_version(package_ver,'cloud-init-')
        if not version_util.is_support(version,"test_cloudinit_bridges",support_cases,main_support_versions,backport_versions):
            self.skipTest("Skip test_cloudinit_bridges because it does not support set-name for bridge. "+package_ver)

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

        self.log.info("Waiting 30s for subscription-manager done...")
        time.sleep(30) # waiting for subscription-manager register done.
        # no error because of disable-repo null
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
        #teardown

    def tearDown(self):
        utils_lib.finish_case(self)
        casegroup = ('test_cloudinit_auto_install_package_with_subscription_manager')
        if self.id().endswith(casegroup) and not self.skipflag:
            utils_lib.run_cmd(self, "sudo subscription-manager unregister")
        #remove the vm in teardown as it is specific and may can not be connected by other cases
        if not self.params.get('no_cleanup') and self.vm.exists():
            self.vm.static_ip = None
            self.vm.delete(wait=True)

if __name__ == '__main__':
    unittest.main()
