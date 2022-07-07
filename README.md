# os-tests

## Introduction

os-tests is a lightweight, portable and customer centric tests collection for Linux OS.

## Installation

### Install from pypi

`# pip install os-tests`

Note: please install [paramiko](https://pypi.org/project/paramiko/) if run os-tests in server-client mode.

There is an pynacl issue when installing paramiko on RHEL-8.6. Please install previous pynacl version (1.4.0) instead.

### Install from source code repo directly

```bash
# pip install git+https://github.com/virt-s1/os-tests.git@master
```

### Build wheel locally and install it

```bash
# git clone https://github.com/virt-s1/os-tests.git
# cd os-tests
# python3 setup.py sdist bdist_wheel
# pip install -U dist/os_tests-0.0.3-py3-none-any.whl
```

note: the default bin path is "/usr/local/bin" if not in virtual environment.

### Public new wheels on [pypi](https://pypi.org/project/os-tests/) (maintainer use only)

`# python3 -m twine upload  dist/*`

## Run test

### os-tests supports 3 working modes

#### Mode 1 -  single node used  

Install and run tests inside the RHEL system directly, fewer cases than Mode 2 and 3, lacking of tests requiring reboot system and instance control access.  
`# os-tests`  
or  
`# python3 -m unittest -v os_tests.os_tests_run`

#### Mode 2 - server client with 2 nodes used  

 Require ssh user, key/password and IP to access existing RHEL system, all tests are done remotely, can do lifecyle, kdump test, but without device hotplug capability and other tests requires instance access.  
`# os-tests --host <remote_node> --user <remote_user> --keyfile <remote_keyfile> --result <result_dir> -p <cases>`

#### Mode 3 - server client with 1 node used, os-tests can provision test system self  

Require cloud/platform account to provision remote system self, can do full test with full control of instance. Eg. device hotplug, snapshot creation, send nmi events......  
Note: supports aws, openstack, alicloud, nutanix, other platforms are in planning. The config template is under cfg dir.  
`# os-tests -p cloudinit --user ec2-user --keyfile /home/virtqe_s1.pem --platform_profile aws_env.yaml`

### More options  

#### List all supported cases only without run

`# os-tests -l`

#### Filter case name with keywords ltp and virtwhat

`# os-tests -l -p ltp,virtwhat`

#### Filter case name with keywords ltp and skip test_ltp_ipsec_icmp

`# os-tests -l -p ltp -s test_ltp_ipsec_icmp`

### Run all cases in one file

`# os-tests -p test_general_check`  

#### Run single case in one file

`# os-tests -p test_change_clocksource`  

### All installed files and dirs

You can list all installed files via `pip show -f os-tests` simply.  

```bash
os_tests
├── cfg       ->configration files
├── data      ->data files for log checking
├── libs      ->libs including resource(vm, disk, network)/func definenation
├── templates ->template for generating html,xml report
├── tests     ->all tests files location
└── utils     ->3rd party utils, ltp, blktests and others
```

### Recommended pkgs in test system  

os-tests will try to install required pkgs from default repo during run, but it would be better to have them if no repo provided.
List RHEL only because CentOS Stream and Fedora usually have public repo available.

**RHEL-7**: install,automake,autoconf,sysstat,gcc,unzip,wget,quota,bzip2,iperf3,pciutils,fio,psmisc,expect,ntpdate,perf,nvme-cli,pciutils,fio,git,tar,nfs-utils,libvirt,qemu-kvm,kernel-debug,python3,dracut-fips,podman,strace,sos  

**RHEL-8**: make,automake,autoconf,sysstat,gcc,unzip,wget,quota,bzip2,iperf3,pciutils,fio,psmisc,expect,perf,nvme-cli,pciutils,fio,php-cli,php-xml,php-json,libaio-devel,blktrace,fio,nvme-cli,git,tar,rng-tools,nfs-utils,libvirt,qemu-kvm,kernel-debug,python3,dracut-fips,podman,xdp-tools,openssl-devel,strace,sos  

**RHEL-9**: make,automake,autoconf,sysstat,gcc,unzip,wget,quota,bzip2,iperf3,pciutils,fio,psmisc,expect,perf,nvme-cli,pciutils,fio,libaio-devel,blktrace,fio,nvme-cli,git,tar,rng-tools,nfs-utils,libvirt,qemu-kvm,python3,dracut-fips,kernel-debug,python3-pip,hostname,podman,xdp-tools,openssl-devel,glibc-all-langpacks,strace,sos

### The log file

The suite saves summary to sum.html and sum.log under "/tmp/os_tests_result/" by default.
The test debug log files are saved in "/tmp/os_tests_result/debug" following case name by default.
You can change "results_dir" in "cfg/os-tests.yaml" to save log to other place or passing as command option.

Below is an example:

```bash
#  os-tests -p test_change_clocksource
Run in mode: is_listcase:False pattern: test_change_clocksource
test_change_clocksource (os_tests.tests.test_general_test.TestGeneralTest) ... ok
----------------------------------------------------------------------
summary in html: /tmp/os_tests_result/sum.html
summary in text: /tmp/os_tests_result/sum.log
----------------------------------------------------------------------
Ran 1 test in 0.383s

OK

# ls -l /tmp/os_tests_result/debug/
total 8
-rw-r--r--. 1 root root 5472 Mar 30 16:44 os_tests.tests.test_general_test.TestGeneralTest.test_change_clocksource.debug
```

### Recommend test matrix to catch potiential issues

- run in normal kernel, it is the most used senario
- run in debug kernel with 'kmemleak=on'
- run in fips enabled kernel
- run in remote-client mode to cover lifecycle cases

### Third party utils  

Below tools are shiped under 'utils' directory with os-tests because not all systems can reach github.
- ltp x86_64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/sync_20211124/ltp-master-20211124.x86_64.rpm
- ltp aarch64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/sync_20211124/ltp-master-20211124.aarch64.rpm
- blktests x86_64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/sync_20211124/blktests-master-20211124.x86_64.rpm
- blktests aarch64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/sync_20211124/blktests-master-20211124.aarch64.rpm

### Contribution

You are welcome to create pull request or raise issue. New case from real customer senario or rhbz is prefered.  
Developing tool VS code is recommended with [refnow](https://marketplace.visualstudio.com/items?itemName=FrankLiang.refnow) plugin which ships the newest case doc template.

If adding case, please verify case doc before pushing.
```bash
$ os-tests --verifydoc -p <casename>
```
