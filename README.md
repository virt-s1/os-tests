# os-tests

## Introduction

os-tests is a lightweight, fast and customer centric tests collection for Linux OS.

## Installation

### Install from pip

`# pip install os-tests`

note: you must install paramiko module if run in server-client mode.  
    This requires libffi-devel,openssl-devel,python-devel are required in aarch64 to compile cryptography

### Install from source code

```bash
# git clone https://github.com/liangxiao1/os-tests.git
# cd os-tests
# python3 setup.py install
```

### Build wheel from source code and install it

```bash
# python3 setup.py sdist bdist_wheel
# pip install -U dist/os_tests-0.0.3-py3-none-any.whl
```

### Public new wheels on [pypi](https://pypi.org/project/os-tests/) (maintainer use only)

`# python3 -m twine upload  dist/*`

## Run test

### Run all os_tests supported cases(os-tests cli was introduced in v0.0.10)

`# os-tests`  
note: the default path is "/usr/local/bin" if not in virtual environment.  
or  
`# python3 -m unittest -v os_tests.os_tests_all`

### List all supported cases only without run

`# os-tests -l`

#### Filter case name with keywords ltp and virtwhat

`# os-tests -l -p ltp,virtwhat`

#### Filter case name with keywords ltp and skip test_ltp_ipsec_icmp

`# os-tests -l -p ltp -s test_ltp_ipsec_icmp`

### Run all cases in one file

`# os-tests -p test_general_check`  
or  
`# python3 -m unittest -v os_tests.tests.test_general_check`

### Run single case in one file

`# os-tests -p test_change_clocksource`  
or  
`# python3 -m unittest -v os_tests.tests.test_general_test.TestGeneralTest.test_change_clocksource`

### The config file

You can change the default setting in "cfg/os-tests.yaml".

If you want to run os-tests all cases in remote node to support lifecyce cases which needs reboot.  
Please specify below options:  
remote_node:   
remote_user: ec2-user  
remote_keyfile:   

### The log file

The suite saves summary to sum.html and sum.log under /tmp/os_tests_result/.
The test debug log files are saved in "/tmp/os_tests_result/debug" following case name by default.
You can change "results_dir" in "cfg/os-tests.yaml" to save log to other place.

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

### The installed files

All test files are located in "os_tests/tests" directory.

```bash
# pip3 show -f os-tests
Name: os-tests
Version: 0.0.5
Summary: Lightweight, fast check and tests collection for Linux OS
Home-page: https://github.com/liangxiao1/os-tests
Author: Xiao Liang
Author-email: xiliang@redhat.com
License: GPLv3+
Location: /usr/local/lib/python3.6/site-packages
Requires: PyYAML
Files:
  os_tests/__init__.py
  os_tests/cfg/os-tests.yaml
  os_tests/data/baseline_log.json
  os_tests/libs/__init__.py
  os_tests/libs/utils_lib.py
  os_tests/os_tests_all.py
  os_tests/tests/__init__.py
  os_tests/tests/test_cloud_init.py
  os_tests/tests/test_general_check.py
  os_tests/tests/test_general_test.py
  os_tests/tests/test_ltp.py

```

### Recommend test matrix to catch potiential issues

- run in normal kernel, it is the most used senario
- run in debug kernel with 'kmemleak=on'
- run in fips enabled kernel
- run in remote-client mode to cover lifecycle cases

### third party utils  

Below tools are shiped under 'utils' directory with os-tests because not all systems can reach github.
- ltp x86 rpms: https://github.com/liangxiao1/rpmbuild_specs/releases/download/ltp-master-20200514/ltp-master-20200514.x86_64.rpm
- ltp aarch64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/ltp-master-20200514/ltp-master-20200514.aarch64.rpm
- blktests x86_64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/blktests_20201009/blktests-master-20201009.x86_64.rpm
- blktests aarch64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/blktests_20201009/blktests-master-20201009.aarch64.rpm

### Contribution

You are welcomed to create pull request or raise issue. New case from real customer senario or rhbz is prefered.
