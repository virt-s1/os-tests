# os-tests

## Introduction

os-tests is a lightweight, fast check and tests collection for Linux OS.

## Installation

### Install from pip

`# pip install os-tests`

note: you must install paramiko module to support run on remotely.  
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
remote_node: None  
remote_user: ec2-user  
remote_keyfile: None  

### The log file

The console only shows the case test result as summary.
The test debug log file are saved in "/tmp/os_tests_result" following case name by default.
You can change "results_dir" in "cfg/os-tests.yaml" to save log in other place.

Below is an example:

```bash
# python3 -m unittest -v os_tests.tests.test_general_test.TestGeneralTest.test_change_clocksource
test_change_clocksource (os_tests.tests.test_general_test.TestGeneralTest) ... ok

----------------------------------------------------------------------
Ran 1 test in 0.117s

OK
# ls -l /tmp/os_tests_result/
total 8
-rw-r--r--. 1 root root 4224 Aug 26 10:11 os_tests.tests.test_general_test.TestGeneralTest.test_change_clocksource.debug
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

### Contribution

You are welcomed to create pull request or raise issue.
