# os-tests

## Introduction

os-tests is a lightweight, fast and customer centric tests collection for Linux OS.

## Installation

### Install from pip

`# pip install os-tests`

note: please install [paramiko-fork](https://pypi.org/project/paramiko-fork/) if run os-tests in server-client mode.
      the main branch of paramiko lacking of rsa-sha2-256 and rsa-sha2-512 support to connect rhel-9 ([1643](https://github.com/paramiko/paramiko/pull/1643)). Keeping its lightweight, os-tests do not set it as required. Because it is not required when run in single node model and extra pkgs (eg. libffi-devel, openssl-devel, python-devel) are required in aarch64 to compile cryptography when install paramiko.

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

### Run all supported cases in local or on remote node

```bash
# os-tests
# os-tests --host <remote_node> --user <remote_user> --keyfile <remote_keyfile> --result <result_dir> -p <cases>
```

note: the default path is "/usr/local/bin" if not in virtual environment.  
or  
`# python3 -m unittest -v os_tests.os_tests_run`

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

### All installed files

You can list all installed files via `pip show -f os-tests` simply.  
The test files are under "os_tests/tests" directory.

The config files with defaul setting are under "os_tests/cfg".  
You can update the default setting in "os-tests.yaml".

If you want to run os-tests all cases in remote node to support lifecyce cases which needs reboot.  
Please specify below options in static configuration:  
remote_node:   
remote_user: ec2-user  
remote_keyfile:   

It equals calling in command line directly.

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
- ltp x86 rpms: https://github.com/liangxiao1/rpmbuild_specs/releases/download/sync_20211124/ltp-master-20211124.x86_64.rpm
- ltp aarch64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/sync_20211124/ltp-master-20211124.aarch64.rpm
- blktests x86_64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/sync_20211124/blktests-master-20211124.x86_64.rpm
- blktests aarch64 rpm: https://github.com/liangxiao1/rpmbuild_specs/releases/download/sync_20211124/blktests-master-20211124.aarch64.rpm

### Contribution

You are welcome to create pull request or raise issue. New case from real customer senario or rhbz is prefered.  
Developing tool VS code is recommended with [refnow](https://marketplace.visualstudio.com/items?itemName=FrankLiang.refnow) plugin which ships the newest case doc template.
