# os-tests

## Introduction

os-tests is a lightweight, fast check and tests collection for Linux OS.

## Installation

`# pip install os-tests`

## Run test

### Run all os_tests supported cases

`# python3 -m unittest -v os_tests.os_tests_all`

### Run all cases in one file

`# python3 -m unittest -v os_tests.tests.test_general_check`

### Run single case in one file

`# python3 -m unittest -v os_tests.tests.test_general_test.TestGeneralTest.test_change_clocksource`

### The log file

The console only shows the case test result.
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
