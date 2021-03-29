import unittest
import argparse
import copy
import os
import sys
from os_tests.libs.html_runner import HTMLTestRunner
from os_tests.tests.test_cloud_init import TestCloudInit
from os_tests.tests.test_general_check import TestGeneralCheck
from os_tests.tests.test_general_test import TestGeneralTest
from os_tests.tests.test_ltp import TestLTP
from os_tests.tests.test_network_test import TestNetworkTest
from os_tests.tests.test_storage import TestStorage
from os_tests.tests.test_lifecycle import TestLifeCycle

test_cloud_init_suite = unittest.TestLoader().loadTestsFromTestCase(TestCloudInit)
test_general_check_suite = unittest.TestLoader().loadTestsFromTestCase(TestGeneralCheck)
test_general_test_suite = unittest.TestLoader().loadTestsFromTestCase(TestGeneralTest)
test_ltp_suite = unittest.TestLoader().loadTestsFromTestCase(TestLTP)
test_network_suite = unittest.TestLoader().loadTestsFromTestCase(TestNetworkTest)
test_storage_suite = unittest.TestLoader().loadTestsFromTestCase(TestStorage)
test_lifecycle_suite = unittest.TestLoader().loadTestsFromTestCase(TestLifeCycle)
all_tests = [test_general_check_suite, test_general_test_suite, test_ltp_suite, test_network_suite, test_storage_suite, test_lifecycle_suite]
TS = unittest.TestSuite(tests=all_tests)


def main():
    parser = argparse.ArgumentParser(
    description="os-tests is a lightweight, fast check and tests collection for Linux OS.")
    parser.add_argument('-l', dest='is_listcase', action='store_true',
                    help='list supported cases without run', required=False)
    parser.add_argument('-p', dest='pattern', default=None, action='store',
                    help='filter case by name', required=False)
    parser.add_argument('-s', dest='skip_pattern', default=None, action='store',
                    help='skip cases', required=False)
    args = parser.parse_args()

    print("Run in mode: is_listcase:{} pattern: {}".format(args.is_listcase, args.pattern))
    this_dir = os.path.dirname(__file__)
    this_dir = os.path.dirname(this_dir)
    ts = unittest.defaultTestLoader.discover(start_dir=this_dir)
    tmp_ts = copy.deepcopy(ts)
    final_ts = unittest.TestSuite()
    for ts1 in tmp_ts:
        if len(ts1._tests) > 0:
            for ts2 in ts1._tests:
                for case in ts2._tests:
                    is_skip = False
                    if args.skip_pattern is not None:
                            for skippattern in args.skip_pattern.split(','):
                                if skippattern in case.id():
                                    is_skip = True
                    if args.pattern is not None:
                        for pattern in args.pattern.split(','):
                            if pattern in case.id() and not is_skip:
                                final_ts.addTest(case)
                    else:
                        if not is_skip:
                            final_ts.addTest(case)
    if final_ts.countTestCases() == 0:
        print("No case found!")
        sys.exit(1)
    if args.is_listcase:
        for case in final_ts:
            print(case.id())
        print("Total case num: %s"%final_ts.countTestCases())
    else:
        HTMLTestRunner(verbosity=2).run(final_ts)
        #unittest.TextTestRunner(verbosity=2).run(final_ts)

if __name__ == "__main__":
    main()
    #unittest.TextTestRunner().run(TS)
