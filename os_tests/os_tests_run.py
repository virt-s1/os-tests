import unittest
import argparse
import copy
import os
import sys
from os_tests.libs.utils_lib import get_cfg
from shutil import rmtree
import os_tests
from os_tests.libs.html_runner import HTMLTestRunner

def main():
    parser = argparse.ArgumentParser(
    description="os-tests is a lightweight, fast check and tests collection for Linux OS.")
    parser.add_argument('-l', dest='is_listcase', action='store_true',
                    help='list supported cases without run', required=False)
    parser.add_argument('-p', dest='pattern', default=None, action='store',
                    help='filter case by name, add --strict for matching exactly', required=False)
    parser.add_argument('--strict', dest='is_strict', action='store_true',
                    help='match exactly if -p or -s specified', required=False)
    parser.add_argument('-s', dest='skip_pattern', default=None, action='store',
                    help='skip cases, add --strict for skipping exactly', required=False)
    parser.add_argument('--host', dest='remote_node', default=None, action='store',
                    help='run tests on remote node', required=False)
    parser.add_argument('--user', dest='remote_user', default=None, action='store',
                    help='user to login to remote node', required=False)
    parser.add_argument('--password', dest='remote_password', default=None, action='store',
                    help='password to login to remote node', required=False)
    parser.add_argument('--keyfile', dest='remote_keyfile', default=None, action='store',
                    help='keyfile to login to remote node', required=False)
    parser.add_argument('--result', dest='results_dir', default=None, action='store',
                    help='save result to specific directory', required=False)
    args = parser.parse_args()

    print("Run in mode: is_listcase:{} pattern: {}".format(args.is_listcase, args.pattern))
    cfg_file, cfg_data = get_cfg()
    if args.results_dir is not None:
        cfg_data['results_dir'] = args.results_dir
    if args.remote_node is not None:
        cfg_data['remote_node'] = args.remote_node
        cfg_data['remote_user'] = args.remote_user
        cfg_data['remote_password'] = args.remote_password
        cfg_data['remote_keyfile'] = args.remote_keyfile

    results_dir = cfg_data['results_dir']
    results_dir_suffix = None
    if os.path.exists(results_dir) and not args.is_listcase:
        rmtree(results_dir)
        print("saving results to {}".format(results_dir))
    os_tests_dir = os.path.dirname(__file__)
    ts = unittest.defaultTestLoader.discover(start_dir=os_tests_dir,pattern='test_*.py', top_level_dir=os.path.dirname(os_tests_dir))
    tmp_ts = copy.deepcopy(ts)
    final_ts = unittest.TestSuite()
    for ts1 in tmp_ts:
        if len(ts1._tests) > 0:
            for ts2 in ts1._tests:
                try:
                    for case in ts2._tests:
                        case.params = cfg_data
                        is_skip = False
                        if args.skip_pattern is not None:
                                for skippattern in args.skip_pattern.split(','):
                                    if skippattern in case.id():
                                        if args.is_strict and case.id().endswith(skippattern):
                                            is_skip = True
                                        elif not args.is_strict:
                                            is_skip = True
                        if args.pattern is not None:
                            for pattern in args.pattern.split(','):
                                if pattern in case.id() and not is_skip:
                                    if args.is_strict and case.id().endswith(pattern):
                                        final_ts.addTest(case)
                                    elif not args.is_strict:
                                        final_ts.addTest(case)
                        else:
                            if not is_skip:
                                final_ts.addTest(case)
                except Exception as err:
                    print("Cannot handle ts discovered:{}".format(ts2))
                    print(err)
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
