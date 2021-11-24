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
    parser.add_argument('--image', dest='image', default=None, action='store',
                    help='specify azure to run azure image check only', required=False)
    parser.add_argument('--disks', dest='blk_devs', default=None, action='store',
                    help='free disks for storage test, eg. "/dev/nvme0n1", data on disk has lost risks', required=False)
    args = parser.parse_args()

    cfg_file, cfg_data = get_cfg()
    if args.results_dir is not None:
        cfg_data['results_dir'] = args.results_dir
    if args.blk_devs is not None:
        cfg_data['blk_devs'] = args.blk_devs
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
    skip_patterns = args.skip_pattern
    test_patterns = args.pattern
    if args.image is not None:
        if 'azure' in args.image:
            print("only run azure image checks")
            test_patterns = 'test_azure_image'
        else:
            print("only azure image check supported for now")
            sys.exit(0)
    else:
        print("skip azure image check by default")
        if skip_patterns:
            skip_patterns = skip_patterns + ',test_azure_image'
        else:
            skip_patterns = 'test_azure_image'

    if cfg_data['remote_node'] is None:
        print("skip lifecycle tests as no remote node found")
        if skip_patterns:
            skip_patterns = skip_patterns + ',test_lifecycle'
        else:
            skip_patterns = 'test_lifecycle'

    print("Run in mode: is_listcase:{} test_patterns:{} skip_patterns:{}".format(args.is_listcase, test_patterns, skip_patterns))

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
                        if skip_patterns is not None:
                                for skippattern in skip_patterns.split(','):
                                    if skippattern in case.id():
                                        if args.is_strict and case.id().endswith(skippattern):
                                            is_skip = True
                                        elif not args.is_strict:
                                            is_skip = True
                        if test_patterns is not None:
                            for pattern in test_patterns.split(','):
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
