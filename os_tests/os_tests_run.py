import unittest
import copy
import os
import sys
from os_tests.libs.utils_lib import get_cfg, init_ssh, init_args, init_provider, filter_case_doc
from shutil import rmtree
import os_tests
from os_tests.libs.html_runner import HTMLTestRunner
import uuid
import logging
LOG_FORMAT = '%(asctime)s:%(levelname)s:%(message)s'

def main():
    log = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    args = init_args()
    vm, disk, nic = None, None, None
    run_uuid = str(uuid.uuid4())
    if args.platform_profile and not args.is_listcase and not args.verifydoc:
        log.info("{}Stage: Provision System{}".format('='*20,'='*20))
        cfg_file, cfg_data = get_cfg(cfg_file=args.platform_profile)
        cfg_data['remote_user'] = args.remote_user
        cfg_data['run_uuid'] = run_uuid
        vm, disk, nic = init_provider(params=cfg_data)
        if not vm:
            log.info('cannot provision vm, please check.')
            sys.exit(1)
    cfg_file, cfg_data = get_cfg()
    if args.results_dir is not None:
        cfg_data['results_dir'] = args.results_dir
    if args.remote_node is not None:
        cfg_data['remote_node'] = args.remote_node
        cfg_data['remote_port'] = args.remote_port
        cfg_data['remote_user'] = args.remote_user
        cfg_data['remote_password'] = args.remote_password
        cfg_data['remote_keyfile'] = args.remote_keyfile

    if vm:
        if vm.floating_ip is None:
            vm.delete()
            sys.exit(1)
        cfg_data['remote_node'] = vm.floating_ip
        cfg_data['remote_port'] = vm.port
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
            if args.pattern:
                test_patterns = args.pattern
            else:
                test_patterns = 'test_azure_image'
        else:
            print("only azure image check supported for now")
            sys.exit(0)
    else:
        print("skip azure image check by default")
        if skip_patterns and not args.verifydoc:
            skip_patterns = skip_patterns + ',test_azure_image'
        else:
            if not args.verifydoc:
                skip_patterns = 'test_azure_image'

    ssh = None
    if cfg_data['remote_node'] is None and not args.platform_profile:
        print("skip lifecycle tests as no remote node found")
        if skip_patterns and not args.verifydoc:
            skip_patterns = skip_patterns + ',test_lifecycle'
        else:
            skip_patterns = 'test_lifecycle' 
    elif not args.is_listcase and not args.verifydoc:
        log.info("{}Stage: Init Connection to System{}".format('='*20,'='*20))
        ssh = init_ssh(params=cfg_data)
        if ssh is None and vm:
            vm.delete()
            sys.exit(1)

    if not args.platform_profile and not args.verifydoc:
        skip_patterns = skip_patterns + ',test_vm_operation' if skip_patterns else 'test_vm_operation'

    log.info("{}Stage: Run Test{}".format('='*20,'='*20))
    print("Run in mode: is_listcase:{} test_patterns:{} skip_patterns:{}".format(args.is_listcase, test_patterns, skip_patterns))

    base_dir = os.path.realpath(os_tests.__file__)
    utils_dir = os.path.dirname(base_dir) + '/utils'
    data_dir = os.path.dirname(base_dir) + '/data'

    ts = unittest.defaultTestLoader.discover(start_dir=os_tests_dir,pattern='test_*.py', top_level_dir=os.path.dirname(os_tests_dir))
    tmp_ts = copy.deepcopy(ts)
    final_ts = unittest.TestSuite()
    for ts1 in tmp_ts:
        if len(ts1._tests) > 0:
            for ts2 in ts1._tests:
                try:
                    for case in ts2._tests:
                        case.params = cfg_data
                        case.run_uuid = run_uuid
                        case.utils_dir = utils_dir
                        case.data_dir = data_dir
                        if ssh is not None:
                            case.SSH = ssh
                        case.vm = vm
                        case.disk = disk
                        case.nic = nic
                        if filter_case_doc(case=case, patterns=test_patterns, skip_patterns=skip_patterns,
                                           filter_field=args.filter_by, strict=args.is_strict, verify_doc=args.verifydoc):
                            final_ts.addTest(case)
                except Exception as err:
                    print("Cannot handle ts discovered:{}".format(ts2))
                    print(err)
    if final_ts.countTestCases() == 0:
        print("No case found!")
        sys.exit(1)
    if args.is_listcase or args.verifydoc:
        for case in final_ts:
            print(case.id())
        print("Total case num: %s"%final_ts.countTestCases())
    else:
        HTMLTestRunner(verbosity=2).run(final_ts)
    if vm:
        #vm.delete()
        if disk is not None and disk.is_exist():
            disk.delete()

if __name__ == "__main__":
    main()
