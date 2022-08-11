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
from itertools import chain
LOG_FORMAT = '%(asctime)s:%(levelname)s:%(message)s'
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

def main():
    args = init_args()
    vms, disks, nics, sshs = [], [], [], []
    run_uuid = str(uuid.uuid4())
    if args.platform_profile and not args.is_listcase and not args.verifydoc:
        cfg_file, cfg_data = get_cfg(cfg_file=args.platform_profile)
        cfg_data['remote_user'] = args.remote_user
        cfg_data['run_uuid'] = run_uuid
        vms, disks, nics = init_provider(params=cfg_data)
    cfg_file, cfg_data = get_cfg()
    is_rmt = False
    if args.results_dir:
        cfg_data['results_dir'] = args.results_dir
    if args.remote_nodes:
        is_rmt = True
        cfg_data['remote_nodes'] = args.remote_nodes.split(',')
        cfg_data['remote_node'] =  cfg_data['remote_nodes'][0]
        cfg_data['remote_port'] = args.remote_port
        cfg_data['remote_user'] = args.remote_user
        cfg_data['remote_password'] = args.remote_password
        cfg_data['remote_keyfile'] = args.remote_keyfile

    if vms:
        is_rmt = True
        cfg_data['remote_nodes'] = []
        cfg_data['remote_node'] = None
        cfg_data['remote_user'] = args.remote_user
        cfg_data['remote_password'] = args.remote_password
        cfg_data['remote_keyfile'] = args.remote_keyfile

    results_dir = cfg_data['results_dir']
    results_dir_suffix = None
    if os.path.exists(results_dir) and not args.is_listcase:
        rmtree(results_dir)
        log.info("saving results to {}".format(results_dir))
    os_tests_dir = os.path.dirname(__file__)
    skip_patterns = args.skip_pattern
    test_patterns = args.pattern
    if args.image is not None:
        if 'azure' in args.image:
            log.info("only run azure image checks")
            if args.pattern:
                test_patterns = args.pattern
            else:
                test_patterns = 'test_azure_image'
        elif 'gcp' in args.image:
            log.info("only run gcp image checks")
            if args.pattern:
                test_patterns = args.pattern
            else:
                test_patterns = 'test_gcp_image'
        elif 'kvm' in args.image:
            log.info("only run rhel guest image checks")
            if args.pattern:
                test_patterns = args.pattern
            else:
                test_patterns = 'test_rhel_guest_image'
        else:
            log.info("only azure,gcp and rhel-kvm image check supported for now")
            sys.exit(0)
    else:
        log.info("skip azure,gcp and rhel-kvm image check by default")
        if skip_patterns and not args.verifydoc:
            skip_patterns = skip_patterns + ',test_azure_image,test_gcp_image,test_rhel_guest_image'
        else:
            if not args.verifydoc:
                skip_patterns = 'test_azure_image,test_gcp_image,test_rhel_guest_image'

    if not is_rmt and not args.platform_profile:
        log.info("skip lifecycle tests as no remote node found")
        if skip_patterns and not args.verifydoc:
            skip_patterns = skip_patterns + ',test_lifecycle'
        else:
            skip_patterns = 'test_lifecycle' 

    if not args.platform_profile and not args.verifydoc:
        skip_patterns = skip_patterns + ',test_vm_operation' if skip_patterns else 'test_vm_operation'

    log.info("{}Stage: Run Test{}".format('='*20,'='*20))
    log.info("Run in mode: is_listcase:{} test_patterns:{} skip_patterns:{}".format(args.is_listcase, test_patterns, skip_patterns))

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
                        case.is_rmt = is_rmt
                        case.params = cfg_data
                        case.run_uuid = run_uuid
                        case.utils_dir = utils_dir
                        case.data_dir = data_dir
                        case.SSHs = sshs
                        case.SSH = case.SSHs and case.SSHs[0] or None
                        case.vms = vms
                        case.vm = case.vms and vms[0] or None
                        case.disks = disks
                        case.disk = case.disks and disks[0] or None
                        case.nics = nics
                        case.nic = case.nics and nics[0] or None
                        if filter_case_doc(case=case, patterns=test_patterns, skip_patterns=skip_patterns,
                                           filter_field=args.filter_by, strict=args.is_strict, verify_doc=args.verifydoc):
                            final_ts.addTest(case)
                except Exception as err:
                    log.info("Cannot handle ts discovered:{}".format(ts2))
                    log.info(err)
    if final_ts.countTestCases() == 0:
        log.info("No case found!")
        sys.exit(1)
    if args.is_listcase or args.verifydoc:
        log.info('\n'.join([case.id() for case in final_ts]))
        log.info("Total case num: %s"%final_ts.countTestCases())
    else:
        HTMLTestRunner(verbosity=2).run(final_ts)

    for res in chain(vms, disks, nics):
        if hasattr(res, 'exists') and res.exists():
            res.delete()
        elif hasattr(res, 'is_exist') and res.is_exist():
            res.delete()
if __name__ == "__main__":
    main()
