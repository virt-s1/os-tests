import unittest
import copy
import os
import sys
from os_tests.libs.utils_lib import get_cfg, update_cfgs, init_ssh, init_args, init_provider, filter_case_doc
from os_tests.libs import utils_lib
from shutil import rmtree
import os_tests
from os_tests.libs.html_runner import HTMLTestRunner
import uuid
import logging
import re
from itertools import chain
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
LOG_FORMAT = '%(asctime)s:%(levelname)s:%(message)s'
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

def main():
    args = init_args()
    cfg_file, cfg_data = get_cfg()
    cfg_data['run_uuid'] = str(uuid.uuid4())
    update_cfgs(cfg_data, vars(args))
    vms, disks, nics, sshs = [], [], [], []
    if args.platform_profile and not args.is_listcase and not args.verifydoc:
        _, provider_data = get_cfg(cfg_file=args.platform_profile)
        update_cfgs(cfg_data, provider_data, update_exists_keys=True)
        provider_data = update_cfgs(cfg_data, provider_data, keep_base=True)
        vms, disks, nics = init_provider(params=provider_data)

    if args.remote_nodes:
        cfg_data['remote_nodes'] = args.remote_nodes.split(',')
        cfg_data['remote_node'] =  cfg_data['remote_nodes'][0]

    is_rmt = bool(args.remote_nodes or vms)

    results_dir = cfg_data['results_dir']
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

    log.info("{}Stage: Run Test{}".format('='*20,'='*20))
    log.info("Run in mode: is_listcase:{} test_patterns:{} skip_patterns:{}".format(args.is_listcase, test_patterns, skip_patterns))

    base_dir = os.path.realpath(os_tests.__file__)
    utils_dir = os.path.dirname(base_dir) + '/utils'
    data_dir = os.path.dirname(base_dir) + '/data'

    ts = unittest.defaultTestLoader.discover(start_dir=os_tests_dir,pattern='test_*.py', top_level_dir=os.path.dirname(os_tests_dir))
    tmp_ts = copy.deepcopy(ts)
    final_ts = unittest.TestSuite()
    tests_list = []
    for ts1 in tmp_ts:
        if len(ts1._tests) > 0:
            for ts2 in ts1._tests:
                try:
                    for case in ts2._tests:
                        case.is_rmt = is_rmt
                        case.params = cfg_data
                        case.run_uuid = cfg_data.get('run_uuid')
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
                            tests_list.append(case)
                except Exception as err:
                    log.info("Cannot handle ts discovered:{}".format(ts2))
                    log.info(err)
    # sort cases following the patterns specified order
    if test_patterns and 'case_name' in args.filter_by:
        sorted_tests = []
        for pattern in test_patterns.split(','):
            for case in tests_list:
                if re.match(".*{}.*".format(pattern),case.id(),re.IGNORECASE) and case not in sorted_tests:
                    sorted_tests.append(case)
        tests_list = sorted_tests
    final_ts.addTests(tests_list)
    if final_ts.countTestCases() == 0:
        log.info("No case found!")
        sys.exit(1)
    if args.is_listcase or args.verifydoc or args.dumpdoc:
        if args.dumpdoc:
            tmp_yaml_data = {}
            for case in final_ts:
                yaml_data = {}
                try:
                    src_content = case._testMethodDoc
                    yaml_data = load(src_content, Loader=Loader)
                    if not hasattr(yaml_data,'get'):
                        yaml_data = {}
                        yaml_data['description'] = src_content
                except Exception as err:
                    yaml_data['doc_yaml_err'] = str(err)
                    yaml_data['description'] = src_content
                yaml_data['case_name'] = case.id()
                tmp_yaml_data[case.id()] = yaml_data
            with open(args.dumpdoc,'w') as fh:
                dump(tmp_yaml_data,fh)
                log.info("Saved casesdoc to {}".format(args.dumpdoc))
        log.info('\n'.join([case.id() for case in final_ts]))
        log.info("Total case num: %s"%final_ts.countTestCases())
    else:
        HTMLTestRunner(verbosity=2).run(final_ts)

    for res in chain(vms, disks, nics):
        if args.no_cleanup:
            log.info("skipped resource cleanup because --no-cleanup found, please release resources manually")
            for i in chain(vms, disks, nics):
                if i.id:
                    log.info(i.id)
            break
        if hasattr(res, 'exists'):
            if res.exists():
                res.delete()
        elif hasattr(res, 'is_exist') and res.is_exist():
            res.delete()
if __name__ == "__main__":
    main()
