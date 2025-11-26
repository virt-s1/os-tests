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
    params = get_cfg()
    params['run_uuid'] = str(uuid.uuid4())
    tmp_params = {}
    if args.params_profile:
        tmp_params = get_cfg(cfg_file=args.params_profile)
        update_cfgs(params, tmp_params)
    vms, disks, nics, sshs, nets = [], [], [], [], []
    if params.get('Cloud') or args.platform_profile:
        if args.platform_profile:
            provider_data = get_cfg(cfg_file=args.platform_profile)
            update_cfgs(params, provider_data)
        update_cfgs(params, vars(args))
        if not args.is_listcase and not args.verifydoc and not args.dumpdoc:
            vms, disks, nics, nets = init_provider(params=params)
    update_cfgs(params, vars(args))

    if args.remote_nodes:
        params['remote_nodes'] = args.remote_nodes.split(',')
        params['remote_node'] =  params['remote_nodes'][0]

    is_rmt = bool(args.remote_nodes or vms)

    results_dir = params['results_dir']
    if os.path.exists(results_dir) and not params.get('is_listcase'):
        rmtree(results_dir)
        log.info("saving results to {}".format(results_dir))
    os_tests_dir = os.path.dirname(__file__)
    skip_patterns = params.get('skip_pattern')
    test_patterns = params.get('pattern')
    images_check = {'azure':'test_azure_image', 'gcp':'test_gcp_image',
                   'kvm':'test_rhel_guest_image','rhel-kvm':'test_rhel_guest_image'}
    
    if params.get('image') is not None:
        if params.get('image') not in images_check.keys():
            log.info("only {} image check supported for now".format(images_check.keys() ))
            sys.exit(0)
        test_patterns =  "{}{}{}".format(test_patterns or '', test_patterns and ',' or '',images_check.get(params.get('image')))   
    else:
        log.info("skip {} image check by default".format(images_check.keys()))
        if skip_patterns and not params.get('verifydoc'):
            skip_patterns = skip_patterns + ',test_azure_image,test_gcp_image,test_rhel_guest_image'
        else:
            if not params.get('verifydoc'):
                skip_patterns = 'test_azure_image,test_gcp_image,test_rhel_guest_image'

    log.info("{}Stage: Run Test{}".format('='*20,'='*20))
    log.info("Run in mode: is_listcase:{} test_patterns:{} skip_patterns:{}".format(params.get('is_listcase'), test_patterns, skip_patterns))

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
                        case.params = params
                        case.run_uuid = params.get('run_uuid')
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
                        case.createvm = True
                        if filter_case_doc(case=case, patterns=test_patterns, skip_patterns=skip_patterns,
                                           filter_field=params.get('filter_by'), strict=params.get('is_strict'), verify_doc=params.get('verifydoc')):
                            tests_list.append(case)
                except Exception as err:
                    log.info("Cannot handle ts discovered:{}".format(ts2))
                    log.info(err)
    # sort cases following the patterns specified order
    if test_patterns and 'case_name' in params.get('filter_by'):
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
    if params.get('is_listcase') or params.get('verifydoc') or params.get('dumpdoc'):
        if params.get('dumpdoc'):
            tmp_yaml_data = {}
            for case in final_ts:
                yaml_data = {}
                try:
                    src_content = case._testMethodDoc
                    # remove the line added by @parameterized.expand()
                    src_content = "\n".join(l for l in src_content.splitlines() if not l.startswith("with parameter: [with"))
                    yaml_data = load(src_content, Loader=Loader)
                    if not hasattr(yaml_data,'get'):
                        yaml_data = {}
                        yaml_data['description'] = src_content
                except Exception as err:
                    yaml_data['doc_yaml_err'] = str(err)
                    yaml_data['description'] = src_content
                yaml_data['case_name'] = case.id()
                tmp_yaml_data[case.id()] = yaml_data
            with open(params.get('dumpdoc'),'w') as fh:
                dump(tmp_yaml_data,fh)
                log.info("Saved casesdoc to {}".format(params.get('dumpdoc')))
        case_name_list = [ case.id() for case in final_ts ]
        log.info('\n'.join(["{} - {}/{}".format(case_name,case_name_list.index(case_name)+1,len(case_name_list)) for case_name in case_name_list]))
        log.info("Total case num: %s"%final_ts.countTestCases())
    else:
        HTMLTestRunner(verbosity=2).run(final_ts)

    for res in chain(vms, disks, nics, nets):
        if params.get('no_cleanup'):
            log.info("skipped resource cleanup because --no-cleanup found, please release resources manually")
            for i in chain(vms, disks, nics, nets):
                if i.id:
                    log.info(i.id)
            break
        if hasattr(res, 'exists'):
            if res.exists():
                res.delete()
        elif hasattr(res, 'is_exist') and res.is_exist():
            res.delete()
    if 'Cloud' in params and params['Cloud'].get('provider') == 'kvm':
        utils_lib.stop_httpserver()

if __name__ == "__main__":
    main()
