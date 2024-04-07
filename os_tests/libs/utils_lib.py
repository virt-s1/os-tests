import base64
from copy import deepcopy
import os
import random
import re
import sys
import time
import logging
import decimal
import subprocess
import os_tests
from os_tests import tests
import json
import difflib
import time
import logging
import argparse
from tipset.libs import rmt_ssh
from functools import wraps
from itertools import chain
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

LOG = logging.getLogger('os_tests.os_tests_run')

def init_args():
    parser = argparse.ArgumentParser(
    description="os-tests is a lightweight, fast check and tests collection for Linux OS.")
    parser.add_argument('-l', dest='is_listcase', action='store_true',
                    help='list supported cases without run', required=False)
    parser.add_argument('-p', dest='pattern', default=None, action='store',
                    help='filter case by name and run it in specified order, add --strict for matching exactly', required=False)
    parser.add_argument('--strict', dest='is_strict', action='store_true',
                    help='match exactly if -p or -s specified', required=False)
    parser.add_argument('-s', dest='skip_pattern', default=None, action='store',
                    help='skip cases, add --strict for skipping exactly', required=False)
    parser.add_argument('--verifydoc', dest='verifydoc', action='store_true',
                    help='verify or show case doc only', required=False)
    parser.add_argument('--dumpdoc', dest='dumpdoc', default=None, action='store',
                    help='dump doc to yaml file', required=False)
    parser.add_argument('--filter_by', dest='filter_by', default='case_name', action='store',
                    help="filter by 'case_name'(default),'case_tag','case_file','component','bugzilla_id',\
                        'is_customer_case','testplan','maintainer','description','key_steps',\
                        'expect_result','debug_want'", required=False)
    parser.add_argument('--hosts', dest='remote_nodes', default=None, action='store',
                    help='run tests on remote nodes', required=False)
    parser.add_argument('--port', dest='remote_port', default=22, action='store',
                    help='port for ssh connection, default is 22', required=False)
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
    parser.add_argument('--platform_profile', dest='platform_profile', default=None, action='store',
                    help='specify platform profile if enable os-tests provison vms self, only supports aws for now', required=False)
    parser.add_argument('--no-cleanup', dest='no_cleanup', action='store_true',
                    help='debug purpose, skip cleanup phase at exit, do not use it in normal test', required=False)
    parser.add_argument('--proxy_url', dest='proxy_url', default=None, action='store',
                    help='specify it if pkg/repo url is internal only, format IP:PORT', required=False)
    parser.add_argument('--case_setup', dest='case_setup', default=None, action='store',
                    help='fips_enable,fips_disable,debugkernel_enable,debugkernel_disable,commands or a bash file before running into case steps,can add timeout:XXX if default 600 is not enough for operation done', required=False)
    parser.add_argument('--case_post', dest='case_post', default=None, action='store',
                    help='collect_kmemleak, other args are similar as case_setup, usually for collecting temporary debug information, can add timeout:XXX if default 600 is not enough for operation done', required=False)
    parser.add_argument('--subscription_username', dest='subscription_username', default=None, action='store',
                    help='username for RHSM register', required=False)
    parser.add_argument('--subscription_password', dest='subscription_password', default=None, action='store',
                    help='password for RHSM register', required=False)
    args = parser.parse_args()
    return args

def init_provider(params=None):
    # this init provider from cfg
    vms = []
    disks = []
    nics = []
    supported_platforms = ['aws', 'openstack', 'ali', 'nutanix', 'google', 'libvirt', 'openshift']
    provider = params['Cloud']['provider']
    os.environ['INFRA_PROVIDER'] = provider
    if not provider:
        LOG.info("no provider found in profile".format(provider, supported_platforms))
        sys.exit(1)
    elif provider not in supported_platforms:
        LOG.info("{} not in supported platforms:{}".format(provider, supported_platforms))
        sys.exit(1)

    if 'aws' in provider:
        from .resources_aws import EC2VM,EC2Volume,EC2NIC
        # init resources only without create them at very beginning
        vms.extend([EC2VM(params),EC2VM(params)])
        disks.append(EC2Volume(params))
        nics.extend([EC2NIC(params),EC2NIC(params),EC2NIC(params),EC2NIC(params)])
        if params.get('instance_type') and ',' in params.get('instance_type'):
            vms[1].instance_type = params.get('instance_type').split(',')[-1] or params.get('instance_type').split(',')[0]
    if 'openstack' in provider:
        from .resources_openstack import OpenstackVM
        vms.append(OpenstackVM(params))
    if 'ali' in provider:
        from .resources_alicloud import AlibabaVM,AlibabaVolume
        vms.append(AlibabaVM(params))
        vm1 = AlibabaVM(params)
        vm1.vm_name += '-vm1'
        vm1.ecs.vm_params["InstanceName"] = vm1.ecs.vm_params["HostName"] = vm1.vm_name
        vms.append(vm1)
        disks.append(AlibabaVolume(params))
    if 'nutanix' in provider:
        from .resources_nutanix import NutanixVM,NutanixVolume
        vms.append(NutanixVM(params))
        disks.append(NutanixVolume(params))
    if 'google' in provider:
        from .resources_gcp import GCPVM
        vms.append(GCPVM(params))
    if 'libvirt' in provider:
        from .resources_libvirt import LibvirtVM
        vms.append(LibvirtVM(params))
    if 'openshift' in provider:
        from .resources_openshift import OpenShiftVM
        vms.append(OpenShiftVM(params))

    return vms, disks, nics

def init_provider_from_guest(test_instance):
    # this init provider from system itself
    if os.getenv('INFRA_PROVIDER'):
        test_instance.log.info("already set provider to {}".format(os.getenv('INFRA_PROVIDER')))
        return True
    provider = 'UNKNOW'
    if is_aws(test_instance):
        provider = 'aws'
    if is_openstack(test_instance):
        provider = 'openstack'
    if is_ali(test_instance):
        provider = 'ali'
    if is_ahv(test_instance):
        provider = 'nutanix'
    if is_gcp(test_instance):
        provider = 'google'
    os.environ['INFRA_PROVIDER'] = provider

def update_cfgs(base_cfg={}, new_cfg={}, keep_base = False, update_exists_keys = False):
    '''
    update base_cfg according to new_cfg
    keep_base: yes or no to change base_cfg
    update_exists_keys: yes or no to update base_cfg if base_cfg has the same key
    '''
    if keep_base:
        tmp_cfg = deepcopy(base_cfg)
    else:
        tmp_cfg = base_cfg
    if update_exists_keys:
        for key in new_cfg.keys():
            if new_cfg.get(key) is not None and key in tmp_cfg.keys():
                tmp_cfg[key] = new_cfg.get(key)
    else:
        for key in new_cfg.keys():
            if new_cfg.get(key) is not None or key not in tmp_cfg.keys():
                tmp_cfg[key] = new_cfg.get(key)
    return tmp_cfg

def init_ssh(params=None, timeout=600, interval=10, log=None, rmt_node=None):
    if log is None:
        LOG_FORMAT = '%(levelname)s:%(message)s'
        log = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    ssh = rmt_ssh.RemoteSSH()
    ssh.rmt_node = rmt_node or params.get('remote_node')
    ssh.port = params.get('remote_port')
    ssh.rmt_user = params.get('remote_user')
    ssh.rmt_password = params.get('remote_password')
    ssh.rmt_keyfile = params.get('remote_keyfile')
    ssh.rmt_proxy = params.get('proxy_url')
    ssh.log = log
    ssh.timeout = timeout
    ssh.interval = interval
    ssh.create_connection()
    return ssh

def init_connection(test_instance, timeout=600, interval=10, rmt_node=None, vm=None, retry=3):
    if not test_instance.params['remote_node'] and not rmt_node and not vm and not test_instance.vm:
        return False
    new_vm_ip = None
    is_master_vm = False
    if test_instance.vm:
        new_vm_ip =  test_instance.vm.floating_ip
        if new_vm_ip != test_instance.params['remote_node']:
            test_instance.params['remote_node'] = new_vm_ip
            if test_instance.params['remote_nodes']:
                test_instance.params['remote_nodes'][0] = new_vm_ip
            else:
                test_instance.params['remote_nodes'].append(new_vm_ip)
            test_instance.log.info("set default remote_node to new address {}".format(test_instance.params['remote_node']))
            is_master_vm = True
    test_instance.log.info("Current IP bucket:{}".format(test_instance.params['remote_nodes']))
    rmt_node = rmt_node or test_instance.params['remote_node'] or None
    if vm:
        if hasattr(vm, 'floating_ip'):
            rmt_node = vm.floating_ip
        if vm.dead_count > 4:
            test_instance.fail("cannot connect to vm over 4 times, skip retry to connect it")
    if not rmt_node:
        test_instance.fail("no rmt_node found")
    test_instance.log.info("init connection to {}.".format(rmt_node))
    ssh_exists = False
    is_active = False
    try:
        ssh_num = 0
        for i, ssh in enumerate(test_instance.SSHs):
            ssh.log = test_instance.log
            if ssh.rmt_node == new_vm_ip:
                test_instance.SSH = ssh
            if ssh.rmt_node == rmt_node:
                ssh_exists = True
                ssh_num = i
                if hasattr(ssh, 'is_active'):
                    # this is avaiable in tipset >= 0.2.0
                    is_active = ssh.is_active()
                else:
                    #can remove below when all use ssh.is_active()
                    ret, _, _ = ssh.cli_run(cmd='uname -r')
                    if ret == 0:
                        test_instance.log.info("connection is live")
                        is_active = True
                break
        for tmp_ssh in test_instance.SSHs:
            if tmp_ssh.rmt_node == test_instance.params['remote_node']:
                test_instance.SSH = tmp_ssh
                break
    except AttributeError:
        pass
    except Exception:
        test_instance.log.info("connection is not live")
    for i in range(0,retry):
        if ssh_exists:
            test_instance.log.info("found existing connection, re-connect")
            if is_active:
                test_instance.SSHs[ssh_num].close()
            test_instance.SSHs[ssh_num].timeout = timeout
            test_instance.SSHs[ssh_num].create_connection()
            ssh = test_instance.SSHs[ssh_num]
        else:
            ssh = init_ssh(params=test_instance.params, timeout=timeout, interval=interval, log=test_instance.log, rmt_node=rmt_node)
            if ssh.ssh_client:
                test_instance.SSHs.append(ssh)
        if ssh.ssh_client:
            break
        test_instance.log.info("retry again {}/{}".format(i,retry))
    vm = vm or test_instance.vm
    if not ssh.ssh_client:
        if vm:
            try:
                vm.get_console_log()
            except NotImplementedError:
                test_instance.log.info("{} not implement this func: get_console_log".format(vm.provider))
            vm.dead_count += 1
            test_instance.log.info("vm dead times:{}".format(vm.dead_count))
            if vm.dead_count == 2:
                test_instance.log.info("vm cannot connect in {} times, restart it".format(vm.dead_count))
                vm.stop()
                vm.start()
            if vm.dead_count == 3:
                test_instance.log.info("vm cannot connect in {} times, re-create it".format(vm.dead_count))
                vm.delete()
                vm.create()
        test_instance.fail("Cannot make ssh connection to remote, please check")
    if vm:
        vm.dead_count = 0
    for tmp_ssh in test_instance.SSHs:
        if tmp_ssh.rmt_node == test_instance.params['remote_node']:
            test_instance.SSH = tmp_ssh
            break
    return True

def send_ssh_cmd(rmt_node, rmt_user, rmt_password, command, timeout=60):
    ssh = rmt_ssh.RemoteSSH()
    ssh.rmt_node = rmt_node
    ssh.rmt_user = rmt_user
    ssh.rmt_password = rmt_password
    ssh.create_connection()
    status, outputs = ssh.remote_excute(command, timeout)
    logging.info('\n command: %s \n status %s \n outputs %s \n' % (command, status, outputs))
    ssh.close()

    return [status,outputs]

def get_cfg(cfg_file = None):
    # Config file
    if not cfg_file:
        cfg_file = os.path.dirname(os_tests.__file__) + "/cfg/os-tests.yaml"
    if not os.path.exists(cfg_file):
        print("{} config file not found!".format(cfg_file))
        sys.exit(1)
        return cfg_file, None
    keys_data = load_yaml(yaml_file=cfg_file)
    if keys_data.get('remote_nodes'):
        keys_data['remote_nodes'] = keys_data['remote_nodes'].split(',')
        keys_data['remote_node'] =  keys_data['remote_nodes'][0]
    return cfg_file, keys_data

def load_yaml(yaml_file = None, yaml_content = None):
    keys_data = None
    try:
        if yaml_file:
            with open(yaml_file,'r') as fh:
                keys_data = load(fh, Loader=Loader)
            return keys_data
        if yaml_content:
            keys_data = load(yaml_content,Loader=Loader)
    except Exception as err:
        print(err)
    return keys_data

def init_case(test_instance):
    """init case
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    """
    if not hasattr(test_instance,'params'):
        cfg_file, keys_data = get_cfg()
        test_instance.params = keys_data
    results_dir = test_instance.params['results_dir']
    attachment_dir = results_dir + "/attachments"
    test_instance.log_dir = results_dir
    if not os.path.exists(results_dir):
        os.mkdir(results_dir)
    if not os.path.exists(attachment_dir):
        os.mkdir(attachment_dir)
    test_class_name = test_instance.__class__.__name__
    case_dir = '.'.join([test_class_name, test_instance.id()])
    debug_dir = os.path.join(attachment_dir, case_dir)
    if not os.path.exists(debug_dir):
        os.mkdir(debug_dir)
    case_log = test_instance.id() + ".debug"
    log_file = debug_dir + '/' + case_log
    if os.path.exists(log_file):
        os.unlink(log_file)
    test_instance.log = logging.getLogger(__name__)
    for handler in logging.root.handlers[:]:
        handler.close()
        logging.root.removeHandler(handler)
    FORMAT = '%(asctime)s:%(levelname)s:%(message)s'
    logging.basicConfig(level=logging.INFO, format=FORMAT, filename=log_file)
    test_instance.log.info("-"*80)
    test_instance.log.info("Code Repo: {}".format(test_instance.params['code_repo']))
    test_instance.log.info("Code Version: v{}".format(os_tests.__version__))
    test_instance.log.info("Case ID: {}".format(test_instance.id()))
    test_instance.log.info("Case Doc: {}".format(eval(test_instance.id()).__doc__))
    test_instance.log.info("Case Params:")
    for key in test_instance.params.keys():
        if key in ['password', 'subscription_username', 'subscription_password']:
            test_instance.log.info("key:{}, val:*******".format(key))
        else:
            test_instance.log.info("key:{}, val:{}".format(key, test_instance.params[key]))
    test_instance.log.info("-"*80)
    test_instance.ssh_timeout = 180
    test_instance.default_boot_index = None
    test_instance.skipflag = False
    if test_instance.vm:
        if test_instance.vm.dead_count > 4:
            test_instance.fail("cannot connect to vm over 4 times, skip retry")
        if test_instance.vm.is_metal:
            test_instance.ssh_timeout = 1200
        if not test_instance.vm.exists():
            test_instance.vm.create()
        if hasattr(test_instance.vm, 'get_state') and 'stopping' in str(test_instance.vm.get_state()):
            for count in iterate_timeout(
                600, "Timed out waiting for getting server stopped."):
                if test_instance.vm.is_stopped(): break
        if test_instance.vm.is_stopped():
            test_instance.vm.start(wait=True)
        test_instance.params['remote_port'] = test_instance.vm.port or 22

    if test_instance.is_rmt:
        test_instance.log.info('ssh connection timeout:{}'.format(test_instance.ssh_timeout))
        init_connection(test_instance, timeout=test_instance.ssh_timeout)
        if not test_instance.params['remote_node']:
            test_instance.fail("remote_node not found")
        if test_instance.SSH:
            test_instance.SSH.log = test_instance.log
            if  not test_instance.SSH.ssh_client:
                test_instance.fail("Cannot make ssh connection to remote, please check!")
    node_info = "{}/node_info".format(attachment_dir)
    node_info_data = {}
    if not os.path.exists(node_info):
        test_instance.log.info("retrive node info.")
        node_info_data['release_name'] = get_os_release_info(test_instance, field="NAME").rstrip('\n| ')
        node_info_data['release_version'] = get_os_release_info(test_instance, field="VERSION").rstrip('\n| ')
        node_info_data['kernel_version'] = run_cmd(test_instance, 'uname -r').rstrip('\n| ')
        node_info_data['product_name'] = run_cmd(test_instance, 'cat /sys/devices/virtual/dmi/id/product_name').rstrip('\n| ')
        node_info_data['sys_vendor'] = run_cmd(test_instance, 'cat /sys/devices/virtual/dmi/id/sys_vendor').rstrip('\n| ')
        #with open(node_info, 'w+') as fh:
        #    fh.write("{} {} - {}".format(release_name, release_version, kernel_version))
        with open(node_info, 'w+') as fh:
            dump(node_info_data,fh)
        test_instance.node_info = node_info_data
    else:
        _, test_instance.node_info = get_cfg(cfg_file=node_info)
    init_provider_from_guest(test_instance)
    core_file_check(test_instance)
    extra_case_setups = test_instance.params.get('case_setup')
    extra_step_parser(test_instance, extra_steps=extra_case_setups)

def finish_case(test_instance):
    """finish case
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    """
    for case, reason in chain(test_instance._outcome.result.failures,test_instance._outcome.result.errors):
        if case.id() == test_instance.id():
             test_instance.log.info(reason)
    extra_case_posts = test_instance.params.get('case_post')
    extra_step_parser(test_instance, extra_steps=extra_case_posts)

def extra_step_parser(test_instance, extra_steps=None):
    if not extra_steps:
        test_instance.log.info("no extra steps detected, you can try case_setup or case_setup to inject more operations before or after case.")
        return True
    test_instance.log.info("extra case steps detected, parse it:{}".format(extra_steps))
    exe_timout = 600
    for extra_case_setup in extra_steps.split(','):
        if "timeout:" in extra_case_setup:
            exe_timout = int(extra_case_setup.split(':')[-1])
            test_instance.log.info("extra case exec timeout detected, use it:{}".format(exe_timout))
            break
    for extra_case_setup in extra_steps.split(','):
        test_instance.log.info("try to understand: {}".format(extra_case_setup))
        if "timeout:" in extra_case_setup:
            continue
        inputs_list = extra_case_setup.split(' ')
        cmdfile = inputs_list[0]
        cmdfile_exists = False
        if cmdfile:
            ret = run_cmd(test_instance, cmd="sudo ls {}".format(cmdfile), ret_status=True, msg='guess {} is a file'.format(cmdfile))
            if ret == 0:
                cmdfile_exists = True
        cmd_options = ''
        if len(inputs_list) > 1:
            cmd_options = ' '.join(inputs_list[1:])
        if os.path.isfile(cmdfile):
            rmt_file = "/tmp/{}".format(os.path.basename(cmdfile))
            if test_instance.is_rmt and not cmdfile_exists:
                test_instance.SSH.put_file(local_file=cmdfile, rmt_file=rmt_file)
            run_cmd(test_instance, cmd="cat {}".format(rmt_file), msg='show file content')
            run_cmd(test_instance, cmd="sudo chmod 777 {}".format(rmt_file), msg='add execute permission')
            run_cmd(test_instance, cmd="sudo {} {}".format(rmt_file, cmd_options), timeout=exe_timout, msg='run the script')
        else:
            funcs = [fips_enable,fips_disable,debugkernel_enable,debugkernel_disable,collect_kmemleak]
            is_func = False
            for func in funcs:
                if func.__name__ in extra_case_setup:
                    is_func = True
                    test_instance.log.info("call {}".format(func.__name__))
                    func(test_instance)
            if not is_func:
                run_cmd(test_instance, cmd=extra_case_setup, timeout=exe_timout, msg='run the {} content as command'.format(extra_case_setup))

def filter_case_doc(case=None, patterns=None, skip_patterns=None, filter_field='case_name', strict=False, verify_doc=False ):
    if patterns is None and skip_patterns is None and not verify_doc:
        return True
    yaml_data = {}
    yaml_fail = None
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
    is_skip = False
    is_select = False
    field_value = yaml_data.get(filter_field)
    if patterns:
        for p in patterns.split(','):
            if 'case_tag' in filter_field:
                if not field_value:
                    break
                # case_tag might has multiples
                for tag_value in field_value.split(','):
                    if not strict and p in tag_value or strict and p == tag_value:
                        is_select = True
                        break
                if is_select:
                    break
            else:
                if not strict and field_value and p in field_value:
                    is_select = True
                    break
                if strict and field_value and p == field_value:
                    is_select = True
                    break
    else:
        is_select = True
    if skip_patterns:
        for p in skip_patterns.split(','):
            if 'case_tag' in filter_field:
                if not field_value:
                    break
                # case_tag might has multiples
                for tag_value in field_value.split(','):
                    if not strict and p in tag_value or strict and p == tag_value:
                        is_skip = True
                        break
                if is_skip:
                    break
            else:
                if not strict and field_value and p in field_value:
                    is_skip = True
                    break
                if strict and field_value and p == field_value:
                    is_skip = True
                    break
    if verify_doc and is_select and not is_skip:
        from tipset.libs import polarion_adm
        print("="*20)
        print(case.id())
        print(case._testMethodDoc)
        print("-"*20)
        if yaml_data.get('doc_yaml_err'):
            print(yaml_data.get('doc_yaml_err'))
            return is_select and not is_skip
        polarion_adm.verify_doc(casedoc = yaml_data)
    return is_select and not is_skip

def msg_to_syslog(test_instance, cmd='sudo virt-what', msg=None):
    '''
    Save msg to journal log and dmesg.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        cmd {string} -- append cmd output to journal and dmesg
        msg {string} -- msg want to save, default is casename
    '''
    if msg is None:
        msg = test_instance.id()
    output = ''
    if cmd:
        output = run_cmd(test_instance, cmd)
    cmd = 'sudo echo os-tests:"{} \n{}" | systemd-cat -p info'.format(msg, output)
    run_cmd(test_instance, cmd, expect_ret=0)
    cmd = "sudo bash -c 'echo \"{} \n{}\" > /dev/kmsg'".format(msg, output)
    run_cmd(test_instance, cmd, expect_ret=0)

def run_cmd(test_instance,
            cmd,
            expect_ret=None,
            expect_not_ret=None,
            expect_kw=None,
            expect_not_kw=None,
            expect_output=None,
            msg=None,
            cancel_kw=None,
            cancel_not_kw=None,
            cancel_ret=None,
            cancel_not_ret=None,
            timeout=120,
            ret_status=False,
            is_log_output=True,
            is_log_cmd=True,
            cursor=None,
            rmt_redirect_stdout=False,
            rmt_redirect_stderr=False,
            rmt_get_pty=False,
            rmt_node = None,
            vm = None
            ):
    """run cmd with/without check return status/keywords and save log

    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        cmd {string} -- cmd to run
        expect_ret {int} -- expected return status
        expect_not_ret {int} -- unexpected return status
        expect_kw {string} -- string expected in output,seperate by ',' if
                              check multi words
        expect_not_kw {string} -- string not expected in output, seperate by
                                  ',' if check multi words
        expect_output {string} -- string exactly the same as output
        cancel_kw {string} -- cancel case if kw not found, seperate by ','
                              if check multi words
        cancel_not_kw {string} -- cancel case if kw found, seperate by ','
                              if check multi words
        cancel_ret {string} -- cancel case if ret code not match, seperate by ','
                              if check multi rets
        cancel_not_ret {string} -- cancel case if ret code found, seperate by ','
                              if check multi rets
        msg {string} -- addtional info to mark cmd run.
        ret_status {bool} -- return ret code instead of output
        is_log_output {bool} -- print cmd output or not
        is_log_cmd {bool} -- print cmd or not
        cursor {string} -- skip content before cursor(line)
        rmt_redirect_stdout {bool} -- ssh command not exit some times, redirect stdout to tmpfile if needed
        rmt_redirect_stderr {bool} -- ssh command not exit some times, redirect stderr to tmpfile if needed
        rmt_node {string} -- run command on specific rmt node
        vm {vm} -- run command on specific vm

    Keyword Arguments:
        check_ret {bool} -- [whether check return] (default: {False})
    """
    if msg is not None:
        test_instance.log.info(msg)
    status = None
    output = None
    exception_hit = False
    run_err = ''
    ssh_index = 0

    try:
        if test_instance.is_rmt:
            if not test_instance.params['remote_node'] and not rmt_node and not vm:
                return
            rmt_node = rmt_node or test_instance.params['remote_node'] or None
            if vm:
                if hasattr(vm, 'floating_ip'):
                    rmt_node = vm.floating_ip
            SSH = None
            for i, ssh in enumerate(test_instance.SSHs):
                ssh.log = test_instance.log
                if ssh.rmt_node == rmt_node:
                    SSH = ssh
                    ssh_index = i
                    break
            if is_log_cmd:
                test_instance.log.info("CMD: {} on {}".format(cmd, rmt_node))
            status, output = SSH.remote_excute(cmd, timeout, is_log_cmd, redirect_stdout=rmt_redirect_stdout, redirect_stderr=rmt_redirect_stderr,rmt_get_pty=rmt_get_pty)
        else:
            if is_log_cmd:
                test_instance.log.info("CMD: {}".format(cmd))
            ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, encoding='utf-8')
            #ret = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, encoding='utf-8')
            status = ret.returncode
            if ret.stdout is not None:
                output = ret.stdout
            #if ret.stderr is not None:
            #    output = output + ret.stderr

    except Exception as err:
        test_instance.log.error("Run cmd failed: {}".format(err))
        status = None
        exception_hit = True
        run_err = str(err)

    if exception_hit:
        test_cmd = 'uname -a'
        test_instance.log.info("Test system is alive via cmd:{}. If still fail, check no hang or panic happens.".format(test_cmd))
        try:
            if test_instance.is_rmt:
                if 'Key-exchange timed out' in run_err:
                    test_instance.log.info('reconnect to remote because it acheived certain number of packets or bytes sent or received using this session')
                    test_instance.SSHs[ssh_index].create_connection()
                    SSH = test_instance.SSHs[ssh_index]
                status, output = SSH.remote_excute(test_cmd, timeout)
                status, output = SSH.remote_excute(cmd, timeout, is_log_cmd, redirect_stdout=rmt_redirect_stdout, redirect_stderr=rmt_redirect_stderr,rmt_get_pty=rmt_get_pty)
            else:
                ret = subprocess.run(test_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, encoding='utf-8')
                status = ret.returncode
                if ret.stdout is not None:
                   output = ret.stdout
                test_instance.log.info("CMD ret: {} out:{}".format(status, output))
                if is_log_cmd:
                    test_instance.log.info("Retry to run CMD: {}".format(cmd))
                status = None
                output = None
                ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, encoding='utf-8')
                status = ret.returncode
                if ret.stdout is not None:
                   output = ret.stdout
        except Exception as err:
            test_instance.log.error("Run cmd failed again {}".format(err))
    if status is None and test_instance.vms:
        for vm in test_instance.vms:
            if vm.exists() and rmt_node == vm.floating_ip:
                try:
                    test_instance.vm.get_console_log()
                except NotImplementedError:
                    test_instance.log.info("{} not implement this func: get_console_log".format(test_instance.vm.provider))

    if cursor is not None and output is not None and cursor in output:
        output = output[output.index(cursor):]
    if is_log_output:
        test_instance.log.info("CMD ret: {} out:{}".format(status, output))
    else:
        test_instance.log.info("CMD ret: {}".format(status))
    if expect_ret is not None:
        test_instance.assertEqual(status,
                         expect_ret,
                         msg='ret is %s, expected is %s' %
                         (status, expect_ret))
    if expect_not_ret is not None:
        test_instance.assertNotEqual(
            status,
            expect_not_ret,
            msg='ret is %s, expected not ret is %s' %
            (status, expect_not_ret))
    if expect_kw is not None:
        for key_word in expect_kw.split(','):
            find_list = re.findall('{}'.format('.*' in key_word and key_word or ".*{}.*".format(key_word)), output)
            if find_list:
                test_instance.log.info('expected "{}" found in "{}"'.format(key_word, ''.join(find_list)))
            else:
                if output is not None and output.count('\n') > 5:
                    test_instance.fail('expected "{}" not found in output(check debug log as too many lines)'.format(key_word))
                else:
                    test_instance.fail('expected "{}" not found in "{}"'.format(key_word,output))
    if expect_not_kw is not None:
        for key_word in expect_not_kw.split(','):
            find_list = re.findall('{}'.format('.*' in key_word and key_word or ".*{}.*".format(key_word)), output)
            if not find_list:
                test_instance.log.info('Unexpected "{}" not found in output'.format(key_word))
            else:
                if output is not None and output.count('\n') > 5:
                    test_instance.fail('Unexpected "{}" found in {}'.format(key_word, ''.join(find_list)))
                else:
                    test_instance.fail('Unexpected "{}" found in "{}"'.format(key_word,output))
    if expect_output is not None:
        test_instance.assertEqual(expect_output,
                         output.rstrip('\n'),
                         msg='exactly expected %s' %
                         (expect_output))
    if cancel_kw is not None:
        cancel_yes = True
        for key_word in cancel_kw.split(','):
            if key_word in output:
                cancel_yes = False
        if cancel_yes:
            test_instance.skipTest("'%s' not found, cancel case. msg:%s" % (cancel_kw, msg))
    if cancel_not_kw is not None:
        for key_word in cancel_not_kw.split(','):
            if key_word in output:
                test_instance.skipTest("'%s' found, cancel case. msg:%s" % (key_word, msg))
    if cancel_ret is not None:
        cancel_yes = True
        for ret in cancel_ret.split(','):
            if int(ret) == int(status):
                cancel_yes = False
        if cancel_yes:
            test_instance.skipTest("expected ret code '{}' not match ret '{}', cancel case. msg:{}".format(cancel_ret, status, msg))
    if cancel_not_ret is not None:
        for ret in cancel_not_ret.split(','):
            if int(ret) == int(status):
                test_instance.skipTest("skip ret code '%s' found act ret '%s' cancel case. msg:%s" % (ret, status, msg))
    if ret_status:
        return status
    return output

def compare_nums(test_instance, num1=None, num2=None, ratio=0, msg='Compare 2 nums'):
    '''
    Compare num1 and num2.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        num1 {int} -- num1
        num2 {int} -- num2
        ratio {int} -- allow ratio
    Return:
        num1 < num2: return True
        (num1 - num2)/num2*100 > ratio: return False
        (num1 - num2)/num2*100 < ratio: return True
    '''
    num1 = float(num1)
    num2 = float(num2)
    ratio = float(ratio)
    test_instance.log.info(msg)
    if num1 < num2:
        test_instance.log.info("{} less than {}".format(num1, num2))
        return True
    if (num1 - num2)/num2*100 > ratio:
        test_instance.fail("{} vs {} over {}%".format(num1, num2, ratio))
    else:
        test_instance.log.info("{} vs {} less {}%, pass".format(num1, num2, ratio))

def getboottime(test_instance):
    '''
    Get system boot time via "systemd-analyze"
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    '''
    run_cmd(test_instance, "which systemd-analyze", expect_ret=0)
    time_start = int(time.time())
    while True:
        output = run_cmd(test_instance, "systemd-analyze")
        if 'Bootup is not yet finished' not in output:
            break
        time_end = int(time.time())
        run_cmd(test_instance, 'systemctl list-jobs')
        if time_end - time_start > 60:
            test_instance.fail("Bootup is not yet finished after 60s")
        test_instance.log.info("Wait for bootup finish......")
        time.sleep(1)
    cmd = "systemd-analyze blame > /tmp/blame.log"
    run_cmd(test_instance, cmd, expect_ret=0)
    run_cmd(test_instance, "cat /tmp/blame.log", expect_ret=0)
    output = run_cmd(test_instance, "systemd-analyze", expect_ret=0)
    boot_time = re.findall("=.*s", output)[0]
    boot_time = boot_time.strip("=\n")
    boot_time_sec = re.findall('[0-9.]+s', boot_time)
    # If ends with 'ms', e.g. 1min 76ms, ignore the ms time.
    boot_time_sec = boot_time_sec[0] if boot_time_sec else '0s'
    boot_time_sec = boot_time_sec.strip('= s')
    if 'min' in boot_time:
        boot_time_min = re.findall('[0-9]+min', boot_time)[0]
        boot_time_min = boot_time_min.strip('min')
        boot_time_sec = int(boot_time_min) * 60 + decimal.Decimal(boot_time_sec).to_integral()
    test_instance.log.info(
        "Boot time is {}(s)".format(boot_time_sec))
    return boot_time_sec

def is_sev_enabled(test_instance):
    '''
    Check whether SEV is enabled on the system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    Return:
        enabled: return True
        N/A: return False
    '''
    if not test_instance.vm:
        test_instance.skipTest("Skip as no VM provisioned.")
    if test_instance.vm.provider == 'google':
        audience = 'aud'
        cmd = "curl -s -H 'Metadata-Flavor: Google' \
            'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience={}&format=full'".format(audience)
        token = run_cmd(test_instance, cmd, expect_ret=0)
        if test_instance.vm.is_sev_enabled(token, audience):
            return True
        else:
            return False
    elif test_instance.vm.provider == 'aws':
        return test_instance.vm.sev_snp_enabled
    else:
        test_instance.skipTest("Skip as unable to determine sev status")
    return False

def is_arch(test_instance, arch="", action=None):
    '''
    Check whether system is specific system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        arch {string} -- arch want to check
        action {string} -- cancel case if it is not arch
    Return:
        arm: return True
        other: return False
    '''
    output = run_cmd(test_instance, "lscpu", expect_ret=0)
    if arch in output:
        test_instance.log.info("{}detected.".format(arch))
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non {} platform.".format(arch))
    test_instance.log.info("Not an {} instance.".format(arch))
    return False

def is_aws(test_instance, action=None):
    '''
    Check whether system is a aws system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a aws system
    Return:
        aws: return True
        other: return False
    '''
    if is_pkg_installed(test_instance, pkg_name='virt-what', cancel_case=False, is_install=False):
        output = run_cmd(test_instance, "sudo bash -c 'cat /sys/devices/virtual/dmi/id/bios_*; virt-what'", expect_ret=0)
    else:
        output = run_cmd(test_instance, "sudo cat /sys/devices/virtual/dmi/id/bios_*", expect_ret=0)
    if any(x in output.lower() for x in ['aws', 'amazon']):
        test_instance.log.info("AWS system.")
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non aws system.")
        test_instance.log.info("Not an aws system.")
    return False

def is_azure(test_instance, action=None):
    '''
    Check whether system is an azure system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a azure system
    Return:
        azure: return True
        other: return False
    '''
    output = run_cmd(test_instance, "[[ -f /usr/sbin/route ]] || sudo yum install -y net-tools")
    output = run_cmd(test_instance, "/usr/sbin/route -n")
    if 'not found' in output:
        return False
    if '168.63.129.16' in output:
        test_instance.log.info("Azure system.")
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non azure system.")
        test_instance.log.info("Not an azure system.")
    return False

def is_ali(test_instance, action=None):
    '''
    Check whether system is a ali system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a ali system
    Return:
        ali: return True
        other: return False
    '''
    if is_pkg_installed(test_instance, pkg_name='virt-what', cancel_case=False, is_install=False):
        output = run_cmd(test_instance, "sudo bash -c 'cat /sys/devices/virtual/dmi/id/product_*; virt-what'", expect_ret=0)
    else:
        output = run_cmd(test_instance, "sudo cat /sys/devices/virtual/dmi/id/product_*", expect_ret=0)
    if 'alibaba' in output.lower():
        test_instance.log.info("Ali system.")
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non ali system.")
        test_instance.log.info("Not an ali system.")
    return False

def is_openstack(test_instance, action=None):
    '''
    Check whether system is a openstack system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a ali system
    Return:
        openstack: return True
        other: return False
    '''
    if 'OpenStack' in test_instance.node_info.get('product_name'):
        test_instance.log.info("Openstack system.")
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non Openstack system.")
        test_instance.log.info("Not an Openstack system.")
    return False

def is_ahv(test_instance, action=None):
    '''
    Check whether system is a nutanix ahv system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a nutanix ahv system
    Return:
        ahv: return True
        other: return False
    '''
    if is_pkg_installed(test_instance, pkg_name='virt-what', cancel_case=False, is_install=False):
        output = run_cmd(test_instance, "sudo virt-what", expect_ret=0)
    else:
        output = run_cmd(test_instance, "sudo cat /sys/devices/virtual/dmi/id/product_*", expect_ret=0)
    if 'ahv' in output.lower():
        test_instance.log.info("Nutanix AHV system.")
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non Nutanix AHV system.")
        test_instance.log.info("Not a Nutanix AHV system.")
    return False

def is_gcp(test_instance, action=None):
    '''
    Check whether system is a gcp system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a aws system
    Return:
        aws: return True
        other: return False
    '''
    if is_pkg_installed(test_instance, pkg_name='virt-what', cancel_case=False, is_install=False):
        output = run_cmd(test_instance, "sudo virt-what", expect_ret=0)
    else:
        output = run_cmd(test_instance, "sudo cat /sys/devices/virtual/dmi/id/bios_*", expect_ret=0)
    if 'google' in output.lower():
        test_instance.log.info("gcp system.")
        return True
    else:
        if action == "cancel":
            test_instance.skipTest("Cancel it in non gcp system.")
        test_instance.log.info("Not an gcp system.")
    return False

def is_metal(test_instance, action=None):
    '''
    Check whether system is a baremetal system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a bare metal system
    Return:
        metal: return True
        other: return False
    '''
    if test_instance.vm:
        if action == "cancel":
            if not test_instance.vm.is_metal:
                test_instance.skipTest("Cancel it in non metal system.")
        return test_instance.vm.is_metal
    output_lscpu = run_cmd(test_instance, "lscpu", expect_ret=0)
    if "x86_64" in output_lscpu and "Hypervisor" not in output_lscpu:
        test_instance.log.info("It is a bare metal instance.")
        return True
    elif "x86_64" in output_lscpu and "Hypervisor" in output_lscpu:
        test_instance.log.info("It is a virtual guest.")
        if action == "cancel":
            test_instance.skipTest("Cancel it in non metal system.")
        return False
    output_dmesg = run_cmd(test_instance, "dmesg", expect_ret=0, is_log_output=False)

    if 'HYP mode not available' in output_dmesg:
        test_instance.log.info("It is a virtual guest.")
        if action == "cancel":
            test_instance.skipTest("Cancel it in non metal system.")
        return False
    else:
        test_instance.log.info("It is a bare metal instance.")
        return True

def is_cmd_exist(test_instance, cmd=None, is_install=True, cancel_case=False, rmt_node=None, vm=None):
    '''
    check cmd exists status, if no, try to install it.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        cmd {string} -- checked command
        is_install {bool} -- try to install it or not
    '''
    cmd_check = "which %s" % cmd
    ret = run_cmd(test_instance, cmd_check, ret_status=True, rmt_node=rmt_node, vm=vm)
    if ret == 0:
        return True
    else:
        test_instance.log.info("No {} found!".format(cmd))
    if not is_install:
        if cancel_case:
            test_instance.skipTest("Cancel it as {} not found".format(cmd))
        return False
    arch = run_cmd(test_instance, 'uname -p',rmt_node=rmt_node, vm=vm).rstrip('\n')
    pkg_find = "sudo yum provides %s" % cmd
    output = run_cmd(test_instance, pkg_find, rmt_node=rmt_node, vm=vm)
    for i in [arch, 'noarch']:
        pkg_list_tmp = re.findall(".*\.{}".format(i), output)
        pkg_list = [i for i in pkg_list_tmp if 'Repo' not in i]
        if len(pkg_list) > 0:
            break
    if len(pkg_list) == 0:
        test_instance.skipTest("Unable to install {}".format(cmd))
        return False
    pkg_list.sort(reverse=True)
    out = run_cmd(test_instance, "sudo yum info {}".format(pkg_list[0]), rmt_node=rmt_node, vm=vm)
    pkg_names = re.findall('Name.*',out)
    if len(pkg_names) > 0:
        pkg_name = pkg_names[0].split(':')[-1].strip(' ')
    else:
        test_instance.skipTest("Unable to retrive {} owned by which pkg".format(cmd))
    run_cmd(test_instance, "sudo yum install -y {}".format(pkg_name), expect_ret=0, timeout=720, rmt_node=rmt_node, vm=vm)
    return True

def is_pkg_installed(test_instance, pkg_name=None, is_install=True, cancel_case=False, timeout=120,rmt_node=None, vm=None):
    '''
    check cmd exists status, if no, try to install it.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        cmd {string} -- checked command
        is_install {bool} -- try to install it or not
    '''
    cmd = "rpm -q {}".format(pkg_name)
    ret = run_cmd(test_instance, cmd, ret_status=True, rmt_node=rmt_node, vm=vm)
    if ret == 0:
        return True
    else:
        test_instance.log.info("No {} found!".format(pkg_name))
        if is_install:
            cmd = 'sudo yum install -y {}'.format(pkg_name)
            ret = run_cmd(test_instance, cmd, ret_status=True, msg='try to install it', timeout=timeout, rmt_node=rmt_node, vm=vm)
            if ret == 0:
                return True
        if cancel_case: test_instance.skipTest("Unable to install {}".format(pkg_name))
        return False

def pkg_install(test_instance, pkg_name=None, pkg_url=None, force=False, rmt_node=None, vm=None):
        """
        Install pkg in target system from default repo or pkg_url.
        $pkg_url_$arch is defined in configuration file.
        I use pre compiled pkgs for saving time in run.
        eg.
        blktests_url_x86_64: https://github.com/liangxiao1/rpmbuild_specs/releases/download/blktests_20201009/blktests-master-20201009.aarch64.rpm
        or
        blktests_url_aarch64: https://github.com/liangxiao1/rpmbuild_specs/releases/download/blktests_20201009/blktests-master-20201009.aarch64.rpm
        Arguments:
            test_instance {avocado Test instance} -- avocado test instance
            pkg_name {string} -- pkg name
            pkg_url {string} -- pkg url or location if it is not in default repo
        """
        if not is_pkg_installed(test_instance, pkg_name=pkg_name, cancel_case=False, is_install=False, rmt_node=rmt_node, vm=vm):
            test_instance.log.info("Try install {} automatically!".format(pkg_name))
            if pkg_url is not None:
                test_instance.log.info("Install {} from {}".format(pkg_name, pkg_url))
                cmd = 'sudo yum -y install %s' % pkg_url
            else:
                test_instance.log.info("Install {} from default repo".format(pkg_name))
                cmd = 'sudo yum -y install %s' % pkg_name
            run_cmd(test_instance, cmd, timeout=1200, rmt_node=rmt_node, vm=vm)
        elif test_instance.params.get('pkg_reinstall'):
            test_instance.log.info("Try reinstall {} automatically!".format(pkg_name))
            if pkg_url is not None:
                test_instance.log.info("Reinstall {} from {}".format(pkg_name, pkg_url))
                cmd = 'sudo yum -y reinstall %s' % pkg_url
            else:
                test_instance.log.info("Reinstall {} from default repo".format(pkg_name))
                cmd = 'sudo yum -y reinstall %s' % pkg_name
            run_cmd(test_instance, cmd, timeout=1200,rmt_node=rmt_node, vm=vm)

        if not is_pkg_installed(test_instance, pkg_name=pkg_name, cancel_case=False, is_install=False,rmt_node=rmt_node, vm=vm) and pkg_url is not None and force:
            test_instance.log.info('Install without dependences!')
            cmd = 'sudo rpm -ivh %s --nodeps' % pkg_url
            if force:
                cmd = cmd + " --force"
            run_cmd(test_instance, cmd, timeout=1200)
        if not is_pkg_installed(test_instance, pkg_name=pkg_name,rmt_node=rmt_node, vm=vm):
            test_instance.skipTest("Cannot install {} automatically!".format(pkg_name))

def get_memsize(test_instance, action=None):
    '''
    Check whether system is a aws system.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        action {string} -- cancel case if it is not a aws system
    Return:
        aws: return True
        other: return False
    '''
    output = run_cmd(test_instance, "cat /proc/meminfo |grep MemTotal", expect_ret=0)

    mem_kb = int(re.findall('\d+', output)[0])
    mem_gb = (mem_kb/1024/1024)
    test_instance.log.info("Total memory: {:0,.1f}GiB".format(mem_gb))
    return mem_gb

def get_disk_online(test_instance):
    '''
    Get online disks in system.
    '''
    cmd = 'lsblk -d'
    output = run_cmd(test_instance, cmd, expect_ret=0, msg='Get online disk count.')
    count = output.count('disk') - output.count('SWAP')
    test_instance.log.info('Online disks: %s' % count)
    return count

def get_cmd_cursor(test_instance, cmd='dmesg -T', rmt_redirect_stdout=False, rmt_get_pty=False, timeout=60):
    '''
    Get command cursor by last matched line.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    Return:
        cursor {string}
    '''
    output = run_cmd(test_instance, cmd, expect_ret=0, is_log_output=False, rmt_redirect_stdout=rmt_redirect_stdout, rmt_get_pty=rmt_get_pty, timeout=timeout)
    if len(output.split('\n')) < 5:
        return output.split('\n')[-1]
    for i in range(-1, -10, -1):
        cursor = output.split('\n')[i]
        if len(cursor) > 3:
            break
    test_instance.log.info("Get cursor: {}".format(cursor))
    return cursor

def check_log(test_instance, log_keyword, log_cmd="journalctl -b 0", expect_ret=None,
            expect_not_ret=None, match_word_exact=False, cursor=None, skip_words=None, rmt_redirect_stdout=False, rmt_redirect_stderr=False, rmt_get_pty=False, msg=None):
    '''
    check journal log
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        log_keyword: which keywords to check, eg error, warn, fail, default is checking journal log happened in today.
        log_cmd: the command to get log
        match_word_exact: is macthing word exactly
        cursor: where to start to check journal log, only for journal log
        skip_words: skip words as you want, split by ","
    '''
    # Result dir
    if msg is not None:
        test_instance.log.info(msg)
    run_cmd(test_instance, '\n')

    check_cmd = log_cmd + '|grep -Ev "{}"'.format(test_instance.id())
    if 'test_check' in test_instance.id():
        check_cmd = check_cmd + '|grep -Ev test_check'
    if match_word_exact:
        check_cmd = check_cmd + '|grep -iw "{}"'.format(log_keyword)
    if skip_words:
        check_cmd = check_cmd + '|grep -Ev "{}"'.format(skip_words.replace(',', '|'))

    ret = False
    if cursor is not None:
        out = run_cmd(test_instance,
                      check_cmd,
                      expect_ret=expect_ret,
                      expect_not_ret= expect_not_ret,
                      msg='Get log......', cursor=cursor,
                      rmt_redirect_stderr=rmt_redirect_stderr,
                      rmt_redirect_stdout=rmt_redirect_stdout,
                      rmt_get_pty=rmt_get_pty)
    else:
        out = run_cmd(test_instance,
                      check_cmd,
                      expect_ret=expect_ret,
                      expect_not_ret= expect_not_ret,
                      msg='Get log......',
                      rmt_redirect_stderr=rmt_redirect_stderr,
                      rmt_redirect_stdout=rmt_redirect_stdout,
                      rmt_get_pty=rmt_get_pty)

    for keyword in log_keyword.split(','):
        ret, msg = find_word(test_instance, out, keyword, skip_words=skip_words)
        if ret:
            test_instance.fail("Found {} in {} log!\n{}".format(keyword, check_cmd, '\n'.join(msg)))
        else:
            test_instance.log.info("No unexpected {} in {} log!".format(keyword, check_cmd))

def clean_sentence(test_instance, line1, line2):
    """only keep neccessary words
    eg.
    line1: Sep 10 05:42:38 ip-172-31-1-196.us-west-2.compute.internal augenrules[783]: failure 1
    line2: augenrules[681]: failure 1

    return:
    line1: augenrules[681]: failure 1
    line2: augenrules[783]: failure 1

    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        line1 {string} -- string 1
        line2 {string} -- string 2
    Returns:
        line1
        line2
    """
    tmpline = ''
    line1_longer = True
    if len(line1) > len(line2):
        tmpline = line2
    else:
        tmpline = line1
        line1_longer = False
    for i in re.findall("\w+",tmpline):
        if len(i) >= 3:
            if i not in line1 or i not in line2:
                return line1, line2
            #test_instance.log.info("got start word {}".format(i))
            if line1_longer:
                line1 = line1[line1.index(i):]
            else:
                line2 = line2[line2.index(i):]
            #test_instance.log.info("return line1:{} line2:{}".format(line1, line2))
            return line1, line2
    return line1, line2

def find_word(test_instance, check_str, log_keyword=None, baseline_dict=None, skip_words=None, case=None):
    """find words in content

    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        check_str {[string]} -- [string content to look]
        log_keyword {[string]} -- [keyword to look]
        baseline_dict {[dict]} -- [baseline dict to compare]
        skip_words: skip words as you want, split by ","
        case: only check items when cases are same, so users can know which case found it and 
               also can be used for test result auto checks.
    Returns:
        [Bool] -- [True|False]
    """
    if not baseline_dict:
        # Baseline data file
        baseline_file = os.path.dirname(os_tests.__file__) + "/data/baseline_log.json"
        with open(baseline_file,'r') as fh:
            test_instance.log.info("Loading baseline data file from {}".format(baseline_file))
            baseline_dict = json.load(fh)
    log_keywords = []
    kw_from_case = False
    if log_keyword and ',' in log_keyword:
        log_keywords.extend(log_keyword.split(','))
    elif log_keyword:
        log_keywords.append(log_keyword)
    elif log_keyword is None and case:
        msg_ids = []
        for key in baseline_dict.keys():
            if baseline_dict[key].get('cases'):
                if case in baseline_dict[key].get('cases'):
                    log_keywords.append(baseline_dict[key].get('content'))
                    msg_ids.append(key)
        test_instance.log.info("fetched rules from {} matching case:{}".format(msg_ids,case))
        kw_from_case = True
        if not log_keywords:
            # if checking keywords not found or is empty, we consider this fail is new.
            return True, []
    new_fail_found = False
    remain_items = []
    all_items = []
    for kw in log_keywords:
        tmp_list = re.findall('.*' in kw and kw or ".*{}.*".format(kw), check_str, flags=re.I)
        if len(tmp_list) == 0:
            test_instance.log.info("No %s found!", kw)
            continue
        else:
            test_instance.log.info("%s found!", kw)
        if skip_words is not None:
            for skip_word in skip_words.split(','):
                tmp_list = [x for x in tmp_list if skip_word not in x]
        if len(tmp_list) == 0:
            test_instance.log.info("No {} found after skipped {}!".format(log_keyword, skip_words))
            continue
        all_items.extend(tmp_list)

    if not all_items:
        # if no items found in checking list, no need to do further checking
        return new_fail_found or kw_from_case, []
    remain_items = list(set(deepcopy(all_items)))

    for line1 in set(all_items):
        test_instance.log.info("Checking:{}".format(line1))
        found_it = False
        if not baseline_dict:
            break
        for basekey in baseline_dict:
            if case and baseline_dict[basekey].get('cases') and case not in baseline_dict[basekey].get('cases'):
                continue
            # this round go through with regex
            for sub_basekey_content in baseline_dict[basekey]["content"].split(';'):
                if sub_basekey_content and re.search(sub_basekey_content, line1):
                    found_it = True
                    matched_msg = basekey
                    test_instance.log.info("regex found in baseline:{}".format(basekey))
                    break
        if not found_it:
            # this round compare the content
            # compare 2 strings, if similary over pass_rate, consider it as same.
            pass_rate = 70
            for basekey in baseline_dict:
                if case and baseline_dict[basekey].get('cases') and case not in baseline_dict[key].get('cases'):
                    continue
                line1_tmp = line1
                line2_tmp = baseline_dict[basekey]["content"]
                line1_tmp, line2_tmp = clean_sentence(test_instance, line1_tmp, line2_tmp)
                seq = difflib.SequenceMatcher(
                    None, a=line1_tmp, b=line2_tmp)
                same_rate = seq.ratio() * 100
                if same_rate > pass_rate:
                    test_instance.log.info("content similar rate:{} over {} baseline:{}".format(same_rate,pass_rate,basekey))
                    matched_msg = basekey
                    found_it = True
                    break
        if found_it:
            basekey = matched_msg
            if baseline_dict[basekey]["status"] != 'active':
                test_instance.log.info("Found a similar log {} matched in baseline. But it is not active, please check manually".format(basekey))
                new_fail_found = True
            trigger = baseline_dict[basekey]["trigger"]
            if trigger and re.search(trigger,check_str,flags=re.I):
                test_instance.log.info("Guess it is expected because trigger keywords found '{}'".format(trigger))
                remain_items.remove(line1)
            elif trigger:
                test_instance.log.info("Guess it is unexpected because trigger keywords not found '{}'".format(trigger))
                new_fail_found = True
            elif not trigger and not new_fail_found:
                remain_items.remove(line1)
            test_instance.log.info(baseline_dict[basekey])
            continue
    if remain_items:
        test_instance.log.info("Below items are unknow!\n{}".format(remain_items))
        new_fail_found = True

    return new_fail_found, remain_items

def get_product_id(test_instance):
    cmd = "source /etc/os-release ;echo $VERSION_ID"
    product_id = run_cmd(test_instance,cmd, expect_ret=0, msg='check release name')
    test_instance.log.info("Get product id: {}".format(product_id))
    return product_id

def get_os_release_info(test_instance, field="VERSION_ID"):
    data_file = '/etc/os-release'
    cmd = "source {} ;echo ${}".format(data_file, field)
    output = run_cmd(test_instance,cmd, expect_ret=0, msg='get {} from {}'.format(field, data_file))
    test_instance.log.info("Got: {}".format(output))
    return output.strip('\n')

def set_service(test_instance, service="systemd-journald-audit.socket", enable_it = False, check_ret = False):
    if not enable_it:
        cmd_dict = [{'cmd':'sudo systemctl stop {}'.format(service), 'msg':'stop {}'.format(service)},
                {'cmd':'sudo systemctl disable {}'.format(service), 'msg':'disable {}'.format(service)},
                {'cmd':'sudo systemctl mask {}'.format(service), 'msg':'mask {} to prevent others bring it up'.format(service)}]
    else:
        cmd_dict = [{'cmd':'sudo systemctl unmask {}'.format(service), 'msg':'unmask {}'.format(service)},
                {'cmd':'sudo systemctl enable --now {}'.format(service), 'msg':'enable and start {}'.format(service)}]
    for cmd in cmd_dict:
        if check_ret:
            run_cmd(test_instance,cmd['cmd'], expect_ret=0, msg=cmd['msg'])
        else:
            run_cmd(test_instance,cmd['cmd'], msg=cmd['msg'])

def wait_for(ret=None, not_ret=None, ck_ret=False, ck_not_ret=False, timeout=60, interval=1):
    '''
    wait for a func return expected value within specified time
    '''
    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            while True:
                LOG.info("{} called, timeout {}".format(func.__name__, timeout))
                result = func(*args, **kwargs)
                if ck_ret and result == ret:
                    break
                if ck_not_ret and not_ret != result:
                    break
                end_time = time.time()
                time.sleep(interval)
                if end_time - start_time > timeout:
                    LOG.info('timeout, exit!')
                    break
            return result
        return wrapper
    return decorate

def iterate_timeout(timeout, message, wait=2):
    start = time.time()
    count = 0
    while (timeout is None) or (time.time() < start + timeout):
        count += 1
        yield count
        logging.debug('Have been waiting for %ss/%ss.' %
                      (int(time.time() - start), timeout))
        time.sleep(wait)
    raise TimeoutError(message)

def get_value(x={}, key=None, path=None):
    # walk through the dict and get key under parent path
    ret = None
    if path is None and isinstance(x,dict):
        return x.get(key)
    if isinstance(x,dict):
        for i in x.keys():
            if path == i:
                if isinstance(x.get(i),dict):
                    ret = x.get(i).get(key)
                    break
            else:
                ret = get_value(x=x.get(i), key=key, path=path)
    return ret

def get_public_key(client_user=None):
    """
    Return a valid string ssh public key for the user executing autoserv or
    autotest. If there's no DSA or RSA public key, create a RSA keypair with
    ssh-keygen and return it.

    :param client_user: genenrate the ssh_key for which client
                        user to login into the server
    :type client_user: str
    :returns: a ssh public key
    :rtype: str
    """

    if client_user:
        if os.environ.get('USER') not in ('root', client_user):
            raise RuntimeError("Can not set ssh-key for OTHER user using"
                               "non-root account. Permission Denied.")
        if client_user == 'root':
            ssh_conf_path = '/root/.ssh'
        else:
            ssh_conf_path = '/home/%s/.ssh' % client_user
    else:
        ssh_conf_path = os.path.expanduser('~/.ssh')
        client_user = os.environ.get('USER')

    dsa_public_key_path = os.path.join(ssh_conf_path, 'id_dsa.pub')
    dsa_private_key_path = os.path.join(ssh_conf_path, 'id_dsa')

    rsa_public_key_path = os.path.join(ssh_conf_path, 'id_rsa.pub')
    rsa_private_key_path = os.path.join(ssh_conf_path, 'id_rsa')

    has_dsa_keypair = (os.path.isfile(dsa_public_key_path) and
                       os.path.isfile(dsa_private_key_path))
    has_rsa_keypair = (os.path.isfile(rsa_public_key_path) and
                       os.path.isfile(rsa_private_key_path))

    if has_rsa_keypair:
        logging.info('RSA keypair found, using it')
        public_key_path = rsa_public_key_path

    elif has_dsa_keypair:
        logging.info('DSA keypair found, using it')
        public_key_path = dsa_public_key_path

    else:
        logging.info('Neither RSA nor DSA keypair found, creating RSA ssh key pair')

        public_key_path = rsa_public_key_path

    public_key = open(public_key_path, 'r')
    public_key_str = public_key.read()
    public_key.close()
    
    return public_key_str

def normalize_data_size(value_str, order_magnitude="M", factor="1024"):
    """
    Normalize a data size in one order of magnitude to another (MB to GB,
    for example).

    :param value_str: a string include the data default unit is 'B'
    :param order_magnitude: the magnitude order of result
    :param factor: the factor between two relative order of magnitude.
                   Normally could be 1024 or 1000
    """
    def __get_unit_index(M):
        try:
            return ['B', 'K', 'M', 'G', 'T'].index(M.upper())
        except ValueError:
            pass
        return 0

    regex = r"(\d+\.?\d*)\s*(\w?)"
    match = re.search(regex, value_str)
    try:
        value = match.group(1)
        unit = match.group(2)
        if not unit:
            unit = 'B'
    except TypeError:
        raise ValueError("Invalid data size format 'value_str=%s'" % value_str)
    from_index = __get_unit_index(unit)
    to_index = __get_unit_index(order_magnitude)
    scale = int(factor)**(to_index - from_index)
    data_size = float(value) / scale
    # Control precision to avoid scientific notaion
    if data_size.is_integer():
        return "%.1f" % data_size
    else:
        return ("%.20f" % data_size).rstrip('0')

def check_attribute(target, attributes, test_instance=None, cancel_case=True):
    '''
    check if has required attribute
    if test_instance passed, can skip case as required
    '''
    if test_instance:
        func_write = test_instance.log.info
    else:
        func_write = print
    if not target or not attributes:
        msg = 'target or attributes is None'
        func_write(msg)
        return False
    for attrname in attributes.split(','):
        if not hasattr(target, attrname):
            msg = 'no {} found {}'.format(attrname,target)
            if test_instance and cancel_case:
                test_instance.skipTest(msg)
            else:
                func_write(msg)
            return False
    return True

def core_file_check(test_instance=None):
    '''
    when there is core file exists, collect it to test result dir for further debugging
    '''
    cmd = 'sudo ls /var/lib/systemd/coredump/core*'
    core_files = run_cmd(test_instance, cmd, msg='check if core file exists')
    if 'No such file or directory' not in core_files:
        test_instance.log.info('Please attached core files when report bugs')
        for core_file in core_files.split('\n'):
            core_file = core_file.strip('\n')
            if not core_file:
                continue
            cmd = 'sudo chmod 766 {}'.format(core_file)
            run_cmd(test_instance, cmd, expect_ret=0)
            if test_instance.params.get('remote_node') is not None:
                test_instance.log.info('retrive {} from remote to {}'.format(core_file, test_instance.log_dir))
                test_instance.SSH.get_file(rmt_file=core_file,local_file='{}/attachments/{}'.format(test_instance.log_dir,os.path.basename(core_file)))
            else:
                cmd = "cp {} {}/attachments/{}".format(core_file, test_instance.log_dir,os.path.basename(core_file) )
                run_cmd(test_instance, cmd, msg='save {} to {}'.format(core_file, test_instance.log_dir))
        run_cmd(test_instance, 'sudo rm -rf /var/lib/systemd/coredump/core*', msg='clean up core files')
        cmd = 'sudo journalctl -b0'
        run_cmd(test_instance, cmd, msg='get traceback from journal')

def get_test_disk(test_instance=None):
        '''
        Look for non-boot disk to do test
        '''
        test_disk = None
        cmd = "lsblk -r --output NAME,MOUNTPOINT|awk -F' ' '{if($2) printf\"%s \",$1}'"
        output = run_cmd(test_instance, cmd, expect_ret=0)
        mount_disks = output.split(' ')
        cmd = 'lsblk -d --output NAME|grep -v NAME'
        output = run_cmd(test_instance, cmd, expect_ret=0)
        disk_list = output.split('\n')
        for disk in disk_list:
            disk_in_use = False
            if not disk:
                continue
            for mount_disk in mount_disks:
                if disk in mount_disk:
                    test_instance.log.info('Disk is mounted: {}'.format(disk))
                    disk_in_use = True
                    break
            if not disk_in_use:
                cmd = 'sudo wipefs -a /dev/{}'.format(disk) #comment this line for bz2074486
                ret = run_cmd(test_instance, cmd, ret_status=True, timeout=1800,msg='test can clean fs on {}'.format(disk))
                if ret == 0:
                    test_disk = disk
                    break
                else:
                    test_instance.log.info('Cannot clean fs on {} - skip'.format(disk))
                    continue
        if test_disk:
            test_instance.log.info('Test disk is found: {}'.format(test_disk))
        else:
             test_instance.skipTest("No free disk for testing.")
        return test_disk

def fips_enable(test_instance=None):
    '''
    enable fips
    '''
    cmdline = run_cmd(test_instance, 'cat /proc/cmdline', expect_ret=0)
    if 'fips=1' in cmdline:
        test_instance.log.info("fips is already enabled")
        return True
    output = run_cmd(test_instance, 'uname -r', expect_ret=0)
    if 'el7' in output:
        run_cmd(test_instance,
                   'sudo dracut -v -f',
                    msg='regenerate the initramfs!',
                    timeout=600)
        cmd = 'sudo grubby --update-kernel=ALL --args="fips=1"'
        run_cmd(test_instance, cmd, msg='Enable fips!', timeout=600)
    else:
        cmd = 'sudo fips-mode-setup --enable'
        run_cmd(test_instance, cmd, msg='Enable fips!', timeout=600)
    if not test_instance.is_rmt:
        test_instance.log.info("run locally, please reboot system to take effect")
        return False
    run_cmd(test_instance, 'sudo reboot', msg='reboot system under test')
    time.sleep(10)
    init_connection(test_instance, timeout=test_instance.ssh_timeout)
    run_cmd(test_instance, 'cat /proc/cmdline', expect_kw='fips=1')
    return True

def fips_disable(test_instance=None):
    '''
    disable fips
    '''
    cmdline = run_cmd(test_instance, 'cat /proc/cmdline', expect_ret=0)
    if 'fips=1' not in cmdline:
        test_instance.log.info("fips is already disabled")
        return True
    output = run_cmd(test_instance, 'uname -r', expect_ret=0)
    if 'el7' in output:
        run_cmd(test_instance,
                   'sudo dracut -v -f',
                    msg='regenerate the initramfs!',
                    timeout=600)
        cmd = 'sudo grubby --update-kernel=ALL  --remove-args="fips=1"'
        run_cmd(test_instance, cmd, msg='Disable fips!')
    else:
        cmd = 'sudo fips-mode-setup --disable'
        run_cmd(test_instance, cmd, msg='Disable fips!')
    if not test_instance.is_rmt:
        test_instance.log.info("run locally, please reboot system to take effect")
        return False
    run_cmd(test_instance, 'sudo reboot', msg='reboot system under test')
    time.sleep(10)
    init_connection(test_instance, timeout=test_instance.ssh_timeout)
    run_cmd(test_instance, 'cat /proc/cmdline', expect_not_kw='fips=1')
    return True

def debugkernel_enable(test_instance=None):
    '''
    enable debug kernel and kmemleak
    '''
    if test_instance.vm and is_ahv(test_instance) and test_instance.vm.is_secure_boot:
        test_instance.log.info('''Red Hat Insights error "sed: can't read /sys/kernel/debug/sched_features: \
Operation not permitted" When using secure boot''')
        return False
    mini_mem = get_memsize(test_instance)
    if int(mini_mem) < 2:
        test_instance.log.info('minimal 2G memory required for debug kernel')
        return False 
    if is_arch(test_instance, 'aarch64') and int(mini_mem) < 4:
        test_instance.log.info("minimal 4G memory required in aarch64")
        return False

    kernel_version = run_cmd(test_instance, 'uname -r', expect_ret=0).strip('\n')
    cmdline = run_cmd(test_instance, 'cat /proc/cmdline', expect_ret=0)
    if 'debug' in kernel_version:
        test_instance.log.info("Already in debug kernel")
        if 'kmemleak=on' in cmdline:
            test_instance.log.info("Already enabled kmemleak")
            return True
        else:
            cmd = 'sudo grubby --update-kernel=ALL --args="kmemleak=on"'
            run_cmd(test_instance, cmd, expect_ret=0, msg='Add "kmemleak=on" to /proc/cmdline')
    else:
        if 'el7' in kernel_version:
            debug_kernel = "/boot/vmlinuz-{}.debug".format(kernel_version)
            run_cmd(test_instance, 'sudo dracut -v -f',
                    msg='regenerate the initramfs!',
                    timeout=600)
        else:
            debug_kernel = "/boot/vmlinuz-{}+debug".format(kernel_version)
        debug_kernel_pkg = 'kernel-debug-' + kernel_version

        is_pkg_installed(test_instance, pkg_name=debug_kernel_pkg, timeout=600)
        run_cmd(test_instance, "sudo grubby --info=%s" % debug_kernel,
                expect_ret=0, msg="check if kernel-debug is installed")
        cmd = "sudo grubby --set-default {}".format(debug_kernel)
        run_cmd(test_instance, cmd, expect_ret=0, msg="Set default boot kernel to debug kernel")
        if 'kmemleak=on' not in cmdline:
            cmd = 'sudo grubby --update-kernel=ALL --args="kmemleak=on"'
            run_cmd(test_instance, cmd, expect_ret=0, msg='Add "kmemleak=on" to /proc/cmdline')

    if not test_instance.is_rmt:
        test_instance.log.info("run locally, please reboot system to take effects")
        return False

    run_cmd(test_instance, 'sudo reboot', msg='reboot OS to take debug kernel effects')
    time.sleep(60)
    init_connection(test_instance, timeout=test_instance.ssh_timeout)
    run_cmd(test_instance, 'uname -r', expect_kw='debug')
    run_cmd(test_instance, 'cat /proc/cmdline', expect_kw='kmemleak=on')
    return True

def debugkernel_disable(test_instance=None):
    '''
    disable debug kernel and kmemleak
    '''
    kernel_version = run_cmd(test_instance, 'uname -r', expect_ret=0).strip('\n')
    cmdline = run_cmd(test_instance, 'cat /proc/cmdline', expect_ret=0)
    if 'debug' not in kernel_version:
        test_instance.log.info("Already disabled debug kernel")
        if 'kmemleak=on' not in cmdline:
            test_instance.log.info("Already disabled kmemleak")
            return True
        else:
            cmd = 'sudo grubby --update-kernel=ALL --remove-args="kmemleak=on"'
            run_cmd(test_instance, cmd, expect_ret=0, msg='Remove "kmemleak=on" from /proc/cmdline')
    else:
        current_kernel = run_cmd(test_instance, 'sudo grubby --default-kernel', expect_ret=0).strip('\n')
        if 'el7' in kernel_version:
            default_kernel = current_kernel.replace('.debug', '')
            run_cmd(test_instance, 'sudo dracut -v -f',
                    msg='regenerate the initramfs!',
                    timeout=600)
            default_kernel_pkg = 'kernel-' + kernel_version.replace('.debug', '')
        else:
            default_kernel = current_kernel.replace('+debug', '')
            default_kernel_pkg = 'kernel-' + kernel_version.replace('+debug', '')

        is_pkg_installed(test_instance, pkg_name=default_kernel_pkg, timeout=600)
        run_cmd(test_instance, "sudo grubby --info=%s" % default_kernel,
                expect_ret=0, msg="check if default kernel is installed")
        cmd = "sudo grubby --set-default {}".format(default_kernel)
        run_cmd(test_instance, cmd, expect_ret=0, msg="Set default boot kernel to default kernel")
        if 'kmemleak=on' in cmdline:
            cmd = 'sudo grubby --update-kernel=ALL --remove-args="kmemleak=on"'
            run_cmd(test_instance, cmd, expect_ret=0, msg='Remove "kmemleak=on" from /proc/cmdline')

    if not test_instance.is_rmt:
        test_instance.log.info("run locally, please reboot system to take effects")
        return False

    run_cmd(test_instance, 'sudo reboot', msg='reboot OS to take default kernel effects')
    time.sleep(60)
    init_connection(test_instance, timeout=test_instance.ssh_timeout)
    run_cmd(test_instance, 'uname -r', expect_not_kw='debug')
    run_cmd(test_instance, 'cat /proc/cmdline', expect_not_kw='kmemleak=on')
    return True

def collect_kmemleak(test_instance=None):
    '''
    collect memory leak in debug kernel with 'kmemleak=on'
    '''
    out = run_cmd(test_instance, 'cat /proc/cmdline')
    if 'debug' not in out or 'kmemleak=on' not in out:
        test_instance.log.info('collect_kmemleak requires debug kernel with kmemleak=on')
        return False

    cmd = 'sudo bash -c "echo scan > /sys/kernel/debug/kmemleak"'
    run_cmd(test_instance, cmd, expect_ret=0, timeout=1800)
    cmd = 'sudo cat /sys/kernel/debug/kmemleak'
    output = run_cmd(test_instance, cmd, expect_ret=0)
    if len(output) > 0:
        test_instance.log.info('Memory leak found!')

def get_active_nic(test_instance=None, rmt_node=None, vm=None):
    cmd = "sudo ip link show|grep mtu|grep -v lo|awk -F':' '{print $2}'"
    output = run_cmd(test_instance, cmd, rmt_node=rmt_node, vm=vm)
    test_instance.active_nic  = "eth0"
    test_instance.log.info("Test which nic connects to public")
    nic_found = False
    for net in output.split('\n'):
        if len(net) < 3:
            continue
        cmd = "sudo ping {} -c 6 -I {}".format(test_instance.params.get('ping_server'), net)
        ret = run_cmd(test_instance, cmd, rmt_node=rmt_node, vm=vm)
        if ret == 0:
            test_instance.active_nic  = net
            nic_found = True
            break
    if not nic_found:
        for net in output.split('\n'):
            #man systemd.net-naming-scheme
            if net.startswith(('eth','en')):
                test_instance.active_nic  = net
                break
    test_instance.log.info("Pick up nic {}".format(test_instance.active_nic ))
    
    cmd = "sudo ip addr show {}".format(test_instance.active_nic )
    output = run_cmd(test_instance, cmd, rmt_node=rmt_node, vm=vm)
    test_instance.rmt_ipv4 = re.findall('[\d.]{7,16}', output)[0]

    return test_instance.rmt_ipv4

def is_firewalld_installed_and_running(test_instance=None, rmt_node=None, vm=None):
    cmd = "sudo systemctl status firewalld"
    output = run_cmd(test_instance, cmd, rmt_node=rmt_node, vm=vm)
    if "Active: active (running)" in output:
        test_instance.log.info("Firewalld is installed and running")
        return True
    else:
        test_instance.log.info("Firewalld is not installed and running")
        return False

def add_port_to_firewall(test_instance=None, rmt_node=None, vm=None, port=None):
    cmd = "sudo firewall-cmd --list-ports | grep {}".format(port)
    output = run_cmd(test_instance, cmd, rmt_node=rmt_node, vm=vm)
    if str(port) not in output:
        cmd = "sudo firewall-cmd --add-port={}/tcp --permanent".format(port)
        run_cmd(test_instance, cmd, rmt_node=rmt_node, vm=vm)
        cmd = "sudo firewall-cmd --reload"
        run_cmd(test_instance, cmd, rmt_node=rmt_node, vm=vm)
    else:
        test_instance.log.info(f'port {port} has exist in the firewalld allow list')

def imds_tracer_tool(test_instance=None, log_check=True, timeout=610, interval=30, cleanup=False, is_return=True):
    '''
    setup/remove aws imds_tracer_tool.service
    is_return: call test_instance fail/skip or return True/False only
    log_check: if check log during the call
    https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
    '''
    if not is_aws(test_instance):
        if is_return:
            test_instance.log.info('only support imdsv2 on aws')
            return False
        else:
            test_instance.skipTest('only support imdsv2 on aws')
    ret = run_cmd(test_instance, 'systemctl status imds_tracer_tool.service', ret_status=True)
    if ret != 0:
        if cleanup:
            test_instance.log.info("imds_tracer_tool service is not enabled, no need to cleanup")
            return True
        is_pkg_installed(test_instance, pkg_name="bcc-tools", cancel_case=is_return, timeout=600)
        is_pkg_installed(test_instance, pkg_name="libbpf", cancel_case=is_return, timeout=600)
        is_pkg_installed(test_instance, pkg_name="git", cancel_case=is_return)
        is_cmd_exist(test_instance, 'python3')
        run_cmd(test_instance, 'sudo rm -rf aws-imds-packet-analyzer')
        run_cmd(test_instance, 'git clone --branch xiliang https://github.com/liangxiao1/aws-imds-packet-analyzer.git')
        run_cmd(test_instance, 'cd aws-imds-packet-analyzer; sudo ./activate-tracer-service.sh')
        time.sleep(30)
        ret = run_cmd(test_instance, 'systemctl status imds_tracer_tool.service', ret_status=True)
        if ret != 0 and not is_return:
            test_instance.fail("cannot start imds_tracer_tool.service")
        elif ret !=0:
            test_instance.log.info('cannot start imds_tracer_tool.service')
            return False
    if log_check:    
        timeout = timeout
        interval = interval
        time_start = int(time.time())
        while True:
           run_cmd(test_instance,'journalctl -u imds_tracer_tool.service', rmt_redirect_stdout=True)
           check_log(test_instance, "IMDSv1", log_cmd="sudo cat /var/log/imds/imds-trace.log")
           time_end = int(time.time())
           if time_end - time_start > timeout:
              test_instance.log.info('timeout ended: {}'.format(timeout))
              break
           test_instance.log.info('retry after {}s'.format(interval))
           time.sleep(interval)
    else:
        run_cmd(test_instance,'journalctl -u imds_tracer_tool.service', rmt_redirect_stdout=True)
        run_cmd(test_instance, "sudo cat /var/log/imds/imds-trace.log")

    if cleanup:
        run_cmd(test_instance, 'systemctl stop imds_tracer_tool.service')
        run_cmd(test_instance, 'cd aws-imds-packet-analyzer; sudo ./deactivate-tracer-service.sh') 
        run_cmd(test_instance, 'sudo rm -rf /var/log/imds/imds-trace.log') 
    return True
