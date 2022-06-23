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
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

LOG = logging.getLogger('os_tests.os_tests_run')
logging.basicConfig(level=logging.INFO)

def init_args():
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
    parser.add_argument('--verifydoc', dest='verifydoc', action='store_true',
                    help='verify or show case doc only', required=False)
    parser.add_argument('--filter_by', dest='filter_by', default='case_name', action='store',
                    help="filter by 'case_name'(default),'case_tag','case_file','component','bugzilla_id',\
                        'is_customer_case','testplan','maintainer','description','key_steps',\
                        'expect_result','debug_want'", required=False)
    parser.add_argument('--host', dest='remote_node', default=None, action='store',
                    help='run tests on remote node', required=False)
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
    args = parser.parse_args()
    return args

def init_provider(params=None):
    vm = None
    disk = None
    nic = None
    if 'aws' in params['Cloud']['provider']:
        from .resources_aws import EC2VM,EC2Volume,EC2NIC
        vm = EC2VM(params)
        vm.create()
        # init disk and do not create disk at very beginning
        disk = EC2Volume(params)
        nic = EC2NIC(params)
    if 'openstack' in params['Cloud']['provider']:
        from .resources_openstack import OpenstackVM
        vm = OpenstackVM(params)
        vm.create()
        disk = None
    if 'ali' in params['Cloud']['provider']:
        from .resources_alicloud import AlibabaVM
        vm = AlibabaVM(params)
        vm.create(wait=True)
        if vm.is_stopped():
            vm.start(wait=True)
        disk = None
    if 'nutanix' in params['Cloud']['provider']:
        from .resources_nutanix import NutanixVM,NutanixVolume
        vm = NutanixVM(params)
        vm.create(wait=True)
        if vm.is_stopped():
            vm.start(wait=True)
        disk = NutanixVolume(params)
    if 'google' in params['Cloud']['provider']:
        from .resources_gcp import GCPVM
        vm = GCPVM(params)
        vm.create(wait=True)
        if vm.is_stopped():
            vm.start(wait=True)
        disk = None
    if 'libvirt' in params['Cloud']['provider']:
        from .resources_libvirt import LibvirtVM
        vm = LibvirtVM(params)
        vm.create(wait=True)
        if vm.is_stopped():
            vm.start(wait=True)
        disk = None
    if 'openshift' in params['Cloud']['provider']:
        from .resources_openshift import OpenShiftVM
        vm = OpenShiftVM(params)
        vm.create(wait=True)
        if vm.is_stopped():
            vm.start(wait=True)
        disk = None

    return vm, disk, nic

def init_ssh(params=None, timeout=600, interval=10, log=None):
    if log is None:
        LOG_FORMAT = '%(levelname)s:%(message)s'
        log = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    ssh = rmt_ssh.RemoteSSH()
    ssh.rmt_node = params['remote_node']
    ssh.port = params['remote_port']
    ssh.rmt_user = params['remote_user']
    ssh.rmt_password = params['remote_password']
    ssh.rmt_keyfile = params['remote_keyfile']
    ssh.log = log
    ssh.timeout = timeout
    ssh.interval = interval
    ssh.create_connection()
    if ssh.ssh_client is not None:
        return ssh
    return None

def init_connection(test_instance, timeout=600, interval=10):
    if test_instance.params['remote_node'] is None:
        return
    test_instance.log.info("remote_node specified, all tests will run in {}".format(test_instance.params['remote_node']))
    try:
        if hasattr(test_instance.vm, 'floating_ip'):
            test_instance.params['remote_node'] = test_instance.vm.floating_ip
        if hasattr(test_instance.SSH, 'ssh_client'):
            test_instance.SSH.log = test_instance.log
            ret, _, _ = test_instance.SSH.cli_run(cmd='uname -r')
            if ret == 0:
                test_instance.log.info("connection is live")
                return
    except AttributeError:
        pass
    except Exception:
        test_instance.log.info("connection is not live")
    test_instance.SSH = init_ssh(params=test_instance.params, timeout=timeout, interval=interval, log=test_instance.log)
    if test_instance.SSH is None:
        if test_instance.vm:
            try:
                test_instance.vm.get_console_log()
            except NotImplementedError:
                test_instance.log.info("{} not implement this func: get_console_log".format(test_instance.vm.provider))

        test_instance.skipTest("Cannot make ssh connection to remote, please check")

def send_ssh_cmd(rmt_node, rmt_user, rmt_password, command):
    ssh = rmt_ssh.RemoteSSH()
    ssh.rmt_node = rmt_node
    ssh.rmt_user = rmt_user
    ssh.rmt_password = rmt_password
    ssh.create_connection()
    status, outputs = ssh.remote_excute(command)
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
    FORMAT = "%(levelname)s:%(message)s"
    logging.basicConfig(level=logging.INFO, format=FORMAT, filename=log_file)
    test_instance.log.info("-"*80)
    test_instance.log.info("Code Repo: {}".format(test_instance.params['code_repo']))
    test_instance.log.info("Code Version: v{}".format(os_tests.__version__))
    test_instance.log.info("Case ID: {}".format(test_instance.id()))
    test_instance.log.info("Case Doc: {}".format(eval(test_instance.id()).__doc__))
    test_instance.log.info("Case Params:")
    for key in test_instance.params.keys():
        if 'password' in key:
            test_instance.log.info("key:{}, val:*******".format(key))
        else:
            test_instance.log.info("key:{}, val:{}".format(key, test_instance.params[key]))
    test_instance.log.info("-"*80)
    if test_instance.params['remote_node'] is not None:
        init_connection(test_instance)
        test_instance.SSH.log = test_instance.log
        if  test_instance.SSH.ssh_client is None:
            test_instance.skipTest("Cannot make ssh connection to remote, please check")
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

def finish_case(test_instance):
    """finish case
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    """
    pass

def filter_case_doc(case=None, patterns=None, skip_patterns=None, filter_field='case_name', strict=False, verify_doc=False ):
    if patterns is None and skip_patterns is None and not verify_doc:
        return True
    yaml_data = {}
    yaml_fail = None
    try:
        yaml_data = load(case._testMethodDoc, Loader=Loader)
        if not hasattr(yaml_data,'get'):
            yaml_data = {}
            yaml_data['case_name'] = case.id()
        else:
            yaml_data['case_name'] = case.id()
    except Exception as err:
        yaml_fail = err
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
                for tag in field_value.split(','):
                    if not strict and p in tag:
                        is_select = True
                        break
                    if strict and p == tag:
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
                for tag in field_value.split(','):
                    if not strict and p in tag:
                        is_skip = True
                        break
                    if strict and p == tag:
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
        expect_fields = ['case_tag','case_name','case_file','component','bugzilla_id',
                        'is_customer_case','testplan','maintainer','description','key_steps',
                        'expect_result','debug_want']
        print("="*20)
        print(case.id())
        print(case._testMethodDoc)
        print("-"*20)
        if  yaml_fail:
            print(yaml_fail)
            return is_select and not is_skip
        for i in expect_fields:
            if not yaml_data.get(i):
                print('missing {}'.format(i))
    return is_select and not is_skip

def msg_to_syslog(test_instance, msg=None):
    '''
    Save msg to journal log and dmesg.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        msg {string} -- msg want to save, default is casename
    Return:
        arm: return True
        other: return False
    '''
    if msg is None:
        msg = test_instance.id()
    cmd = "sudo echo os-tests:{} | systemd-cat -p info".format(msg)
    run_cmd(test_instance, cmd, expect_ret=0)
    cmd = "sudo bash -c 'echo \"{}\" > /dev/kmsg'".format(msg)
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
            timeout=60,
            ret_status=False,
            is_log_output=True,
            cursor=None,
            rmt_redirect_stdout=False,
            rmt_redirect_stderr=False,
            rmt_get_pty=False
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
        cursor {string} -- skip content before cursor(line)
        rmt_redirect_stdout {bool} -- ssh command not exit some times, redirect stdout to tmpfile if needed
        rmt_redirect_stderr {bool} -- ssh command not exit some times, redirect stderr to tmpfile if needed

    Keyword Arguments:
        check_ret {bool} -- [whether check return] (default: {False})
    """
    if msg is not None:
        test_instance.log.info(msg)
    test_instance.log.info("CMD: {}".format(cmd))
    status = None
    output = None
    exception_hit = False

    try:
        if test_instance.params['remote_node'] is not None:
            status, output = test_instance.SSH.remote_excute(cmd, timeout, redirect_stdout=rmt_redirect_stdout, redirect_stderr=rmt_redirect_stderr,rmt_get_pty=rmt_get_pty)
        else:
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

    if exception_hit:
        test_cmd = 'uname -a'
        test_instance.log.info("Test system is alive via cmd:{}. If still fail, check no hang or panic happens.".format(test_cmd))
        try:
            if test_instance.params['remote_node'] is not None:
                status, output = test_instance.SSH.remote_excute(test_cmd, timeout)
                status, output = test_instance.SSH.remote_excute(cmd, timeout, redirect_stdout=rmt_redirect_stdout, redirect_stderr=rmt_redirect_stderr,rmt_get_pty=rmt_get_pty)
            else:
                ret = subprocess.run(test_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, encoding='utf-8')
                status = ret.returncode
                if ret.stdout is not None:
                   output = ret.stdout
                test_instance.log.info("CMD ret: {} out:{}".format(status, output))
                test_instance.log.info("Retry to run CMD: {}".format(cmd))
                status = None
                output = None
                ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, encoding='utf-8')
                status = ret.returncode
                if ret.stdout is not None:
                   output = ret.stdout
        except Exception as err:
            test_instance.log.error("Run cmd failed again {}".format(err))
    if status is None and test_instance.vm:
        try:
            test_instance.vm.get_console_log()
        except NotImplementedError:
            test_instance.log.info("{} not implement this func: get_console_log".format(test_instance.vm.provider))
        test_instance.vm.stop()
        test_instance.vm.start()
        test_instance.params['remote_node'] = test_instance.vm.floating_ip
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
            if output.count('\n') > 5:
                find_list = re.findall('\n.*{}.*\n'.format(key_word), output)
            else:
                find_list = re.findall('.*{}.*'.format(key_word), output)
            if len(find_list) > 0:
                test_instance.log.info('expected "{}" found in "{}"'.format(key_word, ''.join(find_list)))
            else:
                if output.count('\n') > 5:
                    test_instance.fail('expected "{}" not found in output(check debug log as too many lines)'.format(key_word))
                else:
                    test_instance.fail('expected "{}" not found in "{}"'.format(key_word,output))
    if expect_not_kw is not None:
        for key_word in expect_not_kw.split(','):
            if output.count('\n') > 5:
                find_list = re.findall('\n.*{}.*\n'.format(key_word), output)
            else:
                find_list = re.findall('.*{}.*'.format(key_word), output)
            if len(find_list) == 0:
                test_instance.log.info('Unexpected "{}" not found in output'.format(key_word))
            else:
                if output.count('\n') > 5:
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
    output = run_cmd(test_instance, "sudo cat /sys/devices/virtual/dmi/id/bios_*", expect_ret=0)
    if 'amazon' in output.lower():
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
        aws: return True
        other: return False
    '''
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

def is_cmd_exist(test_instance, cmd=None, is_install=True, cancel_case=False):
    '''
    check cmd exists status, if no, try to install it.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        cmd {string} -- checked command
        is_install {bool} -- try to install it or not
    '''
    cmd_check = "which %s" % cmd
    ret = run_cmd(test_instance, cmd_check, ret_status=True)
    if ret == 0:
        return True
    else:
        test_instance.log.info("No {} found!".format(cmd))
    if not is_install:
        if cancel_case:
            test_instance.skipTest("Cancel it as {} not found".format(cmd))
        return False
    arch = run_cmd(test_instance, 'uname -p').rstrip('\n')
    pkg_find = "sudo yum provides %s" % cmd
    output = run_cmd(test_instance, pkg_find)
    for i in [arch, 'noarch']:
        pkg_list_tmp = re.findall(".*\.{}".format(i), output)
        pkg_list = [i for i in pkg_list_tmp if 'Repo' not in i]
        if len(pkg_list) > 0:
            break
    if len(pkg_list) == 0:
        test_instance.skipTest("Unable to install {}".format(cmd))
        return False
    pkg_list.sort(reverse=True)
    out = run_cmd(test_instance, "sudo yum info {}".format(pkg_list[0]))
    pkg_names = re.findall('Name.*',out)
    if len(pkg_names) > 0:
        pkg_name = pkg_names[0].split(':')[-1].strip(' ')
    else:
        test_instance.skipTest("Unable to retrive {} owned by which pkg".format(cmd))
    run_cmd(test_instance, "sudo yum install -y {}".format(pkg_name), expect_ret=0, timeout=180)
    return True

def is_pkg_installed(test_instance, pkg_name=None, is_install=True, cancel_case=False, timeout=120):
    '''
    check cmd exists status, if no, try to install it.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        cmd {string} -- checked command
        is_install {bool} -- try to install it or not
    '''
    cmd = "rpm -q {}".format(pkg_name)
    ret = run_cmd(test_instance, cmd, ret_status=True)
    if ret == 0:
        return True
    else:
        test_instance.log.info("No {} found!".format(pkg_name))
        if is_install:
            cmd = 'sudo yum install -y {}'.format(pkg_name)
            ret = run_cmd(test_instance, cmd, ret_status=True, msg='try to install it', timeout=timeout)
            if ret == 0:
                return True
        if cancel_case: test_instance.skipTest("Unable to install {}".format(pkg_name))
        return False

def pkg_install(test_instance, pkg_name=None, pkg_url=None, force=False):
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
        if not is_pkg_installed(test_instance, pkg_name=pkg_name):
            test_instance.log.info("Try install {} automatically!".format(pkg_name))
            if pkg_url is not None:
                test_instance.log.info("Install {} from {}".format(pkg_name, pkg_url))
                cmd = 'sudo yum -y install %s' % pkg_url
            else:
                test_instance.log.info("Install {} from default repo".format(pkg_name))
                cmd = 'sudo yum -y install %s' % pkg_name
            run_cmd(test_instance, cmd, timeout=1200)
        elif test_instance.params.get('pkg_reinstall'):
            test_instance.log.info("Try reinstall {} automatically!".format(pkg_name))
            if pkg_url is not None:
                test_instance.log.info("Reinstall {} from {}".format(pkg_name, pkg_url))
                cmd = 'sudo yum -y reinstall %s' % pkg_url
            else:
                test_instance.log.info("Reinstall {} from default repo".format(pkg_name))
                cmd = 'sudo yum -y reinstall %s' % pkg_name
            run_cmd(test_instance, cmd, timeout=1200)

        if not is_pkg_installed(test_instance, pkg_name=pkg_name) and pkg_url is not None and force:
            test_instance.log.info('Install without dependences!')
            cmd = 'sudo rpm -ivh %s --nodeps' % pkg_url
            if force:
                cmd = cmd + " --force"
            run_cmd(test_instance, cmd, timeout=1200)
        if not is_pkg_installed(test_instance, pkg_name=pkg_name):
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

def check_log(test_instance, log_keyword, log_cmd="journalctl -b 0", match_word_exact=False, cursor=None, skip_words=None, rmt_redirect_stdout=False, rmt_redirect_stderr=False, rmt_get_pty=False, msg=None):
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
    # Baseline data file
    baseline_file = os.path.dirname(os_tests.__file__) + "/data/baseline_log.json"
    # Result dir
    if msg is not None:
        test_instance.log.info(msg)
    with open(baseline_file,'r') as fh:
        test_instance.log.info("Loading baseline data file from {}".format(baseline_file))
        baseline_dict = json.load(fh)
    run_cmd(test_instance, '\n')
    check_cmd = log_cmd

    if match_word_exact:
        check_cmd = check_cmd + '|grep -iw %s' % log_keyword
    if skip_words:
        check_cmd = check_cmd + '|grep -Ev "{}"'.format(skip_words.replace(',','|'))
    ret = False
    if cursor is not None:
        out = run_cmd(test_instance,
                      check_cmd,
                      expect_ret=0,
                      msg='Get log......', cursor=cursor,
                      rmt_redirect_stderr=rmt_redirect_stderr,
                      rmt_redirect_stdout=rmt_redirect_stdout,
                      rmt_get_pty=rmt_get_pty)
    else:
        out = run_cmd(test_instance,
                      check_cmd,
                      expect_ret=0,
                      msg='Get log......',
                      rmt_redirect_stderr=rmt_redirect_stderr,
                      rmt_redirect_stdout=rmt_redirect_stdout,
                      rmt_get_pty=rmt_get_pty)

    for keyword in log_keyword.split(','):
        ret = find_word(test_instance, out, keyword, baseline_dict=baseline_dict, skip_words=skip_words)
        if not ret and baseline_dict is not None:
            test_instance.fail("New {} in {} log".format(keyword, check_cmd))
        elif not ret:
            test_instance.fail("Found {} in {} log!".format(keyword, check_cmd))
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

def find_word(test_instance, check_str, log_keyword, baseline_dict=None, skip_words=None):
    """find words in content

    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        check_str {[string]} -- [string to look]
        baseline_dict {[dict]} -- [baseline dict to compare]
        match_word_exact: is macthing word exactly
        skip_words: skip words as you want, split by ","

    Returns:
        [Bool] -- [True|False]
    """
    tmp_list = re.findall('.*%s.*\n' % log_keyword, check_str, flags=re.I)
    if len(tmp_list) == 0:
        test_instance.log.info("No %s found!", log_keyword)
        return True
    else:
        test_instance.log.info("%s found!", log_keyword)
    if skip_words is not None:
        for skip_word in skip_words.split(','):
            tmp_list = [x for x in tmp_list if skip_word not in x]
    if len(tmp_list) == 0:
        test_instance.log.info("No {} found after skipped {}!".format(log_keyword, skip_words))
        return True
    # compare 2 string, if similary over fail_rate, consider it as same.
    fail_rate = 70
    no_fail = True
    check_done = False
    for line1 in tmp_list:
        find_it = False
        if baseline_dict is not None:
            for basekey in baseline_dict:
                for sub_basekey_content in baseline_dict[basekey]["content"].split(';'):
                    check_done = False
                    if re.search(sub_basekey_content, line1):
                        if baseline_dict[basekey]["status"] == 'active':
                            test_instance.log.info("Found a similar issue matched in baseline.")
                            find_it = True
                        else:
                            test_instance.log.info("Found a similar issue matched in baseline. But it is not active, please check manually")
                            find_it = False
                            no_fail = False
                            check_done = True
                            break
                        trigger = baseline_dict[basekey]["trigger"]
                        if trigger and re.search(trigger,check_str,flags=re.I):
                            test_instance.log.info("Guess it is expected because trigger keywords found '{}'".format(trigger))
                            find_it = True
                        elif trigger:
                            test_instance.log.info("Guess it is unexpected because trigger keywords not found '{}'".format(trigger))
                            find_it = False
                        test_instance.log.info("log:{}, base:{}".format(line1, sub_basekey_content))
                        test_instance.log.info("ID:%s Baseline analyze:%s Branch:%s Status:%s Link:%s Path:%s" %
                             (basekey,
                              baseline_dict[basekey]["analyze"],
                              baseline_dict[basekey]["branch"],
                              baseline_dict[basekey]["status"],
                              baseline_dict[basekey]["link"],
                              baseline_dict[basekey]["path"]))
                        check_done = True
                        break
                if find_it or check_done:
                    break
                line1_tmp = line1
                line2_tmp = baseline_dict[basekey]["content"]
                line1_tmp, line2_tmp = clean_sentence(test_instance, line1_tmp, line2_tmp)
                seq = difflib.SequenceMatcher(
                    None, a=line1_tmp, b=line2_tmp)
                same_rate = seq.ratio() * 100
                if same_rate > fail_rate:
                    test_instance.log.info(
                        "Compare result rate: %d same, maybe it is not a new one", same_rate)
                    test_instance.log.info("Guest: %s Baseline: %s", line1,
                             baseline_dict[basekey]["content"])
                    test_instance.log.info("ID:%s Baseline analyze:%s Branch:%s Status:%s Link:%s Path:%s" %
                             (basekey,
                              baseline_dict[basekey]["analyze"],
                              baseline_dict[basekey]["branch"],
                              baseline_dict[basekey]["status"],
                              baseline_dict[basekey]["link"],
                              baseline_dict[basekey]["path"]))
                    trigger = baseline_dict[basekey]["trigger"]
                    if trigger and re.search(trigger,check_str,flags=re.I):
                        test_instance.log.info("Guess it is expected because trigger keywords found '{}'".format(trigger))
                        find_it = True
                    elif trigger:
                        test_instance.log.info("Guess it is unexpected because trigger keywords not found '{}'".format(trigger))
                        find_it = False
                        break
                    if baseline_dict[basekey]["status"] == 'active':
                        find_it = True
                    else:
                        test_instance.log.info("Find a similar issue which should be already fixed, please check manually.")
                        find_it = False
                        no_fail = False
                    break
        if not find_it:
            test_instance.log.info("This is a new exception!")
            test_instance.log.info("{}".format(line1))
            no_fail = False

    return no_fail

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
