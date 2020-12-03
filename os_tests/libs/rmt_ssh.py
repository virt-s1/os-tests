import paramiko
import logging
import time
import sys
import os

log = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.INFO)
def build_connection(rmt_node=None, rmt_user='ec2-user', rmt_keyfile=None, timeout=180):
    log.info("Try to make connection: {}@{}".format(rmt_user, rmt_node))
    ssh_client = paramiko.SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())
    start_time = time.time()
    while True:
        try:
            end_time = time.time()
            if end_time-start_time > timeout:
                log.info("Unable to make connection!")
                return None
            if rmt_keyfile is None:
                ssh_client.load_system_host_keys()
                ssh_client.connect(rmt_node, username=rmt_user)
            else:
                if not os.path.exists(rmt_keyfile):
                    log.error("{} not found".format(rmt_keyfile))
                    return None
                ssh_client.connect(
                    rmt_node,
                    username=rmt_user,
                    key_filename=rmt_keyfile,
                    look_for_keys=False,
                    timeout=60
                )
            return ssh_client
        except Exception as e:
            log.info("*** Failed to connect to %s: %r" %
                     (rmt_node, e))
            log.info("Retry again, timeout {}!".format(timeout))
            time.sleep(10)

def cli_run(ssh_client, cmd,timeout):
    stdin, stdout, stderr = ssh_client.exec_command(
                            cmd, timeout=timeout)
                            #cmd, timeout=timeout, get_pty=True)
    start_time = time.time()
    while not stdout.channel.exit_status_ready():
        current_time = time.time()
        if current_time - start_time > timeout:
            log.info('Timeout to run cmd {}s'.format(timeout))
            stdout.channel.close()
            break
    while not stdout.channel.exit_status_ready() and stdout.channel.recv_exit_status():
        time.sleep(1)
        log.info("Wait command complete......")
    output = ''.join(stdout.readlines())
    errlog = ''.join(stderr.readlines())
    ret = stdout.channel.recv_exit_status()
    return ret, output, errlog

def remote_excute(ssh_client, cmd,timeout, redirect_stdout=False, redirect_stderr=False):
    if redirect_stdout or redirect_stderr:
        cmd = cmd + " 1>/tmp/cmd.out 2>/tmp/cmd.err"
    log.info("Run on remote: {}".format(cmd))
    
    status, output, errlog = cli_run(ssh_client, cmd, timeout)
    if redirect_stdout or redirect_stderr:
        _, output, _ = cli_run(ssh_client, 'cat /tmp/cmd.out', timeout)
        _, _, errlog = cli_run(ssh_client, 'cat /tmp/cmd.err', timeout)
    if len(errlog) > 2:
        log.info("cmd err: {}".format(errlog))
    return status, output
