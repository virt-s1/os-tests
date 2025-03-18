from .resources import VMResource, StorageResource, NetworkResource, UnSupportedAction, UnSupportedStatus
from os_tests.libs import utils_lib
import subprocess
import yaml
import re
import os
import json
import time

FNULL = open(os.devnull, 'w')


def login(token, server, project):
    #  p = subprocess.Popen(auth.split(), stdout=subprocess.PIPE)
    #  cmd = ''.join([b.decode("utf-8") for b in p.communicate() if b])
    cmd = 'oc login --insecure-skip-tls-verify --token=%s --server=%s' % (token, server)
    subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()
    subprocess.Popen('oc project %s' % project,
                     shell=True,
                     stdout=subprocess.PIPE).communicate()


class OpenShiftVM(VMResource):

    def __init__(self, params):
        super(OpenShiftVM, self).__init__(params)
        self._data = None

        token = params['Cloud'].get('token')
        self.apiserver = params['Cloud'].get('apiserver')
        project = params['Cloud'].get('project')
        login(token, self.apiserver, project)

        # VM creation parameters
        self.vm_name = params['VM'].get('vm_name')
        self.image_name = params['VM'].get('image_name')
        self.rhel_ver = params['VM'].get('rhel_ver')
        self.arch = params['VM'].get('arch')
        self.flavor = params['Flavor'].get('name')
        self.size = params['Flavor'].get('size')
        self.vcpus = params['Flavor'].get('cpu')
        self.memory = params['Flavor'].get('memory')
        self.user_data = None
        self.run_uuid = params.get('run_uuid')
        self._port = None

        # VM access parameters
        self.vm_username = params['VM'].get('username')
        self.vm_password = params['VM'].get('password')

        self.arch = 'x86_64'

    @property
    def data(self):
        if not self._data:
            self.data = self.vm_name
        return self._data

    @data.setter
    def data(self, name):
        uid = subprocess.Popen(
            'oc get vm %s -o custom-columns=:.metadata.uid --no-headers' %
            name,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=FNULL).communicate()[0].decode("utf-8")
        if uid:
            self._data = {"uid": uid}

    @property
    def port(self):
        if not self._port:
            self._port = subprocess.Popen(
                'oc get svc %s -o custom-columns=:.spec.ports[0].nodePort'
                ' --no-headers' % self.vm_name,
                shell=True,
                stdout=subprocess.PIPE).communicate()[0] \
                    .decode("utf-8").rstrip('\n')
        #return self._port   
        return 22

    @port.setter
    def port(self, name):
        subprocess.Popen(
            'virtctl expose vm %s --port=22 --name=%s --type=LoadBalancer' % (name, name),
            shell=True,
            stdout=FNULL).communicate()
    
    @property
    def floating_ip(self):
        try:
            result = subprocess.run(
                ["oc", "get", "services", "-o", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            services = json.loads(result.stdout)

            for service in services.get("items", []):
                if service["spec"]["type"] == "LoadBalancer" and service["metadata"]["name"] == f"{self.vm_name}":
                    ext_ip = service.get("status", {}).get("loadBalancer", {}).get("ingress", [{}])[0].get("hostname")
                    if ext_ip:
                        # Wait for DNS resolution before returning
                        time.sleep(60)

                        known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")
                        result = subprocess.run(["ssh-keyscan", ext_ip], capture_output=True, text=True)
                        filtered_output = "\n".join(
                            line for line in result.stdout.splitlines() if "SSH-2.0-OpenSSH" not in line
                        )
                        if filtered_output:
                            with open(known_hosts_path, "a") as known_hosts:
                                known_hosts.write(filtered_output + "\n")
                    
                        return ext_ip

        except subprocess.CalledProcessError as e:
            print(f"Error fetching services: {e}")

        return None  

    def create(self, wait=False):
        self.pwd = os.path.abspath(os.path.dirname(__file__))
        data_dir = os.path.join(os.path.dirname(self.pwd), 'data')
        with open(os.path.join(data_dir, 'guest-images/openshift.templ'),
                  'r') as f:
            try:
                vm_spec = yaml.load(f, Loader=yaml.FullLoader)
            except yaml.YAMLError as e:
                print(e)

        ssh_pubkey = utils_lib.get_public_key()
        userData = re.sub(
            'ssh-rsa.*\n', ssh_pubkey, vm_spec['spec']['template']['spec']
            ['volumes'][0]['cloudInitNoCloud']['userData'])
        vm_spec['spec']['template']['spec']['volumes'][0]['cloudInitNoCloud'][
            'userData'] = userData
        vm_spec['spec']['template']['spec']['volumes'][1]['containerDisk'][
            'image'] = self.image_name
        vm_spec['metadata']['name'] = self.vm_name
        vm_spec['spec']['template']['metadata']['labels'][
            'kubevirt.io/domain'] = self.vm_name
        vm_spec['spec']['template']['spec']['domain']['cpu'][
            'cores'] = self.vcpus
        vm_spec['spec']['template']['spec']['domain']['resources']['requests'][
            'memory'] = str(self.memory) + 'Gi'

        with open(os.path.join(data_dir, 'guest-images/openshift.yaml'),
                  'w') as file:
            yaml.dump(vm_spec, file)

        subprocess.Popen('oc apply -f %s' %
                         os.path.join(data_dir, 'guest-images/openshift.yaml'),
                         shell=True,
                         stdout=FNULL).communicate()

        if wait:
            for count in utils_lib.iterate_timeout(
                    900, "Timed out waiting for server to get Created."):
                if self.is_started():
                    break
        self.port = self.vm_name
        self._data = None

    def delete(self, wait=False):
        subprocess.Popen('oc delete vm %s' % self.vm_name,
                         shell=True,
                         stdout=FNULL).communicate()
        subprocess.Popen('oc delete svc %s' % self.vm_name, shell=True,
                         stdout=FNULL).communicate()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get deleted."):
                if not self.exists():
                    break

    def start(self, wait=False):
        subprocess.Popen('virtctl start %s' % self.vm_name,
                         shell=True,
                         stdout=FNULL).communicate()
        if wait:
            for count in utils_lib.iterate_timeout(
                    120, "Timed out waiting for server to get started."):
                if self.is_started():
                    break

    def stop(self, wait=False):
        subprocess.Popen('virtctl stop %s' % self.vm_name,
                         shell=True,
                         stdout=FNULL).communicate()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get stopped."):
                if self.is_stopped():
                    break

    def reboot(self, wait=False):
        subprocess.Popen('virtctl restart %s' % self.vm_name,
                         shell=True,
                         stdout=FNULL).communicate()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get rebooted."):
                if self.is_started():
                    break

    def pause(self, wait=False):
        subprocess.Popen('virtctl pause vm %s' % self.vm_name,
                         shell=True,
                         stdout=FNULL).communicate()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get paused."):
                if self.is_paused():
                    break

    def unpause(self, wait=False):
        subprocess.Popen('virtctl unpause vm %s' % self.vm_name,
                         shell=True,
                         stdout=FNULL).communicate()
        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get unpaused."):
                if self.is_started():
                    break

    def exists(self):
        self._data = None
        if self.data is None:
            return False
        count = sum(1 for i in self.data)
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        status = subprocess.Popen(
            'oc get vm %s -o custom-columns=:.status.printableStatus --no-headers' %
            self.vm_name,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=FNULL).communicate()[0].decode("utf-8").rstrip('\n')
        return status
        running = subprocess.Popen(
            'oc get vmi %s -o custom-columns=:.status.phase --no-headers' %
            self.vm_name,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=FNULL).communicate()[0].decode("utf-8").rstrip('\n')
        if (running == "Running"):
            pause = subprocess.Popen(
                'oc get vmi %s -o yaml | \
                yq e ".status.conditions.[]|select(.lastProbeTime != null \
                and .lastTransitionTime != null).type" -' % self.vm_name,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=FNULL).communicate()[0].decode("utf-8").rstrip('\n')
            if (pause == "Paused"):
                return "PAUSED"
            else:
                return "Running"
        return "Unknown"

    def get_state(self):
        return self._get_status()

    def is_started(self):
        return self._get_status() == "Running"

    def is_stopped(self):
        return self._get_status() == "Stopped"

    def is_paused(self):
        return self._get_status() == "Paused"

    def show(self):
        return self.data

    def get_console_log(self):
        raise NotImplementedError

    def disk_count(self):
        raise NotImplementedError

    def send_nmi(self):
        raise UnSupportedAction('No such operation in openshift')

    def send_hibernation(self):
        raise NotImplementedError

    def attach_block(self, disk, target, wait=True, timeout=120):
        raise NotImplementedError

    def detach_block(self, disk, wait=True, force=False):
        raise NotImplementedError

    def attach_nic(self, nic, wait=True, timeout=120):
        raise NotImplementedError

    def detach_nic(self, nic, wait=True, force=False):
        raise NotImplementedError

    def is_exist(self):
        raise NotImplementedError
