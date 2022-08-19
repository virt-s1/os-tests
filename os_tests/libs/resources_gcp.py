from .resources import VMResource, StorageResource, NetworkResource, UnSupportedAction, UnSupportedStatus
from os_tests.libs import utils_lib
import logging
import time
import sys
try:
    from apiclient.discovery import build
    from google.oauth2 import service_account, id_token
    import google.auth.transport.requests
except ImportError as err:
    print("Please install google-api-python-client module if run gcp test")
    sys.exit(1)

LOG = logging.getLogger('os_tests.os_tests_run')
logging.basicConfig(level=logging.INFO)


def get_service(api_name, api_version, scopes, key_file_location):
    """Get a service that communicates to a Google API.

    Args:
        api_name: The name of the api to connect to.
        api_version: The api version to connect to.
        scopes: A list auth scopes to authorize for the application.
        key_file_location: The path to a valid service account JSON key file.

    Returns:
        A service that is connected to the specified API.
    """

    credentials = service_account.Credentials.from_service_account_file(
        key_file_location, scopes=scopes)

    # Build the service object.
    service = build(api_name,
                    api_version,
                    credentials=credentials,
                    cache_discovery=False)

    return service


def verify_token(token: str, audience: str) -> dict:
    request = google.auth.transport.requests.Request()
    payload = id_token.verify_token(token, request=request, audience=audience, clock_skew_in_seconds=150)
    return payload


def wait_for_operation(compute, project, zone, operation):
    print('Waiting for operation to finish...')
    while True:
        result = compute.zoneOperations().get(project=project,
                                              zone=zone,
                                              operation=operation).execute()

        if result['status'] == 'DONE':
            print("done.")
            if 'error' in result:
                raise Exception(result['error'])
            return result

        time.sleep(1)


def get_instance(compute, project, zone, resourceId):
    result = compute.instances().get(project=project,
                                     zone=zone,
                                     instance=resourceId).execute()
    return result


def get_image(compute, project, resourceId):
    result = compute.images().get(project=project, image=resourceId).execute()
    return result


def list_instances(compute, project, zone):
    result = compute.instances().list(project=project, zone=zone).execute()
    return result['items'] if 'items' in result else None


class GCPVM(VMResource):

    def __init__(self, params, **kwargs):
        super(GCPVM, self).__init__(params)
        self._data = None

        # GCP connection credentials
        self.project = params['Cloud'].get('project_name')
        self.zone = params['Cloud'].get('zone')

        # Define the auth scopes to request.
        scope = 'https://www.googleapis.com/auth/compute'
        service_account_json_file = params['Cloud'].get(
            'service_account_json_file')

        # Authenticate and construct service.
        self.service_v1 = get_service(
            api_name='compute',
            api_version='v1',
            scopes=[scope],
            key_file_location=service_account_json_file)

        self.service_beta = get_service(
            api_name='compute',
            api_version='beta',
            scopes=[scope],
            key_file_location=service_account_json_file)

        # VM creation parameters
        self.vm_name = params['VM'].get('vm_name')
        self.image_name = params['VM'].get('image_name')

        self.flavor = params.get('Flavor').get('name')
        self.size = params.get('Flavor').get('size')
        self.user_data = None

        # VM access parameters
        self.vm_username = params['VM'].get('username')
        self.vm_password = params['VM'].get('password')

        self.arch = params.get('Flavor').get('arch')
        self.nic_type = params.get('Flavor').get('nic_type')

    @property
    def data(self):
        if not self._data:
            self.data = self.vm_name
        return self._data

    @data.setter
    def data(self, name):
        instance = get_instance(self.service_v1, self.project, self.zone, name)
        self._data = instance

    @property
    def floating_ip(self):
        f_ip = self.data['networkInterfaces'][0]['accessConfigs'][0]['natIP']
        return f_ip

    def create(self, sev=False, wait=False):
        # Get image.
        source_disk_image = get_image(self.service_v1, self.project,
                                      self.image_name)['selfLink']

        # Configure the machine
        machine_type = "zones/%s/machineTypes/%s" % (self.zone, self.flavor)
        if sev:
            machine_type = "zones/%s/machineTypes/n2d-standard-2" % self.zone
        if "n2d" in self.flavor or "c2d" in self.flavor:
            sev = True

        config = {
            'name':
            self.vm_name,
            'machineType':
            machine_type,

            # Specify the boot disk and the image to use as a source.
            'disks': [{
                'boot': True,
                'autoDelete': True,
                'initializeParams': {
                    'sourceImage': source_disk_image,
                    'diskSizeGb': self.size.replace('G', ''),
                }
            }],

            # Specify a network interface with NAT to access the public
            # internet.
            'networkInterfaces': [{
                'network':
                'global/networks/default',
                'accessConfigs': [{
                    'type': 'ONE_TO_ONE_NAT',
                    'name': 'External NAT'
                }],
                "nicType": self.nic_type
            }],

            # Allow the instance to access cloud storage and logging.
            'serviceAccounts': [{
                'email':
                'default',
                'scopes': [
                    'https://www.googleapis.com/auth/devstorage.read_write',
                    'https://www.googleapis.com/auth/logging.write'
                ]
            }],
            'scheduling': {
                'provisioningModel': 'SPOT',
                'instanceTerminationAction': 'DELETE'
            },
        }

        if sev:
            config['confidentialInstanceConfig'] = {
                "enableConfidentialCompute": True
            }
            config['disks'][0]['interface'] = 'NVME'
            config['networkInterfaces'][0]['nicType'] = 'GVNIC'

        operation = self.service_v1.instances().insert(project=self.project,
                                                       zone=self.zone,
                                                       body=config).execute()

        wait_for_operation(self.service_v1, self.project, self.zone,
                           operation['name'])

        self._data = None

    def delete(self, wait=False):
        operation = self.service_v1.instances().delete(
            project=self.project, zone=self.zone,
            instance=self.vm_name).execute()

        wait_for_operation(self.service_v1, self.project, self.zone,
                           operation['name'])

    def start(self, wait=False):
        operation = self.service_v1.instances().start(
            project=self.project, zone=self.zone,
            instance=self.vm_name).execute()

        wait_for_operation(self.service_v1, self.project, self.zone,
                           operation['name'])

        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get started."):
                if self.is_started():
                    break

        self._data = None

    def stop(self, wait=False):
        operation = self.service_v1.instances().stop(
            project=self.project, zone=self.zone,
            instance=self.vm_name).execute()

        wait_for_operation(self.service_v1, self.project, self.zone,
                           operation['name'])

        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get stopped."):
                if self.is_stopped():
                    break

    def reboot(self, wait=False):
        self.stop()
        self.start()

    def pause(self, wait=False):
        operation = self.service_beta.instances().suspend(
            project=self.project, zone=self.zone,
            instance=self.vm_name).execute()

        wait_for_operation(self.service_v1, self.project, self.zone,
                           operation['name'])

        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get paused."):
                if self.is_paused():
                    break

    def unpause(self, wait=False):
        operation = self.service_beta.instances().resume(
            project=self.project, zone=self.zone,
            instance=self.vm_name).execute()

        wait_for_operation(self.service_v1, self.project, self.zone,
                           operation['name'])

        if wait:
            for count in utils_lib.iterate_timeout(
                    60, "Timed out waiting for server to get unpaused."):
                if self.is_started():
                    break

        self._data = None

    def exists(self):
        instances = list_instances(self.service_v1, self.project, self.zone)

        if instances:
            for instance in instances:
                if instance['name'] == self.vm_name:
                    return True

        return False

    def _get_status(self):
        self.data = self.vm_name
        return self.data['status']

    def is_started(self):
        return self._get_status() == 'RUNNING'

    def is_stopped(self):
        return self._get_status() == 'TERMINATED'

    def is_paused(self):
        return self._get_status() == 'SUSPENDED'

    def show(self):
        return self.data

    def is_sev_enabled(self, token, audience):
        sev = False
        payload = verify_token(token, audience)
        if 'instance_confidentiality' in payload['google'][
                'compute_engine'] and payload['google']['compute_engine'][
                    'instance_confidentiality'] == 1:
            sev = True
        return sev

    def get_console_log(self):
        response = self.service_v1.instances().getSerialPortOutput(
            project=self.project, zone=self.zone,
            instance=self.vm_name).execute()
        LOG.info(response['contents'])
        return response['contents']

    def disk_count(self):
        raise NotImplementedError

    def get_state(self):
        raise NotImplementedError

    def send_nmi(self):
        raise UnSupportedAction('No such operation in gcp')

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
        return self.exists()
