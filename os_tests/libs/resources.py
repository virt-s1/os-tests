from abc import ABCMeta, abstractmethod

class UnSupportedOperation(Exception):
    """
    raise it if the operation is not supported
    """
    pass

class BaseResource(metaclass=ABCMeta):
    """
    This is an abstract class for the base resource.
    The resource type can be instance, network, disk.
    """

    def __init__(self, params):
        self.params = params
        # mark the resource created, default is os_tests
        self.tag = 'os_tests'
        self.provider = params['Cloud']['provider']

    @abstractmethod
    def show(self):
        """
        show any information about resource information when call it
        :return: return str
        """

    @abstractmethod
    def create(self, wait=False):
        """
        create new resource
        :param wait: wait for resource ready
        :return: raise Exception if resource creation failed
        """

    @abstractmethod
    def delete(self, wait=False):
        """
        delete resource
        :param wait: wait for resource deleted
        :return: raise Exception if resource delete failed
        """

    @abstractmethod
    def is_exist(self):
        """
        check if resource exists
        :return: True if exists.
        Example:
        return True if self._get_status() != -1 else False
        """
    
    @abstractmethod
    def get_state(self):
        """
        get the resource current state.
        :return: the currenet state in str
        """

class VMResource(BaseResource):
    """
    This is an abstract class for the base vm resource.
    """
    def __init__(self, params):
        super().__init__(params)
        # mark the resource created, default is os_tests
        self.tag = 'os_tests_vm'

    @property
    @abstractmethod
    def floating_ip(self):
        """
        get vm's floating ip
        :return: vm's ip or FQDN
        """

    @abstractmethod
    def start(self, wait=False):
        """
        start VM
        :param wait: Wait for vm started
        :return: raise Exception if VM start failed
        """

    @abstractmethod
    def stop(self, wait=False):
        """
        stop VM
        :param wait: wait for vm stopped
        :return: raise Exception if VM stop failed
        """

    @abstractmethod
    def reboot(self, wait=False):
        """
        reboot VM
        :param wait: Wait for vm rebooted
        :return: raise Exception if VM reboot failed
        """
    
    @abstractmethod
    def send_nmi(self):
        """
        send nmi event to vm
        :return: raise Exception if VM send nmi failed
        """

    @abstractmethod
    def send_hibernation(self):
        """
        send hibernation request to vm
        :return: raise Exception if VM send hibernation failed
        """

    @abstractmethod
    def get_console_log(self):
        """
        get console log or retrive debug log if vm hang or panic
        :return: console log as str
        """

    @abstractmethod
    def is_started(self):
        """
        check if vm is started
        :return: return True or False
        """

    @abstractmethod
    def is_stopped(self):
        """
        check if vm is stopped
        :return: return True or False
        """

class StorageResource(BaseResource):
    """
    This is an abstract class for the base storage resource.
    """
    def __init__(self, params):
        super().__init__(params)
        # mark the resource created, default is os_tests
        self.tag = 'os_tests_storage'

    def is_free(self):
        """
        check if disk is free
        :return: return True or False
        """

    @abstractmethod
    def attach_to_vm(self, vm, device_name, wait=True, timeout=120):
        """
        attach disk to vm
        :param vm: vm instance
        :param device_name: None or something like sda,xvda......
        :param wait: wait disk is not free
        :param timeout: timeout for this operation
        :return: True or False
        """

    @abstractmethod
    def detach_from_vm(self, wait=True, force=False):
        """
        detach disk from vm if it is in use
        :param wait: wait for device is free
        :return: raise Exception if VM stop failed
        """

    @abstractmethod
    def create(self, wait=True, disksize=100, disktype='standard', iops=3000, loops=5):
        """
        reboot VM
        :param wait: Wait for vm rebooted
        :return: raise Exception if VM reboot failed
        """