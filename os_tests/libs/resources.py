from abc import ABCMeta, abstractmethod

class BaseResource(metaclass=ABCMeta):
    """
    This is a abstract class for the base resource.
    The resource type can be instance, network, disk.
    """

    def __init__(self, params):
        self.params = params
        # mark the resource created, default is os_tests
        self.tag = 'os_tests'

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
    This is a abstract class for the base vm resource.
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

    def get_console_log(self):
        """
        get console log or retrive debug log if vm hang or panic
        :return: console log as str
        """

class NICResource(BaseResource):
    """
    This is a abstract class for the base vm resource.
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

    def get_console_log(self):
        """
        get console log or retrive debug log if vm hang or panic
        :return: console log as str
        """
