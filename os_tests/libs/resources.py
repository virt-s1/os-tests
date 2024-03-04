from abc import ABCMeta, abstractmethod

class UnSupportedAction(Exception):
    """
    raise if the action is not supported
    """
    pass

class UnSupportedStatus(Exception):
    """
    raise it if the status is not supported
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
        self.support_cases = params.get('support_cases')
        self.id = 0
        # store resource messages
        self.msgs = ''

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
        # mark the resource created, default is os_tests_vm
        self.tag = 'os_tests_vm'
        # dead_count to monitor resource health status
        # for example, if the vm cannot connect over X times, we can skip the follow cases
        # no need to retry connection until timeout
        self.dead_count = 0

    @property
    @abstractmethod
    def floating_ip(self):
        """
        get vm's floating ipv4
        :return: vm's ip or FQDN
        """

    def ipv6_address(self):
        """
        get vm's floating ipv6
        :return: vm's ipv6 or FQDN
        """

    @property
    def is_secure_boot(self):
        """
        vm provisioned with secure boot or not
        :return: True|False
        """
        return False

    @property
    def is_uefi_boot(self):
        """
        vm provisioned with uefi or not
        :return: True|False
        """
        return False

    @property
    def port(self):
        """
        get vm's open port for ssh connection
        :return 22 by default or other dynamic value by overwrite this func.
        """
        return 22

    @property
    def is_metal(self):
        """
        return if vm is metal or not
        """
        return False

    @property
    @abstractmethod
    def disk_count(self):
        """
        get vm's disk count assigned
        :return: the disk count
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
    def pause(self, wait=False):
        """
        pause VM
        :param wait: Wait for vm paused
        :return: return True|False|UnSupportedAction
        """

    @abstractmethod
    def unpause(self, wait=False):
        """
        unpause VM
        :param wait: Wait for vm active
        :return: return True|False|UnSupportedAction
        """

    @abstractmethod
    def send_nmi(self):
        """
        send nmi event to vm
        :return: return True|False|UnSupportedAction
        """

    @abstractmethod
    def send_hibernation(self):
        """
        send hibernation request to vm
        :return: return True|False|UnSupportedAction
        """

    @abstractmethod
    def get_console_log(self):
        """
        get console log or retrive debug log if vm hang or panic
        :return: console log as str or other info when call it
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

    @abstractmethod
    def is_paused(self):
        """
        check if vm is paused
        :return: return True|False|UnSupportedStatus
        """

    @abstractmethod
    def attach_block(self, disk, target, wait=True, timeout=120):
        """
        attach disk to vm
        :param disk: storage instance
        :param target: None or something like sda,xvda......
        :param wait: wait disk is not free
        :param timeout: timeout for this operation
        :return: True or False
        """

    @abstractmethod
    def detach_block(self, disk, wait=True, force=False):
        """
        detach disk from vm
        :param disk: storage instance
        :param wait: wait for device is free
        :param force: force detach even in use
        :return: raise Exception if detach failed
        """

    @abstractmethod
    def attach_nic(self, nic, wait=True, timeout=120):
        """
        attach nic to vm
        :param nic: network instance
        :param device_name: None or something like sda,xvda......
        :param wait: wait disk is not free
        :param timeout: timeout for this operation
        :return: True or False
        """

    @abstractmethod
    def detach_nic(self, nic, wait=True, force=False):
        """
        detach nic from vm if it is in use
        :param nic: network instance
        :param wait: wait for device is free
        :param force: force detach even in use
        :return: raise Exception if detach failed
        """

class StorageResource(BaseResource):
    """
    This is an abstract class for the base storage resource.
    """
    def __init__(self, params):
        super().__init__(params)
        # mark the resource created, default is os_tests_storage
        self.tag = 'os_tests_storage'
        self.type = None
        self.size = 10
        self.iops = None
        self.id = None
        # specif if the disk is in local
        self.path = None

    @abstractmethod
    def is_free(self):
        """
        check if disk is free
        :return: return True or False
        """
    @abstractmethod
    def modify_disk_size(self, os_disk_size, expand_num):
        """
        modify os disk size to plus expand number to origianl size
        :param os_disk_size: os disk original size
        :param expan_num: number to expan os disk size
        """

class NetworkResource(BaseResource):
    """
    This is an abstract class for the base network resource.
    """
    def __init__(self, params):
        super().__init__(params)
        # mark the resource created, default is os_tests_nic
        self.tag = 'os_tests_nic'
        self.type = None
        self.id = None

    @abstractmethod
    def is_free(self):
        """
        check if nic is free
        :return: return True or False
        """