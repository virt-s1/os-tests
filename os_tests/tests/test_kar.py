import configparser
import os
import unittest

from os_tests.libs import utils_lib


class TestKAR(unittest.TestCase):
    run_mappings = {
        "boot": [
            f"--guestname={os.getenv('DISTRO')}..page_{os.getenv('PAGESIZE')}",
            "--netdst=virbr0",
            "--driveformat=virtio_scsi",
            "--testcase=boot",
            "--isopool=null://",
            "--clone=yes",
            "--debug"
        ],
        # "tier1": [
        #     "--category=tier1_test_aarch64",
        #     f"--hostname={os.getenv('DISTRO')}",
        #     f"--customsparams='only qemu_build.host_{os.getenv('PAGESIZE')}'",
        #     "--netdst=virbr0",
        #     "--driveformat=virtio_scsi",
        #     "--isopool=null://",
        #     "--clone=no",
        #     "--debug"
        # ],
    }

    def setUp(self):
        utils_lib.init_case(self)

    def prepare_environment(self, kar_dir, images_dir):
        kar_loc = self.params['kar_location']
        images_loc = self.params['kar_images_location']

        if not kar_loc and not images_loc:
            raise Exception("No kar or images location assigned")

        # Set timeout to 600 for avoiding some timeout error, or maybe put them into CI
        cmd = ("dnf install -y bzip2 qemu-* git vim gcc libvirt-* libguestfs-* "
               "virt-install python3-sphinx gdb* bpf* ksm* tcpdump "
               "rpmdevtools* python3-devel")
        ret, out = utils_lib.run_cmd_local(cmd, timeout=600, is_log_ret=True)
        if ret != 0:
            raise Exception(f"Install packages failed - {out}")

        cmd = ("systemctl start --now virtqemud && "
               "systemctl start --now virtnetworkd && "
               "systemctl start --now virtstoraged && "
               "systemctl start --now virtinterfaced && "
               "systemctl start --now virtnodedevd")
        ret, out = utils_lib.run_cmd_local(cmd, is_log_ret=True)
        if ret != 0:
            raise Exception(f"Enable virtualization failed - {out}")

        ret, _ = utils_lib.run_cmd_local(f"test -d {kar_dir}", is_log_ret=True)
        if ret != 0:
            ret, out = utils_lib.run_cmd_local(f"tar -jxvf {kar_loc} -C /home",
                                               is_log_ret=True)
            if ret != 0:
                raise Exception(f"Decompression kar.bz2 failed - {out}")

        ret, _ = utils_lib.run_cmd_local(f"test -d {images_dir}",
                                         is_log_ret=True)
        if ret != 0:
            ret, out = utils_lib.run_cmd_local(f"mkdir -p {images_dir}",
                                               is_log_ret=True)
            if ret != 0:
                raise Exception(f"Create images directory failed - {out}")

            ret, out = utils_lib.run_cmd_local(f"tar -jxvf {images_loc} -C {images_dir}",
                                               is_log_ret=True,
                                               timeout=600)
            if ret != 0:
                raise Exception(f"Decompression images.bz2 failed - {out}")

    def test_kar_run(self):
        kar_dir = "/home/kar"
        images_dir = "/home/kvm_autotest_root"

        self.prepare_environment(kar_dir, images_dir)

        venv = kar_dir + "/workspace"

        # Set timeout to 600 for avoiding some timeout error
        ret, out = utils_lib.run_cmd_local(cmd=f"source {venv}/bin/activate && pip install netifaces 'jinja2' Pillow",
                                           timeout=600,
                                           is_log_ret=True)
        if ret != 0:
            raise Exception(f"Installing venv dependencies fails - {out}")

        cmd_prefix = (
            f"source {venv}/bin/activate && "
            f"PYTHONPATH={venv}/avocado:{venv}/avocado-vt:{venv}/aexpect "
            f"python3 {kar_dir}/ConfigTest.py "
        )
        error_list = []

        for k, v in self.run_mappings.items():
            cmd = cmd_prefix + " ".join(v)

            # Timeout: 12 hours
            ret, out = utils_lib.run_cmd_local(cmd=cmd,
                                               timeout=12 * 60 * 60,
                                               is_log_ret=True)
            if ret != 0:
                error_list.append(k)

        # Read the avcado config for log dir
        # Then put them into os-tests resutls dir
        kar_config = configparser.ConfigParser()
        kar_config.read(os.getenv('KAR_AVOCADO_CONF'))
        avocado_results_path = os.path.realpath(kar_config['datadir.paths']['logs_dir'] + "/latest")
        ret, _ = utils_lib.run_cmd_local(cmd=f"cp -r {avocado_results_path} {self.params['results_dir']}",
                                            timeout=600,
                                            is_log_ret=True)
        if ret != 0:
            self.log.error(f"Failed for cp -r {avocado_results_path} {self.params['results_dir']}")

        # If error during running, raising in the end
        if error_list:
            for i in error_list:
                self.log.error(f"kar test suite {i} failed")
            raise Exception("Run kar suite failed")

    def tearDown(self):
        utils_lib.finish_case(self)
