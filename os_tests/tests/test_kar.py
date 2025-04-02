import configparser
import os
import unittest

from os_tests.libs import utils_lib


class TestKAR(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)

        if not self.params.get('kar_location'):
            raise Exception("kar location must be assigned")
        if not self.params.get('kar_images_location'):
            raise Exception("images location must be assigned")
        if not self.params.get("kar_tests"):
            raise Exception("no test suite of kar assigned")
        if not self.params.get("kar_avocado_conf"):
            raise Exception("no avocado config assigned")

    def prepare_environment(self, kar_dir, images_dir):
        kar_loc = self.params.get('kar_location')
        images_loc = self.params.get('kar_images_location')

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
        # Read the avocado config for the log dir
        # Then put them into os-tests resutls dir
        kar_config = configparser.ConfigParser()
        kar_config.read(self.params.get("kar_avocado_conf"))

        for k, v in self.params.get("kar_tests").items():
            cmd = cmd_prefix + v

            ret, out = utils_lib.run_cmd_local(cmd=cmd,
                                               timeout=12 * 60 * 60,
                                               is_log_ret=True)
            if ret != 0:
                error_list.append(f"Run testsuite {k} failed with {out}")

            target_res_dir = self.params['results_dir'] + "/" + k
            ret, out = utils_lib.run_cmd_local(cmd=f"mkdir -p {target_res_dir}",
                                               is_log_ret=True)
            if ret != 0:
                error_list.append(f"Create target results directory failed with {out}")

            avocado_results_path = os.path.realpath(kar_config['datadir.paths']['logs_dir'] + "/latest")
            ret, out = utils_lib.run_cmd_local(cmd=f"cp -r {avocado_results_path} {target_res_dir}",
                                               is_log_ret=True)
            if ret != 0:
                error_list.append(f"cp -r {avocado_results_path} {target_res_dir} failed with {out}")

        if error_list:
            for i in error_list:
                self.log.error(i)
            raise Exception("Found error during run kar testsuite")

    def tearDown(self):
        utils_lib.finish_case(self)
