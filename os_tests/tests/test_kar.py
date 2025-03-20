import unittest

from os_tests.libs import utils_lib


class TestKAR(unittest.TestCase):
    run_mappings = {
        "boot": [
            "--guestname=RHEL.9.6..page_64k",
            "--testcase=boot",
            "--isopool=null://",
            "--clone=no",
            "--debug"
        ],
    }

    def setUp(self):
        utils_lib.init_case(self)

    def prepare_environment(self, kar_dir, images_dir):
        kar_loc = self.params['kar_location']
        images_loc = self.params['kar_images_location']

        if not kar_loc and not images_loc:
            raise Exception("No kar or images location assigned")

        # TODO: no yum in RHEL 10, thus, should the case need yum support?
        # TODO: Not sure 600 is enough for some slow installation
        cmd = ("dnf install -y bzip2 qemu-* git vim gcc libvirt-* libguestfs-* "
               "virt-install python3-sphinx gdb* bpf* ksm* tcpdump "
               "rpmdevtools* python3-devel")
        ret, out = utils_lib.run_cmd_local(cmd, timeout=600, is_log_ret=True)
        if ret != 0:
            raise Exception(f"Install packages failed - {out}")

        cmd = ("systemctl enable --now virtqemud.socket && "
               "systemctl enable --now virtnetworkd.socket && "
               "systemctl enable --now virtstoraged.socket && "
               "systemctl enable --now virtinterfaced.socket && "
               "systemctl enable --now virtnodedevd.socket")
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
                                               is_log_ret=True)
            if ret != 0:
                raise Exception(f"Decompression images.bz2 failed - {out}")

    def test_kar_boot(self):
        kar_dir = "/home/kar"
        images_dir = "/home/kvm_autotest_root"

        self.prepare_environment(kar_dir, images_dir)

        venv = kar_dir + "/workspace"

        # TODO: Not sure 600 is enough for some slow installation
        ret, out = utils_lib.run_cmd_local(cmd=f"source {venv}/bin/activate && pip install netifaces 'jinja2'",
                                           timeout=600,
                                           is_log_ret=True)
        if ret != 0:
            raise Exception(f"Installing venv dependencies fails - {out}")

        cmd_prefix = (
            f"source {venv}/bin/activate && "
            f"PYTHONPATH={venv}/avocado:{venv}/avocado-vt:{venv}/aexpect "
            f"python3 {kar_dir}/ConfigTest.py "
        )
        error_handle = []

        for k, v in self.run_mappings.items():
            cmd = cmd_prefix + " ".join(v)

            # TODO: confirm that the duration for cases running, or they may fail with timeout error
            ret, out = utils_lib.run_cmd_local(cmd=cmd,
                                               timeout=600,
                                               is_log_ret=True)
            if ret != 0:
                error_handle.append(k)

        if error_handle:
            for i in error_handle:
                self.log.error(f"kar test suite {i} failed")
            raise Exception("Run kar suite failed")
        # TODO: Collect results. avocado? os-tests? compression?
        # os-tests: --result
        # avocado: is there a parameter?

    def tearDown(self):
        utils_lib.finish_case(self)
