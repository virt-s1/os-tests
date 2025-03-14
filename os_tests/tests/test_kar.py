import unittest

from os_tests.libs import utils_lib

class TestKAR(unittest.TestCase):
    def setUp(self):
        if not self.params['kar_location']:
            raise Exception("No kar location assigned")

        utils_lib.init_case(self)

        cmd = ("dnf yum install -y qemu-* git vim gcc libvirt-* libguestfs-* "
               "virt-install python3-sphinx gdb* bpf* ksm* tcpdump "
               "rpmdevtools* python3-dev*")
        utils_lib.run_cmd_local(cmd)

    def prepare_files(self, kar_dir, kar_loc, images_dir, images_loc):
        s, _ = utils_lib.run_cmd_local(f"test -d {kar_dir}")
        if s != 0:
            s, _ = utils_lib.run_cmd_local(f"tar -jxvf {kar_loc} -C /home")
            if s != 0:
                raise Exception("Decompression kar.bz2 failed")

        s, _ = utils_lib.run_cmd_local(f"test -d {images_dir}")
        if s != 0:
            utils_lib.run_cmd_local(f"mkdir -p {images_dir}")
            if not images_loc:
                raise Exception("No images location")
            s, _ = utils_lib.run_cmd_local(f"tar -jxvf {images_loc} -C {images_dir}")
            if s != 0:
                raise Exception("Decompression images.bz2 failed")

    def test_kar_boot(self):
        kar_dir = "/home/kar"
        kar_loc = self.params['kar_location']
        images_dir = "/home/kvm_autotest_root"
        images_loc = self.params['kar_images_location']

        self.prepare_files(kar_dir, kar_loc, images_dir, images_loc)

        venv = kar_dir + "/workspace"

        s, _ = utils_lib.run_cmd_local(f"source {venv}/bin/activate && pip install netifaces")
        if s != 0:
            raise Exception("Installing netifaces fails")

        # TODO: parameterize guestname, testcase, isopool, clone, debug and etc.
        cmd = (f"source {venv}/bin/activate && "
               f"PYTHONPATH={venv}/avocado:{venv}/avocado-vt:{venv}/aexpect "
               f"python3 {kar_dir}/ConfigTest.py --guestname=RHEL.9.6..page_64k "
               "--testcase=boot "
               "--isopool=null:// --clone=no "
               "--debug")
        s, r = utils_lib.run_cmd_local(cmd)
        if s != 0:
            raise Exception(f"Run kar failed: {r}")

        # TODO: Collect results. avocado? os-tests? compression?

    def tearDown(self):
        utils_lib.finish_case(self)
