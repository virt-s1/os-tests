import configparser
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

        cmd = ("sudo dnf install -q -y bzip2 qemu-* git vim gcc libvirt-* "
               "libguestfs-* virt-install gdb* bpf* ksm* "
               "tcpdump rpmdevtools* python3-devel")
        ret, out = utils_lib.run_cmd(self,
                                     cmd,
                                     timeout=600,
                                     is_log_cmd=True,
                                     ret_out=True,
                                     ret_status=True)
        if ret != 0:
            raise Exception(f"Install packages failed - {out}")

        cmd = ("sudo su -c \""
               "systemctl start --now virtqemud && "
               "systemctl start --now virtnetworkd && "
               "systemctl start --now virtstoraged && "
               "systemctl start --now virtinterfaced && "
               "systemctl start --now virtnodedevd\"")
        ret, out = utils_lib.run_cmd(self,
                                     cmd,
                                     is_log_cmd=True,
                                     ret_out=True,
                                     ret_status=True)
        if ret != 0:
            raise Exception(f"Enable virtualization failed - {out}")

        ret, _ = utils_lib.run_cmd(self,
                                   f"test -d {kar_dir}",
                                   is_log_cmd=True,
                                   ret_out=True,
                                   ret_status=True)
        if ret != 0:
            ret, out = utils_lib.run_cmd(self,
                                         f"sudo tar -jxf {kar_loc} -C /home",
                                         timeout=600,
                                         is_log_cmd=True,
                                         ret_out=True,
                                         ret_status=True)
            if ret != 0:
                raise Exception(f"Decompression kar.bz2 failed - {out}")

        ret, _ = utils_lib.run_cmd(self,
                                   f"test -d {images_dir}",
                                   is_log_cmd=True,
                                   ret_out=True,
                                   ret_status=True)
        if ret != 0:
            ret, out = utils_lib.run_cmd(self,
                                         f"sudo mkdir -p {images_dir}",
                                         is_log_cmd=True,
                                         ret_out=True,
                                         ret_status=True)
            if ret != 0:
                raise Exception(f"Create images directory failed - {out}")

            ret, out = utils_lib.run_cmd(self,
                                         f"sudo tar -jxf {images_loc} -C {images_dir}",
                                         is_log_cmd=True,
                                         timeout=1200,
                                         ret_out=True,
                                         ret_status=True)
            if ret != 0:
                raise Exception(f"Decompression images.bz2 failed - {out}")

    def test_kar_run(self):
        kar_dir = "/home/kar"
        images_dir = "/home/kvm_autotest_root"
        self.prepare_environment(kar_dir, images_dir)

        venv = kar_dir + "/workspace"
        # Set timeout to 600 for avoiding some timeout error
        ret, out = utils_lib.run_cmd(self,
                                     cmd=f"sudo su -c \"source {venv}/bin/activate && pip install netifaces 'jinja2' Pillow transitions\"",
                                     timeout=600,
                                     is_log_cmd=True,
                                     ret_out=True,
                                     ret_status=True)
        if ret != 0:
            raise Exception(f"Installing venv dependencies fails - {out}")

        cmd_prefix = (
            "sudo su -c \""
            f"source {venv}/bin/activate && "
            f"PYTHONPATH={venv}/avocado:{venv}/avocado-vt:{venv}/aexpect "
            f"python3 {kar_dir}/ConfigTest.py "
        )
        error_list = []
        # Read the avocado config for the log dir
        # Then put them into os-tests resutls dir
        kar_config = configparser.ConfigParser()
        ret, out = utils_lib.run_cmd(self,
                                     f"sudo cat {self.params.get("kar_avocado_conf")}",
                                     is_log_cmd=True,
                                     ret_out=True,
                                     ret_status=True)
        if ret != 0:
            raise Exception(f"Read avocado configuration failed with {out}")
        kar_config.read_string(out)

        for k, v in self.params.get("kar_tests").items():
            cmd = cmd_prefix + v + "\""

            # Each testsuite should be finished in 12 hours
            ret, out = utils_lib.run_cmd(self,
                                         cmd=cmd,
                                         timeout=12 * 60 * 60,
                                         is_log_cmd=True,
                                         ret_out=True,
                                         ret_status=True)
            if ret != 0:
                error_list.append(f"Run testsuite {k} failed with {out}")

            # The results is stored locally
            target_res_dir = self.params['results_dir'] + "/" + k
            ret, out = utils_lib.run_cmd_local(cmd=f"mkdir -p {target_res_dir}",
                                               is_log_ret=True)
            if ret != 0:
                error_list.append(f"Create target results directory failed with {out}")

            ret, out = utils_lib.run_cmd(self,
                                         f"sudo realpath {kar_config['datadir.paths']['logs_dir'] + '/latest'}",
                                         is_log_cmd=True,
                                         ret_out=True,
                                         ret_status=True)
            if ret != 0:
                error_list.append(f"Get realpath from {kar_config['datadir.paths']['logs_dir'] + '/latest'} failed with {out}")

            # The log maybe too large, compress them
            ret, out = utils_lib.run_cmd(self,
                                         f"sudo tar -czf /tmp/kar_avocado_{k}.tar.gz {out.strip()}",
                                         is_log_cmd=True,
                                         ret_out=True,
                                         ret_status=True)
            if ret != 0:
                error_list.append(f"compress the log failed with {out}")

            cmd = "scp -q "
            if self.is_rmt:
                cmd += f"-i {self.params['remote_keyfile']} -o StrictHostKeyChecking=no {self.params['remote_user']}@{self.params['remote_nodes'][0]}:"
            cmd += f"/tmp/kar_avocado_{k}.tar.gz {target_res_dir}"
            # subprocess.run will raise timeout exception, catch it and put it into the error list
            try:
                ret, out = utils_lib.run_cmd_local(cmd=cmd,
                                                   is_log_ret=True,
                                                   timeout=1200)
                if ret != 0:
                    error_list.append(f"{cmd} failed with {out}")
            except Exception as e:
                error_list.append(f"{cmd} failed with " + repr(e))

        if error_list:
            self.log.error("*" * 20 + "start to print the error list" + "*" * 20)
            for i in error_list:
                # Separator for error outputs
                self.log.error(i)
                self.log.error("-" * 20)
            self.log.error("*" * 20 + "end to print the error list" + "*" * 20)
            raise Exception("Found errors during run kar testsuite")

    def tearDown(self):
        utils_lib.finish_case(self)
