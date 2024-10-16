import unittest
import re
from os_tests.libs import utils_lib
import time
import os
import json
import tempfile
import string

class TestImageMode(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='sudo dmesg -T')
        utils_lib.collect_basic_info(self)

    def _prepare_containerfile(self,containerfile,bootc_base_image_url,pkgs):
        if not containerfile:
            containerfile_temp = string.Template('''
From $bootc_base_image_url
ADD ./rhel.repo /etc/yum.repos.d/rhel.repo
RUN echo $pkgs
RUN dnf install -y $pkgs && dnf clean all 
            ''')
            fh, tmp_containerfile_file = tempfile.mkstemp(suffix='_containerfile',  dir='/tmp', text=False)
            with open(tmp_containerfile_file, 'a') as fh:
                containerfile_str = containerfile_temp.substitute(bootc_base_image_url=bootc_base_image_url, pkgs=pkgs)
                self.log.info("Add %s" % tmp_containerfile_file)
                fh.writelines(containerfile_str)
            self.log.info("Updated %s" % tmp_containerfile_file)
            with open(tmp_containerfile_file, 'r') as fh:
                for line in fh.readlines():
                    self.log.info(line)
            containerfile = tmp_containerfile_file
        self.SSH.put_file(local_file=containerfile, rmt_file='/tmp/containerfile')
        cmd = "sudo cp /tmp/containerfile ./Containerfile"
        utils_lib.run_cmd(self, cmd, msg='copy {}'.format(containerfile))
        '''
        Don't need to use if/else ?
        if self.params.get('remote_node') is not None:
            self.SSH.put_file(local_file=containerfile, rmt_file='/tmp/containerfile')
            cmd = "sudo cp /tmp/containerfile ./Containerfile"
            utils_lib.run_cmd(self, cmd, msg='copy {}'.format(containerfile))
        else:
            cmd = "sudo cp {} ./Containerfile".format(containerfile)
            utils_lib.run_cmd(self, cmd, msg='copy {}'.format(containerfile))
        '''
        tmp_containerfile_file = tmp_containerfile_file or '/tmp/containerfile'
        if os.path.exists(tmp_containerfile_file):
            os.unlink(tmp_containerfile_file)
            self.log.info("delete tempfile %s" % (tmp_containerfile_file))

    def _podman_login(self,io_user, io_pw, io_name):
        cmd = "sudo podman login -u='{}' -p='{}' {}".format(io_user, io_pw, io_name)
        utils_lib.run_cmd(self, cmd, is_log_cmd=False, expect_ret=0)

    def test_build_rhel_bootc_image(self):
        """
        case_name:
            test_build_rhel_bootc_image
        case_tags:
            image_mode
        case_status:
            approved
        title:
            TestImageMode.test_build_rhel_bootc_image
        importance:
            critical
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            automated
        linked_work_items:
            n/a
        automation_field:
            https://github.com/virt-s1/os-tests/tree/master/os_tests/tests/test_image_mode.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            system
        bug_id:
            n/a
        is_customer_case:
            False
        testplan:
            n/a
        test_type:
            functional
        test_level:
            Component
        maintainer:
            linl@redhat.com
        description: |
            Build different formats disk images for testing RHEL in image mode.
        key_steps: |
            1. Pull base rhel bootc image and build custom container image with test packages installed.
            2. Convert the custom container image to reqired format for testing.
        expected_result: |
            The converted image can be deployed and tested in corrosponding platforms.
        debug_want: |
            n/a
        """
        product_id = utils_lib.get_product_id(self)
        if float(product_id) < 9.4:
            self.fail("Image Mode was supported from rhel 9.4.")
        if self.params.get('subscription_username') and self.params.get('subscription_password'):
            utils_lib.rhsm_register(self, cancel_case=True)
        utils_lib.is_pkg_installed(self, pkg_name='container-tools', is_install=True, cancel_case=True)
        
        disk_image_format = self.params.get('disk_image_format')
        containerfile = self.params.get('containerfile')
        pkgs = self.params.get('pkgs')
        if pkgs:
            pkgs = pkgs.replace(",", " ")
        bootc_base_image_url = self.params.get('bootc_base_image_url')
        
        #prepare containerfile
        if not containerfile:
            if not bootc_base_image_url:
                self.skipTest("Please sepcify the base rhel bootc container image url.")
            if disk_image_format == 'ami':
                default_pkgs = "cloud-init"
            if disk_image_format == 'iso':
                default_pkgs = "cloud-init,hyperv-daemons"
                #default_bootc_image_configure = ""
            if disk_image_format == 'qcow2':
                default_pkgs = "cloud-init"
            if disk_image_format == 'vmdk':
                default_pkgs = "cloud-init,open-vm-tools"
            if disk_image_format == 'vhdx':
                default_pkgs = "hyperv-daemons"
            if disk_image_format == 'vhd':
                default_pkgs = "cloud-init,hyperv-daemons"
            if pkgs:
                pkgs = default_pkgs.replace(',',' ') + " " + pkgs
            else:
                pkgs = default_pkgs        
        self.log.info("print %s" % pkgs)
        self._prepare_containerfile(containerfile, bootc_base_image_url, pkgs)
        dnf_repo_url = self.params.get('dnf_repo_url')
        if dnf_repo_url:
            utils_lib.configure_repo(self, repo_type='dnf_repo', repo_url_param=dnf_repo_url)
        cmd = "sudo cp /etc/yum.repos.d/dnf.repo ./rhel.repo"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Create rhel.repo for packages installation in building custom image")
        
        #login container repo
        quay_io_data = self.params.get('quay_io_data')
        bootc_io_data = self.params.get('bootc_io_data')
        for io_data in [quay_io_data, bootc_io_data]:
            if io_data is not None:
                io_user = io_data.split(',')[0]
                io_pw = io_data.split(',')[1]
                io_name = io_data.split(',')[2]
                self.log.info('Login {}'.format(io_name))
                self._podman_login(io_user, io_pw, io_name)

        cmd = "sudo grep ^From Containerfile | awk '{print $(2)}'| tr -d '\n'"
        bootc_base_image = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Fetch bootc base image repo')
        cmd = "sudo podman rmi {} -f".format(bootc_base_image)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="remove old bootc base image")
        cmd = "sudo podman pull {}".format(bootc_base_image)
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout = 1200, msg="pull bootc base image")
        cmd = "sudo podman images"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Check all container images")
        cmd = "sudo podman inspect {} --format '{{{{.ID}}}}' | tr -d '\n'".format(bootc_base_image)
        bootc_base_image_id = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image ID")
        cmd = "sudo podman inspect {} --format '{{{{.Digest}}}}' | tr -d '\n'".format(bootc_base_image)
        bootc_base_image_digest = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image Digest")
        bootc_base_image_digest = bootc_base_image_digest.split(':')[1]
        bootc_base_image_name = bootc_base_image.split('/')[2].split(':')[0]
        bootc_base_image_tag = bootc_base_image.split(':')[1].replace('.','u')
        inspect_json_name = "{}_{}_inspect.json".format(bootc_base_image_name, bootc_base_image_tag)
        cmd = "sudo podman inspect {} > {}".format(bootc_base_image, inspect_json_name)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image info")
        cmd = "sudo podman inspect {} --format '{{{{.Architecture}}}}' | tr -d '\n'".format(bootc_base_image)
        bootc_image_arch = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image Architecture")
        if bootc_image_arch == 'amd64':
            bootc_image_arch = 'x86_64'
        cmd = "sudo jq -r .[].Config.Labels.\\\"redhat.compose-id\\\" {} | tr -d '\n'".format(inspect_json_name)
        bootc_base_image_compose_id = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image compose-id")
        bootc_custom_image_name = '{}_{}_{}_{}'.format(bootc_base_image_name,
                                                       bootc_base_image_tag,
                                                       disk_image_format,
                                                       bootc_image_arch)

        if bootc_base_image_digest == self.params.get('bootc_base_image_digest'):
            self.skipTest("Custom bootc image based bootc image {} Digest:{} was already built. Skip this case."
            .format(bootc_base_image_name, bootc_base_image_digest))
        if quay_io_data:
            bootc_custom_image = "quay.io/{}/{}:{}".format(quay_io_data.split(',')[0], bootc_custom_image_name, bootc_custom_image_tag)
        else:
            bootc_custom_image = "localhost/{}:{}".format(bootc_custom_image_name, bootc_custom_image_tag)
        cmd = "sudo podman build -t {} .".format(bootc_custom_image)
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout = 1200, msg="Build bootc custom image")
        
        #Create bootable disks with custom bootc images
        bootc_image_builder = self.params.get('bootc_image_builder') or bootc_base_image.replace('rhel-bootc','bootc-image-builder')

        if disk_image_format == 'ami':
            utils_lib.is_pkg_installed(self, pkg_name='awscli2', is_install=True, cancel_case=True)
            ami_name = '{}_{}_{}'.format(bootc_custom_image_name, bootc_custom_image_tag, bootc_base_image_compose_id)
            aws_info = self.params.get('aws_info')
            if aws_info and aws_info.split(',')[3]:
                aws_bucket = aws_info.split(',')[3]
            else:
                aws_bucket = 'rh-image-files'
            if aws_info and aws_info.split(',')[0] and aws_info.split(',')[1]:
                cmd = "sudo podman run --rm -it --privileged --pull=newer --tls-verify=false \
--security-opt label=type:unconfined_t -v /var/lib/containers/storage:/var/lib/containers/storage \
--env AWS_ACCESS_KEY_ID={} --env AWS_SECRET_ACCESS_KEY={} {} --type ami --target-arch {} --local --aws-ami-name {} \
--aws-region {} --aws-bucket {} {}".format(
                                         aws_info.split(',')[0], 
                                         aws_info.split(',')[1], 
                                         bootc_image_builder,
                                         bootc_image_arch,
                                         ami_name,
                                         aws-bucket,
                                         aws_info.split(',')[2],
                                         bootc_custom_image)
                utils_lib.run_cmd(self, cmd, timeout=3600, is_log_cmd=False, msg='Create ami for image mode testing based on {}'.format(bootc_base_image_compose_id))

            else:
                cmd = "sudo grep region .aws/config | awk '{print $(3)}'| tr -d '\n'"
                aws_region = utils_lib.run_cmd(self, cmd, msg='Check aws region')
                if not aws_region:
                    FailTest('Please configure awscli')
                else:
                    cmd = "sudo podman run --rm -it --privileged --pull=newer -v /root/.aws:/root/.aws:ro \
--env AWS_PROFILE=default -v /var/lib/containers/storage:/var/lib/containers/storage {} --local --type ami \
--target-arch {} --aws-ami-name {} --aws-region {} --aws-bucket {} {}".format(
                                                                      bootc_image_builder,
                                                                      bootc_image_arch,
                                                                      ami_name,
                                                                      aws_region,
                                                                      aws_bucket,
                                                                      bootc_custom_image)
                    utils_lib.run_cmd(self, cmd, timeout=3600, msg='Create ami for image mode testing based on {}'.format(bootc_base_image_compose_id))
            cmd = "aws ec2 describe-images --filters 'Name=name,Values={}' --query 'Images[*].ImageId' --output text | tr -d '\n'".format(ami_name)
            ami_id = utils_lib.run_cmd(self, cmd, msg='check ami id')
            if ami_id:
                self.log.info("AMI name:{} ID:{} based on bootc image {} compose-id:{} Digest:{} is uploaded \
to AWS {}".format(ami_name, ami_id, bootc_base_image, bootc_base_image_compose_id, bootc_base_image_digest, aws_region))
            else:
                FailTest('Failed to upload AMI')
        else:
            config_toml_file = self.params.get('config_toml_file')
            config_toml_info = self.params.get('config_toml_info')
            if config_toml_file:
                tmp_config_toml = '/tmp/config_toml'
                self.SSH.put_file(local_file=config_toml_file, rmt_file=tmp_config_toml)
                cmd = "sudo cp {} ./config.toml".format(tmp_config_toml)
                utils_lib.run_cmd(self, cmd, msg='copy {}'.format(config_toml_file))
                if os.path.exists(tmp_config_toml):
                    os.unlink(tmp_config_toml)
                    self.log.info("delete temp config.toml file")
            elif config_toml_info:
                #Note the key will display in the disk convert log if you specify it.
                utils_lib.run_cmd(self, """
sudo cat << EOF | sudo tee ./config.toml
[[customizations.user]]
name = "{}"
password = "{}"
key = "ssh-rsa {}"
groups = ["wheel"]
EOF
""".format(config_toml_info.split(',')[0], config_toml_info.split(',')[1], config_toml_info.split(',')[2]),
                                is_log_cmd=False,
                                msg='create config_toml file')
 
            #Create directory for converted disk images
            output_dir = 'output_{}_{}'.format(bootc_custom_image_name, bootc_custom_image_tag)   
            cmd = "sudo rm {} -rf && sudo mkdir {}".format(output_dir, output_dir)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Create output directory")

            #Convert custom bootc container image to disk image
            disk_image_type = disk_image_format
            if disk_image_format in ['vhdx', 'vhd']:
                disk_image_type = 'qcow2'   
            cmd = "sudo podman run --rm -it --privileged --pull=newer --security-opt \
label=type:unconfined_t -v ./config.toml:/config.toml -v ./{}:/output -v \
/var/lib/containers/storage:/var/lib/containers/storage {} --type {} --target-arch {} \
--config /config.toml --local {}".format(output_dir, bootc_image_builder, disk_image_type, bootc_image_arch, bootc_custom_image)
            utils_lib.run_cmd(self,
                            cmd,
                            expect_ret=0,
                            timeout = 3600,
                            msg="Create container disk image {} for image mode testing based on {}".format(bootc_custom_image, bootc_base_image_compose_id))

            manifest_file = 'manifest{}'.format(output_dir.replace('output',''))
            cmd = "sudo mv {}/manifest-{}.json {}".format(output_dir, disk_image_type, manifest_file)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='move manifest-{}.json to {}'.format(disk_image_type, manifest_file))
        #qcow2_disk = 'disk.qcow2'.format(output_dir.replace('output',''), disk_image_type)
        #qcow2_disk = 'disk.qcow2'
        #iso_disk = 'install.iso'
            utils_lib.is_cmd_exist(self,"qemu-img")
            if disk_image_format == 'vhdx':
                cmd = "sudo qemu-img convert -O vhdx {}/qcow2/disk.qcow2 {}/qcow2/disk.vhdx".format(output_dir, output_dir)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg='convert qcow2 disk to vhdx disk')
            if disk_image_format == 'vhd':
                cmd = "sudo qemu-img convert -f qcow2 -o subformat=fixed,force_size -O vpc {}/qcow2/disk.qcow2 {}/qcow2/disk.vhd".format(output_dir, output_dir)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg='convert qcow2 disk to vhd disk')
            disk_dir = disk_image_type
            disk_file = 'disk.{}'.format(disk_image_format)
            if disk_image_type == 'iso':
                disk_file = 'install.iso'
                disk_dir = 'bootiso'
            cmd = "sudo mv {}/{}/{} {}.{}".format(output_dir, disk_dir, disk_file, output_dir.replace('output_',''), disk_file.split('.')[1])
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='move {} to workdir'.format(disk_file))
            #uploade the output to attachment
            workdir = utils_lib.run_cmd(self, "sudo pwd | tr -d '\n'", expect_ret=0)
            utils_lib.save_file(self, file_dir=workdir, file_name=inspect_json_name)
            utils_lib.save_file(self, file_dir=workdir, file_name=manifest_file)
            #Copy the disk file to your test environment by manual,
            #Or comment out below line to save it to attachments in log.
            utils_lib.save_file(self, file_dir=workdir, file_name='{}.{}'.format(output_dir.replace('output_',''), disk_image_format))

            self.log.info("Please copy Disk image ./{}.{} based on bootc image {} \
compose-id:{} Digest:{} to your test environment.".format(
                                                        output_dir.replace('output_',''), 
                                                        disk_image_format,
                                                        bootc_base_image,
                                                        bootc_base_image_compose_id,
                                                        bootc_base_image_digest))
        #delete container images
        for image in [bootc_base_image, bootc_custom_image, bootc_image_builder]:
            cmd = "sudo podman rmi {} -f".format(image)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='remove container image {}'.format(image))
        
    def tearDown(self):
        utils_lib.finish_case(self)
        pass

if __name__ == '__main__':
    unittest.main()
