import unittest
import re
from os_tests.libs import utils_lib
import time
import os
import json
import tempfile
import string
from urllib.parse import urlparse
from datetime import datetime

class TestImageMode(unittest.TestCase):
    def setUp(self):
        utils_lib.init_case(self)
        self.dmesg_cursor = utils_lib.get_cmd_cursor(self, cmd='sudo dmesg -T')
        utils_lib.collect_basic_info(self)
        self.image_mode_dir = None
        self.bootc_base_image = None
        self.bootc_custom_image = None
        self.bootc_image_builder = None
        self.inspect_json_name = None
        self.manifest_file = None
        self.no_upload_image = self.params.get('no_upload_image')

    def _podman_login(self,io_user, io_pw, io_name):
        cmd = "sudo podman login -u='{}' -p='{}' {}".format(io_user, io_pw, io_name)
        utils_lib.run_cmd(self, cmd, is_log_cmd=False, expect_ret=0)

    def test_create_bootc_disk_image(self):
        """
        case_name:
            test_create_bootc_disk_image
        case_tags:
            image_mode
        case_status:
            approved
        title:
            TestImageMode.test_create_bootc_disk_image
        importance:
            critical
        subsystem_team:
            rhel-sst-virtualization-cloud
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
            component
        maintainer:
            linl@redhat.com
        description: |
            Build different formats disk images for testing RHEL in image mode.
        key_steps: |
            1. Pull base bootc image and build custom bootc container image with test packages installed.
            2. Convert the custom bootc container image to bootable disk image with reqired format for testing.
        expected_result: |
            The converted bootable disk image can be deployed and tested in corrosponding platforms.
        debug_want: |
            n/a
        """
        #product_id = utils_lib.get_product_id(self)
        #if float(product_id) < 9.4:
        #    self.fail("Image Mode was supported from rhel 9.4.")
        if self.params.get('subscription_username') and self.params.get('subscription_password'):
            utils_lib.rhsm_register(self, cancel_case=True)
        container_tools = ['podman', 'buildah', 'skopeo']
        for container_tool in container_tools:
            utils_lib.is_pkg_installed(self, pkg_name=container_tool, is_install=True, cancel_case=True)
        #prepare containerfile
        disk_image_format = self.params.get('disk_image_format')
        bootc_base_image_url = self.params.get('bootc_base_image_url')
        if not ':' in bootc_base_image_url:
            bootc_base_image_url = bootc_base_image_url + ":latest"
        arch = utils_lib.run_cmd(self, "uname -m | tr -d '\n'", expect_ret=0, msg="Check the architechure")
        containerfile = self.params.get('containerfile')
        current_time = datetime.now().strftime("%y%m%d%H%M%S")
        if containerfile and containerfile.startswith("http"):
            containerfile_url = urlparse(containerfile)
            containerfile_basename = os.path.basename(container_url.path)
            if ':' in containerfile_basename:
                containerfile_basename = containerfile_basename.replace(':', '_')
            if '.' in containerfile_basename:
                containerfile_basename = containerfile_basename.replace('.', 'u')
            image_mode_dir = "image_mode_" + containerfile_basename + "_{}_{}".format(disk_image_format, current_time)
            cmd = "sudo rm {} -rf && sudo mkdir {}".format(image_mode_dir, image_mode_dir)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="create image_mode_dir")
            utils_lib.is_pkg_installed(self, pkg_name='curl', is_install=True, cancel_case=True)
            cmd = "sudo curl -o {}/Containerfile {}".format(image_mode_dir, containerfile)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="download {}".format(containerfile))
        else:
            if containerfile and containerfile.startswith("/"):
                containerfile_basename = os.path.basename(containerfile)
                if ':' in containerfile_basename:
                    containerfile_basename = containerfile_basename.replace(':', '_')
                if '.' in containerfile_basename:
                    containerfile_basename = containerfile_basename.replace('.', 'u')
                image_mode_dir = "image_mode_" + containerfile_basename + "_{}_{}".format(disk_image_format, current_time)
                cmd = "sudo rm {} -rf && sudo mkdir {}".format(image_mode_dir, image_mode_dir)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg="create image_mode_dir")
                utils_lib.copy_file(self, local_file=containerfile, target_file_dir=image_mode_dir, target_file_name='Containerfile')
            if not containerfile:
                if not bootc_base_image_url:
                    self.skipTest("Please sepcify the base bootc container image url.")
                image_mode_dir_name = '{}-{}'.format(bootc_base_image_url.split('/')[1], bootc_base_image_url.split(':')[1].replace('.','u'))
                image_mode_dir = "image_mode_{}_{}_{}".format(image_mode_dir_name, disk_image_format, current_time)
                cmd = "sudo rm {} -rf && sudo mkdir {}".format(image_mode_dir, image_mode_dir)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg="create image_mode_dir")
                cmd = 'echo "#Containerfile" > {}/Containerfile'.format(image_mode_dir)
                utils_lib.run_cmd(self, "sudo bash -c '{}'".format(cmd), expect_ret=0, msg="create an empty Containerfile")
        self.image_mode_dir = image_mode_dir
        cmd = "sudo cat {}/Containerfile".format(image_mode_dir)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check Containerfile")
        if bootc_base_image_url:
            cmd = "cd {} && sudo grep -q '^FROM' Containerfile && \
sudo sed -i 's#^FROM.*#FROM {}#' Containerfile || \
sudo sed -i '1iFROM {}' Containerfile && sudo cat Containerfile".format(image_mode_dir, bootc_base_image_url, bootc_base_image_url)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Update the bootc base image repo to the test url")
        
        #Prepare repo file
        dnf_repo_url = self.params.get('dnf_repo_url')
        if dnf_repo_url:
            utils_lib.configure_repo(self, repo_type='dnf_repo', repo_url_param=dnf_repo_url)
            cmd = "cd {} && sudo sed -i '2iADD ./dnf.repo /etc/yum.repos.d/dnf.repo' Containerfile && sudo cat Containerfile".format(image_mode_dir)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Configure repo file in containerfile.")
            #if disk_image_format == 'iso':
                #utils_lib.rhsm_unregister(self, cancel_case=True)
                #self.log.info('unregister rhsm to aviod bug when creating iso disk, please register again after this case if you need.')
            cmd = "sudo mv /etc/yum.repos.d/dnf.repo ./{}/dnf.repo".format(image_mode_dir)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Create dnf.repo for packages installation in building custom image")

        #Configure CAs
        ca_info = self.params.get('ca_info')
        if ca_info:
            ca_url = ca_info.split(',')[0]
            ca_path = ca_info.split(',')[1]
            cmd = "curl -L -k {} -o {} && update-ca-trust".format(ca_url,ca_path)
            utils_lib.run_cmd(self, 
                            "cd {} && sudo sed -i '3iRUN {}' Containerfile && sudo cat Containerfile".format(image_mode_dir, cmd), 
                            expect_ret=0, 
                            msg="Add ca configure to containerfile.")

        #Configure install additional packages
        pkgs = self.params.get('pkgs')
        if pkgs:
            pkgs = pkgs.replace(",", " ")
            cmd = "cd {} && sudo sed -i '4iRUN dnf install -y {} && dnf clean all' Containerfile && sudo cat Containerfile".format(image_mode_dir, pkgs)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Add installed pkgs to Containerfile.")

        config_toml_file = self.params.get('config_toml_file')
        config_toml_info = self.params.get('config_toml_info')
        if config_toml_file:
            utils_lib.copy_file(self, local_file=config_toml_file, target_file_dir=image_mode_dir, target_file_name='config.toml')
        else:
            if not config_toml_info:
                self.skipTest("Please sepcify config.toml to add user for login.")
            #Create config.toml file, Note the key will display in case log if you specify it.
            utils_lib.run_cmd(self, """
sudo cat << EOF | sudo tee {}/config.toml
[[customizations.user]]
name = "{}"
password = "{}"
key = "{}"
groups = ["wheel"]
EOF
""".format(image_mode_dir, config_toml_info.split(',')[0], config_toml_info.split(',')[1], config_toml_info.split(',')[2].replace('\'','')),msg='create config_toml file')
            if config_toml_info.split(',')[0] == 'root':
                cmd = "sudo sed -i 's/wheel/root/g' {}/config.toml".format(image_mode_dir)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Add root user to root group.")
        cmd = 'sudo cat {}/config.toml'.format(image_mode_dir)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Check config.toml")
        cmd = 'sudo grep root {}/config.toml'.format(image_mode_dir)
        ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg="Check if there is root user in config.toml")
        if ret == 0:
            cmd = "RUN sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config"
            utils_lib.run_cmd(self, 
                            "cd {} && echo -e \"\\n{}\\n\" | sudo tee -a Containerfile && cat Containerfile".format(image_mode_dir, cmd), 
                            expect_ret=0, 
                            msg="Configure sshd_config for Root Login with password if there is root user in config.toml")
        
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
        
        cmd = "sudo grep ^FROM {}/Containerfile | awk '{{print $(2)}}'| tr -d '\n'".format(image_mode_dir)
        bootc_base_image = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Fetch bootc base image repo')
        self.bootc_base_image = bootc_base_image
        cmd = 'echo "bootc_base_image: {}" >> {}/bootc_disk_info'.format(bootc_base_image, image_mode_dir)
        utils_lib.run_cmd(self, 
                        "sudo bash -c '{}'".format(cmd), 
                        expect_ret=0, 
                        msg="Save bootc_base_image {} to bootc_disk_info".format(bootc_base_image))
        cmd = "sudo podman rmi {} -f".format(bootc_base_image)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="remove old bootc base image")
        cmd = "sudo podman pull {} --arch {}".format(bootc_base_image, arch)
        for i in range(1,10):
            ret = utils_lib.run_cmd(self, cmd, ret_status=True, timeout = 2400, msg="pull bootc base image")
            if ret == 0:
                break
            self.log.info("Failed to pull bootc base image, try again! Attempt %s/10" % i)
            if i < 10:
                time.sleep(10)
        else:
            self.skipTest("Skip test since cannot pull the bootc base image{} {}.".format(bootc_base_image, arch))
        cmd = "sudo podman images"
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Check all container images")
        cmd = "sudo podman inspect {} --format '{{{{.ID}}}}' | tr -d '\n'".format(bootc_base_image)
        bootc_base_image_id = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image ID")
        cmd = "sudo podman inspect {} --format '{{{{.Digest}}}}' | tr -d '\n'".format(bootc_base_image)
        bootc_base_image_digest = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image Digest")
        cmd = 'echo "bootc_base_image_digest: {}" >> {}/bootc_disk_info'.format(bootc_base_image_digest, image_mode_dir)
        utils_lib.run_cmd(self, "sudo bash -c '{}'".format(cmd), 
                        expect_ret=0, 
                        msg="Save bootc_base_image_digest {} to bootc_disk_info".format(bootc_base_image_digest))
        bootc_base_image_name = '{}_{}'.format(bootc_base_image.split('/')[1],bootc_base_image.split('/')[2].split(':')[0])
        if ':' in bootc_base_image:
            bootc_base_image_tag = bootc_base_image.split(':')[1].replace('.', 'u')
        else:
            bootc_base_image_tag = 'latest'
        inspect_json_name = "{}_{}_inspect.json".format(image_mode_dir, bootc_base_image_name, bootc_base_image_tag)
        cmd = "sudo bash -c 'podman inspect {} > {}/{}'".format(bootc_base_image, image_mode_dir, inspect_json_name)
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image info")
        self.inspect_json_name = inspect_json_name
        cmd = 'echo "inspect_json_name: {}" >> {}/bootc_disk_info'.format(inspect_json_name, image_mode_dir)
        utils_lib.run_cmd(self, 
                        "sudo bash -c '{}'".format(cmd), 
                        expect_ret=0, 
                        msg="Save inspect_json_name {} to bootc_disk_info".format(inspect_json_name))
        cmd = "sudo podman inspect {} --format '{{{{.Architecture}}}}' | tr -d '\n'".format(bootc_base_image)
        bootc_image_arch = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image Architecture")
        if bootc_image_arch == 'amd64':
            bootc_image_arch = 'x86_64'
        if bootc_image_arch == 'arm64':
            bootc_image_arch = 'aarch64'
        cmd = 'echo "arch: {}" >> {}/bootc_disk_info'.format(bootc_image_arch, image_mode_dir)
        utils_lib.run_cmd(self,
                        "sudo bash -c '{}'".format(cmd),
                        expect_ret=0,
                        msg="Save bootc_image_arch {} to bootc_disk_info".format(bootc_image_arch))
        cmd = "sudo jq -r .[].Config.Labels.\\\"redhat.compose-id\\\" {}/{} | tr -d '\n'".format(image_mode_dir, inspect_json_name)
        bootc_base_image_compose_id = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc base image compose-id")
        if bootc_base_image_compose_id:
            cmd = "cd {} && sudo sed -i 's|latest-RHEL-[^/]*|{}|g' ./dnf.repo && sudo cat ./dnf.repo".format(image_mode_dir, bootc_base_image_compose_id)
            utils_lib.run_cmd(self, 
                            cmd, 
                            expect_ret=0, 
                            msg="Set repo for installing packages with the corresponding compose id {}".format(bootc_base_image_compose_id))
        else:
            bootc_base_image_compose_id = 'other'
        cmd = 'echo "compose_id: {}" >> {}/bootc_disk_info'.format(bootc_base_image_compose_id, image_mode_dir)
        utils_lib.run_cmd(self, 
                        "sudo bash -c '{}'".format(cmd), 
                        expect_ret=0, 
                        msg="Save bootc_base_image_compose_id {} to bootc_disk_info".format(bootc_base_image_compose_id))
        bootc_custom_image_name = '{}_{}_{}_{}_{}'.format(bootc_base_image_name,
                                                       bootc_base_image_tag,
                                                       disk_image_format,
                                                       bootc_image_arch,
                                                       current_time)

        #Check if the bootc image is built
        built_digest = self.params.get('bootc_base_image_digest')
        if built_digest:
            built_digest = built_digest.replace('\n','')
            if ':' in built_digest:
                built_digest = built_digest.split(':')[1]
            if bootc_base_image_digest == built_digest or bootc_base_image_digest.split(':')[1] == built_digest or bootc_base_image_digest[-10:]== built_digest:
                self.skipTest("Custom bootc image based bootc image {} Digest:{} was already built. Skip this case."
                              .format(bootc_base_image_name, bootc_base_image_digest))
        bootc_custom_image_tag = bootc_base_image_digest[-10:]

        if quay_io_data:
            bootc_custom_image = "quay.io/{}/{}:{}".format(quay_io_data.split(',')[0], bootc_custom_image_name, bootc_custom_image_tag)
        else:
            bootc_custom_image = "localhost/{}:{}".format(bootc_custom_image_name, bootc_custom_image_tag)
        self.bootc_custom_image = bootc_custom_image
        cmd = 'echo "bootc_custom_image: {}" >> {}/bootc_disk_info'.format(bootc_custom_image, image_mode_dir)
        utils_lib.run_cmd(self,
                        "sudo bash -c '{}'".format(cmd),
                        expect_ret=0,
                        msg="Save bootc_custom_image name {} to bootc_disk_info".format(bootc_custom_image))
        cmd = "cd {} && sudo podman build -t {} . --arch {}".format(image_mode_dir, bootc_custom_image, arch)
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout = 2400, msg="Build bootc custom image")

        #Create bootable disks with custom bootc images
        image_name_string = image_mode_dir.split('_')
        if self.params.get('containerfile'):
            image_name_string = image_name_string[:-2]
        else:
            image_name_string = image_name_string[:-3]
        pre_image_name = '_'.join(image_name_string)
        bootc_image_builder = self.params.get('bootc_image_builder')
        if not bootc_image_builder:
            if 'rhel' in bootc_base_image:
                bootc_image_builder = bootc_base_image.replace('rhel-bootc','bootc-image-builder')
            else:
                cmd = "sudo jq -r .[].Config.Labels.\\\"bootc.diskimage-builder\\\" {}/{} | tr -d '\n'".format(image_mode_dir, inspect_json_name)
                bootc_image_builder = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="check bootc image builder")
                if not bootc_image_builder:
                    self.skipTest("Please sepcify the bootc_image_builder.")
        self.bootc_image_builder = bootc_image_builder
        cmd = 'echo "bootc_image_builder: {}" >> {}/bootc_disk_info'.format(bootc_image_builder, image_mode_dir)
        utils_lib.run_cmd(self,
                        "sudo bash -c '{}'".format(cmd),
                        expect_ret=0,
                        msg="Save bootc_image_builder name {} to bootc_disk_info".format(bootc_image_builder))

        if disk_image_format == 'ami':
            utils_lib.is_pkg_installed(self, pkg_name='awscli2', is_install=True, cancel_case=True)
            ami_name = '{}_{}_{}_{}'.format(pre_image_name, bootc_custom_image_name, bootc_custom_image_tag, bootc_base_image_compose_id)
            if len(ami_name) > 128:
                ami_name = 'image_mode_{}_{}_{}'.format(bootc_custom_image_name, bootc_custom_image_tag, bootc_base_image_compose_id)
            if len(ami_name) > 128:
                ami_name = 'image_mode_{}'.format(ami_name[-110:])
            aws_info = self.params.get('aws_info')
            if aws_info and aws_info.split(',')[2]:
                aws_region = aws_info.split(',')[2]
            if aws_info and aws_info.split(',')[3]:
                aws_bucket = aws_info.split(',')[3]
            else:
                aws_bucket = 'bootc-image-files'
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
                                         aws_region,
                                         aws_bucket,
                                         bootc_custom_image)
                run_output = utils_lib.run_cmd(self, cmd, timeout=3600, is_log_cmd=False, msg='Create ami for image mode testing based on {}'.format(bootc_base_image_compose_id))

            else:
                cmd = "sudo grep region ~/.aws/config | awk '{print $(3)}'| tr -d '\n'"
                aws_region = utils_lib.run_cmd(self, cmd, msg='Check aws region')
                if not aws_region:
                    self.fail('Please configure awscli')
                else:
                    cmd = "sudo podman run --rm -it --privileged --pull=newer -v ~/.aws:/root/.aws:ro \
--env AWS_PROFILE=default -v /var/lib/containers/storage:/var/lib/containers/storage {} --local --type ami \
--target-arch {} --aws-ami-name {} --aws-region {} --aws-bucket {} {}".format(
                                                                      bootc_image_builder,
                                                                      bootc_image_arch,
                                                                      ami_name,
                                                                      aws_region,
                                                                      aws_bucket,
                                                                      bootc_custom_image)
                    run_output = utils_lib.run_cmd(self, cmd, timeout=3600, msg='Create ami for image mode testing based on {}'.format(bootc_base_image_compose_id))
            cmd = "aws ec2 describe-images --filters 'Name=name,Values={}' --query 'Images[*].ImageId' --output text | tr -d '\n'".format(ami_name)
            ami_id = utils_lib.run_cmd(self, cmd, msg='check ami id')
            if not ami_id or not ami_id.startswith('ami'):
                # Try to search the ami id from above podman run output
                pattern = r'ami-[a-f0-9]{17}'
                match = re.search(pattern, run_output)
                if match:
                    ami_id = match.group(0)
                else:
                    self.fail('Failed to upload AMI')

            self.log.info("AMI name:{} ID:{} based on bootc image {} compose-id:{} Digest:{} is uploaded \
to AWS {}".format(ami_name, ami_id, bootc_base_image, bootc_base_image_compose_id, bootc_base_image_digest, aws_region))
            cmd = 'echo "artifacts: {} {}" >> {}/bootc_disk_info'.format(ami_name, ami_id, image_mode_dir)
            utils_lib.run_cmd(self,
                            "sudo bash -c '{}'".format(cmd),
                            expect_ret=0,
                            msg="Save AMI name and ID to bootc_disk_info artifacts")
        else:
            #Create directory for converted disk images
            compose_id = bootc_base_image_compose_id.split('-')[-1].replace('.', '')
            output_dir_name = 'output_{}_{}_{}'.format(bootc_custom_image_name.rsplit('_', 1)[0], compose_id, bootc_custom_image_tag)
            output_dir = "{}/{}".format(image_mode_dir, output_dir_name)
            cmd = "sudo rm {} -rf && sudo mkdir {}".format(output_dir, output_dir)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Create output directory")

            #Convert custom bootc container image to disk image
            disk_image_type = disk_image_format
            if disk_image_format in ['vhdx']:
                disk_image_type = 'qcow2'   
            cmd = "cd {} && sudo podman run --rm -it --privileged --pull=newer --security-opt \
label=type:unconfined_t -v ./config.toml:/config.toml -v ./{}:/output -v \
/var/lib/containers/storage:/var/lib/containers/storage {} --type {} --target-arch {} \
--config /config.toml --local {}".format(image_mode_dir, 
                                         output_dir_name, 
                                         bootc_image_builder, 
                                         disk_image_type, 
                                         bootc_image_arch, 
                                         bootc_custom_image)
            utils_lib.run_cmd(self,
                            cmd,
                            expect_ret=0,
                            timeout = 3600,
                            msg="Create container disk image {} for image mode testing based on {}".format(bootc_custom_image, bootc_base_image_compose_id))

            manifest_file = 'manifest{}'.format(output_dir_name.replace('output',''))
            self.manifest_file = manifest_file
            cmd = 'echo "manifest_file: {}" >> {}/bootc_disk_info'.format(manifest_file, image_mode_dir)
            utils_lib.run_cmd(self,
                            "sudo bash -c '{}'".format(cmd),
                            expect_ret=0,
                            msg="Save manifest_file name {} to bootc_disk_info".format(manifest_file))
            cmd = "sudo mv {}/manifest-{}.json {}/{}".format(output_dir, disk_image_type, image_mode_dir, manifest_file)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='move manifest-{}.json to {}'.format(disk_image_type, manifest_file))
            utils_lib.is_cmd_exist(self,"qemu-img")
            if disk_image_format == 'vhdx':
                cmd = "sudo qemu-img convert -O vhdx {}/qcow2/disk.qcow2 {}/qcow2/disk.vhdx".format(output_dir, output_dir)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg='convert qcow2 disk to vhdx disk')
            cmd = "sudo ls {}/{} | tr -d '\n'".format(image_mode_dir, output_dir_name)
            disk_dir = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check disk dir name')
            disk_file_format = disk_image_format
            if disk_image_format == 'gce':
                disk_file_format = 'tar.gz'
            cmd = "sudo ls {}/{} | grep {} | tr -d '\n'".format(output_dir, disk_dir, disk_file_format)
            disk_file_name = utils_lib.run_cmd(self, cmd, expect_ret=0, msg='check disk file name')
            disk_file = "{}_{}_{}".format(pre_image_name, output_dir_name.replace('output_',''), disk_file_name)
            cmd = "sudo mv {}/{}/{} {}/{}".format(output_dir, disk_dir, disk_file_name, image_mode_dir, disk_file)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='move disk from {}/{}/{} to {}/{}'.format(output_dir, disk_dir, disk_file_name, image_mode_dir, disk_file))
            cmd = 'echo "artifacts: {}" >> {}/bootc_disk_info'.format(disk_file, image_mode_dir)
            utils_lib.run_cmd(self,
                            "sudo bash -c '{}'".format(cmd),
                            expect_ret=0,
                            msg="Save disk_file name {} to bootc_disk_info artifacts".format(disk_file))
            #Save the created bootable bootc image/disk to attachments in log and delete the image_mode_dir.
            #Or if you'd like to copy the disk file to your test environment by manual,
            #please specify --no_upload_image in command or set "no_upload_image: True" in yaml.
            if self.no_upload_image:
                self.log.info("Please copy Disk image {}/{} based on bootc image {} \
compose-id:{} Digest:{} to your test environment.".format(image_mode_dir,
                                                        disk_file,
                                                        bootc_base_image,
                                                        bootc_base_image_compose_id,
                                                        bootc_base_image_digest))
            else:
                utils_lib.save_file(self, file_dir=image_mode_dir, file_name='{}'.format(disk_file))

    def tearDown(self):
        #Save files to log/attachments and delete workdir and container images
        if self.image_mode_dir:
            cmd = 'sudo ls {}/Containerfile'.format(self.image_mode_dir)
            ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg="Check if Containerfile exists")
            if ret == 0:
                utils_lib.save_file(self, file_dir=self.image_mode_dir, file_name="Containerfile")

            cmd = "cd {} && pwd".format(self.image_mode_dir)
            image_mode_dir_path = utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Check image_mode_dir path")
            cmd = 'ls {}/bootc_disk_info'.format(self.image_mode_dir)
            ret = utils_lib.run_cmd(self, cmd, ret_status=True, msg="Check if bootc_disk_info exists")
            if ret == 0:
                cmd = "sudo sed -i '1iimage_mode_dir_path: {}' {}/bootc_disk_info".format(image_mode_dir_path, self.image_mode_dir)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg="Save image_mode_dir_path {}".format(image_mode_dir_path))
            else:
                cmd = 'echo "image_mode_dir_path: {}" >> {}/bootc_disk_info'.format(image_mode_dir_path, self.image_mode_dir)
                utils_lib.run_cmd(self,
                                "sudo bash -c '{}'".format(cmd),
                                expect_ret=0,
                                msg="Save image_mode_dir_path {}".format(image_mode_dir_path))
            
            cmd = 'echo "case_result: done" >> {}/bootc_disk_info'.format(self.image_mode_dir)
            utils_lib.run_cmd(self,
                            "sudo bash -c '{}'".format(cmd),
                            expect_ret=0,
                            msg="Save case status TBD to bootc_disk_info")
            utils_lib.save_file(self, file_dir=self.image_mode_dir, file_name="bootc_disk_info")

        if self.inspect_json_name:
            utils_lib.save_file(self, file_dir=self.image_mode_dir, file_name=self.inspect_json_name)
        if self.manifest_file:
            utils_lib.save_file(self, file_dir=self.image_mode_dir, file_name=self.manifest_file)
        if self.no_upload_image:
            self.log.info("Keep image mode dir and container images.")
        else:
            #delete image mode dir and files in it
            if self.image_mode_dir:
                cmd = "sudo rm -rf {}".format(self.image_mode_dir)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg="delete the {}".format(self.image_mode_dir))
            #delete container images
            if self.bootc_base_image:
                cmd = "sudo podman rmi {} -f".format(self.bootc_base_image)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg='remove container image {}'.format(self.bootc_base_image))
            if self.bootc_custom_image:
                cmd = "sudo podman rmi {} -f".format(self.bootc_custom_image)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg='remove container image {}'.format(self.bootc_custom_image))
            if self.bootc_image_builder:
                cmd = "sudo podman rmi {} -f".format(self.bootc_image_builder)
                utils_lib.run_cmd(self, cmd, expect_ret=0, msg='remove container image {}'.format(self.bootc_image_builder))

        utils_lib.finish_case(self)
        pass

if __name__ == '__main__':
    unittest.main()
