# OS-Tests Advanced Tips

os-tests is designed for catching more issue while keeping test simple, flexible and less manual effort in failure reproducing, debug information collection. This page gives some ideas with examples for different purposes in our work.

## Do not clean up self provisioned test system by passing "--no-cleanup"

```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p test_check_journalctl_fail --no-cleanup
```

## Control case run orders by passing "-p"

The cases are sorted by characters as default behavior. But it follows order specified by "-p".
Below example shows to run cloudinit tests after leap upgrade done.
```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p test_leapp_upgrade_rhui,cloudinit
```

## Run cases crossing two existing hosts.
```bash
$ os-tests --hosts 192.168.122.42,192.168.122.143 --user xxx --password xxx -p test_kdump_over_nfs,test_kdump_over_ssh
```

## Add extra steps to cases by passing "--case_setup"

This parameter makes the os-tests move to next stage to meet various scenarios. That means user can add many things as pre-conditions to the cases.
#### Example-1: run the same case with fips enabled
```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p ltp  --case_setup fips_enable
```

#### Example-2: run the same case with debug kernel and kmemleak enabled
```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p ltp  --case_setup debugkernel_enable
```

#### Example-3: run a script like enable nm-cloud-setup debug mode

Usually we run in normal mode to avoid too many details in test log, but it will be useful if we want to enable it in special case failure debugging.
It might be a good idea to provide method like fips_enable, fips_disable for generic usage. But we cannot cover all, so there is no limitation by allowing file or cmd string specification.
```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p test_second_ip_hotplug  --case_setup /usr/local/lib/python3.6/site-packages/os_tests/utils/debug_nm_cloud_setup.sh
```

#### Example-4: add a user with password to the current system

In many cloud systems, password login is disabled by default. If ssh is not working, you can add one user with password to allow login via console.
If no username or password specified, the [debug_enable_user_with_passwd.sh](https://github.com/virt-s1/os-tests/blob/master/os_tests/utils/debug_enable_user_with_passwd.sh) will auto generate them.

```bash
$ os-tests -p test_leapp_upgrade_rhui,test_cloudinit_mount_with_noexec_option --user ec2-user --keyfile /root/.ssh/id_rsa.pem --platform_profile ./aws.yaml --case_setup "/usr/local/lib/python3.6/site-packages/os_tests/utils/debug_enable_user_with_passwd.sh <$username $password>"
```

#### Example-5: run a command like enable NetworkManager trace debug mode

If you do not check journal log in one case, you can run this case with debug enabled and collect it in another case. This is also one of the case order control advantages. 
```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p test_network_device_hotplug,test_check_journalctl_fail  --case_setup 'sudo nmcli general logging level TRACE domains ALL'
```

Note: "--case_setup" supports multiple actions separating with ',', eg. "fips_enable,$cmd1,$cmd2,$bashfile". They will be executed one by one.
The default execution timeout is 600s, if it is not sufficient, please increase it by appending "timeout:xxx" to the string.

## Add extra post steps to cases by passing "--case_post"

Similar as "--case_setup", this allows user to append extra steps after the case done. We do recommend user to add the post steps to the case teardown if it is general. But we might want to run some temporary command like collect debug info after test.

#### Example-1: run the case with debug kernel and kmemleak enabled, and then collect memory leak
```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p ltp --case_setup debugkernel_enable --case_post collect_kmemleak
```

#### Example-2: run the case with debug enabled and collect its output
```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p test_network_device_hotplug  --case_setup 'sudo nmcli general logging level TRACE domains ALL' --case_post "journalctl -u NetworkManager"
```

## Generate Polarion log file by passing "--tc"

This allows user to generate additional Polarion specific log file sum_polarion.xml, which could be uploaded to Polarion as a test run. 
Note: The tc file is located in the os_tests/data/polarion_tc.json  
The command uploading sum_polarion.xml to Polarion: "curl -k -u <polarion_user>:<polarion_password> -X POST -F file=@/<path to sum_polarion.xml>/sum_polarion.xml https://polarion.engineering.redhat.com/polarion/import/xunit"

#### Example-1: run the case and generate additional Polarion log file
```bash
$ os-tests --user ec2-user --keyfile /home/xxx.pem --platform_profile /home/aws.yaml -p ltp --tc /home/os-tests/os_tests/data/polarion_tc.json
```