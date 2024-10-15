import os
import subprocess
from pathlib import Path

# Remove temporary files
tmp_files = ['/tmp/rpmdb', '/tmp/rpmdb.tmp', '/tmp/rogue', '/tmp/rogue.tmp']
for tmp_file in tmp_files:
    try:
        os.remove(tmp_file)
    except FileNotFoundError:
        pass

# Generate the list of files installed by RPM and resolve their real paths
with open('/tmp/rpmdb', 'w') as rpmdb_file:
    subprocess.run(['rpm', '-qal'], stdout=rpmdb_file)

with open('/tmp/rpmdb.tmp', 'w') as rpmdb_tmp_file, open('/tmp/rpmdb', 'r') as rpmdb_file:
    for line in rpmdb_file:
        try:
            real_path = Path(line.strip()).resolve()
            rpmdb_tmp_file.write(f"{real_path}\n")
        except Exception:
            pass  # Ignore any exceptions, similar to `2>/dev/null` in the original script

# Sort the RPM DB file and remove duplicates
subprocess.run(['sort', '-u', '/tmp/rpmdb.tmp', '-o', '/tmp/rpmdb'])

# Find files not controlled by RPM (the rogue files)
excluded_paths = [
    '/dev/*', '/proc/*', '/run/*', '/selinux/*', '/srv/*', '/sys/*',
    '/tmp/*', '/var/*', '/home/*', '/root/.bash_history', '/usr/share/mime/*'
]
find_command = ['find', '/', '!', '-type', 'd'] + [item for path in excluded_paths for item in ['! -path', path]]
result = subprocess.run(find_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Write rogue files to rogue.tmp
with open('/tmp/rogue.tmp', 'w') as rogue_tmp_file:
    rogue_tmp_file.write(result.stdout)

# Remove the old rogue file
try:
    os.remove('/tmp/rogue')
except FileNotFoundError:
    pass

# Check which files are not owned by any RPM package
with open('/tmp/rogue.tmp', 'r') as rogue_tmp_file, open('/tmp/rogue', 'w') as rogue_file:
    for line in rogue_tmp_file:
        line = line.strip()
        result = subprocess.run(['rpm', '-qf', line], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if 'is not owned by any package' in result.stdout:
            rogue_file.write(f"{line}\n")

# Perform the kernel filtering based on current kernel versions
kernel_versions = subprocess.run(['rpm', '-q', 'kernel'], stdout=subprocess.PIPE, text=True).stdout.splitlines()
for kernel in kernel_versions:
    kernel_version = '-'.join(kernel.split('-')[1:])  # Extract kernel version
    filter_paths = [
        f'/usr/lib/modules/{kernel_version}',
        f'/usr/lib/firmware/{kernel_version}',
        f'/lib/modules/{kernel_version}',
        f'/boot/initramfs-{kernel_version}kdump.img',
        f'/boot/initrd-{kernel_version}kdump.img'
    ]
    for path in filter_paths:
        subprocess.run(['grep', '-v', path, '/tmp/rogue'], stdout=open('/tmp/rogue.tmp', 'w'))
        os.replace('/tmp/rogue.tmp', '/tmp/rogue')

# Additional filters
filter_patterns = [
    "/boot/initramfs-0-rescue-.*.img",
    "/boot/vmlinuz-0-rescue-.*",
    "/usr/lib/fontconfig/cache/.*.cache-7",
    "/etc/sysconfig/network-scripts/ifcfg-en.*",
    "/boot/grub2/[^/]*/.*mod",
    "/boot/grub2/[^/]*/.*lst",
    "/boot/grub2/[^/]*/.*elf",
    "/boot/loader/entries/.*.conf",
    "/etc/pki/ca-trust/extracted/pem/directory-hash/",
    "/etc/NetworkManager/system-connections/cloud-init-.*.nmconnection"
]

for pattern in filter_patterns:
    subprocess.run(['grep', '-v', '-E', pattern, '/tmp/rogue'], stdout=open('/tmp/rogue.tmp', 'w'))
    os.replace('/tmp/rogue.tmp', '/tmp/rogue')

# Clean up temporary files
for tmp_file in ['/tmp/rpmdb', '/tmp/rpmdb.tmp', '/tmp/rogue.tmp']:
    try:
        os.remove(tmp_file)
    except FileNotFoundError:
        pass
