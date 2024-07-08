#!/bin/bash

rm -f /tmp/rpmdb /tmp/rpmdb.tmp /tmp/rogue /tmp/rogue.tmp
rpm -qal >/tmp/rpmdb
cat /tmp/rpmdb | xargs -I{} realpath {} >>/tmp/rpmdb.tmp 2>/dev/null
cat /tmp/rpmdb >>/tmp/rpmdb.tmp && sort -u /tmp/rpmdb.tmp >/tmp/rpmdb
find / ! -type d ! -path '/dev/*' ! -path '/proc/*' ! -path '/run/*' ! -path '/selinux/*' ! -path '/srv/*' ! -path '/sys/*' ! -path '/tmp/*' ! -path '/var/*' ! -path '/home/*' ! -path '/root/.bash_history' ! -path '/usr/share/mime/*' | grep -vxFf /tmp/rpmdb | sort >/tmp/rogue.tmp
rm -f /tmp/rogue
cat /tmp/rogue.tmp | while read -r line; do rpm -qf "$line" | sed -n '/is not owned by any package/s/file \(.*\) is not owned by any package/\1/p' >>/tmp/rogue; done
for line in $(rpm -q kernel | cut -d \- -f 2-); do
  grep -v "/usr/lib/modules/$line" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
  grep -v "/usr/lib/firmware/$line" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
  grep -v "/lib/modules/$line" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
  grep -v "/boot/initramfs-${line}kdump.img" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
  grep -v "/boot/initrd-${line}kdump.img" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
done
grep -v "/boot/initramfs-0-rescue-.*.img" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
grep -v "/boot/vmlinuz-0-rescue-.*" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
grep -v "/usr/lib/fontconfig/cache/.*.cache-7" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
grep -v "/etc/sysconfig/network-scripts/ifcfg-en.*" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
grep -v "/boot/grub2/[^/]*/.*mod" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
grep -v "/boot/grub2/[^/]*/.*lst" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
grep -v "/boot/grub2/[^/]*/.*elf" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
grep -v "/boot/loader/entries/.*.conf" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
grep -v "/etc/pki/ca-trust/extracted/pem/directory-hash/" /tmp/rogue >/tmp/rogue.tmp && mv /tmp/rogue.tmp /tmp/rogue
rm -f /tmp/rpmdb /tmp/rpmdb.tmp /tmp/rogue.tmp
