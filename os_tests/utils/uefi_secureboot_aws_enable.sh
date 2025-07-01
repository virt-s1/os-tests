# https://www.redhat.com/en/blog/red-hat-enterprise-linux-and-secure-boot-cloud
# the script enable secure boot a living system in AWS instances
set -x
PKGS="python3 openssl efivar keyutils awscli2 python3-virt-firmware"
MSFTCRT="MicCorUEFCA2011_2011-06-27.crt"
DBXFILE="DBXUpdate-20250507.x64.bin"
if [[ ! -d /sys/firmware/efi/ ]]; then
    echo "Not uefi booted, exit!"
    exit 0
fi
sudo mokutil --dbx
sudo mokutil --db
out = $(sudo mokutil --sb-state 2>&1)
if ![ $out ~ 'Platform is in Setup Mode' ]; then
    echo "Not in setup mode, exit!"
    exit 0
fi

if ! [ -f $MSFTCRT ]; then
    echo "please download $MSFTCRT into current directory from https://go.microsoft.com/fwlink/p/?linkid=321194"
    exit 0
fi
if ! [ -f $DBXFILE ]; then
    echo "please download $DBXFILE into current directory from https://github.com/fwupd/dbx-firmware.git"
    exit 0
fi
sudo dnf install -y $PKGS
uuidgen --random > GUID.txt
openssl req -quiet -newkey rsa:3072 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj "/CN=Platform key/" -outform DER -out PK.cer
virt-fw-sigdb --add-cert "$(< GUID.txt)" PK.cer -o PK.esl
openssl req -quiet -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj "/CN=Key Exchange Key/" -outform DER -out KEK.cer
virt-fw-sigdb --add-cert "$(< GUID.txt)" KEK.cer -o KEK.esl
openssl req -quiet -newkey rsa:4096 -nodes -keyout custom_db.key -new -x509 -sha256 -days 3650 -subj "/CN=Signature Database key/" --outform DER -out custom_db.cer
virt-fw-sigdb --add-cert "$(< GUID.txt)" custom_db.cer -o custom_db.esl
virt-fw-sigdb --add-cert 77fa9abd-0359-4d32-bd60-28f4e78f784b $MSFTCRT -o ms_db.esl
cat custom_db.esl ms_db.esl > db.esl
sudo efivar -w -n 8be4df61-93ca-11d2-aa0d-00e098032b8c-PK -f PK.esl
sudo efivar -w -n 8be4df61-93ca-11d2-aa0d-00e098032b8c-KEK -f KEK.esl
sudo efivar -w -n d719b2cb-3d3a-4596-a3bc-dad00e67656f-db -f db.esl
sudo efivar -w -n d719b2cb-3d3a-4596-a3bc-dad00e67656f-dbx -f $DBXFILE
sudo mokutil --dbx
sudo mokutil --db
sudo mokutil --sb-state
echo "please reboot when all went well!"
