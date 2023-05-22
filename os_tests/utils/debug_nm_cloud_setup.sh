# enable nm-cloud-setup
# example of called by os-tests: --case_setup "/tmp/debug_nm_cloud_setup.sh"
set -x
debug_file="/usr/lib/systemd/system/nm-cloud-setup.service.d/10-enable-debug-trace.conf"
if [ -s $debug_file ]; then
    echo "${debug_file} exists, exit"
    exit 0
fi
cat <<EOF > /usr/lib/systemd/system/nm-cloud-setup.service.d/10-enable-debug-trace.conf
[Service]
Environment=NM_CLOUD_SETUP_LOG=TRACE
EOF
systemctl daemon-reload
systemctl restart nm-cloud-setup