#!/bin/bash

PROVIDER=$1

SYSTEMD_EDITOR=tee systemctl edit nm-cloud-setup.service <<EOF
[Service]
Environment=NM_CLOUD_SETUP_${PROVIDER}=yes
EOF

systemctl daemon-reload
systemctl restart nm-cloud-setup.timer
