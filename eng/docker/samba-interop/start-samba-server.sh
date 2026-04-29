#!/bin/bash
set -eu

username="${SAMBA_USERNAME:-alice}"
password="${SAMBA_PASSWORD:-Password123!}"
share_name="${SAMBA_SHARE_NAME:-share}"
share_path="${SAMBA_SHARE_PATH:-/share}"
workgroup="${SAMBA_WORKGROUP:-WORKGROUP}"

mkdir -p /run/samba "${share_path}"

if ! id -u "${username}" >/dev/null 2>&1; then
    useradd -M -s /usr/sbin/nologin "${username}"
fi

chown -R "${username}:${username}" "${share_path}"

(echo "${password}"; echo "${password}") | smbpasswd -a -s "${username}" >/dev/null

cat > /etc/samba/smb.conf <<EOF
[global]
    workgroup = ${workgroup}
    server string = OpenCifsInteropSamba
    security = user
    map to guest = Never
    ntlm auth = ntlmv2-only
    server min protocol = SMB2_02
    server max protocol = SMB3
    server signing = mandatory
    smb ports = 445
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes
    log file = /var/log/samba/log.%m
    max log size = 1000
    deadtime = 15

[${share_name}]
    path = ${share_path}
    browseable = yes
    read only = no
    guest ok = no
    valid users = ${username}
    force user = ${username}
    create mask = 0666
    directory mask = 0777
    locking = yes
    strict locking = yes
EOF

testparm -s /etc/samba/smb.conf >/dev/null

exec smbd --foreground --no-process-group --configfile=/etc/samba/smb.conf
