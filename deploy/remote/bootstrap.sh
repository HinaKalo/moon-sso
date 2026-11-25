#!/usr/bin/env bash
# One-time (idempotent) host setup for Moon SSO. Run as root on Moon.
# Creates the service user, directories, master keys, config files and
# systemd units for both instances (prod, staging). Never overwrites secrets.
set -euo pipefail

id moon-sso >/dev/null 2>&1 || useradd --system --home /var/lib/moon-sso --shell /usr/sbin/nologin moon-sso

install -d -m 0755 -o root -g root /opt/moon-sso /opt/moon-sso/releases /opt/moon-sso/bin
install -d -m 0755 -o moon-sso -g moon-sso /var/lib/moon-sso /var/lib/moon-sso/avatars
install -d -m 0755 -o moon-sso -g moon-sso /var/lib/moon-sso-staging /var/lib/moon-sso-staging/avatars
install -d -m 0750 -o root -g moon-sso /etc/moon-sso /etc/moon-sso-staging
install -d -m 0700 -o root -g root /var/backups/moon-sso

for inst in moon-sso moon-sso-staging; do
  if [ ! -s /etc/$inst/master.key ]; then
    umask 077
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/$inst/master.key
    echo "generated /etc/$inst/master.key — back it up offline"
  fi
  chown root:root /etc/$inst/master.key /etc/$inst/db.dsn
  chmod 0600 /etc/$inst/master.key /etc/$inst/db.dsn
  [ -f /etc/$inst/config.toml ] && chown root:moon-sso /etc/$inst/config.toml && chmod 0640 /etc/$inst/config.toml
  chown root:moon-sso /etc/$inst && chmod 0750 /etc/$inst
done

write_config() { # name public admin url admin_url env datadir maxconns
  local f=/etc/$1/config.toml
  [ -f "$f" ] && return 0
  cat > "$f" <<CFG
[server]
public_listen = "$2"
admin_listen = "$3"
public_url = "$4"
admin_url = "$5"
environment = "$6"
insecure_cookies = $9

[database]
dsn_file = "\${CREDENTIALS_DIRECTORY}/db.dsn"
max_open_conns = $8
max_idle_conns = $(( $8 / 2 ))
conn_max_lifetime = "30m"

[secrets]
master_key_file = "\${CREDENTIALS_DIRECTORY}/master.key"

[storage]
data_dir = "$7"

[log]
level = "info"
format = "json"
CFG
  chown root:moon-sso "$f"; chmod 0640 "$f"
}
write_config moon-sso 127.0.0.1:8601 127.0.0.1:8602 https://sso.moonl.cloud https://sso-admin.moonl.cloud prod /var/lib/moon-sso 40 false
write_config moon-sso-staging 127.0.0.1:8611 127.0.0.1:8612 http://127.0.0.1:8611 http://127.0.0.1:8612 staging /var/lib/moon-sso-staging 10 true

write_units() { # unit public_port admin_port etc datadir current description memory
  cat > /etc/systemd/system/$1-public.socket <<U
[Unit]
Description=$7 public listener
PartOf=$1.service

[Socket]
ListenStream=127.0.0.1:$2
FileDescriptorName=public
Service=$1.service
Backlog=4096
NoDelay=true

[Install]
WantedBy=sockets.target
U
  cat > /etc/systemd/system/$1-admin.socket <<U
[Unit]
Description=$7 admin listener
PartOf=$1.service

[Socket]
ListenStream=127.0.0.1:$3
FileDescriptorName=admin
Service=$1.service
Backlog=1024
NoDelay=true

[Install]
WantedBy=sockets.target
U
  cat > /etc/systemd/system/$1.service <<U
[Unit]
Description=$7
After=network.target mysql.service
Wants=mysql.service
Requires=$1-public.socket $1-admin.socket

[Service]
Type=notify
NotifyAccess=main
User=moon-sso
Group=moon-sso
ExecStart=/opt/moon-sso/$6/moon-sso serve -config /etc/$4/config.toml
Sockets=$1-public.socket $1-admin.socket
LoadCredential=master.key:/etc/$4/master.key
LoadCredential=db.dsn:/etc/$4/db.dsn
Restart=always
RestartSec=2
TimeoutStartSec=60
TimeoutStopSec=30
WatchdogSec=30
Environment=GOMEMLIMIT=$8
MemoryMax=2G
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
UMask=0022
ReadWritePaths=$5

[Install]
WantedBy=multi-user.target
U
}
write_units moon-sso 8601 8602 moon-sso /var/lib/moon-sso current "Moon SSO (prod)" 1200MiB
write_units moon-sso-staging 8611 8612 moon-sso-staging /var/lib/moon-sso-staging staging-current "Moon SSO (staging)" 400MiB
systemctl daemon-reload
echo "bootstrap complete"
