#!/usr/bin/env bash
# Daily encrypted backup of the Moon SSO database and avatars.
# Output: /var/backups/moon-sso/moon-sso-<UTC timestamp>.tar.gz.enc (+ .sha256), kept 14 days.
# Decrypt: openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:/etc/moon-sso/backup.key -in X.enc | tar -xz
set -euo pipefail
umask 077
out=/var/backups/moon-sso
key=/etc/moon-sso/backup.key
ts=$(date -u +%Y%m%d-%H%M%S)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"
mysqldump --single-transaction --quick --routines --triggers --hex-blob moon_sso > "$tmp/moon_sso.sql"
tar -C /var/lib/moon-sso -czf "$tmp/avatars.tgz" avatars
cp /etc/moon-sso/config.toml "$tmp/config.toml"
tar -C "$tmp" -czf - moon_sso.sql avatars.tgz config.toml |
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$key" -out "$out/moon-sso-$ts.tar.gz.enc.part"
mv "$out/moon-sso-$ts.tar.gz.enc.part" "$out/moon-sso-$ts.tar.gz.enc"
(cd "$out" && sha256sum "moon-sso-$ts.tar.gz.enc" > "moon-sso-$ts.tar.gz.enc.sha256")
find "$out" -name 'moon-sso-*.enc*' -mtime +14 -delete
echo "backup $out/moon-sso-$ts.tar.gz.enc $(stat -c %s "$out/moon-sso-$ts.tar.gz.enc") bytes"
