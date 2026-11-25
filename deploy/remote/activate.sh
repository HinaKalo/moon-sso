#!/usr/bin/env bash
# activate.sh <prod|staging> <version>
# Migrates the instance's database with the new binary, switches the symlink,
# restarts (sockets stay open, so no connection is refused) and verifies
# readiness. On failure the previous release is restored automatically.
set -euo pipefail
inst=$1; ver=$2
case "$inst" in
  prod)    unit=moon-sso;         etc=/etc/moon-sso;         link=/opt/moon-sso/current;         port=8601 ;;
  staging) unit=moon-sso-staging; etc=/etc/moon-sso-staging; link=/opt/moon-sso/staging-current; port=8611 ;;
  *) echo "unknown instance $inst" >&2; exit 2 ;;
esac
rel=/opt/moon-sso/releases/$ver
[ -x "$rel/moon-sso" ] || { echo "release $ver missing" >&2; exit 2; }
prev=""
[ -L "$link" ] && prev=$(readlink -f "$link")

# Never migrate while a backup dump is running (metadata locks).
while pgrep -f "mysqldump.*moon_sso" >/dev/null; do echo "waiting for backup to finish"; sleep 5; done

echo "[$inst] migrating with $ver"
CREDENTIALS_DIRECTORY=$etc "$rel/moon-sso" migrate -config $etc/config.toml

ln -sfn "$rel" "$link.new" && mv -T "$link.new" "$link"
systemctl enable --quiet $unit-public.socket $unit-admin.socket $unit.service
systemctl start $unit-public.socket $unit-admin.socket
if ! systemctl restart $unit.service; then
  echo "[$inst] restart failed" >&2
  ok=0
else
  ok=0
  for i in $(seq 1 30); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$port/readyz" | grep -q "ready $ver"; then ok=1; break; fi
    sleep 1
  done
fi
if [ $ok -ne 1 ]; then
  echo "[$inst] $ver failed readiness; rolling back to ${prev:-nothing}" >&2
  journalctl -u $unit.service -n 40 --no-pager >&2 || true
  if [ -n "$prev" ]; then
    ln -sfn "$prev" "$link.new" && mv -T "$link.new" "$link"
    systemctl restart $unit.service || true
  fi
  exit 1
fi
echo "[$inst] $ver is serving"
# Keep the 8 most recent releases.
ls -1dt /opt/moon-sso/releases/*/ | tail -n +9 | while read -r d; do
  d=${d%/}
  [ "$d" = "$(readlink -f /opt/moon-sso/current)" ] || [ "$d" = "$(readlink -f /opt/moon-sso/staging-current)" ] || rm -rf "$d"
done
