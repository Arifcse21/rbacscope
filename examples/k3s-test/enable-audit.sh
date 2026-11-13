#!/usr/bin/env bash
# Enable Kubernetes audit logging on a local k3s server, for `rbacscope generate` / `unused`.
#
#   sudo bash examples/k3s-test/enable-audit.sh           # enable (restarts k3s)
#   sudo bash examples/k3s-test/enable-audit.sh --undo    # restore the previous config
#
# The log is written to /var/lib/rancher/k3s/server/logs/audit.log (root-only, rotated at 100 MB).
set -euo pipefail

CONFIG=/etc/rancher/k3s/config.yaml
BACKUP=/etc/rancher/k3s/config.yaml.rbacscope-backup
POLICY=/etc/rancher/k3s/audit-policy.yaml
LOG=/var/lib/rancher/k3s/server/logs/audit.log
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" = 0 ] || { echo "error: run as root (sudo bash $0)" >&2; exit 1; }

if [ "${1:-}" = "--undo" ]; then
  if [ -f "$BACKUP" ]; then mv "$BACKUP" "$CONFIG"; else rm -f "$CONFIG"; fi
  rm -f "$POLICY"
  systemctl restart k3s
  echo "Audit logging disabled; k3s restarted. Existing logs kept in $(dirname "$LOG")."
  exit 0
fi

if [ -f "$CONFIG" ] && grep -q 'kube-apiserver-arg' "$CONFIG"; then
  cat >&2 <<EOF
error: $CONFIG already sets kube-apiserver-arg. Add these entries to that list by hand:
  - audit-log-path=$LOG
  - audit-policy-file=$POLICY
  - audit-log-maxsize=100
  - audit-log-maxbackup=3
then run: systemctl restart k3s
EOF
  exit 1
fi

install -m 0600 "$HERE/audit-policy.yaml" "$POLICY"
mkdir -p "$(dirname "$LOG")"
if [ -f "$CONFIG" ]; then cp "$CONFIG" "$BACKUP"; else : > "$BACKUP.none"; fi

cat >> "$CONFIG" <<EOF
kube-apiserver-arg:
  - audit-log-path=$LOG
  - audit-policy-file=$POLICY
  - audit-log-maxsize=100
  - audit-log-maxbackup=3
EOF

[ -f "$BACKUP.none" ] && rm -f "$BACKUP.none" "$BACKUP"
systemctl restart k3s
echo "Waiting for the API server..."
for _ in $(seq 1 60); do
  if k3s kubectl get --raw /readyz >/dev/null 2>&1; then break; fi
  sleep 2
done
echo "Audit logging enabled: $LOG"
echo "Copy it for rbacscope with: sudo cat $LOG > audit.log"
