#!/usr/bin/env bash
# Point the k3s API server's audit webhook at the in-cluster rbacscope receiver
# (Helm release installed with --set auditWebhook.enabled=true).
#
#   sudo bash examples/k3s-test/enable-audit-webhook.sh [namespace] [release]   # default: rbacscope rbacscope
#   sudo bash examples/k3s-test/enable-audit-webhook.sh --undo
#
# Re-run after reinstalling the chart (the Service IP or token may change). Restarts k3s.
set -euo pipefail

CONFIG=/etc/rancher/k3s/config.yaml
BACKUP=/etc/rancher/k3s/config.yaml.rbacscope-webhook-backup
POLICY=/etc/rancher/k3s/audit-policy.yaml
WEBHOOK=/etc/rancher/k3s/rbacscope-audit-webhook.kubeconfig
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUBECTL="k3s kubectl"

[ "$(id -u)" = 0 ] || { echo "error: run as root (sudo bash $0)" >&2; exit 1; }

wait_ready() {
  echo "Waiting for the API server..."
  for _ in $(seq 1 60); do
    if $KUBECTL get --raw /readyz >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "warning: API server not ready after 120s" >&2
}

if [ "${1:-}" = "--undo" ]; then
  if [ -f "$BACKUP" ]; then mv "$BACKUP" "$CONFIG"; fi
  rm -f "$WEBHOOK"
  systemctl restart k3s
  wait_ready
  echo "Audit webhook removed; k3s restarted."
  exit 0
fi

NS="${1:-rbacscope}"
RELEASE="${2:-rbacscope}"
SECRET="${RELEASE}-audit-token"

svc_ip="$($KUBECTL -n "$NS" get svc "$RELEASE" -o jsonpath='{.spec.clusterIP}')"
port="$($KUBECTL -n "$NS" get svc "$RELEASE" -o jsonpath='{.spec.ports[?(@.name=="audit")].port}')"
if [ -z "$port" ]; then
  echo "error: service $NS/$RELEASE has no 'audit' port; upgrade the release with --set auditWebhook.enabled=true" >&2
  exit 1
fi
token="$($KUBECTL -n "$NS" get secret "$SECRET" -o jsonpath='{.data.token}' | base64 -d)"
[ -n "$token" ] || { echo "error: secret $NS/$SECRET has no token" >&2; exit 1; }
# HTTPS is required: Kubernetes clients only send bearer tokens over TLS.
ca_data="$($KUBECTL -n "$NS" get secret "${RELEASE}-audit-tls" -o jsonpath='{.data.ca\.crt}')"
[ -n "$ca_data" ] || { echo "error: secret $NS/${RELEASE}-audit-tls has no ca.crt (chart older than 0.6.0?)" >&2; exit 1; }
server_name="${RELEASE}.${NS}.svc"

# The token is a credential: keep the kubeconfig root-only.
umask 077
cat > "$WEBHOOK" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: rbacscope
    cluster:
      server: https://${svc_ip}:${port}/audit
      tls-server-name: ${server_name}
      certificate-authority-data: ${ca_data}
contexts:
  - name: rbacscope
    context: {cluster: rbacscope, user: kube-apiserver}
current-context: rbacscope
users:
  - name: kube-apiserver
    user:
      token: ${token}
EOF
umask 022

[ -f "$POLICY" ] || install -m 0600 "$HERE/audit-policy.yaml" "$POLICY"

if [ -f "$CONFIG" ] && grep -q 'audit-webhook-config-file' "$CONFIG"; then
  echo "k3s already points at $WEBHOOK; refreshed it with the current Service IP and token."
else
  if [ -f "$CONFIG" ]; then cp "$CONFIG" "$BACKUP"; else : > "$BACKUP"; fi
  args=("audit-webhook-config-file=$WEBHOOK" "audit-webhook-mode=batch" "audit-webhook-batch-max-wait=5s")
  grep -qs 'audit-policy-file' "$CONFIG" || args=("audit-policy-file=$POLICY" "${args[@]}")
  if grep -qs '^kube-apiserver-arg:' "$CONFIG"; then
    # Append to the existing list (insert in reverse so the order is preserved).
    for ((i=${#args[@]}-1; i>=0; i--)); do
      sed -i "/^kube-apiserver-arg:/a\\  - ${args[$i]}" "$CONFIG"
    done
  else
    { echo "kube-apiserver-arg:"; for a in "${args[@]}"; do echo "  - $a"; done; } >> "$CONFIG"
  fi
fi

systemctl restart k3s
wait_ready
echo "API server now sends audit events to https://${svc_ip}:${port}/audit (TLS name ${server_name}, batched every ~5s)."
echo "Check: kubectl -n $NS logs deploy/$RELEASE | tail"
