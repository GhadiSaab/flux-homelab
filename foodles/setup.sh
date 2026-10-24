#!/usr/bin/env bash
# One-time setup: creates the data dir on the homelab and seals the Foodles credentials.
set -euo pipefail
cd "$(dirname "$0")"

ssh homelab 'mkdir -p ~/foodles && chmod 700 ~/foodles'

read -rp "Foodles email: " email
read -rsp "Foodles password: " password; echo

tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
FOODLES_EMAIL="$email" FOODLES_PASSWORD="$password" python3 -c '
import json, os
print(json.dumps({"apiVersion": "v1", "kind": "Secret",
  "metadata": {"name": "foodles-credentials", "namespace": "foodles"},
  "stringData": {k: os.environ[k] for k in ("FOODLES_EMAIL", "FOODLES_PASSWORD")}}))' > "$tmp"

ssh homelab 'sudo kubeseal --kubeconfig /etc/rancher/k3s/k3s.yaml --controller-name sealed-secrets-controller --controller-namespace flux-system --format yaml' \
  < "$tmp" > sealedsecret.yaml
grep -q encryptedData sealedsecret.yaml
grep -q sealedsecret.yaml kustomization.yaml || sed -i 's/^  - cronjob.yaml$/  - cronjob.yaml\n  - sealedsecret.yaml/' kustomization.yaml
echo "Sealed. Now commit and push foodles/ and kustomization.yaml; Flux deploys within 10 min."
