#!/usr/bin/env bash
# One-time (and every ~90 days) BoursoBank login for the PEA sync.
# Your login/password are typed here, sealed with kubeseal, and never printed or stored in plain text.
set -euo pipefail
K="sudo k3s kubectl"; REPO=~/gitops-homelab/sure
if [ "${1:-}" != "--2fa-only" ]; then
  read -rp  "BoursoBank identifiant (digits): " LOGIN
  read -rsp "BoursoBank mot de passe: " PASS; echo
  $K create secret generic sure-boursorama -n sure --from-literal=login="$LOGIN" --from-literal=password="$PASS" --dry-run=client -o yaml \
    | sudo kubeseal --kubeconfig /etc/rancher/k3s/k3s.yaml --controller-namespace flux-system --controller-name sealed-secrets-controller --format yaml \
    > "$REPO/pea-sync/sealedsecret.yaml"
  unset LOGIN PASS
  $K apply -f "$REPO/pea-sync/sealedsecret.yaml"
  for i in $(seq 30); do $K -n sure get secret sure-boursorama >/dev/null 2>&1 && break; sleep 1; done
fi
echo ">> Logging in to BoursoBank. Approve the request in the BoursoBank app (or type the SMS code) when asked."
$K -n sure delete pod pea-setup --ignore-not-found >/dev/null
$K -n sure run pea-setup -it --rm --restart=Never --image=woob-bourso:1 --image-pull-policy=Never --overrides='{
  "spec": {"securityContext": {"fsGroup": 1000},
    "containers": [{"name": "pea-setup", "image": "woob-bourso:1", "imagePullPolicy": "Never", "stdin": true, "tty": true,
      "command": ["python", "/scripts/fetch.py", "/tmp/pea.json", "--setup"],
      "env": [{"name": "BOURSO_LOGIN", "valueFrom": {"secretKeyRef": {"name": "sure-boursorama", "key": "login"}}},
              {"name": "BOURSO_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "sure-boursorama", "key": "password"}}}],
      "volumeMounts": [{"name": "state", "mountPath": "/state"}, {"name": "scripts", "mountPath": "/scripts"}]}],
    "volumes": [{"name": "state", "persistentVolumeClaim": {"claimName": "sure-woob-state"}},
                {"name": "scripts", "configMap": {"name": "pea-sync-scripts"}}]}}'
echo ">> Running the first sync into Sure..."
$K -n sure delete job pea-sync-manual --ignore-not-found >/dev/null
$K -n sure create job pea-sync-manual --from=cronjob/pea-sync >/dev/null
$K -n sure wait --for=condition=complete job/pea-sync-manual --timeout=300s && $K -n sure logs job/pea-sync-manual -c reconcile | tail -5
