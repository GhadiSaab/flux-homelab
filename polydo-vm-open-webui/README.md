# open-webui on the polydo VM cluster

This deploys the same [open-webui](https://helm.openwebui.com/) chart used in this
repo's `open-webui/helmrelease.yaml`, but on a **separate** standalone k3s cluster
(`vm-lmichault`, 162.38.112.109) rather than the homelab cluster. That cluster is
**not** managed by Flux — this directory exists purely as version-controlled
source-of-truth for the `helm upgrade --install` invocation below, applied manually.

## Why a separate deployment

- Different cluster, different domain (`polydo.dev` instead of `gsaab.dev`), managed
  imperatively via `helm`/`kubectl` (same pattern as the `do-board` app already
  running there), not GitOps.
- Web search reuses the homelab's `searxng` instance over the internet, via the
  `searxng.gsaab.dev` Cloudflare Tunnel hostname added in this repo's
  `cloudflared/configmap.yaml` (see that commit) rather than running a second
  searxng instance.
- RAM is tight on that box (4GB node, shared with other workloads), so
  `RAG_EMBEDDING_ENGINE` is set to `openai` and the local embedding/reranking
  model auto-download is disabled — otherwise the chart's default eagerly
  downloads and loads a local `sentence-transformers` model at boot, which alone
  costs ~1.6GiB RSS. File/knowledge-base RAG uploads won't work as a result,
  since the backend has no `/embeddings` route; chat and web search are
  unaffected.

## Prerequisites (not tracked in git)

The `openai-api-key` secret is created directly in-cluster, never committed:

```bash
kubectl create secret generic openai-api-key -n open-webui \
  --from-literal=api-key=<the qwen36.do-2023.dev API key>
```

DNS: `openwebui.polydo.dev` needs a DNS-only (grey-cloud) `A` record to
`162.38.112.109` on the `polydo.dev` Cloudflare zone, matching the existing
`do-board.polydo.dev` record, so cert-manager's HTTP-01 challenge can complete.

## Deploy

```bash
helm repo add open-webui https://helm.openwebui.com/
kubectl create namespace open-webui
# create the secret as above
helm upgrade --install open-webui open-webui/open-webui -n open-webui -f values.yaml
```
