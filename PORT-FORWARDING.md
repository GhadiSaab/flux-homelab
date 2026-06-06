# Freebox Port Forwarding

Configured on the Freebox router (192.168.1.254).

| External port | Internal IP   | Internal port | Protocol | Service                   |
|--------------|---------------|---------------|----------|---------------------------|
| 80           | 192.168.1.89  | 31768         | TCP      | Traefik HTTP (web)        |
| 16384        | 192.168.1.89  | 31147         | TCP      | Traefik HTTPS (websecureext) |

## Notes

- `192.168.1.89` is Traefik's LoadBalancer IP (k3s MetalLB)
- Internal ports are Traefik's NodePorts — Freebox blocks destination ports below 16384
- Freebox IP source left empty (accepts from any public IP)
- WAN IP: `88.162.235.90` (dynamic — updated via DDNS in `ddns/` gitops folder)
