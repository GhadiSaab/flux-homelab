# PEA sync (BoursoBank → Sure)
Daily 07:30 Europe/Paris: woob reads the PEA positions (qty, PRU, price, cash) and `reconcile.rb`
adds any new buys/sells to the Sure account "PEA BoursoBank" (cost basis = BoursoBank PRU) and reconciles cash.
- Credentials: SealedSecret `sure-boursorama`. Browser state (90-day trusted login): PVC `sure-woob-state`.
- First setup / new password: `ssh -t homelab ~/gitops-homelab/sure/pea-sync/setup.sh`
- Every ~90 days BoursoBank asks for 2FA again; the job fails with `need_2fa`. Then: `ssh -t homelab ~/gitops-homelab/sure/pea-sync/setup.sh --2fa-only`
- Image: `woob-bourso:1` built from Dockerfile here, imported with `docker save | ssh homelab sudo k3s ctr images import -`.
