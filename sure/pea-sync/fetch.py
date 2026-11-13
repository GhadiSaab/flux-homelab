"""Read the BoursoBank PEA (positions + cash) with woob and write JSON for Sure.

Usage: fetch.py OUT.json [--setup]
  --setup: interactive; answers BoursoBank 2FA (app validation / SMS / email code).
Without --setup a pending 2FA exits with status 3 ("need_2fa").
Credentials come from BOURSO_LOGIN / BOURSO_PASSWORD; browser state lives in /state.
"""
import json, os, sys, time
from woob.core import WoobBase
from woob.capabilities.bank import Account
from woob.exceptions import AppValidation, BrowserQuestion, NeedInteractiveFor2FA, BrowserIncorrectPassword
from woob.tools.storage import StandardStorage

out, setup = sys.argv[1], "--setup" in sys.argv
if not os.environ.get("BOURSO_LOGIN"):
    json.dump({"status": "not_configured"}, open(out, "w"))
    print("BoursoBank credentials not set yet (run setup.sh)")
    sys.exit(0)
woob = WoobBase(modules_path=os.environ["WOOB_MODULES"])
params = {"login": os.environ["BOURSO_LOGIN"], "password": os.environ["BOURSO_PASSWORD"]}
if setup:
    params["request_information"] = {}
backend = woob.build_backend("boursorama", params, storage=StandardStorage("/state/storage.yaml"), name="bourso")

def write(obj):
    with open(out, "w") as f:
        json.dump(obj, f, indent=1, default=str)

def dec(x):
    return None if x is None or not hasattr(x, "__float__") else float(x)

def run():
    accounts = [a for a in backend.iter_accounts() if a.type == Account.TYPE_PEA]
    if not accounts:
        raise SystemExit("no PEA account found")
    acc = accounts[0]
    invs, cash = [], None
    for i in backend.iter_investment(acc):
        if i.code and "liquidity" in str(i.code).lower():
            cash = dec(i.valuation)
            continue
        invs.append({"isin": i.code, "label": i.label, "qty": dec(i.quantity), "pru": dec(i.unitprice),
                     "price": dec(i.unitvalue), "valuation": dec(i.valuation)})
    total = dec(acc.balance)
    if cash is None and total is not None:
        cash = round(total - sum(v["valuation"] or 0 for v in invs), 2)
    write({"status": "ok", "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "label": acc.label,
           "total": total, "cash": cash, "investments": invs})
    print(f"ok: {len(invs)} positions, cash={cash}, total={total}")

try:
    for attempt in range(6):
        try:
            run()
            break
        except AppValidation as e:
            if not setup:
                raise NeedInteractiveFor2FA()
            print(f"\n>> {e.message or 'Approve the login in the BoursoBank app'} (waiting...)")
            backend.config["resume"].set("true")
        except BrowserQuestion as q:
            if not setup:
                raise NeedInteractiveFor2FA()
            for field in q.fields:
                backend.config[field.id].set(input(f"\n>> {field.label or field.id}: ").strip())
    else:
        raise SystemExit("2FA did not complete")
except NeedInteractiveFor2FA:
    write({"status": "need_2fa"})
    print("BoursoBank asks for 2FA again: run the setup command (see sure/pea-sync/README.md)")
    sys.exit(3)
except BrowserIncorrectPassword as e:
    write({"status": "bad_password", "message": str(e)})
    print(f"login refused: {e}")
    sys.exit(4)
finally:
    backend.deinit()  # persists browser state (90-day trusted login) to /state
