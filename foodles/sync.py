#!/usr/bin/env python3
"""Log what I eat from the Foodles fridge, with nutrition, as one JSON file per day."""
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

API = os.environ.get("FOODLES_API", "https://api.foodles.co/api")
DATA_DIR = os.environ.get("DATA_DIR", "/data")
STATE_DIR = os.path.join(DATA_DIR, ".state")
# Sales can be cancelled/refunded after the fact; keep re-checking recent ones.
RECHECK_DAYS = 7

# Output key -> Foodles product field. Foodles gives values per 100 g (or 100 mL).
NUTRIENTS = {
    "kcal": "energy_kcal",
    "kj": "energy_kj",
    "fat_g": "fat_content",
    "saturated_fat_g": "fat_content_ags",
    "carbs_g": "glucides",
    "sugars_g": "glucides_sugar",
    "fibre_g": "fibres",
    "protein_g": "proteins",
    "salt_g": "salt",
}


def log(msg):
    print(msg, flush=True)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


class Foodles:
    def __init__(self, email, password, cookie_path):
        self.email = email
        self.password = password
        self.jar = http.cookiejar.MozillaCookieJar(cookie_path)
        try:
            self.jar.load(ignore_discard=True, ignore_expires=True)
        except (FileNotFoundError, http.cookiejar.LoadError):
            pass
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _request(self, method, path, body=None):
        url = path if path.startswith("http") else API + path
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://app.foodles.co",
            "Referer": "https://app.foodles.co/",
            "User-Agent": "foodles-sync (personal nutrition log)",
        }
        csrf = next((c.value for c in self.jar if c.name == "csrftoken"), None)
        if csrf and method != "GET":
            headers["X-CSRFToken"] = csrf
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with self.opener.open(req, timeout=30) as resp:
            return json.load(resp)

    def get(self, path):
        try:
            return self._request("GET", path)
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                raise
        log("session missing or expired, logging in")
        self.login()
        return self._request("GET", path)

    def login(self):
        try:
            self._request("POST", "/auth/login/", {"username": self.email, "password": self.password})
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            try:
                kind = self._request("GET", "/auth/login-type/?" + urllib.parse.urlencode({"email": self.email}))
            except urllib.error.HTTPError:
                kind = {}
            if kind.get("type") == "saml":
                sys.exit("Foodles uses SSO (SAML) for this account, password login is not possible")
            sys.exit(f"Foodles login failed ({e.code}): {detail}")
        self.jar.save(ignore_discard=True, ignore_expires=True)
        os.chmod(self.jar.filename, 0o600)


def portion_nutrition(product):
    """Scale per-100 values to the whole product (weight in g, or volume in mL for drinks)."""
    amount = product.get("weight") or product.get("volume")
    unit = "g" if product.get("weight") else "mL"
    per_100 = {k: product.get(field) for k, field in NUTRIENTS.items()}
    portion = None
    if amount:
        portion = {k: round(v * amount / 100, 1) for k, v in per_100.items() if v is not None}
    return {"amount": amount, "unit": unit, "per_100": per_100, "portion": portion}


def get_product(client, products, product_id):
    key = str(product_id)
    if key not in products:
        try:
            products[key] = client.get(f"/product/{product_id}/")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            products[key] = None
    return products[key]


def build_entry(client, products, tx):
    created = datetime.fromisoformat(tx["created_at"])
    items = []
    for item in tx["items"]:
        product = get_product(client, products, item["product_id"]) if item.get("product_id") else None
        items.append({
            "name": item["name"],
            "product_id": item.get("product_id"),
            "price_eur": item["saved_price"] / 100,
            **(portion_nutrition(product) if product else {"portion": None}),
        })
    return {
        "transaction_id": tx["id"],
        "time": created.isoformat(timespec="seconds"),
        "date": created.date().isoformat(),
        "fridge": tx.get("warehouse"),
        "items": items,
    }


def write_day(day, entries):
    year, month, _ = day.split("-")
    path = os.path.join(DATA_DIR, year, month, f"{day}.json")
    day_entries = sorted((e for e in entries.values() if e["date"] == day), key=lambda e: e["time"])
    if not day_entries:
        if os.path.exists(path):
            os.remove(path)
        return
    eaten = [
        {"time": e["time"][11:16], "transaction_id": e["transaction_id"], **item}
        for e in day_entries
        for item in e["items"]
    ]
    totals = {k: 0.0 for k in NUTRIENTS}
    for item in eaten:
        for k, v in (item["portion"] or {}).items():
            totals[k] += v
    totals = {k: round(v, 1) for k, v in totals.items()}
    totals["price_eur"] = round(sum(item["price_eur"] for item in eaten), 2)
    missing = [item["name"] for item in eaten if not item["portion"]]
    write_json(path, {"date": day, "items": eaten, "totals": totals, "missing_nutrition": missing})
    log(f"{day}: {len(eaten)} item(s), {totals['kcal']} kcal")


def sync(client):
    entries_path = os.path.join(STATE_DIR, "entries.json")
    products_path = os.path.join(STATE_DIR, "products.json")
    entries = load_json(entries_path, {})
    products = load_json(products_path, {})
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECHECK_DAYS)
    touched = set()

    url = "/transaction/"
    while url:
        page = client.get(url)
        reached_old_known = False
        for tx in page["results"]:
            key = str(tx["id"])
            if key in entries and datetime.fromisoformat(tx["created_at"]) < cutoff:
                reached_old_known = True
            if tx["reason"] != "TX_SALE":
                continue
            if tx["cancelled"]:
                if key in entries:
                    log(f"transaction {key} was cancelled, removing it")
                    touched.add(entries.pop(key)["date"])
                continue
            if key in entries:
                continue
            detail = client.get(f"/transaction/{tx['id']}/")
            entries[key] = build_entry(client, products, detail)
            touched.add(entries[key]["date"])
        url = None if reached_old_known else page.get("next")

    for day in sorted(touched):
        write_day(day, entries)
    write_json(products_path, products)
    write_json(entries_path, entries)
    log(f"done, {len(touched)} day file(s) updated")


def main():
    email = os.environ.get("FOODLES_EMAIL")
    password = os.environ.get("FOODLES_PASSWORD")
    if not email or not password:
        sys.exit("FOODLES_EMAIL and FOODLES_PASSWORD must be set")
    os.makedirs(STATE_DIR, exist_ok=True)
    sync(Foodles(email, password, os.path.join(STATE_DIR, "cookies.txt")))


if __name__ == "__main__":
    main()
