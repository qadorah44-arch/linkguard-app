import json, os, re, sys, urllib.request
from datetime import date
from urllib.parse import urlparse

API = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
OUT = "threats.json"

SHARED = {
    "github.com", "githubusercontent.com", "raw.githubusercontent.com", "google.com",
    "googleusercontent.com", "dropbox.com", "amazonaws.com", "azureedge.net",
    "cloudfront.net", "oraclecloud.com", "pastebin.com", "paste.ee", "catbox.moe",
    "trycloudflare.com", "workers.dev", "pages.dev", "filemail.com", "backblazeb2.com",
    "discordapp.com", "discord.com", "mediafire.com", "mega.nz", "sherpadesk.com",
    "ctempurl.com", "b-cdn.net", "plesk.page", "onedrive.live.com", "bit.ly",
}
IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_shared(host):
    parts = host.split(".")
    return any(".".join(parts[i:]) in SHARED for i in range(len(parts) - 1))


def fetch(key):
    req = urllib.request.Request(API, headers={"Auth-Key": key, "User-Agent": "LinkGuard-updater"})
    return json.load(urllib.request.urlopen(req, timeout=60))


def main():
    key = os.environ.get("ABUSECH_KEY", "").strip()
    if not key:
        sys.exit("المفتاح ABUSECH_KEY غير موجود")

    data = fetch(key)
    if data.get("query_status") != "ok":
        sys.exit("رد غير متوقع من URLhaus: " + str(data.get("query_status")))

    domains, ips = set(), set()
    for item in data.get("urls", []):
        if item.get("url_status") != "online":
            continue
        host = (item.get("host") or urlparse(item.get("url", "")).hostname or "").lower()
        if not host:
            continue
        if IP.match(host):
            ips.add(host)
        elif not is_shared(host):
            domains.add(host)

    if len(domains) + len(ips) < 20:
        sys.exit("القائمة المحمّلة صغيرة بشكل مريب، تم الإلغاء")

    with open(OUT, encoding="utf-8") as f:
        db = json.load(f)
    old_d, old_i = set(db.get("blockedDomains", [])), set(db.get("blockedIPs", []))
    db["version"] = date.today().isoformat()
    db["blockedDomains"] = sorted(old_d | domains)
    db["blockedIPs"] = sorted(old_i | ips)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    print(f"new domains={len(domains)} new ips={len(ips)} total={len(db['blockedDomains'])}+{len(db['blockedIPs'])}")


if __name__ == "__main__":
    main()
