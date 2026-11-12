import json, re, sys, urllib.request
from datetime import date
from urllib.parse import urlparse

FEED = "https://urlhaus.abuse.ch/downloads/text_recent/"
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


def main():
    req = urllib.request.Request(FEED, headers={"User-Agent": "LinkGuard-updater"})
    text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "ignore")
    domains, ips = set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = (urlparse(line).hostname or "").lower()
        if not host:
            continue
        if IP.match(host):
            ips.add(host)
        elif not is_shared(host):
            domains.add(host)

    if len(domains) + len(ips) < 50:
        sys.exit("القائمة المحمّلة صغيرة بشكل مريب، تم الإلغاء")

    with open(OUT, encoding="utf-8") as f:
        db = json.load(f)
    db["version"] = date.today().isoformat()
    db["blockedDomains"] = sorted(domains)
    db["blockedIPs"] = sorted(ips)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    print(f"domains={len(domains)} ips={len(ips)}")


if __name__ == "__main__":
    main()
