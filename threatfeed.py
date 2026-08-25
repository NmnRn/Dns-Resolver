"""Tehdit / datacenter IP feed'leri — istemci IP'si bu CIDR aralıklarındaysa
'bot/datacenter kaynaklı' şüpheli sayılır. AÇIK kaynaklar (hesap gerektirmez,
günlük güncel). Default KAPALI (panelden 'threat_feed_enabled' ile açılır).

Blocklist altyapısındaki SSRF-guard'lı indirmeyi tekrar kullanır (redirect yeniden
doğrulanır), ama domain değil CIDR/netset parse eder. Eşleşme, resolver'ın periyodik
taramasında yapılır (az sayıda aktif istemci) → flag'lenenler paylaşılan dosyaya
yazılır; panel oradan okur (büyük CIDR eşleşmesini panelde yapmayız).
"""
import ipaddress

from project_control import blocklists

# Açık, hesap gerektirmeyen, günlük güncellenen feed'ler (CIDR / netset).
FEEDS = [
    "https://www.spamhaus.org/drop/drop.txt",                    # Spamhaus DROP: kötü/ele geçirilmiş netblock
    "https://iplists.firehol.org/files/firehol_level1.netset",   # FireHOL L1: abuse/datacenter/spam
]


def parse_cidrs(text):
    """Feed metninden IP ağları listesi. '#'/';' yorum; 'CIDR ; SBLxxx' (Spamhaus) formatı da olur."""
    nets = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        token = line.split(";")[0].split()[0].strip()      # 'CIDR ; SBLxxx' → CIDR
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return nets


def download(url, timeout=30):
    """Feed'i indir (SSRF-guard'lı; redirect yeniden doğrulanır) → ağ listesi."""
    url = blocklists.normalize_url(url)
    blocklists._assert_safe_url(url)
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "dns-resolver-threatfeed/1.0"})
    with blocklists._OPENER.open(req, timeout=timeout) as resp:
        data = resp.read(blocklists._MAX_BYTES)
    return parse_cidrs(data.decode("utf-8", errors="ignore"))


def load_all(timeout=30):
    """Tüm FEED'leri indir + birleştir → tek ağ listesi (hata veren feed atlanır)."""
    nets = []
    for url in FEEDS:
        try:
            nets += download(url, timeout)
        except Exception:   # noqa: BLE001 — bir feed düşse diğerleri çalışsın
            continue
    return nets


def in_feed(ip, nets):
    """ip, ağ listesindeki herhangi bir CIDR'de mi? (geçersiz IP → False)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in n for n in nets)
