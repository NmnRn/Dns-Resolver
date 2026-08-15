"""
Hazır blocklist (engelleme listesi) indirme + ayrıştırma.

AdGuard/Pi-hole tarzı: kullanıcı bir liste URL'sine "abone olur", resolver bu
URL'yi indirip domainleri çıkarır ve bellekteki blockset'e katar. Desteklenen
formatlar:
  - hosts:   `0.0.0.0 reklam.com`  /  `127.0.0.1 reklam.com`
  - düz:     `reklam.com`  (satır başına bir domain)
  - adblock: `||reklam.com^`
Yorumlar (`#`, `!`) ve domain olmayan satırlar atlanır.
"""
import re
import urllib.request

_ADBLOCK = re.compile(r'^\|\|([a-z0-9.\-_]+)\^')
_HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
_DOMAIN_OK = re.compile(r'^(?=.{1,253}$)([a-z0-9_](-?[a-z0-9_])*\.)+[a-z]{2,}$')
_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"}

# İndirme üst sınırı: kötü niyetli/dev bir URL belleği doldurmasın (25 MB).
_MAX_BYTES = 25 * 1024 * 1024

# GitHub 'blob' (HTML sayfası) URL'si → 'raw' (ham dosya) URL'si.
_GH_BLOB = re.compile(r'^https?://github\.com/([^/]+)/([^/]+)/blob/(.+)$')


def normalize_url(url: str) -> str:
    """Kullanıcı GitHub'ın blob (HTML) linkini yapıştırırsa ham linke çevir —
    aksi halde domain listesi yerine HTML sayfası inip 0 domain çıkar."""
    m = _GH_BLOB.match(url.strip())
    if m:
        return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}"
    return url.strip()


def parse_blocklist(text: str) -> set[str]:
    """Metinden (hosts/düz/adblock) engellenecek domain kümesini çıkarır."""
    domains: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        m = _ADBLOCK.match(line)
        if m:
            d = m.group(1)
        else:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in _HOSTS_IPS:
                d = parts[1]           # hosts: IP domain
            elif len(parts) == 1:
                d = parts[0]           # düz: domain
            else:
                continue
        d = d.strip(".").lower()
        if d and d not in _SKIP and _DOMAIN_OK.match(d):
            domains.add(d)
    return domains


def download_and_parse(url: str, timeout: float = 30) -> set[str]:
    """URL'yi indirir (senkron; executor'da çağır) ve domain kümesi döndürür."""
    url = normalize_url(url)   # GitHub blob linki yapıştırıldıysa ham linke çevir
    req = urllib.request.Request(url, headers={"User-Agent": "dns-resolver-blocklist/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(_MAX_BYTES)
    return parse_blocklist(data.decode("utf-8", errors="ignore"))
