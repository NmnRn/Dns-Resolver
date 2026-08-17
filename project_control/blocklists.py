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
import ipaddress
import re
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit

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


def _assert_safe_url(url: str) -> None:
    """SSRF önlemi: yalnız http/https ve host'un çözdüğü TÜM IP'ler iç/tehlikeli
    olmamalı — loopback (127.x/::1), link-local (bulut-metadata 169.254.169.254),
    unspecified, multicast, reserved reddedilir. Özel LAN (192.168/10/172.16) İZİNLİ
    (yerel liste aynaları çalışsın diye)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"desteklenmeyen şema: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise ValueError("URL'de host yok")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"host çözülemedi: {host}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise ValueError(f"engellenen iç adres (SSRF): {ip}")


def download_and_parse(url: str, timeout: float = 30) -> set[str]:
    """URL'yi indirir (senkron; executor'da çağır) ve domain kümesi döndürür."""
    url = normalize_url(url)   # GitHub blob linki yapıştırıldıysa ham linke çevir
    _assert_safe_url(url)      # SSRF: iç/metadata adreslerini reddet
    req = urllib.request.Request(url, headers={"User-Agent": "dns-resolver-blocklist/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(_MAX_BYTES)
    return parse_blocklist(data.decode("utf-8", errors="ignore"))


def check_link(url: str, timeout: float = 12) -> dict:
    """URL erişilebilir mi — hafif kontrol (listeyi İNDİRMEDEN). Önce HEAD
    dener; HEAD kapalıysa (400/403/405/501) 1 baytlık Range'li GET'e düşer.
    Üç durum döndürür (senkron; asyncio.to_thread ile çağır):
      ok=True                → 2xx/3xx, erişilebilir (✓)
      ok=False, warn=True    → 401/403/429/5xx: sunucu yanıt verdi ama içerik
                               alınamadı (throttle/blok/geçici) — link muhtemelen
                               sağlam (⚠). GitHub raw HEAD'e 429 döndürebilir.
      ok=False, warn=False   → 404/410 (liste yok) veya DNS/bağlantı hatası (✗)
    {'ok', 'warn', 'status', 'detail'} döndürür."""
    try:
        url = normalize_url(url)   # GitHub blob → raw
        _assert_safe_url(url)      # SSRF: iç/metadata adresleri reddet
    except ValueError as e:
        return {"ok": False, "warn": False, "status": None, "detail": str(e)}

    def _classify(code: int, reason: str) -> dict:
        if code in (404, 410):
            return {"ok": False, "warn": False, "status": code,
                    "detail": f"HTTP {code} — liste bulunamadı"}
        return {"ok": False, "warn": True, "status": code,
                "detail": f"HTTP {code} {reason} — erişildi, içerik alınamadı"}

    def _try(method: str) -> dict:
        req = urllib.request.Request(
            url, method=method,
            headers={"User-Agent": "dns-resolver-blocklist/1.0", "Range": "bytes=0-0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            return {"ok": True, "warn": False, "status": code, "detail": "erişilebilir"}

    try:
        return _try("HEAD")
    except urllib.error.HTTPError as e:
        if e.code in (400, 403, 405, 501):   # HEAD desteklenmiyor olabilir → GET
            try:
                return _try("GET")
            except urllib.error.HTTPError as e2:
                return _classify(e2.code, e2.reason)
            except Exception as e2:  # noqa: BLE001
                return {"ok": False, "warn": False, "status": None, "detail": f"erişilemedi: {e2}"}
        return _classify(e.code, e.reason)
    except urllib.error.URLError as e:
        return {"ok": False, "warn": False, "status": None, "detail": f"erişilemedi: {e.reason}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "warn": False, "status": None, "detail": f"erişilemedi: {e}"}
