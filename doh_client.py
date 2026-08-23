"""DoH (DNS-over-HTTPS) istemcisi — ÖNCE HTTP/2, olmazsa HTTP/1.1 + Bootstrap DNS.

quad9 gibi bazı DoH uçları HTTP/2 zorunlu kılıp HTTP/1.1'i 505 ile reddediyor;
Cloudflare/Google ikisini de kabul ediyor. `httpx` (http2=True) TLS ALPN ile en
yüksek ortak sürümü seçer → h2 varsa h2, yoksa h1.1.

RFC 8484 GET (base64url) yöntemi kullanılır: sorgu URL'de gider, gövde yoktur.
(httpcore'un HTTP/2 POST-gövdesi Python 3.14'te hatalı — GET bu yolu hiç kullanmaz.)

Bootstrap DNS: bir upstream'in host adı (ör. dns.google) verilip bootstrap IP
belirtilirse, host adı o düz-DNS sunucusuna sorulup IP'ye çevrilir; bağlantı IP'ye
kurulur ama TLS SNI + sertifika doğrulaması ORİJİNAL host adına yapılır. Böylece
şifreli upstream'ler sistem çözümleyicisine bağımlı kalmaz (chicken-and-egg'i önler).

httpx kurulu değilse urllib'e (yalnız HTTP/1.1, POST) düşer. Resolver + panel paylaşır.
"""
import base64
import ipaddress
import logging
import secrets
import socket
import urllib.request
from urllib.parse import urlsplit, urlunsplit

from dnslib import DNSRecord, QTYPE

try:
    import httpx
    # Mahremiyet: httpx her isteği "HTTP Request: GET .../dns-query?dns=<base64>"
    # diye INFO log'lar; o base64 sorgulanan DOMAIN'i içerir → docker log'a sızmasın.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
except Exception:   # httpx yoksa HTTP/2 devre dışı; urllib ile devam
    httpx = None

_ACCEPT = {"Accept": "application/dns-message"}
_POST_HEADERS = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}


def http2_available() -> bool:
    return httpx is not None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def bootstrap_resolve(bootstrap_ip: str, hostname: str, timeout: float = 3.0) -> str:
    """hostname'i bootstrap DNS sunucusuna (düz UDP/53) sorup ilk A kaydını (IP)
    döndürür. Çözemezse hostname'i AYNEN döndürür → çağıran sistem çözümlemesine düşer."""
    try:
        q = DNSRecord.question(hostname, "A")
        q.header.id = secrets.randbelow(65536)   # CSPRNG txid → off-path spoofing direnci
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(q.pack(), (bootstrap_ip, 53))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()
        resp = DNSRecord.parse(data)
        # Sahte/eski paketi reddet: yanıt id'si + soru adı sorguyla EŞLEŞMELİ.
        if (resp.header.id != q.header.id or
                str(resp.q.qname).rstrip(".").lower() != hostname.rstrip(".").lower()):
            return hostname
        for rr in resp.rr:
            if QTYPE[rr.rtype] == "A":
                return str(rr.rdata)
    except Exception:
        pass
    return hostname


def _bootstrap_target(url: str, ip: str) -> str:
    """URL'nin host'unu ip ile değiştirip yeni URL döndür (yol/port/query korunur).
    Bağlantı IP'ye kurulur; Host header + SNI orijinal ad çağıranda ayrıca ayarlanır."""
    parts = urlsplit(url)
    netloc = ip + (":%d" % parts.port if parts.port else "")
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def doh_query(url: str, query_wire: bytes, timeout: float = 5.0, bootstrap: str = "") -> bytes:
    """DoH sunucusuna wire-format DNS sorgusu gönderip cevabın gövdesini (bytes) döndürür.

    httpx varsa: HTTP/2-öncelikli GET (ALPN ile HTTP/1.1'e düşer). bootstrap (düz IP)
    verilir ve URL host'u ad ise → host bootstrap ile IP'ye çevrilir, IP'ye bağlanılır
    ama Host header + SNI orijinal ad kalır. yoksa: urllib POST (yalnız HTTP/1.1).
    """
    if httpx is not None:
        dns = base64.urlsafe_b64encode(query_wire).decode("ascii").rstrip("=")
        target, headers, extensions = url, dict(_ACCEPT), None
        host = urlsplit(url).hostname
        if bootstrap and host and not _is_ip(host):
            ip = bootstrap_resolve(bootstrap, host, timeout)
            if ip != host:
                target = _bootstrap_target(url, ip)
                headers["Host"] = host                 # IP'ye bağlan ama Host + SNI orijinal ad
                extensions = {"sni_hostname": host}
        kw = {"params": {"dns": dns}, "headers": headers}
        if extensions:
            kw["extensions"] = extensions
        with httpx.Client(http2=True, timeout=timeout) as client:
            resp = client.get(target, **kw)
            resp.raise_for_status()
            return resp.content
    req = urllib.request.Request(url, data=query_wire, method="POST", headers=_POST_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()
