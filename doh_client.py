"""DoH (DNS-over-HTTPS) istemcisi — ÖNCE HTTP/2, olmazsa HTTP/1.1.

quad9 gibi bazı DoH uçları HTTP/2 zorunlu kılıp HTTP/1.1'i 505 ile reddediyor;
Cloudflare/Google ikisini de kabul ediyor. `httpx` (http2=True) TLS ALPN ile en
yüksek ortak sürümü seçer → h2 varsa h2, yoksa h1.1. Böylece "önce 2, olmazsa 1"
tek istekte, otomatik el sıkışmayla olur.

RFC 8484 GET (base64url) yöntemi kullanılır: sorgu URL'de gider, gövde yoktur.
(httpcore'un HTTP/2 POST-gövdesi Python 3.14'te hatalı — GET bu yolu hiç kullanmaz.)

httpx kurulu değilse urllib'e (yalnız HTTP/1.1, POST) düşer — o durumda HTTP/2
zorunlu uçlar yine 505 verir. Resolver + panel testi aynı modülü paylaşır.
"""
import base64
import logging
import urllib.request

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


def doh_query(url: str, query_wire: bytes, timeout: float = 5.0) -> bytes:
    """DoH sunucusuna wire-format DNS sorgusu gönderip cevabın gövdesini (bytes) döndürür.

    httpx varsa: HTTP/2-öncelikli GET (ALPN ile HTTP/1.1'e düşer).
    yoksa:       urllib POST (yalnız HTTP/1.1).
    Hata (HTTP kodu / ağ) yukarıya yükseltilir; çağıran ele alır.
    """
    if httpx is not None:
        dns = base64.urlsafe_b64encode(query_wire).decode("ascii").rstrip("=")
        with httpx.Client(http2=True, timeout=timeout) as client:
            resp = client.get(url, params={"dns": dns}, headers=_ACCEPT)
            resp.raise_for_status()
            return resp.content
    req = urllib.request.Request(url, data=query_wire, method="POST", headers=_POST_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()
