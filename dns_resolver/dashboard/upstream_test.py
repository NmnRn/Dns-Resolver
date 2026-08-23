"""Panelden 'Sunucuları test et': her upstream'e örnek bir DNS sorgusu atıp
yanıt + gecikme ölçer. Senkron (Django view'da asyncio.to_thread ile çağrılır).
Protokol ön eke göre: düz IP/udp:// (UDP), tcp:// (TCP), https:// (DoH), tls:// (DoT),
quic:// (DoQ — henüz desteklenmiyor).
"""
import socket
import ssl
import struct
import time

import doh_client
from dnslib import DNSRecord


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("bağlantı erken kapandı")
        buf += chunk
    return buf


def _split_host_port(addr, default_port):
    """host:port ayır — IPv6 farkındalıklı: [ipv6]:port, düz ipv6 (port yok), ipv4[:port]."""
    addr = addr.strip()
    if addr.startswith('['):                       # [ipv6]:port
        host, _, rest = addr[1:].partition(']')
        port = int(rest[1:]) if rest.startswith(':') and rest[1:].isdigit() else default_port
        return host, port
    if addr.count(':') >= 2:                        # düz IPv6 (port belirtilemez)
        return addr, default_port
    host, _, p = addr.partition(':')                # ipv4[:port] / host[:port]
    return host, (int(p) if p.isdigit() else default_port)


def test_upstream(up, timeout=3):
    """(dict) up / ok(True/False/None) / ms / detail. None = test desteklenmiyor."""
    up = up.strip()
    low = up.lower()
    q = DNSRecord.question("example.com", "A")
    t0 = time.time()
    try:
        if low.startswith("https://"):
            DNSRecord.parse(doh_client.doh_query(up, q.pack(), timeout))   # önce HTTP/2, olmazsa HTTP/1.1
        elif low.startswith("tls://"):
            host, port = _split_host_port(up[6:], 853)
            ctx = ssl.create_default_context()
            raw = socket.create_connection((host, port), timeout=timeout)
            s = ctx.wrap_socket(raw, server_hostname=host)
            s.settimeout(timeout)
            data = q.pack()
            s.sendall(struct.pack("!H", len(data)) + data)
            ln = struct.unpack("!H", _recv_exact(s, 2))[0]
            DNSRecord.parse(_recv_exact(s, ln))
            s.close()
        elif low.startswith("tcp://"):
            host, port = _split_host_port(up[6:], 53)
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            data = q.pack()
            s.sendall(struct.pack("!H", len(data)) + data)
            ln = struct.unpack("!H", _recv_exact(s, 2))[0]
            DNSRecord.parse(_recv_exact(s, ln))
            s.close()
        elif low.startswith("quic://"):
            return {"up": up, "ok": None, "ms": 0, "detail": "DoQ testi desteklenmiyor"}
        else:
            addr = up[6:] if low.startswith("udp://") else up
            host, port = _split_host_port(addr, 53)      # düz IP[:port] (IPv6 farkındalıklı)
            info = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]  # IPv4/IPv6 otomatik
            s = socket.socket(info[0], socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(q.pack(), info[4])
            DNSRecord.parse(s.recvfrom(4096)[0])
            s.close()
        return {"up": up, "ok": True, "ms": round((time.time() - t0) * 1000), "detail": ""}
    except Exception as exc:
        # HTTP durum kodu: httpx.HTTPStatusError.response.status_code ya da urllib HTTPError.code.
        code = getattr(getattr(exc, "response", None), "status_code", None) or getattr(exc, "code", None)
        if code == 505:
            detail = "HTTP 505 — HTTP/2 gerekli (httpx kurulu değil)"
        elif code:
            detail = f"HTTP {code}"
        else:
            detail = type(exc).__name__
        return {"up": up, "ok": False, "ms": round((time.time() - t0) * 1000), "detail": detail}
