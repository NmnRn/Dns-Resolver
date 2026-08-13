"""Panelden 'Sunucuları test et': her upstream'e örnek bir DNS sorgusu atıp
yanıt + gecikme ölçer. Senkron (Django view'da asyncio.to_thread ile çağrılır).
Protokol ön eke göre: düz IP/udp:// (UDP), https:// (DoH), tls:// (DoT).
"""
import socket
import ssl
import struct
import time
import urllib.request

from dnslib import DNSRecord


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("bağlantı erken kapandı")
        buf += chunk
    return buf


def test_upstream(up, timeout=3):
    """(dict) up / ok(True/False/None) / ms / detail. None = test desteklenmiyor."""
    up = up.strip()
    low = up.lower()
    q = DNSRecord.question("example.com", "A")
    t0 = time.time()
    try:
        if low.startswith("https://"):
            req = urllib.request.Request(
                up, data=q.pack(), method="POST",
                headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                DNSRecord.parse(r.read())
        elif low.startswith("tls://"):
            host, _, port = up[6:].partition(":")
            ctx = ssl.create_default_context()
            raw = socket.create_connection((host, int(port) if port else 853), timeout=timeout)
            s = ctx.wrap_socket(raw, server_hostname=host)
            s.settimeout(timeout)
            data = q.pack()
            s.sendall(struct.pack("!H", len(data)) + data)
            ln = struct.unpack("!H", _recv_exact(s, 2))[0]
            DNSRecord.parse(_recv_exact(s, ln))
            s.close()
        elif low.startswith("quic://"):
            return {"up": up, "ok": None, "ms": 0, "detail": "DoQ testi desteklenmiyor"}
        else:
            host = (up[6:] if low.startswith("udp://") else up).split(":")[0]
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(q.pack(), (host, 53))
            DNSRecord.parse(s.recvfrom(4096)[0])
            s.close()
        return {"up": up, "ok": True, "ms": round((time.time() - t0) * 1000), "detail": ""}
    except Exception as exc:
        return {"up": up, "ok": False, "ms": round((time.time() - t0) * 1000), "detail": type(exc).__name__}
