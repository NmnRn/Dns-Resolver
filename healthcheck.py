"""
Docker HEALTHCHECK icin: hangi sunucu(lar) aktifse, birine gercek bir DNS
sorgusu atip anlamli bir cevap gelip gelmedigini kontrol eder.

Basarili -> exit 0, basarisiz/zaman asimi -> exit 1
"""
import os
import socket
import struct
import sys

from dnslib import DNSRecord

TIMEOUT = 5
TEST_DOMAIN = "example.com"


def _recv_exact(sock, n):
    """TCP'de tam n bayt oku (kısa okumalara karşı)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("baglanti erken kapandi")
        buf += chunk
    return buf


def check_udp(port):
    q = DNSRecord.question(TEST_DOMAIN, "A")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(q.pack(), ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
        DNSRecord.parse(data)  # parse edilebiliyorsa gecerli bir DNS cevabidir
        return True
    except Exception:
        return False
    finally:
        s.close()


def check_dot(port):
    import ssl

    q = DNSRecord.question(TEST_DOMAIN, "A")
    data = q.pack()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock) as tls:
                tls.sendall(struct.pack("!H", len(data)) + data)
                length = struct.unpack("!H", _recv_exact(tls, 2))[0]
                DNSRecord.parse(_recv_exact(tls, length))
                return True
    except Exception:
        return False


def check_https(port, host):
    import http.client
    import ssl

    q = DNSRecord.question(TEST_DOMAIN, "A").pack()
    try:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=TIMEOUT, context=ctx)
        conn.request("POST", "/dns-query", body=q, headers={"Host": host})
        resp = conn.getresponse()
        ok = resp.status == 200
        if ok:
            DNSRecord.parse(resp.read())
        return ok
    except Exception:
        return False


def main():
    checks = []
    if os.getenv("ENABLE_UDP_SERVER", "true").lower() == "true":
        checks.append(("UDP", lambda: check_udp(int(os.getenv("CONTAINER_UDP_PORT", "5300")))))
    if os.getenv("ENABLE_HTTPS_SERVER", "false").lower() == "true":
        allowed_host = os.getenv("ALLOWED_HOST", "dns.example.com")
        checks.append(("DoH", lambda: check_https(int(os.getenv("CONTAINER_HTTPS_PORT", "44300")), allowed_host)))
    if os.getenv("ENABLE_DOT_SERVER", "false").lower() == "true":
        checks.append(("DoT", lambda: check_dot(int(os.getenv("CONTAINER_DOT_PORT", "8853")))))

    if not checks:
        print("healthcheck: hicbir sunucu aktif degil (config hatasi)")
        sys.exit(1)

    for name, check in checks:
        if check():
            print(f"healthcheck: {name} OK")
            sys.exit(0)

    print("healthcheck: hicbir aktif sunucu cevap vermedi")
    sys.exit(1)


if __name__ == "__main__":
    main()
