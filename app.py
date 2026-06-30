import os
import random
import socket
import struct
import threading
import urllib.request
from time import time as now
 
from dnslib import QTYPE, RCODE, EDNS0, DNSRecord
from dnslib.server import BaseResolver, DNSServer
from dotenv import load_dotenv
 
import settings
 
settings.control_env_file()
load_dotenv(settings.PROJECT_DIRECTORY / ".env")
 
 
# --- Ayarlanabilir limitler -------------------------------------------------
QUERY_TIMEOUT = 1.0     # tek sunucuya saniye cinsinden bekleme
MAX_HOPS = 16            # bir sorguda kaç delegation adımı izlenir
MAX_DEPTH = 16           # CNAME / NS-çözme özyineleme derinliği
EDNS_UDP_SIZE = 4096     # EDNS0 ile ilan ettiğimiz UDP tampon boyutu
MAX_TTL = 86400          # cache'te bir kaydı en fazla tutma süresi (sn)
NEG_TTL_CAP = 900        # negatif (NXDOMAIN/NODATA) cache üst sınırı (sn)
 
 
def _recv_exact(sock, n):
    """TCP'de tam n bayt oku (kısa okumalara karşı)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("bağlantı erken kapandı")
        buf += chunk
    return buf
 
 
def _min_ttl(records, default=300):
    """Cevaptaki RR'lerin en küçük TTL'i (RFC'ye uygun cache süresi)."""
    ttls = [r.ttl for r in records if r.ttl is not None]
    if not ttls:
        return default
    return max(0, min(ttls))
 
 
class DNSCore:
    """Forwarder'sız, tamamen recursive çözümleme çekirdeği."""
 
    def __init__(self):
        # Bilgiler https://www.iana.org/domains/root/servers adresinden alınmıştır.
        # DoH (DNS-over-HTTPS) uç noktaları: port 53 yerine 443 üzerinden,
        # normal HTTPS trafiğine karışarak gider -> DPI ile ayırt edip
        # engellemek port-53 trafiğine göre çok daha zor.
        # Not: 9.9.9.9 (Quad9) bu listede yok; bare-IP DoH ucu HTTP/2
        # zorunlu kılıyor ve urllib (HTTP/1.1) ile "505 HTTP Version Not
        # Supported" veriyor.
        self.doh_endpoints = [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
        ]
        self.root_servers = {
            "a.root-servers.net": ("198.41.0.4", "2001:503:ba3e::2:30", "Verisign, Inc."),
            "b.root-servers.net": ("170.247.170.2", "2801:1b8:10::b", "University of Southern California, ISI"),
            "c.root-servers.net": ("192.33.4.12", "2001:500:2::c", "Cogent Communications"),
            "d.root-servers.net": ("199.7.91.13", "2001:500:2d::d", "University of Maryland"),
            "e.root-servers.net": ("192.203.230.10", "2001:500:a8::e", "NASA (Ames Research Center)"),
            "f.root-servers.net": ("192.5.5.241", "2001:500:2f::f", "Internet Systems Consortium, Inc."),
            "g.root-servers.net": ("192.112.36.4", "2001:500:12::d0d", "US Department of Defense (NIC)"),
            "h.root-servers.net": ("198.97.190.53", "2001:500:1::53", "US Army (Research Lab)"),
            "i.root-servers.net": ("192.36.148.17", "2001:7fe::53", "Netnod"),
            "j.root-servers.net": ("192.58.128.30", "2001:503:c27::2:30", "Verisign, Inc."),
            "k.root-servers.net": ("193.0.14.129", "2001:7fd::1", "RIPE NCC"),
            "l.root-servers.net": ("199.7.83.42", "2001:500:9f::42", "ICANN"),
            "m.root-servers.net": ("202.12.27.33", "2001:dc3::35", "WIDE Project"),
        }
        # cache: (domain, qtype) -> (expiry, rcode, [rr, ...])
        self._cache = {}
        self._lock = threading.Lock()  # DNSServer çok-thread'li; cache'i kilitliyoruz
 
    # --- Cache ---------------------------------------------------------------
    def _cache_get(self, domain, qtype):
        key = (domain, qtype)
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            expiry, rcode, records = entry
            if now() >= expiry:
                del self._cache[key]
                return None
            return rcode, records
 
    def _cache_put(self, domain, qtype, rcode, records, ttl):
        ttl = max(0, min(ttl, MAX_TTL))
        if ttl == 0:
            return
        with self._lock:
            self._cache[(domain, qtype)] = (now() + ttl, rcode, records)
 
    @staticmethod
    def _soa_ttl(authority):
        """Negatif cache için SOA tabanlı TTL üret."""
        for a in authority:
            if QTYPE[a.rtype] == "SOA":
                # SOA.minimum ve kaydın kendi TTL'inden küçük olanı al
                soa_min = getattr(a.rdata, "minimum", NEG_TTL_CAP)
                return max(0, min(a.ttl, soa_min, NEG_TTL_CAP))
        return NEG_TTL_CAP
 
    # --- Tel üzerinde sorgu --------------------------------------------------
    def _query(self, domain, qtype, server_ip, tcp=False, timeout=QUERY_TIMEOUT):
        """Tek bir sunucuya sorgu at. TC (truncated) gelirse TCP'ye düş."""
        q = DNSRecord.question(domain, qtype)
        q.add_ar(EDNS0(udp_len=EDNS_UDP_SIZE))  # büyük cevaplar UDP'de kesilmesin
        qid = q.header.id
        sock = None
        try:
            if tcp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((server_ip, 53))
                data = q.pack()
                sock.sendall(struct.pack("!H", len(data)) + data)
                length = struct.unpack("!H", _recv_exact(sock, 2))[0]
                resp_data = _recv_exact(sock, length)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(q.pack(), (server_ip, 53))
                resp_data, _ = sock.recvfrom(EDNS_UDP_SIZE)
 
            resp = DNSRecord.parse(resp_data)
 
            # ID eşleşmiyorsa eski/sahte pakettir, güvenme
            if resp.header.id != qid:
                return None
 
            # UDP'de kesik geldiyse TCP ile tekrar dene
            if resp.header.tc and not tcp:
                return self._query(domain, qtype, server_ip, tcp=True, timeout=timeout)
 
            return resp
        except Exception:
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
 
    def _query_any(self, domain, qtype, server_ips, max_attempts=None):
        """
        Verilen sunucu listesini sırayla dene, ilk cevabı dön.
        max_attempts verilirse, o kadar timeout'tan sonra (listenin tamamını
        denemeden) pes edip None döner -> çağıran upstream'e düşebilir.
        """
        servers = list(server_ips)
        random.shuffle(servers)
        if max_attempts is not None:
            servers = servers[:max_attempts]
        for ip in servers:
            resp = self._query(domain, qtype, ip)
            if resp is not None:
                return resp
        return None

    def _query_doh(self, domain, qtype, endpoint, timeout=QUERY_TIMEOUT):
        """RFC 8484: DNS sorgusunu ham wire-format olarak HTTPS body'sinde POST eder."""
        q = DNSRecord.question(domain, qtype)
        qid = q.header.id
        req = urllib.request.Request(
            endpoint,
            data=q.pack(),
            method="POST",
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                resp_data = r.read()
            resp = DNSRecord.parse(resp_data)
            if resp.header.id != qid:
                return None
            return resp
        except Exception:
            return None

    def _query_upstream(self, domain, qtype):
        """
        Recursive yol (root/TLD/authoritative) timeout veriyorsa (muhtemelen
        DPI engeli) DoH (DNS-over-HTTPS) ile üst sunuculara direkt sor —
        port 443 üzerinden gittiği için port-53 odaklı engellemeyi atlatır.
        """
        endpoints = list(self.doh_endpoints)
        random.shuffle(endpoints)
        for endpoint in endpoints:
            resp = self._query_doh(domain, qtype, endpoint)
            if resp is not None:
                return resp
        return None
 
    # --- Asıl çözümleme ------------------------------------------------------
    def resolve(self, domain, qtype, depth=0):
        """
        (rcode, [rr, ...]) döner.
        rcode == NOERROR ve liste boşsa: NODATA (kayıt yok ama domain var).
        rcode == NXDOMAIN: domain yok.
        rcode == SERVFAIL: çözülemedi.
        """
        if depth > MAX_DEPTH:
            return RCODE.SERVFAIL, []
 
        cached = self._cache_get(domain, qtype)
        if cached is not None:
            print(f"Cache hit for {domain} ({qtype})")
            return cached
        print(f"Cache miss for {domain} ({qtype})")
 
        # Root'tan başla
        nameservers = [v[0] for v in self.root_servers.values()]
 
        for _ in range(MAX_HOPS):
            # En fazla 2 sunucu dene; 2'si de timeout verirse (muhtemelen
            # DPI engeli) listenin geri kalanını beklemeden upstream'e düş
            resp = self._query_any(domain, qtype, nameservers, max_attempts=2)
            if resp is None:
                resp = self._query_upstream(domain, qtype)
                if resp is None:
                    return RCODE.SERVFAIL, []
 
            rcode = resp.header.rcode
 
            # 1) NXDOMAIN -> negatif cache
            if rcode == RCODE.NXDOMAIN:
                self._cache_put(domain, qtype, RCODE.NXDOMAIN, [], self._soa_ttl(resp.auth))
                return RCODE.NXDOMAIN, []
 
            # 2) Cevap bölümü doluysa
            if resp.rr:
                direct = [r for r in resp.rr if QTYPE[r.rtype] == qtype]
                if direct:
                    self._cache_put(domain, qtype, RCODE.NOERROR, resp.rr, _min_ttl(resp.rr))
                    return RCODE.NOERROR, resp.rr
 
                # CNAME zinciri: hedefi ayrıca çöz, sonucu birleştir
                cnames = [r for r in resp.rr if QTYPE[r.rtype] == "CNAME"]
                if cnames:
                    target = str(cnames[-1].rdata)
                    sub_rcode, sub_rr = self.resolve(target, qtype, depth + 1)
                    merged = list(resp.rr) + list(sub_rr)
                    if sub_rr:
                        self._cache_put(domain, qtype, sub_rcode, merged, _min_ttl(merged))
                    return sub_rcode, merged
 
                # İstenen tip yok ama başka cevap var -> olduğu gibi dön
                return RCODE.NOERROR, resp.rr
 
            # 3) Cevap yok -> referral mı, NODATA mı?
            ns_records = [a for a in resp.auth if QTYPE[a.rtype] == "NS"]
            if not ns_records:
                # SOA varsa NODATA: domain var, bu tipte kayıt yok
                if any(QTYPE[a.rtype] == "SOA" for a in resp.auth):
                    self._cache_put(domain, qtype, RCODE.NOERROR, [], self._soa_ttl(resp.auth))
                return RCODE.NOERROR, []
 
            # Referral: önce glue (additional) içinde A kaydı ara
            ns_names = {str(a.rdata).rstrip(".").lower() for a in ns_records}
            glue = [
                str(r.rdata) for r in resp.ar
                if QTYPE[r.rtype] == "A" and str(r.rname).rstrip(".").lower() in ns_names
            ]
            if not glue:  # ada özel glue yoksa additional'daki herhangi bir A'yı dene
                glue = [str(r.rdata) for r in resp.ar if QTYPE[r.rtype] == "A"]
 
            if glue:
                nameservers = glue
                continue
 
            # Glue yok: NS adlarını ayrı ayrı çözmeyi dene
            resolved = None
            for ns in ns_records:
                sub_rcode, sub_rr = self.resolve(str(ns.rdata), "A", depth + 1)
                a_ips = [str(r.rdata) for r in sub_rr if QTYPE[r.rtype] == "A"]
                if a_ips:
                    resolved = a_ips
                    break
            if not resolved:
                return RCODE.SERVFAIL, []
            nameservers = resolved
            # döngü devam: yeni nameserver'lara sor
 
        # MAX_HOPS aşıldı
        return RCODE.SERVFAIL, []
 
 
class DNSResolver(BaseResolver):
    """dnslib köprüsü: gelen UDP isteğini DNSCore'a bağlar."""
 
    def __init__(self):
        self.core = DNSCore()
 
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        if not qname.endswith("."):
            qname += "."
        qtype = QTYPE[request.q.qtype]
 
        rcode, records = self.core.resolve(qname, qtype)
 
        reply = request.reply()
        if rcode == RCODE.NXDOMAIN:
            reply.header.rcode = RCODE.NXDOMAIN
        elif rcode == RCODE.SERVFAIL:
            reply.header.rcode = RCODE.SERVFAIL
        else:
            reply.rr = list(records)
        return reply
 
 
def main():
    port = int(os.getenv("UDP_PORT", "53"))
    bind = os.getenv("BIND_ADDRESS", "127.0.0.1")
    server = DNSServer(DNSResolver(), port=port, address=bind)
    print(f"DNS sunucusu başlatıldı: {bind}:{port}")
    server.start()
 
 
if __name__ == "__main__":
    main()

"""Proje Gelişmeye Devam Ediyor. Bu yüzden bazı kısımlar eksik olabilir. Lütfen eksik kısımları tamamlayın ve projeyi geliştirmeye devam edin."""

