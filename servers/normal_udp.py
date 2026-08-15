import concurrent.futures
import ipaddress
import random
import socket
import ssl
import struct
import threading
import urllib.request
from time import time as now

from dnslib import QTYPE, RCODE, EDNS0, DNSRecord, RR, CNAME, A, AAAA
from dnslib.server import BaseResolver, DNSLogger
from dotenv import load_dotenv

from project_control import settings

settings.control_env_file()
load_dotenv(settings.PROJECT_DIRECTORY / ".env")

from logs.dns_logs import logger
import doh_client   # DoH: önce HTTP/2, olmazsa HTTP/1.1 (resolver + panel paylaşır)


# --- Ayarlanabilir limitler -------------------------------------------------
QUERY_TIMEOUT = 1.0     # tek sunucuya saniye cinsinden bekleme
MAX_HOPS = 16            # bir sorguda kaç delegation adımı izlenir
MAX_DEPTH = 16           # CNAME / NS-çözme özyineleme derinliği
EDNS_UDP_SIZE = 4096     # EDNS0 ile ilan ettiğimiz UDP tampon boyutu
MAX_TTL = 86400          # cache'te bir kaydı en fazla tutma süresi (sn)
NEG_TTL_CAP = 900        # negatif (NXDOMAIN/NODATA) cache üst sınırı (sn)
REWRITE_TTL = 300        # DNS rewrite (elle tanımlı kayıt) cevaplarının TTL'i (sn)

# Güvenli arama: motor -> (görünen ad, zorunlu güvenli hedef). Panelde motor başına seçilir.
SAFE_SEARCH_ENGINES = {
    "google":     ("Google", "forcesafesearch.google.com"),
    "youtube":    ("YouTube", "restrict.youtube.com"),
    "bing":       ("Bing", "strict.bing.com"),
    "duckduckgo": ("DuckDuckGo", "safe.duckduckgo.com"),
    "yandex":     ("Yandex", "familysearch.yandex.ru"),
    "pixabay":    ("Pixabay", "safesearch.pixabay.com"),
}
# alan adı -> motor (Google tüm ülke uzantıları jenerik ele alınır, aşağıda).
_SS_DOMAIN_ENGINE = {
    "youtube.com": "youtube", "www.youtube.com": "youtube", "m.youtube.com": "youtube",
    "youtubei.googleapis.com": "youtube", "youtube.googleapis.com": "youtube",
    "www.youtube-nocookie.com": "youtube",
    "bing.com": "bing", "www.bing.com": "bing",
    "duckduckgo.com": "duckduckgo", "www.duckduckgo.com": "duckduckgo",
    "yandex.com": "yandex", "yandex.ru": "yandex", "yandex.by": "yandex", "yandex.kz": "yandex",
    "yandex.com.tr": "yandex", "www.yandex.com": "yandex", "www.yandex.ru": "yandex",
    "pixabay.com": "pixabay", "www.pixabay.com": "pixabay",
}


def safesearch_lookup(domain):
    """(motor_id, hedef) döner; güvenli arama alanı değilse (None, None).
    Google tüm ülke uzantılarını (google.<tld>) kapsar."""
    name = domain.rstrip(".").lower()
    eng = _SS_DOMAIN_ENGINE.get(name)
    if not eng:
        base = name[4:] if name.startswith("www.") else name
        labels = base.split(".")
        if labels[0] == "google" and 2 <= len(labels) <= 3:
            eng = "google"
    if eng:
        return eng, SAFE_SEARCH_ENGINES[eng][1]
    return None, None


class QuietDNSLogger(DNSLogger):
    """dnslib DNSServer'ın açık Request/Reply loglarını susturur.

    Mahremiyet: istemci IP + sorgulanan ad stdout'a (docker logs) YAZILMAZ;
    gerçek değerler yalnız DB'de tutulur. Kendi maskeli özet satırımız
    (DNSResolver.resolve içindeki '**** **** ...') zaten yazılıyor.
    """
    def log_request(self, *a, **k): pass
    def log_reply(self, *a, **k): pass
    def log_recv(self, *a, **k): pass
    def log_send(self, *a, **k): pass
    def log_truncated(self, *a, **k): pass
    def log_data(self, *a, **k): pass
    def log_error(self, *a, **k): pass


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
 
    def __init__(self, db_manager):
        self.db_manager = db_manager
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
        self._cache = {} # {"domain.com", "A"}: (expiry_timestamp, rcode, [rr1, rr2, ...])
        self._lock = threading.Lock()  # DNSServer çok-thread'li; cache'i kilitliyoruz
        # Engelleme (AdGuard tarzı): bellekte set, DB'den periyodik yenilenir.
        # is_blocked hot-path'te → sorgu başına DB'ye GİTMEYİZ. Değişim atomiktir
        # (yeni frozenset referansı atanır; kilit gerekmez).
        self.manual_block = frozenset()   # elle eklenen engeller (blocklist tablosu)
        self.allowset = frozenset()
        self.list_sets = {}               # {liste_adı: frozenset} — hangi liste eşleşti izlenir
        self.safesearch_engines = set()   # güvenli arama açık motorlar (panelden seçilir)
        # DNS rewrites (elle tanımlı kayıt): {domain|*.sonek: cevap(IP ya da hedef domain)}.
        # Panelden yönetilir, _refresh_filters ile atomik yenilenir; is_blocked'tan önce bakılır.
        self.rewrites = {}
        # Erişim kontrolü + rate limit (panelden; app.py periyodik uygular).
        self.client_allow = frozenset()   # boş = herkes; doluysa YALNIZ bunlar sorabilir
        self.client_deny = frozenset()    # her zaman reddedilen istemciler
        self.rate_limit = 0               # istemci başına saniyede sorgu (0 = kapalı)
        self._rate = {}                   # ip -> (pencere_başı, sayı)
        self._rate_lock = threading.Lock()
        # Önbellek ayarları (panelden, app.py periyodik uygular).
        self.cache_enabled = True
        self.cache_min_ttl = 0            # 0 = alt sınır yok (kısa TTL'leri yukarı çekmez)
        self.cache_max_ttl = MAX_TTL      # üst sınır
        # Çözümleme modu: recursion (kendi çekirdeğimiz) vs forwarding (upstream'lere ilet).
        self.use_recursion = True
        self.upstreams = []               # ['1.1.1.1', 'https://…/dns-query', 'tls://…'] (forwarding)
        self.upstream_strategy = "sequential"   # sequential | parallel | fastest
        # Koşullu forwarding: [(son-ek, upstream)] — eşleşen domaini belirli bir
        # upstream'e çözdürür (use_recursion'dan bağımsız). Panelden ayarlanır.
        self.conditionals = []
        # Kaynak bazında işlem süresi: 'DNS çekirdeği' / 'Önbellek' / upstream -> (sayı, toplam_ms)
        self.source_stats = {}
        self._stat_lock = threading.Lock()

    # --- Cache ---------------------------------------------------------------
    def _cache_get(self, domain, qtype):
        if not self.cache_enabled:
            return None
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
        if not self.cache_enabled:
            return
        ttl = min(max(0, int(ttl)), self.cache_max_ttl)
        if ttl > 0 and self.cache_min_ttl > 0:          # kısa TTL'i alt sınıra çek
            ttl = min(max(ttl, self.cache_min_ttl), self.cache_max_ttl)
        if ttl == 0:
            return
        with self._lock:
            self._cache[(domain, qtype)] = (now() + ttl, rcode, records)

    def clear_cache(self):
        """Bellekteki çözümleme önbelleğini boşalt (panelden tetiklenir). Boşalan sayı."""
        with self._lock:
            n = len(self._cache)
            self._cache.clear()
        return n

    # --- Erişim kontrolü + rate limit ----------------------------------------
    @staticmethod
    def _ip_matches(ip, entries):
        """ip, entries (IP ya da CIDR kümesi) ile eşleşiyor mu?"""
        if not entries:
            return False
        if ip in entries:                         # birebir hızlı yol
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for e in entries:
            if "/" in e:
                try:
                    if addr in ipaddress.ip_network(e, strict=False):
                        return True
                except ValueError:
                    pass
        return False

    def is_client_allowed(self, ip):
        """deny'deyse ya da allow doluyken allow'da değilse False."""
        if self._ip_matches(ip, self.client_deny):
            return False
        if self.client_allow and not self._ip_matches(ip, self.client_allow):
            return False
        return True

    def is_rate_limited(self, ip):
        """İstemci saniyelik limiti aştı mı? (0 = kapalı). Sayaç bu çağrıda artar."""
        if self.rate_limit <= 0:
            return False
        t = now()
        with self._rate_lock:
            win, cnt = self._rate.get(ip, (0.0, 0))
            if t - win >= 1.0:
                self._rate[ip] = (t, 1)
                return False
            cnt += 1
            self._rate[ip] = (win, cnt)
            return cnt > self.rate_limit

    def access_ok(self, ip):
        """İstemci sorguya devam edebilir mi (ACL + rate limit)."""
        if not self.is_client_allowed(ip):
            return False
        return not self.is_rate_limited(ip)
 
    @staticmethod
    def _soa_ttl(authority):
        """Negatif cache için SOA tabanlı TTL üret."""
        for a in authority:
            if QTYPE[a.rtype] == "SOA":
                # SOA minimum'u ile kaydın kendi TTL'inden küçük olanı al.
                # dnslib'de minimum ayrı bir alan değil; SOA.times tuple'ının
                # 5. elemanında durur: (serial, refresh, retry, expire, minimum).
                times = getattr(a.rdata, "times", None)
                soa_min = times[4] if times and len(times) >= 5 else NEG_TTL_CAP
                return max(0, min(a.ttl, soa_min, NEG_TTL_CAP))
        return NEG_TTL_CAP
 
    # --- Engelleme (blocklist / allowlist) -----------------------------------
    def update_filter_lists(self, manual_block, allowset, list_sets=None):
        """Elle engeller + izinliler + liste-bazlı kümeleri atomik olarak değiştirir."""
        self.manual_block = frozenset(manual_block)
        self.allowset = frozenset(allowset)
        self.list_sets = dict(list_sets or {})

    def is_blocked(self, domain):
        """
        Engelliyse eşleşen liste ADINI (str) döner, engelli değilse None. allowlist
        ÖNCELİKLİDİR. 'ads.doubleclick.net' -> ['ads.doubleclick.net','doubleclick.net',
        'net'] adaylarından biri manuel listede ya da bir abonelik listesinde varsa
        (ve allowset'te yoksa) engellenir; önce eşleşen listenin adı döner.
        """
        name = domain.rstrip(".").lower()
        if not name:
            return None
        labels = name.split(".")
        candidates = [".".join(labels[i:]) for i in range(len(labels))]
        if any(c in self.allowset for c in candidates):
            return None
        if any(c in self.manual_block for c in candidates):
            return "Elle eklenen"
        for src_name, s in self.list_sets.items():
            if any(c in s for c in candidates):
                return src_name
        return None

    # --- DNS rewrites (elle tanımlı kayıt) -----------------------------------
    def _lookup_rewrite(self, domain):
        """Elle tanımlı DNS rewrite'ı bulur: önce tam eşleşme, sonra '*.sonek'
        wildcard (alt alanlar). Eşleşen cevabı (IP ya da hedef domain) döner,
        yoksa None. is_blocked ile aynı en-spesifik-önce mantığı."""
        rules = self.rewrites
        if not rules:
            return None
        name = domain.rstrip(".").lower()
        if not name:
            return None
        if name in rules:                       # tam eşleşme önceliklidir
            return rules[name]
        labels = name.split(".")
        for i in range(1, len(labels)):         # *.sonek wildcard (yalnız alt alanlar)
            w = "*." + ".".join(labels[i:])
            if w in rules:
                return rules[w]
        return None

    def _rewrite_response(self, domain, qtype, answer, depth):
        """Rewrite cevabını DNS kaydına çevirir. answer bir IP ise A/AAAA döner
        (istenen tip uyuşmazsa NODATA); bir domain ise CNAME + hedefi normal çöz.
        0.0.0.0 / :: gibi cevaplar da geçerli IP'dir → sinkhole olarak döner."""
        try:
            ip = ipaddress.ip_address(answer)
        except ValueError:
            ip = None
        if ip is not None:
            want = "A" if ip.version == 4 else "AAAA"
            if qtype != want:
                return RCODE.NOERROR, []        # IP var ama istenen tip değil → NODATA
            qt = QTYPE.A if ip.version == 4 else QTYPE.AAAA
            rd = A(answer) if ip.version == 4 else AAAA(answer)
            return RCODE.NOERROR, [RR(domain, qt, ttl=REWRITE_TTL, rdata=rd)]
        # answer bir domain → CNAME zinciri + hedefi normal çöz (özyineleme derinlik korumalı)
        target = answer.rstrip(".")
        sub_rcode, sub_rr = self.resolve(target + ".", qtype, depth + 1)
        cname = RR(domain, QTYPE.CNAME, ttl=REWRITE_TTL, rdata=CNAME(target))
        return sub_rcode, [cname] + list(sub_rr)

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
        """RFC 8484 DoH — önce HTTP/2, olmazsa HTTP/1.1 (doh_client, ALPN)."""
        q = DNSRecord.question(domain, qtype)
        qid = q.header.id
        try:
            resp = DNSRecord.parse(doh_client.doh_query(endpoint, q.pack(), timeout))
            return resp if resp.header.id == qid else None
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

    # --- Forwarding (upstream'e iletme) --------------------------------------
    def _query_dot(self, domain, qtype, host, port=853, timeout=QUERY_TIMEOUT):
        """DoT istemci: host:port'a TLS ile bağlan, uzunluk-önekli DNS gönder/al."""
        q = DNSRecord.question(domain, qtype)
        q.add_ar(EDNS0(udp_len=EDNS_UDP_SIZE))
        qid = q.header.id
        sock = None
        try:
            ctx = ssl.create_default_context()
            raw = socket.create_connection((host, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=host)
            sock.settimeout(timeout)
            data = q.pack()
            sock.sendall(struct.pack("!H", len(data)) + data)
            length = struct.unpack("!H", _recv_exact(sock, 2))[0]
            resp = DNSRecord.parse(_recv_exact(sock, length))
            return resp if resp.header.id == qid else None
        except Exception:
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _query_forward_one(self, domain, qtype, upstream):
        """Tek bir upstream'e ilet — protokolü ön eke göre seç (https/tls/udp/düz IP)."""
        u = upstream.strip()
        if not u:
            return None
        low = u.lower()
        try:
            if low.startswith("https://"):
                return self._query_doh(domain, qtype, u)
            if low.startswith("tls://"):
                host, _, port = u[6:].partition(":")
                return self._query_dot(domain, qtype, host, int(port) if port else 853)
            if low.startswith("quic://"):
                logger.warning("DoQ upstream henuz desteklenmiyor, atlaniyor.")
                return None
            if low.startswith("udp://"):
                u = u[6:]
            host = u.split(":")[0]          # düz IP / host (port 53 varsayılır)
            return self._query(domain, qtype, host)
        except Exception:
            return None

    def record_source_time(self, source, ms):
        """Çözüm kaynağının işlem süresini kaydet (ortalama için). '—'/boş atlanır."""
        if not source or source == "—":
            return
        with self._stat_lock:
            c, t = self.source_stats.get(source, (0, 0.0))
            self.source_stats[source] = (c + 1, t + ms)

    def _upstream_avg(self, up):
        """Upstream ortalama süresi (ms); ölçüm yoksa +inf → 'fastest' sıralamasında sona."""
        with self._stat_lock:
            c, t = self.source_stats.get(up, (0, 0.0))
        return (t / c) if c else float("inf")

    def _forward(self, domain, qtype):
        """Forwarding: stratejiye göre upstream'lere ilet → (cevap, kullanılan_upstream)."""
        ups = list(self.upstreams)
        if not ups:
            return None, None
        if self.upstream_strategy == "parallel":
            return self._forward_parallel(domain, qtype, ups)
        if self.upstream_strategy == "fastest":
            ups.sort(key=self._upstream_avg)          # ölçülen en hızlı önce
        for up in ups:                                 # sequential / fastest-ordered
            resp = self._query_forward_one(domain, qtype, up)
            if resp is not None:
                return resp, up
        return None, None

    def _forward_parallel(self, domain, qtype, ups):
        """Tüm upstream'lere aynı anda sor, ilk gelen cevabı dön (yarış)."""
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=len(ups))
        try:
            futs = {ex.submit(self._query_forward_one, domain, qtype, up): up for up in ups}
            for fut in concurrent.futures.as_completed(futs, timeout=QUERY_TIMEOUT + 2):
                up = futs[fut]
                try:
                    resp = fut.result()
                except Exception:
                    resp = None
                if resp is not None:
                    return resp, up
        except Exception:
            pass
        finally:
            ex.shutdown(wait=False)
        return None, None

    def _match_conditional(self, domain):
        """Koşullu forwarding: domain bir son-ek kuralıyla eşleşiyorsa o upstream'i
        döner (en uzun/en spesifik son-ek kazanır), yoksa None. 'home.arpa' hem
        'home.arpa'yı hem tüm alt alanlarını (x.home.arpa) kapsar."""
        if not self.conditionals:
            return None
        name = domain.rstrip(".").lower()
        best = None
        for suffix, up in self.conditionals:
            if name == suffix or name.endswith("." + suffix):
                if best is None or len(suffix) > len(best[0]):
                    best = (suffix, up)
        return best[1] if best else None

    def _forward_result(self, domain, qtype, resp):
        """Forward cevabını (DNSRecord | None) → (rcode, [rr]) + önbelleğe yaz.
        Normal forwarding ile koşullu forwarding'in ORTAK sonuç işleme mantığı."""
        if resp is None:
            return RCODE.SERVFAIL, []
        rcode = resp.header.rcode
        if rcode == RCODE.NXDOMAIN:
            self._cache_put(domain, qtype, RCODE.NXDOMAIN, [], self._soa_ttl(resp.auth))
            return RCODE.NXDOMAIN, []
        if resp.rr:
            self._cache_put(domain, qtype, rcode, list(resp.rr), _min_ttl(resp.rr))
            return rcode, list(resp.rr)
        if any(QTYPE[a.rtype] == "SOA" for a in resp.auth):
            self._cache_put(domain, qtype, RCODE.NOERROR, [], self._soa_ttl(resp.auth))
        return rcode, []

    # --- Asıl çözümleme ------------------------------------------------------
    def resolve(self, domain, qtype, depth=0, source=None):
        """En dış (depth 0) çağrıda işlem süresini kaynağa göre ölçen sarmalayıcı."""
        if depth != 0:
            return self._resolve(domain, qtype, depth, source)
        src = source if source is not None else ["—"]
        t0 = now()
        result = self._resolve(domain, qtype, 0, src)
        self.record_source_time(src[0], (now() - t0) * 1000.0)
        return result

    def _resolve(self, domain, qtype, depth=0, source=None):
        """
        (rcode, [rr, ...]) döner. `source` verilirse (1 elemanlı liste), çözümün
        nereden geldiği yazılır: 'Önbellek' / 'DNS çekirdeği' / upstream adresi.
        rcode == NOERROR ve liste boşsa: NODATA (kayıt yok ama domain var).
        rcode == NXDOMAIN: domain yok.
        rcode == SERVFAIL: çözülemedi.
        """
        if depth > MAX_DEPTH:
            return RCODE.SERVFAIL, []

        # DNS rewrite: elle tanımlı domain→cevap (yerel kayıt). is_blocked'tan ÖNCE
        # bakılır — açık kullanıcı tanımı hem engel hem izin listesine göre önceliklidir.
        _rw = self._lookup_rewrite(domain)
        if _rw is not None:
            if source is not None:
                source[0] = "DNS rewrite"
            return self._rewrite_response(domain, qtype, _rw, depth)

        # Engelleme: blocklist'teki (ya da üst alanı engelli) domain çözülmez.
        if self.is_blocked(domain):
            logger.info("ENGELLENDİ **** (%s)", qtype)
            return RCODE.NXDOMAIN, []

        # Güvenli arama: seçili motoru zorunlu güvenli varyanta CNAME'le yönlendir.
        if self.safesearch_engines and qtype in ("A", "AAAA", "HTTPS"):
            eng, target = safesearch_lookup(domain)
            if target and eng in self.safesearch_engines:
                sub_rcode, sub_rr = self.resolve(target + ".", qtype, depth + 1)
                if source is not None:
                    source[0] = "Güvenli arama"
                cname = RR(domain, QTYPE.CNAME, ttl=300, rdata=CNAME(target))
                return sub_rcode, [cname] + list(sub_rr)

        cached = self._cache_get(domain, qtype)
        if cached is not None:
            logger.debug("Cache hit for **** (%s)", qtype)
            if source is not None:
                source[0] = "Önbellek"   # kaynağı bilinmez (çekirdek ya da upstream) → dürüstçe "Önbellek"
            return cached
        logger.debug("Cache miss for **** (%s)", qtype)

        # Koşullu forwarding: bir son-ek eşleşiyorsa domaini BELİRLİ bir upstream'e
        # çözdür (use_recursion'dan bağımsız — split-horizon; ör. *.home.arpa → router).
        cond_up = self._match_conditional(domain)
        if cond_up:
            resp = self._query_forward_one(domain, qtype, cond_up)
            if source is not None:
                source[0] = cond_up
            return self._forward_result(domain, qtype, resp)

        # Forwarding modu: kendi çekirdeğimiz kapalıysa upstream'lere ilet (recursion yok).
        if not self.use_recursion and self.upstreams:
            resp, used = self._forward(domain, qtype)
            if source is not None:
                source[0] = used or "upstream"
            return self._forward_result(domain, qtype, resp)

        if source is not None:
            source[0] = "DNS çekirdeği"
        # QNAME Minimisation (RFC 7816 / RFC 9156): her hop'ta tam ismi değil,
        # o an gereken kadar etiketi gönderiyoruz. Böylece root/TLD gibi asıl
        # kaydı hiç bilmeyen sunucular, kullanıcının tam olarak hangi ismi
        # sorduğunu görmüyor - sadece kendi delegasyon alanlarını görüyorlar.
        labels = domain.rstrip(".").split(".")
        total_labels = len(labels)
        label_count = 1
 
        # Root'tan başla
        nameservers = [v[0] for v in self.root_servers.values()]
 
        for _ in range(MAX_HOPS):
            is_final_step = label_count >= total_labels
            if is_final_step:
                step_qname, step_qtype = domain, qtype
            else:
                step_qname = ".".join(labels[total_labels - label_count:]) + "."
                step_qtype = "NS"
 
            # En fazla 2 sunucu dene; 2'si de timeout verirse (muhtemelen
            # DPI engeli) listenin geri kalanını beklemeden upstream'e düş
            resp = self._query_any(step_qname, step_qtype, nameservers, max_attempts=2)
            via_upstream = False
            if resp is None:
                # Upstream'e düşerken minimizasyonu bırakıp doğrudan asıl
                # ismi/tipi soruyoruz - amaç burada gizlilik değil, DPI
                # engelini aşıp en azından bir cevap alabilmek
                resp = self._query_upstream(domain, qtype)
                if resp is None:
                    return RCODE.SERVFAIL, []
                via_upstream = True
 
            rcode = resp.header.rcode
 
            # NXDOMAIN ara adımda gelse bile orijinal isim için de geçerlidir
            # (RFC 8020): bir üst isim yoksa altındaki hiçbir isim de var
            # olamaz.
            if rcode == RCODE.NXDOMAIN:
                self._cache_put(domain, qtype, RCODE.NXDOMAIN, [], self._soa_ttl(resp.auth))
                return RCODE.NXDOMAIN, []
 
            finalize = is_final_step or via_upstream
 
            if not finalize:
                # Ara adım: amaç sadece bir sonraki delegasyona ilerlemek.
                ns_records = [a for a in resp.auth if QTYPE[a.rtype] == "NS"]
                if not ns_records:
                    # Delegasyon noktası tam bu isimse NS kaydı Answer
                    # bölümünde döner (AA biti kapalı olsa da).
                    ns_records = [a for a in resp.rr if QTYPE[a.rtype] == "NS"]
 
                if not ns_records:
                    # Bu etikette bir zone cut yok, hâlâ aynı bölgedeyiz ->
                    # aynı sunucularla bir sonraki (daha uzun) etikete geç
                    label_count += 1
                    continue
 
                ns_names = {str(a.rdata).rstrip(".").lower() for a in ns_records}
                glue = [
                    str(r.rdata) for r in resp.ar
                    if QTYPE[r.rtype] == "A" and str(r.rname).rstrip(".").lower() in ns_names
                ]
                if not glue:
                    glue = [str(r.rdata) for r in resp.ar if QTYPE[r.rtype] == "A"]
 
                if glue:
                    nameservers = glue
                else:
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
 
                label_count += 1
                continue
 
            # Son adım (veya upstream'den doğrudan cevap): cevap/CNAME/
            # referral işleme mantığı - minimizasyon öncesiyle aynı.
 
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
            # döngü devam: yeni nameserver'lara sor (label_count aynı kalır)
 
        # MAX_HOPS aşıldı
        return RCODE.SERVFAIL, []
 
 
class DNSResolver(BaseResolver):
    """dnslib köprüsü: gelen UDP isteğini DNSCore'a bağlar."""
 
    def __init__(self, core, method="udp"):
        self.core = core
        self.dns_ttl_cache = self.core._cache
        self.method = method

    def resolve(self, request, handler):
        istek_ani = self.core.db_manager.utc_now()  # çözümleme süresi damgaya yansımasın
        qname = str(request.q.qname)
        if not qname.endswith("."):
            qname += "."
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]
        if not self.core.access_ok(client_ip):   # ACL / rate limit → reddet
            reply = request.reply()
            reply.header.rcode = RCODE.REFUSED
            return reply

        src = ["—"]
        rcode, records = self.core.resolve(qname, qtype, source=src)

        reply = request.reply()
        if rcode == RCODE.NXDOMAIN:
            reply.header.rcode = RCODE.NXDOMAIN
        elif rcode == RCODE.SERVFAIL:
            reply.header.rcode = RCODE.SERVFAIL
        else:
            reply.rr = list(records)

        log = logger.warning if rcode == RCODE.SERVFAIL else logger.info
        # Mahremiyet: istemci IP + sorgulanan ad loglanmaz (DB'de gerçek tutulur).
        log("**** **** %s -> %s (%d kayıt)", qtype, RCODE[rcode], len(records))

        blocked_by = self.core.is_blocked(qname)  # None ya da eşleşen liste adı
        self.core.db_manager.add_to_cache(key=qname, value={"record_type": qtype, "client_ip": client_ip, "queried_at": istek_ani, "method": self.method, "blocked": bool(blocked_by), "blocked_by": blocked_by, "resolved_by": src[0]})
        
        return reply
 

