"""DNSResolver'ın rcode -> reply eşlemesi (transport'tan bağımsız ortak mantık).

Sahte bir DNSCore ile ağa çıkmadan, çözümleme sonucunun DNS cevabına doğru
yansıtıldığını doğrular. Aynı eşleme DoH/DoT/DoQ sunucularında da kullanılır.
"""
import threading

from dnslib import DNSRecord, RCODE, RR

from servers.normal_udp import DNSResolver


class StubDBManager:
    """Sorgu olaylarını kaydeden sahte DBManager (DB yok)."""

    def __init__(self):
        self.events = []

    @staticmethod
    def utc_now():
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).replace(tzinfo=None)

    def add_to_cache(self, key, value):
        self.events.append((key, value))


class StubCore:
    """Ağ yok: sabit bir (rcode, records) döndüren sahte DNSCore."""

    def __init__(self, rcode, records, blocked_by=None):
        self._rcode = rcode
        self._records = records
        self._blocked_by = blocked_by
        self._cache = {}
        self._lock = threading.Lock()
        self.db_manager = StubDBManager()

    def resolve(self, domain, qtype, depth=0, source=None):
        if source is not None:
            source[0] = "DNS çekirdeği"
        return self._rcode, self._records

    def is_blocked(self, domain):
        # Handler her çözümlemeden sonra bunu çağırır (blocked/blocked_by için).
        return self._blocked_by

    def access_ok(self, ip):
        # Handler girişinde ACL/rate-limit kontrolü; testte hep izin ver.
        return True


class FakeHandler:
    client_address = ("192.0.2.1", 12345)


def _request(qname="example.com.", qtype="A"):
    return DNSRecord.question(qname, qtype)


def test_noerror_sets_records():
    records = RR.fromZone("example.com. 300 A 1.2.3.4")
    resolver = DNSResolver(core=StubCore(RCODE.NOERROR, records))
    reply = resolver.resolve(_request(), FakeHandler())
    assert reply.header.rcode == RCODE.NOERROR
    assert len(reply.rr) == 1


def test_nxdomain_sets_rcode_no_records():
    resolver = DNSResolver(core=StubCore(RCODE.NXDOMAIN, []))
    reply = resolver.resolve(_request(), FakeHandler())
    assert reply.header.rcode == RCODE.NXDOMAIN
    assert len(reply.rr) == 0


def test_servfail_sets_rcode():
    resolver = DNSResolver(core=StubCore(RCODE.SERVFAIL, []))
    reply = resolver.resolve(_request(), FakeHandler())
    assert reply.header.rcode == RCODE.SERVFAIL


def test_query_event_logged_with_method():
    """Her çözümleme, tampona (domain, {..., method}) olayı bırakmalı."""
    core = StubCore(RCODE.NOERROR, RR.fromZone("example.com. 300 A 1.2.3.4"))
    resolver = DNSResolver(core=core, method="DnsOverTLS")
    resolver.resolve(_request(), FakeHandler())

    assert len(core.db_manager.events) == 1
    key, value = core.db_manager.events[0]
    assert key == "example.com."
    assert value["record_type"] == "A"
    assert value["client_ip"] == "192.0.2.1"
    assert value["method"] == "DnsOverTLS"
    # İstek anı damgası, çözümleme öncesinde handler girişinde yakalanır
    from datetime import datetime
    assert isinstance(value["queried_at"], datetime)


def test_blocked_query_flags_event():
    """Engellenen sorgu: core NXDOMAIN döner + olay blocked/blocked_by taşır."""
    core = StubCore(RCODE.NXDOMAIN, [], blocked_by="Elle eklenen")
    resolver = DNSResolver(core=core, method="udp")
    reply = resolver.resolve(_request("reklam.com."), FakeHandler())

    assert reply.header.rcode == RCODE.NXDOMAIN
    _, value = core.db_manager.events[0]
    assert value["blocked"] is True
    assert value["blocked_by"] == "Elle eklenen"


def test_clean_query_not_flagged():
    """Engellenmemiş sorgu: blocked False, blocked_by None."""
    core = StubCore(RCODE.NOERROR, RR.fromZone("example.com. 300 A 1.2.3.4"))
    resolver = DNSResolver(core=core, method="udp")
    resolver.resolve(_request(), FakeHandler())

    _, value = core.db_manager.events[0]
    assert value["blocked"] is False
    assert value["blocked_by"] is None
