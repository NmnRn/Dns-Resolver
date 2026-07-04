"""DNSResolver'ın rcode -> reply eşlemesi (transport'tan bağımsız ortak mantık).

Sahte bir DNSCore ile ağa çıkmadan, çözümleme sonucunun DNS cevabına doğru
yansıtıldığını doğrular. Aynı eşleme DoH/DoT/DoQ sunucularında da kullanılır.
"""
import threading

from dnslib import DNSRecord, RCODE, RR

from servers.normal_udp import DNSResolver


class StubCore:
    """Ağ yok: sabit bir (rcode, records) döndüren sahte DNSCore."""

    def __init__(self, rcode, records):
        self._rcode = rcode
        self._records = records
        self._cache = {}
        self._lock = threading.Lock()

    def resolve(self, domain, qtype, depth=0):
        return self._rcode, self._records


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
