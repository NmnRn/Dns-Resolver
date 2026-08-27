"""QNAME minimizasyonu + empty-non-terminal (ENT) yanlış-NXDOMAIN düzeltmesi (RFC 9156).

Bazı yetkili sunucular ara ismin (ENT, ör. 'dualstack.awsglobalaccelerator.com' —
grpc.chat.signal.org zinciri) NS sorgusuna YANLIŞ NXDOMAIN döner. Minimize edilmiş ARA
adımın NXDOMAIN'ine GÜVENİLMEZ → minimizasyon bırakılıp TAM ad aynı sunuculara sorulur.
Gerçek yokluk (son adım) yine NXDOMAIN döner. Ağsız: _query_any mock'lanır."""
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, A, NS, RCODE

from servers.normal_udp import DNSCore


def _referral(qname, ns_name, glue_ip):
    r = DNSRecord(DNSHeader(qr=1, aa=0), q=DNSQuestion(qname, QTYPE.NS))
    r.add_auth(RR(qname, QTYPE.NS, rdata=NS(ns_name), ttl=3600))
    r.add_ar(RR(ns_name, QTYPE.A, rdata=A(glue_ip), ttl=3600))
    return r


def _nxdomain(qname, qtype):
    return DNSRecord(DNSHeader(qr=1, aa=1, rcode=RCODE.NXDOMAIN),
                     q=DNSQuestion(qname, getattr(QTYPE, qtype)))


def _answer_a(qname, ip):
    r = DNSRecord(DNSHeader(qr=1, aa=1), q=DNSQuestion(qname, QTYPE.A))
    r.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=300))
    return r


def _core(resp_map):
    c = DNSCore(db_manager=None)
    c.root_servers = {'a': ('192.0.2.1',)}
    c._query_any = lambda domain, qtype, servers, max_attempts=None, do=False: resp_map.get((domain, qtype))
    return c


def test_ent_intermediate_nxdomain_not_trusted():
    """Ara isim (ENT) 'b.example. NS' YANLIŞ NXDOMAIN dönse de tam ad çözülür → NOERROR."""
    resp = {
        ("example.", "NS"): _referral("example.", "ns.example.", "10.0.0.9"),
        ("b.example.", "NS"): _nxdomain("b.example.", "NS"),       # ENT → yanlış NXDOMAIN
        ("a.b.example.", "A"): _answer_a("a.b.example.", "1.2.3.4"),
    }
    rc, rr = _core(resp)._resolve("a.b.example.", "A")
    assert rc == RCODE.NOERROR
    assert any(QTYPE[r.rtype] == "A" and str(r.rdata) == "1.2.3.4" for r in rr)


def test_real_nxdomain_still_nxdomain():
    """Gerçek yokluk: ara NXDOMAIN + tam ad da NXDOMAIN → NXDOMAIN (regresyon güvenliği)."""
    resp = {
        ("example.", "NS"): _referral("example.", "ns.example.", "10.0.0.9"),
        ("nx.example.", "NS"): _nxdomain("nx.example.", "NS"),
        ("foo.nx.example.", "A"): _nxdomain("foo.nx.example.", "A"),   # tam ad da yok
    }
    rc, rr = _core(resp)._resolve("foo.nx.example.", "A")
    assert rc == RCODE.NXDOMAIN and rr == []


def test_final_step_nxdomain_trusted():
    """SON adımın NXDOMAIN'i kesindir (RFC 8020) → gerçek yokluk NXDOMAIN döner."""
    resp = {
        ("example.", "NS"): _referral("example.", "ns.example.", "10.0.0.9"),
        ("nx.example.", "A"): _nxdomain("nx.example.", "A"),
    }
    rc, rr = _core(resp)._resolve("nx.example.", "A")
    assert rc == RCODE.NXDOMAIN and rr == []
