"""Cache-poisoning savunmaları: cevap-soru eşleşmesi (_resp_ok) + bailiwick
zinciri (_bailiwick_chain). Ağsız, saf statik-metot testleri."""
from dnslib import DNSRecord, QTYPE, RR, A, CNAME

from servers.normal_udp import DNSCore


def _rr(name, rtype, rdata):
    return RR(name, getattr(QTYPE, rtype), rdata=rdata, ttl=300)


# --- _resp_ok: ID + SORU eşleşmeli (spoof'a karşı, RFC 5452) -----------------
def test_resp_ok_matches():
    q = DNSRecord.question("example.com", "A")
    assert DNSCore._resp_ok(q.reply(), q)


def test_resp_ok_wrong_id():
    q = DNSRecord.question("example.com", "A")
    r = q.reply()
    r.header.id = (q.header.id + 1) & 0xFFFF
    assert not DNSCore._resp_ok(r, q)


def test_resp_ok_wrong_qname():
    q = DNSRecord.question("example.com", "A")
    r = DNSRecord.question("evil.com", "A").reply()
    r.header.id = q.header.id
    assert not DNSCore._resp_ok(r, q)          # ID doğru ama isim farklı → RED


def test_resp_ok_wrong_qtype():
    q = DNSRecord.question("example.com", "A")
    r = DNSRecord.question("example.com", "AAAA").reply()
    r.header.id = q.header.id
    assert not DNSCore._resp_ok(r, q)


# --- _bailiwick_chain: zincir dışı (enjekte) kayıtları at --------------------
def test_bailiwick_drops_injected():
    recs = [_rr("a.com.", "A", A("1.2.3.4")), _rr("evil.com.", "A", A("6.6.6.6"))]
    chain, _ = DNSCore._bailiwick_chain(recs, "a.com.", "A")
    assert {str(r.rname).rstrip(".") for r in chain} == {"a.com"}   # evil.com ATILDI


def test_bailiwick_follows_cname_chain():
    recs = [_rr("a.com.", "CNAME", CNAME("b.com.")),
            _rr("b.com.", "A", A("1.2.3.4")),
            _rr("evil.com.", "A", A("6.6.6.6"))]
    chain, _ = DNSCore._bailiwick_chain(recs, "a.com.", "A")
    assert {str(r.rname).rstrip(".") for r in chain} == {"a.com", "b.com"}
    assert any(QTYPE[r.rtype] == "A" for r in chain)


def test_bailiwick_off_name_only_is_empty():
    recs = [_rr("evil.com.", "A", A("6.6.6.6"))]     # sorulan isme ait hiç kayıt yok
    chain, _ = DNSCore._bailiwick_chain(recs, "a.com.", "A")
    assert chain == []
