"""DNS rewrites: DNSCore._lookup_rewrite eşleşmesi + _resolve hook cevap üretimi.

Ağa çıkılmaz: IP cevapları doğrudan RR üretir; CNAME zinciri de tamamen rewrite
kurallarıyla (offline) çözülecek şekilde kurulur.
"""
from dnslib import QTYPE, RCODE

from servers.normal_udp import DNSCore


def _core(rules):
    c = DNSCore(db_manager=None)
    c.rewrites = rules
    return c


# --- _lookup_rewrite: eşleşme mantığı (ağ yok) ---
def test_exact_match():
    c = _core({'nas.ev': '192.168.1.10'})
    assert c._lookup_rewrite('nas.ev.') == '192.168.1.10'
    assert c._lookup_rewrite('NAS.EV.') == '192.168.1.10'      # normalize (lower + nokta)
    assert c._lookup_rewrite('baska.ev.') is None


def test_wildcard_matches_subdomains_only():
    c = _core({'*.reklam.com': '0.0.0.0'})
    assert c._lookup_rewrite('x.reklam.com.') == '0.0.0.0'
    assert c._lookup_rewrite('a.b.reklam.com.') == '0.0.0.0'
    assert c._lookup_rewrite('reklam.com.') is None            # çıplak alan wildcard'a girmez


def test_exact_beats_wildcard():
    c = _core({'*.reklam.com': '0.0.0.0', 'ozel.reklam.com': '1.2.3.4'})
    assert c._lookup_rewrite('ozel.reklam.com.') == '1.2.3.4'


def test_empty_rules():
    assert _core({})._lookup_rewrite('x.com.') is None


# --- _resolve hook: cevap üretimi ---
def test_ipv4_answer_a_record():
    c = _core({'nas.ev': '192.168.1.10'})
    rcode, rr = c.resolve('nas.ev.', 'A')
    assert rcode == RCODE.NOERROR
    assert len(rr) == 1 and QTYPE[rr[0].rtype] == 'A'
    assert str(rr[0].rdata) == '192.168.1.10'


def test_ipv4_answer_aaaa_is_nodata():
    c = _core({'nas.ev': '192.168.1.10'})
    rcode, rr = c.resolve('nas.ev.', 'AAAA')
    assert rcode == RCODE.NOERROR and rr == []                 # IP var ama tip uyuşmuyor → NODATA


def test_ipv6_answer_aaaa_record():
    c = _core({'v6.ev': '2001:db8::1'})
    rcode, rr = c.resolve('v6.ev.', 'AAAA')
    assert rcode == RCODE.NOERROR
    assert len(rr) == 1 and QTYPE[rr[0].rtype] == 'AAAA'


def test_sinkhole_zero_ip():
    c = _core({'*.ads.test': '0.0.0.0'})
    rcode, rr = c.resolve('x.ads.test.', 'A')
    assert rcode == RCODE.NOERROR
    assert str(rr[0].rdata) == '0.0.0.0'


def test_cname_chain_offline():
    # a.test → b.test (CNAME), b.test → 9.9.9.9 (A): zincir tamamen rewrite ile çözülür (ağ yok)
    c = _core({'a.test': 'b.test', 'b.test': '9.9.9.9'})
    rcode, rr = c.resolve('a.test.', 'A')
    assert rcode == RCODE.NOERROR
    types = [QTYPE[x.rtype] for x in rr]
    assert types[0] == 'CNAME' and 'A' in types
    a_rec = [x for x in rr if QTYPE[x.rtype] == 'A'][0]
    assert str(a_rec.rdata) == '9.9.9.9'


def test_source_attribution():
    c = _core({'nas.ev': '192.168.1.10'})
    src = ['—']
    c.resolve('nas.ev.', 'A', source=src)
    assert src[0] == 'DNS rewrite'


def test_no_rewrite_no_interference():
    # Kural yokken _lookup_rewrite None → mevcut akış (is_blocked vs) bozulmaz.
    c = _core({})
    assert c._lookup_rewrite('example.com.') is None
