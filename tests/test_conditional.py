"""Koşullu forwarding: DNSCore._match_conditional (son-ek eşleşme) +
_forward_result (forward cevabı → (rcode, records), ağ yok)."""
from dnslib import RCODE, QTYPE, RR, A, DNSRecord

from servers.normal_udp import DNSCore


def _core(conds):
    c = DNSCore(db_manager=None)
    c.conditionals = conds
    return c


# --- _match_conditional ---
def test_suffix_matches_domain_and_subdomains():
    c = _core([('home.arpa', '192.168.1.1')])
    assert c._match_conditional('home.arpa.') == '192.168.1.1'
    assert c._match_conditional('x.home.arpa.') == '192.168.1.1'
    assert c._match_conditional('a.b.home.arpa.') == '192.168.1.1'


def test_no_partial_or_unrelated_match():
    c = _core([('home.arpa', '192.168.1.1')])
    assert c._match_conditional('example.com.') is None
    assert c._match_conditional('nothome.arpa.') is None   # '.home.arpa' ile bitmez


def test_longest_suffix_wins():
    c = _core([('b.com', '2.2.2.2'), ('a.b.com', '1.1.1.1')])
    assert c._match_conditional('x.a.b.com.') == '1.1.1.1'   # en spesifik son-ek
    assert c._match_conditional('y.b.com.') == '2.2.2.2'


def test_empty_conditionals():
    assert _core([])._match_conditional('x.com.') is None


# --- _forward_result (ağ yok, sahte DNSRecord) ---
def test_forward_result_records_and_noerror():
    resp = DNSRecord.question('ev.local', 'A').reply()
    resp.add_answer(RR('ev.local', QTYPE.A, ttl=60, rdata=A('10.0.0.9')))
    rcode, rr = _core([])._forward_result('ev.local.', 'A', resp)
    assert rcode == RCODE.NOERROR
    assert len(rr) == 1 and str(rr[0].rdata) == '10.0.0.9'


def test_forward_result_none_is_servfail():
    assert _core([])._forward_result('x.', 'A', None) == (RCODE.SERVFAIL, [])


def test_forward_result_nxdomain():
    resp = DNSRecord.question('nope.local', 'A').reply()
    resp.header.rcode = RCODE.NXDOMAIN
    rcode, rr = _core([])._forward_result('nope.local.', 'A', resp)
    assert rcode == RCODE.NXDOMAIN and rr == []
