"""Forwarding (upstream'e iletme) modu: DNSCore._query_forward_one protokol
ayrımı, _forward ilk-cevap mantığı ve resolve()'ın use_recursion kapalıyken
_forward'a kısa devre yapması.
"""
from dnslib import RCODE, RR

from servers.normal_udp import DNSCore


def _core():
    return DNSCore(db_manager=None)


def test_forward_dispatch_by_prefix():
    core = _core()
    calls = []
    core._query = lambda d, q, host, **k: (calls.append(('udp', host)), 'R')[1]
    core._query_doh = lambda d, q, ep: (calls.append(('doh', ep)), 'R')[1]
    core._query_dot = lambda d, q, host, port=853: (calls.append(('dot', host, port)), 'R')[1]

    core._query_forward_one('example.com.', 'A', '1.1.1.1')
    core._query_forward_one('example.com.', 'A', 'udp://9.9.9.9')
    core._query_forward_one('example.com.', 'A', 'https://dns.quad9.net/dns-query')
    core._query_forward_one('example.com.', 'A', 'tls://dns.google')
    core._query_forward_one('example.com.', 'A', 'tls://dns.google:8853')

    assert ('udp', '1.1.1.1') in calls
    assert ('udp', '9.9.9.9') in calls
    assert ('doh', 'https://dns.quad9.net/dns-query') in calls
    assert ('dot', 'dns.google', 853) in calls
    assert ('dot', 'dns.google', 8853) in calls


def test_forward_quic_not_supported_yet():
    core = _core()
    assert core._query_forward_one('x.', 'A', 'quic://dns.adguard.com') is None


def test_forward_blank_upstream():
    core = _core()
    assert core._query_forward_one('x.', 'A', '   ') is None


def test_forward_first_answer_wins():
    core = _core()
    core.upstreams = ['1.1.1.1', '8.8.8.8']
    seq = iter([None, 'ANSWER'])
    core._query_forward_one = lambda d, q, up: next(seq)
    assert core._forward('x.', 'A') == 'ANSWER'


def test_forward_none_when_all_fail():
    core = _core()
    core.upstreams = ['1.1.1.1', '8.8.8.8']
    core._query_forward_one = lambda d, q, up: None
    assert core._forward('x.', 'A') is None


def test_resolve_forwarding_mode_short_circuits():
    """use_recursion kapalı + upstream var → _forward kullanılır, recursion YOK."""
    core = _core()
    core.use_recursion = False
    core.upstreams = ['1.1.1.1']
    from dnslib import DNSRecord
    reply = DNSRecord.question('example.com.', 'A').reply()
    reply.add_answer(*RR.fromZone('example.com. 60 A 1.2.3.4'))
    core._forward = lambda d, q: reply

    rcode, records = core.resolve('example.com.', 'A')
    assert rcode == RCODE.NOERROR
    assert any(str(r.rdata) == '1.2.3.4' for r in records)


def test_resolve_forwarding_servfail_when_no_answer():
    core = _core()
    core.use_recursion = False
    core.upstreams = ['1.1.1.1']
    core._forward = lambda d, q: None
    rcode, records = core.resolve('example.com.', 'A')
    assert rcode == RCODE.SERVFAIL
    assert records == []
