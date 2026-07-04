"""TTL yardımcıları: _min_ttl ve DNSCore._soa_ttl.

_soa_ttl, negatif (NXDOMAIN/NODATA) cache süresini SOA kaydına göre üretir:
min(kayıt_ttl, SOA.minimum, NEG_TTL_CAP).
"""
from dnslib import RR

from servers.normal_udp import DNSCore, _min_ttl, NEG_TTL_CAP


def test_min_ttl_empty_returns_default():
    assert _min_ttl([]) == 300
    assert _min_ttl([], default=42) == 42


def test_min_ttl_returns_smallest():
    rrs = RR.fromZone("a.com. 300 A 1.1.1.1") + RR.fromZone("a.com. 100 A 2.2.2.2")
    assert _min_ttl(rrs) == 100


def _soa(ttl, minimum):
    return RR.fromZone(
        f"example.com. {ttl} SOA ns.example.com. admin.example.com. "
        f"1 7200 3600 1209600 {minimum}"
    )


def test_soa_ttl_uses_record_ttl_when_smallest():
    # min(ttl=300, minimum=86400, NEG_TTL_CAP=900) = 300
    assert DNSCore._soa_ttl(_soa(300, 86400)) == 300


def test_soa_ttl_uses_soa_minimum_when_smallest():
    # min(ttl=100000, minimum=60, NEG_TTL_CAP=900) = 60
    # SOA minimum alanının gerçekten devreye girdiğini doğrular.
    assert DNSCore._soa_ttl(_soa(100000, 60)) == 60


def test_soa_ttl_capped_at_neg_ttl_cap():
    # min(ttl=100000, minimum=86400, NEG_TTL_CAP=900) = 900
    assert DNSCore._soa_ttl(_soa(100000, 86400)) == NEG_TTL_CAP


def test_soa_ttl_no_soa_returns_cap():
    a = RR.fromZone("a.com. 300 A 1.1.1.1")
    assert DNSCore._soa_ttl(a) == NEG_TTL_CAP
