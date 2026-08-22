"""DNSCore engelleme mantığı: is_blocked (öznitelik + parent-walk + allowlist
önceliği) ve resolve()'ın engellenen alan için ağa çıkmadan NXDOMAIN dönmesi.

is_blocked engelliyse EŞLEŞEN LİSTE ADINI döner (sorgu geçmişinde/analizde
'hangi listeden' göstermek için), değilse None.
"""
from dnslib import RCODE

from servers.normal_udp import DNSCore


def _core(manual=(), allow=(), lists=None):
    core = DNSCore(db_manager=None)
    core.update_filter_lists(frozenset(manual), frozenset(allow), lists or {})
    return core


def test_manual_block_returns_label():
    core = _core(manual={"ads.com"})
    assert core.is_blocked("ads.com") == "Elle eklenen"


def test_source_list_returns_its_name():
    core = _core(lists={"Hagezi": frozenset({"tracker.net"})})
    assert core.is_blocked("tracker.net") == "Hagezi"


def test_parent_domain_walk():
    # Listede üst alan varsa alt alan da engellenir.
    core = _core(manual={"doubleclick.net"})
    assert core.is_blocked("ads.g.doubleclick.net") == "Elle eklenen"


def test_allowlist_overrides_block():
    core = _core(manual={"example.com"}, allow={"example.com"})
    assert core.is_blocked("example.com") is None


def test_allowlist_parent_walk_overrides():
    core = _core(lists={"L": frozenset({"cdn.net"})}, allow={"cdn.net"})
    assert core.is_blocked("img.cdn.net") is None


def test_manual_precedes_source_lists():
    core = _core(manual={"x.com"}, lists={"L": frozenset({"x.com"})})
    assert core.is_blocked("x.com") == "Elle eklenen"


def test_case_and_trailing_dot_insensitive():
    core = _core(manual={"ads.com"})
    assert core.is_blocked("ADS.COM.") == "Elle eklenen"


def test_clean_domain_not_blocked():
    core = _core(manual={"ads.com"})
    assert core.is_blocked("safe.org") is None


def test_empty_domain_not_blocked():
    core = _core(manual={"ads.com"})
    assert core.is_blocked(".") is None


def test_resolve_blocked_returns_nxdomain_without_network():
    # Engelli alan hot-path'te kısa devre olur: ağ yok, cevap NXDOMAIN + boş.
    core = _core(manual={"blocked.com"})
    rcode, records = core.resolve("blocked.com.", "A")
    assert rcode == RCODE.NXDOMAIN
    assert records == []


def test_wildcard_blocks_subdomains_not_apex():
    core = _core(manual={"*.example.com"})
    assert core.is_blocked("sub.example.com") == "Elle eklenen"
    assert core.is_blocked("a.b.example.com") == "Elle eklenen"
    assert core.is_blocked("example.com") is None      # apex '*.'e girmez


def test_wildcard_tld_onion():
    core = _core(manual={"*.onion"})
    assert core.is_blocked("foo.onion") == "Elle eklenen"
    assert core.is_blocked("a.b.onion") == "Elle eklenen"


def test_wildcard_allow_overrides():
    core = _core(manual={"*.example.com"}, allow={"*.example.com"})
    assert core.is_blocked("sub.example.com") is None


def test_status_for_helper():
    from servers.normal_udp import status_for
    assert status_for(RCODE.NOERROR, False) == "ok"
    assert status_for(RCODE.NXDOMAIN, False) == "nxdomain"
    assert status_for(RCODE.SERVFAIL, False) == "servfail"
    assert status_for(RCODE.NOERROR, True) == "blocked"    # blocked önceliklidir
    assert status_for(RCODE.NXDOMAIN, True) == "blocked"
