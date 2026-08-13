"""Erişim kontrolü + rate limit: DNSCore.is_client_allowed / is_rate_limited / access_ok."""
from servers.normal_udp import DNSCore


def _core():
    return DNSCore(db_manager=None)


def test_allow_empty_permits_all():
    assert _core().is_client_allowed("1.2.3.4")


def test_deny_blocks():
    c = _core()
    c.client_deny = frozenset({"1.2.3.4"})
    assert not c.is_client_allowed("1.2.3.4")
    assert c.is_client_allowed("5.6.7.8")


def test_allow_only_listed():
    c = _core()
    c.client_allow = frozenset({"10.0.0.5"})
    assert c.is_client_allowed("10.0.0.5")
    assert not c.is_client_allowed("10.0.0.6")


def test_deny_precedes_allow():
    c = _core()
    c.client_allow = frozenset({"10.0.0.5"})
    c.client_deny = frozenset({"10.0.0.5"})
    assert not c.is_client_allowed("10.0.0.5")


def test_cidr_match():
    c = _core()
    c.client_deny = frozenset({"192.168.1.0/24"})
    assert not c.is_client_allowed("192.168.1.42")
    assert c.is_client_allowed("192.168.2.1")


def test_bad_ip_no_crash():
    c = _core()
    c.client_deny = frozenset({"10.0.0.0/8"})
    assert c.is_client_allowed("not-an-ip")   # eşleşmez, patlamaz


def test_rate_limit_off():
    c = _core()
    c.rate_limit = 0
    assert not any(c.is_rate_limited("1.1.1.1") for _ in range(100))


def test_rate_limit_trips():
    c = _core()
    c.rate_limit = 3
    ip = "9.9.9.9"
    assert [c.is_rate_limited(ip) for _ in range(5)] == [False, False, False, True, True]


def test_access_ok_combines():
    c = _core()
    c.client_deny = frozenset({"2.2.2.2"})
    assert c.access_ok("1.1.1.1")
    assert not c.access_ok("2.2.2.2")
