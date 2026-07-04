"""DNSCore'un bellek cache'i (_cache_put / _cache_get) birim testleri."""
import time

from dnslib import RCODE, RR

from servers.normal_udp import DNSCore, MAX_TTL


def test_put_get_roundtrip():
    core = DNSCore()
    records = RR.fromZone("example.com. 300 A 1.2.3.4")
    core._cache_put("example.com.", "A", RCODE.NOERROR, records, 300)

    result = core._cache_get("example.com.", "A")
    assert result is not None
    rcode, got = result
    assert rcode == RCODE.NOERROR
    assert got == records


def test_miss_returns_none():
    core = DNSCore()
    assert core._cache_get("yok.com.", "A") is None


def test_ttl_zero_not_stored():
    core = DNSCore()
    core._cache_put("sifir.com.", "A", RCODE.NOERROR, [], 0)
    assert ("sifir.com.", "A") not in core._cache


def test_ttl_capped_at_max_ttl():
    core = DNSCore()
    before = time.time()
    core._cache_put("buyuk.com.", "A", RCODE.NOERROR, [], MAX_TTL + 100000)
    expiry = core._cache[("buyuk.com.", "A")][0]
    assert expiry <= before + MAX_TTL + 1


def test_expired_entry_removed_on_read():
    core = DNSCore()
    key = ("eski.com.", "A")
    core._cache[key] = (time.time() - 1, RCODE.NOERROR, [])  # süresi dolmuş
    assert core._cache_get("eski.com.", "A") is None
    assert key not in core._cache  # okurken silinmeli
