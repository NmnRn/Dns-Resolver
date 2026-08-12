"""DNSCore'un bellek cache'i (_cache_put / _cache_get) birim testleri."""
import time

from dnslib import RCODE, RR

from servers.normal_udp import DNSCore, MAX_TTL


def test_put_get_roundtrip():
    core = DNSCore(db_manager=None)
    records = RR.fromZone("example.com. 300 A 1.2.3.4")
    core._cache_put("example.com.", "A", RCODE.NOERROR, records, 300)

    result = core._cache_get("example.com.", "A")
    assert result is not None
    rcode, got = result
    assert rcode == RCODE.NOERROR
    assert got == records


def test_miss_returns_none():
    core = DNSCore(db_manager=None)
    assert core._cache_get("yok.com.", "A") is None


def test_ttl_zero_not_stored():
    core = DNSCore(db_manager=None)
    core._cache_put("sifir.com.", "A", RCODE.NOERROR, [], 0)
    assert ("sifir.com.", "A") not in core._cache


def test_ttl_capped_at_max_ttl():
    core = DNSCore(db_manager=None)
    before = time.time()
    core._cache_put("buyuk.com.", "A", RCODE.NOERROR, [], MAX_TTL + 100000)
    expiry = core._cache[("buyuk.com.", "A")][0]
    assert expiry <= before + MAX_TTL + 1


def test_expired_entry_removed_on_read():
    core = DNSCore(db_manager=None)
    key = ("eski.com.", "A")
    core._cache[key] = (time.time() - 1, RCODE.NOERROR, [])  # süresi dolmuş
    assert core._cache_get("eski.com.", "A") is None
    assert key not in core._cache  # okurken silinmeli


def test_cache_disabled_does_not_store_or_return():
    core = DNSCore(db_manager=None)
    core.cache_enabled = False
    core._cache_put("x.com.", "A", RCODE.NOERROR, [], 300)
    assert core._cache == {}                         # yazmaz
    core._cache[("y.com.", "A")] = (time.time() + 100, RCODE.NOERROR, [])
    assert core._cache_get("y.com.", "A") is None    # okumaz (bypass)


def test_cache_min_ttl_raises_short_ttl():
    core = DNSCore(db_manager=None)
    core.cache_min_ttl = 600
    before = time.time()
    core._cache_put("z.com.", "A", RCODE.NOERROR, [], 30)  # kısa TTL yukarı çekilir
    expiry = core._cache[("z.com.", "A")][0]
    assert expiry >= before + 600 - 1


def test_cache_max_ttl_override_caps():
    core = DNSCore(db_manager=None)
    core.cache_max_ttl = 100
    before = time.time()
    core._cache_put("w.com.", "A", RCODE.NOERROR, [], 100000)
    expiry = core._cache[("w.com.", "A")][0]
    assert expiry <= before + 100 + 1


def test_clear_cache_empties_and_counts():
    core = DNSCore(db_manager=None)
    core._cache_put("a.com.", "A", RCODE.NOERROR, [], 300)
    core._cache_put("b.com.", "A", RCODE.NOERROR, [], 300)
    n = core.clear_cache()
    assert n == 2
    assert core._cache == {}
