"""cache_loop.CLEAR_CACHE eviction mantığı."""
import asyncio
import threading
from time import time as now

from cache_loop import CLEAR_CACHE


def test_clear_cache_removes_only_expired():
    cache = {
        ("canli.com.", "A"): (now() + 100, 0, []),   # süresi dolmamış
        ("olu.com.", "A"): (now() - 100, 0, []),      # süresi dolmuş
    }
    cleaner = CLEAR_CACHE(cache=cache, _lock=threading.Lock())
    asyncio.run(cleaner.clear_cache())
    assert ("canli.com.", "A") in cache
    assert ("olu.com.", "A") not in cache


def test_all_clear_cache_empties():
    cache = {("a.com.", "A"): (now() + 100, 0, [])}
    cleaner = CLEAR_CACHE(cache=cache, _lock=threading.Lock())
    cleaner.all_clear_cache()
    assert cache == {}
