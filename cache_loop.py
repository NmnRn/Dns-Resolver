import asyncio
from time import time as now


class CLEAR_CACHE:

    def __init__(self, cache: dict, _lock):
        self.cache = cache
        self._lock = _lock
    async def clear_cache_loop(self):
        while True:
            await self.clear_cache()
            await asyncio.sleep(600)  # Clear cache every 600 seconds
            print("Ölü bilgiler temizlendi.")

    async def clear_cache(self):
        _cache = self.cache
        for keys,value in list(_cache.items()):
            if value[0] < now():
                with self._lock:
                    _cache.pop(keys)

    def all_clear_cache(self):
        with self._lock:
            self.cache.clear()

    async def control_cache_length(self):
        while True:
            with self._lock:
                if len(self.cache.keys()) > 50000:
                    self.cache.clear()
            await asyncio.sleep(60)  # Check cache length every 60 seconds