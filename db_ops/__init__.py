import threading
import asyncio
from datetime import datetime, timezone

import db_ops.db_core as dbops

MAX_BUFFER = 50_000  # DB erişilemezken tamponun büyüyebileceği üst sınır

from logs.dns_logs import logger

class DBManager(dbops.DB_CON):
    def __init__(self):
        super().__init__()
        self.flush_cache = []
        self._lock = threading.Lock()

    async def write_on_background(self, interval=60):
        """Tamponu periyodik olarak DB'ye boşaltan sonsuz görev.

        Koşulsuz flush: tampon boşsa write_cache_to_db anında döner, maliyeti
        yok. DB hatası görevi öldürmemeli — batch zaten geri kuyruklandığı
        için loglayıp bir sonraki turu bekleriz.
        """
        while True:
            await asyncio.sleep(interval)
            try:
                await self.write_cache_to_db()
            except Exception:
                # Ayrıntı write_cache_to_db içinde error olarak loglandı.
                logger.debug("Periyodik flush başarısız; sonraki turda tekrar denenecek.")
    async def write_cache_to_db(self):
        """
        Write pending query events to the database in one batch.
        Called periodically (and once at shutdown).
        Buffered event shape: (domain, {'record_type', 'client_ip', 'queried_at', 'method'})
        """
        with self._lock:
            batch, self.flush_cache = self.flush_cache, []
        if not batch:
            return

        params = [
            (domain, value['record_type'], value['client_ip'], value['queried_at'], value['method'])
            for domain, value in batch
        ]
        try:
            async with self.get_db_cursor() as (cursor, conn):
                await cursor.executemany(
                    """
                    INSERT INTO dns_cache (domain, record_type, client_ip, queried_at, method)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    params,
                )
                await conn.commit()
        except Exception:
            # Yazılamayan batch'i başa geri koy; sınır aşılırsa en eskiler düşer.
            with self._lock:
                self.flush_cache = (batch + self.flush_cache)[-MAX_BUFFER:]
                kalan = len(self.flush_cache)
            logger.error("DB'ye yazılamayan batch geri kondu, toplam %d kayıt tamponda.", kalan)
            raise
        else:
            # try içinde değil: log bir gün patlasa bile commit edilmiş batch
            # except'e düşüp mükerrer yazılmasın.
            logger.info("DB'ye %d kayıt yazıldı.", len(batch))

    def add_to_cache(self, key, value):
        """
        Add a query event to the buffer. Thread-safe and non-blocking;
        safe to call from sync handler threads and async code alike.

        Zaman damgasını çağıran değil BURASI vurur: tek saat, tek format —
        GMT+0 (UTC), tz-suffix'siz DATETIME olarak DB'ye gider.
        """
        value = dict(value)  # çağıranın dict'ini değiştirme
        value["queried_at"] = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._lock:
            self.flush_cache.append((key, value))

    async def close_project(self):
        """
        Close the project by closing the DB pool.
        """
        await self.write_cache_to_db()
        await super().close_pool()
