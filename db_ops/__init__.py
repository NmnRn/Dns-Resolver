import threading
import asyncio
import json
import os
from datetime import datetime, timezone

import db_ops.db_core as dbops
import db_ops.db_control_users as dbusers
MAX_BUFFER = 50_000  # DB erişilemezken tamponun büyüyebileceği üst sınır
# Flush bekleyen tamponun yazıldığı paylaşılan dosya (panel okuyup DB ile birleştirir).
PENDING_FILE = os.getenv('PENDING_FILE', '/app/data/pending.json')

from logs.dns_logs import logger

class DBManager(dbops.DB_CON):
    def __init__(self):
        super().__init__()
        self.flush_cache = []
        self._lock = threading.Lock()
        # Geçmiş (query log) aç/kapa — panelden ayarlanır, app.py periyodik uygular.
        # Kapalıyken sorgular tamponlanmaz → DB'ye ve pending snapshot'a yazılmaz.
        self.logging_enabled = True

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
            (domain, value['record_type'], value['client_ip'], value['queried_at'], value['method'],
             value.get('blocked', False), value.get('blocked_by'))
            for domain, value in batch
        ]
        try:
            async with self.get_db_cursor() as (cursor, conn):
                await cursor.executemany(
                    """
                    INSERT INTO dns_cache (domain, record_type, client_ip, queried_at, method, blocked, blocked_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
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
            self.write_pending_snapshot()  # flush sonrası dosyayı tazele (mükerrer önle)

    @staticmethod
    def utc_now():
        """GMT+0, tz-suffix'siz (naive) datetime — DB'deki DATETIME formatı."""
        return datetime.now(timezone.utc).replace(tzinfo=None)

    def add_to_cache(self, key, value):
        """
        Add a query event to the buffer. Thread-safe and non-blocking;
        safe to call from sync handler threads and async code alike.

        'queried_at' isteğin geldiği andır: sunucular handler girişinde
        utc_now() ile yakalayıp event'e koyar. Koymamışlarsa güvenlik ağı
        olarak ekleme anı damgalanır (çözümleme süresi kadar geç kalabilir).
        """
        if not self.logging_enabled:   # geçmiş kapalı → sorguyu hiç tamponlama
            return
        value = dict(value)  # çağıranın dict'ini değiştirme
        value.setdefault("queried_at", self.utc_now())
        with self._lock:
            self.flush_cache.append((key, value))

    def write_pending_snapshot(self):
        """
        Flush bekleyen (henüz DB'de olmayan) sorguları paylaşılan dosyaya (atomik)
        yazar. Panel bu dosyayı okuyup DB sonuçlarıyla birleştirir → sorgu geçmişi
        cache+db olarak canlı görünür (yeni sorgu 15 sn'lik flush'u beklemez).
        """
        with self._lock:
            snap = [
                {
                    "domain": k,
                    "record_type": v.get("record_type"),
                    "client_ip": v.get("client_ip"),
                    "queried_at": v["queried_at"].strftime("%Y-%m-%d %H:%M:%S")
                    if hasattr(v.get("queried_at"), "strftime") else str(v.get("queried_at")),
                    "method": v.get("method"),
                    "blocked": v.get("blocked", False),
                    "blocked_by": v.get("blocked_by"),
                }
                for k, v in self.flush_cache
            ]
        tmp = PENDING_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snap, f)
            os.replace(tmp, PENDING_FILE)
        except OSError:
            pass

    async def close_project(self):
        """
        Close the project by closing the DB pool.
        """
        await self.write_cache_to_db()
        await super().close_pool()

