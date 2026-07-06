"""DBManager flush tamponu birim testleri — DB'siz, sahte cursor ile.

write_cache_to_db'nin takas deseni şu garantileri vermeli:
- başarılı yazımda batch tek seferde gider, commit edilir, tampon boşalır
- boş tamponda DB'ye hiç dokunulmaz
- hata durumunda batch geri kuyruklanır ve hata yutulmaz
- flush SIRASINDA eklenen olaylar kaybolmaz (eski clear() bug'ının regresyon testi)
"""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import pytest

from db_ops import DBManager


class FakeCursor:
    def __init__(self, fail=False):
        self.fail = fail
        self.received = None

    async def executemany(self, sql, params):
        if self.fail:
            raise RuntimeError("DB erişilemez")
        self.received = params


class FakeConn:
    def __init__(self):
        self.committed = False

    async def commit(self):
        self.committed = True


def make_manager(fail=False):
    manager = DBManager()
    cursor, conn = FakeCursor(fail), FakeConn()

    @asynccontextmanager
    async def fake_get_db_cursor(dictionary=False):
        yield cursor, conn

    manager.get_db_cursor = fake_get_db_cursor
    return manager, cursor, conn


def _event():
    return {"record_type": "A", "client_ip": "1.1.1.1", "method": "Normal DNS"}


def test_add_to_cache_stamps_naive_utc_datetime():
    """Zaman damgasını add_to_cache vurur: tz-suffix'siz (naive) UTC datetime."""
    manager, _, _ = make_manager()
    manager.add_to_cache("a.com.", _event())

    stamped = manager.flush_cache[0][1]["queried_at"]
    assert isinstance(stamped, datetime)
    assert stamped.tzinfo is None
    utc_simdi = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs((utc_simdi - stamped).total_seconds()) < 5


def test_flush_writes_batch_and_commits():
    manager, cursor, conn = make_manager()
    manager.add_to_cache("a.com.", _event())
    stamped = manager.flush_cache[0][1]["queried_at"]
    asyncio.run(manager.write_cache_to_db())

    assert cursor.received == [("a.com.", "A", "1.1.1.1", stamped, "Normal DNS")]
    assert conn.committed
    assert manager.flush_cache == []


def test_empty_buffer_skips_db():
    manager, cursor, conn = make_manager()
    asyncio.run(manager.write_cache_to_db())

    assert cursor.received is None
    assert not conn.committed


def test_failed_flush_requeues_batch_and_raises():
    manager, cursor, conn = make_manager(fail=True)
    manager.add_to_cache("a.com.", _event())

    with pytest.raises(RuntimeError):
        asyncio.run(manager.write_cache_to_db())

    assert len(manager.flush_cache) == 1  # olay kaybolmadı
    assert not conn.committed


def test_events_added_during_flush_survive():
    """DB yazımı sürerken gelen olaylar, takas sayesinde tamponda kalmalı."""
    manager, cursor, conn = make_manager()
    manager.add_to_cache("once.com.", _event())

    orig_executemany = cursor.executemany

    async def executemany_with_concurrent_add(sql, params):
        manager.add_to_cache("flush-sirasinda.com.", _event())
        await orig_executemany(sql, params)

    cursor.executemany = executemany_with_concurrent_add
    asyncio.run(manager.write_cache_to_db())

    assert len(cursor.received) == 1  # yalnızca eski batch yazıldı
    assert [k for k, _ in manager.flush_cache] == ["flush-sirasinda.com."]
