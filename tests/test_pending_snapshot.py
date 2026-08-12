"""write_pending_snapshot: flush bekleyen sorguları paylaşılan dosyaya yazar.

Panel bu dosyayı okuyup DB ile birleştirir → sorgu geçmişi 'cache + db' canlı
görünür. Burada dosyanın doğru alanlarla (blocked/blocked_by dahil) ve panelin
beklediği string tarih formatıyla yazıldığını doğrularız.

PENDING_FILE, conftest'teki autouse fixture ile tmp'ye yönlendirilmiştir.
"""
import json

import db_ops
from db_ops import DBManager


def _read_snapshot():
    with open(db_ops.PENDING_FILE, encoding="utf-8") as f:
        return json.load(f)


def test_snapshot_writes_event_fields():
    m = DBManager()
    m.add_to_cache("ads.com.", {
        "record_type": "A", "client_ip": "1.2.3.4", "method": "udp",
        "blocked": True, "blocked_by": "Elle eklenen",
    })
    m.write_pending_snapshot()

    data = _read_snapshot()
    assert len(data) == 1
    row = data[0]
    assert row["domain"] == "ads.com."
    assert row["record_type"] == "A"
    assert row["client_ip"] == "1.2.3.4"
    assert row["method"] == "udp"
    assert row["blocked"] is True
    assert row["blocked_by"] == "Elle eklenen"


def test_snapshot_queried_at_is_formatted_string():
    m = DBManager()
    m.add_to_cache("x.com.", {"record_type": "A", "client_ip": "9.9.9.9", "method": "doh"})
    m.write_pending_snapshot()

    row = _read_snapshot()[0]
    # Panelin ayrıştırdığı biçim: "YYYY-MM-DD HH:MM:SS" (19 karakter)
    assert isinstance(row["queried_at"], str)
    assert len(row["queried_at"]) == 19
    assert row["queried_at"][4] == "-" and row["queried_at"][13] == ":"


def test_snapshot_defaults_unblocked():
    m = DBManager()
    m.add_to_cache("clean.com.", {"record_type": "A", "client_ip": "8.8.8.8", "method": "dot"})
    m.write_pending_snapshot()

    row = _read_snapshot()[0]
    assert row["blocked"] is False
    assert row["blocked_by"] is None


def test_snapshot_reflects_multiple_events_in_order():
    m = DBManager()
    for d in ("a.com.", "b.com.", "c.com."):
        m.add_to_cache(d, {"record_type": "A", "client_ip": "1.1.1.1", "method": "udp"})
    m.write_pending_snapshot()

    assert [r["domain"] for r in _read_snapshot()] == ["a.com.", "b.com.", "c.com."]
