"""config_store: tek-kaynak JSON + ayrı bellek cache (mtime_ns invalidation) +
atomik yazma + doğrulama/defaults."""
import json
import os

import pytest

import config_store


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Her test kendi geçici servers.json'ını kullansın; modül cache'i sıfırla."""
    monkeypatch.setenv("SERVERS_CONFIG", str(tmp_path / "servers.json"))
    config_store._reset_cache()
    yield
    config_store._reset_cache()


def _write_raw(obj):
    with open(os.environ["SERVERS_CONFIG"], "w", encoding="utf-8") as f:
        json.dump(obj, f)


def test_defaults_when_file_missing():
    cfg = config_store.get_config()
    assert cfg["methods"]["udp"]["enabled"] is True
    assert cfg["methods"]["doh"]["enabled"] is False
    assert cfg["methods"]["udp"]["container_port"] == 5300
    assert cfg["methods"]["doh"]["container_port"] == 44300
    assert cfg["bind"] == "0.0.0.0"
    assert cfg["site_port"] == 8444


def test_reads_from_file():
    _write_raw({"methods": {"doh": {"enabled": True, "container_port": 8443}}})
    cfg = config_store.get_config(force=True)
    assert cfg["methods"]["doh"]["enabled"] is True
    assert cfg["methods"]["doh"]["container_port"] == 8443
    # eksik metotlar defaulta çekilir
    assert cfg["methods"]["udp"]["enabled"] is True
    assert cfg["methods"]["dot"]["container_port"] == 8853


def test_write_config_round_trip_and_persists():
    cfg = config_store.get_config()
    cfg["methods"]["dot"]["enabled"] = True
    cfg["methods"]["dot"]["external_port"] = 8530
    config_store.write_config(cfg)
    # diskte gerçekten var
    on_disk = json.load(open(os.environ["SERVERS_CONFIG"], encoding="utf-8"))
    assert on_disk["methods"]["dot"]["enabled"] is True
    assert on_disk["methods"]["dot"]["external_port"] == 8530
    # cache de güncel (force'suz)
    assert config_store.get_config()["methods"]["dot"]["enabled"] is True


def test_validation_coerces_types_and_fills_defaults():
    _write_raw({"site_port": "9000", "methods": {"udp": {"container_port": "5301"}}})
    cfg = config_store.get_config(force=True)
    assert cfg["site_port"] == 9000              # str → int
    assert cfg["methods"]["udp"]["container_port"] == 5301
    assert cfg["methods"]["udp"]["enabled"] is True   # eksik alan default
    assert "doq" in cfg["methods"]               # eksik metot eklendi


def test_corrupt_file_falls_back_to_defaults():
    with open(os.environ["SERVERS_CONFIG"], "w") as f:
        f.write("{ bozuk json !!!")
    cfg = config_store.get_config(force=True)
    assert cfg["methods"]["udp"]["enabled"] is True  # patlamaz, default döner


def test_cache_avoids_reread_until_mtime_changes(monkeypatch):
    _write_raw({"methods": {"udp": {"enabled": True}}})
    calls = {"n": 0}
    real = config_store._read_file

    def counting():
        calls["n"] += 1
        return real()

    monkeypatch.setattr(config_store, "_read_file", counting)
    config_store.get_config()          # ilk → diskten (1)
    config_store.get_config()          # cache → disk yok
    config_store.get_config()          # cache → disk yok
    assert calls["n"] == 1
    # dosyayı değiştir + mtime'ı ileri al → yeniden okunmalı
    _write_raw({"methods": {"udp": {"enabled": False}}})
    st = os.stat(os.environ["SERVERS_CONFIG"])
    os.utime(os.environ["SERVERS_CONFIG"], ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))
    assert config_store.changed() is True
    cfg = config_store.get_config()
    assert calls["n"] == 2
    assert cfg["methods"]["udp"]["enabled"] is False


def test_returned_dict_is_a_copy():
    cfg = config_store.get_config()
    cfg["methods"]["udp"]["enabled"] = False   # dönen kopyayı boz
    assert config_store.get_config()["methods"]["udp"]["enabled"] is True  # cache etkilenmez


def test_enabled_methods():
    _write_raw({"methods": {"udp": {"enabled": True}, "doh": {"enabled": True},
                            "dot": {"enabled": False}, "doq": {"enabled": False}}})
    em = config_store.get_config(force=True) and config_store.enabled_methods()
    assert em == {"udp": True, "doh": True, "dot": False, "doq": False}
