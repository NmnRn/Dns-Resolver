"""Sunucu topolojisi (hangi DNS metodu açık + portlar) için TEK kaynak:
``config/servers.json``.

Tasarım — dosya okuma ile bellek cache'i AYRI:
  * Disk okuma yalnız ``_read_file()`` içinde olur.
  * ``get_config()`` normalde belleği döndürür; DİSKE GİTMEZ. Yalnız dosya
    ``mtime_ns`` DEĞİŞTİYSE (panel/elle düzenleme) yeniden okuyup cache'i tazeler.
  * ``write_config()`` atomik yazar (temp + ``os.replace``) ve cache'i günceller.

Panel (uvicorn) yazar, resolver (app.py) okur — iki AYRI process. Her birinin
kendi cache'i vardır; biri yazınca dosya mtime'ı değişir, diğeri bir sonraki
``get_config()``/``changed()`` çağrısında farkı görüp tazeler → otomatik senkron.

Bu dosya, eski ``.env`` (CONTAINER_*/ENABLE_*/EXTERNAL_*) ve DB
(``resolver_config`` + port ``app_settings``) ikiliğinin YERİNE geçer.
``.env`` yalnız sır/DB için kalır.
"""
import json
import os
import threading

# config_store.py proje kökündedir (logcrypto gibi) → <kök>/config/servers.json
_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config", "servers.json"
)


def _path() -> str:
    """Config dosyası yolu. Test/özel kurulum için SERVERS_CONFIG ile geçersiz kılınır."""
    return os.environ.get("SERVERS_CONFIG", _DEFAULT_PATH)


# Metot defaultları — dosya yoksa ya da alan eksikse tamamlanır.
# GÜVENLİ VARSAYILAN: yalnız düz UDP açık; DoH/DoT/DoQ kapalı ve host'a yayınlanmaz.
_METHOD_DEFAULTS = {
    "udp": {"enabled": True,  "container_port": 5300,  "external_port": 53,  "publish": False},
    "doh": {"enabled": False, "container_port": 44300, "external_port": 443, "publish": False},
    "dot": {"enabled": False, "container_port": 8853,  "external_port": 853, "publish": False},
    "doq": {"enabled": False, "container_port": 8530,  "external_port": 853, "publish": False},
}
_DEFAULTS = {
    "bind": "0.0.0.0",
    "site_port": 8444,
    "cert_file": "/app/certificates/fullchain.pem",
    "key_file": "/app/certificates/privkey.pem",
    "allowed_host": "dns.example.com",
}
METHODS = tuple(_METHOD_DEFAULTS)  # ('udp','doh','dot','doq')

_lock = threading.Lock()
_cache: dict | None = None        # bellekteki parse edilmiş config
_cache_mtime: int | None = None   # cache alındığındaki dosya mtime_ns (yoksa -1)


def _mtime_ns(path: str) -> int:
    """Dosya mtime'ı (nanosaniye) — 1sn granülerlik tuzağı olmasın. Yoksa -1 (sabit
    sentinel → dosya yokken sürekli yeniden-okuma tetiklenmez)."""
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return -1


def _coerce_int(val, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return int(default)


def _validate(raw: dict) -> dict:
    """Ham dict → tam/temiz config: defaultlarla doldur, tipleri zorla. Bilinmeyen
    metotlar yok sayılır; eksikler defaulta çekilir."""
    raw = raw if isinstance(raw, dict) else {}
    cfg = {
        "bind": str(raw.get("bind") or _DEFAULTS["bind"]),
        "site_port": _coerce_int(raw.get("site_port"), _DEFAULTS["site_port"]),
        "cert_file": str(raw.get("cert_file") or _DEFAULTS["cert_file"]),
        "key_file": str(raw.get("key_file") or _DEFAULTS["key_file"]),
        "allowed_host": str(raw.get("allowed_host") or _DEFAULTS["allowed_host"]),
        "methods": {},
    }
    raw_methods = raw.get("methods")
    raw_methods = raw_methods if isinstance(raw_methods, dict) else {}
    for name, d in _METHOD_DEFAULTS.items():
        m = raw_methods.get(name)
        m = m if isinstance(m, dict) else {}
        cfg["methods"][name] = {
            "enabled": bool(m.get("enabled", d["enabled"])),
            "container_port": _coerce_int(m.get("container_port"), d["container_port"]),
            "external_port": _coerce_int(m.get("external_port"), d["external_port"]),
            "publish": bool(m.get("publish", d["publish"])),
        }
    return cfg


def _read_file() -> dict:
    """DİSK OKUMA — yalnız burada. Dosya yok/bozuksa güvenli defaultlar döner."""
    try:
        with open(_path(), encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        raw = {}
    return _validate(raw)


def get_config(force: bool = False) -> dict:
    """Config'i döndürür. Normalde BELLEKTEN (diske gitmez); yalnız dosya mtime'ı
    değiştiyse (ya da force) yeniden okur. Derin KOPYA döner → çağıran mutasyonu
    cache'i bozmaz."""
    global _cache, _cache_mtime
    with _lock:
        m = _mtime_ns(_path())
        if force or _cache is None or m != _cache_mtime:
            _cache = _read_file()
            _cache_mtime = m
        return json.loads(json.dumps(_cache))


def changed() -> bool:
    """Dosya, cache alındığından beri değişti mi? (tek ucuz stat — reconcile için)."""
    with _lock:
        return _mtime_ns(_path()) != _cache_mtime


def write_config(cfg: dict) -> dict:
    """Doğrula → atomik yaz (temp + fsync + os.replace) → cache'i güncelle.
    Temizlenmiş (validate edilmiş) config'i döner."""
    global _cache, _cache_mtime
    clean = _validate(cfg)
    path = _path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomik → resolver yarım dosya okumaz
    with _lock:
        _cache = clean
        _cache_mtime = _mtime_ns(path)
    return json.loads(json.dumps(clean))


def enabled_methods() -> dict:
    """{method: bool} — ServerManager.reconcile için istenen durum."""
    return {k: v["enabled"] for k, v in get_config()["methods"].items()}


def _reset_cache() -> None:
    """Yalnız testler için: bellekteki cache'i sıfırla (bir sonraki get_config diskten okur)."""
    global _cache, _cache_mtime
    with _lock:
        _cache = None
        _cache_mtime = None
