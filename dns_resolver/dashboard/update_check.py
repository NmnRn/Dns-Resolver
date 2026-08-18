"""Güncelleme kontrolü — panel açılırken arka planda, DB'yi yormadan.

Yerel `VERSION` (imajla gelir) ile uzak `VERSION`'ı (GitHub raw) karşılaştırır.
Durum yalnız BELLEKTE tutulur (tek uvicorn süreci); ~15 dk'da bir, sayfa açılışı
tetikleyince kontrol edilir (engellemeyen daemon thread). DEBUG'da ve
DNS_UPDATE_CHECK=0 iken kapalı (yerelde dış istek atma).

Yeni sürüm yayınlarken repo kökündeki `VERSION`'ı yükselt → dağıtımlar günceli
çekerken farkı görüp bildirim çubuğunu gösterir (güncelleyince fark kapanır).
"""
import logging
import os
import threading
import time
import urllib.request
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

_BRANCH = "dns-python-website"
_REMOTE_URL = os.getenv(
    "DNS_UPDATE_URL",
    f"https://raw.githubusercontent.com/NmnRn/Dns-Resolver/{_BRANCH}/VERSION",
)
_INTERVAL = int(os.getenv("DNS_UPDATE_INTERVAL", "900"))   # sn (varsayılan 15 dk)
_TIMEOUT = 5


def _read_local() -> str:
    try:
        return (Path(settings.BASE_DIR).parent / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:   # noqa: BLE001 — VERSION yoksa kontrol sessizce kapanır
        return ""


LOCAL_VERSION = _read_local()

_state = {"available": False, "latest": "", "checked_at": 0.0}
_lock = threading.Lock()
_checking = False


def _enabled() -> bool:
    if getattr(settings, "DEBUG", False):
        return False                      # yerel geliştirmede dış istek atma
    if os.getenv("DNS_UPDATE_CHECK", "1") == "0":
        return False
    return bool(LOCAL_VERSION)


def _do_check() -> None:
    global _checking
    try:
        req = urllib.request.Request(_REMOTE_URL, headers={"User-Agent": "dns-resolver-update/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            latest = r.read(200).decode("utf-8", "ignore").strip()
        if latest:
            with _lock:
                _state["latest"] = latest
                _state["available"] = latest != LOCAL_VERSION
    except Exception:   # noqa: BLE001 — ağ/uzak hatası bildirimi bozmasın
        logger.debug("guncelleme kontrolu basarisiz", exc_info=True)
    finally:
        with _lock:
            _state["checked_at"] = time.time()   # hata olsa da bekle (spam etme)
        _checking = False


def maybe_check() -> None:
    """Sayfa açılışında çağrılır: süresi geldiyse arka planda kontrolü tetikler
    (engellemez, DB kullanmaz). Zaten kontrol ediliyorsa / süre dolmadıysa çıkar."""
    global _checking
    if not _enabled():
        return
    now = time.time()
    with _lock:
        if _checking or (now - _state["checked_at"] < _INTERVAL):
            return
        _checking = True
    threading.Thread(target=_do_check, daemon=True).start()


def get_status() -> dict:
    with _lock:
        return {
            "update_available": _state["available"],
            "update_latest": _state["latest"],
            "local_version": LOCAL_VERSION,
        }
