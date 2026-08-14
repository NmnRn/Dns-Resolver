"""Test kurulumu.

İki şey yapar:
  1. Django (web panosu) testleri için ortamı kurar. Proje iç içe:
     <root>/dns_resolver/{manage.py, dashboard/, dns_resolver/settings.py}
     Ayar modülü 'dns_resolver.settings' olduğundan iç paketi bulabilmek için
     <root>/dns_resolver dizini import yolunun BAŞINA eklenir. Django yoksa /
     ayar yüklenemezse dashboard testleri kendini atlar (skip).
  2. write_pending_snapshot'ın gerçek /app yoluna değil, teste özel geçici bir
     dosyaya yazması için PENDING_FILE'i her testte tmp_path'e yönlendirir.
"""
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DJANGO_ROOT = os.path.join(_ROOT, "dns_resolver")
if _DJANGO_ROOT not in sys.path:
    sys.path.insert(0, _DJANGO_ROOT)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dns_resolver.settings")
try:
    import django

    django.setup()
except Exception:  # pragma: no cover - Django yoksa dashboard testleri skip olur
    pass

import db_ops
import logcrypto


@pytest.fixture(autouse=True)
def _isolate_pending_file(tmp_path, monkeypatch):
    """Snapshot yazımı testte /app'e değil izole bir tmp dosyasına gitsin."""
    monkeypatch.setattr(db_ops, "PENDING_FILE", str(tmp_path / "pending.json"))


@pytest.fixture(autouse=True)
def _disable_log_encryption(monkeypatch):
    """Testler operatörün .env'indeki DNS_LOG_KEY'den ETKİLENMESİN: şifrelemeyi
    kapat (düz metin varsay). At-rest şifreleme kendi başına test_logcrypto'da
    sınanır; buffer/snapshot testleri düz metin üzerinden çalışır."""
    monkeypatch.delenv("DNS_LOG_KEY", raising=False)
    logcrypto._siv = None
    logcrypto._init = False
    yield
    logcrypto._siv = None
    logcrypto._init = False
