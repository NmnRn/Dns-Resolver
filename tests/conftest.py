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


@pytest.fixture(autouse=True)
def _isolate_pending_file(tmp_path, monkeypatch):
    """Snapshot yazımı testte /app'e değil izole bir tmp dosyasına gitsin."""
    monkeypatch.setattr(db_ops, "PENDING_FILE", str(tmp_path / "pending.json"))
