"""Şablonlara ortak değişkenler."""
from django.conf import settings

from . import update_check


def static_version(request):
    """Statik dosya önbellek-kırma damgası (base.html'de ?v={{ static_v }})."""
    return {'static_v': getattr(settings, 'STATIC_VERSION', '')}


def update_status(request):
    """Güncelleme bildirimi: her sayfa açılışında kontrolü tetikler (arka planda,
    DB'siz) ve son bilinen durumu şablona verir (base.html bildirim çubuğu)."""
    update_check.maybe_check()
    return update_check.get_status()
