"""Şablonlara ortak değişkenler."""
from django.conf import settings


def static_version(request):
    """Statik dosya önbellek-kırma damgası (base.html'de ?v={{ static_v }})."""
    return {'static_v': getattr(settings, 'STATIC_VERSION', '')}
