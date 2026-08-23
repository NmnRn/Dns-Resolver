"""Panele Content-Security-Policy + ek güvenlik başlıkları ekleyen hafif middleware.

`django.middleware.security` zaten HSTS/nosniff/referrer/X-Frame'i yönetir; CSP için
ayrı paket (django-csp) yerine sabit muhafazakâr bir politika kullanılır:

Uygulama TAMAMEN self-hosted (harici CDN/font/script YOK) → `default-src 'self'`
güvenle konur. Inline `<script>` blokları ve `style=` öznitelikleri kullanıldığı için
script/style-src'de `'unsafe-inline'` bırakılır — nonce'lu strict CSP paneli bozardı
ve XSS sink'i zaten yok (Django auto-escape sağlam, `|safe` kullanılmıyor). Böylece
CSP, HARİCİ script/style/object/base/frame yüklemeyi engelleyerek savunma katmanı ekler.
"""

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)

_PERMISSIONS = "camera=(), microphone=(), geolocation=()"


class SecurityHeadersMiddleware:
    """Yanıtlara CSP + Permissions-Policy ekler (zaten set edilmişse dokunmaz)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", _CSP)
        response.setdefault("Permissions-Policy", _PERMISSIONS)
        return response
