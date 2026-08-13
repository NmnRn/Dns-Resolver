"""Panel giriş brute-force koruması + istemci IP çıkarımı (views._login_*, _client_ip)."""
import pytest

try:
    from dashboard import views
except Exception as exc:  # pragma: no cover - Django yoksa
    pytest.skip(f"dashboard import edilemedi: {exc}", allow_module_level=True)


class _Req:
    """Minimal request sahtesi: yalnız META (X-Forwarded-For / REMOTE_ADDR)."""

    def __init__(self, xff='', remote='9.9.9.9'):
        self.META = {'REMOTE_ADDR': remote}
        if xff:
            self.META['HTTP_X_FORWARDED_FOR'] = xff


def test_client_ip_prefers_xff_first():
    # Ters proxy (Cloudflare) arkasında gerçek istemci XFF'in ilk değeridir.
    assert views._client_ip(_Req(xff='1.2.3.4, 5.6.7.8')) == '1.2.3.4'


def test_client_ip_falls_back_to_remote():
    assert views._client_ip(_Req(remote='9.9.9.9')) == '9.9.9.9'


def test_locks_after_max_fails():
    ip = 'throttle-test-a'
    views._login_reset(ip)
    assert not views._login_locked(ip)
    for _ in range(views._LOGIN_MAX_FAILS):
        views._login_note_fail(ip)
    assert views._login_locked(ip)
    views._login_reset(ip)               # temizle (diğer testleri kirletme)


def test_below_max_not_locked():
    ip = 'throttle-test-b'
    views._login_reset(ip)
    for _ in range(views._LOGIN_MAX_FAILS - 1):
        views._login_note_fail(ip)
    assert not views._login_locked(ip)
    views._login_reset(ip)


def test_reset_clears_counter():
    ip = 'throttle-test-c'
    for _ in range(views._LOGIN_MAX_FAILS):
        views._login_note_fail(ip)
    assert views._login_locked(ip)
    views._login_reset(ip)
    assert not views._login_locked(ip)
