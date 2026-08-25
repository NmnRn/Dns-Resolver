"""Blocklist indirme SSRF korumaları: iç/metadata adres + tehlikeli şema reddi +
redirect hedefinin yeniden-doğrulanması. Literal IP kullanılır → DNS/ağ YOK."""
import pytest

from project_control import blocklists


def test_assert_safe_url_blocks_internal_and_schemes():
    for bad in ["http://169.254.169.254/latest/meta-data/",   # bulut metadata (link-local)
                "http://127.0.0.1/", "https://127.0.0.1/", "http://[::1]/",
                "file:///etc/passwd", "gopher://x/", "ftp://x/"]:
        with pytest.raises(ValueError):
            blocklists._assert_safe_url(bad)


def test_redirect_target_reblocked():
    h = blocklists._SafeRedirectHandler()
    # İlk URL güvenli olsa bile redirect iç/metadata adrese GİDEMEZ
    for bad in ["http://169.254.169.254/", "http://127.0.0.1/admin"]:
        with pytest.raises(ValueError):
            h.redirect_request(None, None, 302, "Found", {}, bad)
