"""logcrypto: client_ip at-rest şifreleme (DNS_LOG_KEY).

Anahtar yoksa no-op (düz metin, geriye uyumlu); varsa deterministik AES-SIV
(aynı IP → aynı şifre, GROUP BY çalışsın) + geri çözme (panel gerçek IP'yi gösterir).
"""
import base64
import os

import pytest

import logcrypto


def _use(key):
    """Anahtarı ayarla (None=kaldır) ve tembel başlatma durumunu sıfırla."""
    if key is None:
        os.environ.pop('DNS_LOG_KEY', None)
    else:
        os.environ['DNS_LOG_KEY'] = key
    logcrypto._siv = None
    logcrypto._init = False


@pytest.fixture(autouse=True)
def _isolate():
    """Her testi izole et: DNS_LOG_KEY'i ve modül durumunu geri yükle."""
    saved = os.environ.get('DNS_LOG_KEY')
    _use(None)
    yield
    _use(saved)


def _key():
    return base64.b64encode(os.urandom(64)).decode()   # 64 bayt = AES-256-SIV


def test_noop_without_key():
    _use(None)
    assert not logcrypto.enabled()
    assert logcrypto.enc('1.2.3.4') == '1.2.3.4'
    assert logcrypto.dec('1.2.3.4') == '1.2.3.4'


def test_roundtrip_with_key():
    _use(_key())
    assert logcrypto.enabled()
    ct = logcrypto.enc('192.168.1.55')
    assert ct.startswith('enc:') and ct != '192.168.1.55'
    assert logcrypto.dec(ct) == '192.168.1.55'


def test_deterministic_same_ip_same_ct():
    _use(_key())
    assert logcrypto.enc('10.0.0.1') == logcrypto.enc('10.0.0.1')   # GROUP BY/DISTINCT için
    assert logcrypto.enc('10.0.0.1') != logcrypto.enc('10.0.0.2')


def test_ipv6_fits_column():
    _use(_key())
    ip6 = '0000:0000:0000:0000:0000:ffff:255.255.255.255'  # 45 char (en uzun IPv6)
    ct = logcrypto.enc(ip6)
    assert len(ct) <= 120                 # dns_cache.client_ip VARCHAR(120)
    assert logcrypto.dec(ct) == ip6


def test_dec_plaintext_passthrough():
    _use(_key())
    assert logcrypto.dec('8.8.8.8') == '8.8.8.8'   # prefixsiz düz (legacy) değer korunur


def test_double_encrypt_guard():
    _use(_key())
    ct = logcrypto.enc('1.2.3.4')
    assert logcrypto.enc(ct) == ct         # zaten şifreli → tekrar şifrelenmez


def test_empty_and_none_preserved():
    _use(_key())
    assert logcrypto.enc('') == ''
    assert logcrypto.enc(None) is None
    assert logcrypto.dec(None) is None


def test_invalid_key_disables():
    _use('not-base64-!!')                   # geçersiz anahtar → şifreleme kapalı (güvenli)
    assert not logcrypto.enabled()
    assert logcrypto.enc('1.2.3.4') == '1.2.3.4'
