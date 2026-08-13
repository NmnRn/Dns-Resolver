"""DNS sorgu günlüğünde istemci IP'sini (PII) at-rest şifreleme.

DNS_LOG_KEY ortam değişkeni VERİLMİŞSE client_ip deterministik AES-SIV ile
şifrelenip 'enc:<base64>' biçiminde saklanır; verilmemişse düz metin kalır
(geriye uyumlu no-op — mevcut kayıtlar ve anahtarsız kurulumlar aynen çalışır).

Neden deterministik (aynı IP -> aynı şifre): panelin 'en aktif istemci',
COUNT(DISTINCT client_ip) ve GROUP BY client_ip sorguları şifreli sütun üzerinde
çalışmaya devam etsin. Geri-çözülebilir olduğundan panel 'kimden geldi' için
gerçek IP'yi çözerek gösterir. (Deterministik şifreleme değer eşitliğini açığa
çıkarır — analiz çalışsın diye bilinçli bir denge; ham IP yine de gizli kalır.)

İki AYRI process paylaşır: resolver (yazar) + panel (okur/çözer). Bağımlılık
yalnız stdlib + cryptography — proje-içi import yok, süreçleri kuplajlamaz.

Anahtar üretimi (64 bayt = AES-256-SIV):
    python -c "import base64,os;print(base64.b64encode(os.urandom(64)).decode())"
ve .env dosyasına:  DNS_LOG_KEY=...
Anahtar SABİT kalmalı; değişirse eski kayıtların IP'leri çözülemez.
"""
import base64
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV
except Exception:   # cryptography yoksa şifreleme sessizce devre dışı
    AESSIV = None

_PREFIX = "enc:"        # şifreli değeri düz IP'den ayırt etmek için
_siv = None             # tembel başlatılan AESSIV örneği (ya da None)
_init = False


def _load_siv():
    """DNS_LOG_KEY'i env'den oku ve AESSIV kur. Env yoksa/geçersizse None.

    Tembel (ilk kullanımda) çalışır: .env, çağıran process'in başlangıcında zaten
    yüklenmiş olur; import anına bağımlı kalmayız.
    """
    global _siv, _init
    if _init:
        return _siv
    _init = True
    raw = os.getenv("DNS_LOG_KEY", "").strip()
    if not raw or AESSIV is None:
        return None
    try:
        key = base64.b64decode(raw)
    except Exception:
        return None
    if len(key) not in (32, 48, 64):   # AES-SIV geçerli anahtar boyları
        return None
    _siv = AESSIV(key)
    return _siv


def enabled():
    """Şifreleme etkin mi (geçerli DNS_LOG_KEY var mı)?"""
    return _load_siv() is not None


def enc(ip):
    """Düz IP -> 'enc:<base64>' (anahtar varsa); yoksa/boşsa değeri aynen döndürür."""
    siv = _load_siv()
    if not ip or siv is None or str(ip).startswith(_PREFIX):
        return ip                      # boş, kapalı ya da zaten şifreli
    try:
        ct = siv.encrypt(str(ip).encode("utf-8"), None)
        return _PREFIX + base64.b64encode(ct).decode("ascii")
    except Exception:
        return ip                      # şifreleme patlarsa veri kaybetme, düz yaz


def dec(value):
    """'enc:<base64>' -> düz IP; şifresiz/çözülemez ise değeri aynen döndürür."""
    siv = _load_siv()
    if not value or siv is None or not str(value).startswith(_PREFIX):
        return value                   # düz (legacy/kapalı) ya da anahtarsız
    try:
        ct = base64.b64decode(value[len(_PREFIX):])
        return siv.decrypt(ct, None).decode("utf-8")
    except Exception:
        return value                   # yanlış anahtar/bozuk → ham değeri göster
