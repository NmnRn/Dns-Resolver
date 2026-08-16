"""Web panosu (Django) saf yardımcıları: _sparkline, _with_pct, _cert_path ve
sertifika doğrulaması check_cert.

Django kurulumu conftest'te yapılır; import edilemezse tüm modül atlanır.
check_cert, cryptography ile üretilen kendinden-imzalı sertifikalara karşı
sınanır (dosya /app'e değil tmp'ye yazılır; mutlak yol olduğundan olduğu gibi
kullanılır).
"""
from datetime import datetime, timedelta, timezone

import pytest

try:
    from dashboard import views
except Exception as exc:  # pragma: no cover - Django yoksa
    pytest.skip(f"dashboard import edilemedi: {exc}", allow_module_level=True)


# --------------------------------------------------------------------------- #
# _sparkline
# --------------------------------------------------------------------------- #
def test_sparkline_empty_returns_none():
    assert views._sparkline([]) is None


def test_sparkline_shape_and_endpoints():
    sp = views._sparkline([0, 5, 10], w=100, h=50, pad=5)
    assert set(sp) >= {"line", "area", "w", "h", "dx", "dy"}
    assert sp["line"].startswith("0.0,")   # ilk nokta x=0
    assert sp["dx"] == 100                  # son nokta x=w
    assert sp["area"].endswith("Z")         # alan kapalı yol


def test_sparkline_max_at_top_min_at_bottom():
    sp = views._sparkline([0, 10], w=10, h=50, pad=5)
    ys = [float(p.split(",")[1]) for p in sp["line"].split()]
    assert min(ys) == 5.0    # en büyük değer üstte (y = pad)
    assert max(ys) == 45.0   # en küçük değer altta (y = h - pad)


# --------------------------------------------------------------------------- #
# _with_pct
# --------------------------------------------------------------------------- #
def test_with_pct_scales_to_max():
    out = views._with_pct([{"cnt": 10}, {"cnt": 5}, {"cnt": 0}])
    assert [r["pct"] for r in out] == [100, 50, 0]


def test_with_pct_empty_is_safe():
    assert views._with_pct([]) == []


def test_with_pct_custom_key():
    out = views._with_pct([{"n": 4}, {"n": 2}], key="n")
    assert [r["pct"] for r in out] == [100, 50]


# --------------------------------------------------------------------------- #
# _valid_port  (panelden ayarlanabilir iç dinleme portu doğrulaması)
# --------------------------------------------------------------------------- #
def test_valid_port_accepts_range():
    assert views._valid_port("53")
    assert views._valid_port("5300")
    assert views._valid_port(65535)
    assert views._valid_port(" 853 ")  # boşluk tolere edilir


def test_valid_port_rejects_out_of_range():
    assert not views._valid_port("0")
    assert not views._valid_port("65536")
    assert not views._valid_port("-1")


def test_valid_port_rejects_non_numeric():
    assert not views._valid_port("abc")
    assert not views._valid_port("")
    assert not views._valid_port(None)
    assert not views._valid_port("80.5")


# --------------------------------------------------------------------------- #
# _cert_path
# --------------------------------------------------------------------------- #
def test_cert_path_relative_resolved_under_app():
    assert views._cert_path("certificates/x.pem") == "/app/certificates/x.pem"


def test_cert_path_absolute_unchanged():
    assert views._cert_path("/etc/ssl/x.pem") == "/etc/ssl/x.pem"


def test_cert_path_empty():
    assert views._cert_path("") == ""


# --------------------------------------------------------------------------- #
# _auto_list_name  (isim verilmeyen özel liste için URL'den kısa ad)
# --------------------------------------------------------------------------- #
def test_auto_list_name_last_segment():
    assert views._auto_list_name("https://x.com/a/b/multi.txt") == "multi"
    assert views._auto_list_name(
        "https://raw.githubusercontent.com/h/d/refs/heads/main/adblock/ultimate.txt") == "ultimate"


def test_auto_list_name_falls_back_to_host():
    assert views._auto_list_name("https://small.oisd.nl/") == "small.oisd.nl"


# --------------------------------------------------------------------------- #
# Zamanlama saat ayrıştırma + DNS rewrite doğrulayıcıları
# --------------------------------------------------------------------------- #
def test_hhmm_to_min():
    assert views._hhmm_to_min("09:00") == 540
    assert views._hhmm_to_min("00:00") == 0
    assert views._hhmm_to_min("23:59") == 1439


def test_hhmm_to_min_invalid():
    assert views._hhmm_to_min("24:00") is None   # saat 0–23
    assert views._hhmm_to_min("12:60") is None   # dakika 0–59
    assert views._hhmm_to_min("9") is None
    assert views._hhmm_to_min("") is None
    assert views._hhmm_to_min("ab:cd") is None


def test_valid_rewrite_domain():
    assert views._valid_rewrite_domain("nas.example.com")
    assert views._valid_rewrite_domain("*.reklam.example.com")   # wildcard
    assert not views._valid_rewrite_domain("")
    assert not views._valid_rewrite_domain("*.")
    assert not views._valid_rewrite_domain("nodots")             # tek etiket, TLD yok


def test_valid_rewrite_answer():
    assert views._valid_rewrite_answer("192.168.1.10")           # IPv4
    assert views._valid_rewrite_answer("2001:db8::1")            # IPv6
    assert views._valid_rewrite_answer("0.0.0.0")               # sinkhole
    assert views._valid_rewrite_answer("hedef.example.com")      # domain (CNAME)
    assert not views._valid_rewrite_answer("")
    assert not views._valid_rewrite_answer("ne ip ne domain !!")


# --------------------------------------------------------------------------- #
# check_cert  (kendinden-imzalı sertifika üreterek)
# --------------------------------------------------------------------------- #
def _write_cert(path, not_before, not_after, cn="dns.test"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _now():
    # cryptography sürümleri arası uyum için naive-UTC kullan.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def test_check_cert_valid(tmp_path):
    p = tmp_path / "c.pem"
    now = _now()
    _write_cert(p, now - timedelta(days=1), now + timedelta(days=90), cn="dns.example")
    info = views.check_cert(str(p))
    assert "error" not in info
    assert info["status"] == "VALID"
    assert info["subject"] == "dns.example"
    assert info["issuer"] == "dns.example"
    assert info["days"] >= 88


def test_check_cert_expiring_soon(tmp_path):
    p = tmp_path / "c.pem"
    now = _now()
    _write_cert(p, now - timedelta(days=1), now + timedelta(days=10))
    assert views.check_cert(str(p))["status"] == "EXPIRING"


def test_check_cert_expired(tmp_path):
    p = tmp_path / "c.pem"
    now = _now()
    _write_cert(p, now - timedelta(days=5), now - timedelta(days=1))
    info = views.check_cert(str(p))
    assert info["status"] == "EXPIRED"
    assert info["days"] < 0


def test_check_cert_missing_file(tmp_path):
    info = views.check_cert(str(tmp_path / "yok.pem"))
    assert "error" in info and "bulunamadı" in info["error"]


def test_check_cert_empty_path():
    assert "error" in views.check_cert("")


def test_check_cert_garbage_file(tmp_path):
    p = tmp_path / "bad.pem"
    p.write_bytes(b"bu bir sertifika degil")
    assert "error" in views.check_cert(str(p))
