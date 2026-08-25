"""project_control.blocklists: hazır listelerin ayrıştırılması + indirilmesi.

parse_blocklist üç formatı da anlamalı (hosts / düz / adblock), yorum ve
domain-olmayan satırları elemeli, domainleri normalize + tekilleştirmeli.
download_and_parse ağa çıkmadan (urlopen sahte) ve boyut sınırına uyarak test
edilir.
"""
import pytest

import project_control.blocklists as bl
from project_control.blocklists import parse_blocklist, download_and_parse, normalize_url


def test_normalize_github_blob_to_raw():
    # Kullanıcı GitHub'ın HTML (blob) linkini yapıştırırsa ham linke çevrilmeli.
    blob = "https://github.com/hagezi/dns-blocklists/blob/main/share/ad-shield-subdomains.txt"
    assert normalize_url(blob) == \
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/ad-shield-subdomains.txt"


def test_normalize_leaves_raw_and_others_unchanged():
    raw = "https://raw.githubusercontent.com/x/y/main/a.txt"
    assert normalize_url(raw) == raw
    assert normalize_url("https://small.oisd.nl/") == "https://small.oisd.nl/"
    assert normalize_url("  https://example.com/list.txt  ") == "https://example.com/list.txt"


def test_parses_hosts_format():
    out = parse_blocklist("0.0.0.0 ads.example.com\n127.0.0.1 tracker.net")
    assert out == {"ads.example.com", "tracker.net"}


def test_parses_adblock_format():
    assert parse_blocklist("||doubleclick.net^") == {"doubleclick.net"}
    # ^ sonrası ek modifier'lar (ör. $third-party) domaini bozmamalı
    assert parse_blocklist("||ads.example.com^$third-party") == {"ads.example.com"}


def test_parses_plain_domains():
    assert parse_blocklist("evil.com\nbad.org\n") == {"evil.com", "bad.org"}


def test_skips_comments_and_blank_lines():
    txt = "# hosts yorumu\n! adblock yorumu\n\n   \ngood.com\n"
    assert parse_blocklist(txt) == {"good.com"}


def test_skips_localhost_style_entries():
    txt = "127.0.0.1 localhost\n0.0.0.0 broadcasthost\n::1 ip6-localhost\n0.0.0.0 real-ad.com"
    assert parse_blocklist(txt) == {"real-ad.com"}


def test_normalizes_case_and_trailing_dot():
    assert parse_blocklist("0.0.0.0 ADS.Example.COM.") == {"ads.example.com"}


def test_rejects_non_domains():
    # IP-benzeri, tek etiket ve içinde boşluk olan hedefler elenmeli
    txt = "0.0.0.0 999\nplainword\n0.0.0.0 has space\n0.0.0.0 ok-domain.com"
    assert parse_blocklist(txt) == {"ok-domain.com"}


def test_dedups_across_formats():
    assert parse_blocklist("ads.com\n0.0.0.0 ads.com\n||ads.com^") == {"ads.com"}


def test_empty_input():
    assert parse_blocklist("") == set()


# --- download_and_parse: urlopen'ı sahteleyerek (ağsız) ---------------------
class _FakeResp:
    def __init__(self, data):
        self._data = data
        self.read_n = None

    def read(self, n=-1):
        self.read_n = n
        return self._data if n is None or n < 0 else self._data[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_download_and_parse(monkeypatch):
    resp = _FakeResp(b"0.0.0.0 ad.com\n||track.net^\n# yorum\n")
    monkeypatch.setattr(bl, "_assert_safe_url", lambda url: None)   # SSRF ağ kontrolünü atla
    monkeypatch.setattr(bl._OPENER, "open", lambda req, timeout=None: resp)
    assert download_and_parse("http://x/list.txt") == {"ad.com", "track.net"}


def test_download_respects_size_cap(monkeypatch):
    resp = _FakeResp(b"0.0.0.0 ad.com\n")
    monkeypatch.setattr(bl, "_assert_safe_url", lambda url: None)
    monkeypatch.setattr(bl._OPENER, "open", lambda req, timeout=None: resp)
    download_and_parse("http://x/list.txt")
    # read çağrısı en fazla _MAX_BYTES ister → sınırsız bellek tüketimi engellenir
    assert resp.read_n == bl._MAX_BYTES


# --- SSRF: iç/metadata adresleri reddet, LAN + public izin ------------------
def _fake_gai(ip):
    """socket.getaddrinfo yerine tek IP döndüren sahte (ağa çıkmadan test)."""
    return lambda host, port, **kw: [(2, 1, 6, "", (ip, port))]


def test_assert_safe_url_blocks_internal(monkeypatch):
    # loopback / link-local (bulut-metadata) / unspecified → RED
    for bad in ("127.0.0.1", "169.254.169.254", "0.0.0.0"):
        monkeypatch.setattr(bl.socket, "getaddrinfo", _fake_gai(bad))
        with pytest.raises(ValueError):
            bl._assert_safe_url("http://evil.example/x")
    # http/https dışı şema → RED (getaddrinfo'ya bile gitmez)
    with pytest.raises(ValueError):
        bl._assert_safe_url("ftp://x/y")


def test_assert_safe_url_allows_public_and_lan(monkeypatch):
    monkeypatch.setattr(bl.socket, "getaddrinfo", _fake_gai("1.2.3.4"))
    bl._assert_safe_url("https://ok.example/list.txt")     # public → raise YOK
    monkeypatch.setattr(bl.socket, "getaddrinfo", _fake_gai("192.168.1.10"))
    bl._assert_safe_url("http://lan.example/list.txt")     # özel LAN aynası → izin


# --- check_link: erişilebilirlik (listeyi indirmeden, HEAD/küçük-GET) -------
class _Resp:
    """urlopen bağlam-yöneticisi taklidi (status alanlı)."""
    def __init__(self, status): self.status = status
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _http_error(code, reason="err"):
    return bl.urllib.error.HTTPError("http://x", code, reason, {}, None)


def test_check_link_ssrf_returns_error_not_raise(monkeypatch):
    # SSRF iç adres → istisna FIRLATMAZ, {ok:False,warn:False} döner
    monkeypatch.setattr(bl.socket, "getaddrinfo", _fake_gai("127.0.0.1"))
    r = bl.check_link("http://evil.example/x")
    assert r["ok"] is False and r["warn"] is False


def test_check_link_ok_2xx(monkeypatch):
    monkeypatch.setattr(bl, "_assert_safe_url", lambda url: None)
    monkeypatch.setattr(bl._OPENER, "open", lambda req, timeout=None: _Resp(200))
    r = bl.check_link("https://ok.example/list.txt")
    assert r["ok"] is True and r["status"] == 200


def test_check_link_404_is_broken(monkeypatch):
    monkeypatch.setattr(bl, "_assert_safe_url", lambda url: None)
    def _op(req, timeout=None): raise _http_error(404, "Not Found")
    monkeypatch.setattr(bl._OPENER, "open", _op)
    r = bl.check_link("https://x.example/gone.txt")
    assert r["ok"] is False and r["warn"] is False and r["status"] == 404


def test_check_link_429_is_warn(monkeypatch):
    # GitHub raw HEAD'e 429 döndürebilir → kırık DEĞİL, uyarı
    monkeypatch.setattr(bl, "_assert_safe_url", lambda url: None)
    def _op(req, timeout=None): raise _http_error(429, "Too Many Requests")
    monkeypatch.setattr(bl._OPENER, "open", _op)
    r = bl.check_link("https://raw.example/list.txt")
    assert r["ok"] is False and r["warn"] is True and r["status"] == 429


def test_check_link_head_403_falls_back_to_get(monkeypatch):
    # HEAD 403 → GET'e düş; GET 200 → erişilebilir
    monkeypatch.setattr(bl, "_assert_safe_url", lambda url: None)
    calls = []
    def _op(req, timeout=None):
        calls.append(req.get_method())
        if req.get_method() == "HEAD":
            raise _http_error(403, "Forbidden")
        return _Resp(200)
    monkeypatch.setattr(bl._OPENER, "open", _op)
    r = bl.check_link("https://x.example/list.txt")
    assert r["ok"] is True and "HEAD" in calls and "GET" in calls
