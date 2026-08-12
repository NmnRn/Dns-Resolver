"""project_control.blocklists: hazır listelerin ayrıştırılması + indirilmesi.

parse_blocklist üç formatı da anlamalı (hosts / düz / adblock), yorum ve
domain-olmayan satırları elemeli, domainleri normalize + tekilleştirmeli.
download_and_parse ağa çıkmadan (urlopen sahte) ve boyut sınırına uyarak test
edilir.
"""
import project_control.blocklists as bl
from project_control.blocklists import parse_blocklist, download_and_parse


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
    monkeypatch.setattr(bl.urllib.request, "urlopen", lambda req, timeout=None: resp)
    assert download_and_parse("http://x/list.txt") == {"ad.com", "track.net"}


def test_download_respects_size_cap(monkeypatch):
    resp = _FakeResp(b"0.0.0.0 ad.com\n")
    monkeypatch.setattr(bl.urllib.request, "urlopen", lambda req, timeout=None: resp)
    download_and_parse("http://x/list.txt")
    # read çağrısı en fazla _MAX_BYTES ister → sınırsız bellek tüketimi engellenir
    assert resp.read_n == bl._MAX_BYTES
