"""WHOIS yardımcısı (dashboard.views._whois): IANA referral'ı takip eder → RIR'i
sorgular. Soket MOCK'lanır → CANLI ağ YOK."""
import pytest

django = pytest.importorskip("django")
from dashboard import views   # conftest django.setup + path ayarı yapar


class _FakeSock:
    def __init__(self, data):
        self._data = data
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def sendall(self, b):
        pass
    def recv(self, n):
        d, self._data = self._data, b""
        return d


def test_whois_follows_iana_referral(monkeypatch):
    responses = {
        "whois.iana.org": b"refer:        whois.arin.net\n\n% IANA\n",
        "whois.arin.net": b"NetName:        EXAMPLE-NET\nOrganization:   Example ISP\nCountry: TR\n",
    }
    calls = []

    def fake_conn(addr, timeout=None):
        calls.append(addr[0])
        return _FakeSock(responses.get(addr[0], b""))

    monkeypatch.setattr(views.socket, "create_connection", fake_conn)
    out = views._whois("1.2.3.4")
    assert "EXAMPLE-NET" in out and "Example ISP" in out
    assert calls == ["whois.iana.org", "whois.arin.net"]   # IANA → RIR


def test_whois_no_referral_returns_iana(monkeypatch):
    def fake_conn(addr, timeout=None):
        return _FakeSock(b"% referral yok\naddress: bir yer\n")

    monkeypatch.setattr(views.socket, "create_connection", fake_conn)
    out = views._whois("2.2.2.2")
    assert "bir yer" in out


def test_whois_domain_uses_tld_then_registry(monkeypatch):
    # alan adı → IANA'ya TLD ('com') sorulur, 'whois:' referral'ı takip edilir,
    # sonra tam alan adı registry'ye sorulur.
    responses = {
        "whois.iana.org": b"whois:        whois.verisign-grs.com\n",
        "whois.verisign-grs.com": b"Domain Name: EXAMPLE.COM\nRegistrar: Test Reg\n",
    }
    calls = []

    def fake_conn(addr, timeout=None):
        calls.append(addr[0])
        return _FakeSock(responses.get(addr[0], b""))

    monkeypatch.setattr(views.socket, "create_connection", fake_conn)
    out = views._whois("example.com")
    assert "Test Reg" in out
    assert calls == ["whois.iana.org", "whois.verisign-grs.com"]
