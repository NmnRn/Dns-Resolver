"""WHOIS yardımcısı (dashboard.views._whois): IANA referral'ı takip eder → RIR'i
sorgular. Soket MOCK'lanır → CANLI ağ YOK."""
import ipaddress

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


def test_local_ip_note_private_and_loopback():
    assert "yerel" in views._local_ip_note(ipaddress.ip_address("192.168.1.5")).lower()
    assert views._local_ip_note(ipaddress.ip_address("10.5.5.5")) is not None      # RFC1918
    assert views._local_ip_note(ipaddress.ip_address("127.0.0.1")) is not None     # loopback


def test_local_ip_note_public_is_none(monkeypatch):
    monkeypatch.setattr(views, "_server_ips", lambda: [])   # dns-net /24 eşleşmesin
    assert views._local_ip_note(ipaddress.ip_address("1.1.1.1")) is None


def test_local_ip_note_dns_net_subnet(monkeypatch):
    monkeypatch.setattr(views, "_server_ips", lambda: ["172.27.17.2"])   # konteyner IP
    note = views._local_ip_note(ipaddress.ip_address("172.27.17.9"))
    assert note is not None and "dns-net" in note


def test_vcard_name():
    vc = ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Org"]]]
    assert views._vcard_name(vc) == "Example Org"
    assert views._vcard_name(None) == ""


def test_rdap_format_ip():
    data = {"startAddress": "1.1.1.0", "endAddress": "1.1.1.255", "name": "APNIC-LABS",
            "type": "ALLOCATED", "country": "AU",
            "entities": [{"roles": ["registrant"],
                          "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                   ["fn", {}, "text", "Cloudflare"]]]}],
            "events": [{"eventAction": "registration", "eventDate": "2011-01-01"}]}
    out = views._rdap_format(data, "ip")
    assert "1.1.1.0" in out and "APNIC-LABS" in out and "Cloudflare" in out and "registration" in out


def test_rdap_format_domain():
    data = {"ldhName": "EXAMPLE.COM", "status": ["client transfer prohibited"],
            "entities": [{"roles": ["registrar"], "handle": "376"}],
            "events": [{"eventAction": "expiration", "eventDate": "2027-08-13"}]}
    out = views._rdap_format(data, "domain")
    assert "EXAMPLE.COM" in out and "registrar" in out and "expiration" in out
