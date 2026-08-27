"""Upstream yardımcıları: '#' yorum atlama (_ups_list), IPv6 host:port ayırma
(_split_host_port) ve ikincil (yedek) upstream fallback (_forward)."""
import pytest

import app
from servers.normal_udp import DNSCore


def test_ups_list_skips_comments_and_blanks():
    txt = "1.1.1.1\n# yorum\n   # boşluklu yorum\ntls://dns.google, 9.9.9.9\n\n"
    assert app._ups_list(txt) == ["1.1.1.1", "tls://dns.google", "9.9.9.9"]
    assert app._ups_list("") == []
    assert app._ups_list("# hepsi\n# yorum") == []


def test_split_host_port_ipv6_ipv4_host():
    sp = pytest.importorskip("dashboard.upstream_test")._split_host_port
    assert sp("2a07:a8c0::5a:7dfd", 53) == ("2a07:a8c0::5a:7dfd", 53)   # düz IPv6
    assert sp("[2a07:a8c0::5a:7dfd]:8853", 853) == ("2a07:a8c0::5a:7dfd", 8853)
    assert sp("8.8.8.8", 53) == ("8.8.8.8", 53)
    assert sp("8.8.8.8:5353", 53) == ("8.8.8.8", 5353)
    assert sp("dns.google:853", 53) == ("dns.google", 853)


def test_secondary_upstream_fallback():
    core = DNSCore(db_manager=None)
    core.upstreams = ["1.1.1.1"]
    core.upstreams_secondary = ["9.9.9.9"]
    core.upstream_strategy = "sequential"
    calls = []

    def fake(domain, qtype, up):
        calls.append(up)
        return "RESP" if up == "9.9.9.9" else None   # birincil çuvallar, ikincil yanıtlar

    core._query_forward_one = fake
    resp, up = core._forward("x.com", "A")
    assert resp == "RESP" and up == "9.9.9.9"
    assert calls == ["1.1.1.1", "9.9.9.9"]            # önce birincil, sonra ikincil


def test_af_for_ipv6():
    import socket
    from servers.normal_udp import _af_for
    assert _af_for("2a07:a8c0::5a:7dfd") == socket.AF_INET6
    assert _af_for("8.8.8.8") == socket.AF_INET


def test_forward_ipv6_routing():
    core = DNSCore(db_manager=None)
    seen = {}

    def fake_query(domain, qtype, server_ip, tcp=False, timeout=1.0, port=53, do=False):
        seen["q"] = (server_ip, port, tcp)
        return "R"

    def fake_dot(domain, qtype, host, port=853, timeout=1.0, do=False):
        seen["dot"] = (host, port)
        return "R"

    core._query = fake_query
    core._query_dot = fake_dot
    core._query_forward_one("x.com", "A", "2a07:a8c0::5a:7dfd")     # düz IPv6
    assert seen["q"] == ("2a07:a8c0::5a:7dfd", 53, False)
    core._query_forward_one("x.com", "A", "[2a07::1]:5353")         # [IPv6]:port
    assert seen["q"] == ("2a07::1", 5353, False)
    core._query_forward_one("x.com", "A", "tls://[2606:4700:4700::1111]:853")
    assert seen["dot"] == ("2606:4700:4700::1111", 853)


def test_no_secondary_when_primary_ok():
    core = DNSCore(db_manager=None)
    core.upstreams = ["1.1.1.1"]
    core.upstreams_secondary = ["9.9.9.9"]
    core.upstream_strategy = "sequential"
    calls = []

    def fake(domain, qtype, up):
        calls.append(up)
        return "RESP"                                 # birincil yanıtlıyor

    core._query_forward_one = fake
    resp, up = core._forward("x.com", "A")
    assert up == "1.1.1.1" and calls == ["1.1.1.1"]   # ikincil'e hiç gidilmez


# --- RTT-tabanlı sunucu seçimi (çekirdek modu: root/TLD/yetkili sıralaması) --- #
def test_server_srtt_ewma_and_default():
    core = DNSCore(db_manager=None)
    from servers.normal_udp import SRTT_DEFAULT, SRTT_ALPHA
    assert core._server_srtt_get("1.2.3.4") == SRTT_DEFAULT      # ölçülmemiş → orta değer
    core._record_server_rtt("1.2.3.4", 100.0)                    # ilk ölçüm → aynen
    assert core._server_srtt_get("1.2.3.4") == 100.0
    core._record_server_rtt("1.2.3.4", 20.0)                     # EWMA: 0.3*20 + 0.7*100 = 76
    assert abs(core._server_srtt_get("1.2.3.4") - (SRTT_ALPHA * 20 + (1 - SRTT_ALPHA) * 100)) < 1e-9


def test_query_any_prefers_fastest(monkeypatch):
    """SRTT en düşük (en hızlı) sunucu ilk denenir; keşif kapalıyken sıralı."""
    core = DNSCore(db_manager=None)
    core._record_server_rtt("slow", 300.0)
    core._record_server_rtt("fast", 10.0)
    core._record_server_rtt("mid", 80.0)
    monkeypatch.setattr("servers.normal_udp.random.random", lambda: 1.0)  # keşif YOK → sırala

    order = []
    def fake_query(domain, qtype, ip, do=False):
        order.append(ip)
        return "R" if ip == "fast" else None     # en hızlı yanıtlar → ilk denemede döner
    core._query = fake_query

    resp = core._query_any("x.", "A", ["slow", "mid", "fast"])
    assert resp == "R"
    assert order[0] == "fast"                    # en düşük SRTT ilk


def test_query_any_explore_shuffles(monkeypatch):
    """Keşif olasılığı tetiklenirse rastgele sıralanır (tek IP'ye kilitlenme önlenir)."""
    core = DNSCore(db_manager=None)
    core._record_server_rtt("a", 10.0); core._record_server_rtt("b", 20.0)
    monkeypatch.setattr("servers.normal_udp.random.random", lambda: 0.0)   # < SRTT_EXPLORE → keşif
    seen = {}
    monkeypatch.setattr("servers.normal_udp.random.shuffle",
                        lambda lst: seen.__setitem__("shuffled", True))
    core._query = lambda d, q, ip, do=False: "R"
    core._query_any("x.", "A", ["a", "b"])
    assert seen.get("shuffled") is True          # keşif dalı → shuffle çağrıldı


# --- SRTT arka plan probu (yalnız çekirdek modu) --- #
def test_srtt_probe_round_recursion_only():
    """Prob turu: çekirdek modunda root'ları + TLD glue'sunu ölçer; forward modda /
    kapalıyken HİÇ prob atmaz (dışarı çıkış yok)."""
    import asyncio
    from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A, QTYPE
    from app import _srtt_probe_round

    class _DB:
        def __init__(self, on=True, tlds='com'):
            self._m = {'srtt_probe': '1' if on else '0', 'srtt_probe_tlds': tlds}
        async def get_setting(self, k, d=None):
            return self._m.get(k, d)

    async def _immediate(fn, *args):
        return fn(*args)

    class _Loop:
        def run_in_executor(self, ex, fn, *args):
            return _immediate(fn, *args)

    def make_core():
        c = DNSCore(db_manager=None)
        c.root_servers = {'a': ('10.0.0.1',), 'b': ('10.0.0.2',)}
        return c

    def tld_resp():                              # com. NS → glue A kaydı içeren cevap
        r = DNSRecord(DNSHeader(qr=1), q=DNSQuestion('com.', QTYPE.NS))
        r.add_ar(RR('x.gtld.', QTYPE.A, rdata=A('10.9.9.9'), ttl=3600))
        return r

    # 1) Çekirdek modu → tüm root'lar + TLD glue ölçülür (root'lar önce)
    core = make_core(); probed = []
    core._query = lambda d, q, ip, do=False: probed.append(ip)
    core._query_any = lambda d, q, servers, m=None, do=False: tld_resp()
    asyncio.run(_srtt_probe_round(core, _Loop(), _DB(on=True, tlds='com')))
    assert probed == ['10.0.0.1', '10.0.0.2', '10.9.9.9']

    # 2) Forward modu → HİÇ prob yok
    core2 = make_core(); core2.use_recursion = False; probed2 = []
    core2._query = lambda d, q, ip, do=False: probed2.append(ip)
    core2._query_any = lambda *a, **k: tld_resp()
    asyncio.run(_srtt_probe_round(core2, _Loop(), _DB(on=True)))
    assert probed2 == []

    # 3) Kapalı (srtt_probe=0) → HİÇ prob yok
    core3 = make_core(); probed3 = []
    core3._query = lambda d, q, ip, do=False: probed3.append(ip)
    asyncio.run(_srtt_probe_round(core3, _Loop(), _DB(on=False)))
    assert probed3 == []
