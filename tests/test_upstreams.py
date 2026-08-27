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
