"""DoH ASGI app (servers/doh_app): GET (?dns=base64url) + POST wire, Host/path 404,
ACL REFUSED, NXDOMAIN/SERVFAIL. Hypercorn GEREKMEZ — ASGI callable doğrudan sürülür."""
import asyncio
import base64
import json
import os

import pytest
from dnslib import DNSRecord, RCODE, RR, QTYPE, A

import config_store
from servers import doh_app


@pytest.fixture(autouse=True)
def _cfg(tmp_path, monkeypatch):
    p = tmp_path / "servers.json"
    p.write_text(json.dumps({"allowed_host": "dns.example.com",
                             "methods": {"doh": {"enabled": True, "container_port": 44300}}}))
    monkeypatch.setenv("SERVERS_CONFIG", str(p))
    config_store._reset_cache()
    yield
    config_store._reset_cache()


class _DBM:
    def __init__(self):
        self.cached = []
    def utc_now(self):
        return "2026-01-01 00:00:00"
    def add_to_cache(self, key, value):
        self.cached.append((key, value))


class _Core:
    def __init__(self, rcode=RCODE.NOERROR, records=None, allow=True, blocked=None):
        self.db_manager = _DBM()
        self._rcode, self._records, self._allow, self._blocked = rcode, records or [], allow, blocked
        self.resolved = []
    def access_ok(self, ip):
        return self._allow
    def is_blocked(self, q):
        return self._blocked
    def resolve(self, qname, qtype, source=None):
        if source is not None:
            source[0] = "test-kaynak"
        self.resolved.append((qname, qtype))
        return self._rcode, self._records


def _scope(method, path="/dns-query", query=b"", host="dns.example.com", client="1.2.3.4"):
    return {"type": "http", "method": method, "path": path, "query_string": query,
            "headers": [(b"host", host.encode())], "client": (client, 1234)}


def _drive(app, scope, body=b""):
    sent = []
    state = {"sent_body": False}

    async def receive():
        if not state["sent_body"]:
            state["sent_body"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(msg):
        sent.append(msg)

    asyncio.run(app(scope, receive, send))
    return sent


def _status(sent):
    return sent[0]["status"]


def _body(sent):
    return b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def _wire(name="example.com", qtype="A"):
    return DNSRecord.question(name, qtype).pack()


def test_post_valid_returns_answer():
    recs = [RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60)]
    core = _Core(records=recs)
    app = doh_app.make_app(core)
    sent = _drive(app, _scope("POST"), body=_wire())
    assert _status(sent) == 200
    assert sent[0]["headers"][0] == (b"content-type", b"application/dns-message")
    resp = DNSRecord.parse(_body(sent))
    assert resp.header.rcode == RCODE.NOERROR
    assert core.resolved == [("example.com.", "A")]
    assert core.db_manager.cached and core.db_manager.cached[0][1]["method"] == "doh"


def test_get_valid_base64url():
    core = _Core()
    app = doh_app.make_app(core)
    dns = base64.urlsafe_b64encode(_wire()).rstrip(b"=")
    sent = _drive(app, _scope("GET", query=b"dns=" + dns))
    assert _status(sent) == 200
    assert core.resolved == [("example.com.", "A")]


def test_wrong_host_404():
    core = _Core()
    sent = _drive(doh_app.make_app(core), _scope("POST", host="evil.example.net"), body=_wire())
    assert _status(sent) == 404
    assert core.resolved == []


def test_wrong_path_404():
    core = _Core()
    sent = _drive(doh_app.make_app(core), _scope("POST", path="/other"), body=_wire())
    assert _status(sent) == 404


def test_get_without_dns_param_400():
    core = _Core()
    sent = _drive(doh_app.make_app(core), _scope("GET"))
    assert _status(sent) == 400


def test_bad_wire_400():
    core = _Core()
    sent = _drive(doh_app.make_app(core), _scope("POST"), body=b"not-a-dns-message")
    assert _status(sent) == 400


def test_acl_refused():
    core = _Core(allow=False)
    sent = _drive(doh_app.make_app(core), _scope("POST"), body=_wire())
    assert _status(sent) == 200
    assert DNSRecord.parse(_body(sent)).header.rcode == RCODE.REFUSED
    assert core.resolved == []       # çözümlemeye gitmedi


def test_method_not_allowed_405():
    core = _Core()
    sent = _drive(doh_app.make_app(core), _scope("PUT"), body=_wire())
    assert _status(sent) == 405


def test_nxdomain_passthrough():
    core = _Core(rcode=RCODE.NXDOMAIN)
    sent = _drive(doh_app.make_app(core), _scope("POST"), body=_wire())
    assert DNSRecord.parse(_body(sent)).header.rcode == RCODE.NXDOMAIN
