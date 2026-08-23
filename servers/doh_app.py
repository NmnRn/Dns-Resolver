"""DoH sunucusu — ASGI uygulaması (Hypercorn ile HTTP/2 + HTTP/1.1).

RFC 8484:
  * GET  /dns-query?dns=<base64url, pad'siz>   (do_GET desteği)
  * POST /dns-query   body: application/dns-message

Eski BaseHTTPServer (yalnız POST, HTTP/1.1) yerine geçer. `core.resolve`
BLOKLAYICI olduğundan `run_in_executor` ile threadpool'a alınır — aksi hâlde
tek bir sorgu tüm HTTP/2 bağlantısını kilitler.

Host/allowed_host + iç port config_store'dan (config/servers.json) okunur.
Mahremiyet: istemci IP + sorgulanan ad LOGLANMAZ (yalnız DB'de gerçek tutulur).
"""
import asyncio
import base64
from urllib.parse import parse_qs

from dnslib import QTYPE, RCODE, DNSRecord

import config_store
from logs.dns_logs import logger
from servers.normal_udp import status_for, _clean_reply

DNS_QUERY_PATH = "/dns-query"
DNS_MSG = b"application/dns-message"


async def _send(send, status: int, body: bytes = b"", content_type: bytes = b"text/plain"):
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", content_type),
                    (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body})


async def _read_body(receive) -> bytes:
    body = b""
    while True:
        msg = await receive()
        if msg["type"] == "http.request":
            body += msg.get("body", b"")
            if not msg.get("more_body"):
                break
        elif msg["type"] == "http.disconnect":
            break
    return body


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # pad'siz base64url


def make_app(core):
    """core'a bağlı ASGI callable üretir (Hypercorn'a verilir)."""

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        istek_ani = core.db_manager.utc_now()  # çözümleme öncesi (log damgası)

        headers = {k.decode("latin1").lower(): v.decode("latin1")
                   for k, v in scope.get("headers", [])}
        host = headers.get("host", "").split(":")[0]
        allowed = (config_store.get_config().get("allowed_host") or "").strip()

        if scope.get("path") != DNS_QUERY_PATH or (allowed and host != allowed):
            await _send(send, 404)
            return

        method = scope["method"]
        if method == "GET":
            dns_b64 = (parse_qs(scope.get("query_string", b"").decode("latin1")).get("dns") or [""])[0]
            if not dns_b64:
                await _send(send, 400)
                return
            try:
                wire = _b64url_decode(dns_b64)
            except Exception:
                await _send(send, 400)
                return
        elif method == "POST":
            wire = await _read_body(receive)
        else:
            await _send(send, 405)
            return

        try:
            request = DNSRecord.parse(wire)
        except Exception:
            await _send(send, 400)
            return

        qname = str(request.q.qname)
        if not qname.endswith("."):
            qname += "."
        qtype = QTYPE[request.q.qtype]
        client_ip = (scope.get("client") or ("", 0))[0]

        if not core.access_ok(client_ip):          # ACL / rate limit → sessiz REFUSED
            reply = _clean_reply(request)
            reply.header.rcode = RCODE.REFUSED
            await _send(send, 200, reply.pack(), DNS_MSG)
            return

        # core.resolve BLOKLAYICI (ağ) → executor'a al (H2 kilitlenmesin).
        loop = asyncio.get_event_loop()
        src = ["—"]
        ds = ["off"]
        rcode, records = await loop.run_in_executor(
            None, lambda: core.resolve(qname, qtype, source=src, dnssec_out=ds)
        )
        reply = _clean_reply(request)
        if rcode == RCODE.NXDOMAIN:
            reply.header.rcode = RCODE.NXDOMAIN
        elif rcode == RCODE.SERVFAIL:
            reply.header.rcode = RCODE.SERVFAIL
        else:
            reply.rr = list(records)
        if ds[0] == "secure":
            reply.header.ad = 1
        reply_bytes = reply.pack()

        log = logger.warning if rcode == RCODE.SERVFAIL else logger.info
        log("(DoH) **** **** %s -> %s (%d kayit)", qtype, RCODE[rcode], len(records))

        blocked_by = core.is_blocked(qname)
        core.db_manager.add_to_cache(key=qname, value={
            "record_type": qtype, "client_ip": client_ip, "queried_at": istek_ani,
            "method": "doh", "blocked": bool(blocked_by), "blocked_by": blocked_by,
            "resolved_by": src[0], "status": status_for(rcode, bool(blocked_by)), "dnssec": ds[0],
        })
        await _send(send, 200, reply_bytes, DNS_MSG)

    return app
