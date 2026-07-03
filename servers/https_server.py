import ssl
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnslib import QTYPE, RCODE, DNSRecord
from dotenv import load_dotenv

import settings

settings.control_env_file()
load_dotenv(settings.PROJECT_DIRECTORY / ".env")

from logs.dns_logs import logger

DNS_QUERY_PATH = "/dns-query"
ALLOWED_HOST = os.getenv("ALLOWED_HOST", "dns.example.com")


class DoHHandler(BaseHTTPRequestHandler):
    """RFC 8484: DNS sorgusunu HTTP body'sinde ham wire-format olarak alır."""

    def __init__(self, core, *args, **kwargs):
        self.core = core
        super().__init__(*args, **kwargs)

    def _reject(self, code):
        self.send_response(code)
        self.end_headers()

    def do_POST(self):
        host = self.headers.get("Host", "").split(":")[0]
        if self.path != DNS_QUERY_PATH or host != ALLOWED_HOST:
            self._reject(404)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            request = DNSRecord.parse(body)
        except Exception:
            self._reject(400)
            return

        qname = str(request.q.qname)
        if not qname.endswith("."):
            qname += "."
        qtype = QTYPE[request.q.qtype]
        client_ip = self.client_address[0]

        rcode, records = self.core.resolve(qname, qtype)

        reply = request.reply()
        if rcode == RCODE.NXDOMAIN:
            reply.header.rcode = RCODE.NXDOMAIN
        elif rcode == RCODE.SERVFAIL:
            reply.header.rcode = RCODE.SERVFAIL
        else:
            reply.rr = list(records)
        reply_bytes = reply.pack()

        log = logger.warning if rcode == RCODE.SERVFAIL else logger.info
        log("(DoH) %s %s %s -> %s (%d kayıt)", client_ip, qname, qtype, RCODE[rcode], len(records))

        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(reply_bytes)))
        self.end_headers()
        self.wfile.write(reply_bytes)

    def log_message(self, format, *args):
        pass  # BaseHTTPRequestHandler'ın kendi stderr logunu kapat, biz zaten logluyoruz


def _make_handler(core):
    """socketserver her bağlantı için HandlerClass(request, client_address, server)
    çağırır - bu factory, core'u araya gizlice ekleyip doğru sıraya sokuyor."""
    def handler(*args, **kwargs):
        return DoHHandler(core, *args, **kwargs)
    return handler


def build_server(core, bind="0.0.0.0", port=44300, certfile=None, keyfile=None):
    """Sunucuyu kurar ama başlatmaz (.serve_forever() çağrılmaz) - app.py'nin
    diğer sunucularla aynı şekilde thread'e verip yönetebilmesi için."""
    server = ThreadingHTTPServer((bind, port), _make_handler(core))

    has_certs = certfile and keyfile and os.path.exists(certfile) and os.path.exists(keyfile)
    if has_certs:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    scheme = "https" if has_certs else "http"
    if not has_certs:
        logger.warning(
            "DoH sunucusu sertifikasız başlatılıyor: trafik DÜZ HTTP (şifresiz)! "
            "Yalnızca önünde TLS sonlandıran bir proxy (ör. Cloudflare Tunnel) varsa güvenli."
        )
        print("UYARI: DoH sertifikasız - düz HTTP olarak başlatılıyor (şifresiz).")
    print(f"DoH sunucusu başlatıldı: {scheme}://{bind}:{port}{DNS_QUERY_PATH}")
    logger.info("DoH sunucusu başlatıldı: %s://%s:%d%s", scheme, bind, port, DNS_QUERY_PATH)
    return server


def run(core, bind="0.0.0.0", port=44300, certfile=None, keyfile=None):
    """Bağımsız/test amaçlı: sunucuyu kurar ve doğrudan bloklayarak çalıştırır."""
    build_server(core, bind, port, certfile, keyfile).serve_forever()
