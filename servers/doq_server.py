import os
from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from dotenv import load_dotenv
import asyncio
from project_control import settings

from dnslib import QTYPE, RCODE, DNSRecord
from logs.dns_logs import logger
from servers.normal_udp import status_for, _clean_reply

load_dotenv(settings.PROJECT_DIRECTORY / ".env")


def _log_query_task(task):
    """DoQ sorgu işleme görevi sessizce hata verirse logla."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("DoQ sorgu işleme görevi hata verdi: %r", exc)


class DoQProtocol(QuicConnectionProtocol):
    def __init__(self, core, *args, **kwargs):
        self.core = core
        super().__init__(*args, **kwargs)
        self.buffers = {}  # stream_id -> bytes

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            buf = self.buffers.get(event.stream_id, b"")
            buf += event.data

            if len(buf) < 2:
                # henüz length prefix gelmedi
                self.buffers[event.stream_id] = buf
                return
            
            n = int.from_bytes(buf[:2], "big")
            if len(buf) < 2 + n:
                # henüz tüm DNS sorgusu gelmedi
                self.buffers[event.stream_id] = buf
                return
            msg = bytes(buf[2:2+n])
            task = asyncio.ensure_future(self.handle_query(msg, event))
            task.add_done_callback(_log_query_task)
            self.buffers.pop(event.stream_id, None)  # buffer'ı temizle
    async def handle_query(self, msg, event):
        istek_ani = self.core.db_manager.utc_now()  # istek anı (çözümleme öncesi)
        loop = asyncio.get_event_loop()

        parsed = DNSRecord.parse(msg)
        qname = str(parsed.q.qname)
        if not qname.endswith("."):
            qname += "."
        qtype = QTYPE[parsed.q.qtype]
        
        reply = _clean_reply(parsed)

        try:
            # aioquic'in özel (private) alanı; sürüm güncellemesinde değişebilir.
            client_ip = self._quic._network_paths[0].addr[0]
        except (AttributeError, IndexError):
            client_ip = "unknown"

        src = ["—"]
        ds = ["off"]
        if not self.core.access_ok(client_ip):   # ACL / rate limit → reddet
            reply.header.rcode = RCODE.REFUSED
        else:
            rcode, record = await loop.run_in_executor(
                None, lambda: self.core.resolve(qname, qtype, 0, src, ds))
            if rcode == RCODE.NXDOMAIN:
                reply.header.rcode = RCODE.NXDOMAIN
            elif rcode == RCODE.SERVFAIL:
                reply.header.rcode = RCODE.SERVFAIL
            else:
                reply.rr = list(record)
            if ds[0] == "secure":
                reply.header.ad = 1
            blocked_by = self.core.is_blocked(qname)
            self.core.db_manager.add_to_cache(key=qname, value={"record_type": qtype, "client_ip": client_ip, "queried_at": istek_ani, "method": "doq", "blocked": bool(blocked_by), "blocked_by": blocked_by, "resolved_by": src[0], "status": status_for(rcode, bool(blocked_by)), "dnssec": ds[0]})
        reply.header.id = 0
        reply_bytes = reply.pack()
        
        self._quic.send_stream_data(event.stream_id, len(reply_bytes).to_bytes(2, "big") + reply_bytes, end_stream=True)
        self.transmit()

        

async def build_server(core, bind="127.0.0.1", port=853, certfile=None, keyfile=None):

    certfile = certfile or os.getenv("CERT_FILE", "/app/certificates/fullchain.pem")
    keyfile = keyfile or os.getenv("KEY_FILE", "/app/certificates/privkey.pem")
    has_certs = certfile and keyfile and os.path.exists(certfile) and os.path.exists(keyfile)
    
    if not has_certs:
        logger.error("DoQ sunucusu için sertifika bulunamadı {certfile=%s, keyfile=%s}, başlatılmıyor.", certfile, keyfile)
        print("DoQ sunucusu için sertifika bulunamadı, başlatılmıyor.")
        return None

    logger.info("DoQ sunucusu sertifikaları kontrol ediliyor: {certfile=%s, keyfile=%s}", certfile, keyfile)
    
    config = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    config.load_cert_chain(certfile, keyfile)   # DoT/DoH ile aynı sertifika
    
    logger.info("DoQ sunucusu sertifikaları başarıyla yüklendi.")

    aioquic_server = serve(
        host=bind,
        port=port,
        configuration=config,
        create_protocol=lambda *args, **kwargs: DoQProtocol(core, *args, **kwargs),
    )
    return await aioquic_server
