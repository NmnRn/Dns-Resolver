import os
import ssl

from dotenv import load_dotenv
from dnslib.server import DNSServer
import servers.normal_udp as udp_server

load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))  # .env dosyasını yükle

from logs.dns_logs import logger

CERT_FILE = os.getenv("CERT_FILE", "/app/certificates/fullchain.pem")
KEY_FILE = os.getenv("KEY_FILE", "/app/certificates/privkey.pem")


def build_server(core, bind="0.0.0.0", port=853, certfile=None, keyfile=None):
    """Sunucuyu kurar ama başlatmaz (.serve_forever() çağrılmaz) - app.py'nin
    diğer sunucularla aynı şekilde thread'e verip yönetebilmesi için.

    DoT tanımı gereği TLS zorunlu; sertifika yoksa (DoH'un düz-HTTP fallback'i
    gibi bir alternatifi yok) sunucu başlatılmaz, None döner ve çağıran atlar."""
    certfile = certfile or CERT_FILE
    keyfile = keyfile or KEY_FILE

    has_certs = certfile and keyfile and os.path.exists(certfile) and os.path.exists(keyfile)
    if not has_certs:
        logger.warning("DoT sunucusu için sertifika bulunamadı (%s / %s) - başlatılmıyor.", certfile, keyfile)
        print("DoT sunucusu için sertifika bulunamadı, başlatılmıyor.")
        return None

    server = DNSServer(udp_server.DNSResolver(core, method="DnsOverTLS"), port=port, address=bind, tcp=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    server.server.socket = ctx.wrap_socket(server.server.socket, server_side=True)
    print(f"DoT sunucusu başlatıldı: {bind}:{port}")
    logger.info("DoT sunucusu başlatıldı: %s:%d", bind, port)
    return server
