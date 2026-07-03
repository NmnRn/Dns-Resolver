import os
import asyncio
import signal

from dotenv import load_dotenv

import settings
import cache_loop

settings.control_env_file()
load_dotenv(settings.PROJECT_DIRECTORY / ".env")

from logs.dns_logs import logger

import servers.normal_udp as udp_server
import servers.https_server as https_server


def build_udp_server(core):
    port = int(os.getenv("CONTAINER_UDP_PORT", "5300"))
    bind = os.getenv("BIND_ADDRESS", "0.0.0.0")
    from dnslib.server import DNSServer
    server = DNSServer(udp_server.DNSResolver(core), port=port, address=bind)
    return server.start, server.stop


def build_https_server(core):
    port = int(os.getenv("CONTAINER_HTTPS_PORT", "44300"))
    bind = os.getenv("BIND_ADDRESS", "0.0.0.0")
    certfile = os.getenv("CERT_FILE", "/app/certificates/fullchain.pem")
    keyfile = os.getenv("KEY_FILE", "/app/certificates/privkey.pem")
    server = https_server.build_server(core, bind=bind, port=port, certfile=certfile, keyfile=keyfile)
    return server.serve_forever, server.shutdown


# server adı -> (kurucu fonksiyon, aktif mi)
SERVER_REGISTRY = {
    "normal-udp": (build_udp_server, os.getenv("ENABLE_UDP_SERVER", "true").lower() == "true"),
    "https_server": (build_https_server, os.getenv("ENABLE_HTTPS_SERVER", "true").lower() == "true"),
}


def main():
    core = udp_server.DNSCore()

    active = []
    for name, (builder, is_enabled) in SERVER_REGISTRY.items():
        if not is_enabled:
            logger.info("%s sunucusu devre dışı bırakıldı.", name)
            print(f"{name} sunucusu devre dışı bırakıldı.")
            continue
        logger.info("%s sunucusu başlatılıyor...", name)
        print(f"{name} sunucusu başlatılıyor...")
        start_fn, stop_fn = builder(core)
        active.append((name, start_fn, stop_fn))

    if not active:
        logger.error("Hiçbir sunucu başlatılmadı. Lütfen ayarları kontrol edin.")
        print("Hiçbir sunucu başlatılmadı. Lütfen ayarları kontrol edin.")
        return

    # Cache temizleme döngüsünü başlat (tüm sunucular aynı DNSCore'u paylaşıyor)
    cache_cleaner = cache_loop.CLEAR_CACHE(cache=core._cache, _lock=core._lock)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(cache_cleaner.clear_cache_loop())

    for name, start_fn, _ in active:
        loop.run_in_executor(None, start_fn)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown, active, loop, cache_cleaner)

    loop.run_forever()


def shutdown(active, loop, cleaner):
    print("Sunucular kapatılıyor...")
    cleaner.all_clear_cache()
    for _, _, stop_fn in active:
        stop_fn()
    loop.stop()


if __name__ == "__main__":
    main()
