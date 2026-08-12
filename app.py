import os
import asyncio
import signal
from dotenv import load_dotenv
from project_control import settings, cache_loop, blocklists

settings.control_env_file()
load_dotenv(settings.PROJECT_DIRECTORY / ".env")

from logs.dns_logs import logger

import servers.normal_udp as udp_server
import servers.https_server as https_server
import servers.dot_server as dot_server
import servers.doq_server as doq_server
import servers.manager as server_manager
from project_control.check_ssl_certificate import SSLCertificateChecker

import db_ops

def build_udp_server(core):
    port = int(os.getenv("CONTAINER_UDP_PORT", "5300"))
    bind = os.getenv("BIND_ADDRESS", "127.0.0.1")
    from dnslib.server import DNSServer
    server = DNSServer(udp_server.DNSResolver(core), port=port, address=bind,
                       logger=udp_server.QuietDNSLogger())
    return server.start, server.stop


def build_https_server(core):
    port = int(os.getenv("CONTAINER_HTTPS_PORT", "44300"))
    bind = os.getenv("BIND_ADDRESS", "127.0.0.1")
    certfile = os.getenv("CERT_FILE", "/app/certificates/fullchain.pem")
    keyfile = os.getenv("KEY_FILE", "/app/certificates/privkey.pem")
    server = https_server.build_server(core, bind=bind, port=port, certfile=certfile, keyfile=keyfile)
    return server.serve_forever, server.shutdown


def build_dot_server(core):
    port = int(os.getenv("CONTAINER_DOT_PORT", "8853"))
    bind = os.getenv("BIND_ADDRESS", "127.0.0.1")
    certfile = os.getenv("CERT_FILE", "/app/certificates/fullchain.pem")
    keyfile = os.getenv("KEY_FILE", "/app/certificates/privkey.pem")
    server = dot_server.build_server(core, bind=bind, port=port, certfile=certfile, keyfile=keyfile)
    if server is None:
        return None
    return server.start, server.stop

def _log_task_error(task):
    """Fire-and-forget bir task sessizce hata ile biterse logla."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("Arka plan görevi hata ile sonlandı: %r", exc)


def _make_server_error_logger(name):
    """Executor thread'inde çalışan bir sunucu beklenmedik biçimde durursa logla."""
    def _callback(fut):
        if fut.cancelled():
            return
        exc = fut.exception()
        if exc is not None:
            logger.error("%s sunucusu hata ile durdu: %r", name, exc)
    return _callback


def _check_certificates():
    """
    TLS/HTTPS/QUIC motorlarından önce sertifikaları kontrol et.
    .env dosyasından CERT_FILE ve KEY_FILE yollarını oku ve geçerliliğini kontrol et.
    """
    cert_file = os.getenv("CERT_FILE", "/app/certificates/fullchain.pem")
    key_file = os.getenv("KEY_FILE", "/app/certificates/privkey.pem")
    
    logger.info("Sertifikalar kontrol ediliyor... {cert_file=%s, key_file=%s}", cert_file, key_file)
    
    from pathlib import Path
    
    # Dosya var mı kontrol et
    if not Path(cert_file).exists():
        logger.error("Sertifika dosyası bulunamadı: %s", cert_file)
        return False
    
    if not Path(key_file).exists():
        logger.error("Özel anahtar dosyası bulunamadı: %s", key_file)
        return False
    
    logger.debug("Sertifika dosyaları bulundu.")
    
    # Sertifikayı kontrol et
    checker = SSLCertificateChecker(warning_days=30)
    cert_info = checker.check_file(cert_file)
    
    if 'error' in cert_info:
        logger.error("Sertifika doğrulama başarısız: %s", cert_info['error'])
        return False
    
    status = cert_info.get('status', 'UNKNOWN')
    subject = cert_info.get('subject', 'Bilinmiyor')
    issuer = cert_info.get('issuer', 'Bilinmiyor')
    valid_until = cert_info.get('valid_until', 'Bilinmiyor')
    
    logger.info("Sertifika bilgileri:")
    logger.info("  Subject: %s", subject)
    logger.info("  Issuer: %s", issuer)
    logger.info("  Geçerli Olacağı Tarih: %s", valid_until)
    
    if status == "VALID":
        logger.info("✅ Sertifika geçerli ve kullanıma hazır.")
        return True
    elif "EXPIRING_SOON" in status:
        logger.warning("⚠️ Sertifika yakında sona erecek: %s", status)
        return True  # Hala kullanılabilir ama uyarı
    elif status == "EXPIRED":
        logger.error("❌ Sertifika süresi dolmuş!")
        return False
    else:
        logger.warning("⚠️ Sertifika durumu bilinmiyor: %s", status)
        return True  # Bilinmeyen durum, yine de devam et


def make_starters(core, loop):
    """
    Her metot için bir "starter" üretir: çağrıldığında sunucuyu başlatıp bir
    stop() fonksiyonu döndüren (başlatılamazsa None) async fonksiyon.
    ServerManager bunları DB'deki resolver_config'e göre çağırır.

    Thread-tabanlı sunucular (udp/doh/dot) blocking start ile executor'da koşar;
    DoQ (aioquic) event loop'ta koşar. Port/bind/cert değerleri build_* içinde
    env'den okunur.
    """

    # Panelden ayarlanan cert yolları + iç dinleme portlarını env'e uygula →
    # build_* değerleri env'den okur. Bir sunucu (re)start edildiğinde çağrılır;
    # değişikliğin yansıması için metodun kapat-aç edilmesi (UDP'de resolver
    # restart) gerekir — ServerManager port değişiminde otomatik restart etmez.
    _SETTING_ENV = {
        'cert_file': 'CERT_FILE',
        'key_file': 'KEY_FILE',
        'udp_port': 'CONTAINER_UDP_PORT',
        'https_port': 'CONTAINER_HTTPS_PORT',
        'dot_port': 'CONTAINER_DOT_PORT',
        'doq_port': 'CONTAINER_DOQ_PORT',
    }

    async def _apply_settings_env():
        for key, env in _SETTING_ENV.items():
            val = await core.db_manager.get_setting(key)
            if val:
                os.environ[env] = str(val)

    async def start_udp():
        await _apply_settings_env()
        start_fn, stop_fn = build_udp_server(core)
        fut = loop.run_in_executor(None, start_fn)
        fut.add_done_callback(_make_server_error_logger("udp"))
        return stop_fn

    async def start_doh():
        await _apply_settings_env()
        built = build_https_server(core)
        if built is None:
            return None
        start_fn, stop_fn = built
        fut = loop.run_in_executor(None, start_fn)
        fut.add_done_callback(_make_server_error_logger("doh"))
        return stop_fn

    async def start_dot():
        await _apply_settings_env()
        built = build_dot_server(core)  # sertifika yoksa None
        if built is None:
            return None
        start_fn, stop_fn = built
        fut = loop.run_in_executor(None, start_fn)
        fut.add_done_callback(_make_server_error_logger("dot"))
        return stop_fn

    async def start_doq():
        await _apply_settings_env()
        server = await doq_server.build_server(  # sertifika yoksa None
            core,
            bind=os.getenv("BIND_ADDRESS", "127.0.0.1"),
            port=int(os.getenv("CONTAINER_DOQ_PORT", "8530")),
        )
        if server is None:
            return None
        return server.close

    return {"udp": start_udp, "doh": start_doh, "dot": start_dot, "doq": start_doq}


def main():
    db_manager = db_ops.DBManager()
    core = udp_server.DNSCore(db_manager=db_manager)

    # Sertifika bilgisini (yapılandırılmışsa) logla. DoT/DoQ başlatılırken cert'i
    # zaten kendisi kontrol eder; burası yalnızca bilgilendirme amaçlı.
    if os.getenv("CERT_FILE", "no") not in ("no", "") and os.getenv("KEY_FILE", "no") not in ("no", ""):
        _check_certificates()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(db_manager.open_project())

    # Engelleme listelerini (blocklist/allowlist) açılışta bir kez yükle;
    # aşağıdaki periyodik görev sonra tazeler.
    _block, _allow = loop.run_until_complete(db_manager.get_filter_lists())
    core.update_filter_lists(_block, _allow)

    # Cache temizleme + periyodik DB flush (tüm sunucular aynı DNSCore'u paylaşır).
    cache_cleaner = cache_loop.CLEAR_CACHE(cache=core._cache, _lock=core._lock)
    cache_task = loop.create_task(cache_cleaner.clear_cache_loop())
    cache_task.add_done_callback(_log_task_error)
    length_task = loop.create_task(cache_cleaner.control_cache_length())
    length_task.add_done_callback(_log_task_error)
    # Tampon 15 sn'de bir DB'ye boşaltılır (batch; tampon boşsa write anında döner).
    flush_task = loop.create_task(db_manager.write_on_background(interval=15))
    flush_task.add_done_callback(_log_task_error)

    # Flush bekleyen tampon 1 sn'de bir paylaşılan dosyaya yazılır → panel sorgu
    # geçmişini cache(dosya)+db birleştirir; yeni sorgu flush'u beklemeden görünür.
    async def _pending_snapshot(interval=1):
        while True:
            await asyncio.sleep(interval)
            try:
                await loop.run_in_executor(None, db_manager.write_pending_snapshot)
            except Exception as e:
                logger.debug("pending snapshot hatasi: %r", e)
    snapshot_task = loop.create_task(_pending_snapshot())
    snapshot_task.add_done_callback(_log_task_error)

    # DNS sunucuları artık DB'deki resolver_config'e göre ÇALIŞIRKEN yönetilir:
    # web panelinden bir metodu açıp kapatmak, prosesi yeniden başlatmadan
    # ~birkaç saniyede etki eder. Güvenli varsayılan: sadece UDP açık.
    manager = server_manager.ServerManager(make_starters(core, loop))
    reconcile_task = loop.create_task(
        manager.reconcile_loop(db_manager.get_resolver_config, interval=5)
    )
    reconcile_task.add_done_callback(_log_task_error)

    # Engelleme listelerini DB'den periyodik yenile: elle eklenenler (blocklist/allowlist)
    # + hazır liste abonelikleri (blocklist_sources) indirilip RAM'de birleştirilir.
    # Büyük listeler her turda yeniden İNDİRİLMEZ; kaynak bazında cache'lenir ve yalnız
    # yeni/URL-değişmiş/bayat (force) olduğunda tekrar indirilir. İndirme executor'da
    # (bloklamasın). Kaldırılan/kapatılan kaynağın cache'i düşer.
    _source_cache: dict[int, tuple[str, frozenset]] = {}

    async def _refresh_filters(interval=30):
        while True:
            await asyncio.sleep(interval)
            try:
                manual_block, allow = await db_manager.get_filter_lists()
                sources = await db_manager.get_blocklist_sources()
                active_ids = set()
                list_sets: dict[str, frozenset] = {}
                for s in sources:
                    sid, name, url, force = s["id"], s["name"], s["url"], s["force"]
                    active_ids.add(sid)
                    cached = _source_cache.get(sid)
                    if cached is None or cached[0] != url or force:
                        try:
                            domains = await loop.run_in_executor(
                                None, blocklists.download_and_parse, url
                            )
                            _source_cache[sid] = (url, frozenset(domains))
                            await db_manager.set_source_stats(sid, len(domains))
                            logger.info("Engelleme listesi indirildi: %s (%d domain)", url, len(domains))
                        except Exception as e:
                            logger.error("Engelleme listesi indirilemedi %s: %r", url, e)
                            await db_manager.set_source_stats(sid, 0)
                            _source_cache.setdefault(sid, (url, frozenset()))
                    list_sets[name] = _source_cache[sid][1]
                # Kaldırılan/kapatılan kaynakların cache'ini temizle.
                for sid in [k for k in _source_cache if k not in active_ids]:
                    del _source_cache[sid]
                core.update_filter_lists(manual_block, allow, list_sets)
            except Exception as e:
                logger.error("Filtre listesi yenileme hatası: %r", e)
    filter_task = loop.create_task(_refresh_filters())
    filter_task.add_done_callback(_log_task_error)

    # Genel ayarları (geçmiş aç/kapa + önbellek) periyodik uygula.
    _seen_clear = {"at": None}
    async def _refresh_settings(interval=10):
        while True:
            try:
                lg = await db_manager.get_setting('log_queries', '1')
                db_manager.logging_enabled = (str(lg) != '0')
                ce = await db_manager.get_setting('cache_enabled', '1')
                core.cache_enabled = (str(ce) != '0')
                try:
                    core.cache_min_ttl = max(0, int(await db_manager.get_setting('cache_min_ttl', '0')))
                except (TypeError, ValueError):
                    core.cache_min_ttl = 0
                try:
                    core.cache_max_ttl = max(1, int(await db_manager.get_setting('cache_max_ttl', str(udp_server.MAX_TTL))))
                except (TypeError, ValueError):
                    core.cache_max_ttl = udp_server.MAX_TTL
                clear_at = await db_manager.get_setting('cache_clear_at', '0')
                if _seen_clear["at"] is None:
                    _seen_clear["at"] = clear_at            # açılışta boşaltma
                elif clear_at and clear_at != _seen_clear["at"]:
                    n = core.clear_cache()
                    _seen_clear["at"] = clear_at
                    logger.info("Önbellek panelden temizlendi (%d kayıt).", n)
            except Exception as e:
                logger.error("Ayar yenileme hatası: %r", e)
            await asyncio.sleep(interval)
    settings_task = loop.create_task(_refresh_settings())
    settings_task.add_done_callback(_log_task_error)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown, manager, loop, cache_cleaner)

    logger.info("Resolver başlatıldı; DNS metotları web panelindeki ayara göre yönetiliyor.")
    print("Resolver başlatıldı; DNS metotları web panelindeki ayara göre yönetiliyor.")
    loop.run_forever()
    loop.run_until_complete(db_manager.close_project())


def shutdown(manager, loop, cleaner):
    print("Sunucular kapatılıyor...")
    cleaner.all_clear_cache()
    manager.stop_all()
    loop.stop()


if __name__ == "__main__":
    main()
