import os
import json
import asyncio
import signal
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from project_control import settings, cache_loop, blocklists

settings.control_env_file()
load_dotenv(settings.PROJECT_DIRECTORY / ".env")

from logs.dns_logs import logger

import servers.normal_udp as udp_server
import servers.dot_server as dot_server
import servers.doq_server as doq_server
import servers.manager as server_manager
from project_control.check_ssl_certificate import SSLCertificateChecker

import db_ops
import config_store
import logcrypto

def _ups_list(text):
    """Upstream metnini listeye çevir: virgül/satır ile ayır, boşları at, '#' ile
    başlayan YORUM satırlarını yok say."""
    out = []
    for ln in (text or '').replace(',', '\n').splitlines():
        ln = ln.strip()
        if ln and not ln.startswith('#'):
            out.append(ln)
    return out


def build_udp_server(core):
    cfg = config_store.get_config()
    port = cfg["methods"]["udp"]["container_port"]
    bind = cfg["bind"]
    from dnslib.server import DNSServer
    server = DNSServer(udp_server.DNSResolver(core), port=port, address=bind,
                       logger=udp_server.QuietDNSLogger())
    return server.start, server.stop


def build_dot_server(core):
    cfg = config_store.get_config()
    port = cfg["methods"]["dot"]["container_port"]
    server = dot_server.build_server(core, bind=cfg["bind"], port=port,
                                     certfile=cfg["cert_file"], keyfile=cfg["key_file"])
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
    cfg = config_store.get_config()
    cert_file = cfg["cert_file"]
    key_file = cfg["key_file"]

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


def _desired_servers():
    """ServerManager için istenen durum: {method: {enabled, container_port}} —
    TEK kaynak config_store (config/servers.json). Port değişimi de burada görünür
    → reconcile ilgili metodu yeniden başlatır."""
    cfg = config_store.get_config()
    return {m: {"enabled": d["enabled"], "container_port": d["container_port"]}
            for m, d in cfg["methods"].items()}


def make_starters(core, loop):
    """
    Her metot için bir "starter" üretir: çağrıldığında sunucuyu başlatıp bir
    stop() fonksiyonu döndüren (başlatılamazsa None) async fonksiyon.
    ServerManager bunları config_store'daki (config/servers.json) istenen duruma
    göre çağırır.

    Thread-tabanlı sunucular (udp/doh/dot) blocking start ile executor'da koşar;
    DoQ (aioquic) event loop'ta koşar. Port/bind/cert değerleri build_* içinde
    config_store'dan okunur (env/DB değil).
    """

    async def start_udp():
        start_fn, stop_fn = build_udp_server(core)
        fut = loop.run_in_executor(None, start_fn)
        fut.add_done_callback(_make_server_error_logger("udp"))
        return stop_fn

    async def start_doh():
        # DoH: ASGI app + Hypercorn (HTTP/2 + HTTP/1.1). Event loop'ta TASK olarak
        # koşar (thread değil). Hypercorn lazy import → kurulu değilse app.py yine
        # import edilebilir (testler hypercorn'suz çalışır).
        import hypercorn.asyncio
        from hypercorn.config import Config as HConfig
        from servers import doh_app

        cfg = config_store.get_config()
        doh = cfg["methods"]["doh"]
        hconf = HConfig()
        hconf.bind = [f"{cfg['bind']}:{doh['container_port']}"]
        hconf.accesslog = None       # per-request log KAPALI → domain/IP sızmaz
        certfile, keyfile = cfg["cert_file"], cfg["key_file"]
        if os.path.exists(certfile) and os.path.exists(keyfile):
            hconf.certfile = certfile
            hconf.keyfile = keyfile
            hconf.alpn_protocols = ["h2", "http/1.1"]   # HTTP/2 (TLS+ALPN) + h1 fallback
        else:
            hconf.alpn_protocols = ["http/1.1"]          # cert yok → düz HTTP/1.1 (proxy arkası)
            logger.warning("DoH sertifikasız başlatılıyor: düz HTTP/1.1 (H2 için TLS+ALPN şart).")

        shutdown = asyncio.Event()
        task = loop.create_task(
            hypercorn.asyncio.serve(doh_app.make_app(core), hconf,
                                    shutdown_trigger=shutdown.wait)
        )
        task.add_done_callback(_make_server_error_logger("doh"))
        return shutdown.set          # ServerManager stop() → graceful shutdown

    async def start_dot():
        built = build_dot_server(core)  # sertifika yoksa None
        if built is None:
            return None
        start_fn, stop_fn = built
        fut = loop.run_in_executor(None, start_fn)
        fut.add_done_callback(_make_server_error_logger("dot"))
        return stop_fn

    async def start_doq():
        cfg = config_store.get_config()
        server = await doq_server.build_server(  # sertifika yoksa None
            core,
            bind=cfg["bind"],
            port=cfg["methods"]["doq"]["container_port"],
            certfile=cfg["cert_file"],
            keyfile=cfg["key_file"],
        )
        if server is None:
            return None
        return server.close

    return {"udp": start_udp, "doh": start_doh, "dot": start_dot, "doq": start_doq}


def main():
    db_manager = db_ops.DBManager()
    core = udp_server.DNSCore(db_manager=db_manager)

    # Sertifika bilgisini (varsa) logla. DoT/DoQ başlatılırken cert'i zaten kendisi
    # kontrol eder; burası yalnızca bilgilendirme amaçlı. Yollar config_store'dan.
    _cfg = config_store.get_config()
    if os.path.exists(_cfg["cert_file"]) and os.path.exists(_cfg["key_file"]):
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

    # DNS sunucuları config_store'daki (config/servers.json) istenen duruma göre
    # ÇALIŞIRKEN yönetilir: panelden bir metodu açıp kapatmak (ya da iç portunu
    # değiştirmek), prosesi yeniden başlatmadan ~birkaç saniyede etki eder.
    # Güvenli varsayılan: sadece UDP açık.
    manager = server_manager.ServerManager(make_starters(core, loop))
    reconcile_task = loop.create_task(
        manager.reconcile_loop(_desired_servers, interval=5)
    )
    reconcile_task.add_done_callback(_log_task_error)

    # Engelleme listelerini DB'den periyodik yenile: elle eklenenler (blocklist/allowlist)
    # + hazır liste abonelikleri (blocklist_sources) indirilip RAM'de birleştirilir.
    # Büyük listeler her turda yeniden İNDİRİLMEZ; kaynak bazında cache'lenir ve yalnız
    # yeni/URL-değişmiş/bayat (force) olduğunda tekrar indirilir. İndirme executor'da
    # (bloklamasın). Kaldırılan/kapatılan kaynağın cache'i düşer.
    _source_cache: dict[int, tuple[str, frozenset]] = {}

    async def _refresh_filters(interval=15):
        while True:
            await asyncio.sleep(interval)
            try:
                manual_block, allow = await db_manager.get_filter_lists()
                sources = await db_manager.get_blocklist_sources()
                active_ids = {s["id"] for s in sources}
                list_sets: dict[str, frozenset] = {}

                # İndirme eşzamanlılığı SINIRI: aynı anda EN FAZLA 2 liste iner
                # (bant genişliği/CPU'yu boğmasın). Bu bir İNDİRME sınırıdır —
                # kaç liste EKLENECEĞİNE sınır yoktur; çok liste varsa 2'şerli iner.
                _dl_sem = asyncio.Semaphore(2)

                async def _download_source(s):
                    sid, url = s["id"], s["url"]
                    async with _dl_sem:
                        try:
                            domains = await loop.run_in_executor(
                                None, blocklists.download_and_parse, url)
                            _source_cache[sid] = (url, frozenset(domains))
                            await db_manager.set_source_stats(sid, len(domains))
                            logger.info("Engelleme listesi indirildi: %s (%d domain)", url, len(domains))
                        except Exception as e:
                            logger.error("Engelleme listesi indirilemedi %s: %r", url, e)
                            await db_manager.set_source_stats(sid, 0)
                            _source_cache.setdefault(sid, (url, frozenset()))
                            await db_manager.add_notification(
                                "warn", "health", "Liste indirilemedi",
                                f"{url} — {type(e).__name__}",
                                dedup_key=f"dlfail:{sid}", dedup_window=3600)

                # Yalnız yeni / URL-değişmiş / bayat (force) kaynakları indir.
                pending = [s for s in sources
                           if (_source_cache.get(s["id"]) is None
                               or _source_cache[s["id"]][0] != s["url"] or s["force"])]
                if pending:
                    await asyncio.gather(*(_download_source(s) for s in pending))

                for s in sources:   # list_sets'i (indirilmiş + önceden cache'li) kur
                    list_sets[s["name"]] = _source_cache.get(s["id"], (s["url"], frozenset()))[1]
                # Kaldırılan/kapatılan kaynakların cache'ini temizle.
                for sid in [k for k in _source_cache if k not in active_ids]:
                    del _source_cache[sid]
                # Ön tanımlı servis engelleri (TikTok/Instagram…) — DB'den, list_sets'e kat.
                # Zamanlanmış engelleme: pencere dışındaki servisleri list_sets'e KATMA.
                schedules = await db_manager.get_schedules()
                _wd = _mn = 0
                if schedules:
                    _off = int(await db_manager.get_setting('schedule_tz_offset', '0') or 0)
                    _now = datetime.now(timezone.utc) + timedelta(minutes=_off)
                    _wd, _mn = _now.weekday(), _now.hour * 60 + _now.minute
                for svc, doms in (await db_manager.get_service_lists()).items():
                    sch = schedules.get(svc)
                    if sch is None or db_ops.db_core.schedule_active(sch[0], sch[1], sch[2], _wd, _mn):
                        list_sets[svc] = doms   # zamanlama yok → hep engelli; var → yalnız pencere içinde
                # DNS rewrites (elle tanımlı kayıt) — atomik ata (is_blocked'tan önce bakılır).
                core.rewrites = await db_manager.get_rewrites()
                core.update_filter_lists(manual_block, allow, list_sets)
            except Exception as e:
                logger.error("Filtre listesi yenileme hatası: %r", e)
    # Resolver-türevli panel bildirimleri: yeni istemci, şüpheli(bogus) alan, sertifika
    # süresi. Hot-path'e DOKUNMADAN DB'den türetir; dedup notifications tablosunda.
    async def _scan_notifications(interval=120):
        checker = SSLCertificateChecker(warning_days=30)
        while True:
            await asyncio.sleep(interval)
            try:
                span = interval // 60 + 2
                for cip in await db_manager.scan_new_client_ips(minutes=span):
                    ip = (logcrypto.dec(cip) or "?").strip()
                    if ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                        continue                       # sağlık probe'u vb. → atla
                    await db_manager.add_notification(
                        "info", "client", "Yeni istemci", f"{ip} ilk kez sorgu yaptı.",
                        dedup_key=f"newclient:{cip}", dedup_window=315360000)  # ~10y = bir kez
                for dcip in await db_manager.scan_bogus_domains(minutes=span + 5):
                    dom = (logcrypto.dec(dcip) or "?").rstrip(".")
                    await db_manager.add_notification(
                        "warn", "domain", "Şüpheli alan (DNSSEC bozuk)",
                        f"{dom} — imzalı ama doğrulanamadı (bogus).",
                        dedup_key=f"bogus:{dcip}", dedup_window=86400)
                cf = config_store.get_config().get("cert_file")
                if cf and os.path.exists(cf):
                    info = await loop.run_in_executor(None, checker.check_file, cf)
                    st = info.get("status", "") if isinstance(info, dict) else ""
                    if "EXPIRING_SOON" in st:
                        await db_manager.add_notification(
                            "warn", "health", "Sertifika yakında sona erecek",
                            f"Geçerlilik: {info.get('valid_until', '?')}",
                            dedup_key="certexp", dedup_window=43200)
                    elif st == "EXPIRED":
                        await db_manager.add_notification(
                            "crit", "health", "Sertifika süresi DOLDU",
                            "TLS (DoT/DoQ/DoH) başlatılamayabilir — sertifikayı yenile.",
                            dedup_key="certexpired", dedup_window=43200)
            except Exception as e:  # noqa: BLE001 — bildirim ikincil, döngü ölmesin
                logger.debug("bildirim taramasi hatasi: %r", e)
    scan_task = loop.create_task(_scan_notifications())
    scan_task.add_done_callback(_log_task_error)

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
                core.use_recursion = (str(await db_manager.get_setting('use_recursion', '1')) != '0')
                core.dnssec = (str(await db_manager.get_setting('dnssec', '0')) != '0')   # default KAPALI
                core.upstreams = _ups_list(await db_manager.get_setting('upstreams', ''))
                # İkincil (yedek) upstream'ler: 1.'ler HİÇ yanıt vermezse denenir.
                core.upstreams_secondary = _ups_list(await db_manager.get_setting('upstreams_secondary', ''))
                core.upstream_strategy = await db_manager.get_setting('upstream_strategy', 'sequential')
                # Koşullu forwarding: satır başına "son-ek upstream" → [(son-ek, upstream)].
                _cf = await db_manager.get_setting('conditional_forwards', '') or ''
                conds = []
                for _ln in _cf.splitlines():
                    _p = _ln.split()
                    if len(_p) >= 2:
                        _suf = _p[0].strip().lower().rstrip('.')
                        if _suf.startswith('*.'):
                            _suf = _suf[2:]
                        if _suf:
                            conds.append((_suf, _p[1].strip()))
                core.conditionals = conds
                # Bootstrap DNS: isimli şifreli upstream host çözümü için düz IP (boş=sistem).
                core.bootstrap_dns = (await db_manager.get_setting('bootstrap_dns', '') or '').strip()
                _ss = await db_manager.get_setting('safesearch_engines', '') or ''
                core.safesearch_engines = set(x.strip() for x in _ss.split(',') if x.strip())
                # Erişim kontrolü + rate limit
                try:
                    core.rate_limit = max(0, int(await db_manager.get_setting('rate_limit', '0')))
                except (TypeError, ValueError):
                    core.rate_limit = 0
                _ca = await db_manager.get_setting('client_allow', '') or ''
                core.client_allow = frozenset(x.strip() for x in _ca.replace(',', '\n').splitlines() if x.strip())
                _cd = await db_manager.get_setting('client_deny', '') or ''
                core.client_deny = frozenset(x.strip() for x in _cd.replace(',', '\n').splitlines() if x.strip())
                # Kaynak (çekirdek/önbellek/upstream) işlem süresi ortalamalarını panele aç.
                try:
                    _stats = {k: {'avg_ms': round(t / c, 1), 'count': c}
                              for k, (c, t) in list(core.source_stats.items()) if c}
                    _sp = os.getenv('SOURCE_STATS_FILE', '/app/data/source_stats.json')
                    with open(_sp + '.tmp', 'w') as _f:
                        json.dump(_stats, _f)
                    os.replace(_sp + '.tmp', _sp)
                except Exception:
                    pass
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

    # Log retention: N günden eski sorgu geçmişini periyodik sil (0 = kapalı).
    async def _retention_loop(interval=3600):
        while True:
            try:
                days = int(await db_manager.get_setting('log_retention_days', '0') or 0)
                if days > 0:
                    n = await db_manager.delete_old_logs(days)
                    if n:
                        logger.info("Log retention: %d eski kayıt silindi (>%d gün).", n, days)
            except Exception as e:
                logger.error("Log retention hatası: %r", e)
            await asyncio.sleep(interval)
    retention_task = loop.create_task(_retention_loop())
    retention_task.add_done_callback(_log_task_error)

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
