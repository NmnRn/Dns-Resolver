"""
DNS sorgu veritabanına (MariaDB) asenkron erişim katmanı.

Django ORM KULLANILMAZ; resolver kod tabanıyla tutarlı olacak şekilde doğrudan
aiomysql ile okunur. Bağlantı ayarları settings.DNS_DB'den gelir (db_ops/db_core.py
ile aynı DB_* ortam değişkenleri).

Havuz (pool), çalışan event loop'a göre saklanır: Django async view'ları tek kalıcı
bir loop üzerinde çalışır, ama runserver/ASGI/test arasında loop değişebildiğinden
havuzu loop'a bağlamak çapraz-loop hatalarını önler. Salt-okunur olduğumuz için
autocommit=True: her SELECT en güncel commit'lenmiş veriyi görür (REPEATABLE READ
snapshot'ına takılmayız).
"""
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

import aiomysql
from django.conf import settings

import logcrypto  # client_ip at-rest şifreliyse gösterim için çöz (DNS_LOG_KEY)

# Resolver'ın flush bekleyen tamponu (aynı container, paylaşılan dosya). db_ops/__init__.py
# ile AYNI yol. Sorgu geçmişi = bu (cache) + DB olarak birleştirilir.
_PENDING_FILE = os.getenv('PENDING_FILE', '/app/data/pending.json')
_SOURCE_STATS_FILE = os.getenv('SOURCE_STATS_FILE', '/app/data/source_stats.json')

_pools: dict[asyncio.AbstractEventLoop, aiomysql.Pool] = {}
_locks: dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}


def _conn_kwargs() -> dict:
    cfg = settings.DNS_DB
    kw = dict(user=cfg['user'], password=cfg['password'], db=cfg['db'], autocommit=True)
    if cfg.get('unix_socket'):
        # Yerel geliştirme: TCP yerine unix socket.
        kw['unix_socket'] = cfg['unix_socket']
    else:
        kw['host'] = cfg['host']
        kw['port'] = cfg['port']
    return kw


async def get_pool() -> aiomysql.Pool:
    """Çalışan event loop için havuzu döndürür; yoksa (tek seferlik) oluşturur."""
    loop = asyncio.get_running_loop()
    pool = _pools.get(loop)
    if pool is not None and not pool.closed:
        return pool

    lock = _locks.setdefault(loop, asyncio.Lock())
    async with lock:
        pool = _pools.get(loop)
        if pool is None or pool.closed:
            # connect_timeout: DB ulaşılamazsa asılı kalmayıp hızlıca hata versin
            # (view bunu yakalayıp "erişilemedi" sayfası gösterir).
            pool = await aiomysql.create_pool(minsize=1, maxsize=5, connect_timeout=5, **_conn_kwargs())
            _pools[loop] = pool
    return pool


async def _fetch_all(sql: str, params: tuple = ()) -> list[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql, params)
            return list(await cur.fetchall())   # fetchall boşta tuple döndürebilir → hep list


async def _fetch_one(sql: str, params: tuple = ()) -> dict | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql, params)
            return await cur.fetchone()


async def get_stats() -> dict:
    """Üst bölümdeki özet kartları için toplu istatistikler."""
    row = await _fetch_one(
        """
        SELECT
            COUNT(*)                                   AS total,
            COUNT(DISTINCT domain)                     AS distinct_domains,
            COUNT(DISTINCT client_ip)                  AS distinct_clients,
            SUM(queried_at >= UTC_TIMESTAMP() - INTERVAL 24 HOUR) AS last_24h,
            SUM(blocked)                               AS blocked
        FROM dns_cache
        """
    )
    # SUM(...) NULL dönebilir (hiç satır yoksa); 0'a normalize et.
    return {
        'total': row['total'] or 0,
        'distinct_domains': row['distinct_domains'] or 0,
        'distinct_clients': row['distinct_clients'] or 0,
        'last_24h': int(row['last_24h'] or 0),
        'blocked': int(row['blocked'] or 0),
    }


async def get_block_breakdown(limit: int = 12) -> list[dict]:
    """Engellenen sorguların hangi listeden (blocked_by) geldiği dağılımı."""
    return await _fetch_all(
        """
        SELECT COALESCE(blocked_by, '?') AS name, COUNT(*) AS cnt
        FROM dns_cache
        WHERE blocked = TRUE
        GROUP BY blocked_by
        ORDER BY cnt DESC
        LIMIT %s
        """,
        (limit,),
    )


async def get_top_blocked_domains(limit: int = 10) -> list[dict]:
    """En çok engellenen alan adları (Analiz'de kırmızı liste)."""
    rows = await _fetch_all(
        """
        SELECT domain, COUNT(*) AS cnt
        FROM dns_cache
        WHERE blocked = TRUE
        GROUP BY domain
        ORDER BY cnt DESC
        LIMIT %s
        """,
        (limit,),
    )
    for r in rows:                       # domain şifreliyse çöz (GROUP BY şifreli değer üzerinde çalıştı)
        r['domain'] = (logcrypto.dec(r.get('domain')) or '').rstrip('.')
    return rows


async def get_hourly_series(hours: int = 24) -> list[int]:
    """Son `hours` saatin saatlik sorgu sayıları (eskiden yeniye; eksik saatler 0)."""
    rows = await _fetch_all(
        """
        SELECT DATE_FORMAT(queried_at, '%%Y-%%m-%%d %%H') AS bucket, COUNT(*) AS cnt
        FROM dns_cache
        WHERE queried_at >= UTC_TIMESTAMP() - INTERVAL %s HOUR
        GROUP BY bucket
        """,
        (hours,),
    )
    counts = {r['bucket']: int(r['cnt']) for r in rows}
    now = datetime.now(timezone.utc)
    return [counts.get((now - timedelta(hours=i)).strftime('%Y-%m-%d %H'), 0)
            for i in range(hours - 1, -1, -1)]


async def get_hourly_detail(hours: int = 24) -> list[dict]:
    """Saatlik kırılım: toplam + engellenen + en aktif istemci (grafik hover ipucu).
    'utc' saat başı UTC damgasıdır; panel JS'i yerel saate çevirir."""
    tot = await _fetch_all(
        """
        SELECT DATE_FORMAT(queried_at, '%%Y-%%m-%%d %%H') AS bucket,
               COUNT(*) AS total, COALESCE(SUM(blocked), 0) AS blocked
        FROM dns_cache
        WHERE queried_at >= UTC_TIMESTAMP() - INTERVAL %s HOUR
        GROUP BY bucket
        """,
        (hours,),
    )
    agg = {r['bucket']: (int(r['total']), int(r['blocked'])) for r in tot}
    cli = await _fetch_all(
        """
        SELECT DATE_FORMAT(queried_at, '%%Y-%%m-%%d %%H') AS bucket, client_ip, COUNT(*) AS c
        FROM dns_cache
        WHERE queried_at >= UTC_TIMESTAMP() - INTERVAL %s HOUR
        GROUP BY bucket, client_ip
        """,
        (hours,),
    )
    top = {}
    for r in cli:
        b, c = r['bucket'], int(r['c'])
        if b not in top or c > top[b][1]:
            top[b] = (r['client_ip'], c)
    now = datetime.now(timezone.utc)
    out = []
    for i in range(hours - 1, -1, -1):
        dt = now - timedelta(hours=i)
        key = dt.strftime('%Y-%m-%d %H')
        total, blocked = agg.get(key, (0, 0))
        tc = top.get(key)
        out.append({
            'utc': dt.strftime('%Y-%m-%d %H:00:00'),
            'total': total, 'blocked': blocked,
            'client': logcrypto.dec(tc[0]) if tc else '', 'client_cnt': tc[1] if tc else 0,
        })
    return out


async def get_top_domains(limit: int = 10) -> list[dict]:
    rows = await _fetch_all(
        """
        SELECT domain, COUNT(*) AS cnt
        FROM dns_cache
        GROUP BY domain
        ORDER BY cnt DESC
        LIMIT %s
        """,
        (limit,),
    )
    for r in rows:                       # domain şifreliyse çöz + sondaki DNS noktasını at
        r['domain'] = (logcrypto.dec(r.get('domain')) or '').rstrip('.')
    return rows


async def get_method_breakdown() -> list[dict]:
    return await _fetch_all(
        """
        SELECT COALESCE(method, '?') AS method, COUNT(*) AS cnt
        FROM dns_cache
        GROUP BY COALESCE(method, '?')
        ORDER BY cnt DESC
        """
    )


async def get_record_type_breakdown(limit: int = 8) -> list[dict]:
    return await _fetch_all(
        """
        SELECT COALESCE(record_type, '?') AS record_type, COUNT(*) AS cnt
        FROM dns_cache
        GROUP BY COALESCE(record_type, '?')
        ORDER BY cnt DESC
        LIMIT %s
        """,
        (limit,),
    )


async def get_recent_queries(domain: str = '', method: str = '', limit: int = 25, offset: int = 0) -> list[dict]:
    """Son sorgular; opsiyonel domain (LIKE) + method (tam) filtresi, LIMIT/OFFSET sayfalama."""
    where = []
    params: list = []
    if domain:
        if logcrypto.enabled():
            # Şifreli sütunda alt-string aranamaz → tam domain eşleşmesi
            # (deterministik: aranan domain'i şifreleyip birebir eşleştir).
            where.append('domain = %s')
            params.append(logcrypto.enc(domain.strip().rstrip('.') + '.'))
        else:
            where.append('domain LIKE %s')
            params.append(f'%{domain}%')
    if method:
        where.append('method = %s')
        params.append(method)
    clause = ('WHERE ' + ' AND '.join(where)) if where else ''
    params.append(limit)
    params.append(offset)
    rows = await _fetch_all(
        f"""
        SELECT id, domain, record_type, client_ip,
               DATE_FORMAT(queried_at, '%%Y-%%m-%%d %%H:%%i:%%s') AS queried_at, method, user_id, blocked, blocked_by, resolved_by
        FROM dns_cache
        {clause}
        ORDER BY queried_at DESC
        LIMIT %s OFFSET %s
        """,
        tuple(params),
    )
    for r in rows:                       # şifreliyse gösterim için çöz + sondaki DNS noktasını at
        r['domain'] = (logcrypto.dec(r.get('domain')) or '').rstrip('.')
        r['client_ip'] = logcrypto.dec(r.get('client_ip'))
    return rows


def read_pending(domain: str = '', method: str = '') -> list[dict]:
    """
    Resolver'ın flush bekleyen tamponu (paylaşılan dosya) — henüz DB'de olmayan
    sorgular, en yeni önce, domain/method filtreli. Panel bunu DB ile birleştirir.
    Sync (küçük yerel dosya); dosya yoksa/bozuksa boş liste.
    """
    try:
        with open(_PENDING_FILE, encoding='utf-8') as f:
            items = json.load(f)
    except (OSError, ValueError):
        return []
    dom = domain.lower()
    out = []
    for it in reversed(items):  # append sırası → en yeni önce
        # pending küçük + bellekte → domain'i çözüp alt-string filtre yapabiliriz
        # (DB tarafında şifreli sütunda alt-string aranamaz; burada Python'da olur).
        d = (logcrypto.dec(it.get('domain')) or '').rstrip('.')  # çöz + sondaki DNS noktasını at
        if dom and dom not in d.lower():
            continue
        if method and it.get('method') != method:
            continue
        out.append({
            'domain': d, 'record_type': it.get('record_type'),
            'client_ip': logcrypto.dec(it.get('client_ip')), 'queried_at': it.get('queried_at'),
            'method': it.get('method'), 'user_id': None, 'pending': True,
            'blocked': it.get('blocked', False), 'blocked_by': it.get('blocked_by'),
            'resolved_by': it.get('resolved_by'),
        })
    return out


async def get_top_clients(limit: int = 10) -> list[dict]:
    # GROUP BY şifreli sütun üzerinde çalışır (deterministik: aynı IP → aynı şifre);
    # yalnız gösterim için sonra çözeriz.
    rows = await _fetch_all(
        """
        SELECT client_ip, COUNT(*) AS cnt
        FROM dns_cache
        GROUP BY client_ip
        ORDER BY cnt DESC
        LIMIT %s
        """,
        (limit,),
    )
    for r in rows:
        r['client_ip'] = logcrypto.dec(r.get('client_ip'))
    return rows


# --------------------------------------------------------------------------- #
# resolver_config — panelden canlı sunucu aç/kapa (resolver ~5 sn'de uygular).
# Havuz autocommit=True olduğu için UPDATE anında commit'lenir.
# --------------------------------------------------------------------------- #
_METHOD_ORDER = ['udp', 'doh', 'dot', 'doq']


async def get_resolver_config() -> dict:
    """Metot -> bool ('udp'/'doh'/'dot'/'doq' hangileri açık). Eksikler False."""
    rows = await _fetch_all("SELECT method, enabled FROM resolver_config")
    cfg = {r['method']: bool(r['enabled']) for r in rows}
    return {m: cfg.get(m, False) for m in _METHOD_ORDER}


async def set_method_enabled(method: str, enabled: bool) -> None:
    """Bir yöntemin enabled bayrağını yazar (yalnız bilinen yöntemler)."""
    if method not in _METHOD_ORDER:
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE resolver_config SET enabled = %s WHERE method = %s",
                (1 if enabled else 0, method),
            )


# --------------------------------------------------------------------------- #
# blocklist / allowlist — panelden filtre yönetimi (resolver ~15 sn'de uygular).
# --------------------------------------------------------------------------- #
async def get_blocklist() -> list[dict]:
    return await _fetch_all("SELECT domain, enabled FROM blocklist ORDER BY domain")


async def get_allowlist() -> list[dict]:
    return await _fetch_all("SELECT domain FROM allowlist ORDER BY domain")


async def _write(sql: str, params: tuple) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)


async def add_block(domain: str) -> None:
    await _write("INSERT IGNORE INTO blocklist (domain, enabled) VALUES (%s, TRUE)", (domain,))


async def remove_block(domain: str) -> None:
    await _write("DELETE FROM blocklist WHERE domain = %s", (domain,))


async def add_allow(domain: str) -> None:
    await _write("INSERT IGNORE INTO allowlist (domain) VALUES (%s)", (domain,))


async def remove_allow(domain: str) -> None:
    await _write("DELETE FROM allowlist WHERE domain = %s", (domain,))


# --------------------------------------------------------------------------- #
# blocklist_sources — hazır liste abonelikleri (resolver indirir, RAM'e katar).
# --------------------------------------------------------------------------- #
async def get_sources() -> list[dict]:
    return await _fetch_all(
        "SELECT id, name, url, enabled, count, updated_at FROM blocklist_sources ORDER BY name"
    )


async def add_source(name: str, url: str) -> None:
    # url UNIQUE; yeniden eklenirse tekrar aç + yeniden indirt (updated_at NULL).
    await _write(
        "INSERT INTO blocklist_sources (name, url, updated_at) VALUES (%s, %s, NULL) "
        "ON DUPLICATE KEY UPDATE name = VALUES(name), enabled = TRUE, updated_at = NULL",
        (name, url),
    )


async def remove_source(source_id: int) -> None:
    await _write("DELETE FROM blocklist_sources WHERE id = %s", (source_id,))


async def remove_source_by_url(url: str) -> None:
    await _write("DELETE FROM blocklist_sources WHERE url = %s", (url,))


async def toggle_source(source_id: int, enabled: bool) -> None:
    await _write(
        "UPDATE blocklist_sources SET enabled = %s WHERE id = %s",
        (1 if enabled else 0, source_id),
    )


async def refresh_source(source_id: int) -> None:
    # updated_at = NULL → resolver bir sonraki turda yeniden indirir.
    await _write("UPDATE blocklist_sources SET updated_at = NULL WHERE id = %s", (source_id,))


# --------------------------------------------------------------------------- #
# app_settings — panelden ayarlanabilir yapılandırma (ör. sertifika yolları).
# --------------------------------------------------------------------------- #
async def get_settings() -> dict:
    rows = await _fetch_all("SELECT k, v FROM app_settings")
    return {r['k']: r['v'] for r in rows}


async def set_setting(k: str, v: str) -> None:
    await _write(
        "INSERT INTO app_settings (k, v) VALUES (%s, %s) ON DUPLICATE KEY UPDATE v = VALUES(v)",
        (k, v),
    )


async def clear_history() -> None:
    """Veritabanındaki tüm sorgu geçmişini siler (geri alınamaz)."""
    await _write("DELETE FROM dns_cache", ())


async def get_enabled_services() -> set:
    """Şu an engelli ön tanımlı servislerin adları."""
    rows = await _fetch_all("SELECT DISTINCT service FROM blocked_services")
    return {r['service'] for r in rows}


async def set_service(name: str, domains: list, enabled: bool) -> None:
    """Servisi aç (domainleri ekle) ya da kapat (o servisin satırlarını sil)."""
    if enabled:
        for d in domains:
            await _write("INSERT IGNORE INTO blocked_services (service, domain) VALUES (%s, %s)",
                         (name, d.strip().lower()))
    else:
        await _write("DELETE FROM blocked_services WHERE service = %s", (name,))


def read_source_stats() -> dict:
    """Resolver'ın yazdığı kaynak (çekirdek/önbellek/upstream) işlem süresi ortalamaları."""
    try:
        with open(_SOURCE_STATS_FILE, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}
