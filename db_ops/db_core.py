import aiomysql
from aiomysql.cursors import DictCursor
from contextlib import asynccontextmanager
import os
import asyncio
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))  # .env dosyasını yükle

from logs.dns_logs import logger
import db_ops.db_control_users as dbusers
# Şema sürümü: uyumsuz her şema değişikliğinde 1 artır ve MIGRATIONS'a
# eski sürümü yeni sürüme taşıyan adımı ekle. Açılışta migrate_scheme()
# kayıtlı sürümden güncel sürüme sırayla yürür.
SCHEMA_VERSION = 6

MIGRATIONS = {
    # 1 -> 2: timestamp BIGINT yerine queried_at DATETIME (UTC). Log verisi
    # beta döneminde feda edilebilir; tablo düşürülür, control_scheme yeniden kurar.
    1: ("DROP TABLE IF EXISTS dns_cache",),
    # 2 -> 3: engelleme izleme — sorgu engellendi mi + hangi liste eşleşti.
    2: (
        "ALTER TABLE dns_cache ADD COLUMN blocked BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE dns_cache ADD COLUMN blocked_by VARCHAR(255) DEFAULT NULL",
    ),
    # 3 -> 4: çözüm kaynağı — 'DNS çekirdeği' / 'Önbellek' / upstream sunucu.
    3: (
        "ALTER TABLE dns_cache ADD COLUMN resolved_by VARCHAR(255) DEFAULT NULL",
    ),
    # 4 -> 5: dns_cache indeksleri (büyük log tablosunda sorgu/analiz hızı).
    4: (
        "ALTER TABLE dns_cache ADD INDEX idx_queried_at (queried_at)",
        "ALTER TABLE dns_cache ADD INDEX idx_domain (domain)",
        "ALTER TABLE dns_cache ADD INDEX idx_blocked (blocked)",
    ),
    # 5 -> 6: client_ip artık (opsiyonel) DNS_LOG_KEY ile şifreli saklanabilir.
    # Deterministik AES-SIV base64 çıktısı 45 karaktere sığmaz (IPv6 ~84) → genişlet.
    # Şifreleme kapalıyken düz IP yazılır; kolon her iki durumu da taşır.
    5: (
        "ALTER TABLE dns_cache MODIFY client_ip VARCHAR(120)",
    ),
}


class DB_CON():
    
    def __init__(self):
        self.db_pool = None
        self.user_manager = dbusers.USER_MANAGER(self)  # USER_MANAGER sınıfını başlat ve db_con olarak self'i geçir

    async def create_pool(self):
        if self.db_pool is not None:
            return self.db_pool
        pool = await aiomysql.create_pool(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", 3306)),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", "password"),
            db=os.getenv("DB_NAME", "dns_db"),
        )
        self.db_pool = pool
        return self.db_pool

    async def close_pool(self):
        if self.db_pool is not None:
            self.db_pool.close()
            await self.db_pool.wait_closed()
            self.db_pool = None


    async def db_retry(self, coro_func, retries: int = 5, delay: float = 0.2):
        """Maria DB 1020 hatası durumunda yeniden deneme yapacak bir fonksiyon."""
        for attempt in range(retries):
            try:
                return await coro_func()
            except aiomysql.Error as e:
                if getattr(e, 'args', None) and e.args[0] == 1020 and attempt < retries - 1:
                    await asyncio.sleep(delay * (attempt + 1))
                    continue
                raise

    @asynccontextmanager
    async def get_db_connection(self):
        """
        Havuzdan güvenle bir bağlantı (connection) ödünç veren asenkron
        bağlam yöneticisi; çıkışta bağlantı havuza geri döner.
        """
        if self.db_pool is None:
            await self.create_pool()

        async with self.db_pool.acquire() as connection:
            yield connection


    @asynccontextmanager
    async def get_db_cursor(self, dictionary: bool = False):
        """
        Havuzdaki bir bağlantı üzerinden (cursor, connection) ikilisi veren
        asenkron bağlam yöneticisi.

        Havuz autocommit=False çalışır: çıplak bir SELECT bile REPEATABLE READ
        transaction'ı açar ve snapshot'ı sabitler. Bağlantı bu transaction
        kapanmadan havuza dönerse sonraki kullanıcı, başkalarının commit'lerini
        görmeyen bayat snapshot'ı okur. Bu yüzden çıkışta rollback yapılır;
        commit etmiş yazma işlemleri için bu no-op'tur.
        """
        async with self.get_db_connection() as connection:
            try:
                if dictionary:
                    async with connection.cursor(DictCursor) as cursor:
                        yield cursor, connection
                else:
                    async with connection.cursor() as cursor:
                        yield cursor, connection
            finally:
                try:
                    await connection.rollback()
                except Exception:
                    pass


    async def migrate_scheme(self):
        """
        Şema sürümünü kontrol eder, eskiyse migrasyonları sırayla uygular.

        Sürüm bilgisi schema_version tablosunda tutulur. Kayıt yoksa:
        dns_cache varsa sürümleme-öncesi (legacy, v1) kurulum kabul edilir;
        hiç tablo yoksa taze kurulumdur, doğrudan güncel sürüm yazılır.
        """
        async with self.get_db_cursor() as (cursor, conn):
            await cursor.execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INT NOT NULL)"
            )
            await cursor.execute("SELECT version FROM schema_version LIMIT 1")
            row = await cursor.fetchone()
            if row is None:
                await cursor.execute("SHOW TABLES LIKE 'dns_cache'")
                legacy = await cursor.fetchone() is not None
                version = 1 if legacy else SCHEMA_VERSION
                await cursor.execute(
                    "INSERT INTO schema_version (version) VALUES (%s)", (version,)
                )
            else:
                version = row[0]

            while version < SCHEMA_VERSION:
                logger.info("Şema migrasyonu uygulanıyor: v%d -> v%d", version, version + 1)
                for sql in MIGRATIONS[version]:
                    await cursor.execute(sql)
                version += 1
                await cursor.execute("UPDATE schema_version SET version = %s", (version,))
            await conn.commit()

    async def control_scheme(self):
        """
        Şema kontrolü yapar ve gerekli tabloları oluşturur. Eğer tablolar zaten mevcutsa, herhangi bir işlem yapmaz.
        """
        async with self.get_db_cursor() as (cursor, conn):
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_cache (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    domain VARCHAR(255),
                    record_type VARCHAR(10),
                    client_ip VARCHAR(120),
                    queried_at DATETIME,
                    method VARCHAR(16),
                    user_id INT,
                    blocked BOOLEAN NOT NULL DEFAULT FALSE,
                    blocked_by VARCHAR(255) DEFAULT NULL,
                    resolved_by VARCHAR(255) DEFAULT NULL,
                    INDEX idx_queried_at (queried_at),
                    INDEX idx_domain (domain),
                    INDEX idx_blocked (blocked)
                );
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE,
                    password_hash VARCHAR(255),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    log_dns BOOLEAN DEFAULT FALSE,
                    random_key VARCHAR(255) DEFAULT NULL
                );
            """)
            # Hangi DNS metotlarının açık olduğu — web panelinden yönetilir,
            # resolver çalışırken okuyup sunucuları başlatıp durdurur.
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS resolver_config (
                    method VARCHAR(16) PRIMARY KEY,
                    enabled BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            # GÜVENLİ VARSAYILAN: sadece düz UDP açık; DoH/DoT/DoQ kapalı.
            # INSERT IGNORE => mevcut satırlar (kullanıcının seçimleri) korunur.
            await cursor.execute("""
                INSERT IGNORE INTO resolver_config (method, enabled) VALUES
                ('udp', TRUE), ('doh', FALSE), ('dot', FALSE), ('doq', FALSE)
            """)
            # Engelleme listeleri (AdGuard tarzı): blocklist + allowlist.
            # Yeni tablolar → migrasyon gerekmez (IF NOT EXISTS yeter).
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocklist (
                    domain VARCHAR(255) PRIMARY KEY,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS allowlist (
                    domain VARCHAR(255) PRIMARY KEY
                )
            """)
            # Hazır engelleme listeleri (URL abonelikleri) — resolver indirir, RAM'e katar.
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocklist_sources (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255),
                    url VARCHAR(512) UNIQUE,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    count INT NOT NULL DEFAULT 0,
                    updated_at DATETIME NULL
                )
            """)
            # Ön tanımlı servis engelleme (panelden aç/kapa; domainler burada tutulur).
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_services (
                    service VARCHAR(64) NOT NULL,
                    domain VARCHAR(255) NOT NULL,
                    PRIMARY KEY (service, domain)
                )
            """)
            # Panelden ayarlanabilir anahtar-değer ayarları (ör. sertifika yolları).
            await cursor.execute(
                "CREATE TABLE IF NOT EXISTS app_settings (k VARCHAR(64) PRIMARY KEY, v VARCHAR(512))"
            )
            await cursor.execute(
                "INSERT IGNORE INTO app_settings (k, v) VALUES "
                "(%s,%s),(%s,%s),(%s,%s),(%s,%s),(%s,%s),(%s,%s),"
                "(%s,%s),(%s,%s),(%s,%s),(%s,%s),(%s,%s),(%s,%s),(%s,%s),(%s,%s),(%s,%s),"
                "(%s,%s),(%s,%s),(%s,%s),(%s,%s)",
                ('cert_file', os.getenv('CERT_FILE', 'certificates/fullchain.pem'),
                 'key_file', os.getenv('KEY_FILE', 'certificates/privkey.pem'),
                 # İç dinleme portları (build_* env'den okur; dış/host yayını ayrı).
                 'udp_port', os.getenv('CONTAINER_UDP_PORT', '5300'),
                 'https_port', os.getenv('CONTAINER_HTTPS_PORT', '44300'),
                 'dot_port', os.getenv('CONTAINER_DOT_PORT', '8853'),
                 'doq_port', os.getenv('CONTAINER_DOQ_PORT', '8530'),
                 # Genel ayarlar (panelden; resolver periyodik uygular).
                 'log_queries', '1',        # sorgu geçmişi aç/kapa
                 'cache_enabled', '1',      # önbellek aç/kapa
                 'cache_min_ttl', '0',      # alt sınır (0 = yok)
                 'cache_max_ttl', '86400',  # üst sınır (sn)
                 'cache_clear_at', '0',     # panelden "temizle" damgası (değişince resolver boşaltır)
                 # Çözümleme modu: recursion (kendi çekirdek) vs forwarding.
                 'use_recursion', '1',      # 1 = recursive, 0 = forwarding
                 'upstreams', '',           # forwarding upstream'leri (satır başına bir tane)
                 'upstream_strategy', 'sequential',  # sequential | parallel | fastest
                 'safesearch_engines', '',   # güvenli arama açık motorlar (virgülle: google,bing…)
                 # Erişim kontrolü + log retention.
                 'client_allow', '',         # yalnız bu istemciler sorabilir (boş = herkes)
                 'client_deny', '',          # reddedilen istemciler (IP/CIDR)
                 'rate_limit', '0',          # istemci başına saniyede sorgu (0 = kapalı)
                 'log_retention_days', '0'),  # N günden eski geçmişi sil (0 = sonsuz)
            )
            await conn.commit()

    async def get_resolver_config(self):
        """Metot -> bool sözlüğü ('udp'/'doh'/'dot'/'doq' hangileri açık)."""
        async with self.get_db_cursor(dictionary=True) as (cursor, conn):
            await cursor.execute("SELECT method, enabled FROM resolver_config")
            rows = await cursor.fetchall()
        return {r['method']: bool(r['enabled']) for r in rows}

    async def get_filter_lists(self):
        """
        (blockset, allowset) döndürür — engelli (enabled) + izinli domain kümeleri,
        karşılaştırma için normalize (küçük harf, baş/son boşluk ve son nokta atılmış).
        resolver bellekte tutar; sorgu başına DB'ye gidilmez.
        """
        def norm(d):
            return d.strip().rstrip(".").lower()
        async with self.get_db_cursor(dictionary=True) as (cursor, conn):
            await cursor.execute("SELECT domain FROM blocklist WHERE enabled = TRUE")
            block = {norm(r["domain"]) for r in await cursor.fetchall()}
            await cursor.execute("SELECT domain FROM allowlist")
            allow = {norm(r["domain"]) for r in await cursor.fetchall()}
        return block, allow

    async def get_service_lists(self):
        """Ön tanımlı servis engelleri: {servis_adı: frozenset(domain)}. is_blocked
        bunları list_sets'e katar → eşleşen servisin adını döndürür (attribution)."""
        out = {}
        async with self.get_db_cursor(dictionary=True) as (cursor, conn):
            await cursor.execute("SELECT service, domain FROM blocked_services")
            for r in await cursor.fetchall():
                out.setdefault(r["service"], set()).add(r["domain"].strip().rstrip(".").lower())
        return {k: frozenset(v) for k, v in out.items()}

    async def get_blocklist_sources(self):
        """
        Enabled hazır listeler: [{id, url, force}]. force=True ise resolver yeniden
        indirir (yeni eklenmiş = updated_at NULL, ya da 24 saatten eski = bayat).
        """
        async with self.get_db_cursor(dictionary=True) as (cursor, conn):
            await cursor.execute(
                "SELECT id, name, url, "
                "(updated_at IS NULL OR updated_at < UTC_TIMESTAMP() - INTERVAL 24 HOUR) AS force_dl "
                "FROM blocklist_sources WHERE enabled = TRUE"
            )
            rows = await cursor.fetchall()
        return [{"id": r["id"], "name": r["name"], "url": r["url"], "force": bool(r["force_dl"])} for r in rows]

    async def get_setting(self, key, default=None):
        """app_settings'ten tek bir ayar değeri (panelden değiştirilebilir)."""
        async with self.get_db_cursor(dictionary=True) as (cursor, conn):
            await cursor.execute("SELECT v FROM app_settings WHERE k = %s", (key,))
            row = await cursor.fetchone()
        return row["v"] if row else default

    async def delete_old_logs(self, days):
        """N günden eski dns_cache satırlarını sil (log retention). Silinen sayı."""
        if days <= 0:
            return 0
        async with self.get_db_cursor() as (cursor, conn):
            await cursor.execute(
                "DELETE FROM dns_cache WHERE queried_at < UTC_TIMESTAMP() - INTERVAL %s DAY", (days,))
            await conn.commit()
            return cursor.rowcount

    async def set_source_stats(self, source_id, count):
        """Bir listenin domain sayısını ve son güncelleme zamanını yazar."""
        async with self.get_db_cursor() as (cursor, conn):
            await cursor.execute(
                "UPDATE blocklist_sources SET count = %s, updated_at = UTC_TIMESTAMP() WHERE id = %s",
                (count, source_id),
            )
            await conn.commit()

    async def open_project(self):
        """
        Projeyi açar ve gerekli işlemleri başlatır.
        """
        await self.create_pool()
        await self.migrate_scheme()   # önce eski şemayı güncel sürüme taşı
        await self.control_scheme()   # sonra eksik tabloları kur
