import aiomysql
from aiomysql.cursors import DictCursor
from contextlib import asynccontextmanager
import os
import asyncio
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))  # .env dosyasını yükle


class DB_CON():
    
    def __init__(self):
        self.db_pool = None
    
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
                    client_ip VARCHAR(45),
                    queried_at DATETIME,
                    method VARCHAR(16)
                )
            """)
            await conn.commit()

    async def open_project(self):
        """
        Projeyi açar ve gerekli işlemleri başlatır.
        """
        await self.create_pool()
        await self.control_scheme()
