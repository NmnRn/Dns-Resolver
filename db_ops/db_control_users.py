import aiomysql


class USER_MANAGER():
    """
    Kullanıcı tablosu ve işlemleri için sınıf.
    """

    def __init__(self, db_con):
        self.db_con = db_con
        self.users = {}

    async def create_user(self, username: str, password_hash: str, log_dns: bool = False):
        async with self.db_con.get_db_connection() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "INSERT INTO users (username, password_hash, log_dns) VALUES (%s, %s, %s)",
                    (username, password_hash, log_dns)
                )
                await conn.commit()
                self.users[username] = {
                    'username': username,
                    'password_hash': password_hash,
                    'log_dns': log_dns
                }

    async def get_user_from_db(self, username: str):
        async with self.db_con.get_db_connection() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(
                    "SELECT * FROM users WHERE username = %s",
                    (username,)
                )
                return await cursor.fetchone()
            
    async def load_users(self):
        async with self.db_con.get_db_connection() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute("SELECT * FROM users")
                self.users = {row['username']: row for row in await cursor.fetchall()}
            