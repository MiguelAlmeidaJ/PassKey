import os
import sys
from pathlib import Path
import mysql.connector
from dotenv import load_dotenv

def config():
    root = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    load_dotenv(root / ".env")
    host = os.getenv("DB_HOST", "127.0.0.1")
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Conecte via túnel SSH: DB_HOST=127.0.0.1")
    password = os.getenv("DB_PASSWORD", "")
    if not password or password == "SUBSTITUA":
        raise ValueError("Configure DB_PASSWORD no arquivo .env")
    return dict(host=host, port=int(os.getenv("DB_PORT", "13306")), user=os.getenv("DB_USER", "passkey"), password=password, database=os.getenv("DB_NAME", "passkey"), connection_timeout=10)

class Storage:
    def __init__(self):
        self.db = mysql.connector.connect(**config())
        for sql in (
            "CREATE TABLE IF NOT EXISTS vault_config (id TINYINT PRIMARY KEY, salt VARBINARY(16) NOT NULL, verifier BLOB NOT NULL) ENGINE=InnoDB",
            "CREATE TABLE IF NOT EXISTS vault_entries (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, payload LONGBLOB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB"
        ):
            with self.db.cursor() as cursor:
                cursor.execute(sql)
        self.db.commit()

    def get_config(self):
        with self.db.cursor() as cursor:
            cursor.execute("SELECT salt, verifier FROM vault_config WHERE id=1")
            return cursor.fetchone()

    def initialize(self, salt, verifier):
        self.execute("INSERT INTO vault_config(id,salt,verifier) VALUES(1,%s,%s)", (salt, verifier))

    def entries(self):
        with self.db.cursor() as cursor:
            cursor.execute("SELECT id, payload FROM vault_entries ORDER BY id DESC")
            return cursor.fetchall()

    def execute(self, sql, params):
        try:
            with self.db.cursor() as cursor:
                cursor.execute(sql, params)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def add(self, payload):
        self.execute("INSERT INTO vault_entries(payload) VALUES(%s)", (payload,))

    def update(self, record_id, payload):
        self.execute("UPDATE vault_entries SET payload=%s WHERE id=%s", (payload, record_id))

    def delete(self, record_id):
        self.execute("DELETE FROM vault_entries WHERE id=%s", (record_id,))

    def close(self):
        self.db.close()
