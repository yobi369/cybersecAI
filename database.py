"""SQLite/PostgreSQL database adapter for CyberSecAI.

Set DATABASE_URL to a PostgreSQL connection string for durable hosted storage.
SQLite remains available for local development and isolated tests.
"""
import os
import re
import sqlite3
from pathlib import Path

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DATABASE_PATH = Path(os.environ.get(
    "CYBERSECAI_DATABASE",
    str(Path(__file__).parent / "data" / "cybersecai.db"),
))


class CursorAdapter:
    def __init__(self, cursor):
        self._cursor = cursor
        self.lastrowid = None

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class ConnectionAdapter:
    def __init__(self, connection):
        self._connection = connection
        self.is_postgres = True

    def execute(self, sql, params=()):
        statement = sql.replace("?", "%s")
        statement = re.sub(r"^\s*BEGIN IMMEDIATE\s*$", "BEGIN", statement, flags=re.I)
        wants_id = bool(re.match(r"\s*INSERT\s+INTO\s+(users|events|audit_log)\b", statement, re.I))
        if wants_id and not re.search(r"\bRETURNING\b", statement, re.I):
            statement = statement.rstrip().rstrip(";") + " RETURNING id"
        cursor = self._connection.execute(statement, params)
        result = CursorAdapter(cursor)
        if wants_id:
            row = cursor.fetchone()
            result.lastrowid = row["id"] if row else None
        return result

    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()
        return False


def connect_db():
    if DATABASE_URL:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("Install psycopg[binary] to use DATABASE_URL PostgreSQL storage") from exc
        connection = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
        return ConnectionAdapter(connection)
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=10000")
    return db


def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')), created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, source TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('informational','low','medium','high','critical')), status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','resolved','false_positive')), event_time TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id));
    CREATE INDEX IF NOT EXISTS idx_events_status_severity ON events(status,severity);
    CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);
    CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT, details_json TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS auth_throttle(bucket_key TEXT PRIMARY KEY, failures INTEGER NOT NULL, window_started REAL NOT NULL, blocked_until REAL NOT NULL DEFAULT 0);
    """
    if DATABASE_URL:
        pg_schema = re.sub(r"\bid INTEGER PRIMARY KEY\b", "id BIGSERIAL PRIMARY KEY", schema)
        pg_schema = pg_schema.replace("created_by INTEGER", "created_by BIGINT").replace("actor_id INTEGER", "actor_id BIGINT")
        with connect_db() as db:
            db.executescript(pg_schema)
    else:
        with connect_db() as db:
            db.executescript(schema)
            db.commit()
