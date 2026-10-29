import unittest
from database import ConnectionAdapter


class FakeCursor:
    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.rowcount = 1

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(self):
        self.statements = []

    def execute(self, statement, params=()):
        self.statements.append((statement, params))
        rows = [{"id": 42}] if "RETURNING id" in statement else []
        return FakeCursor(rows)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class PostgreSQLAdapterTests(unittest.TestCase):
    def test_converts_placeholders_and_returns_inserted_id(self):
        raw = FakeConnection()
        db = ConnectionAdapter(raw)
        cursor = db.execute("INSERT INTO users(username) VALUES(?)", ("analyst",))
        self.assertEqual(raw.statements[0][0], "INSERT INTO users(username) VALUES(%s) RETURNING id")
        self.assertEqual(raw.statements[0][1], ("analyst",))
        self.assertEqual(cursor.lastrowid, 42)

    def test_converts_immediate_begin_for_postgres(self):
        raw = FakeConnection()
        db = ConnectionAdapter(raw)
        db.execute("BEGIN IMMEDIATE")
        self.assertEqual(raw.statements[0][0], "BEGIN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
