"""End-to-end PostgreSQL adapter test; run with DATABASE_URL set to a disposable database."""
import os
import unittest


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL is not configured")
class PostgreSQLIntegrationTests(unittest.TestCase):
    def test_bootstrap_login_event_and_audit_round_trip(self):
        import app as api
        from database import connect_db

        with connect_db() as db:
            db.execute("DELETE FROM audit_log")
            db.execute("DELETE FROM events")
            db.execute("DELETE FROM users")
            db.commit()

        client = api.create_app({"TESTING": True}).test_client()
        bootstrap_token = os.environ["CYBERSECAI_BOOTSTRAP_TOKEN"]
        boot = client.post(
            "/api/v1/auth/bootstrap",
            headers={"X-Bootstrap-Token": bootstrap_token},
            json={"username": "pg_integration_admin", "password": "long-integration-test-password"},
        )
        self.assertEqual(boot.status_code, 201, boot.get_data(as_text=True))

        login = client.post(
            "/api/v1/auth/login",
            json={"username": "pg_integration_admin", "password": "long-integration-test-password"},
        )
        self.assertEqual(login.status_code, 200, login.get_data(as_text=True))
        headers = {"Authorization": "Bearer " + login.json["access_token"]}

        event = client.post(
            "/api/v1/events",
            headers=headers,
            json={
                "title": "PostgreSQL integration event",
                "description": "Synthetic integration test only",
                "source": "postgres-integration-test",
                "severity": "medium",
                "event_time": "2026-01-01T12:00:00Z",
            },
        )
        self.assertEqual(event.status_code, 201, event.get_data(as_text=True))
        listing = client.get("/api/v1/events", headers=headers)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json["total"], 1)
        audit = client.get("/api/v1/audit", headers=headers)
        self.assertEqual(audit.status_code, 200)
        self.assertGreaterEqual(len(audit.json["items"]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
