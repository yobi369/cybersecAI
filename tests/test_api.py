import os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"CYBERSECAI_DATABASE": str(Path(self.tmp.name)/"test.db"),
            "CYBERSECAI_SECRET_KEY": "test-secret-key-that-is-at-least-thirty-two-bytes", "CYBERSECAI_BOOTSTRAP_TOKEN": "test-bootstrap-token-that-is-over-32-bytes"})
        self.env.start()
        import database
        import app as api
        database.DATABASE_PATH = Path(os.environ["CYBERSECAI_DATABASE"])
        api.DATABASE_PATH = database.DATABASE_PATH
        api.init_db()
        self.client = api.create_app({"TESTING": True}).test_client()
    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()
    def bootstrap(self):
        return self.client.post("/api/v1/auth/bootstrap", headers={"X-Bootstrap-Token":"test-bootstrap-token-that-is-over-32-bytes"}, json={"username":"security_admin","password":"strong-test-password-123"})
    def login(self, password="strong-test-password-123"):
        return self.client.post("/api/v1/auth/login", json={"username":"security_admin","password":password})
    def headers(self, token):
        return {"Authorization":"Bearer "+token}
    def test_console_is_served(self):
        response = self.client.get("/console")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security operations console", response.data)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers.get("Content-Security-Policy", ""))

    def test_auth_responses_are_not_cacheable(self):
        response = self.client.post("/api/v1/auth/login", json={"username": "missing", "password": "wrong"})
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")
    def test_bootstrap_requires_secret(self):
        response = self.client.post("/api/v1/auth/bootstrap", json={"username":"intruder","password":"strong-test-password-123"})
        self.assertEqual(response.status_code, 403)

    def test_bootstrap_is_one_time(self):
        self.assertEqual(self.bootstrap().status_code, 201)
        self.assertEqual(self.bootstrap().status_code, 409)
    def test_login_me_and_auth_required(self):
        self.bootstrap()
        token = self.login().json["access_token"]
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=self.headers(token)).json["role"], "admin")
        self.assertEqual(self.client.get("/api/v1/events").status_code, 401)
    def test_wrong_password_and_tampering_rejected(self):
        self.bootstrap()
        self.assertEqual(self.login("incorrect-password").status_code, 401)
        token = self.login().json["access_token"]
        changed = token[:-1] + ("a" if token[-1] != "a" else "b")
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=self.headers(changed)).status_code, 401)
    def test_create_filter_update_and_audit(self):
        self.bootstrap()
        headers = self.headers(self.login().json["access_token"])
        event = self.client.post("/api/v1/events", headers=headers, json={"title":"Repeated failed logins",
            "description":"Synthetic test event","source":"test-fixture","severity":"medium","event_time":"2026-01-01T12:00:00Z"})
        self.assertEqual(event.status_code, 201, event.json)
        event_id = event.json["id"]
        self.assertEqual(self.client.get("/api/v1/events?severity=medium", headers=headers).json["total"], 1)
        self.assertEqual(self.client.patch(f"/api/v1/events/{event_id}", headers=headers, json={"status":"investigating"}).status_code, 200)
        self.assertGreaterEqual(len(self.client.get("/api/v1/audit", headers=headers).json["items"]), 3)
    def test_validation_rejects_bad_severity_and_extra_update_fields(self):
        self.bootstrap()
        headers = self.headers(self.login().json["access_token"])
        response = self.client.post("/api/v1/events", headers=headers, json={"title":"x","description":"y","source":"z","severity":"impossible"})
        self.assertEqual(response.status_code, 400)
        response = self.client.patch("/api/v1/events/1", headers=headers, json={"status":"resolved","severity":"low"})
        self.assertEqual(response.status_code, 400)
    def test_log_analysis_returns_labeled_heuristics(self):
        self.bootstrap()
        headers = self.headers(self.login().json["access_token"])
        response = self.client.post("/api/v1/analyze", headers=headers, json={
            "logs": "authentication failure for test user\nnormal service started\n"
        })
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["finding_count"], 1)
        self.assertEqual(response.json["findings"][0]["rule_id"], "AUTH-001")
        self.assertIn("not proof of compromise", response.json["disclaimer"])

    def test_log_analysis_rejects_empty_and_oversized_input(self):
        self.bootstrap()
        headers = self.headers(self.login().json["access_token"])
        self.assertEqual(self.client.post("/api/v1/analyze", headers=headers, json={"logs": ""}).status_code, 400)
        self.assertEqual(self.client.post("/api/v1/analyze", headers=headers, json={"logs": "x" * 100001}).status_code, 413)

    def test_password_change_invalidates_existing_tokens(self):
        self.assertEqual(self.bootstrap().status_code, 201)
        token = self.login().json["access_token"]
        response = self.client.post("/api/v1/auth/password", headers=self.headers(token), json={
            "current_password": "strong-test-password-123",
            "new_password": "new-strong-test-password-456",
        })
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=self.headers(token)).status_code, 401)
        self.assertEqual(self.login().status_code, 401)
        new_login = self.client.post("/api/v1/auth/login", json={
            "username": "security_admin", "password": "new-strong-test-password-456"
        })
        self.assertEqual(new_login.status_code, 200, new_login.json)

    def test_login_throttles_repeated_failures(self):
        self.bootstrap()
        for _ in range(5):
            response = self.login("incorrect-password")
            self.assertEqual(response.status_code, 401)
        blocked = self.login()
        self.assertEqual(blocked.status_code, 429)
        self.assertGreaterEqual(int(blocked.headers.get("Retry-After", "0")), 1)

    def test_short_bootstrap_password_rejected(self):
        response = self.client.post("/api/v1/auth/bootstrap", headers={"X-Bootstrap-Token":"test-bootstrap-token-that-is-over-32-bytes"}, json={"username":"admin","password":"short"})
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__": unittest.main(verbosity=2)
