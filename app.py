"""CyberSecAI API: defensive security-event triage for authorized environments."""
from __future__ import annotations
import hashlib, hmac, json, os, sqlite3, time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any
from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_PATH = Path(os.environ.get("CYBERSECAI_DATABASE", str(Path(__file__).parent / "data" / "cybersecai.db")))
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "3600"))
MAX_BODY_BYTES = 256 * 1024
VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"open", "investigating", "resolved", "false_positive"}
VALID_ROLES = {"admin", "analyst", "viewer"}

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def connect_db():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=10000")
    return db

def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')), created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, source TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('informational','low','medium','high','critical')), status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','resolved','false_positive')), event_time TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id));
        CREATE INDEX IF NOT EXISTS idx_events_status_severity ON events(status,severity);
        CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT, details_json TEXT NOT NULL, created_at TEXT NOT NULL);
        """)
        db.commit()

def audit(db, actor_id, action, resource_type, resource_id=None, details=None):
    db.execute("INSERT INTO audit_log(actor_id,action,resource_type,resource_id,details_json,created_at) VALUES(?,?,?,?,?,?)",
               (actor_id, action, resource_type, resource_id, json.dumps(details or {}, separators=(",", ":"), sort_keys=True), utc_now()))

def token_secret():
    secret = os.environ.get("CYBERSECAI_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("CYBERSECAI_SECRET_KEY must be set to at least 32 characters")
    return secret.encode()

def issue_token(user):
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = json.dumps({"sub": user["id"], "username": user["username"], "role": user["role"], "exp": int(time.time()) + TOKEN_TTL_SECONDS}, separators=(",", ":"), sort_keys=True).encode()
    body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    signing = f"{header}.{body}".encode()
    signature = base64.urlsafe_b64encode(hmac.new(token_secret(), signing, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{header}.{body}.{signature}"

def decode_token(token):
    import base64
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        expected = base64.urlsafe_b64encode(hmac.new(token_secret(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(expected, parts[2]): return None
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        if not isinstance(claims.get("exp"), int) or claims["exp"] <= int(time.time()): return None
        if not isinstance(claims.get("sub"), int) or claims.get("role") not in VALID_ROLES: return None
        return claims
    except (ValueError, TypeError, KeyError, RuntimeError, json.JSONDecodeError):
        return None

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_BODY_BYTES)
    if test_config: app.config.update(test_config)
    init_db()

    @app.errorhandler(413)
    def too_large(_): return jsonify(error="request_too_large"), 413
    @app.errorhandler(404)
    def not_found(_): return jsonify(error="not_found"), 404
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error("Unhandled application error: %s", error)
        return jsonify(error="internal_error"), 500

    def db():
        if "db" not in g: g.db = connect_db()
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        connection = g.pop("db", None)
        if connection is not None: connection.close()

    def authenticated(handler):
        @wraps(handler)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "): return jsonify(error="authentication_required"), 401
            claims = decode_token(header[7:].strip())
            if claims is None: return jsonify(error="invalid_or_expired_token"), 401
            user = db().execute("SELECT id,username,role FROM users WHERE id=?", (claims["sub"],)).fetchone()
            if user is None or user["username"] != claims["username"] or user["role"] != claims["role"]:
                return jsonify(error="invalid_or_expired_token"), 401
            g.user = user
            return handler(*args, **kwargs)
        return wrapper

    def roles(*allowed):
        def decorator(handler):
            @wraps(handler)
            @authenticated
            def wrapper(*args, **kwargs):
                if g.user["role"] not in allowed: return jsonify(error="insufficient_permissions"), 403
                return handler(*args, **kwargs)
            return wrapper
        return decorator

    def payload_object():
        value = request.get_json(silent=True) if request.is_json else None
        return value if isinstance(value, dict) else None

    def text_field(payload, key, limit):
        value = payload.get(key)
        if not isinstance(value, str): return None
        value = value.strip()
        if not value or len(value) > limit or any(ord(c) < 32 and c not in "\t\n\r" for c in value): return None
        return value

    @app.get("/health")
    def health(): return jsonify(status="ok", service="cybersecai-api", timestamp=utc_now())

    @app.post("/api/v1/auth/bootstrap")
    def bootstrap():
        payload = payload_object()
        if payload is None: return jsonify(error="invalid_json"), 400
        username = text_field(payload, "username", 64)
        password = payload.get("password")
        if not username or not username.replace("_", "").replace("-", "").isalnum(): return jsonify(error="invalid_username"), 400
        if not isinstance(password, str) or not 14 <= len(password) <= 256: return jsonify(error="weak_password"), 400
        connection = db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                connection.rollback()
                return jsonify(error="bootstrap_closed"), 409
            cursor = connection.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                                         (username, generate_password_hash(password), "admin", utc_now()))
            audit(connection, cursor.lastrowid, "user.bootstrap", "user", str(cursor.lastrowid))
            connection.commit()
            return jsonify(message="Administrator created"), 201
        except sqlite3.IntegrityError:
            connection.rollback()
            return jsonify(error="username_unavailable"), 409

    @app.post("/api/v1/auth/login")
    def login():
        payload = payload_object()
        if payload is None: return jsonify(error="invalid_json"), 400
        username, password = text_field(payload, "username", 64), payload.get("password")
        if not username or not isinstance(password, str) or len(password) > 256: return jsonify(error="invalid_credentials"), 401
        user = db().execute("SELECT id,username,password_hash,role FROM users WHERE username=?", (username,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password): return jsonify(error="invalid_credentials"), 401
        audit(db(), user["id"], "auth.login", "user", str(user["id"]))
        db().commit()
        return jsonify(access_token=issue_token(user), token_type="Bearer", expires_in=TOKEN_TTL_SECONDS,
                       user={"id": user["id"], "username": user["username"], "role": user["role"]})

    @app.get("/api/v1/auth/me")
    @authenticated
    def me(): return jsonify(id=g.user["id"], username=g.user["username"], role=g.user["role"])

    @app.get("/api/v1/events")
    @authenticated
    def list_events():
        try:
            limit, offset = min(max(int(request.args.get("limit", "50")), 1), 100), max(int(request.args.get("offset", "0")), 0)
        except ValueError: return jsonify(error="invalid_pagination"), 400
        severity, status = request.args.get("severity"), request.args.get("status")
        if severity is not None and severity not in VALID_SEVERITIES: return jsonify(error="invalid_severity"), 400
        if status is not None and status not in VALID_STATUSES: return jsonify(error="invalid_status"), 400
        clauses, values = [], []
        if severity: clauses.append("severity=?"); values.append(severity)
        if status: clauses.append("status=?"); values.append(status)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = db().execute("SELECT id,title,description,source,severity,status,event_time,created_at,updated_at,created_by FROM events" + where + " ORDER BY id DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
        total = db().execute("SELECT COUNT(*) total FROM events" + where, values).fetchone()["total"]
        return jsonify(items=[dict(row) for row in rows], total=total, limit=limit, offset=offset)

    @app.post("/api/v1/events")
    @roles("admin", "analyst")
    def create_event():
        payload = payload_object()
        if payload is None: return jsonify(error="invalid_json"), 400
        title, description, source = text_field(payload, "title", 160), text_field(payload, "description", 4000), text_field(payload, "source", 200)
        severity, event_time = payload.get("severity"), payload.get("event_time", utc_now())
        if not title or not description or not source: return jsonify(error="invalid_event_fields"), 400
        if severity not in VALID_SEVERITIES: return jsonify(error="invalid_severity"), 400
        if not isinstance(event_time, str) or len(event_time) > 64: return jsonify(error="invalid_event_time"), 400
        try: event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00")).isoformat()
        except ValueError: return jsonify(error="invalid_event_time"), 400
        now = utc_now()
        cursor = db().execute("INSERT INTO events(title,description,source,severity,status,event_time,created_at,updated_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)",
                              (title, description, source, severity, "open", event_time, now, now, g.user["id"]))
        event_id = cursor.lastrowid
        audit(db(), g.user["id"], "event.created", "event", str(event_id), {"severity": severity, "source": source})
        db().commit()
        return jsonify(id=event_id, title=title, description=description, source=source, severity=severity,
                       status="open", event_time=event_time, created_at=now, updated_at=now, created_by=g.user["id"]), 201

    @app.patch("/api/v1/events/<int:event_id>")
    @roles("admin", "analyst")
    def update_event(event_id):
        payload = payload_object()
        if payload is None or set(payload) != {"status"}: return jsonify(error="invalid_update"), 400
        status = payload.get("status")
        if status not in VALID_STATUSES: return jsonify(error="invalid_status"), 400
        connection = db()
        row = connection.execute("SELECT id,status FROM events WHERE id=?", (event_id,)).fetchone()
        if row is None: return jsonify(error="not_found"), 404
        now, previous = utc_now(), row["status"]
        connection.execute("UPDATE events SET status=?,updated_at=? WHERE id=?", (status, now, event_id))
        audit(connection, g.user["id"], "event.status_changed", "event", str(event_id), {"from": previous, "to": status})
        connection.commit()
        return jsonify(id=event_id, status=status, updated_at=now)

    @app.get("/api/v1/audit")
    @roles("admin")
    def list_audit():
        try:
            limit, offset = min(max(int(request.args.get("limit", "50")), 1), 100), max(int(request.args.get("offset", "0")), 0)
        except ValueError: return jsonify(error="invalid_pagination"), 400
        rows = db().execute("SELECT id,actor_id,action,resource_type,resource_id,details_json,created_at FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return jsonify(items=[{**dict(row), "details": json.loads(row["details_json"])} for row in rows], limit=limit, offset=offset)
    return app

app = create_app()
if __name__ == "__main__":
    if os.environ.get("FLASK_DEBUG", "").lower() == "true": raise SystemExit("Debug mode is disabled in this entry point.")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), debug=False)
