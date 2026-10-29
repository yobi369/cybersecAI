"""CyberSecAI API: defensive security-event triage for authorized environments."""
from __future__ import annotations
import hashlib, hmac, json, os, sqlite3, time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, g, jsonify, request, render_template
from werkzeug.security import check_password_hash, generate_password_hash
from database import connect_db, init_db, DATABASE_PATH, DATABASE_URL

TOKEN_TTL_SECONDS = max(60, min(int(os.environ.get("TOKEN_TTL_SECONDS", "3600")), 86400))
MAX_BODY_BYTES = 256 * 1024
VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"open", "investigating", "resolved", "false_positive"}
VALID_ROLES = {"admin", "analyst", "viewer"}

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def audit(db, actor_id, action, resource_type, resource_id=None, details=None):
    db.execute(
        "INSERT INTO audit_log(actor_id,action,resource_type,resource_id,details_json,created_at) VALUES(?,?,?,?,?,?)",
        (actor_id, action, resource_type, resource_id,
         json.dumps(details or {}, separators=(",", ":"), sort_keys=True), utc_now()),
    )

def token_secret():
    secret = os.environ.get("CYBERSECAI_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("CYBERSECAI_SECRET_KEY must be set to at least 32 characters")
    return secret.encode()

def issue_token(user):
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = json.dumps({
        "sub": user["id"], "username": user["username"], "role": user["role"], "ver": user["token_version"],
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }, separators=(",", ":"), sort_keys=True).encode()
    body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    signing = f"{header}.{body}".encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(token_secret(), signing, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{header}.{body}.{signature}"

def decode_token(token):
    import base64
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        expected = base64.urlsafe_b64encode(
            hmac.new(token_secret(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(expected, parts[2]):
            return None
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        if not isinstance(claims.get("exp"), int) or claims["exp"] <= int(time.time()):
            return None
        if not isinstance(claims.get("sub"), int) or not isinstance(claims.get("ver"), int) or claims.get("role") not in VALID_ROLES:
            return None
        return claims
    except (ValueError, TypeError, KeyError, RuntimeError, json.JSONDecodeError):
        return None

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_BODY_BYTES)
    if test_config: app.config.update(test_config)
    init_db()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if request.path.startswith("/api/v1/auth/"):
            response.headers["Cache-Control"] = "no-store"
        return response

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
            user = db().execute("SELECT id,username,role,token_version FROM users WHERE id=?", (claims["sub"],)).fetchone()
            if user is None or user["username"] != claims["username"] or user["role"] != claims["role"] or user["token_version"] != claims["ver"]:
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

    @app.get("/console")
    def console():
        return render_template("console.html")

    @app.get("/health")
    def health(): return jsonify(status="ok", service="cybersecai-api", timestamp=utc_now())

    @app.post("/api/v1/auth/bootstrap")
    def bootstrap():
        bootstrap_secret = os.environ.get("CYBERSECAI_BOOTSTRAP_TOKEN", "")
        supplied_secret = request.headers.get("X-Bootstrap-Token", "")
        if len(bootstrap_secret) < 32 or not hmac.compare_digest(bootstrap_secret, supplied_secret):
            return jsonify(error="bootstrap_not_authorized"), 403
        payload = payload_object()
        if payload is None: return jsonify(error="invalid_json"), 400
        username = text_field(payload, "username", 64)
        password = payload.get("password")
        if not username or not username.replace("_", "").replace("-", "").isalnum(): return jsonify(error="invalid_username"), 400
        if not isinstance(password, str) or not 14 <= len(password) <= 256: return jsonify(error="weak_password"), 400
        connection = db()
        try:
            connection.execute("BEGIN IMMEDIATE" if not DATABASE_URL else "BEGIN")
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
        client_ip = request.remote_addr or "unknown"
        throttle_key = hashlib.sha256((username.casefold() + "|" + client_ip).encode()).hexdigest()
        now = time.time()
        throttle = db().execute(
            "SELECT failures,window_started,blocked_until FROM auth_throttle WHERE bucket_key=?",
            (throttle_key,),
        ).fetchone()
        if throttle and throttle["blocked_until"] > now:
            retry_after = max(1, int(throttle["blocked_until"] - now))
            response = jsonify(error="too_many_attempts", retry_after_seconds=retry_after)
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            return response

        user = db().execute("SELECT id,username,password_hash,role,token_version FROM users WHERE username=?", (username,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            if not throttle or now - throttle["window_started"] >= 900:
                failures, window_started = 1, now
            else:
                failures, window_started = throttle["failures"] + 1, throttle["window_started"]
            blocked_until = now + 900 if failures >= 5 else 0
            db().execute(
                "INSERT INTO auth_throttle(bucket_key,failures,window_started,blocked_until) VALUES(?,?,?,?) "
                "ON CONFLICT(bucket_key) DO UPDATE SET failures=excluded.failures, "
                "window_started=excluded.window_started, blocked_until=excluded.blocked_until",
                (throttle_key, failures, window_started, blocked_until),
            )
            db().commit()
            return jsonify(error="invalid_credentials"), 401
        db().execute("DELETE FROM auth_throttle WHERE bucket_key=?", (throttle_key,))
        audit(db(), user["id"], "auth.login", "user", str(user["id"]))
        db().commit()
        return jsonify(access_token=issue_token(user), token_type="Bearer", expires_in=TOKEN_TTL_SECONDS,
                       user={"id": user["id"], "username": user["username"], "role": user["role"]})

    @app.get("/api/v1/auth/me")
    @authenticated
    def me(): return jsonify(id=g.user["id"], username=g.user["username"], role=g.user["role"])

    @app.post("/api/v1/auth/password")
    @authenticated
    def change_password():
        payload = payload_object()
        if payload is None:
            return jsonify(error="invalid_json"), 400
        current_password, new_password = payload.get("current_password"), payload.get("new_password")
        if not isinstance(current_password, str) or not isinstance(new_password, str):
            return jsonify(error="invalid_password_fields"), 400
        if not 14 <= len(new_password) <= 256:
            return jsonify(error="weak_password"), 400
        user = db().execute("SELECT id,password_hash FROM users WHERE id=?", (g.user["id"],)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], current_password):
            return jsonify(error="invalid_credentials"), 401
        db().execute("UPDATE users SET password_hash=?,token_version=token_version+1 WHERE id=?",
                     (generate_password_hash(new_password), g.user["id"]))
        audit(db(), g.user["id"], "auth.password_changed", "user", str(g.user["id"]))
        db().commit()
        return jsonify(message="Password changed. Sign in again; existing sessions have been invalidated."), 200

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

    @app.post("/api/v1/analyze")
    @roles("admin", "analyst")
    def analyze_logs():
        """Apply transparent defensive rules to user-supplied, authorized log text."""
        import re
        payload = payload_object()
        if payload is None:
            return jsonify(error="invalid_json"), 400
        logs = payload.get("logs")
        if not isinstance(logs, str) or not logs.strip():
            return jsonify(error="invalid_logs"), 400
        if len(logs) > 100_000:
            return jsonify(error="logs_too_large", max_characters=100000), 413
        rules = [
            ("AUTH-001", "high", re.compile(r"(?i)(failed password|authentication failure|invalid user|login failed)"),
             "Authentication failure indicator", "Repeated matches can indicate password guessing; validate against normal operational activity."),
            ("PRIV-001", "high", re.compile(r"(?i)(sudo:.*COMMAND=|privilege escalation|elevation attempt)"),
             "Privileged command indicator", "Review the actor, command, host, and approved change records."),
            ("SCRIPT-001", "medium", re.compile(r"(?i)(encodedcommand|frombase64string|powershell.{0,30}-enc\b)"),
             "Encoded script indicator", "Encoded script use can be legitimate; inspect execution context and parent process."),
            ("WEB-001", "medium", re.compile(r"(?i)(union\s+select|<script[ >]|\.\./\.\./|%2e%2e%2f)"),
             "Potential web attack string", "Treat this as a heuristic match, not proof of exploitation."),
            ("NET-001", "medium", re.compile(r"(?i)(port scan|too many connection attempts|connection refused.*repeated)"),
             "Network probing indicator", "Correlate source, destination, frequency, and authorized testing windows."),
        ]
        findings = []
        for line_number, line in enumerate(logs.splitlines()[:2000], start=1):
            if len(line) > 4000:
                line = line[:4000]
            for rule_id, severity, pattern, title, guidance in rules:
                if pattern.search(line):
                    findings.append({"rule_id": rule_id, "severity": severity, "title": title,
                                     "line": line_number, "evidence": line[:500], "guidance": guidance})
                    if len(findings) >= 200:
                        break
            if len(findings) >= 200:
                break
        counts = {level: sum(1 for item in findings if item["severity"] == level)
                  for level in ("high", "medium", "low", "informational")}
        return jsonify(engine="cybersecai-rule-based-v1", mode="heuristic",
                       disclaimer="Heuristic indicators only; not proof of compromise and not AI-generated.",
                       lines_processed=min(len(logs.splitlines()), 2000), findings=findings,
                       finding_count=len(findings), severity_counts=counts), 200

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
