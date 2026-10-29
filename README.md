# CyberSecAI — Security Operations Platform

CyberSecAI combines a browser-based SOC dashboard prototype with a Python API for authenticated security-event triage. The API supports event creation, filtering, status tracking, role-aware access and audit records.

> **Honest status:** This is an actively developed foundation, not a production-certified SOC or SIEM. The dashboard's original metrics and terminal output remain illustrative. The API does not currently connect to live SIEM telemetry, provide AI inference, run vulnerability scans, or perform automated containment. CI success is not production certification.

## Capabilities
- Password-hashed accounts and one-time first-admin bootstrap.
- Expiring HMAC-signed bearer tokens and role checks (admin, analyst, viewer).
- Security-event creation, filtering, pagination and status updates.
- Administrator-only audit endpoint.
- Request-size limits, input validation, parameterized SQL and non-root container.
- Automated API and HTML integrity tests.
- Local development and a free-tier Render blueprint for evaluation.

## Run locally
Requires Python 3.12 or newer.

    git clone https://github.com/yobi369/cybersecAI.git
    cd cybersecAI
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    export CYBERSECAI_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
    export CYBERSECAI_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)
    python -m unittest discover -s tests -v
    gunicorn --workers 2 --bind 127.0.0.1:8000 app:app

Health endpoint: http://127.0.0.1:8000/health. Analyst console: http://127.0.0.1:8000/console.

## Bootstrap the first administrator
The endpoint requires the CYBERSECAI_BOOTSTRAP_TOKEN environment secret in the X-Bootstrap-Token header and closes once a user exists. Keep this secret private and rotate it after setup.

    curl -X POST http://127.0.0.1:8000/api/v1/auth/bootstrap -H 'Content-Type: application/json' -H "X-Bootstrap-Token: $CYBERSECAI_BOOTSTRAP_TOKEN" -d '{"username":"security_admin","password":"replace-with-a-long-unique-password"}'

Log in at POST /api/v1/auth/login with JSON username and password. Use the returned token in the Authorization header as Bearer token.

## API overview
| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | /health | Public | Health check |
| POST | /api/v1/auth/bootstrap | Public, one-time | Create initial administrator |
| POST | /api/v1/auth/login | Public | Obtain expiring token |
| GET | /api/v1/auth/me | Authenticated | Current account |
| GET | /api/v1/events | Authenticated | Filter/list events |
| POST | /api/v1/events | Admin, analyst | Create event |
| PATCH | /api/v1/events/{id} | Admin, analyst | Change event status |
| POST | /api/v1/analyze | Admin, analyst | Run transparent heuristic checks on supplied log text |
| GET | /api/v1/audit | Admin | Read audit records |

Severity values: informational, low, medium, high, critical. Status values: open, investigating, resolved, false_positive. The log-analysis endpoint uses transparent heuristic patterns, caps input size, and returns evidence with guidance. It is not an AI model, does not prove compromise, and may produce false positives or miss threats.

## Deployment
A Render blueprint and Dockerfile are provided. **Do not use default SQLite storage for production.** The blueprint is a low-cost evaluation starting point, not a complete production configuration. Free web services may sleep and local filesystem data may be ephemeral. Before operational use, migrate to a durable managed PostgreSQL database, configure network and TLS controls, add shared rate limiting, and test backup/restore.

Read SECURITY.md before deploying. Do not ingest unredacted logs or secrets. Independent security and operational reviews remain required before production use.

## License
No license is currently specified. Reuse and redistribution permissions are not granted unless a license is added.
