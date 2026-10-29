# Security Policy

## Current posture
CyberSecAI is an evolving security-operations project. The browser dashboard is a demonstration; the API provides authenticated security-event triage and audit records. It is not a complete SIEM, autonomous response system, or substitute for independent security assessment.

## Reporting
Use GitHub private vulnerability reporting if enabled, or contact the maintainer privately. Do not publish secrets, personal information, exploit chains, or third-party logs in public issues.

## Implemented controls
- Password hashing with Werkzeug.
- One-time first-administrator bootstrap requiring a separate environment secret, closed after an account exists.
- HMAC-signed expiring bearer tokens; secret supplied by environment configuration.
- Role checks for event modification and administrator-only audit access.
- SQL parameterization, input bounds, JSON validation, pagination and request-size limits.
- Baseline browser security headers and no-store cache policy on authentication routes.
- Database-backed login throttling: five failed attempts per username/IP bucket trigger a 15-minute lockout. Edge-level abuse controls are still required.
- PostgreSQL adapter selected through `DATABASE_URL`; SQLite remains the local-development default.
- Audit records for bootstrap, successful login, event creation and status changes.
- Container runs as a non-root user.

## Required before production use
- Configure a durable PostgreSQL `DATABASE_URL` with provider-enforced TLS, least-privilege credentials, connection limits, tested backups and restore. PostgreSQL adapter code is present but has not yet been verified against a live PostgreSQL service. SQLite remains the local default and is not recommended for shared multi-instance production.
- Configure TLS, network restrictions, secrets management, and edge-level rate limiting.
- Add edge-level rate limiting and abuse monitoring; application login throttling does not protect every endpoint or replace perimeter controls.
- Add password reset, account administration, token revocation, MFA and tenant isolation before serving multiple organizations.
- Add log retention/deletion policies and protect audit logs against tampering.
- Add dependency, container, SAST, DAST, accessibility and penetration testing.
- Verify deployment, database durability, backup restoration and incident procedures in the target environment.
- Obtain independent security and operational reviews.

## Safe use
Only analyze logs from systems you own or are authorized to assess. Do not submit credentials, API keys, unredacted personal data or confidential incident records to public demos. The project does not execute containment actions or scan third-party systems.
