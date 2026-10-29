# Security Policy

## Current posture
CyberSecAI is an evolving security-operations project. The browser dashboard is a demonstration; the API provides authenticated security-event triage and audit records. It is not a complete SIEM, autonomous response system, or substitute for independent security assessment.

## Reporting
Use GitHub private vulnerability reporting if enabled, or contact the maintainer privately. Do not publish secrets, personal information, exploit chains, or third-party logs in public issues.

## Implemented controls
- Password hashing with Werkzeug.
- One-time first-administrator bootstrap, closed after an account exists.
- HMAC-signed expiring bearer tokens; secret supplied by environment configuration.
- Role checks for event modification and administrator-only audit access.
- SQL parameterization, input bounds, JSON validation, pagination and request-size limits.
- Audit records for bootstrap, successful login, event creation and status changes.
- Container runs as a non-root user.

## Required before production use
- Use a managed durable database with tested backups and restore. SQLite is the local default and is not recommended for shared multi-instance production.
- Configure TLS, network restrictions, secrets management, and edge-level rate limiting.
- Add login throttling and abuse monitoring; per-process throttling is not sufficient across workers.
- Add password reset, account administration, token revocation, MFA and tenant isolation before serving multiple organizations.
- Add log retention/deletion policies and protect audit logs against tampering.
- Add dependency, container, SAST, DAST, accessibility and penetration testing.
- Verify deployment, database durability, backup restoration and incident procedures in the target environment.
- Obtain independent security and operational reviews.

## Safe use
Only analyze logs from systems you own or are authorized to assess. Do not submit credentials, API keys, unredacted personal data or confidential incident records to public demos. The project does not execute containment actions or scan third-party systems.
