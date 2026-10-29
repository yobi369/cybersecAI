# Production Readiness Runbook

This checklist is intentionally provider-neutral. Completing code CI does not mean the service is production-ready. Record evidence for each item in the target environment before changing a deployment from evaluation to production.

## 1. Release gate

- [ ] Review the exact commit and pull request diff.
- [ ] Confirm the full CI workflow passes on the exact release commit: unit/integrity tests, PostgreSQL integration, Bandit, pip-audit, Docker build, health smoke test, and non-root assertion.
- [ ] Review dependency scan findings and resolve or explicitly document accepted risk.
- [ ] Run a human review of authentication, authorization, audit behavior, input handling, and data retention.
- [ ] Confirm the heuristic analyzer's limitations are clearly communicated to operators.

## 2. Required configuration

- [ ] Set `CYBERSECAI_SECRET_KEY` using a secret manager; use a unique, randomly generated value of at least 32 characters. Never commit it or reuse a CI/test secret.
- [ ] Set `CYBERSECAI_BOOTSTRAP_TOKEN` using a separate secret. Use it only for the initial administrator bootstrap, then remove/rotate the bootstrap secret after verifying the first admin account exists.
- [ ] Configure `DATABASE_URL` for managed PostgreSQL with TLS certificate verification, least-privilege database credentials, connection limits, and restricted network access.
- [ ] Configure a valid `TOKEN_TTL_SECONDS` value appropriate to the deployment's risk.
- [ ] Terminate HTTPS at a trusted ingress/load balancer. Configure trusted proxy behavior deliberately; do not trust arbitrary forwarded headers.
- [ ] Set edge-level rate limits for authentication and expensive endpoints, plus alerting for abuse.
- [ ] Ensure secrets and database credentials are never included in logs or error responses.

## 3. Database and recovery

- [ ] Verify migrations on an empty database and on a representative existing database snapshot.
- [ ] Confirm the application database role has only required permissions; separate migration/administrative credentials where supported.
- [ ] Configure encrypted backups and retention to match the service's data classification and recovery objectives.
- [ ] Perform a restore into an isolated environment; record duration, row counts, and checks of events, users, and audit records.
- [ ] Document recovery point objective (RPO), recovery time objective (RTO), owner, and escalation process.
- [ ] Confirm database records persist across application restarts and redeploys.

## 4. Identity and access

- [ ] Provision the first administrator securely and remove the bootstrap secret after use.
- [ ] Create individual accounts; never share administrator credentials.
- [ ] Deliver initial passwords through a separate secure channel and require each user to change the initial password after first sign-in (not yet enforced by the application).
- [ ] Before use with sensitive or multi-organization data, implement and verify MFA, verified password recovery, and tenant isolation as applicable.
- [ ] Verify disabled accounts and role changes revoke existing sessions.
- [ ] Review administrator access regularly and remove unused accounts.

## 5. Audit, monitoring, and privacy

- [ ] Define retention, deletion, and access rules for event and audit data.
- [ ] Restrict direct database access and ship important operational/security events to a separately controlled destination where appropriate.
- [ ] Test alerts for repeated login failures, application errors, database unavailability, and unusual account changes.
- [ ] Ensure logs and submitted samples are redacted; establish handling and deletion procedures for personal or confidential information.
- [ ] Document incident response, evidence preservation, and escalation procedures.

## 6. Live acceptance tests

Run only against the authorized staging/release environment with synthetic data.

- [ ] `GET /health` returns HTTP 200.
- [ ] `GET /console` and its static assets load with the strict Content Security Policy; no inline scripts or styles are required.
- [ ] Bootstrap succeeds only once with the configured bootstrap secret; remove that secret after initial setup.
- [ ] Valid login works; invalid login is generic; throttling returns HTTP 429 and `Retry-After`.
- [ ] Viewer cannot create or update events or administer users.
- [ ] Analyst can create/update permitted events but cannot administer users or read admin-only audit endpoints.
- [ ] Password change, role changes, and account disable invalidate existing sessions as expected.
- [ ] Event creation, filtering, pagination, and audit records work against PostgreSQL.
- [ ] Restart/redeploy does not lose persisted data.
- [ ] Restore a backup in isolation and verify representative records.
- [ ] Confirm browser security headers, HTTPS, edge rate limits, and absence of sensitive data in logs.
- [ ] Perform accessibility checks and independent security testing before real sensitive data is accepted.

## 7. Current known blockers

As of this checklist's creation, the project has automated CI coverage but has **not** been certified for production use. The following are not yet evidenced by a live target environment:

- A deployed service backed by configured, durable PostgreSQL with provider-verified TLS and least-privilege credentials.
- A successful hosted backup restore and disaster-recovery exercise.
- Edge/perimeter rate limiting, production alerting, and incident-response validation.
- MFA, verified password recovery, enforced first-login password change, and tenant isolation where required.
- Independent security/operational review and live accessibility/DAST/penetration testing.

Do not mark these complete based on local tests or CI alone.
