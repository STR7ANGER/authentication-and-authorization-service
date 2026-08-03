# Deployment and operations runbook

## Deployment topology

Deploy `apps/web` as one Vercel project and the Hono API image as a long-lived container service. Use a Neon pooled `DATABASE_URL` for API traffic and a direct connection for Prisma migrations. Neon documents that pooled endpoints use PgBouncer transaction mode, so do not rely on session-level database state. Redis must be a durable managed deployment for shared limits and webhook work.

References: [Vercel monorepos](https://vercel.com/docs/monorepos), [Neon connection pooling](https://neon.com/docs/connect/connection-pooling), [Redis rate limiter pattern](https://redis.io/docs/latest/develop/use-cases/rate-limiter/).

## Release

1. Create a backup/restore point and a Neon branch from production.
2. Run `npm ci && npm run db:generate && npm run check && npm run build`.
3. Run `npx prisma migrate deploy` against the preview branch, then `npm run e2e` with disposable fixtures.
4. Build/scan both Docker images, deploy the API, and verify `/health`, root JWKS and protected `/internal/metrics`.
5. Deploy the web project with `WEB_URL` matching the exact origin. Smoke-test signup, verification delivery, login, refresh, MFA and tenant denial.
6. Promote the migration and application. Watch 4xx/5xx, p95 duration, login failures, refresh reuse, webhook DLQ and database saturation.

Required secrets: database/Redis URLs, two independent peppers, MFA/webhook encryption key, Ed25519 PEM pair, metrics bearer token and webhook signing secret. Generate at least 32 random bytes for symmetric values. Never use `.env.example` values.

## Alerts and SLOs

- Availability target: 99.9%; interactive p95 under 500 ms excluding downstream OAuth/email.
- Page immediately on sustained 5xx >2%, refresh-reuse spike, signing failures or database unavailability.
- Ticket on MFA failure spike, webhook dead letters, rate-limit saturation or p95 >500 ms for 15 minutes.
- Security logs retained per customer policy; delete raw IP/device values because only SHA-256 context hashes are needed here.

## Failure recovery

- **Bad migration:** stop rollout; restore the branch/backup. Migrations are forward-only in production—write a compensating migration rather than editing applied SQL.
- **Signing incident:** disable login issuance, restore prior KMS secret/JWKS, revoke affected sessions, rotate and notify per incident policy.
- **Refresh replay:** family/session revocation is automatic; investigate the critical security event and prompt reauthentication.
- **Redis unavailable:** keep authorization on PostgreSQL, reduce replica count or enable gateway limits, and pause webhook dispatch to avoid duplicate storms.
- **Webhook target failing:** retry at 1/2/4/8 minutes then dead-letter on attempt five; operators inspect and replay only after target recovery.
- **Database unavailable:** fail closed for authentication/authorization. Do not accept credentials into an in-memory fallback.

## Backup and retention

Test database restore quarterly. Retain audit/security events according to tenant policy, normally 90–365 days; prune expired verification/reset/OAuth states and used refresh records daily. User deletion must revoke sessions/keys and cascade account-owned records while preserving legally required, pseudonymized audit evidence.

## Rollback

Application images are immutable and can roll back independently when schema compatibility is preserved. Keep additive fields nullable/defaulted for one release, deploy readers before writers, and remove old fields only after rollback windows close.
