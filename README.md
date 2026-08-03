# Aegis Identity & Access Service

A reusable identity boundary with a hosted login, security console, Hono API, Go policy core, Prisma/PostgreSQL persistence, Redis-ready rate limiting, and a typed TypeScript SDK.

## Capabilities

- Verified email/password accounts with parameterized scrypt hashes and a server-side pepper
- 15-minute Ed25519 JWTs, 30-day rotating refresh families, reuse detection, and session revocation
- Google/GitHub OAuth adapter contract with one-time state and S256 PKCE
- RFC 6238 TOTP, encrypted factors, single-use recovery codes, and risk-based step-up
- Organizations, invitations, tenant-scoped RBAC, hashed scoped API keys, usage records, and audit events
- Suspicious-login signals, structured logs, protected Prometheus metrics, signed webhook queues with backoff/DLQ, and staged signing-key rotation
- Responsive Next.js hosted auth and operator console, versioned contracts, OpenAPI, and SDK

## Run locally

Requirements: Node 24+, Go 1.25+, and Docker.

```bash
cp .env.example .env
docker compose up -d postgres redis identity-core
npm ci
npm run db:generate
npm run db:migrate
npm run dev:api
```

In another terminal run `npm run dev`, then open `http://localhost:3000` or `/admin`. Generate Ed25519 PEM values with `openssl genpkey -algorithm ED25519` and `openssl pkey -pubout`; store production keys in a managed secret store, never Git.

## Verification

```bash
npm run check
DATABASE_URL=postgresql://identity:identity@localhost:5491/identity?schema=public npm run e2e
npm run build
docker compose config --quiet
```

See [architecture](docs/architecture.md), [threat model](docs/security.md), [API contract](docs/openapi.yaml), [operations runbook](docs/runbook.md), and [demo](docs/demo.md).

## Repository boundaries

`apps/web` contains UI only; `apps/api` owns transport/application orchestration; `packages/contracts` and `packages/sdk` are client-safe; `services/identity` is an independently runnable Go policy/risk core; `prisma` owns transactional data and reproducible migrations. MongoDB and Gemini are intentionally absent because this service has no document/AI workload that justifies them.
