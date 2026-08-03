# Architecture and decisions

## Runtime view

```text
Browser / SDK
   | HTTPS
Next.js hosted UI ---- Hono API gateway ---- PostgreSQL (Prisma)
                              |       |
                              |       +---- Redis boundary (distributed limits/jobs)
                              +------------ Go identity core (policy/risk)
```

The implementation is a modular service: MVC-shaped routes call application services, which enforce domain rules before repositories. Frontend and backend deploy independently and share only versioned schemas. PostgreSQL is authoritative; Redis failure may reduce distributed throttling/job throughput but never grants access.

## ADR-001: asymmetric access tokens

Ed25519 keeps signing private and verification distributable through `/.well-known/jwks.json`. Access tokens expire after 15 minutes. Stateful session checks provide immediate disable/revoke behavior; rotating opaque refresh tokens expire after 30 days. Reuse revokes the entire family and session.

## ADR-002: command and query surfaces

REST endpoints represent security commands. `POST /v1/query` is the experimental **Query Request** surface: a typed discriminated request that supports composed reads without putting sensitive filters in URLs. It is deliberately narrower than arbitrary GraphQL to preserve predictable authorization and query cost. The admin console uses this read model.

## ADR-003: service extraction

The Go core demonstrates an independently scalable boundary for password policy, risk evaluation, and refresh-family state. The TypeScript API remains the transaction coordinator until operational evidence warrants further extraction. The webhook dispatcher can become a worker without changing its persisted delivery contract.

## Data invariants

- Emails and organization slugs are unique.
- Membership identity is `(organizationId, userId)`; every tenant read is filtered through membership authorization.
- Only hashes of verification, reset, invitation, refresh, and API-key tokens are stored.
- MFA and webhook secrets use AES-256-GCM authenticated encryption.
- API keys are shown only once, scoped, revocable, and recorded on use.
- Webhook event/endpoint pairs are unique, retried exponentially, and dead-lettered after five failures.

## Acceptance map

Tasks 1–9: workspace, credentials, JWT/session core and automated security tests. Tasks 10–18: OAuth PKCE, hosted UI, MFA, organizations/RBAC and database E2E. Tasks 19–24: SDK/API keys, suspicious logins, audit and webhooks. Tasks 25–30: console, Query Request, limits/metrics/key staging, OpenAPI, deployment and clean-environment gates.
