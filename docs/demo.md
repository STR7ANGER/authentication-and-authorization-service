# Demo script

1. Open `/` and verify the responsive hosted login, provider choices, labeled fields, keyboard focus and password reveal.
2. Open `/admin` and show identity posture, active sessions, MFA coverage, recent risk/audit events and operator controls.
3. Run the database E2E: it creates two verified users, proves tenant invitation/RBAC denial, creates and consumes a scoped API key, queues a signed webhook, completes OAuth with PKCE, enrolls TOTP, triggers risk step-up, rotates a refresh token, detects replay and resets a credential.
4. Query `/.well-known/jwks.json`, `/health`, and protected metrics. Show that logs include request IDs but never bodies or bearer values.
5. Run `go test ./...` in `services/identity` and explain the independently deployable policy/risk boundary.

Screenshots are stored in `docs/assets/hosted-login.jpg` and `docs/assets/security-console.jpg` after visual verification.
