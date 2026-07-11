# Authentication and Authorization Service — 30-Task Execution Plan

Complete tasks in order unless a dependency is explicitly removed. Each day has 10 active tasks; unfinished work rolls forward before later tasks begin. Keep at most 10 task checkboxes marked `[~]` (in progress) at once; use `[x]` only after verification.

## Day 1 — Foundation and first vertical slice (Tasks 1–10)

- [ ] 1. Design workspace, Docker, CI, key strategy, threat model, and API contracts; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 2. Implement workspace, Docker, CI, key strategy, threat model, and API contracts; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 3. Verify workspace, Docker, CI, key strategy, threat model, and API contracts with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 4. Design user/credential schema, password hashing, signup, verification, and login; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 5. Implement user/credential schema, password hashing, signup, verification, and login; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 6. Verify user/credential schema, password hashing, signup, verification, and login with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 7. Design JWT signing, refresh rotation, reuse detection, sessions, and logout; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 8. Implement JWT signing, refresh rotation, reuse detection, sessions, and logout; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 9. Verify JWT signing, refresh rotation, reuse detection, sessions, and logout with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 10. Design OAuth provider adapters, account linking, callback safety, and hosted UI; write acceptance criteria, contracts, risks, and the smallest vertical slice.

## Day 2 — Core workflows and integrations (Tasks 11–20)

- [ ] 11. Implement OAuth provider adapters, account linking, callback safety, and hosted UI; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 12. Verify OAuth provider adapters, account linking, callback safety, and hosted UI with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 13. Design TOTP MFA, recovery codes, step-up auth, and reset workflow; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 14. Implement TOTP MFA, recovery codes, step-up auth, and reset workflow; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 15. Verify TOTP MFA, recovery codes, step-up auth, and reset workflow with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 16. Design organizations, invitations, RBAC evaluator, and tenant isolation; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 17. Implement organizations, invitations, RBAC evaluator, and tenant isolation; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 18. Verify organizations, invitations, RBAC evaluator, and tenant isolation with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 19. Design API keys, scopes, hashing, rotation, usage records, and middleware SDK; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 20. Implement API keys, scopes, hashing, rotation, usage records, and middleware SDK; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.

## Day 3 — Advanced behavior and production hardening (Tasks 21–30)

- [ ] 21. Verify API keys, scopes, hashing, rotation, usage records, and middleware SDK with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 22. Design device history, suspicious-login rules, alerts, audit logs, and webhooks; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 23. Implement device history, suspicious-login rules, alerts, audit logs, and webhooks; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 24. Verify device history, suspicious-login rules, alerts, audit logs, and webhooks with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 25. Design admin console, GraphQL queries, rate limits, metrics, and key rotation; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 26. Implement admin console, GraphQL queries, rate limits, metrics, and key rotation; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 27. Verify admin console, GraphQL queries, rate limits, metrics, and key rotation with tests, failure cases, telemetry, documentation, and a reviewable demo.
- [ ] 28. Design security/integration/E2E tests, client examples, OpenAPI docs, and deployment runbook; write acceptance criteria, contracts, risks, and the smallest vertical slice.
- [ ] 29. Implement security/integration/E2E tests, client examples, OpenAPI docs, and deployment runbook; keep frontend, API, domain logic, workers, and persistence in their declared boundaries.
- [ ] 30. Verify security/integration/E2E tests, client examples, OpenAPI docs, and deployment runbook with tests, failure cases, telemetry, documentation, and a reviewable demo.

## Task completion checklist

A task is complete only when code is formatted and typed, tests pass, migrations are reproducible, UI states are handled, authorization is enforced, logs contain no secrets, and relevant docs are updated. Track blockers beneath the task instead of silently widening scope.

