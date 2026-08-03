# Threat model and security review

## Assets and trust boundaries

Credentials, peppers, private signing keys, MFA seeds, refresh tokens, API keys, tenant membership and audit trails are critical assets. Untrusted boundaries are browser input, OAuth callbacks, bearer tokens, webhook targets, proxy headers and organization identifiers. Database administrators and platform operators are privileged roles and require separate production access controls.

## Threats and controls

| Threat | Control | Residual/operational action |
|---|---|---|
| Credential database theft | scrypt `N=2^15,r=8,p=3`, random salt, separate pepper | Benchmark on production hardware; rotate pepper through a forced credential reset |
| Password guessing | non-enumerating reset, consistent credential error, sensitive-route limits | Put a distributed Redis limiter/WAF in front of horizontally scaled API replicas |
| Refresh theft/replay | hashed opaque tokens, one-time rotation, family reuse revocation, critical event | Alert on `refresh_reuse_total` |
| JWT forgery/key exposure | Ed25519, public JWKS, short expiry, platform-admin staged rotation | Keep private keys in KMS/secret manager; overlap old public keys during rollout |
| OAuth injection/CSRF | one-time state, exact redirect contract, S256 PKCE verifier binding, 10-minute expiry | Provider adapters must verify issuer, audience, nonce and provider token response |
| MFA database theft/replay | AES-GCM encrypted seed, ±1 time window, single-use recovery codes | Production should rate-limit per factor/user and support operator recovery evidence |
| Tenant data access | centralized membership lookup, permission matrix, organization-filtered queries | Add database RLS before supporting customer-supplied SQL/reporting |
| API-key leakage | hash at rest, prefix lookup, least scopes, show once, revocation and usage logs | Rotate keys and redact Authorization headers at every proxy |
| Webhook SSRF/tamper | HTTPS-only schema, encrypted endpoint secret, HMAC envelope, durable retry/DLQ | Production dispatcher must block private/link-local destinations and enforce timeouts |
| Log/metric disclosure | structured metadata only, no bodies/tokens, operator-protected metrics | Central sink must apply retention and role restrictions |

The scrypt settings use one of OWASP's documented equivalent configurations; OWASP prefers Argon2id when available and permits scrypt alternatives. OAuth uses transaction-specific S256 PKCE in line with the current OAuth Security BCP. TOTP uses 30-second RFC 6238 steps.

Primary references: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [RFC 9700 OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html), [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 6238 TOTP](https://www.rfc-editor.org/rfc/rfc6238.html).

## Key rotation ceremony

1. Generate a new Ed25519 pair in the managed key system and back up the prior public key.
2. As a platform admin, stage its public JWK through `POST /v1/admin/signing-keys/rotate`; audit/metrics record the event.
3. Deploy the matching private PEM and set its `kid`; publish both old and new public JWKs during the maximum access-token overlap.
4. Verify new signatures, wait at least 15 minutes plus clock skew, then retire the old public key.
5. If verification errors rise, restore the prior secret and JWKS set; never send private key material to the rotation endpoint.

## Review result and known gaps

No known critical/high issue remains in the implemented demonstration scope. Before real customer use: integrate provider token exchange/issuer validation, a managed mailer, external KMS, Redis-backed distributed limiter/worker, SSRF egress policy, OpenTelemetry traces, dependency/image scanning and third-party penetration testing. Development-only token responses must be disabled outside local/test environments.
