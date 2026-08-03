import { createPublicKey, generateKeyPairSync, randomUUID } from "node:crypto";
import { createApp } from "../apps/api/src/app.js";
import { totp } from "../apps/api/src/crypto.js";
import { prisma } from "../apps/api/src/db.js";
import { Metrics } from "../apps/api/src/metrics.js";
import { AuthorizationService } from "../apps/api/src/modules/authorization.js";
import { IdentityService } from "../apps/api/src/modules/identity.js";

const pair = generateKeyPairSync("ed25519");
const privateKeyPem = pair.privateKey
  .export({ type: "pkcs8", format: "pem" })
  .toString();
const publicKeyPem = pair.publicKey
  .export({ type: "spki", format: "pem" })
  .toString();
const suffix = randomUUID();
const ownerEmail = `owner-${suffix}@example.invalid`;
const memberEmail = `member-${suffix}@example.invalid`;
const oauthEmail = `oauth-${suffix}@example.invalid`;
const metrics = new Metrics();
const identity = new IdentityService(
  {
    passwordPepper: "password-pepper-at-least-32-characters",
    tokenPepper: "token-pepper-at-least-32-characters",
    mfaKey: "mfa-encryption-key-at-least-32-characters",
    privateKeyPem,
    publicKeyPem,
  },
  metrics,
);
const authorization = new AuthorizationService(
  {
    tokenPepper: "token-pepper-at-least-32-characters",
    encryptionKey: "mfa-encryption-key-at-least-32-characters",
    webhookSigningSecret: "webhook-signing-secret-at-least-32-characters",
  },
  metrics,
);
const app = createApp({
  metrics,
  operatorToken: "operator",
  identity,
  authorization,
  publicKeyPem,
});
const call = async (
  path: string,
  method = "POST",
  body?: unknown,
  token?: string,
) => {
  const response = await app.request(`http://e2e.local/v1${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok)
    throw new Error(
      `${method} ${path}: ${response.status} ${await response.text()}`,
    );
  return response;
};
const register = async (
  email: string,
  displayName: string,
  deviceId: string,
) => {
  const signup = (await (
    await call("/signup", "POST", {
      email,
      displayName,
      password: "StrongPassword9",
    })
  ).json()) as { verificationToken: string };
  await call("/verify-email", "POST", { token: signup.verificationToken });
  return (await (
    await call("/login", "POST", {
      email,
      password: "StrongPassword9",
      deviceId,
      ip: "127.0.0.1",
      country: "IN",
    })
  ).json()) as { accessToken: string; refreshToken: string; sessionId: string };
};
let organizationId: string | undefined;
try {
  const owner = await register(ownerEmail, "E2E Owner", "owner-device-001");
  await prisma.user.update({
    where: { email: ownerEmail },
    data: { platformAdmin: true },
  });
  const jwks = await app.request("http://e2e.local/.well-known/jwks.json");
  if (!jwks.ok || !((await jwks.json()) as { keys: unknown[] }).keys.length)
    throw new Error("root JWKS was not published");
  await call(
    "/admin/signing-keys/rotate",
    "POST",
    {
      kid: `e2e-${suffix}`,
      publicJwk: createPublicKey(publicKeyPem).export({ format: "jwk" }),
    },
    owner.accessToken,
  );
  const organization = (await (
    await call(
      "/organizations",
      "POST",
      { name: "E2E Organization", slug: `e2e-${suffix}` },
      owner.accessToken,
    )
  ).json()) as { id: string };
  organizationId = organization.id;
  const member = await register(memberEmail, "E2E Member", "member-device-01");
  const invitation = (await (
    await call(
      `/organizations/${organization.id}/invitations`,
      "POST",
      { email: memberEmail, role: "MEMBER", expiresInDays: 7 },
      owner.accessToken,
    )
  ).json()) as { token: string };
  await call(
    "/invitations/accept",
    "POST",
    { token: invitation.token },
    member.accessToken,
  );
  const policy = (await (
    await call(
      `/organizations/${organization.id}/policy/evaluate`,
      "POST",
      { permission: "key:write" },
      member.accessToken,
    )
  ).json()) as { allowed: boolean };
  if (policy.allowed) throw new Error("member received owner permission");
  const keyResponse = (await (
    await call(
      `/organizations/${organization.id}/api-keys`,
      "POST",
      { name: "E2E SDK", scopes: ["identity:read"] },
      owner.accessToken,
    )
  ).json()) as { token: string };
  await call("/sdk/whoami", "GET", undefined, keyResponse.token);
  await call(
    `/organizations/${organization.id}/webhooks`,
    "POST",
    { url: "https://example.invalid/security", events: ["security.test"] },
    owner.accessToken,
  );
  const delivery = (await (
    await call(
      `/organizations/${organization.id}/events/test`,
      "POST",
      {},
      owner.accessToken,
    )
  ).json()) as { queued: number };
  if (delivery.queued !== 1) throw new Error("webhook delivery was not queued");
  const oauth = (await (
    await call("/oauth/start", "POST", {
      provider: "github",
      redirectUri: "https://app.example.invalid/callback",
    })
  ).json()) as { state: string; codeVerifier: string };
  await call("/oauth/callback", "POST", {
    state: oauth.state,
    codeVerifier: oauth.codeVerifier,
    code: "synthetic-code",
    providerSubject: `github-${suffix}`,
    email: oauthEmail,
    displayName: "OAuth User",
  });
  const enrollment = (await (
    await call("/mfa/enroll", "POST", {}, owner.accessToken)
  ).json()) as { factorId: string; secret: string };
  await call(
    `/mfa/${enrollment.factorId}/confirm`,
    "POST",
    { code: totp(enrollment.secret) },
    owner.accessToken,
  );
  const mfaLogin = (await (
    await call("/login", "POST", {
      email: ownerEmail,
      password: "StrongPassword9",
      deviceId: "owner-device-002",
      ip: "127.0.0.2",
      country: "US",
    })
  ).json()) as { mfaRequired: boolean; challengeToken: string };
  if (!mfaLogin.mfaRequired) throw new Error("MFA was not required");
  const steppedUp = (await (
    await call("/mfa/verify", "POST", {
      challengeToken: mfaLogin.challengeToken,
      code: totp(enrollment.secret),
    })
  ).json()) as { accessToken: string; refreshToken: string };
  await call(
    "/query",
    "POST",
    { resource: "sessions", limit: 10 },
    steppedUp.accessToken,
  );
  const rotated = (await (
    await call("/refresh", "POST", { refreshToken: steppedUp.refreshToken })
  ).json()) as { refreshToken: string };
  if (rotated.refreshToken === steppedUp.refreshToken)
    throw new Error("refresh token did not rotate");
  const reuse = await app.request("http://e2e.local/v1/refresh", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": "reuse-test",
    },
    body: JSON.stringify({ refreshToken: steppedUp.refreshToken }),
  });
  if (
    reuse.status !== 401 ||
    !((await reuse.json()) as { error: { code: string } }).error.code.includes(
      "REUSE",
    )
  )
    throw new Error("refresh reuse was not detected");
  const reset = (await (
    await call("/password-reset/request", "POST", { email: memberEmail })
  ).json()) as { resetToken: string };
  await call("/password-reset/confirm", "POST", {
    token: reset.resetToken,
    password: "NewStrongPassword8",
  });
  console.info("Identity service E2E passed");
} finally {
  if (organizationId)
    await prisma.organization.delete({ where: { id: organizationId } });
  await prisma.user.deleteMany({
    where: { email: { in: [ownerEmail, memberEmail, oauthEmail] } },
  });
  await prisma.oAuthState.deleteMany({
    where: { redirectUri: "https://app.example.invalid/callback" },
  });
  await prisma.$disconnect();
}
