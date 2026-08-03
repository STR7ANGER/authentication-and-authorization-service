import { z } from "zod";

const email = z.string().email().toLowerCase();
export const password = z
  .string()
  .min(12)
  .max(128)
  .refine(
    (value) => /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value),
    "Password must include upper, lower, and number.",
  );
export const signupInput = z.object({
  email,
  displayName: z.string().trim().min(2).max(100),
  password,
});
export const verificationInput = z.object({ token: z.string().min(32) });
export const loginInput = z.object({
  email,
  password,
  deviceId: z.string().min(8).max(200),
  ip: z.union([z.ipv4(), z.ipv6()]),
  country: z.string().length(2).toUpperCase(),
});
export const refreshInput = z.object({ refreshToken: z.string().min(32) });
export const logoutInput = z.object({
  refreshToken: z.string().min(32).optional(),
  allSessions: z.boolean().default(false),
});
export const resetRequestInput = z.object({ email });
export const resetConfirmInput = z.object({
  token: z.string().min(32),
  password,
});
export const oauthStartInput = z.object({
  provider: z.enum(["google", "github"]),
  redirectUri: z.string().url(),
  linkToUserId: z.string().cuid().optional(),
});
export const oauthCallbackInput = z.object({
  state: z.string().min(32),
  codeVerifier: z.string().min(43).max(128),
  code: z.string().min(4),
  providerSubject: z.string().min(2).max(200),
  email,
  displayName: z.string().trim().min(2).max(100),
});
export const signingKeyRotationInput = z.object({
  kid: z.string().regex(/^[a-zA-Z0-9._-]{3,80}$/),
  publicJwk: z
    .record(z.string(), z.unknown())
    .refine(
      (jwk) =>
        jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string",
      "An Ed25519 public JWK is required.",
    ),
});
export const mfaConfirmInput = z.object({ code: z.string().regex(/^\d{6}$/) });
export const mfaVerifyInput = z.object({
  challengeToken: z.string().min(32),
  code: z.string().min(6).max(64),
});
export const organizationInput = z.object({
  name: z.string().trim().min(2).max(100),
  slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
});
export const invitationInput = z.object({
  email,
  role: z.enum(["ADMIN", "MEMBER"]),
  expiresInDays: z.number().int().min(1).max(14).default(7),
});
export const invitationAcceptInput = z.object({ token: z.string().min(32) });
export const policyInput = z.object({
  permission: z.string().regex(/^[a-z]+:[a-z]+$/),
});
export const apiKeyInput = z.object({
  name: z.string().trim().min(2).max(80),
  scopes: z
    .array(z.string().regex(/^[a-z]+:[a-z]+$/))
    .min(1)
    .max(20),
});
export const webhookInput = z.object({
  url: z.string().url().startsWith("https://"),
  events: z.array(z.string().min(3).max(100)).min(1).max(30),
});
export const adminQuery = z.discriminatedUnion("resource", [
  z.object({
    resource: z.literal("sessions"),
    limit: z.number().int().min(1).max(100).default(25),
  }),
  z.object({
    resource: z.literal("members"),
    organizationId: z.string().cuid(),
    limit: z.number().int().min(1).max(100).default(25),
  }),
  z.object({
    resource: z.literal("securityEvents"),
    organizationId: z.string().cuid().optional(),
    limit: z.number().int().min(1).max(100).default(25),
  }),
  z.object({
    resource: z.literal("audit"),
    organizationId: z.string().cuid(),
    limit: z.number().int().min(1).max(100).default(25),
  }),
]);
