import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  base32Encode,
  decryptSecret,
  encryptSecret,
  hashPassword,
  signAccessToken,
  totp,
  verifyAccessToken,
  verifyPassword,
  verifyTotp,
} from "../src/crypto.js";
import {
  deliveryTransition,
  roleAllows,
} from "../src/modules/authorization.js";
import { RateLimiter } from "../src/rate-limit.js";

describe("identity cryptography", () => {
  it("hashes passwords and encrypts MFA secrets", async () => {
    const hash = await hashPassword("StrongPassword9", "pepper");
    expect(await verifyPassword("StrongPassword9", hash, "pepper")).toBe(true);
    expect(await verifyPassword("WrongPassword9", hash, "pepper")).toBe(false);
    const sealed = encryptSecret("MFA-SECRET", "encryption-key");
    expect(decryptSecret(sealed, "encryption-key")).toBe("MFA-SECRET");
  });
  it("signs and verifies Ed25519 access tokens", () => {
    const keys = generateKeyPairSync("ed25519");
    const privateKey = keys.privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    const publicKey = keys.publicKey
      .export({ type: "spki", format: "pem" })
      .toString();
    const token = signAccessToken(
      {
        sub: "user",
        sid: "session",
        iat: 1,
        exp: 4_000_000_000,
        iss: "identity-service",
      },
      privateKey,
    );
    expect(verifyAccessToken(token, publicKey)?.sub).toBe("user");
    expect(verifyAccessToken(`${token}x`, publicKey)).toBeNull();
  });
  it("generates valid time-based codes", () => {
    const secret = base32Encode(Buffer.from("12345678901234567890"));
    expect(
      verifyTotp(secret, totp(secret, 1_700_000_000_000), 1_700_000_000_000),
    ).toBe(true);
  });
});
describe("authorization controls", () => {
  it("applies organization roles", () => {
    expect(roleAllows("OWNER", "key:write")).toBe(true);
    expect(roleAllows("MEMBER", "key:write")).toBe(false);
  });
  it("rate limits repeated requests", () => {
    const limiter = new RateLimiter(1, 1000, () => 1);
    limiter.consume("login");
    expect(() => limiter.consume("login")).toThrow("Request rate exceeded");
  });
  it("backs off webhook failures and dead-letters the fifth", () => {
    expect(deliveryTransition(false, 1)).toEqual({
      status: "FAILED",
      delayMs: 60_000,
    });
    expect(deliveryTransition(false, 5)).toEqual({
      status: "DEAD_LETTER",
      delayMs: 0,
    });
    expect(deliveryTransition(true, 2).status).toBe("DELIVERED");
  });
});
