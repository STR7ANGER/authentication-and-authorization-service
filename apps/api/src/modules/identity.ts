import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  loginInput,
  mfaConfirmInput,
  mfaVerifyInput,
  oauthCallbackInput,
  oauthStartInput,
  refreshInput,
  resetConfirmInput,
  resetRequestInput,
  signingKeyRotationInput,
  signupInput,
  verificationInput,
} from "@identity/contracts";
import {
  base32Encode,
  decryptSecret,
  digest,
  encryptSecret,
  hashPassword,
  signAccessToken,
  verifyAccessToken,
  verifyPassword,
  verifyTotp,
} from "../crypto.js";
import { prisma } from "../db.js";
import { DomainError } from "../errors.js";
import type { Metrics } from "../metrics.js";

export type Principal = {
  userId: string;
  sessionId: string;
  platformAdmin: boolean;
};
type Secrets = {
  passwordPepper: string;
  tokenPepper: string;
  mfaKey: string;
  privateKeyPem: string;
  publicKeyPem: string;
};
const opaque = (prefix: string) =>
  `${prefix}_${randomBytes(32).toString("base64url")}`;
const hashContext = (value: string) =>
  createHash("sha256").update(value).digest("hex");

export class IdentityService {
  constructor(
    private secrets: Secrets,
    private metrics: Metrics,
  ) {}
  private accessToken(userId: string, sessionId: string) {
    const now = Math.floor(Date.now() / 1000);
    return signAccessToken(
      {
        sub: userId,
        sid: sessionId,
        iat: now,
        exp: now + 15 * 60,
        iss: "identity-service",
      },
      this.secrets.privateKeyPem,
    );
  }
  async signup(raw: unknown) {
    const input = signupInput.parse(raw);
    const existing = await prisma.user.findUnique({
      where: { email: input.email },
    });
    if (existing)
      throw new DomainError(
        "EMAIL_ALREADY_REGISTERED",
        409,
        "Email is already registered.",
      );
    const token = opaque("verify");
    const user = await prisma.user.create({
      data: {
        email: input.email,
        displayName: input.displayName,
        credential: {
          create: {
            passwordHash: await hashPassword(
              input.password,
              this.secrets.passwordPepper,
            ),
          },
        },
      },
    });
    await prisma.emailVerification.create({
      data: {
        userId: user.id,
        tokenHash: digest(token, this.secrets.tokenPepper),
        expiresAt: new Date(Date.now() + 24 * 3_600_000),
      },
    });
    this.metrics.increment("signups_total");
    return {
      userId: user.id,
      verificationToken: token,
      delivery: "DEVELOPMENT_RESPONSE_ONLY",
    };
  }
  async verifyEmail(raw: unknown) {
    const input = verificationInput.parse(raw);
    const record = await prisma.emailVerification.findUnique({
      where: { tokenHash: digest(input.token, this.secrets.tokenPepper) },
    });
    if (!record || record.usedAt || record.expiresAt <= new Date())
      throw new DomainError(
        "VERIFICATION_INVALID",
        404,
        "Verification token is invalid or expired.",
      );
    await prisma.$transaction([
      prisma.emailVerification.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
      prisma.user.update({
        where: { id: record.userId },
        data: { verifiedAt: new Date() },
      }),
    ]);
    return { verified: true };
  }
  private async createSession(
    userId: string,
    context: { deviceId: string; ip: string; country: string },
    riskScore: number,
    familyId = randomUUID(),
  ) {
    const refreshToken = opaque("refresh");
    const session = await prisma.session.create({
      data: {
        userId,
        deviceHash: hashContext(context.deviceId),
        ipHash: hashContext(context.ip),
        country: context.country,
        riskScore,
        refreshTokens: {
          create: {
            familyId,
            tokenHash: digest(refreshToken, this.secrets.tokenPepper),
            expiresAt: new Date(Date.now() + 30 * 86_400_000),
          },
        },
      },
    });
    return {
      accessToken: this.accessToken(userId, session.id),
      expiresIn: 900,
      refreshToken,
      sessionId: session.id,
    };
  }
  async login(raw: unknown) {
    const input = loginInput.parse(raw);
    const user = await prisma.user.findUnique({
      where: { email: input.email },
      include: {
        credential: true,
        mfaFactors: { where: { status: "ACTIVE" }, take: 1 },
        sessions: {
          where: { revokedAt: null },
          orderBy: { lastSeenAt: "desc" },
          take: 5,
        },
      },
    });
    if (
      !user?.credential ||
      !(await verifyPassword(
        input.password,
        user.credential.passwordHash,
        this.secrets.passwordPepper,
      ))
    )
      throw new DomainError(
        "INVALID_CREDENTIALS",
        401,
        "Credentials are invalid.",
      );
    if (!user.verifiedAt)
      throw new DomainError(
        "EMAIL_NOT_VERIFIED",
        403,
        "Verify email before login.",
      );
    if (user.disabledAt)
      throw new DomainError("ACCOUNT_DISABLED", 403, "Account is disabled.");
    const deviceHash = hashContext(input.deviceId);
    const newDevice = !user.sessions.some(
      (session) => session.deviceHash === deviceHash,
    );
    const countryChange = Boolean(
      user.sessions[0] && user.sessions[0].country !== input.country,
    );
    const riskScore = (newDevice ? 25 : 0) + (countryChange ? 50 : 0);
    if (riskScore >= 50)
      await prisma.securityEvent.create({
        data: {
          userId: user.id,
          type: "SUSPICIOUS_LOGIN",
          severity: "WARNING",
          details: { newDevice, countryChange, country: input.country },
        },
      });
    if (user.mfaFactors.length) {
      const challengeToken = opaque("mfa");
      await prisma.mfaChallenge.create({
        data: {
          userId: user.id,
          tokenHash: digest(challengeToken, this.secrets.tokenPepper),
          deviceId: input.deviceId,
          ip: input.ip,
          country: input.country,
          expiresAt: new Date(Date.now() + 5 * 60_000),
        },
      });
      return { mfaRequired: true, challengeToken, riskScore };
    }
    this.metrics.increment("logins_total");
    return this.createSession(user.id, input, riskScore);
  }
  async authenticate(header?: string): Promise<Principal> {
    if (!header?.startsWith("Bearer "))
      throw new DomainError(
        "UNAUTHENTICATED",
        401,
        "Bearer access token required.",
      );
    const claims = verifyAccessToken(
      header.slice(7),
      this.secrets.publicKeyPem,
    );
    if (!claims)
      throw new DomainError(
        "UNAUTHENTICATED",
        401,
        "Access token is invalid or expired.",
      );
    const session = await prisma.session.findUnique({
      where: { id: claims.sid },
      include: { user: true },
    });
    if (
      !session ||
      session.userId !== claims.sub ||
      session.revokedAt ||
      session.user.disabledAt
    )
      throw new DomainError("UNAUTHENTICATED", 401, "Session is inactive.");
    await prisma.session.update({
      where: { id: session.id },
      data: { lastSeenAt: new Date() },
    });
    return {
      userId: session.userId,
      sessionId: session.id,
      platformAdmin: session.user.platformAdmin,
    };
  }
  async refresh(raw: unknown) {
    const input = refreshInput.parse(raw);
    const tokenHash = digest(input.refreshToken, this.secrets.tokenPepper);
    const record = await prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { session: true },
    });
    if (!record)
      throw new DomainError(
        "REFRESH_INVALID",
        401,
        "Refresh token is invalid.",
      );
    if (record.usedAt || record.revokedAt) {
      await prisma.$transaction([
        prisma.refreshToken.updateMany({
          where: { familyId: record.familyId },
          data: { revokedAt: new Date() },
        }),
        prisma.session.update({
          where: { id: record.sessionId },
          data: { revokedAt: new Date() },
        }),
        prisma.securityEvent.create({
          data: {
            userId: record.session.userId,
            type: "REFRESH_REUSE",
            severity: "CRITICAL",
            details: { familyId: record.familyId },
          },
        }),
      ]);
      this.metrics.increment("refresh_reuse_total");
      throw new DomainError(
        "REFRESH_REUSE_DETECTED",
        401,
        "Token family was revoked.",
      );
    }
    if (record.expiresAt <= new Date() || record.session.revokedAt)
      throw new DomainError("REFRESH_EXPIRED", 401, "Refresh token expired.");
    const nextToken = opaque("refresh");
    const next = await prisma.$transaction(async (tx) => {
      const created = await tx.refreshToken.create({
        data: {
          sessionId: record.sessionId,
          familyId: record.familyId,
          tokenHash: digest(nextToken, this.secrets.tokenPepper),
          expiresAt: new Date(Date.now() + 30 * 86_400_000),
        },
      });
      await tx.refreshToken.update({
        where: { id: record.id },
        data: { usedAt: new Date(), replacedBy: created.id },
      });
      return created;
    });
    return {
      accessToken: this.accessToken(record.session.userId, record.sessionId),
      expiresIn: 900,
      refreshToken: nextToken,
      tokenId: next.id,
    };
  }
  async logout(principal: Principal, allSessions: boolean) {
    if (allSessions)
      await prisma.session.updateMany({
        where: { userId: principal.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    else
      await prisma.session.update({
        where: { id: principal.sessionId },
        data: { revokedAt: new Date() },
      });
    return { revoked: true };
  }
  async requestReset(raw: unknown) {
    const input = resetRequestInput.parse(raw);
    const user = await prisma.user.findUnique({
      where: { email: input.email },
    });
    if (!user) return { accepted: true };
    const token = opaque("reset");
    await prisma.passwordReset.create({
      data: {
        userId: user.id,
        tokenHash: digest(token, this.secrets.tokenPepper),
        expiresAt: new Date(Date.now() + 30 * 60_000),
      },
    });
    return {
      accepted: true,
      resetToken: token,
      delivery: "DEVELOPMENT_RESPONSE_ONLY",
    };
  }
  async confirmReset(raw: unknown) {
    const input = resetConfirmInput.parse(raw);
    const reset = await prisma.passwordReset.findUnique({
      where: { tokenHash: digest(input.token, this.secrets.tokenPepper) },
    });
    if (!reset || reset.usedAt || reset.expiresAt <= new Date())
      throw new DomainError(
        "RESET_INVALID",
        404,
        "Reset token is invalid or expired.",
      );
    await prisma.$transaction([
      prisma.credential.update({
        where: { userId: reset.userId },
        data: {
          passwordHash: await hashPassword(
            input.password,
            this.secrets.passwordPepper,
          ),
          version: { increment: 1 },
          changedAt: new Date(),
        },
      }),
      prisma.passwordReset.update({
        where: { id: reset.id },
        data: { usedAt: new Date() },
      }),
      prisma.session.updateMany({
        where: { userId: reset.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);
    return { reset: true };
  }
  async startOAuth(raw: unknown, principal?: Principal) {
    const input = oauthStartInput.parse(raw);
    if (input.linkToUserId && input.linkToUserId !== principal?.userId)
      throw new DomainError(
        "LINK_AUTH_REQUIRED",
        403,
        "Account linking requires the matching user session.",
      );
    const state = opaque("oauth");
    const codeVerifier = randomBytes(48).toString("base64url");
    const codeChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
    await prisma.oAuthState.create({
      data: {
        provider: input.provider,
        stateHash: digest(state, this.secrets.tokenPepper),
        codeVerifierHash: digest(codeVerifier, this.secrets.tokenPepper),
        redirectUri: input.redirectUri,
        ...(input.linkToUserId ? { linkToUserId: input.linkToUserId } : {}),
        expiresAt: new Date(Date.now() + 10 * 60_000),
      },
    });
    return {
      state,
      codeVerifier,
      authorizationUrl: `https://auth.example.invalid/${input.provider}?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(input.redirectUri)}&code_challenge=${codeChallenge}&code_challenge_method=S256`,
    };
  }
  async completeOAuth(raw: unknown) {
    const input = oauthCallbackInput.parse(raw);
    const state = await prisma.oAuthState.findUnique({
      where: { stateHash: digest(input.state, this.secrets.tokenPepper) },
    });
    if (
      !state ||
      state.usedAt ||
      state.expiresAt <= new Date() ||
      state.codeVerifierHash !==
        digest(input.codeVerifier, this.secrets.tokenPepper)
    )
      throw new DomainError(
        "OAUTH_STATE_INVALID",
        401,
        "OAuth state is invalid or expired.",
      );
    const user = state.linkToUserId
      ? await prisma.user.findUnique({ where: { id: state.linkToUserId } })
      : await prisma.user.upsert({
          where: { email: input.email },
          create: {
            email: input.email,
            displayName: input.displayName,
            verifiedAt: new Date(),
          },
          update: { verifiedAt: new Date() },
        });
    if (!user)
      throw new DomainError(
        "OAUTH_LINK_USER_NOT_FOUND",
        404,
        "Link target not found.",
      );
    await prisma.$transaction([
      prisma.oAuthIdentity.upsert({
        where: {
          provider_providerSubject: {
            provider: state.provider,
            providerSubject: input.providerSubject,
          },
        },
        create: {
          userId: user.id,
          provider: state.provider,
          providerSubject: input.providerSubject,
        },
        update: { userId: user.id },
      }),
      prisma.oAuthState.update({
        where: { id: state.id },
        data: { usedAt: new Date() },
      }),
    ]);
    return {
      userId: user.id,
      provider: state.provider,
      linked: Boolean(state.linkToUserId),
    };
  }
  async rotateSigningKey(principal: Principal, raw: unknown) {
    if (!principal.platformAdmin)
      throw new DomainError(
        "PLATFORM_ADMIN_REQUIRED",
        403,
        "Platform administrator access required.",
      );
    const input = signingKeyRotationInput.parse(raw);
    await prisma.$transaction([
      prisma.signingKey.updateMany({
        where: { active: true },
        data: { active: false, retiredAt: new Date() },
      }),
      prisma.signingKey.upsert({
        where: { id: input.kid },
        create: {
          id: input.kid,
          publicJwk: input.publicJwk as object,
          active: true,
        },
        update: {
          publicJwk: input.publicJwk as object,
          active: true,
          retiredAt: null,
        },
      }),
      prisma.auditEvent.create({
        data: {
          actorId: principal.userId,
          action: "signing_key.rotated",
          targetType: "signing_key",
          targetId: input.kid,
        },
      }),
    ]);
    this.metrics.increment("signing_key_rotations_total");
    return { activeKid: input.kid, deploymentRequired: true };
  }
  async enrollMfa(principal: Principal) {
    const secret = base32Encode(randomBytes(20));
    const recoveryCodes = Array.from({ length: 8 }, () =>
      randomBytes(6).toString("hex").toUpperCase(),
    );
    const factor = await prisma.mfaFactor.create({
      data: {
        userId: principal.userId,
        secretCiphertext: encryptSecret(secret, this.secrets.mfaKey),
        recoveryCodes: {
          create: recoveryCodes.map((code) => ({
            codeHash: digest(code, this.secrets.tokenPepper),
          })),
        },
      },
    });
    return {
      factorId: factor.id,
      secret,
      recoveryCodes,
      uri: `otpauth://totp/IdentityService:${principal.userId}?secret=${secret}&issuer=IdentityService`,
    };
  }
  async confirmMfa(principal: Principal, factorId: string, raw: unknown) {
    const input = mfaConfirmInput.parse(raw);
    const factor = await prisma.mfaFactor.findFirst({
      where: { id: factorId, userId: principal.userId, status: "PENDING" },
    });
    if (
      !factor ||
      !verifyTotp(
        decryptSecret(factor.secretCiphertext, this.secrets.mfaKey),
        input.code,
      )
    )
      throw new DomainError("MFA_CODE_INVALID", 401, "MFA code is invalid.");
    await prisma.mfaFactor.updateMany({
      where: { userId: principal.userId, status: "ACTIVE" },
      data: { status: "DISABLED" },
    });
    return prisma.mfaFactor.update({
      where: { id: factor.id },
      data: { status: "ACTIVE", confirmedAt: new Date() },
    });
  }
  async verifyMfa(raw: unknown) {
    const input = mfaVerifyInput.parse(raw);
    const challenge = await prisma.mfaChallenge.findUnique({
      where: {
        tokenHash: digest(input.challengeToken, this.secrets.tokenPepper),
      },
    });
    if (!challenge || challenge.usedAt || challenge.expiresAt <= new Date())
      throw new DomainError(
        "MFA_CHALLENGE_INVALID",
        401,
        "MFA challenge is invalid.",
      );
    const factor = await prisma.mfaFactor.findFirst({
      where: { userId: challenge.userId, status: "ACTIVE" },
      include: { recoveryCodes: { where: { usedAt: null } } },
    });
    if (!factor)
      throw new DomainError(
        "MFA_NOT_ENROLLED",
        409,
        "MFA factor is unavailable.",
      );
    const totpValid =
      /^\d{6}$/.test(input.code) &&
      verifyTotp(
        decryptSecret(factor.secretCiphertext, this.secrets.mfaKey),
        input.code,
      );
    const recovery = factor.recoveryCodes.find(
      (code) =>
        code.codeHash ===
        digest(input.code.toUpperCase(), this.secrets.tokenPepper),
    );
    if (!totpValid && !recovery)
      throw new DomainError("MFA_CODE_INVALID", 401, "MFA code is invalid.");
    await prisma.$transaction([
      prisma.mfaChallenge.update({
        where: { id: challenge.id },
        data: { usedAt: new Date() },
      }),
      ...(recovery
        ? [
            prisma.recoveryCode.update({
              where: { id: recovery.id },
              data: { usedAt: new Date() },
            }),
          ]
        : []),
    ]);
    return this.createSession(challenge.userId, challenge, 0);
  }
}
