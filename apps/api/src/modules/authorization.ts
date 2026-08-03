import { createHmac, randomBytes, randomUUID } from "node:crypto";
import {
  adminQuery,
  apiKeyInput,
  invitationAcceptInput,
  invitationInput,
  organizationInput,
  policyInput,
  webhookInput,
} from "@identity/contracts";
import type { MembershipRole, Prisma } from "@prisma/client";
import { decryptSecret, digest, encryptSecret } from "../crypto.js";
import { prisma } from "../db.js";
import { DomainError } from "../errors.js";
import type { Metrics } from "../metrics.js";
import type { Principal } from "./identity.js";

const permissions: Record<MembershipRole, string[]> = {
  OWNER: ["*:*"],
  ADMIN: [
    "organization:read",
    "member:read",
    "member:write",
    "key:read",
    "key:write",
    "audit:read",
    "webhook:write",
  ],
  MEMBER: ["organization:read", "member:read"],
};
export const roleAllows = (role: MembershipRole, permission: string) =>
  permissions[role].includes("*:*") || permissions[role].includes(permission);
export const deliveryTransition = (delivered: boolean, attempts: number) => {
  if (delivered) return { status: "DELIVERED" as const, delayMs: 0 };
  if (attempts >= 5) return { status: "DEAD_LETTER" as const, delayMs: 0 };
  return {
    status: "FAILED" as const,
    delayMs: Math.min(60_000 * 2 ** (attempts - 1), 3_600_000),
  };
};
type Secrets = {
  tokenPepper: string;
  encryptionKey: string;
  webhookSigningSecret: string;
};

export class AuthorizationService {
  constructor(
    private secrets: Secrets,
    private metrics: Metrics,
  ) {}
  private async membership(principal: Principal, organizationId: string) {
    const member = await prisma.membership.findUnique({
      where: {
        organizationId_userId: { organizationId, userId: principal.userId },
      },
    });
    if (!member)
      throw new DomainError(
        "MEMBERSHIP_REQUIRED",
        403,
        "Organization membership required.",
      );
    return member;
  }
  private async require(
    principal: Principal,
    organizationId: string,
    permission: string,
  ) {
    const member = await this.membership(principal, organizationId);
    if (!roleAllows(member.role, permission))
      throw new DomainError("FORBIDDEN", 403, "Permission denied.");
    return member;
  }
  async assertPermission(
    principal: Principal,
    organizationId: string,
    permission: string,
  ) {
    await this.require(principal, organizationId, permission);
  }
  async createOrganization(principal: Principal, raw: unknown) {
    const input = organizationInput.parse(raw);
    try {
      const organization = await prisma.organization.create({
        data: {
          ...input,
          memberships: { create: { userId: principal.userId, role: "OWNER" } },
        },
      });
      await prisma.auditEvent.create({
        data: {
          organizationId: organization.id,
          actorId: principal.userId,
          action: "organization.created",
          targetType: "organization",
          targetId: organization.id,
        },
      });
      return organization;
    } catch {
      throw new DomainError(
        "ORGANIZATION_SLUG_TAKEN",
        409,
        "Organization slug is already used.",
      );
    }
  }
  async invite(principal: Principal, organizationId: string, raw: unknown) {
    await this.require(principal, organizationId, "member:write");
    const input = invitationInput.parse(raw);
    const token = `invite_${randomBytes(32).toString("base64url")}`;
    const invitation = await prisma.invitation.create({
      data: {
        organizationId,
        email: input.email,
        role: input.role,
        tokenHash: digest(token, this.secrets.tokenPepper),
        invitedBy: principal.userId,
        expiresAt: new Date(Date.now() + input.expiresInDays * 86_400_000),
      },
    });
    return {
      invitationId: invitation.id,
      token,
      delivery: "DEVELOPMENT_RESPONSE_ONLY",
    };
  }
  async acceptInvitation(principal: Principal, raw: unknown) {
    const input = invitationAcceptInput.parse(raw);
    const invitation = await prisma.invitation.findUnique({
      where: { tokenHash: digest(input.token, this.secrets.tokenPepper) },
    });
    const user = await prisma.user.findUnique({
      where: { id: principal.userId },
    });
    if (
      !invitation ||
      !user ||
      invitation.email !== user.email ||
      invitation.status !== "PENDING" ||
      invitation.expiresAt <= new Date()
    )
      throw new DomainError(
        "INVITATION_INVALID",
        404,
        "Invitation is invalid or expired.",
      );
    return prisma.$transaction(async (tx) => {
      const membership = await tx.membership.create({
        data: {
          organizationId: invitation.organizationId,
          userId: principal.userId,
          role: invitation.role,
        },
      });
      await tx.invitation.update({
        where: { id: invitation.id },
        data: { status: "ACCEPTED", acceptedAt: new Date() },
      });
      await tx.auditEvent.create({
        data: {
          organizationId: invitation.organizationId,
          actorId: principal.userId,
          action: "invitation.accepted",
          targetType: "membership",
          targetId: principal.userId,
        },
      });
      return membership;
    });
  }
  async evaluate(principal: Principal, organizationId: string, raw: unknown) {
    const input = policyInput.parse(raw);
    const member = await this.membership(principal, organizationId);
    return {
      allowed: roleAllows(member.role, input.permission),
      role: member.role,
      reason: "organization_rbac",
    };
  }
  async createApiKey(
    principal: Principal,
    organizationId: string,
    raw: unknown,
  ) {
    await this.require(principal, organizationId, "key:write");
    const input = apiKeyInput.parse(raw);
    const token = `idk_${randomBytes(32).toString("base64url")}`;
    const key = await prisma.apiKey.create({
      data: {
        organizationId,
        name: input.name,
        prefix: token.slice(0, 14),
        tokenHash: digest(token, this.secrets.tokenPepper),
        scopes: input.scopes,
        createdBy: principal.userId,
      },
    });
    return { id: key.id, prefix: key.prefix, token };
  }
  async revokeApiKey(principal: Principal, organizationId: string, id: string) {
    await this.require(principal, organizationId, "key:write");
    const result = await prisma.apiKey.updateMany({
      where: { id, organizationId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (!result.count)
      throw new DomainError("API_KEY_NOT_FOUND", 404, "API key not found.");
    return { revoked: true };
  }
  async authenticateApiKey(
    header: string | undefined,
    requiredScope: string,
    route: string,
  ) {
    if (!header?.startsWith("Bearer idk_"))
      throw new DomainError(
        "API_KEY_REQUIRED",
        401,
        "Scoped API key required.",
      );
    const token = header.slice(7);
    const key = await prisma.apiKey.findUnique({
      where: { prefix: token.slice(0, 14) },
    });
    if (
      !key ||
      key.revokedAt ||
      key.tokenHash !== digest(token, this.secrets.tokenPepper)
    )
      throw new DomainError("API_KEY_INVALID", 401, "API key is invalid.");
    if (!key.scopes.includes("*:*") && !key.scopes.includes(requiredScope))
      throw new DomainError(
        "API_KEY_SCOPE_REQUIRED",
        403,
        "API key scope is insufficient.",
      );
    await prisma.$transaction([
      prisma.apiKey.update({
        where: { id: key.id },
        data: { lastUsedAt: new Date() },
      }),
      prisma.apiKeyUsage.create({ data: { apiKeyId: key.id, route } }),
    ]);
    return {
      organizationId: key.organizationId,
      apiKeyId: key.id,
      scopes: key.scopes,
    };
  }
  async registerWebhook(
    principal: Principal,
    organizationId: string,
    raw: unknown,
  ) {
    await this.require(principal, organizationId, "webhook:write");
    const input = webhookInput.parse(raw);
    const secret = `whsec_${randomBytes(32).toString("base64url")}`;
    const endpoint = await prisma.webhookEndpoint.create({
      data: {
        organizationId,
        url: input.url,
        events: input.events,
        secretCiphertext: encryptSecret(secret, this.secrets.encryptionKey),
      },
    });
    return {
      id: endpoint.id,
      secret,
      url: endpoint.url,
      events: endpoint.events,
    };
  }
  async emitEvent(
    organizationId: string,
    eventType: string,
    payload: Prisma.InputJsonObject,
  ) {
    const endpoints = await prisma.webhookEndpoint.findMany({
      where: { organizationId, disabledAt: null, events: { has: eventType } },
    });
    const eventId = randomUUID();
    await prisma.webhookDelivery.createMany({
      data: endpoints.map((endpoint) => ({
        endpointId: endpoint.id,
        eventId,
        eventType,
        payload,
      })),
    });
    this.metrics.increment("webhook_events_total");
    const body = JSON.stringify({ id: eventId, type: eventType, payload });
    return {
      eventId,
      queued: endpoints.length,
      envelopes: endpoints.map((endpoint) => ({
        endpointId: endpoint.id,
        body,
        signature: createHmac(
          "sha256",
          `${decryptSecret(endpoint.secretCiphertext, this.secrets.encryptionKey)}:${this.secrets.webhookSigningSecret}`,
        )
          .update(body)
          .digest("hex"),
      })),
    };
  }
  async recordWebhookAttempt(deliveryId: string, delivered: boolean) {
    const delivery = await prisma.webhookDelivery.findUnique({
      where: { id: deliveryId },
    });
    if (!delivery)
      throw new DomainError(
        "WEBHOOK_DELIVERY_NOT_FOUND",
        404,
        "Webhook delivery not found.",
      );
    const attempts = delivery.attempts + 1;
    const transition = deliveryTransition(delivered, attempts);
    const updated = await prisma.webhookDelivery.update({
      where: { id: delivery.id },
      data: {
        attempts,
        status: transition.status,
        nextAttemptAt: new Date(Date.now() + transition.delayMs),
        ...(delivered ? { deliveredAt: new Date() } : {}),
      },
    });
    this.metrics.increment(
      `webhook_delivery_${transition.status.toLowerCase()}_total`,
    );
    return updated;
  }
  async revokeSession(principal: Principal, sessionId: string) {
    const result = await prisma.session.updateMany({
      where: { id: sessionId, userId: principal.userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (!result.count)
      throw new DomainError("SESSION_NOT_FOUND", 404, "Session not found.");
    return { revoked: true };
  }
  async query(principal: Principal, raw: unknown) {
    const input = adminQuery.parse(raw);
    if (input.resource === "sessions")
      return prisma.session.findMany({
        where: { userId: principal.userId },
        select: {
          id: true,
          country: true,
          riskScore: true,
          revokedAt: true,
          lastSeenAt: true,
          createdAt: true,
        },
        orderBy: { lastSeenAt: "desc" },
        take: input.limit,
      });
    if (input.resource === "members") {
      await this.require(principal, input.organizationId, "member:read");
      return prisma.membership.findMany({
        where: { organizationId: input.organizationId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              displayName: true,
              verifiedAt: true,
            },
          },
        },
        take: input.limit,
      });
    }
    if (input.resource === "audit") {
      await this.require(principal, input.organizationId, "audit:read");
      return prisma.auditEvent.findMany({
        where: { organizationId: input.organizationId },
        orderBy: { createdAt: "desc" },
        take: input.limit,
      });
    }
    if (input.organizationId)
      await this.require(principal, input.organizationId, "audit:read");
    return prisma.securityEvent.findMany({
      where: {
        ...(input.organizationId
          ? { organizationId: input.organizationId }
          : { userId: principal.userId }),
      },
      orderBy: { createdAt: "desc" },
      take: input.limit,
    });
  }
}
