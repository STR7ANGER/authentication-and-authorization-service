import { createPublicKey } from "node:crypto";
import { logoutInput } from "@identity/contracts";
import { Hono } from "hono";
import type { AuthorizationService } from "./modules/authorization.js";
import type { IdentityService } from "./modules/identity.js";

export const createRoutes = (
  identity: IdentityService,
  authorization: AuthorizationService,
  publicKeyPem: string,
) => {
  const routes = new Hono();
  const actor = (header?: string) => identity.authenticate(header);
  routes.get("/.well-known/jwks.json", (c) =>
    c.json({
      keys: [
        {
          ...createPublicKey(publicKeyPem).export({ format: "jwk" }),
          kid: "primary",
          alg: "EdDSA",
          use: "sig",
        },
      ],
    }),
  );
  routes.post("/signup", async (c) =>
    c.json(await identity.signup(await c.req.json()), 201),
  );
  routes.post("/verify-email", async (c) =>
    c.json(await identity.verifyEmail(await c.req.json())),
  );
  routes.post("/login", async (c) =>
    c.json(await identity.login(await c.req.json())),
  );
  routes.post("/refresh", async (c) =>
    c.json(await identity.refresh(await c.req.json())),
  );
  routes.post("/logout", async (c) => {
    const input = logoutInput.parse(await c.req.json());
    return c.json(
      await identity.logout(
        await actor(c.req.header("authorization")),
        input.allSessions,
      ),
    );
  });
  routes.post("/password-reset/request", async (c) =>
    c.json(await identity.requestReset(await c.req.json()), 202),
  );
  routes.post("/password-reset/confirm", async (c) =>
    c.json(await identity.confirmReset(await c.req.json())),
  );
  routes.post("/oauth/start", async (c) => {
    const header = c.req.header("authorization");
    return c.json(
      await identity.startOAuth(
        await c.req.json(),
        header ? await actor(header) : undefined,
      ),
    );
  });
  routes.post("/oauth/callback", async (c) =>
    c.json(await identity.completeOAuth(await c.req.json())),
  );
  routes.post("/admin/signing-keys/rotate", async (c) =>
    c.json(
      await identity.rotateSigningKey(
        await actor(c.req.header("authorization")),
        await c.req.json(),
      ),
      201,
    ),
  );
  routes.post("/mfa/enroll", async (c) =>
    c.json(
      await identity.enrollMfa(await actor(c.req.header("authorization"))),
      201,
    ),
  );
  routes.post("/mfa/:id/confirm", async (c) =>
    c.json(
      await identity.confirmMfa(
        await actor(c.req.header("authorization")),
        c.req.param("id"),
        await c.req.json(),
      ),
    ),
  );
  routes.post("/mfa/verify", async (c) =>
    c.json(await identity.verifyMfa(await c.req.json())),
  );
  routes.post("/organizations", async (c) =>
    c.json(
      await authorization.createOrganization(
        await actor(c.req.header("authorization")),
        await c.req.json(),
      ),
      201,
    ),
  );
  routes.post("/organizations/:id/invitations", async (c) =>
    c.json(
      await authorization.invite(
        await actor(c.req.header("authorization")),
        c.req.param("id"),
        await c.req.json(),
      ),
      201,
    ),
  );
  routes.post("/invitations/accept", async (c) =>
    c.json(
      await authorization.acceptInvitation(
        await actor(c.req.header("authorization")),
        await c.req.json(),
      ),
      201,
    ),
  );
  routes.post("/organizations/:id/policy/evaluate", async (c) =>
    c.json(
      await authorization.evaluate(
        await actor(c.req.header("authorization")),
        c.req.param("id"),
        await c.req.json(),
      ),
    ),
  );
  routes.post("/organizations/:id/api-keys", async (c) =>
    c.json(
      await authorization.createApiKey(
        await actor(c.req.header("authorization")),
        c.req.param("id"),
        await c.req.json(),
      ),
      201,
    ),
  );
  routes.delete("/organizations/:organizationId/api-keys/:id", async (c) =>
    c.json(
      await authorization.revokeApiKey(
        await actor(c.req.header("authorization")),
        c.req.param("organizationId"),
        c.req.param("id"),
      ),
    ),
  );
  routes.post("/organizations/:id/webhooks", async (c) =>
    c.json(
      await authorization.registerWebhook(
        await actor(c.req.header("authorization")),
        c.req.param("id"),
        await c.req.json(),
      ),
      201,
    ),
  );
  routes.post("/organizations/:id/events/test", async (c) => {
    const principal = await actor(c.req.header("authorization"));
    await authorization.assertPermission(
      principal,
      c.req.param("id"),
      "webhook:write",
    );
    return c.json(
      await authorization.emitEvent(c.req.param("id"), "security.test", {
        synthetic: true,
      }),
      202,
    );
  });
  routes.delete("/sessions/:id", async (c) =>
    c.json(
      await authorization.revokeSession(
        await actor(c.req.header("authorization")),
        c.req.param("id"),
      ),
    ),
  );
  routes.post("/query", async (c) =>
    c.json(
      await authorization.query(
        await actor(c.req.header("authorization")),
        await c.req.json(),
      ),
    ),
  );
  routes.get("/sdk/whoami", async (c) =>
    c.json(
      await authorization.authenticateApiKey(
        c.req.header("authorization"),
        "identity:read",
        "/v1/sdk/whoami",
      ),
    ),
  );
  return routes;
};
