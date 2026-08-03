import { createPublicKey } from "node:crypto";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { requestId } from "hono/request-id";
import { secureHeaders } from "hono/secure-headers";
import { ZodError } from "zod";
import { DomainError } from "./errors.js";
import type { Metrics } from "./metrics.js";
import type { AuthorizationService } from "./modules/authorization.js";
import type { IdentityService } from "./modules/identity.js";
import { RateLimiter } from "./rate-limit.js";
import { createRoutes } from "./routes.js";
export const createApp = (
  options: {
    metrics?: Metrics;
    operatorToken?: string;
    identity?: IdentityService;
    authorization?: AuthorizationService;
    publicKeyPem?: string;
  } = {},
) => {
  const app = new Hono();
  const general = new RateLimiter(120, 60_000);
  const sensitive = new RateLimiter(10, 60_000);
  app.use("*", requestId());
  app.use("*", secureHeaders());
  app.use(
    "*",
    cors({ origin: process.env.WEB_URL ?? "http://localhost:3000" }),
  );
  app.onError((error, c) => {
    if (error instanceof DomainError)
      return c.json(
        { error: { code: error.code, message: error.message } },
        error.status,
      );
    if (error instanceof ZodError)
      return c.json(
        { error: { code: "VALIDATION_FAILED", message: "Invalid request." } },
        422,
      );
    console.error(
      JSON.stringify({
        level: "error",
        event: "http.unhandled",
        requestId: c.get("requestId"),
      }),
    );
    return c.json({ error: { code: "INTERNAL_ERROR" } }, 500);
  });
  app.use("/v1/*", async (c, next) => {
    const started = Date.now();
    const path = new URL(c.req.url).pathname;
    const key = `${c.req.header("x-forwarded-for") ?? "local"}:${path}`;
    const rate = [
      "/v1/login",
      "/v1/signup",
      "/v1/refresh",
      "/v1/mfa/verify",
    ].includes(path)
      ? sensitive.consume(key)
      : general.consume(key);
    c.header("x-ratelimit-limit", String(rate.limit));
    c.header("x-ratelimit-remaining", String(rate.remaining));
    await next();
    options.metrics?.increment(
      `http_${Math.floor(c.res.status / 100)}xx_total`,
    );
    options.metrics?.observe("http_request_duration_ms", Date.now() - started);
    console.info(
      JSON.stringify({
        level: "info",
        event: "http.completed",
        requestId: c.get("requestId"),
        method: c.req.method,
        path,
        status: c.res.status,
        durationMs: Date.now() - started,
      }),
    );
  });
  app.get("/health", (c) =>
    c.json({ status: "ok", service: "identity-access-api", contract: "v1" }),
  );
  const publicKeyPem = options.publicKeyPem;
  if (publicKeyPem)
    app.get("/.well-known/jwks.json", (c) =>
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
  if (options.metrics && options.operatorToken)
    app.get("/internal/metrics", (c) => {
      if (c.req.header("authorization") !== `Bearer ${options.operatorToken}`)
        return c.json({ error: { code: "FORBIDDEN" } }, 403);
      c.header("content-type", "text/plain; version=0.0.4");
      return c.body(options.metrics?.render() ?? "");
    });
  if (options.identity && options.authorization && options.publicKeyPem)
    app.route(
      "/v1",
      createRoutes(
        options.identity,
        options.authorization,
        options.publicKeyPem,
      ),
    );
  return app;
};
