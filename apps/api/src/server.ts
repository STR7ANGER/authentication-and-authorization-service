import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { parseEnvironment } from "./env.js";
import { Metrics } from "./metrics.js";
import { AuthorizationService } from "./modules/authorization.js";
import { IdentityService } from "./modules/identity.js";

const env = parseEnvironment(process.env);
const metrics = new Metrics();
const identity = new IdentityService(
  {
    passwordPepper: env.PASSWORD_PEPPER,
    tokenPepper: env.TOKEN_PEPPER,
    mfaKey: env.MFA_ENCRYPTION_KEY,
    privateKeyPem: env.JWT_PRIVATE_KEY_PEM.replaceAll("\\n", "\n"),
    publicKeyPem: env.JWT_PUBLIC_KEY_PEM.replaceAll("\\n", "\n"),
  },
  metrics,
);
const authorization = new AuthorizationService(
  {
    tokenPepper: env.TOKEN_PEPPER,
    encryptionKey: env.MFA_ENCRYPTION_KEY,
    webhookSigningSecret: env.WEBHOOK_SIGNING_SECRET,
  },
  metrics,
);
const server = serve({
  fetch: createApp({
    metrics,
    operatorToken: env.OPERATOR_METRICS_TOKEN,
    identity,
    authorization,
    publicKeyPem: env.JWT_PUBLIC_KEY_PEM.replaceAll("\\n", "\n"),
  }).fetch,
  port: env.API_PORT,
});
console.info(
  JSON.stringify({
    level: "info",
    event: "server.started",
    port: env.API_PORT,
  }),
);
process.on("SIGTERM", () => server.close());
