import { z } from "zod";

const schema = z.object({
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url().default("redis://localhost:6431"),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(3031),
  WEB_URL: z.string().url().default("http://localhost:3000"),
  PASSWORD_PEPPER: z.string().min(32),
  TOKEN_PEPPER: z.string().min(32),
  MFA_ENCRYPTION_KEY: z.string().min(32),
  JWT_PRIVATE_KEY_PEM: z.string().min(32),
  JWT_PUBLIC_KEY_PEM: z.string().min(32),
  OPERATOR_METRICS_TOKEN: z.string().min(32),
  WEBHOOK_SIGNING_SECRET: z.string().min(32),
});
export const parseEnvironment = (environment: NodeJS.ProcessEnv) =>
  schema.parse(environment);
