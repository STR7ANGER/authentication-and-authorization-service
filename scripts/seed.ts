import { hashPassword } from "../apps/api/src/crypto.js";
import { prisma } from "../apps/api/src/db.js";

const email = "admin@aegis.local";
const pepper =
  process.env.PASSWORD_PEPPER ?? "local-development-password-pepper";
const user = await prisma.user.upsert({
  where: { email },
  create: {
    email,
    displayName: "Aegis Admin",
    verifiedAt: new Date(),
    platformAdmin: true,
    credential: {
      create: {
        passwordHash: await hashPassword("LocalAdminPassword9", pepper),
      },
    },
  },
  update: { platformAdmin: true },
});
await prisma.organization.upsert({
  where: { slug: "aegis-demo" },
  create: {
    name: "Aegis Demo",
    slug: "aegis-demo",
    memberships: { create: { userId: user.id, role: "OWNER" } },
  },
  update: {},
});
console.info("Seeded admin@aegis.local / LocalAdminPassword9 (local use only)");
await prisma.$disconnect();
