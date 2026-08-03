import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  sign as cryptoSign,
  verify as cryptoVerify,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";

const SCRYPT = { N: 2 ** 15, r: 8, p: 3, maxmem: 128 * 1024 * 1024 };
const scrypt = (
  password: string,
  salt: Buffer,
  length: number,
  options = SCRYPT,
) =>
  new Promise<Buffer>((resolve, reject) =>
    scryptCallback(password, salt, length, options, (error, derived) =>
      error ? reject(error) : resolve(derived),
    ),
  );
const b64 = (value: Buffer | string) =>
  Buffer.from(value).toString("base64url");
export const digest = (value: string, pepper: string) =>
  createHash("sha256").update(`${pepper}:${value}`).digest("hex");
export const hashPassword = async (password: string, pepper: string) => {
  const salt = randomBytes(16);
  const derived = await scrypt(`${pepper}:${password}`, salt, 64);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64url")}$${derived.toString("base64url")}`;
};
export const verifyPassword = async (
  password: string,
  encoded: string,
  pepper: string,
) => {
  const parts = encoded.split("$");
  const parameterized = parts.length === 6;
  const saltText = parameterized ? parts[4] : parts[1];
  const hashText = parameterized ? parts[5] : parts[2];
  if (!saltText || !hashText) return false;
  const expected = Buffer.from(hashText, "base64url");
  const options = parameterized
    ? {
        N: Number(parts[1]),
        r: Number(parts[2]),
        p: Number(parts[3]),
        maxmem: SCRYPT.maxmem,
      }
    : { N: 2 ** 14, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
  const actual = await scrypt(
    `${pepper}:${password}`,
    Buffer.from(saltText, "base64url"),
    expected.length,
    options,
  );
  return timingSafeEqual(actual, expected);
};
export type AccessClaims = {
  sub: string;
  sid: string;
  iat: number;
  exp: number;
  iss: "identity-service";
};
export const signAccessToken = (
  claims: AccessClaims,
  privateKeyPem: string,
) => {
  const header = b64(
    JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: "primary" }),
  );
  const payload = b64(JSON.stringify(claims));
  const signature = cryptoSign(
    null,
    Buffer.from(`${header}.${payload}`),
    privateKeyPem,
  ).toString("base64url");
  return `${header}.${payload}.${signature}`;
};
export const verifyAccessToken = (
  token: string,
  publicKeyPem: string,
  now = Date.now,
) => {
  const [header, payload, signature] = token.split(".");
  if (!header || !payload || !signature) return null;
  try {
    if (
      !cryptoVerify(
        null,
        Buffer.from(`${header}.${payload}`),
        publicKeyPem,
        Buffer.from(signature, "base64url"),
      )
    )
      return null;
    const claims = JSON.parse(
      Buffer.from(payload, "base64url").toString(),
    ) as AccessClaims;
    return claims.exp * 1000 > now() && claims.iss === "identity-service"
      ? claims
      : null;
  } catch {
    return null;
  }
};
const encryptionKey = (secret: string) =>
  createHash("sha256").update(secret).digest();
export const encryptSecret = (plaintext: string, secret: string) => {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(secret), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext]
    .map((item) => item.toString("base64url"))
    .join(".");
};
export const decryptSecret = (sealed: string, secret: string) => {
  const parts = sealed.split(".");
  if (parts.length !== 3) throw new Error("Encrypted secret is malformed");
  const iv = Buffer.from(parts[0] ?? "", "base64url");
  const tag = Buffer.from(parts[1] ?? "", "base64url");
  const ciphertext = Buffer.from(parts[2] ?? "", "base64url");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(secret), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString();
};
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const base32Encode = (input: Buffer) => {
  let bits = "";
  for (const byte of input) bits += byte.toString(2).padStart(8, "0");
  let output = "";
  for (let index = 0; index < bits.length; index += 5)
    output +=
      alphabet[Number.parseInt(bits.slice(index, index + 5).padEnd(5, "0"), 2)];
  return output;
};
const base32Decode = (input: string) => {
  let bits = "";
  for (const character of input.replaceAll("=", "").toUpperCase())
    bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8)
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  return Buffer.from(bytes);
};
export const totp = (secret: string, at = Date.now()) => {
  const counter = Math.floor(at / 30_000);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const hash = createHmac("sha1", base32Decode(secret)).update(buffer).digest();
  const offset = (hash[hash.length - 1] ?? 0) & 15;
  const binary =
    (((hash[offset] ?? 0) & 127) << 24) |
    (((hash[offset + 1] ?? 0) & 255) << 16) |
    (((hash[offset + 2] ?? 0) & 255) << 8) |
    ((hash[offset + 3] ?? 0) & 255);
  return String(binary % 1_000_000).padStart(6, "0");
};
export const verifyTotp = (secret: string, code: string, at = Date.now()) =>
  [-1, 0, 1].some((window) => totp(secret, at + window * 30_000) === code);
