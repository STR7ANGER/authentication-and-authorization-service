import { describe, expect, it } from "vitest";
import { loginInput, password } from "../src/index.js";

describe("identity contracts", () => {
  it("enforces password strength", () => {
    expect(() => password.parse("weak-password")).toThrow();
    expect(password.parse("StrongPassword9")).toBe("StrongPassword9");
  });
  it("requires bounded login context", () => {
    expect(() =>
      loginInput.parse({
        email: "user@example.com",
        password: "StrongPassword9",
        deviceId: "short",
        ip: "not-ip",
        country: "IND",
      }),
    ).toThrow();
  });
});
