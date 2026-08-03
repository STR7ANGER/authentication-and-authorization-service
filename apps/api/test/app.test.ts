import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { Metrics } from "../src/metrics.js";

describe("service shell", () => {
  it("serves health and protects metrics", async () => {
    const app = createApp({
      metrics: new Metrics(),
      operatorToken: "operator",
    });
    expect((await app.request("http://local/health")).status).toBe(200);
    expect((await app.request("http://local/internal/metrics")).status).toBe(
      403,
    );
  });
});
