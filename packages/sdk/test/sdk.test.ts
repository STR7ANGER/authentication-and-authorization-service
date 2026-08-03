import { describe, expect, it, vi } from "vitest";
import { createIdentityClient, hasRequiredScopes } from "../src/index.js";

describe("identity SDK", () => {
  it("evaluates required scopes", () => {
    expect(hasRequiredScopes(["identity:read"], ["identity:read"])).toBe(true);
    expect(hasRequiredScopes(["identity:read"], ["identity:write"])).toBe(
      false,
    );
    expect(hasRequiredScopes(["*:*"], ["identity:write"])).toBe(true);
  });

  it("sends the API key without exposing it in the URL", async () => {
    const request = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            organizationId: "org",
            apiKeyId: "key",
            scopes: [],
          }),
          { status: 200 },
        ),
    );
    const client = createIdentityClient({
      baseUrl: "https://identity.example.com/",
      apiKey: "idk_secret",
      fetch: request,
    });
    await client.whoami();
    expect(request).toHaveBeenCalledWith(
      "https://identity.example.com/v1/sdk/whoami",
      { headers: { authorization: "Bearer idk_secret" } },
    );
  });
});
