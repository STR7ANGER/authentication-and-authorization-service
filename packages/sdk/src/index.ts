export type IdentityClientOptions = {
  baseUrl: string;
  apiKey: string;
  fetch?: typeof globalThis.fetch;
};

export const hasRequiredScopes = (granted: string[], required: string[]) =>
  granted.includes("*:*") || required.every((scope) => granted.includes(scope));

export const createIdentityClient = (options: IdentityClientOptions) => {
  const request = options.fetch ?? globalThis.fetch;
  const get = async <T>(path: string): Promise<T> => {
    const response = await request(
      `${options.baseUrl.replace(/\/$/, "")}${path}`,
      {
        headers: { authorization: `Bearer ${options.apiKey}` },
      },
    );
    if (!response.ok)
      throw new Error(`Identity API request failed with ${response.status}`);
    return (await response.json()) as T;
  };
  return {
    whoami: () =>
      get<{ organizationId: string; apiKeyId: string; scopes: string[] }>(
        "/v1/sdk/whoami",
      ),
  };
};
