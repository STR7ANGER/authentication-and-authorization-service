export class DomainError extends Error {
  constructor(
    readonly code: string,
    readonly status: 400 | 401 | 403 | 404 | 409 | 422 | 429,
    message: string,
  ) {
    super(message);
  }
}
