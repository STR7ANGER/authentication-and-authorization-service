import { DomainError } from "./errors.js";
export class RateLimiter {
  private buckets = new Map<string, { count: number; resetAt: number }>();
  constructor(
    private limit: number,
    private windowMs: number,
    private now = Date.now,
  ) {}
  consume(key: string) {
    const time = this.now();
    const current = this.buckets.get(key);
    const bucket =
      !current || current.resetAt <= time
        ? { count: 0, resetAt: time + this.windowMs }
        : current;
    bucket.count++;
    this.buckets.set(key, bucket);
    if (bucket.count > this.limit)
      throw new DomainError("RATE_LIMITED", 429, "Request rate exceeded.");
    return {
      limit: this.limit,
      remaining: Math.max(0, this.limit - bucket.count),
    };
  }
}
