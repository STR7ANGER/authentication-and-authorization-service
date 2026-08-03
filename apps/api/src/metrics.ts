export class Metrics {
  private counters = new Map<string, number>();
  private timings = new Map<
    string,
    { count: number; sum: number; max: number }
  >();
  increment(name: string) {
    if (!/^[a-z][a-z0-9_]*$/.test(name)) throw new Error("Invalid metric name");
    this.counters.set(name, (this.counters.get(name) ?? 0) + 1);
  }
  observe(name: string, value: number) {
    const item = this.timings.get(name) ?? { count: 0, sum: 0, max: 0 };
    this.timings.set(name, {
      count: item.count + 1,
      sum: item.sum + value,
      max: Math.max(item.max, value),
    });
  }
  render() {
    return [
      ...[...this.counters].map(([key, value]) => `identity_${key} ${value}`),
      ...[...this.timings].flatMap(([key, value]) => [
        `identity_${key}_count ${value.count}`,
        `identity_${key}_sum ${value.sum}`,
        `identity_${key}_max ${value.max}`,
      ]),
    ].join("\n");
  }
}
