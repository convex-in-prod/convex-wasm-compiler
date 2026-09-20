export const experimental_reuseContext = true;

const retained = {} as Record<string, { nested?: string }>;

export function mutate(key: string, value: string): void {
  globalThis[key] = { nested: value };
  globalThis[key].nested = value;
  retained[key] = { nested: value };
  retained[key].nested = value;
}
