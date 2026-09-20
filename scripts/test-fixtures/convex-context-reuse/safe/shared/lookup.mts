const lookup = new Map([
  ["alpha", "one"],
  ["beta", "two"],
]);

export function readLookup(key: string): string | undefined {
  return lookup.get(key);
}
