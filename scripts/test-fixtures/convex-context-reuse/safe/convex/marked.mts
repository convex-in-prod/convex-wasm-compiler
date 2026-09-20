import { readLookup } from "./reexport.mjs";
import { registeredValue } from "./registry.mjs";
import type { UnsafeType } from "./typeOnlyUnsafe.mjs";

export const experimental_reuseContext = true;

export function readSafeValue(key: string): string | undefined {
  const unusedTypeWitness: UnsafeType | undefined = undefined;
  void unusedTypeWitness;
  return readLookup(key) ?? registeredValue;
}

export async function sortLocalResults(values: readonly number[]): Promise<number | undefined> {
  const [resolvedValues] = await Promise.all([Promise.resolve(values)]);
  const localValues = [...resolvedValues];
  let selected = localValues[0];
  localValues.sort((left, right) => left - right);
  selected = localValues.at(-1);
  return selected;
}

export function updateLocalNumber(values: readonly number[]): number {
  let minimum = Number.POSITIVE_INFINITY;
  for (const value of values) {
    minimum = Math.min(minimum, value);
  }
  return minimum;
}
