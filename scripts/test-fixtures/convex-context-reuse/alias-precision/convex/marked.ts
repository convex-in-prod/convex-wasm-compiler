export const experimental_reuseContext = true;

const retainedState = { nested: { values: [] as string[] } };
const retainedValues: string[] = [];
const { push } = Array.prototype;
const { defineProperty } = Object;

export function retain(value: string): void {
  const { nested } = retainedState;
  nested.values.push(value);
  push.call(retainedValues, value);
  defineProperty(globalThis, "contextReuseAliasFixture", { value });

  {
    const retainedState = { nested: { values: [] as string[] } };
    const { nested } = retainedState;
    nested.values.push(value);
  }
}
