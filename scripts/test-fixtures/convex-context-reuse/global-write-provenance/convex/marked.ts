export const experimental_reuseContext = true;

const retainedView = new DataView(new ArrayBuffer(1));

export function writeGlobals(): void {
  Object = {};
  Uint8Array.contextReuseFixture = true;
  contextReuseRuntimeState.value = true;
}

export function writeShadowedLocal(): void {
  const Object = { contextReuseFixture: false };
  const alias = Object;
  alias.contextReuseFixture = true;
}

export function writeReassignedAlias(): void {
  let alias = {};
  alias = globalThis;
  alias.contextReuseFixture = true;
}

export function writeConditionalAlias(condition: boolean): void {
  const alias = condition ? globalThis : {};
  alias.contextReuseFixture = true;
}

export function writeRetainedDataView(): void {
  retainedView.setUint8(0, 1);
}

const retainedRecord = {};

export function writeThroughExplicitGlobalThis(): void {
  globalThis.Object.assign(retainedRecord, { value: true });
  globalThis.Reflect.apply(globalThis.Object.defineProperty, undefined, [
    retainedRecord,
    "other",
    { value: true },
  ]);
}

function ignoreAssign(): void {}
const possibleAssign = globalThis.contextReuseUseAssign ? globalThis.Object.assign : ignoreAssign;

export function writeThroughConditionalMutator(): void {
  possibleAssign(retainedRecord, { conditional: true });
}

export function mutateFreshConditionalState(condition: boolean): void {
  const values: string[] | undefined = condition ? undefined : [];
  values?.push("local");

  const identifiers = condition ? new Set<string>() : undefined;
  identifiers?.add("local");

  let record: { retained?: boolean } | undefined = condition ? undefined : { retained: false };
  if (record !== undefined) {
    record = { ...record };
    delete record.retained;
  }
}
