export let retainedValue = "";

const cache = new Map<string, string>();
const headers = new Headers();
const mutableRecord: Record<string, string> = {};

Promise.resolve("import-time");
setTimeout(() => undefined, 1);
globalThis.addEventListener("context-reuse-fixture", () => undefined);
void fetch("https://context-reuse.invalid");
Array.prototype.contextReuseFixture = true;
headers.append("x-context-reuse", "fixture");
mutableRecord["initialized"] = "true";
delete mutableRecord["initialized"];
globalThis["contextReuseFixture"] = true;
delete globalThis["contextReuseFixture"];

export function retain(value: string): void {
  retainedValue = value;
  cache.set(value, value);
  cache["computedProperty"] = value;
  globalThis.fixtureRetainedValue = value;
  void import("./dynamicTarget.mjs");
  const runtimeModule = "./dynamicTarget.mjs";
  void require(runtimeModule);
}
