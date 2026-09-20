import { sharedStatefulRegex } from "../shared/statefulRegex.mjs";

const moduleArray: string[] = [];
const moduleRecord: Record<string, string> = {};
const push = Array.prototype.push;

const exportedMutableValue: string[] = [];
export { exportedMutableValue };

export class PersistentClassState {
  static readonly values = new Map<string, string>();

  static {
    this.values.set("initialized", "true");
  }

  static retain(key: string, value: string): void {
    this.values.set(key, value);
  }
}

export function exerciseSyntaxBoundaries(key: string, value: string): void {
  const moduleArrayAlias = moduleArray;
  const globalAlias = globalThis;
  globalAlias[key] = value;
  ({ value: moduleRecord[key] } = { value });
  for (moduleRecord[key] of [value]) {
    moduleArray.push(value);
  }
  moduleArrayAlias.push(value);
  push.call(moduleArray, value);
  Reflect.apply(push, moduleArray, [value]);
  Reflect.apply(push, Array.prototype, [value]);
  Object.assign.call(undefined, moduleRecord, { [key]: value });
  Object.assign.apply(undefined, [moduleRecord, { [key]: value }]);
  Reflect.apply(Object.defineProperty, undefined, [moduleRecord, key, { value }]);
  const dynamicAssignArguments = [moduleRecord, { [key]: value }];
  Object.assign.apply(undefined, dynamicAssignArguments);
  Reflect.apply(Object.assign, undefined, dynamicAssignArguments);
  sharedStatefulRegex["test"](value);
  const defineProperty = Object.defineProperty;
  defineProperty(globalAlias, key, { value });
  setTimeout(() => undefined, 1);
}

export function exerciseShadowedBuiltIn(value: string): void {
  const Object = { assign: () => undefined };
  Object.assign(moduleRecord, { value });
}

void process["env"];
const { env: importedEnvironment } = process;
void importedEnvironment;
new Intl.DateTimeFormat("en-US");
["fixture"].map(async (value) => value);
void (async (): Promise<void> => undefined)();
(function importTimeCall(): void {
  void fetch("https://context-reuse.invalid/syntax-boundary");
}).call(undefined);

export function exerciseSpreadMutators(): void {
  const argumentsWithTarget = [moduleRecord, { value: "spread" }];
  Object.assign(...argumentsWithTarget);
  Object.assign.call(undefined, ...argumentsWithTarget);
  Object.assign.apply(...argumentsWithTarget);
  Reflect.apply(Object.assign, ...argumentsWithTarget);
  push.call(...argumentsWithTarget);
  push.apply(...argumentsWithTarget);
}
