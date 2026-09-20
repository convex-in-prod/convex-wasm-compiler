import RuntimeDefault, * as RuntimeNamespace from "runtime-default-namespace";
import { runtimeNamed, runtimeOriginal as runtimeAliased } from "runtime-named";
import "runtime-side-effect";

export const experimental_reuseContext = true;

export function readRuntimeValues() {
  return [RuntimeDefault(), RuntimeNamespace.read(), runtimeNamed(), runtimeAliased()];
}
