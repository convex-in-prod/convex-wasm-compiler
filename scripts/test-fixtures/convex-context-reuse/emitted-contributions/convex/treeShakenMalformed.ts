import { actionOnly } from "malformed-pruned-package";

export const experimental_reuseContext = true;

export function unusedMalformedActionHelper(): unknown {
  return actionOnly;
}
