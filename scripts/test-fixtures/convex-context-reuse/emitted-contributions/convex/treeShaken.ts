import { actionOnly } from "test-package";

export const experimental_reuseContext = true;

export function unusedActionHelper(): unknown {
  return actionOnly;
}
