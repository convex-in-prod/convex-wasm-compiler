import { retain } from "../shared/state";

export const experimental_reuseContext = true;

export function first(value: string): void {
  retain(value);
}
