import { retain } from "../shared/state";

export const experimental_reuseContext = true;

export function second(value: string): void {
  retain(value);
}
