import { retain } from "./middle.mjs";
import "./nodeBridge.mjs";
import "./syntaxBoundaries.mjs";
import "context-reuse-missing-package";

export const experimental_reuseContext = true;

export function unsafeQuery(value: string): void {
  retain(value);
}
