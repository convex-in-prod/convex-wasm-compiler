import { rememberContext, rememberMethod, rememberWithClass } from "../shared/applicationState";

export const experimental_reuseContext = true;

export function retainThroughApplicationState(ctx: { storage: { getUrl: unknown } }): void {
  rememberContext(ctx);
  rememberMethod(ctx.storage.getUrl);
  rememberWithClass(ctx.storage.getUrl);
}
