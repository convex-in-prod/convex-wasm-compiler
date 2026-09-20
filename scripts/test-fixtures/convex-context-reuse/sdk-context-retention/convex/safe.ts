import { invokeStorageMethod, useContextNow } from "../shared/invocationHelpers";

export const experimental_reuseContext = true;

export function passWithinInvocation(
  ctx: { storage: { getUrl: (storageId: string) => Promise<string | null> } },
  storageId: string
): Promise<string | null> {
  const invocationState = {
    currentContext: ctx,
    remember(value: typeof ctx) {
      this.currentContext = value;
    },
  };
  invocationState.remember(ctx);
  const getUrl = invocationState.currentContext.storage.getUrl;
  return invokeStorageMethod(getUrl, storageId);
}

export function passContextToHelper(
  ctx: { storage: { getUrl: (storageId: string) => Promise<string | null> } },
  storageId: string
): Promise<string | null> {
  return useContextNow(ctx, storageId);
}
