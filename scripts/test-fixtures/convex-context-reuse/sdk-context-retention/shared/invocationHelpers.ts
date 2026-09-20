export function invokeStorageMethod(
  getUrl: (storageId: string) => Promise<string | null>,
  storageId: string
): Promise<string | null> {
  return getUrl(storageId);
}

export function useContextNow(
  ctx: { storage: { getUrl: (storageId: string) => Promise<string | null> } },
  storageId: string
): Promise<string | null> {
  return invokeStorageMethod(ctx.storage.getUrl, storageId);
}
