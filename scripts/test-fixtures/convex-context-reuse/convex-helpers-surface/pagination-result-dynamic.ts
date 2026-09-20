import { getPage } from "convex-helpers/server/pagination";

declare const ctx: unknown;
declare const key: string;

export async function readDynamicPageField() {
  const page = await getPage(ctx as never, {} as never);
  return page[key as keyof typeof page];
}
