export const experimental_reuseContext = true;

let retainedContext: unknown;
const retainedMethods: unknown[] = [];

export function retainDirectly(ctx: { storage: { getUrl: unknown } }): void {
  retainedContext = ctx;
  retainedMethods.push(ctx.storage.getUrl);
}
