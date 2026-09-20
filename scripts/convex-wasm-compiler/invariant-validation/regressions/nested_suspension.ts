import { query } from "./_generated/server";

async function loadTwice(ctx: unknown, id: string) {
  const first = await ctx.db.get("items", id);
  return await ctx.db.get("items", first._id);
}

export const selected = query({
  args: {},
  handler: async (ctx, args) => await Promise.all(args.ids.map((id: string) => loadTwice(ctx, id))),
});
