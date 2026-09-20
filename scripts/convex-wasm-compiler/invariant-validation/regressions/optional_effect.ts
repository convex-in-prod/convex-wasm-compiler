import { query } from "./_generated/server";

export const selected = query({
  args: {},
  handler: async (ctx, args) => await ctx.db?.get("items", args.id),
});
