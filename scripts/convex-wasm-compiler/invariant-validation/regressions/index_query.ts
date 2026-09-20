import { query } from "./_generated/server";

export const selected = query({
  args: {},
  handler: async (ctx, args) =>
    await ctx.db
      .query("items")
      .withIndex("by_owner", (index) => index.eq("owner", args.owner))
      .unique(),
});
