import { mutation } from "./_generated/server";

export const selected = mutation({
  args: {},
  handler: async (ctx, args) => {
    await ctx.db.patch("items", args.id, { state: "done" });
    return null;
  },
});
