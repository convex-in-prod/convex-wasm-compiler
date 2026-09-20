import { query } from "./_generated/server";

export const selected = query({
  args: {
    firstId: v.id("items"),
    secondId: v.id("items"),
  },
  handler: async (ctx, args) =>
    await Promise.all([ctx.db.get("items", args.firstId), ctx.db.get("items", args.secondId)]),
});
