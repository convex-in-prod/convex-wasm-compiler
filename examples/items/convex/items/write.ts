import { v } from "convex/values";
import { mutation } from "../_generated/server";

export const put = mutation({
  args: { name: v.string() },
  handler: async (ctx, args) => {
    await ctx.db.insert("items", { name: args.name });
    return null;
  },
});
