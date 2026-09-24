import { query } from "../_generated/server";

export const get = query({
  args: {},
  handler: async (ctx) => {
    const items = await ctx.db.query("items").collect();
    return items.length;
  },
});
