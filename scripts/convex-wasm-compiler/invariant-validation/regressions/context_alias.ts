import { query } from "./_generated/server";

export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const database = ctx.db;
    return await database.get("items", args.id);
  },
});
