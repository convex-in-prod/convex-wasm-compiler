import { query } from "./_generated/server";

export const selected = query({
  args: { ids: v.array(v.id("items")) },
  handler: async (ctx, args) =>
    await Promise.all(args.ids.map((id: string) => ctx.db.get("items", id))),
});
