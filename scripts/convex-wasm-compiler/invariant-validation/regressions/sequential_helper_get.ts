import { query } from "./_generated/server";
import { requiredDocument as load } from "./helper.js";

export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const document = await load(ctx, "documents", args.id);
    return document.label;
  },
});
