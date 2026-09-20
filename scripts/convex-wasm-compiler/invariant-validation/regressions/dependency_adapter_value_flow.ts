import { query } from "./_generated/server";
import { getManyFrom } from "invariant-validation-dependency-adapter";

async function loadMany(helperContext, owner) {
  return getManyFrom(helperContext.db, "items", "by_owner", owner);
}

export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const records = await loadMany(ctx, args.owner);
    return records.map((record) => record._id);
  },
});
