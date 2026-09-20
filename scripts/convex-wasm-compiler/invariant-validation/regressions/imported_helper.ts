import { query } from "./_generated/server";
import { normalize } from "./helper.js";

export const selected = query({
  args: {},
  handler: async (_ctx, args) => normalize(args.value),
});
