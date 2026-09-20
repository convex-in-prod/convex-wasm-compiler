import { query } from "./_generated/server";
import { nextValue } from "./helper.js";

export const selected = query({
  args: {},
  handler: async () => nextValue(),
});
