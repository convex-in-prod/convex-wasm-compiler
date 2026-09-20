import { query } from "./_generated/server";

export const selected = query({
  args: {},
  handler: async () => Date.now(),
});
