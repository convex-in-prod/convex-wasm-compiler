import { query } from "./_generated/server";

export const selected = query({
  args: {},
  handler: async (_ctx, args) => ({
    encoded: JSON.stringify([args.value]),
    maximum: Math.max(1, Number(args.value)),
  }),
});
