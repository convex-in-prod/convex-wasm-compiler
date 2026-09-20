import { query } from "./_generated/server";

const Promise = { all: (values: unknown[]) => values };

export const selected = query({
  args: {},
  handler: async () => Promise.all([1, 2, 3]),
});
