import { query } from "./_generated/server";

function summarize({ values: [first = 1] = [], limit = 4 } = {}) {
  let total = first;
  let current = first;
  while (current < limit) {
    total += current;
    current += 1;
  }
  try {
    if (total > 10) throw new Error("large");
  } catch (error) {
    total = error.message.length;
  }
  return new Set([total]).has(total);
}

export const selected = query({
  args: {},
  handler: async (_ctx, args) => summarize(args.options),
});
