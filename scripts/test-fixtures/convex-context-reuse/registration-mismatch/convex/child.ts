import { query } from "convex/server";

export const child = query({
  args: {},
  handler: () => "child",
});
