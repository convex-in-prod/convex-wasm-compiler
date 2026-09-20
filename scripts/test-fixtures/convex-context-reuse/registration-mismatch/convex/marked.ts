import { action, mutation, query } from "convex/server";

export const experimental_reuseContext = true;

export const found = query({
  args: {},
  handler: () => "found",
});

export const wrong = mutation({
  args: {},
  handler: () => "wrong",
});

export const sourceOnly = mutation({
  args: {},
  handler: () => "source-only",
});

export const actionOnly = action({
  args: {},
  handler: () => "action-only",
});

const runtime = {
  opaqueSelected: "selected",
  opaqueUnselected: "unselected",
};

export const { opaqueSelected, opaqueUnselected } = runtime;

export { child as reexported } from "./child";
