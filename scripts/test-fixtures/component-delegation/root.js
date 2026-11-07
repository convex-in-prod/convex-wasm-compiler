import { componentsGeneric, mutationGeneric, queryGeneric } from "convex/server";
import { ConvexError } from "convex/values";

const child = componentsGeneric().child;

async function invoke(ctx, args) {
  try {
    return args.query
      ? await ctx.runQuery(child.functions.read, args)
      : await ctx.runMutation(child.functions.write, args);
  } catch (error) {
    const structured = args.mode === "structured" || args.mode === "attributed";
    if ((error instanceof ConvexError) !== structured) {
      throw new Error("Nested rejection has the wrong error class");
    }
    if (args.handle === "catch") {
      return { structured, data: structured ? error.data : null };
    }
    if (args.handle === "replace") throw new Error("replacement");
    if (args.handle === "edit") error.data.count += 1n;
    throw error;
  }
}

export const read = queryGeneric(invoke);
export const write = mutationGeneric(invoke);
