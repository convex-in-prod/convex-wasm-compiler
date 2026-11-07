import { mutationGeneric, queryGeneric } from "convex/server";
import { ConvexError } from "convex/values";

async function invoke(ctx, args) {
  if (args.mode === "success") return args.payload;
  if (args.mode === "structured") throw new ConvexError(args.payload);
  if (args.mode === "ordinary") throw new Error("component rejected");
  try {
    await ctx.db.patch("documents", args.id, {});
  } catch (cause) {
    if (args.mode === "unhandled") {
      // A detached rejection must override the returned attributed rejection.
      void Promise.reject(new Error("detached component rejection"));
      throw cause;
    }
    if (args.mode === "missing") throw cause;
    const error = new ConvexError(args.payload);
    Object.defineProperty(error, "cause", { value: cause });
    throw error;
  }
  throw new Error("Fixture expected a missing document");
}

export const read = queryGeneric(invoke);
export const write = mutationGeneric(invoke);
