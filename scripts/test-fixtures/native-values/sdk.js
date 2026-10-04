import { setupReader } from "sdk-database";

globalThis.captureSdkQuery = (compact, sourceKind) => {
  let query;
  let records = 0;
  globalThis.Convex = {
    typedQueryArgs: true,
    queryCollect: true,
    captureQueryValue: (value) => {
      if (value !== null) throw new Error("Unexpected query literal");
      const bytes = new ArrayBuffer(5);
      new Uint8Array(bytes).set([67, 86, 65, 49, 0]);
      return bytes;
    },
    ...(compact
      ? {
          queryRecord: (...args) => {
            records += 1;
            return record(...args);
          },
        }
      : {}),
    asyncSyscallTyped: (op, args) => {
      if (op !== 7) throw new Error("Expected collection operation");
      query = args[0];
      return [];
    },
    asyncSyscallValueArgs: (op, args) => {
      if (op !== "1.0/queryCollect") throw new Error("Expected collection operation");
      query = args.query;
      return [];
    },
  };
  let builder = setupReader().query("documents");
  if (sourceKind === 1) builder = builder.order("desc");
  else if (sourceKind === 2)
    builder = builder.withIndex("by_field", (range) =>
      range.eq("field", null).lte("other", undefined)
    );
  else
    builder = builder.withSearchIndex("search", (search) =>
      search.search("text", "word").eq("field", null)
    );
  builder.filter((q) => q.and(q.eq(q.field("field"), null), q.eq(q.field("field"), null))).take(3);
  if (query === undefined) throw new Error("SDK did not submit the query synchronously");
  return { query, records };
};
