type FunctionReference<Kind extends string> = { kind: Kind };

export declare const api: {
  marked: {
    read: FunctionReference<"query">;
    write: FunctionReference<"mutation">;
  };
  unmarked: {
    write: FunctionReference<"mutation">;
  };
  excluded: {
    read: FunctionReference<"query">;
  };
  notDatabase: {
    run: FunctionReference<"action">;
  };
};

export declare const internal: {};
