import assert from "node:assert/strict";
import test from "node:test";

import {
  convexWasmOfficialOutputChunkNativeSymbolLocator,
  convexWasmOfficialOutputNativeSymbolIdentitySha256,
  convexWasmOfficialOutputSourceMembershipIdentitySha256,
} from "./convex-wasm-native-symbol-identity.mjs";

test("source membership ignores order and normalized duplicate paths", () => {
  const first = convexWasmOfficialOutputSourceMembershipIdentitySha256({
    sourceRoot: "/src",
    sources: ["./shared.js", "entry.js", "shared.js"],
  });
  const second = convexWasmOfficialOutputSourceMembershipIdentitySha256({
    sourceRoot: "/src",
    sources: ["entry.js", "shared.js"],
  });
  assert.equal(first, second);
  assert.match(first, /^[0-9a-f]{64}$/u);
});

test("native symbol identity binds the rooted import path and entry publication", () => {
  const sourceMembershipSha256 = "a".repeat(64);
  const base = {
    bindingPath: { entryPath: "functions/query.js", imports: [] },
    canonicalEntryPath: "functions/query.js",
    sourceMembershipSha256,
  };
  const entryLocator = convexWasmOfficialOutputChunkNativeSymbolLocator(base);
  const importedLocator = convexWasmOfficialOutputChunkNativeSymbolLocator({
    ...base,
    bindingPath: {
      entryPath: "functions/query.js",
      imports: [{ kind: "dynamic-import", occurrence: 0 }],
    },
    canonicalEntryPath: null,
  });
  const chunkIdentity = convexWasmOfficialOutputNativeSymbolIdentitySha256({
    entryPath: "functions/query.js",
    entryPublication: false,
    nativeSymbolLocator: entryLocator,
  });
  assert.equal(
    convexWasmOfficialOutputNativeSymbolIdentitySha256({
      entryPath: "functions/query.js",
      entryPublication: false,
      nativeSymbolLocator: entryLocator,
    }),
    chunkIdentity
  );
  assert.notEqual(
    convexWasmOfficialOutputNativeSymbolIdentitySha256({
      entryPath: "functions/query.js",
      entryPublication: false,
      nativeSymbolLocator: importedLocator,
    }),
    chunkIdentity
  );
  assert.notEqual(
    convexWasmOfficialOutputNativeSymbolIdentitySha256({
      entryPath: "functions/query.js",
      entryPublication: true,
      nativeSymbolLocator: entryLocator,
    }),
    chunkIdentity
  );
  assert.throws(
    () =>
      convexWasmOfficialOutputChunkNativeSymbolLocator({
        ...base,
        bindingPath: {
          entryPath: "functions/query.js",
          imports: [{ kind: "unknown", occurrence: 0 }],
        },
        canonicalEntryPath: null,
      }),
    /kind is unsupported/u
  );
});
