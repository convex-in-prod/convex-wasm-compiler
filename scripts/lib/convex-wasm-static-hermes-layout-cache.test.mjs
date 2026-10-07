import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import {
  planStaticHermesRetainedLayout,
  publishStaticHermesRetainedLayout,
} from "./convex-wasm-static-hermes-layout-cache.mjs";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "hermes-layout-cache-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    repositoryRoot: root,
    cacheRoot: join(root, "cache"),
    buildId: "test",
    scope: "isolated-test",
  });
  await fs.mkdir(cacheLayout.cacheRoot, { mode: 0o700 });
  const generatedCIdentity = {
    exportedUnitName: "sample",
    flags: ["-Xemit-c-bundle", "-Xemit-c-layout"],
    generatedSource: { sha256: digest("original"), size: 8 },
    semanticEnvironment: { LANG: "C" },
    staticHermes: { materials: "a".repeat(64), revision: "test" },
    unitRole: "untyped-official-chunk",
  };
  return { root, cacheLayout, generatedCIdentity, stage: "generated-c" };
}

async function publishOutput(options, plan, strings) {
  const bundlePath = await fs.mkdtemp(join(options.root, "bundle-"));
  const bytes = Buffer.from(
    JSON.stringify({
      kind: "static-hermes-c-layout-v1",
      unitName: "sample",
      strings,
      functions: [],
      scopes: [],
      shards: [],
    }),
  );
  const descriptor = {
    path: "sh_sample_layout.json",
    sha256: digest(bytes),
    size: bytes.length,
  };
  await fs.writeFile(join(bundlePath, descriptor.path), bytes, { mode: 0o600 });
  await publishStaticHermesRetainedLayout({
    cacheLayout: options.cacheLayout,
    generatedCEntry: {
      bundle: { layout: descriptor },
      bundlePath,
      identity: plan.identity,
      stage: options.stage,
    },
  });
  return descriptor;
}

test("source choices remain pinned across edits, relocation and ancestor eviction", async (t) => {
  const options = await fixture(t);
  const first = await planStaticHermesRetainedLayout(options);
  assert.equal(first.identity.retainedLayout, null);
  const initial = await publishOutput(options, first, ["61"]);
  assert.deepEqual(await planStaticHermesRetainedLayout(options), first);
  const edited = {
    ...options,
    generatedCIdentity: {
      ...options.generatedCIdentity,
      generatedSource: { sha256: digest("edit"), size: 4 },
    },
  };
  const second = await planStaticHermesRetainedLayout(edited);
  assert.deepEqual(second.identity.retainedLayout, {
    sha256: initial.sha256,
    size: initial.size,
  });
  const changed = await publishOutput(options, second, ["61", "62"]);
  assert.deepEqual(await planStaticHermesRetainedLayout(edited), second);
  const next = {
    ...edited,
    generatedCIdentity: {
      ...edited.generatedCIdentity,
      generatedSource: { sha256: digest("next"), size: 4 },
    },
  };
  const third = await planStaticHermesRetainedLayout(next);
  assert.deepEqual(third.identity.retainedLayout, {
    sha256: changed.sha256,
    size: changed.size,
  });
  await fs.rm(
    join(
      options.cacheLayout.immutable.artifacts,
      "static-hermes-layout-output",
    ),
    { recursive: true },
  );
  const relocated = deriveConvexWasmCacheLayout({
    repositoryRoot: join(options.root, "other-checkout"),
    cacheRoot: options.cacheLayout.cacheRoot,
    buildId: "other",
    scope: "isolated-test",
  });
  assert.deepEqual(
    await planStaticHermesRetainedLayout({ ...edited, cacheLayout: relocated }),
    second,
  );
  const unbuilt = {
    ...next,
    generatedCIdentity: {
      ...next.generatedCIdentity,
      generatedSource: { sha256: digest("unbuilt"), size: 7 },
    },
  };
  assert.equal(
    (await planStaticHermesRetainedLayout(unbuilt)).identity.retainedLayout,
    null,
  );
});

test("compiler, flag and unit changes select independent layout lineages", async (t) => {
  const options = await fixture(t);
  const first = await planStaticHermesRetainedLayout(options);
  await publishOutput(options, first, ["61"]);
  for (const changes of [
    {
      staticHermes: {
        ...options.generatedCIdentity.staticHermes,
        materials: "b".repeat(64),
      },
    },
    { flags: [...options.generatedCIdentity.flags, "-O"] },
    { exportedUnitName: "another" },
    { semanticEnvironment: { LANG: "other" } },
  ]) {
    const plan = await planStaticHermesRetainedLayout({
      ...options,
      generatedCIdentity: { ...options.generatedCIdentity, ...changes },
    });
    assert.equal(plan.identity.retainedLayout, null);
  }
});

test("concurrent planners adopt one immutable choice while output discovery changes", async (t) => {
  const options = await fixture(t);
  const first = await planStaticHermesRetainedLayout(options);
  const initial = await publishOutput(options, first, ["61"]);
  const edited = {
    ...options,
    generatedCIdentity: {
      ...options.generatedCIdentity,
      generatedSource: { sha256: digest("edit"), size: 4 },
    },
  };
  const seed = await planStaticHermesRetainedLayout(edited);
  const next = {
    ...edited,
    generatedCIdentity: {
      ...edited.generatedCIdentity,
      generatedSource: { sha256: digest("next"), size: 4 },
    },
  };
  const firstPlans = Array.from({ length: 8 }, () =>
    planStaticHermesRetainedLayout(next),
  );
  const changed = await publishOutput(options, seed, ["61", "62"]);
  const plans = await Promise.all([
    ...firstPlans,
    ...Array.from({ length: 8 }, () => planStaticHermesRetainedLayout(next)),
  ]);
  for (const plan of plans) assert.deepEqual(plan, plans[0]);
  assert.ok(
    [initial.sha256, changed.sha256].includes(plans[0].retainedLayout.sha256),
  );
});

test("layout selection rejects corrupt bytes and symlink substitution", async (t) => {
  for (const mutation of ["bytes", "symlink"]) {
    await t.test(mutation, async (t) => {
      const options = await fixture(t);
      const cold = await planStaticHermesRetainedLayout(options);
      await publishOutput(options, cold, ["61"]);
      const edited = {
        ...options,
        generatedCIdentity: {
          ...options.generatedCIdentity,
          generatedSource: { sha256: digest("edit"), size: 4 },
        },
      };
      const plan = await planStaticHermesRetainedLayout(edited);
      const path = plan.retainedLayout.path;
      if (mutation === "bytes") {
        await fs.writeFile(path, "corrupt", { mode: 0o600 });
      } else {
        const moved = join(options.root, "moved.json");
        await fs.rename(path, moved);
        await fs.symlink(moved, path);
      }
      await assert.rejects(
        planStaticHermesRetainedLayout(edited),
        /digest|size|symlink|symbolic link/u,
      );
      assert.ok((await fs.readdir(dirname(path))).includes("COMPLETE"));
    });
  }
});
