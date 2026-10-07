import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";

import {
  admitArtifactCacheEntryPublication,
  publishArtifactCacheEntry,
  readAndValidateArtifactCacheEntryFresh,
  validateArtifactCacheEntryFresh,
} from "./convex-wasm-artifact-cache-entry.mjs";
import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  fail,
  fingerprintJson,
  requireSha256,
} from "./convex-wasm-artifact-contract.mjs";
import { readPrivateRegularFile } from "./convex-wasm-artifact-material.mjs";
import { normalizeConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";
import { MAX_STATIC_HERMES_RETAINED_LAYOUT_BYTES } from "./convex-wasm-static-hermes-c-bundle.mjs";
import { staticHermesRetainedLayoutInvocation } from "./convex-wasm-static-hermes-precompile-protocol.mjs";

const PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const SELECTION_STAGE = "static-hermes-layout-selection";
const OUTPUT_STAGE = "static-hermes-layout-output";
const OUTPUT_KIND = "convex-wasm-static-hermes-layout-output-v1";
const COLD_SELECTION = Buffer.from("null\n");

export function staticHermesLayoutCacheReferences(
  generatedCIdentity,
  generatedCStage,
) {
  if (!Object.hasOwn(generatedCIdentity, "retainedLayout")) return [];
  const { retainedLayout: _, ...unseededIdentity } = generatedCIdentity;
  return [
    {
      stage: SELECTION_STAGE,
      identity: {
        kind: "convex-wasm-static-hermes-layout-selection-v1",
        generatedCIdentity: unseededIdentity,
        generatedCStage,
      },
    },
    {
      stage: OUTPUT_STAGE,
      identity: { kind: OUTPUT_KIND, generatedCIdentity, generatedCStage },
    },
  ].map(({ stage, identity }) => ({
    stage,
    key: fingerprintJson({ kind: PIPELINE_KIND, stage, identity }),
  }));
}

function lineageIdentity(identity, stage) {
  // Source and graph provenance change on edits. Only allocation-compatible compiler inputs
  // belong to the discovery namespace; exact source still binds every selection and C artifact.
  return {
    kind: "convex-wasm-static-hermes-layout-lineage-v1",
    stage,
    exportedUnitName: identity.exportedUnitName,
    flags: identity.flags,
    staticHermes: identity.staticHermes,
    semanticEnvironment: identity.semanticEnvironment,
    unitRole: identity.unitRole,
    ...(identity.opaqueValueAbiVersion === undefined
      ? {}
      : { opaqueValueAbiVersion: identity.opaqueValueAbiVersion }),
    ...(identity.valueMode === undefined
      ? {}
      : { valueMode: identity.valueMode }),
  };
}

function requireOutputProvenance(identity, expectedLineage) {
  assertPlainObject(identity, "retained layout output identity");
  assertExactKeys(
    identity,
    new Set(["kind", "generatedCIdentity", "generatedCStage"]),
    "retained layout output identity",
  );
  if (
    identity.kind !== OUTPUT_KIND ||
    !Object.hasOwn(identity.generatedCIdentity, "retainedLayout") ||
    fingerprintJson(
      lineageIdentity(identity.generatedCIdentity, identity.generatedCStage),
    ) !== expectedLineage
  ) {
    fail("retained layout output does not match its compiler/unit lineage");
  }
}

async function readSelection(layout, key, identity, lineage) {
  const entry = await readAndValidateArtifactCacheEntryFresh(
    layout.cacheRoot,
    layout,
    SELECTION_STAGE,
    key,
    "json",
    MAX_STATIC_HERMES_RETAINED_LAYOUT_BYTES,
  );
  if (entry === undefined) return undefined;
  if (canonicalJson(entry.identity) !== canonicalJson(identity))
    fail("retained layout selection identity changed");
  if (entry.metadata === null) {
    if (!entry.artifactContents.equals(COLD_SELECTION))
      fail("cold retained layout selection has unexpected bytes");
  } else {
    requireOutputProvenance(entry.metadata, lineage);
  }
  return entry;
}

async function pointerPath(layout, lineage) {
  const directory = join(layout.state.root, "static-hermes-layouts", "v1");
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await requirePrivateCacheDirectory(layout.cacheRoot, directory);
  return join(directory, `${lineage}.json`);
}

async function readLatest(layout, lineage) {
  const path = await pointerPath(layout, lineage);
  let bytes;
  try {
    await requirePrivateCacheFile(layout.cacheRoot, path);
    bytes = await readPrivateRegularFile(
      path,
      256,
      "retained layout discovery pointer",
    );
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
  const pointer = JSON.parse(bytes.toString("utf8"));
  assertPlainObject(pointer, "retained layout discovery pointer");
  assertExactKeys(
    pointer,
    new Set(["key"]),
    "retained layout discovery pointer",
  );
  const key = requireSha256(pointer.key, "retained layout output key");
  const entry = await readAndValidateArtifactCacheEntryFresh(
    layout.cacheRoot,
    layout,
    OUTPUT_STAGE,
    key,
    "json",
    MAX_STATIC_HERMES_RETAINED_LAYOUT_BYTES,
  );
  // Normal immutable-cache eviction may leave a discovery pointer without its target.
  if (entry === undefined) return undefined;
  requireOutputProvenance(entry.identity, lineage);
  if (entry.metadata !== null)
    fail("retained layout output has unexpected metadata");
  return entry;
}

async function publishSelection(layout, key, identity, lineage, candidate) {
  const directory = join(layout.immutable.artifacts, SELECTION_STAGE);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await requirePrivateCacheDirectory(layout.cacheRoot, directory);
  const temporary = await fs.mkdtemp(join(directory, ".publish-selection-"));
  try {
    const artifactPath = join(temporary, "artifact.json");
    await fs.writeFile(
      artifactPath,
      candidate === undefined ? COLD_SELECTION : candidate.artifactContents,
      { flag: "wx", mode: 0o600 },
    );
    const { entrySource } = await admitArtifactCacheEntryPublication({
      artifactPath,
      artifactFile: "artifact.json",
      identity,
      key,
      maxArtifactBytes: MAX_STATIC_HERMES_RETAINED_LAYOUT_BYTES,
      metadata: candidate === undefined ? null : candidate.identity,
      readContents: false,
      stage: SELECTION_STAGE,
    });
    await Promise.all([
      fs.writeFile(join(temporary, "entry.json"), entrySource, {
        flag: "wx",
        mode: 0o600,
      }),
      fs.writeFile(join(temporary, "COMPLETE"), `${key}\n`, {
        flag: "wx",
        mode: 0o600,
      }),
    ]);
    try {
      await fs.rename(temporary, join(directory, key));
    } catch (error) {
      if (error?.code !== "EEXIST" && error?.code !== "ENOTEMPTY") throw error;
      // This entry records a choice, not deterministic compiler output. Concurrent planners may
      // observe different latest hints. Both must adopt the first published, authenticated choice.
    }
    const selection = await readSelection(layout, key, identity, lineage);
    if (selection === undefined)
      fail("retained layout selection disappeared during publication");
    return selection;
  } finally {
    await fs.rm(temporary, { recursive: true, force: true });
  }
}

export async function planStaticHermesRetainedLayout({
  cacheLayout,
  generatedCIdentity,
  stage,
}) {
  const invocation = staticHermesRetainedLayoutInvocation([
    ...generatedCIdentity.flags,
    `-exported-unit=${generatedCIdentity.exportedUnitName}`,
  ]);
  if (invocation === undefined) return { identity: generatedCIdentity };
  if (
    invocation.inputPath !== undefined ||
    Object.hasOwn(generatedCIdentity, "retainedLayout")
  ) {
    fail(
      "automatic retained layout selection requires an unseeded generated-C identity",
    );
  }
  const layout = normalizeConvexWasmCacheLayout(cacheLayout);
  const lineage = fingerprintJson(lineageIdentity(generatedCIdentity, stage));
  const identity = {
    kind: "convex-wasm-static-hermes-layout-selection-v1",
    generatedCIdentity,
    generatedCStage: stage,
  };
  const key = fingerprintJson({
    kind: PIPELINE_KIND,
    stage: SELECTION_STAGE,
    identity,
  });
  const selection =
    (await readSelection(layout, key, identity, lineage)) ??
    (await publishSelection(
      layout,
      key,
      identity,
      lineage,
      await readLatest(layout, lineage),
    ));
  const retainedLayout =
    selection.metadata === null
      ? null
      : {
          sha256: selection.artifactSha256,
          size: selection.artifactSize,
        };
  return {
    identity: { ...generatedCIdentity, retainedLayout },
    ...(retainedLayout === null
      ? {}
      : {
          retainedLayout: { ...retainedLayout, path: selection.artifactPath },
        }),
  };
}

export async function publishStaticHermesRetainedLayout({
  cacheLayout,
  generatedCEntry,
}) {
  if (!Object.hasOwn(generatedCEntry.identity, "retainedLayout")) return;
  const layout = normalizeConvexWasmCacheLayout(cacheLayout);
  const descriptor = generatedCEntry.bundle?.layout;
  if (descriptor === undefined)
    fail("retained layout generation did not publish its declared output");
  const identity = {
    kind: OUTPUT_KIND,
    generatedCIdentity: generatedCEntry.identity,
    generatedCStage: generatedCEntry.stage,
  };
  const key = fingerprintJson({
    kind: PIPELINE_KIND,
    stage: OUTPUT_STAGE,
    identity,
  });
  let entry = await validateArtifactCacheEntryFresh(
    layout.cacheRoot,
    layout,
    OUTPUT_STAGE,
    key,
    "json",
    MAX_STATIC_HERMES_RETAINED_LAYOUT_BYTES,
  );
  if (entry === undefined) {
    entry = await publishArtifactCacheEntry({
      artifactPath: join(generatedCEntry.bundlePath, descriptor.path),
      cacheLayout: layout,
      cacheRoot: layout.cacheRoot,
      extension: "json",
      identity,
      key,
      maxArtifactBytes: MAX_STATIC_HERMES_RETAINED_LAYOUT_BYTES,
      metadata: null,
      stage: OUTPUT_STAGE,
    });
  }
  if (
    entry.artifactSha256 !== descriptor.sha256 ||
    entry.artifactSize !== descriptor.size
  ) {
    fail("published retained layout does not match its generated-C bundle");
  }
  const lineage = fingerprintJson(
    lineageIdentity(generatedCEntry.identity, generatedCEntry.stage),
  );
  const path = await pointerPath(layout, lineage);
  const temporary = `${path}.${randomBytes(12).toString("hex")}`;
  try {
    await fs.writeFile(temporary, `${canonicalJson({ key })}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    await fs.rename(temporary, path);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}
