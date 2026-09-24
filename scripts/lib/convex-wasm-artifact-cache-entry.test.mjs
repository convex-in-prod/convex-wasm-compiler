import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  admitArtifactCacheEntryPublication,
  copyAuthenticatedArtifactCacheEntry,
  publishArtifactCacheEntry,
  readAndValidateArtifactCacheEntry,
  requireAuthenticatedArtifactCacheEntryJsonDigests,
  requireAuthenticatedArtifactCacheEntryPhysicalState,
  validateArtifactCacheEntry,
  validateArtifactCacheEntryInValidationScope,
} from "./convex-wasm-artifact-cache-entry.mjs";
import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";

const PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const CACHE_ENTRY_KIND = "convex-wasm-artifact-cache-entry-v5";

test("publishes an immutable artifact and authenticates a same-key publisher", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-publication-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "publication",
    cacheRoot,
    scope: "isolated-test",
    repositoryRoot: cacheRoot,
  });
  const stage = "fixture";
  const identity = { source: "synthetic" };
  const key = fingerprintJson({ identity, kind: PIPELINE_KIND, stage });
  const artifactPath = join(cacheRoot, "source.wasm");
  const bytes = Buffer.from("synthetic wasm payload");
  await fs.writeFile(artifactPath, bytes, { mode: 0o600 });
  const options = {
    artifactPath,
    cacheLayout,
    cacheRoot,
    extension: "wasm",
    identity,
    key,
    maxArtifactBytes: bytes.length,
    metadata: { target: "synthetic" },
    readPublishedArtifactContents: true,
    stage,
  };
  const [first, second] = await Promise.all([
    publishArtifactCacheEntry(options),
    publishArtifactCacheEntry(options),
  ]);
  const concurrent = await Promise.all(
    Array.from({ length: 4 }, () => publishArtifactCacheEntry(options))
  );
  assert.equal(first.artifactSha256, second.artifactSha256);
  for (const entry of concurrent) assert.equal(entry.artifactSha256, first.artifactSha256);
  assert.deepEqual(first.artifactContents, bytes);
  assert.deepEqual(second.artifactContents, bytes);
  assert.equal(first.artifactPath, second.artifactPath);
  assert.equal((await readAndValidateArtifactCacheEntry(
    cacheRoot, cacheLayout, stage, key, "wasm", bytes.length
  )).artifactSha256, first.artifactSha256);
  assert.deepEqual(await fs.readdir(join(cacheLayout.immutable.artifacts, stage)), [key]);

  await fs.writeFile(artifactPath, Buffer.from("different wasm payload"), { mode: 0o600 });
  await assert.rejects(
    publishArtifactCacheEntry(options),
    /different bytes for the same cache identity/u
  );
  assert.deepEqual(await fs.readdir(join(cacheLayout.immutable.artifacts, stage)), [key]);
});

test("publication rejects empty and oversized artifacts before creating a cache entry", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-publication-limit-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "publication-limit",
    cacheRoot,
    scope: "isolated-test",
    repositoryRoot: cacheRoot,
  });
  const stage = "fixture";
  const identity = { source: "limit-fixture" };
  const artifactPath = join(cacheRoot, "source.wasm");
  const options = {
    artifactPath,
    cacheLayout,
    cacheRoot,
    extension: "wasm",
    identity,
    key: fingerprintJson({ identity, kind: PIPELINE_KIND, stage }),
    maxArtifactBytes: 4,
    metadata: null,
    stage,
  };
  await fs.writeFile(artifactPath, Buffer.alloc(0), { mode: 0o600 });
  await assert.rejects(publishArtifactCacheEntry(options), /empty artifact/u);
  await fs.writeFile(artifactPath, Buffer.from("large"), { mode: 0o600 });
  await assert.rejects(publishArtifactCacheEntry(options), /byte limit|exceeds|maximum/u);
  await assert.rejects(
    publishArtifactCacheEntry({ ...options, extension: "../escape" }),
    /extension must be a path component/u
  );
  await assert.rejects(fs.stat(join(cacheLayout.immutable.artifacts, stage)), { code: "ENOENT" });
});

test("fresh admission accepts balanced concurrent hard-link publication", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-balanced-admission-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const artifactPath = join(root, "artifact.o");
  const loserPath = join(root, "loser.o");
  const contents = Buffer.from("completed native payload");
  await fs.writeFile(artifactPath, contents, { mode: 0o600 });
  const stage = "fixture";
  const identity = { kind: "balanced-publication" };
  const key = fingerprintJson({ identity, kind: PIPELINE_KIND, stage });
  const originalOpen = fs.open;
  for (const readContents of [false, true]) {
    let reads = 0;
    fs.open = async (path, ...args) => {
      const handle = await originalOpen(path, ...args);
      if (path === artifactPath) {
        const read = handle.read.bind(handle);
        handle.read = async (...readArgs) => {
          reads += 1;
          const result = await read(...readArgs);
          await fs.link(artifactPath, loserPath);
          await fs.unlink(loserPath);
          return result;
        };
      }
      return handle;
    };
    try {
      const before = await fs.lstat(artifactPath, { bigint: true });
      const { entry } = await admitArtifactCacheEntryPublication({
        artifactPath,
        artifactFile: "artifact.o",
        identity,
        key,
        maxArtifactBytes: contents.length,
        metadata: null,
        readContents,
        stage,
      });
      assert.equal(reads, 1);
      assert.equal(entry.artifactSha256, createHash("sha256").update(contents).digest("hex"));
      assert.equal(entry.artifactSize, contents.length);
      const copied = copyAuthenticatedArtifactCacheEntry(entry);
      const digests = requireAuthenticatedArtifactCacheEntryJsonDigests(entry);
      assert.equal(requireAuthenticatedArtifactCacheEntryJsonDigests(copied), digests);
      for (const field of ["key", "stage"]) {
        const original = entry[field];
        entry[field] = field === "key" ? "f".repeat(64) : "foreign-stage";
        for (const changed of [entry, copyAuthenticatedArtifactCacheEntry(entry)]) {
          assert.throws(
            () => requireAuthenticatedArtifactCacheEntryJsonDigests(changed),
            /lacks authenticated immutable identity and metadata/u
          );
        }
        assert.equal(requireAuthenticatedArtifactCacheEntryJsonDigests(copied), digests);
        entry[field] = original;
        assert.equal(requireAuthenticatedArtifactCacheEntryJsonDigests(entry), digests);
      }
      assert.equal(entry.admission.payload.nlink, before.nlink.toString());
      assert.notEqual(entry.admission.payload.ctimeNs, before.ctimeNs.toString());
      if (readContents) assert.deepEqual(entry.artifactContents, contents);
      assert.deepEqual(await fs.readdir(root), ["artifact.o"]);
    } finally {
      fs.open = originalOpen;
    }
  }
});

test("published admission survives validator reload while copies and changes require hashing", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-durable-admission-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "durable-admission",
    cacheRoot,
    scope: "isolated-test",
    repositoryRoot: cacheRoot,
  });
  const stage = "fixture";
  const identity = { engine: "exact-engine", package: "exact-package" };
  const key = fingerprintJson({ identity, kind: PIPELINE_KIND, stage });
  const entryPath = join(cacheLayout.immutable.artifacts, stage, key);
  await fs.mkdir(entryPath, { recursive: true, mode: 0o700 });
  const artifactPath = join(entryPath, "artifact.o");
  const contents = Buffer.from("owned immutable artifact");
  await fs.writeFile(artifactPath, contents, { mode: 0o600 });
  const { entrySource } = await admitArtifactCacheEntryPublication({
    artifactPath,
    artifactFile: "artifact.o",
    identity,
    key,
    maxArtifactBytes: contents.length,
    metadata: null,
    readContents: false,
    stage,
  });
  await Promise.all([
    fs.writeFile(join(entryPath, "entry.json"), entrySource, { mode: 0o600 }),
    fs.writeFile(join(entryPath, "COMPLETE"), `${key}\n`, { mode: 0o600 }),
  ]);
  const reloaded = await import(`./convex-wasm-artifact-cache-entry.mjs?durable-admission-test`);
  const originalOpen = fs.open;
  let payloadReads = 0;
  fs.open = async (path, ...args) => {
    if (path === artifactPath) payloadReads += 1;
    return await originalOpen(path, ...args);
  };
  try {
    const validate = (maximumBytes = contents.length) =>
      reloaded.validateArtifactCacheEntry(cacheRoot, cacheLayout, stage, key, "o", maximumBytes);
    assert.equal((await validate()).artifactSize, contents.length);
    assert.equal(payloadReads, 0, "durable admission has no process-local prerequisite");
    for (const field of ["ctimeNs", "nlink"]) {
      const incomplete = JSON.parse(entrySource);
      delete incomplete.admission.payload[field];
      await fs.writeFile(join(entryPath, "entry.json"), `${canonicalJson(incomplete)}\n`);
      await validate();
    }
    assert.equal(payloadReads, 2, "incomplete admission is not evidence of hard-link churn");
    await fs.writeFile(join(entryPath, "entry.json"), entrySource);
    payloadReads = 0;
    await fs.link(artifactPath, join(cacheRoot, "package-alias.o"));
    await validate();
    assert.equal(payloadReads, 0, "ordinary package hard-link publication retains admission");
    const changedDigest = JSON.parse(entrySource);
    changedDigest.artifactSha256 = "0".repeat(64);
    await fs.writeFile(join(entryPath, "entry.json"), `${canonicalJson(changedDigest)}\n`);
    await assert.rejects(validate(), /digest or size does not match/u);
    assert.equal(payloadReads, 1, "entry checksum prevents digest metadata from self-certifying");
    await fs.writeFile(join(entryPath, "entry.json"), entrySource);
    payloadReads = 0;
    await assert.rejects(validate(contents.length - 1), /maximum|limit|bytes/u);
    await reloaded.readAndValidateArtifactCacheEntry(
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length
    );
    assert.equal(payloadReads, 1, "byte consumers still read and authenticate");
    const copy = join(cacheRoot, "copy.o");
    await fs.copyFile(artifactPath, copy);
    await fs.rename(copy, artifactPath);
    await validate();
    assert.equal(payloadReads, 2, "copied payload needs full admission");
    const legacy = JSON.parse(entrySource);
    delete legacy.admission;
    await fs.writeFile(join(entryPath, "entry.json"), `${canonicalJson(legacy)}\n`);
    await validate();
    await validate();
    assert.equal(payloadReads, 4, "legacy validation never self-certifies admission");
    const refreshed = await admitArtifactCacheEntryPublication({
      artifactPath,
      artifactFile: "artifact.o",
      identity,
      key,
      maxArtifactBytes: contents.length,
      metadata: null,
      readContents: false,
      stage,
    });
    await fs.writeFile(join(entryPath, "entry.json"), refreshed.entrySource);
    assert.equal(payloadReads, 5);
    await validate();
    assert.equal(payloadReads, 5);
    const before = await fs.stat(artifactPath);
    await fs.writeFile(artifactPath, Buffer.alloc(contents.length, 120));
    await fs.utimes(artifactPath, before.atime, before.mtime);
    await assert.rejects(validate(), /digest or size does not match/u);
    assert.equal(payloadReads, 6, "same-size rewrite with restored mtime needs full admission");
    const changedIdentity = JSON.parse(entrySource);
    changedIdentity.identity.engine = "other-engine";
    await fs.writeFile(join(entryPath, "entry.json"), `${canonicalJson(changedIdentity)}\n`);
    await assert.rejects(validate(), /identity does not match its key/u);
  } finally {
    fs.open = originalOpen;
  }
});

test("reads and authenticates a small immutable artifact in one physical pass", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-readable-cache-entry-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const cacheRoot = join(root, "cache");
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "readable-entry",
    cacheRoot,
    scope: "isolated-test",
    repositoryRoot: root,
  });
  const stage = "fixture-json";
  const identity = {
    kind: "readable-cache-entry-fixture-v1",
    nested: [{ value: "authenticated" }],
    value: "authenticated",
  };
  const key = fingerprintJson({ identity, kind: PIPELINE_KIND, stage });
  const entryPath = join(cacheLayout.immutable.artifacts, stage, key);
  await fs.mkdir(entryPath, { mode: 0o700, recursive: true });
  for (const directory of [
    cacheRoot,
    join(cacheRoot, "immutable"),
    cacheLayout.immutable.root,
    cacheLayout.immutable.artifacts,
    join(cacheLayout.immutable.artifacts, stage),
    entryPath,
  ]) {
    await fs.chmod(directory, 0o700);
  }
  const contents = Buffer.from('{"kind":"fixture-artifact-v1","value":1}\n');
  const artifactFile = "artifact.json";
  const entry = {
    artifactFile,
    artifactSha256: createHash("sha256").update(contents).digest("hex"),
    artifactSize: contents.length,
    identity,
    key,
    kind: CACHE_ENTRY_KIND,
    metadata: { kind: "fixture-metadata-v1", nested: [{ value: "authenticated" }] },
    stage,
  };
  await Promise.all([
    fs.writeFile(join(entryPath, "COMPLETE"), `${key}\n`, { mode: 0o600 }),
    fs.writeFile(join(entryPath, artifactFile), contents, { mode: 0o600 }),
    fs.writeFile(join(entryPath, "entry.json"), `${canonicalJson(entry)}\n`, { mode: 0o600 }),
  ]);

  const hashed = await validateArtifactCacheEntry(
    cacheRoot,
    cacheLayout,
    stage,
    key,
    "json",
    contents.length
  );
  assert.equal(Object.hasOwn(hashed, "artifactContents"), false);
  assert.deepEqual(requireAuthenticatedArtifactCacheEntryJsonDigests(hashed), {
    identitySha256: fingerprintJson(entry.identity),
    metadataSha256: fingerprintJson(entry.metadata),
  });
  assert.equal(Object.isFrozen(hashed.identity), true);
  assert.equal(Object.isFrozen(hashed.metadata), true);

  const artifactPath = join(entryPath, artifactFile);
  const originalOpen = fs.open;
  let artifactOpenCount = 0;
  let artifactReadCount = 0;
  let entryDirectoryOpenCount = 0;
  fs.open = async (path, ...argumentsList) => {
    const handle = await originalOpen(path, ...argumentsList);
    if (path === entryPath) {
      entryDirectoryOpenCount += 1;
    }
    if (path === artifactPath) {
      artifactOpenCount += 1;
      const originalRead = handle.read.bind(handle);
      handle.read = async (...readArguments) => {
        artifactReadCount += 1;
        return await originalRead(...readArguments);
      };
    }
    return handle;
  };
  let readable;
  let overlappingReadable;
  try {
    [readable, overlappingReadable] = await Promise.all(
      Array.from({ length: 2 }, () =>
        readAndValidateArtifactCacheEntry(
          cacheRoot,
          cacheLayout,
          stage,
          key,
          "json",
          contents.length
        )
      )
    );
  } finally {
    fs.open = originalOpen;
  }
  // The directory snapshot supplies the private file identity to the one payload read.
  assert.equal(artifactOpenCount, 1);
  assert.equal(artifactReadCount, 1);
  assert.equal(entryDirectoryOpenCount, 1);
  assert.notEqual(readable, overlappingReadable);
  assert.deepEqual(readable.artifactContents, contents);
  assert.deepEqual(overlappingReadable.artifactContents, contents);
  delete readable.artifactContents;
  assert.deepEqual(overlappingReadable.artifactContents, contents);
  assert.equal(readable.artifactSha256, entry.artifactSha256);
  assert.deepEqual(
    requireAuthenticatedArtifactCacheEntryJsonDigests(overlappingReadable),
    requireAuthenticatedArtifactCacheEntryJsonDigests(hashed)
  );
  assert.throws(() => {
    readable.identity.value = "forged";
  }, TypeError);
  const retainedIdentity = readable.identity;
  const retainedMetadata = readable.metadata;
  const retainedDigests = requireAuthenticatedArtifactCacheEntryJsonDigests(readable);
  for (const admitted of [hashed, readable, overlappingReadable]) {
    for (const field of ["key", "stage"]) {
      const original = admitted[field];
      admitted[field] = field === "key" ? "f".repeat(64) : "foreign-stage";
      assert.throws(
        () => requireAuthenticatedArtifactCacheEntryJsonDigests(admitted),
        /lacks authenticated immutable identity and metadata/u
      );
      admitted[field] = original;
      assert.deepEqual(
        requireAuthenticatedArtifactCacheEntryJsonDigests(admitted),
        retainedDigests
      );
    }
  }
  assert.equal(overlappingReadable.identity, retainedIdentity);
  assert.equal(overlappingReadable.metadata, retainedMetadata);
  for (const tree of [retainedIdentity, retainedMetadata]) {
    assert.throws(() => {
      tree.nested[0].value = "forged";
    }, TypeError);
    assert.throws(() => {
      tree.nested.push({ value: "forged" });
    }, TypeError);
  }
  const replacedIdentity = readable.identity;
  readable.identity = { ...readable.identity };
  assert.throws(
    () => requireAuthenticatedArtifactCacheEntryJsonDigests(readable),
    /lacks authenticated immutable identity and metadata/u
  );
  readable.identity = replacedIdentity;
  readable.metadata = structuredClone(retainedMetadata);
  assert.throws(
    () => requireAuthenticatedArtifactCacheEntryJsonDigests(readable),
    /lacks authenticated immutable identity and metadata/u
  );
  readable.identity = structuredClone(retainedIdentity);
  readable.identity.nested[0].value = "replacement";
  readable.metadata.nested[0].value = "replacement";
  assert.equal(retainedIdentity.nested[0].value, "authenticated");
  assert.equal(retainedMetadata.nested[0].value, "authenticated");
  assert.deepEqual(requireAuthenticatedArtifactCacheEntryJsonDigests(overlappingReadable), {
    identitySha256: fingerprintJson(retainedIdentity),
    metadataSha256: fingerprintJson(retainedMetadata),
  });
  assert.equal(
    requireAuthenticatedArtifactCacheEntryJsonDigests(overlappingReadable),
    retainedDigests
  );
  assert.throws(
    () => requireAuthenticatedArtifactCacheEntryJsonDigests({ ...hashed }),
    /lacks authenticated immutable identity and metadata/u
  );

  const originalArtifactStatus = await fs.stat(artifactPath);
  const tampered = Buffer.from(contents);
  tampered[0] ^= 1;
  await fs.writeFile(artifactPath, tampered);
  await fs.utimes(artifactPath, originalArtifactStatus.atime, originalArtifactStatus.mtime);
  await assert.rejects(
    readAndValidateArtifactCacheEntry(cacheRoot, cacheLayout, stage, key, "json", contents.length),
    /cache artifact digest or size does not match metadata/u
  );
});

test("scoped artifact validation retains hard-link churn and reauthenticates other changes", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-scoped-cache-entry-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const cacheRoot = join(root, "cache");
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "scoped-entry",
    cacheRoot,
    scope: "isolated-test",
    repositoryRoot: root,
  });
  const stage = "fixture-object";
  const identity = { kind: "scoped-cache-entry-fixture-v1" };
  const key = fingerprintJson({ identity, kind: PIPELINE_KIND, stage });
  const stagePath = join(cacheLayout.immutable.artifacts, stage);
  const entryPath = join(stagePath, key);
  await fs.mkdir(entryPath, { mode: 0o700, recursive: true });
  for (const directory of [
    cacheRoot,
    join(cacheRoot, "immutable"),
    cacheLayout.immutable.root,
    cacheLayout.immutable.artifacts,
    stagePath,
    entryPath,
  ]) {
    await fs.chmod(directory, 0o700);
  }
  const contents = Buffer.from("authenticated object\n");
  const entry = {
    artifactFile: "artifact.o",
    artifactSha256: createHash("sha256").update(contents).digest("hex"),
    artifactSize: contents.length,
    identity,
    key,
    kind: CACHE_ENTRY_KIND,
    metadata: { kind: "scoped-cache-entry-metadata-v1" },
    stage,
  };
  await Promise.all([
    fs.writeFile(join(entryPath, "COMPLETE"), `${key}\n`, { mode: 0o600 }),
    fs.writeFile(join(entryPath, "artifact.o"), contents, { mode: 0o600 }),
    fs.writeFile(join(entryPath, "entry.json"), `${canonicalJson(entry)}\n`, { mode: 0o600 }),
  ]);
  const artifactPath = join(entryPath, "artifact.o");
  const fixedTimestampSeconds = 1_700_000_000;
  await fs.utimes(artifactPath, fixedTimestampSeconds, fixedTimestampSeconds);

  const validationMemo = new Map();
  const stateRequest = {
    validationMemo,
    cacheRoot,
    cacheLayout,
    stage,
    key,
    expectedExtension: "o",
  };
  assert.throws(
    () => requireAuthenticatedArtifactCacheEntryPhysicalState(stateRequest),
    /lacks authenticated physical state/u
  );
  await validateArtifactCacheEntryInValidationScope(
    validationMemo,
    cacheRoot,
    cacheLayout,
    stage,
    key,
    "o",
    contents.length
  );
  const admittedState = requireAuthenticatedArtifactCacheEntryPhysicalState(stateRequest);
  const admittedPayload = JSON.parse(admittedState).files.find(
    ([name]) => name === "artifact.o"
  )[1];
  const payloadStat = await fs.lstat(artifactPath, { bigint: true });
  assert.equal(admittedPayload.ino, payloadStat.ino.toString());
  assert.equal(admittedPayload.ctimeNs, payloadStat.ctimeNs.toString());
  for (const changedExpectation of [
    { expectedExtension: "wasm" },
    { key: "0".repeat(64) },
    { stage: "another-stage" },
    { cacheRoot: join(root, "another-cache") },
    {
      cacheLayout: {
        ...cacheLayout,
        immutable: { ...cacheLayout.immutable, artifacts: join(root, "another-artifact-store") },
      },
    },
  ]) {
    assert.throws(
      () =>
        requireAuthenticatedArtifactCacheEntryPhysicalState({
          ...stateRequest,
          ...changedExpectation,
        }),
      /lacks authenticated physical state/u
    );
  }
  validationMemo.clear();
  assert.throws(
    () => requireAuthenticatedArtifactCacheEntryPhysicalState(stateRequest),
    /lacks authenticated physical state/u
  );
  await validateArtifactCacheEntryInValidationScope(
    validationMemo,
    cacheRoot,
    cacheLayout,
    stage,
    key,
    "o",
    contents.length
  );
  assert.throws(
    () =>
      requireAuthenticatedArtifactCacheEntryPhysicalState({
        ...stateRequest,
        validationMemo: new Map(validationMemo),
      }),
    /lacks authenticated physical state/u
  );
  await assert.rejects(
    validateArtifactCacheEntryInValidationScope(
      validationMemo,
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "wasm",
      contents.length
    ),
    /cache entry is corrupt/u
  );
  await assert.rejects(
    validateArtifactCacheEntryInValidationScope(
      validationMemo,
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length - 1
    ),
    /cached artifact has \d+ bytes, above the \d+-byte limit/u
  );
  const siblingHardLinkPath = join(root, "sibling-control-entry-artifact.o");
  await fs.link(artifactPath, siblingHardLinkPath);
  assert.equal(
    requireAuthenticatedArtifactCacheEntryPhysicalState(stateRequest),
    admittedState,
    "physical-state handoff retains the verifier snapshot instead of observing link changes"
  );
  const originalOpen = fs.open;
  let payloadOpenCount = 0;
  fs.open = async (path, ...argumentsList) => {
    if (path === artifactPath) payloadOpenCount += 1;
    return await originalOpen(path, ...argumentsList);
  };
  try {
    await validateArtifactCacheEntryInValidationScope(
      validationMemo,
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length
    );
  } finally {
    fs.open = originalOpen;
  }
  assert.equal(payloadOpenCount, 0, "a sibling immutable hard link retains authentication");
  await fs.rm(siblingHardLinkPath);
  fs.open = async (path, ...argumentsList) => {
    if (path === artifactPath) payloadOpenCount += 1;
    return await originalOpen(path, ...argumentsList);
  };
  try {
    await validateArtifactCacheEntryInValidationScope(
      validationMemo,
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length
    );
    assert.equal(payloadOpenCount, 0, "a hard-link removal retains authentication");

    const tampered = Buffer.from(contents);
    tampered[0] ^= 1;
    await fs.writeFile(artifactPath, tampered);
    await fs.utimes(artifactPath, fixedTimestampSeconds, fixedTimestampSeconds);
    await assert.rejects(
      validateArtifactCacheEntryInValidationScope(
        validationMemo,
        cacheRoot,
        cacheLayout,
        stage,
        key,
        "o",
        contents.length
      ),
      /cache artifact digest or size does not match metadata/u
    );
    assert.equal(
      payloadOpenCount,
      1,
      "a same-size rewrite with restored mtime cannot reuse scoped authority"
    );

    await fs.writeFile(artifactPath, contents);
    await fs.utimes(artifactPath, fixedTimestampSeconds, fixedTimestampSeconds);
    await validateArtifactCacheEntryInValidationScope(
      validationMemo,
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length
    );
    assert.equal(payloadOpenCount, 2, "restored bytes acquire new scoped authority");

    const replacementPath = join(root, "replacement-artifact.o");
    await fs.writeFile(replacementPath, contents, { mode: 0o600 });
    await fs.utimes(replacementPath, fixedTimestampSeconds, fixedTimestampSeconds);
    await fs.rename(replacementPath, artifactPath);
    await validateArtifactCacheEntryInValidationScope(
      validationMemo,
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length
    );
    assert.equal(payloadOpenCount, 3, "a replacement inode requires fresh authentication");

    await fs.utimes(artifactPath, fixedTimestampSeconds, fixedTimestampSeconds + 1);
    await validateArtifactCacheEntryInValidationScope(
      validationMemo,
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length
    );
    assert.equal(payloadOpenCount, 4, "an mtime change requires fresh authentication");
  } finally {
    fs.open = originalOpen;
  }
  for (const operation of ["add", "remove"]) {
    await t.test(`payload memo admits concurrent hard-link ${operation}`, async () => {
      const siblingPaths = Array.from({ length: 4 }, (_, index) =>
        join(root, `concurrent-${operation}-${index}.o`)
      );
      if (operation === "remove") {
        await Promise.all(siblingPaths.map((path) => fs.link(artifactPath, path)));
      }
      let payloadHashCount = 0;
      fs.open = async (path, ...argumentsList) => {
        const handle = await originalOpen(path, ...argumentsList);
        if (path === artifactPath) {
          const index = payloadHashCount++;
          const originalRead = handle.read.bind(handle);
          let linked = false;
          handle.read = async (...readArguments) => {
            const result = await originalRead(...readArguments);
            if (!linked) {
              linked = true;
              if (operation === "add") await fs.link(artifactPath, siblingPaths[index]);
              else await fs.unlink(siblingPaths[index]);
            }
            return result;
          };
        }
        return handle;
      };
      try {
        const validated = await validateArtifactCacheEntryInValidationScope(
          new Map(),
          cacheRoot,
          cacheLayout,
          stage,
          key,
          "o",
          contents.length,
          4,
          new Map()
        );
        assert.equal(validated.artifactSha256, entry.artifactSha256);
        assert.equal(payloadHashCount, 1, "publication must not discard authenticated bytes");
      } finally {
        fs.open = originalOpen;
      }
    });
  }
  await t.test("payload memo reauthenticates a same-size rewrite with restored mtime", async () => {
    const payloadValidationMemo = new Map();
    const validated = await validateArtifactCacheEntryInValidationScope(
      new Map(),
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length,
      4,
      payloadValidationMemo
    );
    assert.equal(validated.artifactSha256, entry.artifactSha256);
    const tampered = Buffer.from(contents);
    tampered[0] ^= 1;
    await fs.writeFile(artifactPath, tampered);
    await fs.utimes(artifactPath, fixedTimestampSeconds, fixedTimestampSeconds + 1);
    try {
      await assert.rejects(
        validateArtifactCacheEntryInValidationScope(
          new Map(),
          cacheRoot,
          cacheLayout,
          stage,
          key,
          "o",
          contents.length,
          4,
          payloadValidationMemo
        ),
        /cache artifact digest or size does not match metadata/u
      );
    } finally {
      await fs.writeFile(artifactPath, contents);
    }
  });
  const savedStagePath = `${stagePath}-saved`;
  await fs.rename(stagePath, savedStagePath);
  await fs.symlink(savedStagePath, stagePath, "dir");
  await assert.rejects(
    validateArtifactCacheEntryInValidationScope(
      validationMemo,
      cacheRoot,
      cacheLayout,
      stage,
      key,
      "o",
      contents.length
    ),
    /must be a non-symlink directory|traverses a symbolic link/u
  );
});
