import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { buildConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

async function producerFixture(t, name) {
  const root = await fs.mkdtemp(join(tmpdir(), `convex-wasm-producer-${name}-`));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  await fs.mkdir(join(root, "scripts"), { recursive: true });
  await Promise.all([
    fs.writeFile(
      join(root, "scripts", "root.mjs"),
      'import { value } from "./helper.mjs";\nexport const result = value;\n'
    ),
    fs.writeFile(join(root, "scripts", "helper.mjs"), "export const value = 1;\n"),
  ]);
  await fs.writeFile(
    join(root, "scripts", "convex-wasm-artifact-producer-source-manifest.json"),
    `${JSON.stringify(
      {
        kind: "convex-wasm-artifact-producer-source-manifest",
        schemaVersion: 2,
        roots: ["scripts/root.mjs"],
      },
      null,
      2
    )}\n`
  );
  return root;
}

async function producerRuntimeHandoffFixture(t, name) {
  const root = await producerFixture(t, name);
  const runtimePath = join(root, "scripts", "runtime-main.cpp");
  await fs.writeFile(runtimePath, "constexpr int bridgeHandoffVersion = 1;\n");
  const manifestPath = join(root, "scripts", "convex-wasm-artifact-producer-source-manifest.json");
  const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
  manifest.roots = [...manifest.roots, "scripts/runtime-main.cpp"].sort();
  await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { root, runtimePath };
}

async function producerDeploymentSemanticFixture(t, name) {
  const root = await fs.mkdtemp(join(tmpdir(), `convex-wasm-producer-deployment-${name}-`));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const libraryDirectory = join(root, "scripts", "lib");
  await fs.mkdir(libraryDirectory, { recursive: true });
  await Promise.all([
    fs.writeFile(
      join(libraryDirectory, "convex-wasm-deployment.mjs"),
      [
        'import { directArtifactHandoffSemanticRevision } from "./convex-wasm-deployment-artifact-semantics.mjs";',
        "export const deployment = { directArtifactHandoffSemanticRevision, jobs: 6 };",
        "",
      ].join("\n")
    ),
    fs.writeFile(
      join(libraryDirectory, "convex-wasm-deployment-artifact-semantics.mjs"),
      'export const directArtifactHandoffSemanticRevision = "direct-artifact-handoff-v1";\n'
    ),
  ]);
  await fs.writeFile(
    join(root, "scripts", "convex-wasm-artifact-producer-source-manifest.json"),
    `${JSON.stringify(
      {
        kind: "convex-wasm-artifact-producer-source-manifest",
        operationalFiles: ["scripts/lib/convex-wasm-deployment.mjs"],
        roots: ["scripts/lib/convex-wasm-deployment.mjs"],
        schemaVersion: 2,
      },
      null,
      2
    )}\n`
  );
  return { libraryDirectory, root };
}

test("the compiler producer manifest covers its owned source files", async () => {
  const manifest = JSON.parse(
    await fs.readFile(
      join(repositoryRoot, "scripts", "convex-wasm-artifact-producer-source-manifest.json"),
      "utf8"
    )
  );
  const libraryFiles = (await fs.readdir(join(repositoryRoot, "scripts", "lib")))
    .filter((name) => (name.endsWith(".mjs") && !name.endsWith(".test.mjs")) || name.endsWith(".cpp"))
    .map((name) => `scripts/lib/${name}`);
  assert.deepEqual(
    manifest.roots.filter((path) => path.startsWith("scripts/lib/")),
    libraryFiles.sort()
  );
  const identity = await buildConvexWasmProducerIdentity(repositoryRoot);
  assert.equal(identity.kind, "convex-wasm-artifact-producer-identity-v1");
  assert.equal(identity.nodeVersion, process.version);
  assert.equal(identity.sources.length > 20, true);
  assert.equal(
    identity.sources.some(({ path }) => path.startsWith("/")),
    false
  );
  assert.equal(JSON.stringify(identity).includes(repositoryRoot), false);
  assert.notEqual(
    identity.sources.find(
      ({ path }) => path === "scripts/lib/convex-wasm-native-capability-runtime-main.cpp"
    ),
    undefined
  );
  assert.notEqual(
    identity.sources.find(({ path }) => path === "scripts/lib/convex-wasm-lowering.mjs"),
    undefined
  );
  assert.notEqual(
    identity.sources.find(
      ({ path }) => path === "scripts/lib/convex-wasm-module-graph-common-partition.mjs"
    ),
    undefined
  );
  for (const path of [
    "scripts/lib/convex-wasm-capability-identity.mjs",
    "scripts/lib/convex-wasm-module-graph-cohort-contract.mjs",
    "scripts/lib/convex-wasm-module-graph-deployment-binding.mjs",
    "scripts/lib/convex-wasm-module-graph-membership.mjs",
    "scripts/lib/convex-wasm-official-output-cohort-schedule.mjs",
  ]) {
    assert.notEqual(identity.sources.find((source) => source.path === path), undefined);
    assert.equal(identity.operationalSources.some((source) => source.path === path), false);
  }
  assert.notEqual(
    identity.operationalSources.find(
      ({ path }) => path === "scripts/lib/convex-wasm-native-launch-scheduling.mjs"
    ),
    undefined
  );
});

test("discovers production relative imports from the declared roots", async (t) => {
  const root = await producerFixture(t, "discovered-import");
  const identity = await buildConvexWasmProducerIdentity(root);
  assert.notEqual(
    identity.sources.find(({ path }) => path === "scripts/helper.mjs"),
    undefined
  );
});

test("producer identity uses current bytes and is independent of checkout location", async (t) => {
  const firstRoot = await producerFixture(t, "first");
  const secondRoot = await producerFixture(t, "second");
  const [first, relocated] = await Promise.all([
    buildConvexWasmProducerIdentity(firstRoot),
    buildConvexWasmProducerIdentity(secondRoot),
  ]);
  assert.deepEqual(first, relocated);

  await fs.writeFile(join(secondRoot, "scripts", "helper.mjs"), "export const value = 2;\n");
  const dirty = await buildConvexWasmProducerIdentity(secondRoot);
  assert.notEqual(dirty.sha256, first.sha256);
  assert.notEqual(
    dirty.sources.find(({ path }) => path === "scripts/helper.mjs").sha256,
    first.sources.find(({ path }) => path === "scripts/helper.mjs").sha256
  );
});

test("producer identity changes when the native bridge handoff contract changes", async (t) => {
  const { root, runtimePath } = await producerRuntimeHandoffFixture(t, "runtime-handoff");
  const initial = await buildConvexWasmProducerIdentity(root);
  await fs.writeFile(runtimePath, "constexpr int bridgeHandoffVersion = 2;\n");
  const changedRuntimeHandoff = await buildConvexWasmProducerIdentity(root);
  assert.notEqual(changedRuntimeHandoff.sha256, initial.sha256);
  assert.notEqual(
    changedRuntimeHandoff.sources.find(({ path }) => path === "scripts/runtime-main.cpp").sha256,
    initial.sources.find(({ path }) => path === "scripts/runtime-main.cpp").sha256
  );
});

test("operational native launch scheduling stays outside the producer identity", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-producer-operational-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  await fs.mkdir(join(root, "scripts"), { recursive: true });
  await Promise.all([
    fs.writeFile(
      join(root, "scripts", "root.mjs"),
      'import { value } from "./semantic.mjs";\nimport "./native-launch.mjs";\nexport { value };\n'
    ),
    fs.writeFile(join(root, "scripts", "semantic.mjs"), "export const value = 1;\n"),
    fs.writeFile(
      join(root, "scripts", "native-launch.mjs"),
      [
        "export const defaultJobs = 1;",
        "export const aotEstimatedRssMiB = 5120;",
        "export function aotArguments(args) {",
        '  return [...args, "--parallel-compilation-workers", String(defaultJobs)];',
        "}",
        "",
      ].join("\n")
    ),
  ]);
  await fs.writeFile(
    join(root, "scripts", "convex-wasm-artifact-producer-source-manifest.json"),
    `${JSON.stringify(
      {
        kind: "convex-wasm-artifact-producer-source-manifest",
        operationalFiles: ["scripts/native-launch.mjs"],
        roots: ["scripts/root.mjs"],
        schemaVersion: 2,
      },
      null,
      2
    )}\n`
  );
  const initial = await buildConvexWasmProducerIdentity(root);
  await fs.writeFile(
    join(root, "scripts", "native-launch.mjs"),
    [
      "export const defaultJobs = 6;",
      "export const aotEstimatedRssMiB = 16384;",
      "export function aotArguments(args) {",
      '  return [...args, "--parallel-compilation-workers", "6"];',
      "}",
      "",
    ].join("\n")
  );
  const changedNativeLaunch = await buildConvexWasmProducerIdentity(root);
  assert.equal(changedNativeLaunch.sha256, initial.sha256);
  assert.equal(
    changedNativeLaunch.sources.some(({ path }) => path === "scripts/native-launch.mjs"),
    false
  );
  assert.notEqual(
    changedNativeLaunch.operationalSources.find(({ path }) => path === "scripts/native-launch.mjs")
      .sha256,
    initial.operationalSources[0].sha256
  );
  await fs.writeFile(join(root, "scripts", "semantic.mjs"), "export const value = 2;\n");
  const changedSemanticSource = await buildConvexWasmProducerIdentity(root);
  assert.notEqual(changedSemanticSource.sha256, initial.sha256);
});

test("deployment operations stay outside producer SHA while sealed artifact semantics rotate it", async (t) => {
  const { libraryDirectory, root } = await producerDeploymentSemanticFixture(
    t,
    "semantic-boundary"
  );
  const deploymentPath = join(libraryDirectory, "convex-wasm-deployment.mjs");
  const semanticPath = join(libraryDirectory, "convex-wasm-deployment-artifact-semantics.mjs");
  const initial = await buildConvexWasmProducerIdentity(root);

  await fs.writeFile(
    deploymentPath,
    [
      'import { directArtifactHandoffSemanticRevision } from "./convex-wasm-deployment-artifact-semantics.mjs";',
      "export const deployment = { directArtifactHandoffSemanticRevision, jobs: 12, reportBytes: 134217728 };",
      "",
    ].join("\n")
  );
  const operationalEdit = await buildConvexWasmProducerIdentity(root);
  assert.equal(operationalEdit.sha256, initial.sha256);
  assert.notEqual(
    operationalEdit.operationalSources.find(
      ({ path }) => path === "scripts/lib/convex-wasm-deployment.mjs"
    ).sha256,
    initial.operationalSources[0].sha256
  );

  await fs.writeFile(
    semanticPath,
    'export const directArtifactHandoffSemanticRevision = "direct-artifact-handoff-v2";\n'
  );
  const semanticEdit = await buildConvexWasmProducerIdentity(root);
  assert.notEqual(semanticEdit.sha256, initial.sha256);
  assert.notEqual(
    semanticEdit.sources.find(
      ({ path }) => path === "scripts/lib/convex-wasm-deployment-artifact-semantics.mjs"
    ).sha256,
    initial.sources[0].sha256
  );
});
