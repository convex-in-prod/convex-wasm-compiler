import { createHash } from "node:crypto";
import { createReadStream, constants, promises as fs } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { createRuntimeRegistrySourceCatalog } from "./runtime-registry-transfer-closure.mjs";

function fail(message) {
  throw new Error(`Convex Wasm runtime registry publication: ${message}`);
}

async function hashFile(path) {
  const hash = createHash("sha256");
  let size = 0;
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
    size += chunk.length;
  }
  return { sha256: hash.digest("hex"), size };
}

async function syncPath(path) {
  const handle = await fs.open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeControlFile(path, bytes) {
  const handle = await fs.open(path, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function copyRecordedDirectory(source, target, files) {
  const sourceState = await fs.lstat(source);
  if (!sourceState.isDirectory() || (await fs.realpath(source)) !== source) {
    fail("verified source package directory changed before publication");
  }
  await fs.mkdir(target, { mode: 0o700 });
  for (const record of files) {
    const sourcePath = join(source, record.name);
    const targetPath = join(target, record.name);
    const state = await fs.lstat(sourcePath);
    if (!state.isFile() || state.size !== record.size) {
      fail(`verified source file changed before publication: ${record.name}`);
    }
    await fs.copyFile(sourcePath, targetPath, constants.COPYFILE_EXCL);
    await fs.chmod(targetPath, 0o600);
    const copied = await hashFile(targetPath);
    if (copied.sha256 !== record.sha256 || copied.size !== record.size) {
      fail(`published file differs from its authenticated record: ${record.name}`);
    }
    await syncPath(targetPath);
  }
  await syncPath(target);
}

export async function publishFreshRuntimeRegistry({
  artifacts,
  deploymentBytes,
  generation,
  moduleGraphs,
  registryRoot,
}) {
  if (!isAbsolute(registryRoot) || registryRoot === "/" || resolve(registryRoot) !== registryRoot) {
    fail("registry root must be a canonical absolute non-root path");
  }
  const parent = dirname(registryRoot);
  if ((await fs.realpath(parent)) !== parent) {
    fail("registry parent must be a canonical directory");
  }
  try {
    await fs.lstat(registryRoot);
    fail("fresh registry target already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (
    deploymentBytes.length !== artifacts.deploymentManifest.size ||
    createHash("sha256").update(deploymentBytes).digest("hex") !==
      artifacts.deploymentManifest.sha256 ||
    moduleGraphs.length === 0 ||
    canonicalJson(generation.moduleGraphs) !==
      canonicalJson(moduleGraphs.map(({ record }) => record).sort((a, b) =>
        a.graphManifestSha256.localeCompare(b.graphManifestSha256)
      ))
  ) {
    fail("registry generation differs from its authenticated deployment or packages");
  }
  const generationBytes = Buffer.from(`${canonicalJson(generation)}\n`);
  const generationManifestSha256 = createHash("sha256").update(generationBytes).digest("hex");
  const currentContent = {
    deploymentSha256: generation.deploymentManifest.deploymentSha256,
    generation: { sha256: generationManifestSha256, size: generationBytes.length },
    generationSha256: generation.generationSha256,
    kind: "convex-wasm-runtime-registry-current-v1",
  };
  const current = { ...currentContent, currentSha256: fingerprintJson(currentContent) };
  const catalog = createRuntimeRegistrySourceCatalog([
    {
      deploymentSha256: generation.deploymentManifest.deploymentSha256,
      generation: current.generation,
      generationSha256: generation.generationSha256,
      sourcePackageRuntimeContentSha256: artifacts.sourcePackageRuntimeContentSha256,
    },
  ]);
  const graphReferences = moduleGraphs.map((graph) => {
    const modules = new Map();
    for (const artifact of graph.record.artifacts) {
      const role = modules.get(artifact.role) ?? { role: artifact.role };
      role[artifact.kind] = {
        cacheKey: artifact.cacheKey,
        path: join(
          registryRoot,
          "module-graph-cache", "immutable", "v6", "artifacts",
          artifact.stage, artifact.cacheKey,
          artifact.kind === "coreWasm" ? "artifact.wasm" : "artifact.cwasm"
        ),
        sha256: artifact.sha256,
        size: artifact.size,
        stage: artifact.stage,
      };
      modules.set(artifact.role, role);
    }
    const graphManifestSha256 = graph.record.graphManifestSha256;
    const packagePath = join(
      registryRoot, "module-graph-cache", "immutable", "v6", "packages", graphManifestSha256
    );
    return {
      artifacts: {
        base: modules.get("base"),
        leaf: modules.get("leaf"),
        shared: [...modules.values()].filter(({ role }) => role !== "base" && role !== "leaf"),
      },
      graphManifestPath: join(packagePath, "graph-manifest.json"),
      graphManifestSha256,
      packagePath,
    };
  });
  const preflight = {
    runtimeRegistry: {
      currentSha256: current.currentSha256,
      generationReferences: [{
        current: true,
        deploymentSha256: generation.deploymentManifest.deploymentSha256,
        generation: current.generation,
        generationSha256: generation.generationSha256,
        moduleGraphs: graphReferences,
        sourcePackageRuntimeContentSha256: artifacts.sourcePackageRuntimeContentSha256,
      }],
      path: registryRoot,
      sourceCatalog: {
        catalogSha256: catalog.manifest.catalogSha256,
        entries: catalog.manifest.entries,
      },
    },
  };
  const stage = await fs.mkdtemp(join(parent, ".convex-wasm-registry-"));
  await fs.chmod(stage, 0o700);
  let published = false;
  try {
    const immutable = join(stage, "module-graph-cache", "immutable", "v6");
    const artifactRoot = join(immutable, "artifacts");
    const packageRoot = join(immutable, "packages");
    const generationRoot = join(
      stage,
      "generations",
      generation.deploymentManifest.deploymentSha256,
      generation.generationSha256
    );
    for (const path of [
      join(stage, "generations"),
      dirname(generationRoot),
      generationRoot,
      join(stage, "packages"),
      join(stage, "module-graph-cache"),
      join(stage, "module-graph-cache", "immutable"),
      immutable,
      artifactRoot,
      packageRoot,
    ]) {
      await fs.mkdir(path, { mode: 0o700 });
    }
    const copiedArtifacts = new Map();
    for (const graph of moduleGraphs) {
      for (const artifact of graph.record.artifacts) {
        const key = `${artifact.stage}/${artifact.cacheKey}`;
        const previous = copiedArtifacts.get(key);
        if (previous !== undefined) {
          if (canonicalJson(previous) !== canonicalJson(artifact)) {
            fail("module graphs disagree about one immutable artifact");
          }
          continue;
        }
        copiedArtifacts.set(key, artifact);
        const stageRoot = join(artifactRoot, artifact.stage);
        try {
          await fs.mkdir(stageRoot, { mode: 0o700 });
        } catch (error) {
          if (error?.code !== "EEXIST") throw error;
        }
        await copyRecordedDirectory(
          join(graph.cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey),
          join(stageRoot, artifact.cacheKey),
          artifact.files
        );
        await syncPath(stageRoot);
      }
      const graphManifestSha256 = graph.record.graphManifestSha256;
      await copyRecordedDirectory(
        join(graph.cacheLayout.immutable.packages, graphManifestSha256),
        join(packageRoot, graphManifestSha256),
        graph.record.package.files
      );
    }
    await writeControlFile(join(generationRoot, "deployment.json"), deploymentBytes);
    await writeControlFile(join(generationRoot, "generation.json"), generationBytes);
    await writeControlFile(
      join(generationRoot, "COMPLETE"),
      Buffer.from(`${generation.generationSha256}\n`)
    );
    await syncPath(generationRoot);
    await writeControlFile(join(stage, "source-catalog.json"), catalog.bytes);
    await writeControlFile(join(stage, "current"), Buffer.from(`${canonicalJson(current)}\n`));
    for (const path of [dirname(generationRoot), join(stage, "generations"), packageRoot, artifactRoot,
      immutable, join(stage, "module-graph-cache", "immutable"), join(stage, "module-graph-cache"), stage]) {
      await syncPath(path);
    }
    await fs.rename(stage, registryRoot);
    published = true;
    await syncPath(parent);
    return { catalogSha256: catalog.manifest.catalogSha256, currentSha256: current.currentSha256,
      generationSha256: generation.generationSha256, preflight, registryRoot };
  } finally {
    if (!published) await fs.rm(stage, { recursive: true, force: true });
  }
}
