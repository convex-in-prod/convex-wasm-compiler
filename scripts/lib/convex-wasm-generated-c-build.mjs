import { promises as fs } from "node:fs";
import { join } from "node:path";

import {
  assertPlainObject,
  fail,
  normalizeJson,
  requirePositiveInteger,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";
import { hashPrivateRegularFile, mapBounded } from "./convex-wasm-artifact-material.mjs";
import { ensureArtifactStage } from "./convex-wasm-artifact-stage.mjs";
import { writeConvexWasmStaticHermesMemberArchive } from "./convex-wasm-static-hermes-member-archive.mjs";
import {
  authenticateStaticHermesCBundle,
  staticHermesCBundleMemberCompilation,
  staticHermesCBundleTranslationUnitBytes,
} from "./convex-wasm-static-hermes-c-bundle.mjs";
import { runStaticHermesSourceStage } from "./convex-wasm-static-hermes-stage.mjs";
import { buildConvexWasmNativeObject } from "./convex-wasm-native-object-build.mjs";
import { requirePrivateCacheDirectory } from "./convex-wasm-private-cache.mjs";

const LINK_INPUT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\.(?:o|a)$/u;
const MAX_ARCHIVE_BYTES = 640 * 1024 * 1024;

export async function buildConvexWasmGeneratedCLinkInput({
  cacheLayout,
  cacheRoot,
  commands,
  generatedJavaScript,
  identities,
  limits,
  linkInputName,
  materials,
  memberCompilationPolicy,
  memberJobs,
  runCommand,
  verifyEmscriptenMaterials,
  verifyStaticHermesMaterials,
}) {
  if (
    typeof runCommand !== "function" ||
    typeof verifyEmscriptenMaterials !== "function" ||
    typeof verifyStaticHermesMaterials !== "function"
  ) {
    fail("generated-C building requires command and material-verification functions");
  }
  requireString(linkInputName, "generated-C linker input name");
  if (!LINK_INPUT_NAME_PATTERN.test(linkInputName)) {
    fail("generated-C linker input must be a safe object or archive name");
  }
  requirePositiveInteger(memberJobs, "generated-C member jobs");
  assertPlainObject(identities.object, "generated-C object identity");
  assertPlainObject(identities.archive, "generated-C archive identity");
  assertPlainObject(memberCompilationPolicy, "generated-C member compilation policy");
  if (
    Object.hasOwn(identities.archive, "bundleSha256") ||
    Object.hasOwn(identities.archive, "memberCompilationPolicy") ||
    Object.hasOwn(identities.archive, "members")
  ) {
    fail("generated-C archive identity member fields are owned by the builder");
  }
  const maxGeneratedCBytes = requirePositiveInteger(
    limits.generatedCBytes,
    "generated-C byte limit"
  );
  const maxObjectBytes = requirePositiveInteger(limits.objectBytes, "generated-C object byte limit");
  const maxArchiveBytes = Math.min(
    requirePositiveInteger(limits.archiveBytes, "generated-C archive byte limit"),
    MAX_ARCHIVE_BYTES
  );
  const scratchRoot = cacheLayout.work.scratch;
  await fs.mkdir(scratchRoot, { recursive: true, mode: 0o700 });
  await requirePrivateCacheDirectory(cacheRoot, scratchRoot);
  const workPath = await fs.mkdtemp(join(scratchRoot, "generated-c-"));
  await requirePrivateCacheDirectory(cacheRoot, workPath);
  try {
    const source = await runStaticHermesSourceStage({
      command: commands.staticHermes,
      generatedJavaScript,
      materials,
      maxGeneratedCBytes,
      runCommand,
      verifyMaterials: verifyStaticHermesMaterials,
      workPath,
    });
    if (source.kind === "sourceRejected") return source;
    const bundle = source.artifact.bundle;
    if (bundle === undefined) {
      if (!linkInputName.endsWith(".o")) {
        fail("ordinary generated C requires an object linker input name");
      }
      const object = await buildConvexWasmNativeObject({
        cacheLayout,
        cacheRoot,
        command: commands.compileExport,
        identity: identities.object,
        inputs: [{
          name: "unit.c",
          path: source.outputPath,
          sha256: source.artifact.sha256,
          size: source.artifact.size,
        }],
        maxObjectBytes,
        outputName: "unit.o",
        runCommand,
        sourceName: "unit.c",
        stage: "export-object",
        verifyMaterials: verifyEmscriptenMaterials,
      });
      return {
        kind: "success",
        linkInput: {
          name: linkInputName,
          path: object.entry.artifactPath,
          sha256: object.entry.artifactSha256,
          size: object.entry.artifactSize,
        },
        object,
        source,
      };
    }
    if (!linkInputName.endsWith(".a")) {
      fail("generated C bundles require an archive linker input name");
    }
    const authenticated = await authenticateStaticHermesCBundle(
      workPath,
      bundle,
      maxGeneratedCBytes
    );
    const translationUnitBytes = staticHermesCBundleTranslationUnitBytes(bundle);
    const header = {
      name: bundle.header.path,
      path: join(workPath, bundle.header.path),
      sha256: bundle.header.sha256,
      size: bundle.header.size,
    };
    const objects = await mapBounded(
      bundle.translationUnits.map((member, index) => ({ member, index })),
      memberJobs,
      async ({ member, index }) => {
        const objectName = `member-${String(index).padStart(5, "0")}.o`;
        const compilation = staticHermesCBundleMemberCompilation(
          member,
          {
            executable: commands.compileExportMember.executable,
            args: [...commands.compileExportMember.args, member.path, "-o", objectName],
          },
          "export-member-object",
          memberCompilationPolicy,
          translationUnitBytes
        );
        return buildConvexWasmNativeObject({
          cacheLayout,
          cacheRoot,
          command: compilation.command,
          identity: identities.object,
          inputs: [header, {
            name: member.path,
            path: join(workPath, member.path),
            sha256: member.sha256,
            size: member.size,
          }],
          maxObjectBytes,
          outputName: objectName,
          runCommand,
          sourceName: member.path,
          stage: compilation.stage,
          verifyMaterials: verifyEmscriptenMaterials,
        });
      }
    );
    const objectNames = objects.map((_, index) =>
      `member-${String(index).padStart(5, "0")}.o`
    );
    const authenticateArchiveInputs = async () => {
      await authenticateStaticHermesCBundle(workPath, bundle, maxGeneratedCBytes);
      await mapBounded(
        objects.map((object, index) => ({ object, index })),
        memberJobs,
        async ({ object, index }) => {
          const { entry } = object;
          const digest = await hashPrivateRegularFile(
            entry.artifactPath,
            entry.artifactSize,
            `generated-C archive member ${objectNames[index]}`
          );
          if (digest.size !== entry.artifactSize || digest.sha256 !== entry.artifactSha256) {
            fail(`generated-C archive member ${objectNames[index]} does not match its identity`);
          }
        }
      );
    };
    await authenticateArchiveInputs();
    const archive = await ensureArtifactStage({
      authenticatePublicationPrerequisite: authenticateArchiveInputs,
      build: async (archiveWorkPath) => {
        const outputPath = join(archiveWorkPath, "unit.a");
        await writeConvexWasmStaticHermesMemberArchive(
          outputPath,
          objects.map(({ entry }) => ({
            path: entry.artifactPath,
            sha256: entry.artifactSha256,
            size: entry.artifactSize,
          })),
          objectNames
        );
        return { metadata: null, outputPath, timing: null };
      },
      cacheLayout,
      cacheRoot,
      extension: "a",
      identity: normalizeJson({
        ...identities.archive,
        bundleSha256: authenticated.artifactSha256,
        memberCompilationPolicy,
        members: objects.map(({ entry }, index) => ({
          name: objectNames[index],
          sha256: entry.artifactSha256,
          size: entry.artifactSize,
        })),
      }, "generated-C archive identity"),
      maxArtifactBytes: maxArchiveBytes,
      stage: "export-member-archive",
    });
    return {
      archive,
      kind: "success",
      linkInput: {
        name: linkInputName,
        path: archive.entry.artifactPath,
        sha256: archive.entry.artifactSha256,
        size: archive.entry.artifactSize,
      },
      objects,
      source,
    };
  } finally {
    await fs.rm(workPath, { recursive: true, force: true });
  }
}
