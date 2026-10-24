#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);

export async function smokeToolchainRelease(archive) {
  const digest = createHash("sha256");
  for await (const bytes of createReadStream(archive)) digest.update(bytes);
  if (await fs.readFile(`${archive}.sha256`, "utf8") !== `${digest.digest("hex")}  ${basename(archive)}\n`) {
    throw new Error("Toolchain archive checksum differs");
  }
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "convex-wasm-relocation-")));
  const python = (await exec("python3", ["-B", "-E", "-c", "import os, sys; print(os.path.realpath(sys.executable))"], {
    signal: AbortSignal.timeout(30_000),
  })).stdout.trim();
  const runtimePath = [dirname(process.execPath), dirname(python), "/usr/bin", "/bin"].join(":");
  const run = async (command, args) => (await exec(command, args, { cwd: root,
    env: { HOME: root, PATH: runtimePath, TMPDIR: root },
    signal: AbortSignal.timeout(30 * 60_000), maxBuffer: 16 * 1024 * 1024 })).stdout;
  try {
    await run("tar", ["-xzf", archive, "-C", root]);
    const relocated = join(root, "relocated toolchain");
    await fs.rename(join(root, "convex-wasm-compiler"), relocated);
    const executable = join(relocated, "convex-wasm");
    const verified = JSON.parse(await run(executable, ["verify"]));
    // Exercise the ordinary packaged-gate configuration and shipped evidence as
    // well as the lower-level compiler probe, with no source/build checkout.
    await run(process.execPath, ["--input-type=module", "-e", `
      import { promises as fs } from "node:fs";
      import { join } from "node:path";
      import { pathToFileURL } from "node:url";
      const [installation, work] = process.argv.slice(1);
      const library = join(installation, "lib/compiler");
      const load = name => import(pathToFileURL(join(library, "scripts", name)));
      const { createStaticHermesGateConfigArtifacts } = await load("create-gate-config.mjs");
      const { readConvexWasmValueCodecMatrixReport } = await load("lib/convex-wasm-committed-value-codec-report.mjs");
      const { createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReportFile,
        readConvexWasmRequestEnvelopeMatrixReport } = await load("lib/convex-wasm-request-envelope-report.mjs");
      const manifest = JSON.parse(await fs.readFile(join(installation, "toolchain.json"), "utf8"));
      const policy = JSON.parse(await fs.readFile(join(library, "examples/items/convex-wasm-gate-policy.json"), "utf8"));
      policy.command.environment.HOME = work;
      policy.command.environment.PATH = process.env.PATH;
      await createStaticHermesGateConfigArtifacts({ gateRoot: join(installation, "gate"), policy,
        cacheRoot: join(work, "cache"), precompilerPackageDirectory: join(installation, manifest.nativePackages.precompiler),
        artifactConfigOutputPath: join(work, "artifact-config.json"), platformLimitsOutputPath: join(work, "limits.json") });
      await readConvexWasmValueCodecMatrixReport(join(installation, "evidence/codec.json"));
      const request = join(installation, "evidence/request.json");
      await readConvexWasmRequestEnvelopeMatrixReport(request,
        await createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReportFile(request));
    `, relocated, root]);
    const smoke = JSON.parse(await run(executable, ["smoke", "--cache-root", join(root, "cache")]));
    for (const name of ["generatedLinkInput", "runtimeObject", "coreWasm", "aot"]) {
      if (smoke[name][1] !== "hit") throw new Error(`Relocated toolchain did not reuse ${name}`);
    }
    // The in-process probe cannot catch setup failures on the next CLI invocation.
    const repeated = JSON.parse(await run(executable, ["smoke", "--cache-root", join(root, "cache")]));
    for (const name of ["generatedLinkInput", "runtimeObject", "coreWasm", "aot"]) {
      if (!repeated[name].every(status => status === "hit")) throw new Error(`Repeated toolchain invocation did not reuse ${name}`);
    }
    return { ...verified, smoke, repeated };
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  if (process.argv.length !== 3) throw new Error("usage: smoke-toolchain-release.mjs ARCHIVE.tar.gz");
  process.stdout.write(`${JSON.stringify(await smokeToolchainRelease(resolve(process.argv[2])))}\n`);
}
