#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));

export async function packageWslToolchain(archive, output) {
  const name = basename(archive);
  const version = /^convex-wasm-toolchain-([0-9.]+)-linux-x64\.tar\.gz$/u.exec(name)?.[1];
  if (version === undefined) throw new Error("WSL2 package requires a Linux x64 toolchain archive");
  const hash = createHash("sha256");
  for await (const bytes of createReadStream(archive)) hash.update(bytes);
  const sha256 = hash.digest("hex");
  if (await fs.readFile(`${archive}.sha256`, "utf8") !== `${sha256}  ${name}\n`) {
    throw new Error("Linux toolchain archive checksum differs");
  }
  await fs.mkdir(output, { mode: 0o700 });
  const stage = await fs.mkdtemp(join(output, ".wsl2-"));
  const zipName = `convex-wasm-toolchain-${version}-windows-x64-wsl2.zip`;
  const zip = join(output, zipName);
  try {
    await fs.copyFile(archive, join(stage, name));
    for (const file of ["convex-wasm.ps1", "install-wsl-toolchain.sh"]) {
      await fs.copyFile(join(scriptDirectory, "windows", file), join(stage, file));
    }
    await fs.copyFile(join(scriptDirectory, "../docs/toolchain-releases.md"), join(stage, "README.md"));
    await fs.writeFile(join(stage, "toolchain-release.json"), `${JSON.stringify({
      kind: "convex-wasm-wsl2-release-v1", archive: name, sha256,
    })}\n`);
    // The compressed Linux payload already preserves all executable/private modes.
    await promisify(execFile)("zip", ["-0", "-q", "-r", zip, "."], {
      cwd: stage, signal: AbortSignal.timeout(10 * 60_000),
    });
    const zipHash = createHash("sha256");
    for await (const bytes of createReadStream(zip)) zipHash.update(bytes);
    await fs.writeFile(`${zip}.sha256`, `${zipHash.digest("hex")}  ${zipName}\n`, { flag: "wx" });
    return zip;
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  if (process.argv.length !== 4) throw new Error("usage: package-wsl-toolchain.mjs LINUX_ARCHIVE OUTPUT_DIRECTORY");
  process.stdout.write(`${await packageWslToolchain(resolve(process.argv[2]), resolve(process.argv[3]))}\n`);
}
