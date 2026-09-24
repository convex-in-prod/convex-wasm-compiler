#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReportFile } from "./lib/convex-wasm-request-envelope-report.mjs";

function usage() {
  return [
    "usage: create-convex-wasm-request-envelope-evidence-authority.mjs",
    "       --report MATRIX_REPORT.json --output EVIDENCE_AUTHORITY.json",
  ].join("\n");
}

export function parseArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      !["--output", "--report"].includes(option) ||
      value === undefined ||
      value.length === 0 ||
      values.has(option)
    ) {
      throw new Error(usage());
    }
    values.set(option, value);
  }
  for (const option of ["--output", "--report"]) {
    if (!values.has(option)) {
      throw new Error(`missing ${option}\n${usage()}`);
    }
  }
  return {
    outputPath: resolve(values.get("--output")),
    reportPath: resolve(values.get("--report")),
  };
}

export async function publishConvexWasmRequestEnvelopeEvidenceAuthority({ authority, outputPath }) {
  const finalPath = resolve(outputPath);
  const parent = dirname(finalPath);
  const [realParent, parentStat] = await Promise.all([fs.realpath(parent), fs.lstat(parent)]);
  if (
    realParent !== parent ||
    !parentStat.isDirectory() ||
    parentStat.uid !== process.getuid() ||
    (parentStat.mode & 0o777) !== 0o700
  ) {
    throw new Error(
      "request-envelope evidence authority parent must be a current-user-owned canonical 0700 directory"
    );
  }
  const temporaryPath = `${finalPath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const encoded = `${JSON.stringify(authority, null, 2)}\n`;
  try {
    const handle = await fs.open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(encoded, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await fs.link(temporaryPath, finalPath);
    } catch (error) {
      if (error !== null && typeof error === "object" && error.code === "EEXIST") {
        throw new Error(`evidence authority output already exists: ${finalPath}`, {
          cause: error,
        });
      }
      throw error;
    }
    const directoryHandle = await fs.open(parent, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
  return { bytes: Buffer.byteLength(encoded), path: finalPath };
}

export async function main(argumentsList) {
  const { outputPath, reportPath } = parseArguments(argumentsList);
  if (outputPath === reportPath) {
    throw new Error("request-envelope matrix report and evidence authority paths must be distinct");
  }
  const authority =
    await createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReportFile(reportPath);
  const published = await publishConvexWasmRequestEnvelopeEvidenceAuthority({
    authority,
    outputPath,
  });
  return { authority, published };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = await main(process.argv.slice(2));
  process.stdout.write(
    `${JSON.stringify({
      output: result.published.path,
      reportSha256: result.authority.reportSha256,
    })}\n`
  );
}
