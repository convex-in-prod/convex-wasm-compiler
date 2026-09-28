import { promises as fs } from "node:fs";
import { resolve } from "node:path";

export async function staticHermesHostArchives(hostBuildPath) {
  const boostRoot = resolve(hostBuildPath, "external/boost");
  let versionDirectories;
  try {
    versionDirectories = await fs.readdir(boostRoot, { withFileTypes: true });
  } catch (error) {
    throw new Error("Static Hermes host build omitted Boost context", { cause: error });
  }
  const available = [];
  for (const entry of versionDirectories) {
    if (!entry.isDirectory()) continue;
    const candidate = resolve(boostRoot, entry.name, "libs/context/libboost_context.a");
    try {
      if ((await fs.stat(candidate)).isFile()) available.push(candidate);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  if (available.length !== 1) {
    throw new Error("Static Hermes host build must provide exactly one Boost context archive");
  }
  return [
    resolve(hostBuildPath, "lib/libhermesvm_a.a"),
    resolve(hostBuildPath, "lib/VM/libhermesVMRuntime.a"),
    resolve(hostBuildPath, "API/hermes/libhermesapi.a"),
    resolve(hostBuildPath, "public/hermes/Public/libhermesPublic.a"),
    available[0],
    resolve(hostBuildPath, "jsi/libjsi.a"),
  ];
}
