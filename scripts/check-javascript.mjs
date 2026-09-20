#!/usr/bin/env node

import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const execFileAsync = promisify(execFile);
const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(scriptPath), "..");

async function javascriptModules(directory) {
  const modules = [];
  const entries = await fs.readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      modules.push(...(await javascriptModules(path)));
    } else if (entry.isFile() && entry.name.endsWith(".mjs")) {
      modules.push(path);
    }
  }
  return modules;
}

const modules = await javascriptModules(join(repositoryRoot, "scripts"));
for (const path of modules) {
  await execFileAsync(process.execPath, ["--check", path], {
    cwd: repositoryRoot,
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
  });
}
for (const path of modules) {
  if (path !== scriptPath) {
    await import(pathToFileURL(path));
  }
}
process.stdout.write(`Checked ${modules.length} JavaScript modules.\n`);
