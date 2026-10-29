#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import { join, resolve } from "node:path";

function median(values) {
  return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
}

async function arm(sourceRoot, outputRoot, variant, waves) {
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(sourceRoot, "scripts", "benchmark-cache-retention.mjs"), outputRoot, variant, String(waves)], {
      cwd: sourceRoot, stdio: ["ignore", "ignore", "pipe"],
    });
    let errorOutput = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (text) => { errorOutput = (errorOutput + text).slice(-16_384); });
    // The child enforces the 60-second measured arm. This outer bound additionally covers
    // fixture creation/imports and ensures a hung arm cannot occupy the host guard forever.
    const deadline = setTimeout(() => child.kill("SIGKILL"), 90_000);
    child.once("error", (error) => { clearTimeout(deadline); reject(error); });
    child.once("exit", (code, signal) => {
      clearTimeout(deadline);
      if (code === 0) resolve();
      else reject(new Error(`retention benchmark failed (${code ?? signal}): ${errorOutput}`));
    });
  });
  return JSON.parse(await fs.readFile(join(outputRoot, "result.json"), "utf8"));
}

async function main(args) {
  if (args.length !== 3) throw new Error("usage: compare-cache-retention-benchmarks.mjs BASELINE_SOURCE CANDIDATE_SOURCE NEW_OUTPUT_DIRECTORY");
  const [baseline, candidate, output] = args.map((path) => resolve(path));
  await fs.mkdir(output, { mode: 0o700 });
  const summaries = [];
  const sourceIdentities = {};
  for (const variant of ["metadata", "hardlink"]) {
    for (const waves of [4, 1]) {
      const pairs = [];
      for (let round = 0; round < 3; round += 1) {
        const pair = {};
        const order = round % 2 === 0 ? ["baseline", "candidate"] : ["candidate", "baseline"];
        for (const name of order) {
          const path = join(output, `${variant}-${waves}-${round + 1}-${name}`);
          pair[name] = await arm(name === "baseline" ? baseline : candidate, path, variant, waves);
          process.stdout.write(`${JSON.stringify({ variant, waves, round: round + 1, name, wallMilliseconds: pair[name].wallMilliseconds, peakRssKiB: pair[name].peakRssKiB })}\n`);
        }
        for (const name of ["baseline", "candidate"]) {
          const identity = { revision: pair[name].sourceRevision, digests: pair[name].sourceDigests };
          if (sourceIdentities[name] === undefined) sourceIdentities[name] = identity;
          else assert.deepEqual(identity, sourceIdentities[name], "source changed during comparison");
        }
        assert.deepEqual(pair.candidate.harnessDigests, pair.baseline.harnessDigests);
        assert.deepEqual(pair.candidate.policy, pair.baseline.policy);
        assert.equal(pair.candidate.node, pair.baseline.node);
        assert.equal(pair.candidate.platform, pair.baseline.platform);
        assert.equal(pair.candidate.kind, "convex-wasm-cache-retention-benchmark-v2");
        assert.equal(pair.baseline.kind, pair.candidate.kind);
        assert.equal(pair.candidate.inputTreeSha256, pair.baseline.inputTreeSha256);
        assert.equal(pair.candidate.remainingTreeSha256, pair.baseline.remainingTreeSha256);
        assert.ok(pair.candidate.retained.artifacts.length / pair.candidate.fixture.artifactCount >= 0.8);
        // Inode-dependent witnesses and plan hashes differ between independent fixtures.
        // Compare policy decisions, exact deterministic order, and measured occupancy.
        assert.equal(pair.candidate.fixture.inputAllocatedBytes, pair.baseline.fixture.inputAllocatedBytes);
        assert.deepEqual(pair.candidate.removed, pair.baseline.removed);
        assert.deepEqual(pair.candidate.retained, pair.baseline.retained);
        assert.equal(pair.candidate.remainingAllocatedBytes, pair.baseline.remainingAllocatedBytes);
        assert.equal(pair.candidate.diagnostics.phases.inventory.calls, 1);
        assert.equal(pair.candidate.waves.length, waves);
        assert.equal(pair.candidate.diagnostics.phases.immutableOccupancy.calls, 1 + waves);
        assert.equal(pair.candidate.termination, "no-eligible-candidates");
        pairs.push(pair);
      }
      const measurements = {};
      for (const name of ["baseline", "candidate"]) {
        measurements[name] = {
          wallMilliseconds: median(pairs.map((pair) => pair[name].wallMilliseconds)),
          cpuMicroseconds: median(pairs.map((pair) => pair[name].cpu.user + pair[name].cpu.system)),
          peakRssKiB: median(pairs.map((pair) => pair[name].peakRssKiB)),
        };
      }
      const wallSpeedup = measurements.baseline.wallMilliseconds / measurements.candidate.wallMilliseconds;
      const cpuRatio = measurements.candidate.cpuMicroseconds / measurements.baseline.cpuMicroseconds;
      const rssRatio = measurements.candidate.peakRssKiB / measurements.baseline.peakRssKiB;
      summaries.push({ variant, waves, measurements, wallSpeedup, cpuRatio, rssRatio,
        semanticAndInventoryGatesPassed: true,
        retainedAuthenticationScalingGate: "requires separate attribution; I/O counters do not prove authentication work",
        pairedWallRatios: pairs.map((pair) => pair.baseline.wallMilliseconds / pair.candidate.wallMilliseconds),
        performanceTargetMet: waves === 4 ? wallSpeedup >= 2 : wallSpeedup >= 1 / 1.1 && cpuRatio <= 1.1,
        rssTargetMet: rssRatio <= 1.2 });
      await fs.writeFile(join(output, "summary.json"), `${JSON.stringify(summaries, null, 2)}\n`, { mode: 0o600 });
    }
  }
  process.stdout.write(`${JSON.stringify(summaries)}\n`);
}

if (import.meta.main) await main(process.argv.slice(2));
