import { spawn } from "node:child_process";

const TERMINATION_GRACE_MS = 5_000;

export function positiveIntegerEnvironment(environment, name, fallback) {
  const raw = environment[name];
  if (raw === undefined) return fallback;
  if (!/^[1-9][0-9]*$/u.test(raw)) {
    throw new Error(`${name} must be a positive integer`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

export function describeNativeCommandTermination(termination) {
  if (termination.kind === "outputLimit") {
    return `exceeded the ${termination.maximumBytes}-byte output limit`;
  }
  if (termination.kind === "timeout") {
    return `exceeded the ${termination.timeoutMs} ms timeout`;
  }
  throw new Error(`unsupported native command termination ${termination.kind}`);
}

export async function runBoundedNativeCommand({
  arguments: argumentsList,
  command,
  cwd,
  environment,
  maxOutputBytes,
  operation,
  timeoutMs,
}) {
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new Error(`${operation} output limit must be a positive safe integer`);
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`${operation} timeout must be a positive safe integer`);
  }

  const child = spawn(command, argumentsList, {
    cwd,
    detached: process.platform !== "win32",
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  const output = [];
  let outputBytes = 0;
  let termination;
  let forcedTermination;
  const kill = (signal) => {
    if (process.platform === "win32" || child.pid === undefined) {
      child.kill(signal);
      return;
    }
    try {
      process.kill(-child.pid, signal);
    } catch {
      // The process group may disappear between the timeout and this cleanup attempt.
      child.kill(signal);
    }
  };
  const stop = (value) => {
    if (termination !== undefined) return;
    termination = value;
    kill("SIGTERM");
    forcedTermination = setTimeout(() => kill("SIGKILL"), TERMINATION_GRACE_MS);
    forcedTermination.unref();
  };
  const append = (chunks) => (chunk) => {
    outputBytes += chunk.length;
    if (outputBytes > maxOutputBytes) {
      stop({ kind: "outputLimit", maximumBytes: maxOutputBytes });
      return;
    }
    chunks.push(chunk);
    output.push(chunk);
  };
  child.stdout.on("data", append(stdout));
  child.stderr.on("data", append(stderr));
  const timeout = setTimeout(() => stop({ kind: "timeout", timeoutMs }), timeoutMs);
  timeout.unref();
  try {
    const result = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    return {
      ...result,
      output: Buffer.concat(output),
      stderr: Buffer.concat(stderr),
      stdout: Buffer.concat(stdout),
      termination,
    };
  } finally {
    clearTimeout(timeout);
    clearTimeout(forcedTermination);
  }
}
