import { isAbsolute } from "node:path";
import { performance } from "node:perf_hooks";

import { runBoundedNativeCommand } from "./bounded-native-command.mjs";
import { ConvexWasmNativeCommandFailure } from "./convex-wasm-native-launch-scheduling.mjs";

const STAGE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;

export function createConvexWasmNativeCommandRunner({
  environment,
  maxOutputBytes,
  signal,
  timeoutMs,
}) {
  if (typeof environment !== "object" || environment === null || Array.isArray(environment)) {
    throw new Error("native command environment must be an explicit object");
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new Error("native command output limit must be a positive safe integer");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error("native command timeout must be a positive safe integer");
  }
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    throw new Error("native command cancellation signal must be an AbortSignal");
  }
  return async ({ command, stage, workPath }) => {
    if (typeof stage !== "string" || !STAGE_PATTERN.test(stage)) {
      throw new Error("native command stage must be a path-safe name");
    }
    if (typeof command?.executable !== "string" || !isAbsolute(command.executable)) {
      throw new Error(`${stage} executable must be an absolute path`);
    }
    if (!Array.isArray(command.args) || command.args.some((argument) => typeof argument !== "string")) {
      throw new Error(`${stage} arguments must be strings`);
    }
    if (typeof workPath !== "string" || !isAbsolute(workPath)) {
      throw new Error(`${stage} work path must be absolute`);
    }
    const start = performance.now();
    let result;
    try {
      result = await runBoundedNativeCommand({
        arguments: command.args,
        command: command.executable,
        cwd: workPath,
        environment,
        maxOutputBytes,
        operation: stage,
        signal,
        timeoutMs,
      });
    } catch (error) {
      const code = error instanceof Error && "code" in error ? error.code : undefined;
      const reason = ["EACCES", "ENOENT", "ENOTDIR"].includes(code) ? code : "other";
      throw new ConvexWasmNativeCommandFailure(
        `${stage} native command could not start`,
        { kind: "command-start", reason }
      );
    }
    if (result.termination !== undefined) {
      const terminationKind = result.termination.kind === "outputLimit"
        ? "output"
        : result.termination.kind === "aborted"
          ? "interrupted"
          : "timeout";
      throw new ConvexWasmNativeCommandFailure(
        `${stage} native command ${terminationKind}`,
        { kind: "guard-termination", terminationKind }
      );
    }
    if (result.code !== 0) {
      throw new ConvexWasmNativeCommandFailure(
        `${stage} native command failed`,
        { code: result.code, kind: "command-exit", signal: result.signal }
      );
    }
    return { wallMilliseconds: performance.now() - start };
  };
}
