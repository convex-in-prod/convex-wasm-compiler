import { spawn } from "node:child_process";

const FORWARDED_SIGNALS = ["SIGINT", "SIGTERM"];

export async function runVerifiedNativePackage({ argumentsList, loadPackage, packageDirectory }) {
  const verifiedPackage = await loadPackage(packageDirectory);
  let signalHandlers;
  try {
    const child = spawn(verifiedPackage.binaryPath, argumentsList, { stdio: "inherit" });
    signalHandlers = new Map(FORWARDED_SIGNALS.map((signal) => [signal, () => child.kill(signal)]));
    for (const [signal, handler] of signalHandlers) {
      process.once(signal, handler);
    }
    const result = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    if (result.signal === null && !Number.isInteger(result.code)) {
      throw new Error("verified native package exited without a code or signal");
    }
    return result;
  } finally {
    if (signalHandlers !== undefined) {
      for (const [signal, handler] of signalHandlers) {
        process.off(signal, handler);
      }
    }
  }
}

export function exitLikeNativeChild(result) {
  if (result.signal !== null) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.exitCode = result.code;
}
