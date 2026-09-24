const DARWIN_COMPILER_TIMING_RUNNER = `
timing_path=$1
shift
exec 3>&2
exec /usr/bin/time -l /bin/sh -c 'exec "$@" 2>&3' convex-wasm-compiler "$@" 2>"$timing_path"
`;

function fail(message) {
  throw new Error(`Convex Wasm compiler process: ${message}`);
}

export function convexWasmCompilerProcessCommand({
  availableJobs,
  cacheDir,
  executable,
  jobs,
  outputPath,
  platform,
  readyOutputPath,
  requestPath,
  timingPath,
}) {
  if (!Number.isSafeInteger(availableJobs) || availableJobs < 1) {
    fail("available compiler jobs must be a positive integer");
  }
  if (!Number.isSafeInteger(jobs) || jobs < 1 || jobs > availableJobs) {
    fail(`compiler process jobs must be an integer from 1 through ${availableJobs} available CPUs`);
  }
  if (typeof readyOutputPath !== "string" || readyOutputPath.length === 0) {
    fail("compiler process ready output path must be a non-empty string");
  }
  const compilerArguments = [
    executable,
    "--batch-request",
    requestPath,
    "--cache-dir",
    cacheDir,
    "--batch-output",
    outputPath,
    "--batch-ready-output",
    readyOutputPath,
    "--jobs",
    String(jobs),
  ];
  if (platform === "linux") {
    return {
      arguments: [
        "--quiet",
        "--format",
        '{"userSeconds":%U,"systemSeconds":%S,"maxRssKiB":%M}',
        "--output",
        timingPath,
        "--",
        ...compilerArguments,
      ],
      command: "/usr/bin/time",
      resourceUsageFormat: "linux-gnu-time-v1",
    };
  }
  if (platform === "darwin") {
    return {
      arguments: [
        "-c",
        DARWIN_COMPILER_TIMING_RUNNER,
        "convex-wasm-timed-compiler",
        timingPath,
        ...compilerArguments,
      ],
      command: "/bin/sh",
      resourceUsageFormat: "darwin-bsd-time-v1",
    };
  }
  fail(`unsupported compiler process platform ${platform}`);
}

export function parseConvexWasmCompilerResourceUsage(format, source) {
  if (format === "linux-gnu-time-v1") {
    let timing;
    try {
      timing = JSON.parse(source);
    } catch (error) {
      throw new Error("Convex Wasm compiler process: compiler produced invalid GNU time output", {
        cause: error,
      });
    }
    if (
      typeof timing.maxRssKiB !== "number" ||
      typeof timing.systemSeconds !== "number" ||
      typeof timing.userSeconds !== "number" ||
      ![timing.maxRssKiB, timing.systemSeconds, timing.userSeconds].every(
        (value) => Number.isFinite(value) && value >= 0
      )
    ) {
      fail("compiler process produced incomplete GNU time output");
    }
    return {
      maxRssKiB: timing.maxRssKiB,
      measurement: format,
      systemCpuMilliseconds: timing.systemSeconds * 1_000,
      userCpuMilliseconds: timing.userSeconds * 1_000,
    };
  }
  if (format === "darwin-bsd-time-v1") {
    const cpu = source.match(
      /([0-9]+(?:\.[0-9]+)?)\s+real\s+([0-9]+(?:\.[0-9]+)?)\s+user\s+([0-9]+(?:\.[0-9]+)?)\s+sys/u
    );
    const residentBytes = source.match(/([0-9]+)\s+maximum resident set size/u);
    if (cpu === null || residentBytes === null) {
      fail("compiler process produced incomplete macOS time output");
    }
    return {
      maxRssKiB: Math.ceil(Number(residentBytes[1]) / 1024),
      measurement: format,
      systemCpuMilliseconds: Number(cpu[3]) * 1_000,
      userCpuMilliseconds: Number(cpu[2]) * 1_000,
    };
  }
  fail(`unsupported compiler resource usage format ${format}`);
}
