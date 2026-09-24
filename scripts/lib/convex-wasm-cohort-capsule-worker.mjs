import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";

const ownedWorkerResults = new WeakSet();
const workerRole = "convex-wasm-cohort-capsule-admission";

export function isOwnedConvexWasmCohortCapsuleWorkerResult(value) {
  return ownedWorkerResults.has(value);
}

export function createConvexWasmCohortCapsuleWorkerPool({ jobs }) {
  if (!Number.isSafeInteger(jobs) || jobs < 1) {
    throw new Error("capsule admission requires a positive launch job limit");
  }
  const limit = Math.min(2, jobs);
  const workers = [];
  const queued = [];
  const pending = new Set();
  let nextId = 0;
  let closing;
  let failure;
  let stopping = false;

  const rejectPool = (reason) => {
    failure ??= reason;
    for (const task of queued.splice(0)) task.reject(reason);
  };
  const assign = (record) => {
    if (record.task !== undefined || failure !== undefined || queued.length === 0) return;
    const task = queued.shift();
    record.task = task;
    // Only first-open JSON admission runs remotely. Command values are cloned for validation;
    // the resource guard stays parent-owned. Restoration rebinds both before any native work.
    try {
      const { resourceGuard: _resourceGuard, ...artifactConfig } = task.arguments.artifactConfig;
      record.worker.postMessage({
        id: task.id,
        arguments: { ...task.arguments, artifactConfig },
      });
    } catch (error) {
      record.task = undefined;
      task.reject(error);
      rejectPool(error);
    }
  };
  const startWorker = () => {
    const worker = new Worker(new URL(import.meta.url), { workerData: { role: workerRole } });
    const record = { failure: undefined, restoring: false, task: undefined, worker };
    workers.push(record);
    worker.on("error", (error) => {
      record.failure ??= error;
      // A response can still be restoring parent authority when the worker exits. Its task owns
      // that restoration until settlement, so close must not lose it through an early rejection.
      if (!record.restoring) {
        record.task?.reject(error);
        record.task = undefined;
      }
      rejectPool(error);
    });
    worker.on("exit", (code) => {
      if (stopping) return;
      const error = new Error(`capsule admission worker exited before drainage with code ${code}`);
      record.failure ??= error;
      if (!record.restoring) {
        record.task?.reject(error);
        record.task = undefined;
      }
      rejectPool(error);
    });
    worker.on("message", async (message) => {
      const task = record.task;
      try {
        if (task === undefined || task.id !== message.id) {
          throw new Error("capsule admission worker response does not match its assigned cohort");
        }
        if (message.status === "error") {
          task.reject(message.error);
        } else if (message.status === "miss") {
          task.resolve(undefined);
        } else if (message.status === "hit") {
          record.restoring = true;
          ownedWorkerResults.add(message.result);
          const { restoreConvexWasmOfficialOutputCohortCapsuleFromWorker } =
            await import("./convex-wasm-official-output-cohort-capsule.mjs");
          const restored = await restoreConvexWasmOfficialOutputCohortCapsuleFromWorker(
            message.result,
            task.arguments
          );
          if (record.failure !== undefined) throw record.failure;
          task.resolve(restored);
        } else {
          throw new Error("capsule admission worker returned an unsupported outcome");
        }
      } catch (error) {
        const reason = record.failure ?? error;
        task?.reject(reason);
        rejectPool(reason);
      } finally {
        ownedWorkerResults.delete(message.result);
        record.restoring = false;
        record.task = undefined;
        assign(record);
      }
    });
    return record;
  };

  return Object.freeze({
    probe(arguments_) {
      if (closing !== undefined) throw new Error("capsule admission pool is closed");
      if (failure !== undefined) throw failure;
      const operation = (async () => {
        const { isConvexWasmOfficialOutputCohortCapsulePresent } =
          await import("./convex-wasm-official-output-cohort-capsule.mjs");
        if (!(await isConvexWasmOfficialOutputCohortCapsulePresent(arguments_))) return undefined;
        if (failure !== undefined) throw failure;
        return await new Promise((resolve, reject) => {
          queued.push({ arguments: arguments_, id: nextId++, reject, resolve });
          const idle = workers.find((record) => record.task === undefined);
          try {
            if (idle !== undefined) assign(idle);
            else if (workers.length < limit) assign(startWorker());
          } catch (error) {
            rejectPool(error);
          }
        });
      })();
      pending.add(operation);
      void operation.then(
        () => pending.delete(operation),
        () => pending.delete(operation)
      );
      return operation;
    },
    close() {
      closing ??= (async () => {
        await Promise.allSettled([...pending]);
        stopping = true;
        const terminations = await Promise.allSettled(
          workers.map(({ worker }) => Promise.resolve().then(() => worker.terminate()))
        );
        const rejected = terminations.find(({ status }) => status === "rejected");
        if (rejected !== undefined) throw rejected.reason;
      })();
      return closing;
    },
  });
}

if (!isMainThread && workerData?.role === workerRole) {
  let modules;
  // Defer imports until this module has finished evaluation: descriptor admission imports the
  // owned-result predicate above, while the capsule itself imports the artifact pipeline.
  parentPort.on("message", async ({ id, arguments: arguments_ }) => {
    try {
      modules ??= Promise.all([
        import("./convex-wasm-official-output-cohort-capsule.mjs"),
        import("./convex-wasm-artifact-pipeline.mjs"),
      ]);
      const [capsules, pipeline] = await modules;
      const capsule = await capsules.probeConvexWasmOfficialOutputCohortCapsule(arguments_);
      parentPort.postMessage(
        capsule === undefined
          ? { id, status: "miss" }
          : {
              id,
              result: pipeline.exportConvexWasmCohortPlanningWorkerResult(capsule),
              status: "hit",
            }
      );
    } catch (error) {
      parentPort.postMessage({ error, id, status: "error" });
    }
  });
}
