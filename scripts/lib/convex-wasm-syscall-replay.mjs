// Replays SDK JSON syscalls, including their normal guest-side serialization.
// It does not replace the typed capability bridge or model database timing.
export function prepareConvexWasmSyscallReplay(calls) {
  if (!Array.isArray(calls)) throw new Error("Replay calls must be an array");
  const epochs = [];
  let reads = [];
  const queries = new Map();
  const events = new Set();
  let lastReadCompletion = -1;
  let lastStart = -1;
  let lastWriteCompletion = -1;
  for (let index = 0; index < calls.length; index++) {
    const call = calls[index];
    if (call.sequence !== index || !["syscall", "asyncSyscall"].includes(call.channel) ||
        typeof call.operation !== "string" || typeof call.arguments !== "string" || typeof call.result !== "string" ||
        !Number.isSafeInteger(call.startedEvent) || !Number.isSafeInteger(call.completedEvent) ||
        call.startedEvent <= lastStart ||
        call.completedEvent <= call.startedEvent || call.completedEvent >= calls.length * 2 ||
        events.has(call.startedEvent) || events.has(call.completedEvent)) throw new Error(`Invalid replay call ${index}`);
    lastStart = call.startedEvent;
    events.add(call.startedEvent);
    events.add(call.completedEvent);
    const args = parseReplayJson(call.arguments);
    const result = parseReplayJson(call.result);
    const entry = { operation: call.operation, arguments: args, result: call.result };
    switch (call.operation) {
      case "1.0/get":
        if (call.channel !== "asyncSyscall") throw new Error("Get replay requires an async call");
        if (call.startedEvent < lastWriteCompletion) throw new Error("Replay does not support reads overlapping a write");
        reads.push(entry);
        lastReadCompletion = Math.max(lastReadCompletion, call.completedEvent);
        break;
      case "1.0/queryStream":
        if (call.channel !== "syscall" || !Number.isSafeInteger(result.queryId) || queries.has(result.queryId)) throw new Error("Invalid replay query start");
        if (call.startedEvent < lastWriteCompletion) throw new Error("Replay does not support reads overlapping a write");
        entry.next = [];
        queries.set(result.queryId, { entry, completedEvent: call.completedEvent });
        reads.push(entry);
        break;
      case "1.0/queryStreamNext": {
        const query = queries.get(args.queryId);
        if (call.channel !== "asyncSyscall" || query === undefined || typeof result.done !== "boolean" ||
            query.completedEvent > call.startedEvent ||
            (query.entry.next.length > 0 && parseReplayJson(query.entry.next.at(-1)).done)) throw new Error("Invalid replay query continuation");
        query.entry.next.push(call.result);
        query.completedEvent = call.completedEvent;
        lastReadCompletion = Math.max(lastReadCompletion, call.completedEvent);
        break;
      }
      case "1.0/queryCleanup": {
        const query = queries.get(args.queryId);
        if (call.channel !== "syscall" || query === undefined || query.completedEvent > call.startedEvent) throw new Error("Invalid replay query cleanup");
        query.entry.cleanup = call.result;
        queries.delete(args.queryId);
        break;
      }
      case "1.0/insert":
      case "1.0/shallowMerge":
      case "1.0/replace":
      case "1.0/remove":
      case "1.0/schedule":
      case "1.0/cancel_job":
        // Independent reads can reorder within one snapshot. They cannot
        // cross a write, since later reads may observe different data.
        if (call.channel !== "asyncSyscall" || queries.size !== 0 || lastReadCompletion > call.startedEvent) throw new Error("Replay does not support reads overlapping a write");
        epochs.push({ reads, write: entry });
        reads = [];
        lastWriteCompletion = Math.max(lastWriteCompletion, call.completedEvent);
        break;
      default:
        throw new Error(`Unsupported replay operation at call ${index}`);
    }
  }
  if (queries.size !== 0) throw new Error("Replay capture contains unclosed queries");
  epochs.push({ reads, write: null });
  return { epochs, calls: calls.length };
}

export function createConvexWasmSyscallReplay(prepared) {
  let epochIndex = 0;
  let remaining = prepared.epochs[0].reads.slice();
  const queries = new Map();
  let nextQuery = 1;
  let calls = 0;
  let failure;
  function fail(message) {
    if (failure === undefined) failure = new Error(message);
    throw failure;
  }
  function invoke(channel, operation, serializedArgs) {
    if (failure !== undefined) throw failure;
    let args;
    try {
      args = parseReplayJson(serializedArgs);
    } catch (error) {
      failure = error;
      throw error;
    }
    const isSync = operation === "1.0/queryStream" || operation === "1.0/queryCleanup";
    if (channel !== (isSync ? "syscall" : "asyncSyscall")) fail(`Replay channel differs at call ${calls}`);
    calls++;
    if (operation === "1.0/queryStreamNext" || operation === "1.0/queryCleanup") {
      if (Object.keys(args).length !== 1) fail("Unexpected replay query arguments");
      const query = queries.get(args.queryId);
      if (query === undefined) fail("Replay query is not open");
      if (operation === "1.0/queryStreamNext") {
        if (query.index === query.entry.next.length) fail("Replay query has no remaining result");
        return Promise.resolve(query.entry.next[query.index++]);
      }
      if (query.index !== query.entry.next.length) fail("Replay query closed with unread results");
      queries.delete(args.queryId);
      return query.entry.cleanup;
    }
    const read = operation === "1.0/get" || operation === "1.0/queryStream";
    let entry;
    if (read) {
      const index = remaining.findIndex(value => value.operation === operation && equalJson(value.arguments, args));
      if (index === -1) fail(`Replay read differs in epoch ${epochIndex} (${operation})`);
      [entry] = remaining.splice(index, 1);
    } else {
      entry = prepared.epochs[epochIndex].write;
      if (remaining.length !== 0 || queries.size !== 0 || entry === null ||
          entry.operation !== operation || !equalJson(entry.arguments, args)) {
        // Request and response values may contain private data.
        fail(`Replay write differs in epoch ${epochIndex} (${operation})`);
      }
      epochIndex++;
      remaining = prepared.epochs[epochIndex].reads.slice();
    }
    if (operation === "1.0/queryStream") {
      const queryId = nextQuery++;
      queries.set(queryId, { entry, index: 0 });
      return JSON.stringify({ queryId });
    }
    return Promise.resolve(entry.result);
  }
  return {
    Convex: {
      syscall(operation, args) { return invoke("syscall", operation, args); },
      asyncSyscall(operation, args) { return invoke("asyncSyscall", operation, args); },
      jsSyscall() { fail("Value syscalls are outside this JSON replay contract"); },
    },
    assertComplete() {
      if (failure !== undefined) throw failure;
      if (epochIndex !== prepared.epochs.length - 1 || remaining.length !== 0 || queries.size !== 0 || calls !== prepared.calls) throw new Error(`Incomplete syscall replay: ${calls} calls, ${prepared.calls} expected`);
      return { calls, writeEpochs: epochIndex };
    },
  };
}

function parseReplayJson(serialized) {
  if (typeof serialized !== "string") throw new Error("Replay JSON must be a string");
  try {
    return JSON.parse(serialized);
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    // SyntaxError messages can include a slice of the private input.
    throw new Error("Malformed replay JSON");
  }
}

function equalJson(left, right) {
  if (left === right) return true;
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") return false;
  if (Array.isArray(left) !== Array.isArray(right)) return false;
  const keys = Object.keys(left);
  if (keys.length !== Object.keys(right).length) return false;
  return keys.every(key => Object.prototype.hasOwnProperty.call(right, key) && equalJson(left[key], right[key]));
}
