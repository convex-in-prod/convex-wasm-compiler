//! Offline typed imports. Requests and writes are matched outside guest code.
//! Unknown capabilities trap; a trace cannot pass by omitting an operation.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::{Value, json};
use wasmtime::{Caller, Error, ExternType, Linker, Module, Val};

use crate::{
    capability_replay::{QueryResponse, Replay, Trace},
    capability_replay_codec as codec,
    wasmtime_wasi::{WasiAccess, WasiState, checked_offset, memory},
};

type HostResult<T> = Result<T, Error>;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub selector: u64,
    pub timestamp_ms: f64,
    pub args: Value,
    pub expected: Value,
    pub replay: Trace,
    pub entropy: Vec<Entropy>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entropy {
    kind: String,
    value: Value,
}

enum Stored {
    Value(Vec<u8>),
    Payload(Vec<u8>),
    Request(Value),
}

enum Operation {
    Get(Value),
    Query(codec::QueryTerminal, Value),
    Next(u32),
    Write(&'static str, Value),
}

enum Stream {
    Unstarted(Value),
    Started(u32),
}

pub struct State {
    pub wasi: WasiState,
    pub host_time: Duration,
    pub host_calls: usize,
    pub console_calls: usize,
    pub object_layouts: [u64; 4],
    pub gc: [u64; 6],
    pub environment_reads: BTreeMap<String, Option<String>>,
    environment: BTreeMap<String, Option<String>>,
    timestamp_ms: f64,
    started: Instant,
    replay: Option<Replay>,
    input: Vec<u8>,
    output: Option<Value>,
    entropy: VecDeque<Entropy>,
    values: BTreeMap<i64, Stored>,
    next_value: i64,
    pending: VecDeque<(i32, Operation)>,
    operations: BTreeMap<i32, Option<Vec<u8>>>,
    ready: VecDeque<i32>,
    announced: Option<(i32, bool)>,
    next_operation: i32,
    streams: BTreeMap<u32, Stream>,
    next_stream: u32,
    closed_streams: BTreeSet<u32>,
    failed: bool,
}

impl WasiAccess for State {
    fn wasi(&self) -> &WasiState {
        &self.wasi
    }
    fn wasi_mut(&mut self) -> &mut WasiState {
        &mut self.wasi
    }
}

impl State {
    pub fn new(environment: BTreeMap<String, Option<String>>) -> Self {
        Self {
            wasi: WasiState {
                args: vec![],
                stdout: vec![],
                stderr: vec![],
            },
            host_time: Duration::ZERO,
            host_calls: 0,
            console_calls: 0,
            object_layouts: [0; 4],
            gc: [0; 6],
            environment_reads: BTreeMap::new(),
            environment,
            timestamp_ms: 0.0,
            started: Instant::now(),
            replay: None,
            input: vec![],
            output: None,
            entropy: VecDeque::new(),
            values: BTreeMap::new(),
            next_value: 1,
            pending: VecDeque::new(),
            operations: BTreeMap::new(),
            ready: VecDeque::new(),
            announced: None,
            next_operation: 1,
            streams: BTreeMap::new(),
            next_stream: 1,
            closed_streams: BTreeSet::new(),
            failed: false,
        }
    }

    pub fn begin(&mut self, case: &Case) -> HostResult<()> {
        self.quiescent()?;
        if self.replay.is_some() || !case.timestamp_ms.is_finite() || !case.args.is_object() {
            return Err(Error::msg("Invalid replay invocation start"));
        }
        // Async handles are invocation-local in the backend. The guest indexes
        // pending-Promise arrays by these handles, so carrying the counters into
        // the next invocation introduces unbounded replay-only allocation/work.
        self.next_operation = 1;
        self.next_stream = 1;
        self.replay = Some(Replay::new(case.replay.clone()).map_err(Error::msg)?);
        self.input = codec::encode_value(&case.args, false).map_err(Error::msg)?;
        self.output = None;
        self.entropy = case.entropy.clone().into();
        self.timestamp_ms = case.timestamp_ms;
        self.started = Instant::now();
        self.host_time = Duration::ZERO;
        self.host_calls = 0;
        self.console_calls = 0;
        self.object_layouts = [0; 4];
        self.gc = [0; 6];
        self.closed_streams.clear();
        self.wasi.stdout.clear();
        self.wasi.stderr.clear();
        Ok(())
    }

    pub fn finish(&mut self, case: &Case) -> HostResult<usize> {
        self.quiescent()?;
        // Normalize the capture's JSON Number spelling with the same transport
        // used for input, without discarding any fields or array ordering.
        let expected = codec::decode_value(
            &codec::encode_value(&case.expected, false).map_err(Error::msg)?,
            false,
        )
        .map_err(Error::msg)?;
        if !self.entropy.is_empty() || self.output.as_ref() != Some(&expected) {
            return Err(Error::msg("Replay result or entropy consumption differs"));
        }
        let count = self
            .replay
            .as_ref()
            .ok_or_else(|| Error::msg("Replay is not active"))?
            .finish()
            .map_err(Error::msg)?;
        self.replay = None;
        Ok(count)
    }

    fn quiescent(&self) -> HostResult<()> {
        if self.failed
            || !self.values.is_empty()
            || !self.pending.is_empty()
            || !self.streams.is_empty()
            || !self.operations.is_empty()
            || !self.ready.is_empty()
            || self.announced.is_some()
        {
            return Err(Error::msg(format!(
                "Replay host is not quiescent: failed={}, values={}, operations={}, ready={}, announced={}, started={}, pending={}, streams={}",
                self.failed,
                self.values.len(),
                self.operations.len(),
                self.ready.len(),
                self.announced.is_some(),
                self.next_operation - 1,
                self.pending.len(),
                self.streams.len()
            )));
        }
        Ok(())
    }

    fn authorize(&self, capability: i64, initialization: bool) -> HostResult<()> {
        let expected = if self.replay.is_some() { 1 } else { 0 };
        if capability != expected || (!initialization && expected == 0) {
            return Err(Error::msg("Invalid replay capability"));
        }
        Ok(())
    }

    fn replay(&mut self) -> HostResult<&mut Replay> {
        self.replay
            .as_mut()
            .ok_or_else(|| Error::msg("Replay is not active"))
    }

    fn insert(&mut self, value: Stored) -> HostResult<i64> {
        let handle = self.next_value;
        self.next_value = handle
            .checked_add(1)
            .ok_or_else(|| Error::msg("Replay value handle overflow"))?;
        self.values.insert(handle, value);
        Ok(handle)
    }

    fn enqueue(&mut self, operation: Operation) -> HostResult<i32> {
        let handle = self.next_operation;
        self.next_operation = handle
            .checked_add(1)
            .ok_or_else(|| Error::msg("Replay operation handle overflow"))?;
        self.pending.push_back((handle, operation));
        Ok(handle)
    }

    fn announce(&mut self) -> HostResult<i32> {
        if self.announced.is_some() {
            return Err(Error::msg("Previous replay completion is unconsumed"));
        }
        match self.ready.pop_front() {
            None => Ok(0),
            Some(handle) => {
                self.announced = Some((handle, false));
                Ok(handle)
            }
        }
    }

    fn write(&mut self, operation: &str, args: Value) -> HostResult<Option<Vec<u8>>> {
        // Consuming a request in the matcher does not mean the guest observed
        // its result. Writes require all preceding completions to be consumed.
        if !self.operations.is_empty() || self.announced.is_some() {
            return Err(Error::msg("Replay write overlaps a pending operation"));
        }
        let result = self.replay()?.write(operation, &args).map_err(Error::msg)?;
        // Void completions have no payload handle in the typed ABI. A null
        // value is a real payload and the guest correctly rejects it here.
        let bytes = if matches!(operation, "1.0/insert" | "1.0/schedule") {
            Some(codec::encode_value(&result, false).map_err(Error::msg)?)
        } else {
            None
        };
        Ok(bytes)
    }

    fn stream_handle(&mut self, id: u32) -> HostResult<u32> {
        let stream = self
            .streams
            .remove(&id)
            .ok_or_else(|| Error::msg("Replay stream is not open"))?;
        let handle = match stream {
            Stream::Started(handle) => handle,
            Stream::Unstarted(query) => {
                match self.replay()?.query(query, false).map_err(Error::msg)? {
                    QueryResponse::Stream(handle) => handle,
                    _ => return Err(Error::msg("Replay stream returned a bulk result")),
                }
            }
        };
        self.streams.insert(id, Stream::Started(handle));
        Ok(handle)
    }

    fn close_stream(&mut self, id: u32) -> HostResult<()> {
        if self
            .pending
            .iter()
            .any(|(_, operation)| matches!(operation, Operation::Next(stream) if *stream == id))
        {
            return Err(Error::msg(
                "Replay stream closed with a pending continuation",
            ));
        }
        let handle = self.stream_handle(id)?;
        self.replay()?.stream_close(handle).map_err(Error::msg)?;
        self.streams.remove(&id);
        Ok(())
    }

    fn wait(&mut self) -> HostResult<i32> {
        // Starting a typed capability only queues its descriptor. Match and
        // execute the next compatible read wave on wait, as the backend does.
        // Poll never advances queued writes before guest microtasks observe the
        // preceding wave. This preserves write barriers without rejecting
        // valid callers that enqueue several mutations together.
        if self.announced.is_some() || !self.ready.is_empty() {
            return self.announce();
        }
        if !self.operations.is_empty() {
            return Err(Error::msg("Replay completion has no announcement"));
        }
        let Some((_, first)) = self.pending.front() else {
            return Err(Error::msg("Replay wait has no queued operation"));
        };
        let group = match first {
            Operation::Get(_) => 1,
            Operation::Query(_, _) | Operation::Next(_) => 2,
            Operation::Write(_, _) => 0,
        };
        loop {
            let (handle, operation) = self
                .pending
                .pop_front()
                .ok_or_else(|| Error::msg("Replay operation disappeared"))?;
            let result = match operation {
                Operation::Get(args) => {
                    let result = self.replay()?.get(&args).map_err(Error::msg)?;
                    Some(codec::encode_document(&result).map_err(Error::msg)?)
                }
                Operation::Query(terminal, query) => {
                    let QueryResponse::Documents(documents) =
                        self.replay()?.query(query, true).map_err(Error::msg)?
                    else {
                        return Err(Error::msg("Bulk replay returned a stream"));
                    };
                    Some(
                        match terminal {
                            codec::QueryTerminal::Collect => codec::encode_documents(&documents),
                            codec::QueryTerminal::First => {
                                codec::encode_document(documents.first().unwrap_or(&Value::Null))
                            }
                            codec::QueryTerminal::Unique if documents.len() <= 1 => {
                                codec::encode_document(documents.first().unwrap_or(&Value::Null))
                            }
                            _ => return Err(Error::msg("Unsupported replay query result")),
                        }
                        .map_err(Error::msg)?,
                    )
                }
                Operation::Next(id) => {
                    let stream = self.stream_handle(id)?;
                    let result = self.replay()?.stream_next(stream).map_err(Error::msg)?;
                    if result["done"] == true {
                        self.close_stream(id)?;
                        self.closed_streams.insert(id);
                    }
                    Some(codec::encode_stream_result(&result).map_err(Error::msg)?)
                }
                Operation::Write(name, args) => self.write(name, args)?,
            };
            self.operations.insert(handle, result);
            self.ready.push_back(handle);
            let compatible = match self.pending.front() {
                Some((_, Operation::Get(_))) => group == 1,
                Some((_, Operation::Query(_, _) | Operation::Next(_))) => group == 2,
                _ => false,
            };
            if !compatible {
                break;
            }
        }
        self.announce()
    }

    fn completion_status(&mut self, handle: i32) -> HostResult<i32> {
        if self.announced != Some((handle, false)) {
            return Err(Error::msg("Invalid replay status observation"));
        }
        self.announced = Some((handle, true));
        Ok(0)
    }

    fn take_completion(&mut self, handle: i32) -> HostResult<i64> {
        if self.announced != Some((handle, true)) {
            return Err(Error::msg("Invalid replay completion consumption"));
        }
        self.announced = None;
        match self
            .operations
            .remove(&handle)
            .ok_or_else(|| Error::msg("Missing replay completion"))?
        {
            Some(bytes) => self.insert(Stored::Value(bytes)),
            None => Ok(0),
        }
    }

    fn entropy(&mut self, kind: &str) -> HostResult<Value> {
        let value = self
            .entropy
            .pop_front()
            .ok_or_else(|| Error::msg("Replay entropy is exhausted"))?;
        if value.kind != kind {
            return Err(Error::msg("Replay entropy kind differs"));
        }
        Ok(value.value)
    }
}

struct Arguments<'a>(&'a [Val]);
impl Arguments<'_> {
    fn i32(&self, index: usize) -> HostResult<i32> {
        self.0
            .get(index)
            .and_then(Val::i32)
            .ok_or_else(|| Error::msg("Invalid replay i32 argument"))
    }
    fn i64(&self, index: usize) -> HostResult<i64> {
        self.0
            .get(index)
            .and_then(Val::i64)
            .ok_or_else(|| Error::msg("Invalid replay i64 argument"))
    }
    fn f64(&self, index: usize) -> HostResult<f64> {
        self.0
            .get(index)
            .and_then(Val::f64)
            .ok_or_else(|| Error::msg("Invalid replay f64 argument"))
    }
    fn bytes(&self, caller: &mut Caller<'_, State>, index: usize) -> HostResult<Vec<u8>> {
        let offset = checked_offset(self.i32(index)?)?;
        let length = checked_offset(self.i32(index + 1)?)?;
        if length > 16 * 1024 * 1024 {
            return Err(Error::msg("Replay import exceeds byte limit"));
        }
        let memory = memory(caller)?;
        let bytes = memory
            .data(&*caller)
            .get(
                offset
                    ..offset
                        .checked_add(length)
                        .ok_or_else(|| Error::msg("Replay memory overflow"))?,
            )
            .ok_or_else(|| Error::msg("Replay import exceeds guest memory"))?;
        Ok(bytes.to_vec())
    }
    fn string(&self, caller: &mut Caller<'_, State>, index: usize) -> HostResult<String> {
        String::from_utf8(self.bytes(caller, index)?)
            .map_err(|_| Error::msg("Invalid replay UTF-8"))
    }
    fn optional_string(
        &self,
        caller: &mut Caller<'_, State>,
        index: usize,
    ) -> HostResult<Option<String>> {
        if self.i32(index)? == 0 && self.i32(index + 1)? == 0 {
            Ok(None)
        } else {
            Ok(Some(self.string(caller, index)?))
        }
    }
    fn copy(&self, caller: &mut Caller<'_, State>, index: usize, bytes: &[u8]) -> HostResult<i32> {
        if checked_offset(self.i32(index + 1)?)? < bytes.len() {
            return Err(Error::msg("Replay destination is too short"));
        }
        memory(caller)?.write(caller, checked_offset(self.i32(index)?)?, bytes)?;
        i32::try_from(bytes.len()).map_err(|_| Error::msg("Replay payload exceeds i32"))
    }
}

fn dispatch(
    caller: &mut Caller<'_, State>,
    name: &str,
    args: Arguments<'_>,
) -> HostResult<Option<Val>> {
    let result = match name {
        "convex_capability_current" => Val::I64(if caller.data().replay.is_some() { 1 } else { 0 }),
        "convex_typed_value_abi_v1" => Val::I32(1),
        "convex_execution_observation_enabled" => Val::I32(1),
        "convex_has_developer_error" => Val::I32(0),
        "convex_observe_object_layouts" => {
            for index in 0..4 {
                caller.data_mut().object_layouts[index] = u64::try_from(args.i64(index)?)
                    .map_err(|_| Error::msg("Negative replay layout counter"))?;
            }
            return Ok(None);
        }
        "convex_observe_gc" => {
            for index in 0..6 {
                caller.data_mut().gc[index] = u64::try_from(args.i64(index)?)
                    .map_err(|_| Error::msg("Negative replay GC counter"))?;
            }
            return Ok(None);
        }
        "convex_invocation_unix_timestamp_ms" => Val::F64(caller.data().timestamp_ms.to_bits()),
        "convex_performance_now" => {
            caller.data().authorize(args.i64(0)?, false)?;
            Val::F64((caller.data().started.elapsed().as_secs_f64() * 1000.0).to_bits())
        }
        "convex_guest_value_request_len" | "convex_guest_value_request_binary_v1" => {
            Val::I32(i32::try_from(caller.data().input.len())?)
        }
        "convex_guest_value_request_copy" => {
            let input = caller.data().input.clone();
            Val::I32(args.copy(caller, 0, &input)?)
        }
        "convex_guest_value_result_binary" => {
            if caller.data().output.is_some() {
                return Err(Error::msg("Replay result was set twice"));
            }
            let value = codec::decode_value(&args.bytes(caller, 0)?, false).map_err(Error::msg)?;
            caller.data_mut().output = Some(value);
            return Ok(None);
        }
        "convex_capability_start_get" => {
            caller.data().authorize(args.i64(0)?, false)?;
            let id = args.string(caller, 1)?;
            let table = args.optional_string(caller, 3)?;
            let system = args.i32(5)?;
            if !matches!(system, 0 | 1) {
                return Err(Error::msg("Invalid replay system flag"));
            }
            let mut request = json!({"id": id, "isSystem": system != 0});
            if let Some(table) = table {
                request["table"] = Value::String(table);
            }
            Val::I32(caller.data_mut().enqueue(Operation::Get(request))?)
        }
        "convex_capability_query_record" => {
            caller.data().authorize(args.i64(0)?, false)?;
            let (terminal, query) =
                codec::decode_query(&args.bytes(caller, 1)?).map_err(Error::msg)?;
            if terminal == codec::QueryTerminal::Stream {
                let state = caller.data_mut();
                let handle = state.next_stream;
                state.next_stream = handle
                    .checked_add(1)
                    .ok_or_else(|| Error::msg("Replay stream handle overflow"))?;
                state.streams.insert(handle, Stream::Unstarted(query));
                Val::I32(i32::try_from(handle)?)
            } else {
                Val::I32(
                    caller
                        .data_mut()
                        .enqueue(Operation::Query(terminal, query))?,
                )
            }
        }
        "convex_async_query_stream_next" => {
            let stream = u32::try_from(args.i32(0)?)?;
            if !caller.data().streams.contains_key(&stream) {
                return Err(Error::msg("Replay stream is not open"));
            }
            Val::I32(caller.data_mut().enqueue(Operation::Next(stream))?)
        }
        "convex_async_query_stream_close" => {
            let stream = u32::try_from(args.i32(0)?)?;
            if !caller.data_mut().closed_streams.remove(&stream) {
                caller.data_mut().close_stream(stream)?;
            }
            return Ok(None);
        }
        "convex_capability_start_write" => {
            caller.data().authorize(args.i64(0)?, false)?;
            let kind = args.i32(1)?;
            let table = args.optional_string(caller, 2)?;
            let id = args.optional_string(caller, 4)?;
            let mut request = json!({});
            if let Some(table) = table {
                request["table"] = Value::String(table);
            }
            if let Some(id) = id {
                request["id"] = Value::String(id);
            }
            if kind != 4 {
                request["value"] =
                    codec::decode_value(&args.bytes(caller, 6)?, kind == 2).map_err(Error::msg)?;
            } else if args.i32(6)? != 0 || args.i32(7)? != 0 {
                return Err(Error::msg("Replay delete has a value"));
            }
            let operation = match kind {
                1 => "1.0/insert",
                2 => "1.0/shallowMerge",
                3 => "1.0/replace",
                4 => "1.0/remove",
                _ => return Err(Error::msg("Invalid replay write kind")),
            };
            Val::I32(
                caller
                    .data_mut()
                    .enqueue(Operation::Write(operation, request))?,
            )
        }
        "convex_capability_start_schedule" => {
            caller.data().authorize(args.i64(0)?, false)?;
            let time = args.f64(2)?;
            if !time.is_finite() {
                return Err(Error::msg("Invalid replay schedule time"));
            }
            let ts = match args.i32(1)? {
                1 if time >= 0.0 => (caller.data().timestamp_ms + time) / 1000.0,
                2 => time / 1000.0,
                _ => return Err(Error::msg("Invalid replay schedule kind")),
            };
            let address = args.string(caller, 4)?;
            let address_key = match args.i32(3)? {
                1 => "name",
                2 => "reference",
                3 => "functionHandle",
                _ => return Err(Error::msg("Invalid replay function address")),
            };
            let value = codec::decode_value(&args.bytes(caller, 6)?, false).map_err(Error::msg)?;
            Val::I32(caller.data_mut().enqueue(Operation::Write(
                "1.0/schedule",
                json!({address_key: address, "ts": ts, "args": value}),
            ))?)
        }
        "convex_capability_start_string" => {
            caller.data().authorize(args.i64(0)?, false)?;
            if args.i32(1)? != 4 {
                return Err(Error::msg("Unsupported replay string capability"));
            }
            let id = args.string(caller, 2)?;
            Val::I32(
                caller
                    .data_mut()
                    .enqueue(Operation::Write("1.0/cancel_job", json!({"id": id})))?,
            )
        }
        "convex_async_operation_wait_any" => Val::I32(caller.data_mut().wait()?),
        "convex_async_operation_poll_ready" => Val::I32(caller.data_mut().announce()?),
        "convex_async_operation_completion_status" => {
            let handle = args.i32(0)?;
            Val::I32(caller.data_mut().completion_status(handle)?)
        }
        "convex_async_operation_completion_take" => {
            let handle = args.i32(0)?;
            Val::I64(caller.data_mut().take_completion(handle)?)
        }
        "convex_guest_value_encode_binary" => {
            let Some(Stored::Value(bytes)) = caller.data_mut().values.remove(&args.i64(0)?) else {
                return Err(Error::msg("Invalid replay value handle"));
            };
            Val::I64(caller.data_mut().insert(Stored::Payload(bytes))?)
        }
        "convex_guest_value_payload_len" => {
            let Some(Stored::Payload(bytes)) = caller.data().values.get(&args.i64(0)?) else {
                return Err(Error::msg("Invalid replay payload handle"));
            };
            Val::I32(i32::try_from(bytes.len())?)
        }
        "convex_guest_value_payload_copy" => {
            let Some(Stored::Payload(bytes)) = caller.data().values.get(&args.i64(0)?) else {
                return Err(Error::msg("Invalid replay payload handle"));
            };
            let bytes = bytes.clone();
            Val::I32(args.copy(caller, 1, &bytes)?)
        }
        "convex_guest_value_payload_release" => {
            if !matches!(
                caller.data_mut().values.remove(&args.i64(0)?),
                Some(Stored::Payload(_))
            ) {
                return Err(Error::msg("Invalid replay payload release"));
            }
            return Ok(None);
        }
        "convex_capability_request_decode" => {
            let request: Value = serde_json::from_slice(&args.bytes(caller, 0)?)
                .map_err(|_| Error::msg("Invalid replay capability JSON"))?;
            Val::I64(caller.data_mut().insert(Stored::Request(request))?)
        }
        "convex_capability_request_release" => {
            if !matches!(
                caller.data_mut().values.remove(&args.i64(0)?),
                Some(Stored::Request(_))
            ) {
                return Err(Error::msg("Invalid replay request release"));
            }
            return Ok(None);
        }
        "convex_capability_sync_take" => {
            caller.data().authorize(args.i64(0)?, true)?;
            let Some(Stored::Request(request)) = caller.data_mut().values.remove(&args.i64(1)?)
            else {
                return Err(Error::msg("Invalid replay request handle"));
            };
            if request.as_object().is_none_or(|object| object.len() != 3)
                || request["kind"] != "environmentVariableGet"
                || request["version"] != 4
            {
                return Err(Error::msg("Unsupported replay synchronous capability"));
            }
            let name = request["name"]
                .as_str()
                .ok_or_else(|| Error::msg("Invalid replay environment key"))?;
            let value = caller.data().environment.get(name).cloned().flatten();
            caller
                .data_mut()
                .environment_reads
                .insert(name.to_owned(), value.clone());
            let bytes = codec::encode_value(&json!({"value": value}), false).map_err(Error::msg)?;
            Val::I64(caller.data_mut().insert(Stored::Value(bytes))?)
        }
        "convex_crypto_random_uuid" => {
            caller.data().authorize(args.i64(0)?, false)?;
            let value = caller.data_mut().entropy("uuid")?;
            let value = value
                .as_str()
                .ok_or_else(|| Error::msg("Invalid replay UUID"))?;
            if value.len() != 36 || args.i32(2)? != 36 {
                return Err(Error::msg("Invalid replay UUID length"));
            }
            args.copy(caller, 1, value.as_bytes())?;
            return Ok(None);
        }
        "convex_math_random" => {
            caller.data().authorize(args.i64(0)?, false)?;
            let value = caller
                .data_mut()
                .entropy("random")?
                .as_f64()
                .ok_or_else(|| Error::msg("Invalid replay random number"))?;
            if !(0.0..1.0).contains(&value) {
                return Err(Error::msg("Invalid replay random number range"));
            }
            Val::F64(value.to_bits())
        }
        "convex_async_operation_cancel_all" => {
            caller.data().quiescent()?;
            Val::I32(0)
        }
        "convex_console_message" => {
            caller.data().authorize(args.i64(0)?, true)?;
            if !(0..=4).contains(&args.i32(1)?) {
                return Err(Error::msg("Invalid replay log level"));
            }
            let _: Vec<String> = serde_json::from_slice(&args.bytes(caller, 2)?)
                .map_err(|_| Error::msg("Invalid replay console payload"))?;
            // Captured application logs may contain private values. Count them
            // for diagnostics without echoing the payload into runner output.
            caller.data_mut().console_calls += 1;
            Val::I32(0)
        }
        "convex_profile_mark" => return Ok(None),
        "convex_developer_error" => {
            return Err(Error::msg("Guest reported a replay developer error"));
        }
        _ => return Err(Error::msg(format!("Unsupported replay import: {name}"))),
    };
    Ok(Some(result))
}

pub fn add_imports(linker: &mut Linker<State>, module: &Module) -> HostResult<()> {
    for import in module
        .imports()
        .filter(|import| import.module() == "convex")
    {
        let ExternType::Func(signature) = import.ty() else {
            return Err(Error::msg("Unexpected replay non-function import"));
        };
        let name = import.name().to_owned();
        linker.func_new(
            "convex",
            import.name(),
            signature,
            move |mut caller, params, results| {
                if caller.data().failed {
                    return Err(Error::msg("Replay host has failed"));
                }
                let started = Instant::now();
                let result = dispatch(&mut caller, &name, Arguments(params));
                caller.data_mut().host_time += started.elapsed();
                caller.data_mut().host_calls += 1;
                match result {
                    Ok(Some(value)) if results.len() == 1 => {
                        results[0] = value;
                        Ok(())
                    }
                    Ok(None) if results.is_empty() => Ok(()),
                    Ok(_) => {
                        caller.data_mut().failed = true;
                        Err(Error::msg("Replay import signature differs"))
                    }
                    Err(error) => {
                        caller.data_mut().failed = true;
                        Err(error)
                    }
                }
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_invocations_restart_async_handles_after_quiescence() {
        let case: Case = serde_json::from_value(json!({
            "selector": 1, "timestamp_ms": 1000, "args": {}, "expected": {},
            "entropy": [], "replay": {"calls": 2, "epochs": [{
                "reads": [
                    {"operation": "1.0/get", "arguments": {"id": "first"}, "result": "null"},
                    {"operation": "1.0/get", "arguments": {"id": "second"}, "result": "null"}
                ], "write": null
            }]}
        }))
        .unwrap();
        let mut state = State::new(BTreeMap::new());
        let mut previous_value = 0;
        for _ in 0..128 {
            state.begin(&case).unwrap();
            let first = state
                .enqueue(Operation::Get(json!({"id": "first"})))
                .unwrap();
            assert!(state.begin(&case).is_err());
            let second = state
                .enqueue(Operation::Get(json!({"id": "second"})))
                .unwrap();
            assert_eq!([first, second], [1, 2]);
            for operation in [first, second] {
                assert_eq!(state.wait().unwrap(), operation);
                assert_eq!(state.completion_status(operation).unwrap(), 0);
                let value = state.take_completion(operation).unwrap();
                // Opaque value handles keep their separate lifetime; restarting
                // async numbering must not make consumed values usable again.
                assert!(value > previous_value);
                previous_value = value;
                assert!(matches!(
                    state.values.remove(&value),
                    Some(Stored::Value(_))
                ));
            }
            state.output = Some(json!({}));
            assert_eq!(state.finish(&case).unwrap(), 2);
        }
    }

    fn state_with_read_and_writes() -> State {
        let mut state = State::new(BTreeMap::new());
        let trace: Trace = serde_json::from_value(json!({"calls": 3, "epochs": [
            {"reads": [{"operation": "1.0/get", "arguments": {"id": "record"}, "result": "null"}],
             "write": {"operation": "1.0/remove", "arguments": {"id": "first"}, "result": "{}"}},
            {"reads": [], "write": {"operation": "1.0/remove", "arguments": {"id": "second"}, "result": "{}"}},
            {"reads": [], "write": null}
        ]})).unwrap();
        state.replay = Some(Replay::new(trace).unwrap());
        state
    }

    #[test]
    fn queued_writes_wait_for_read_acknowledgment_and_remain_ordered() {
        let mut state = state_with_read_and_writes();
        let read = state
            .enqueue(Operation::Get(json!({"id": "record"})))
            .unwrap();
        let first = state
            .enqueue(Operation::Write("1.0/remove", json!({"id": "first"})))
            .unwrap();
        let second = state
            .enqueue(Operation::Write("1.0/remove", json!({"id": "second"})))
            .unwrap();
        assert_eq!(state.announce().unwrap(), 0);
        assert_eq!(state.wait().unwrap(), read);
        assert!(state.wait().is_err());
        assert!(state.write("1.0/remove", json!({"id": "first"})).is_err());
        assert!(state.take_completion(read).is_err());
        state.completion_status(read).unwrap();
        let payload = state.take_completion(read).unwrap();
        assert!(matches!(
            state.values.remove(&payload),
            Some(Stored::Value(_))
        ));
        assert_eq!(state.announce().unwrap(), 0);
        for operation in [first, second] {
            assert_eq!(state.wait().unwrap(), operation);
            assert_eq!(state.completion_status(operation).unwrap(), 0);
            assert_eq!(state.take_completion(operation).unwrap(), 0);
            assert_eq!(state.announce().unwrap(), 0);
        }
        state.quiescent().unwrap();
        assert_eq!(state.replay().unwrap().finish().unwrap(), 3);
    }

    #[test]
    fn changing_queued_write_order_still_fails() {
        let mut state = state_with_read_and_writes();
        state
            .enqueue(Operation::Get(json!({"id": "record"})))
            .unwrap();
        state
            .enqueue(Operation::Write("1.0/remove", json!({"id": "second"})))
            .unwrap();
        let read = state.wait().unwrap();
        state.completion_status(read).unwrap();
        let value = state.take_completion(read).unwrap();
        state.values.remove(&value);
        assert!(state.wait().is_err());
        assert!(state.replay().unwrap().finish().is_err());
    }
}
