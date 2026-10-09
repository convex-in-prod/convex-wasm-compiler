//! Host-side matching for traces prepared by convex-wasm-syscall-replay.mjs.
//! Transport changes may combine a fully consumed stream into a bulk query;
//! predicates, document order, write arguments and write boundaries stay exact.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

type ReplayResult<T> = Result<T, &'static str>;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    epochs: Vec<Epoch>,
    calls: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    reads: Vec<Entry>,
    write: Option<Entry>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    operation: String,
    arguments: Value,
    result: String,
    next: Option<Vec<String>>,
    cleanup: Option<String>,
}

struct Stream {
    next: Vec<Value>,
    consumed: usize,
}

#[derive(Debug, PartialEq)]
pub enum QueryResponse {
    Documents(Vec<Value>),
    Stream(u32),
}

pub struct Replay {
    trace: Trace,
    epoch: usize,
    remaining: Vec<Entry>,
    streams: BTreeMap<u32, Stream>,
    next_stream: u32,
    calls: usize,
    failed: bool,
}

fn parse_result(serialized: &str) -> ReplayResult<Value> {
    // serde errors can quote private input. Only the classification crosses
    // this diagnostic boundary.
    serde_json::from_str(serialized).map_err(|_| "Malformed replay result")
}

fn request_arguments(entry: &Entry) -> ReplayResult<Value> {
    let mut arguments = entry
        .arguments
        .as_object()
        .ok_or("Replay arguments are not an object")?
        .clone();
    // Typed imports implement the negotiated ABI and do not transmit the SDK
    // version string. No other captured request field is discarded.
    if let Some(version) = arguments.remove("version") {
        if !version.is_string() {
            return Err("Replay SDK version is invalid");
        }
    }
    Ok(Value::Object(arguments))
}

fn same_arguments(left: &Value, right: &Value) -> bool {
    match (left, right) {
        // Captures originate in JavaScript, which has one ordinary Number
        // type. serde_json distinguishes integral and floating JSON spellings.
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_arguments(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| same_arguments(a, b)))
        }
        _ => left == right,
    }
}

impl Replay {
    pub fn new(trace: Trace) -> ReplayResult<Self> {
        if trace.epochs.is_empty() || trace.epochs.last().unwrap().write.is_some() {
            return Err("Replay trace has no terminal read epoch");
        }
        let mut count = 0usize;
        for (index, epoch) in trace.epochs.iter().enumerate() {
            if index + 1 < trace.epochs.len() && epoch.write.is_none() {
                return Err("Replay trace has an intermediate terminal epoch");
            }
            for read in &epoch.reads {
                request_arguments(read)?;
                let result = parse_result(&read.result)?;
                count += 1;
                match read.operation.as_str() {
                    "1.0/get"
                        if read.next.is_none()
                            && read.cleanup.is_none()
                            && (result.is_null() || result.is_object()) => {}
                    "1.0/queryStream" => {
                        if !result.as_object().is_some_and(|value| {
                            value.len() == 1
                                && value.get("queryId").is_some_and(|id| {
                                    id.as_u64().is_some_and(|id| id <= 9007199254740991)
                                })
                        }) {
                            return Err("Replay query start result is invalid");
                        }
                        let next = read.next.as_ref().ok_or("Replay query has no results")?;
                        let cleanup = read.cleanup.as_ref().ok_or("Replay query is not closed")?;
                        if parse_result(cleanup)? != json!({}) {
                            return Err("Replay query cleanup result is invalid");
                        }
                        let mut done = false;
                        for serialized in next {
                            let value = parse_result(serialized)?;
                            if done || !value.is_object() || value.as_object().unwrap().len() != 2 {
                                return Err("Replay query continuation is invalid");
                            }
                            done = value["done"]
                                .as_bool()
                                .ok_or("Replay query done flag is invalid")?;
                            if !value.as_object().unwrap().contains_key("value")
                                || (done && !value["value"].is_null())
                                || (!done && !value["value"].is_object())
                            {
                                return Err("Replay query document is invalid");
                            }
                        }
                        count += next.len() + 1;
                    }
                    _ => return Err("Unsupported replay read"),
                }
            }
            if let Some(write) = &epoch.write {
                request_arguments(write)?;
                let result = parse_result(&write.result)?;
                if write.next.is_some() || write.cleanup.is_some() {
                    return Err("Replay write contains query state");
                }
                match write.operation.as_str() {
                    "1.0/insert"
                        if result.as_object().is_some_and(|v| {
                            v.len() == 1 && v.get("_id").is_some_and(Value::is_string)
                        }) => {}
                    "1.0/shallowMerge" | "1.0/replace" | "1.0/remove" | "1.0/cancel_job"
                        if result == json!({}) => {}
                    "1.0/schedule" if result.is_string() => {}
                    _ => return Err("Unsupported replay write or result"),
                }
                count += 1;
            }
        }
        if count != trace.calls {
            return Err("Replay call count differs from its entries");
        }
        Ok(Self {
            remaining: trace.epochs[0].reads.clone(),
            trace,
            epoch: 0,
            streams: BTreeMap::new(),
            next_stream: 1,
            calls: 0,
            failed: false,
        })
    }

    fn take_read(&mut self, operation: &str, arguments: &Value) -> ReplayResult<Entry> {
        if self.failed {
            return Err("Replay has failed");
        }
        // Poison before matching: a caught mismatch cannot produce a passing
        // receipt by subsequently consuming another request.
        self.failed = true;
        let index = self
            .remaining
            .iter()
            .position(|entry| {
                entry.operation == operation
                    && request_arguments(entry)
                        .is_ok_and(|expected| same_arguments(&expected, arguments))
            })
            .ok_or("Replay read differs from the current epoch")?;
        let entry = self.remaining.remove(index);
        self.calls += 1;
        self.failed = false;
        Ok(entry)
    }

    pub fn get(&mut self, arguments: &Value) -> ReplayResult<Value> {
        let entry = self.take_read("1.0/get", arguments)?;
        parse_result(&entry.result)
    }

    pub fn query(&mut self, query: Value, collect: bool) -> ReplayResult<QueryResponse> {
        let entry = self.take_read("1.0/queryStream", &json!({"query": query}))?;
        self.failed = true;
        let next = entry
            .next
            .as_ref()
            .ok_or("Replay query results disappeared")?
            .iter()
            .map(|value| parse_result(value))
            .collect::<ReplayResult<Vec<_>>>()?;
        let response = if collect {
            // An early-closed stream does not establish the rest of a bulk
            // result. Never infer end-of-query from cleanup alone.
            if next.last().is_none_or(|value| value["done"] != true) {
                return Err("A partial stream cannot supply a bulk replay result");
            }
            self.calls += next.len() + 1;
            QueryResponse::Documents(
                next.into_iter()
                    .filter(|v| v["done"] == false)
                    .map(|mut v| v.as_object_mut().unwrap().remove("value").unwrap())
                    .collect(),
            )
        } else {
            let handle = self.next_stream;
            self.next_stream = handle
                .checked_add(1)
                .ok_or("Replay query handle overflow")?;
            self.streams.insert(handle, Stream { next, consumed: 0 });
            QueryResponse::Stream(handle)
        };
        self.failed = false;
        Ok(response)
    }

    pub fn stream_next(&mut self, handle: u32) -> ReplayResult<Value> {
        if self.failed {
            return Err("Replay has failed");
        }
        self.failed = true;
        let stream = self
            .streams
            .get_mut(&handle)
            .ok_or("Replay query is not open")?;
        let value = stream
            .next
            .get(stream.consumed)
            .ok_or("Replay query has no remaining result")?
            .clone();
        stream.consumed += 1;
        self.calls += 1;
        self.failed = false;
        Ok(value)
    }

    pub fn stream_close(&mut self, handle: u32) -> ReplayResult<()> {
        if self.failed {
            return Err("Replay has failed");
        }
        self.failed = true;
        let stream = self
            .streams
            .remove(&handle)
            .ok_or("Replay query is not open")?;
        if stream.consumed != stream.next.len() {
            return Err("Replay query closed with unread results");
        }
        self.calls += 1;
        self.failed = false;
        Ok(())
    }

    /// The host driver must additionally reject writes while read operations
    /// are pending; matching a request is not acknowledgment of its response.
    pub fn write(&mut self, operation: &str, arguments: &Value) -> ReplayResult<Value> {
        if self.failed {
            return Err("Replay has failed");
        }
        self.failed = true;
        let entry = self.trace.epochs[self.epoch]
            .write
            .as_ref()
            .ok_or("Replay has no remaining write")?;
        if !self.remaining.is_empty()
            || !self.streams.is_empty()
            || entry.operation != operation
            || !same_arguments(&request_arguments(entry)?, arguments)
        {
            return Err("Replay write differs from the current epoch");
        }
        let result = parse_result(&entry.result)?;
        let result = match operation {
            "1.0/insert" => result["_id"].clone(),
            "1.0/schedule" => result,
            _ => Value::Null,
        };
        self.epoch += 1;
        self.remaining = self.trace.epochs[self.epoch].reads.clone();
        self.calls += 1;
        self.failed = false;
        Ok(result)
    }

    pub fn finish(&self) -> ReplayResult<usize> {
        if self.failed
            || self.epoch + 1 != self.trace.epochs.len()
            || !self.remaining.is_empty()
            || !self.streams.is_empty()
            || self.calls != self.trace.calls
        {
            return Err("Incomplete or failed capability replay");
        }
        Ok(self.calls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(epochs: Value, calls: usize) -> Trace {
        serde_json::from_value(json!({"epochs": epochs, "calls": calls})).unwrap()
    }

    fn query_entry(done: bool) -> Value {
        let mut next = vec![json!({"done": false, "value": {"n": 7}}).to_string()];
        if done {
            next.push(json!({"done": true, "value": null}).to_string());
        }
        json!({"operation": "1.0/queryStream", "arguments": {"query": {"source": "fixture"}, "version": "1"},
            "result": "{\"queryId\":91}", "next": next, "cleanup": "{}"})
    }

    #[test]
    fn bulk_and_stream_consume_the_same_captured_documents() {
        let input = trace(json!([{"reads": [query_entry(true)], "write": null}]), 4);
        let mut bulk = Replay::new(input.clone()).unwrap();
        assert_eq!(
            bulk.query(json!({"source": "fixture"}), true).unwrap(),
            QueryResponse::Documents(vec![json!({"n": 7})])
        );
        assert_eq!(bulk.finish(), Ok(4));
        let mut stream = Replay::new(input).unwrap();
        assert_eq!(
            stream.query(json!({"source": "fixture"}), false).unwrap(),
            QueryResponse::Stream(1)
        );
        assert_eq!(
            stream.stream_next(1).unwrap(),
            json!({"done": false, "value": {"n": 7}})
        );
        assert_eq!(
            stream.stream_next(1).unwrap(),
            json!({"done": true, "value": null})
        );
        stream.stream_close(1).unwrap();
        assert_eq!(stream.finish(), Ok(4));
    }

    #[test]
    fn partial_streams_cannot_become_bulk_results_or_hide_unread_values() {
        let input = trace(json!([{"reads": [query_entry(false)], "write": null}]), 3);
        let mut bulk = Replay::new(input.clone()).unwrap();
        assert!(bulk.query(json!({"source": "fixture"}), true).is_err());
        assert!(bulk.finish().is_err());
        let mut stream = Replay::new(input.clone()).unwrap();
        stream.query(json!({"source": "fixture"}), false).unwrap();
        assert!(stream.stream_close(1).is_err());
        assert!(stream.finish().is_err());
        let mut consumed = Replay::new(input).unwrap();
        consumed.query(json!({"source": "fixture"}), false).unwrap();
        assert_eq!(
            consumed.stream_next(1).unwrap(),
            json!({"done": false, "value": {"n": 7}})
        );
        consumed.stream_close(1).unwrap();
        assert_eq!(consumed.finish(), Ok(3));
    }

    #[test]
    fn independent_reads_reorder_but_writes_and_optional_fields_remain_exact() {
        let read = |id| json!({"operation": "1.0/get", "arguments": {"id": id}, "result": "null"});
        let input = trace(
            json!([
                {"reads": [read("a"), read("b")], "write": {"operation": "1.0/insert", "arguments": {"table": "items", "value": {"n": 1}}, "result": "{\"_id\":\"new\"}"}},
                {"reads": [read("new")], "write": null}
            ]),
            4,
        );
        let mut run = Replay::new(input.clone()).unwrap();
        run.get(&json!({"id": "b"})).unwrap();
        run.get(&json!({"id": "a"})).unwrap();
        assert_eq!(
            run.write("1.0/insert", &json!({"table": "items", "value": {"n": 1}}))
                .unwrap(),
            "new"
        );
        run.get(&json!({"id": "new"})).unwrap();
        assert_eq!(run.finish(), Ok(4));
        let mut early = Replay::new(input.clone()).unwrap();
        assert!(
            early
                .write("1.0/insert", &json!({"table": "items", "value": {"n": 1}}))
                .is_err()
        );
        assert!(early.get(&json!({"id": "a"})).is_err());
        let mut changed = Replay::new(input).unwrap();
        assert!(changed.get(&json!({"id": "a", "table": null})).is_err());
        assert!(changed.finish().is_err());
    }

    #[test]
    fn request_numbers_follow_javascript_equality_without_coercing_types() {
        let input = trace(
            json!([
                {"reads": [], "write": {"operation": "1.0/insert", "arguments": {"table": "items", "value": {"n": 1}}, "result": "{\"_id\":\"new\"}"}},
                {"reads": [], "write": null}
            ]),
            1,
        );
        let mut replay = Replay::new(input.clone()).unwrap();
        replay
            .write(
                "1.0/insert",
                &json!({"table": "items", "value": {"n": 1.0}}),
            )
            .unwrap();
        assert_eq!(replay.finish(), Ok(1));
        let mut replay = Replay::new(input).unwrap();
        assert!(
            replay
                .write(
                    "1.0/insert",
                    &json!({"table": "items", "value": {"n": "1"}})
                )
                .is_err()
        );
    }

    #[test]
    fn duplicate_queries_keep_their_result_sequence_and_failures_are_sticky() {
        let first = query_entry(true);
        let mut second = query_entry(true);
        second["next"][0] = json!({"done": false, "value": {"n": 8}}).to_string().into();
        let input = trace(json!([{"reads": [first, second], "write": null}]), 8);
        let mut run = Replay::new(input.clone()).unwrap();
        for n in [7, 8] {
            assert_eq!(
                run.query(json!({"source": "fixture"}), true).unwrap(),
                QueryResponse::Documents(vec![json!({"n": n})])
            );
        }
        assert_eq!(run.finish(), Ok(8));
        let mut changed = Replay::new(input).unwrap();
        assert_eq!(
            changed
                .query(json!({"source": "private-changed"}), true)
                .unwrap_err(),
            "Replay read differs from the current epoch"
        );
        assert!(changed.query(json!({"source": "fixture"}), true).is_err());
    }

    #[test]
    fn malformed_capture_data_is_rejected_without_printing_payloads() {
        let mut entry = query_entry(true);
        entry["next"][0] = "{private-input".into();
        assert_eq!(
            Replay::new(trace(json!([{"reads": [entry], "write": null}]), 4)).err(),
            Some("Malformed replay result")
        );
        let mut entry = query_entry(true);
        entry["result"] = "null".into();
        assert_eq!(
            Replay::new(trace(json!([{"reads": [entry], "write": null}]), 4)).err(),
            Some("Replay query start result is invalid")
        );
        assert!(
            Replay::new(trace(
                json!([{"reads": [query_entry(true)], "write": null}]),
                3
            ))
            .is_err()
        );
        let mut entry = query_entry(true);
        entry["arguments"]["version"] = Value::Null;
        assert_eq!(
            Replay::new(trace(json!([{"reads": [entry], "write": null}]), 4)).err(),
            Some("Replay SDK version is invalid")
        );
    }
}
