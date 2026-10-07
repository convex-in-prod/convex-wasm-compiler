use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Mutex,
    thread::{self, ThreadId},
    time::Instant,
};

use serde::Serialize;

use crate::incremental_cache::{HEADER_BYTES, TIERS, WAYS};

const MAX_TRACE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LookupResult {
    Hit,
    Miss,
}

struct PendingLookup {
    key: [u8; 32],
    result: LookupResult,
    wall: Instant,
    cpu_nanoseconds: u64,
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum CompileInterval {
    Matched {
        preceding_lookup: LookupResult,
        wall_nanoseconds: u64,
        thread_cpu_nanoseconds: u64,
    },
    Unmatched,
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum InsertResult {
    Stored {
        tier: usize,
        displaced_record_bytes: Option<u64>,
    },
    Oversized,
}

struct TraceState {
    writer: BufWriter<File>,
    bytes: usize,
    pending: HashMap<ThreadId, PendingLookup>,
    complete: bool,
}

/// Optional bounded diagnostics. Keys identify compiler stencils without
/// recording source or compiled bytes. Tracing never changes cache authority.
pub struct CacheTrace {
    state: Mutex<TraceState>,
}

impl CacheTrace {
    pub fn create(path: &Path, namespace: [u8; 32]) -> io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("trace has no parent"))?;
        let metadata = fs::symlink_metadata(parent)?;
        if !path.is_absolute()
            || fs::canonicalize(parent)? != parent
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::other(
                "cache trace requires an absolute path in a private owned canonical directory",
            ));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut state = TraceState {
            writer: BufWriter::new(file),
            bytes: 0,
            pending: HashMap::new(),
            complete: false,
        };
        state.write(&serde_json::json!({
            "kind": "convex-wasm-incremental-cache-trace-v1",
            "namespace": namespace.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "recordHeaderBytes": HEADER_BYTES,
            "tiers": TIERS.iter().map(|(sets, limit)| serde_json::json!({
                "sets": sets, "ways": WAYS, "recordLimitBytes": limit,
            })).collect::<Vec<_>>(),
        }))?;
        Ok(Self {
            state: Mutex::new(state),
        })
    }

    pub fn lookup(
        &self,
        key: [u8; 32],
        result: LookupResult,
        value_bytes: Option<usize>,
        lookup_nanoseconds: u64,
    ) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.write(&serde_json::json!({
            "event": "lookup",
            "key": key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "result": result,
            "valueBytes": value_bytes,
            "lookupNanoseconds": lookup_nanoseconds,
        }))?;
        // The pinned Cranelift compile_with_cache calls get and insert on the
        // same worker. Start after lookup I/O, stop before publication I/O. The
        // interval includes stencil compilation and serialization, not Wasm
        // translation before get or linking after insert.
        state.pending.insert(
            thread::current().id(),
            PendingLookup {
                key,
                result,
                wall: Instant::now(),
                cpu_nanoseconds: thread_cpu_nanoseconds()?,
            },
        );
        Ok(())
    }

    pub fn begin_insert(&self, key: &[u8; 32]) -> io::Result<CompileInterval> {
        let wall = Instant::now();
        let cpu = thread_cpu_nanoseconds()?;
        let pending = self
            .state
            .lock()
            .unwrap()
            .pending
            .remove(&thread::current().id());
        match pending {
            Some(pending) if &pending.key == key => Ok(CompileInterval::Matched {
                preceding_lookup: pending.result,
                wall_nanoseconds: u64::try_from(wall.duration_since(pending.wall).as_nanos())
                    .map_err(io::Error::other)?,
                thread_cpu_nanoseconds: cpu
                    .checked_sub(pending.cpu_nanoseconds)
                    .ok_or_else(|| io::Error::other("thread CPU clock moved backwards"))?,
            }),
            // CacheStore also permits insertion without a preceding lookup.
            // Never attribute another thread's or key's interval to that work.
            _ => Ok(CompileInterval::Unmatched),
        }
    }

    pub fn insert(
        &self,
        key: [u8; 32],
        value_bytes: usize,
        result: InsertResult,
        interval: CompileInterval,
    ) -> io::Result<()> {
        self.state.lock().unwrap().write(&serde_json::json!({
            "event": "insert",
            "key": key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "valueBytes": value_bytes,
            "result": result,
            "compileInterval": interval,
        }))
    }

    pub fn finish(&self, report: &impl Serialize) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.write(&serde_json::json!({"event": "complete", "counters": report}))?;
        state.writer.flush()?;
        state.writer.get_ref().sync_all()?;
        state.complete = true;
        Ok(())
    }
}

impl TraceState {
    fn write(&mut self, value: &impl Serialize) -> io::Result<()> {
        if self.complete {
            return Err(io::Error::other("cache trace is already complete"));
        }
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_TRACE_BYTES - self.bytes {
            return Err(io::Error::other("cache trace exceeds 64 MiB"));
        }
        self.writer.write_all(&bytes)?;
        self.bytes += bytes.len();
        Ok(())
    }
}

fn thread_cpu_nanoseconds() -> io::Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(value.tv_sec).map_err(io::Error::other)?;
    let nanos = u64::try_from(value.tv_nsec).map_err(io::Error::other)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanos))
        .ok_or_else(|| io::Error::other("thread CPU clock exceeds u64 nanoseconds"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        sync::Arc,
    };

    fn root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "convex-wasm-cache-trace-{name}-{}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        root.canonicalize().unwrap()
    }

    #[test]
    fn intervals_belong_to_the_matching_worker_and_key() {
        let root = root("workers");
        let path = root.join("trace.jsonl");
        let trace = Arc::new(CacheTrace::create(&path, [1; 32]).unwrap());
        trace.lookup([1; 32], LookupResult::Miss, None, 10).unwrap();
        assert!(matches!(
            trace.begin_insert(&[2; 32]).unwrap(),
            CompileInterval::Unmatched
        ));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let trace = Arc::clone(&trace);
                scope.spawn(move || {
                    trace.lookup([3; 32], LookupResult::Miss, None, 10).unwrap();
                    let interval = trace.begin_insert(&[3; 32]).unwrap();
                    assert!(matches!(
                        interval,
                        CompileInterval::Matched {
                            preceding_lookup: LookupResult::Miss,
                            ..
                        }
                    ));
                    trace
                        .insert([3; 32], 123, InsertResult::Oversized, interval)
                        .unwrap();
                });
            }
        });
        trace.finish(&serde_json::json!({"inserts": 4})).unwrap();
        let events: Vec<serde_json::Value> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event"] == "insert")
                .count(),
            4
        );
        assert_eq!(events.last().unwrap()["event"], "complete");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(trace.finish(&()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trace_requires_fresh_private_output_and_bounds_file_growth() {
        let root = root("output");
        let path = root.join("trace.jsonl");
        let trace = CacheTrace::create(&path, [1; 32]).unwrap();
        assert!(CacheTrace::create(&path, [1; 32]).is_err());
        let alias = root.join("alias.jsonl");
        symlink(&path, &alias).unwrap();
        assert!(CacheTrace::create(&alias, [1; 32]).is_err());
        assert!(
            trace
                .state
                .lock()
                .unwrap()
                .write(&"x".repeat(MAX_TRACE_BYTES))
                .is_err()
        );
        trace.finish(&()).unwrap();
        assert!(fs::metadata(&path).unwrap().len() < 1024);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(CacheTrace::create(&root.join("shared.jsonl"), [1; 32]).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
