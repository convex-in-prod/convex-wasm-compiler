use std::{
    borrow::Cow,
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasmtime::CacheStore;

use crate::incremental_cache_trace::{CacheTrace, CompileInterval, InsertResult, LookupResult};

const MAGIC: &[u8; 8] = b"CWCLIF01";
pub(super) const HEADER_BYTES: usize = 72;
pub(super) const WAYS: usize = 16;
// Slot sizes include authentication. Finer classes and more ways retain medium
// and expensive large stencils instead of spending most capacity on padding.
// The complete layout is bounded at 2 GiB across source/compiler revisions.
pub(super) const TIERS: [(usize, usize); 13] = [
    (1536, 4 * 1024),
    (256, 8 * 1024),
    (128, 16 * 1024),
    (128, 32 * 1024),
    (160, 64 * 1024),
    (112, 128 * 1024),
    (64, 256 * 1024),
    (28, 512 * 1024),
    (14, 1024 * 1024),
    (5, 2 * 1024 * 1024),
    (3, 4 * 1024 * 1024),
    (1, 8 * 1024 * 1024),
    (1, 16 * 1024 * 1024),
];

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheReport {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
    pub rejected_records: u64,
    pub oversized_values: u64,
}

/// Disposable compiled-function records, authenticated before Cranelift reads
/// them. The namespace binds the actual precompiler and engine configuration;
/// Cranelift's key additionally binds its function stencil and target settings.
pub struct IncrementalCache {
    root: PathBuf,
    namespace: [u8; 32],
    secret: [u8; 32],
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
    rejected_records: AtomicU64,
    oversized_values: AtomicU64,
    failure: Mutex<Option<io::Error>>,
    trace: Option<CacheTrace>,
}

impl std::fmt::Debug for IncrementalCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IncrementalCache")
            .finish_non_exhaustive()
    }
}

impl IncrementalCache {
    pub fn open(root: PathBuf, namespace: [u8; 32], trace_path: Option<&Path>) -> io::Result<Self> {
        let trace = trace_path
            .map(|path| CacheTrace::create(path, namespace))
            .transpose()?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        require_private(&fs::symlink_metadata(&root)?, true)?;
        // The preceding layout used different slot limits. Keep a fixed
        // format directory so old/new executables can run concurrently without
        // reinterpreting or deleting each other's records. Legacy slots remain
        // bounded at 1 GiB and can be removed by an idle-cache maintenance pass.
        let root = root.join("size-classes-v2");
        match DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        require_private(&fs::symlink_metadata(&root)?, true)?;
        // Only key initialization is globally serialized. Compilation and
        // reads remain parallel, and insertion locks cover one shard each.
        let init_lock = private_file(&root.join("init.lock"), true)?;
        init_lock.lock()?;
        let key_path = root.join("authentication-key");
        let mut secret = [0; 32];
        match private_file(&key_path, false) {
            Ok(mut key) => {
                if key.metadata()?.len() != 32 {
                    return Err(io::Error::other(
                        "incremental cache authentication key is invalid",
                    ));
                }
                key.read_exact(&mut secret)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                File::open("/dev/urandom")?.read_exact(&mut secret)?;
                let pending = root.join("authentication-key.pending");
                let mut key = private_file(&pending, true)?;
                key.set_len(0)?;
                key.write_all(&secret)?;
                key.sync_all()?;
                fs::rename(pending, key_path)?;
            }
            Err(error) => return Err(error),
        }
        drop(init_lock);
        for shard in 0..256 {
            let path = root.join(format!("{shard:02x}"));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            require_private(&fs::symlink_metadata(path)?, true)?;
        }
        Ok(Self {
            root,
            namespace,
            secret,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            rejected_records: AtomicU64::new(0),
            oversized_values: AtomicU64::new(0),
            failure: Mutex::new(None),
            trace,
        })
    }

    fn key(&self, key: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(MAGIC);
        hash.update(self.namespace);
        hash.update(key);
        hash.finalize().into()
    }

    fn paths(&self, key: &[u8; 32], tier: usize) -> [PathBuf; WAYS] {
        let (sets, _) = TIERS[tier];
        let set = usize::from(u16::from_le_bytes([key[0], key[1]])) % sets;
        let shard = self.root.join(format!("{:02x}", set % 256));
        std::array::from_fn(|way| shard.join(format!("{tier}-{set:04x}-{way}")))
    }

    fn lookup(&self, key: &[u8; 32]) -> io::Result<Option<Vec<u8>>> {
        for (tier, (_, limit)) in TIERS.iter().enumerate() {
            for path in self.paths(key, tier) {
                let mut file = match private_file(&path, false) {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                let length = file.metadata()?.len();
                if length < HEADER_BYTES as u64 || length > *limit as u64 {
                    self.rejected_records.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut header = [0; HEADER_BYTES];
                file.read_exact(&mut header)?;
                if &header[..8] != MAGIC {
                    self.rejected_records.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if &header[8..40] != key {
                    continue; // An ordinary set collision is not a corrupt record.
                }
                let mut value = Vec::new();
                file.take((*limit - HEADER_BYTES + 1) as u64)
                    .read_to_end(&mut value)?;
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).unwrap();
                mac.update(&header[..40]);
                mac.update(&value);
                if value.len() + HEADER_BYTES != length as usize
                    || mac.verify_slice(&header[40..]).is_err()
                {
                    // A crash can lose an unsynced disposable record. Never give
                    // unauthenticated bytes to the compiler; report and rebuild it.
                    self.rejected_records.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn publish(&self, key: &[u8; 32], value: &[u8], tier: usize) -> io::Result<Option<u64>> {
        let paths = self.paths(key, tier);
        let shard = paths[0].parent().unwrap();
        let lock = private_file(&shard.join("insert.lock"), true)?;
        lock.lock()?;
        let mut oldest = None;
        let mut selected = &paths[0];
        let mut replacing = true;
        let mut displaced_record_bytes = None;
        for path in &paths {
            match fs::symlink_metadata(path) {
                Ok(metadata) => {
                    require_private(&metadata, false)?;
                    let mut file = private_file(path, false)?;
                    let mut header = [0; HEADER_BYTES];
                    if metadata.len() >= HEADER_BYTES as u64 {
                        file.read_exact(&mut header)?;
                        if &header[..8] == MAGIC && &header[8..40] == key {
                            // Concurrent compilation can insert the same key
                            // after both workers missed. Replace its slot instead
                            // of letting duplicate records evict other functions.
                            selected = path;
                            replacing = false;
                            displaced_record_bytes = None;
                            break;
                        }
                    }
                    let modified = metadata.modified()?;
                    if oldest.is_none_or(|time| modified < time) {
                        oldest = Some(modified);
                        selected = path;
                        displaced_record_bytes = Some(metadata.len());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    selected = path;
                    replacing = false;
                    displaced_record_bytes = None;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8..40].copy_from_slice(key);
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).unwrap();
        mac.update(&header[..40]);
        mac.update(value);
        header[40..].copy_from_slice(&mac.finalize().into_bytes());
        // One pending file per locked shard also bounds abandoned writes. Atomic
        // replacement lets readers finish using the old inode without a lock.
        let pending = shard.join("pending");
        let mut file = private_file(&pending, true)?;
        file.set_len(0)?;
        file.write_all(&header)?;
        file.write_all(value)?;
        fs::rename(pending, selected)?;
        if replacing {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        self.inserts.fetch_add(1, Ordering::Relaxed);
        Ok(displaced_record_bytes)
    }

    fn record_failure(&self, error: io::Error) {
        let mut failure = self.failure.lock().unwrap();
        if failure.is_none() {
            *failure = Some(error);
        }
    }

    pub fn report(&self) -> io::Result<CacheReport> {
        // CacheStore cannot return errors. Surface unexpected I/O failures here,
        // before the caller publishes any compiled artifact.
        if let Some(error) = self.failure.lock().unwrap().as_ref() {
            return Err(io::Error::new(error.kind(), error.to_string()));
        }
        Ok(CacheReport {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            rejected_records: self.rejected_records.load(Ordering::Relaxed),
            oversized_values: self.oversized_values.load(Ordering::Relaxed),
        })
    }

    pub fn finish_trace(&self, report: &CacheReport) -> io::Result<()> {
        if let Some(trace) = &self.trace {
            trace.finish(report)?;
        }
        Ok(())
    }
}

impl CacheStore for IncrementalCache {
    fn get(&self, key: &[u8]) -> Option<Cow<'_, [u8]>> {
        let key = self.key(key);
        let start = self.trace.as_ref().map(|_| Instant::now());
        let (result, value) = match self.lookup(&key) {
            Ok(Some(value)) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                (LookupResult::Hit, Some(value))
            }
            Ok(None) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                (LookupResult::Miss, None)
            }
            Err(error) => {
                self.record_failure(error);
                return None;
            }
        };
        if let (Some(trace), Some(start)) = (&self.trace, start) {
            let elapsed =
                u64::try_from(start.elapsed().as_nanos()).expect("lookup duration exceeds u64");
            if let Err(error) = trace.lookup(key, result, value.as_ref().map(Vec::len), elapsed) {
                self.record_failure(error);
            }
        }
        value.map(Cow::Owned)
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> bool {
        let key = self.key(key);
        let interval = match &self.trace {
            Some(trace) => match trace.begin_insert(&key) {
                Ok(interval) => interval,
                Err(error) => {
                    self.record_failure(error);
                    return false;
                }
            },
            None => CompileInterval::Unmatched,
        };
        let Some(tier) = TIERS
            .iter()
            .position(|(_, limit)| value.len() <= limit - HEADER_BYTES)
        else {
            self.oversized_values.fetch_add(1, Ordering::Relaxed);
            if let Some(trace) = &self.trace {
                if let Err(error) =
                    trace.insert(key, value.len(), InsertResult::Oversized, interval)
                {
                    self.record_failure(error);
                }
            }
            return false;
        };
        match self.publish(&key, &value, tier) {
            Ok(displaced_record_bytes) => {
                if let Some(trace) = &self.trace {
                    if let Err(error) = trace.insert(
                        key,
                        value.len(),
                        InsertResult::Stored {
                            tier,
                            displaced_record_bytes,
                        },
                        interval,
                    ) {
                        self.record_failure(error);
                        return false;
                    }
                }
                true
            }
            Err(error) => {
                self.record_failure(error);
                false
            }
        }
    }
}

fn require_private(metadata: &Metadata, directory: bool) -> io::Result<()> {
    // Cache bytes can become executable code. Restrict both the key and records
    // to the current user, including on callers' explicitly selected cache roots.
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(io::Error::other(
            "incremental cache requires private owned files and directories",
        ));
    }
    Ok(())
}

fn private_file(path: &Path, writable: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .create(writable)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    require_private(&file.metadata()?, false)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "convex-wasm-incremental-{name}-{}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        path.canonicalize().unwrap()
    }

    #[test]
    fn records_survive_reopening_and_bind_namespace_and_bytes() {
        let root = root("authentication");
        let cache = IncrementalCache::open(root.clone(), [1; 32], None).unwrap();
        assert!(cache.insert(b"function", b"compiled bytes".to_vec()));
        let path = cache.paths(&cache.key(b"function"), 0)[0].clone();
        drop(cache);
        let cache = IncrementalCache::open(root.clone(), [1; 32], None).unwrap();
        assert_eq!(cache.get(b"function").unwrap().as_ref(), b"compiled bytes");
        assert!(
            IncrementalCache::open(root.clone(), [2; 32], None)
                .unwrap()
                .get(b"function")
                .is_none()
        );
        let mut corrupt = fs::read(&path).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&path, corrupt).unwrap();
        assert!(cache.get(b"function").is_none());
        assert_eq!(cache.report().unwrap().rejected_records, 1);
        assert!(cache.insert(b"function", b"compiled bytes".to_vec()));
        assert_eq!(cache.get(b"function").unwrap().as_ref(), b"compiled bytes");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_is_bounded_and_collisions_retain_all_ways() {
        let root = root("bounds");
        let trace_path = root.join("trace.jsonl");
        let cache = IncrementalCache::open(root.clone(), [1; 32], Some(&trace_path)).unwrap();
        let mut keys = Vec::new();
        let mut candidate = 0_u64;
        while keys.len() < WAYS + 1 {
            let key = cache.key(&candidate.to_le_bytes());
            if u16::from_le_bytes([key[0], key[1]]) as usize % TIERS[0].0 == 0 {
                keys.push(candidate.to_le_bytes());
            }
            candidate += 1;
        }
        for key in &keys[..WAYS] {
            assert!(cache.insert(key, key.to_vec()));
        }
        for key in &keys[..WAYS] {
            assert_eq!(cache.get(key).unwrap().as_ref(), key);
        }
        assert!(cache.insert(&keys[WAYS], keys[WAYS].to_vec()));
        assert_eq!(
            keys.iter().filter(|key| cache.get(*key).is_some()).count(),
            WAYS
        );
        assert_eq!(cache.get(&keys[WAYS]).unwrap().as_ref(), keys[WAYS]);
        let medium = vec![3; TIERS[0].1];
        assert!(cache.insert(b"medium", medium.clone()));
        assert_eq!(cache.get(b"medium").unwrap().as_ref(), medium);
        let large = vec![5; 2 * 1024 * 1024];
        assert!(cache.insert(b"large", large.clone()));
        assert_eq!(cache.get(b"large").unwrap().as_ref(), large);
        assert!(cache.get(b"oversized").is_none());
        assert!(!cache.insert(b"oversized", vec![0; TIERS.last().unwrap().1]));
        assert!(cache.get(b"oversized").is_none());
        assert_eq!(cache.report().unwrap().evictions, 1);
        assert_eq!(cache.report().unwrap().oversized_values, 1);
        assert_eq!(
            TIERS
                .iter()
                .map(|(sets, bytes)| WAYS * sets * bytes)
                .sum::<usize>(),
            2 * 1024 * 1024 * 1024
        );
        cache.finish_trace(&cache.report().unwrap()).unwrap();
        let events: Vec<serde_json::Value> = fs::read_to_string(trace_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let displaced: Vec<_> = events
            .iter()
            .filter(|event| event["result"]["displacedRecordBytes"].is_number())
            .collect();
        assert_eq!(displaced.len(), 1);
        assert_eq!(
            displaced[0]["result"]["displacedRecordBytes"],
            HEADER_BYTES + 8
        );
        let oversized = events
            .iter()
            .find(|event| event["result"]["kind"] == "oversized")
            .unwrap();
        assert_eq!(oversized["valueBytes"], TIERS.last().unwrap().1);
        assert_eq!(oversized["compileInterval"]["kind"], "matched");
        assert_eq!(oversized["compileInterval"]["precedingLookup"], "miss");
        assert!(oversized["compileInterval"]["threadCpuNanoseconds"].is_u64());
        assert_eq!(events.last().unwrap()["counters"]["evictions"], 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_insertion_does_not_displace_another_function() {
        let root = root("duplicates");
        let cache = IncrementalCache::open(root.clone(), [1; 32], None).unwrap();
        let key = b"same-function";
        for _ in 0..WAYS * 2 {
            assert!(cache.insert(key, b"compiled bytes".to_vec()));
        }
        let occupied = cache
            .paths(&cache.key(key), 0)
            .iter()
            .filter(|path| path.exists())
            .count();
        assert_eq!(occupied, 1);
        assert_eq!(cache.report().unwrap().evictions, 0);
        assert_eq!(cache.get(key).unwrap().as_ref(), b"compiled bytes");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_size_class_survives_reopening_and_is_authenticated() {
        let root = root("classes");
        let cache = IncrementalCache::open(root.clone(), [1; 32], None).unwrap();
        for (tier, (_, limit)) in TIERS.iter().enumerate() {
            let value = vec![tier as u8; limit - HEADER_BYTES];
            assert!(cache.insert(&(tier as u64).to_le_bytes(), value));
        }
        drop(cache);
        let cache = IncrementalCache::open(root.clone(), [1; 32], None).unwrap();
        for (tier, (_, limit)) in TIERS.iter().enumerate() {
            let key = (tier as u64).to_le_bytes();
            let value = cache.get(&key).unwrap();
            assert_eq!(value.len(), limit - HEADER_BYTES);
            assert!(value.iter().all(|byte| *byte == tier as u8));
        }
        assert_eq!(cache.report().unwrap().rejected_records, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_stores_publish_complete_authenticated_records() {
        let root = root("concurrent");
        let caches: Vec<_> = (0..4)
            .map(|_| Arc::new(IncrementalCache::open(root.clone(), [1; 32], None).unwrap()))
            .collect();
        std::thread::scope(|scope| {
            for cache in &caches {
                scope.spawn(|| {
                    for i in 0..64_u64 {
                        let key = i.to_le_bytes();
                        assert!(cache.insert(&key, key.to_vec()));
                        if let Some(value) = cache.get(&key) {
                            assert_eq!(value.as_ref(), key);
                        }
                    }
                });
            }
        });
        for cache in &caches {
            assert_eq!(cache.report().unwrap().rejected_records, 0);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlinks_and_shared_permissions_are_not_cache_authority() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = root("permissions");
        let cache = IncrementalCache::open(root.clone(), [1; 32], None).unwrap();
        assert!(cache.insert(b"function", b"value".to_vec()));
        let path = cache.paths(&cache.key(b"function"), 0)[0].clone();
        fs::remove_file(&path).unwrap();
        symlink(cache.root.join("authentication-key"), &path).unwrap();
        assert!(cache.get(b"function").is_none());
        assert!(cache.report().is_err());
        assert!(cache.report().is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(IncrementalCache::open(root.clone(), [1; 32], None).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
