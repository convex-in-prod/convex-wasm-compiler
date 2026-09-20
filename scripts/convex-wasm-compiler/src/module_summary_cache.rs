use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail, ensure};

use super::{MODULE_SUMMARY_SCHEMA, OXC_VERSION, hash_bytes};

const MODULE_SUMMARY_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;
const MODULE_SUMMARY_CACHE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MODULE_SUMMARY_TEMP_MAX_AGE: Duration = Duration::from_secs(60 * 60);
#[derive(Debug, Default)]
pub(super) struct ModuleSummaryCacheGc {
    pub(super) initial_files: usize,
    pub(super) initial_bytes: u64,
    pub(super) removed_age_files: usize,
    pub(super) removed_age_bytes: u64,
    pub(super) removed_size_files: usize,
    pub(super) removed_size_bytes: u64,
    pub(super) removed_stale_temp_files: usize,
    pub(super) removed_stale_temp_bytes: u64,
    pub(super) active_temp_files: usize,
    pub(super) active_temp_bytes: u64,
    pub(super) remaining_files: usize,
    pub(super) remaining_bytes: u64,
}

/// Read a published summary only when the directory entry is an ordinary file.
///
/// Cache summaries are derived evidence, but accepting a symlink here would let a
/// cache-path replacement redirect the compiler to arbitrary bytes between the
/// cache lookup and semantic validation.  The prune pass rejects such entries too;
/// keep the lookup boundary fail-closed instead of relying on a later maintenance
/// pass.
pub(super) fn read_module_summary_cache(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "module summary cache entry is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.mode() & 0o777 == 0o600,
        "module summary cache entry is not private: {}",
        path.display()
    );
    ensure!(
        metadata.uid() == current_uid(),
        "module summary cache entry is not owned by the current user: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= MODULE_SUMMARY_CACHE_MAX_BYTES,
        "module summary cache entry exceeds its byte limit: {}",
        path.display()
    );
    // Open once and compare the descriptor identity with the directory entry.
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        // Another compiler may prune an idle entry after the directory-entry
        // check.  A cache eviction is a miss, not a compiler failure.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to read module summary cache {}", path.display())
            });
        }
    };
    let opened = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        opened.is_file()
            && opened.dev() == metadata.dev()
            && opened.ino() == metadata.ino()
            && opened.len() == metadata.len()
            && opened.mode() & 0o777 == 0o600
            && opened.uid() == current_uid(),
        "module summary cache entry changed before it was read: {}",
        path.display()
    );
    let expected_len =
        usize::try_from(opened.len()).context("module summary cache entry is too large")?;
    let mut bytes = Vec::with_capacity(expected_len);
    let mut buffer = [0u8; 64 * 1024];
    while bytes.len() < expected_len {
        let remaining = expected_len - bytes.len();
        let read_len = remaining.min(buffer.len());
        let count = file
            .read(&mut buffer[..read_len])
            .with_context(|| format!("failed to read module summary cache {}", path.display()))?;
        ensure!(
            count > 0,
            "module summary cache entry changed while it was being read: {}",
            path.display()
        );
        bytes.extend_from_slice(&buffer[..count]);
    }
    let after = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        after.is_file()
            && opened.dev() == after.dev()
            && opened.ino() == after.ino()
            && opened.len() == after.len()
            && opened.mode() & 0o777 == after.mode() & 0o777
            && opened.uid() == after.uid()
            && opened.mtime() == after.mtime()
            && opened.mtime_nsec() == after.mtime_nsec()
            && opened.ctime() == after.ctime()
            && opened.ctime_nsec() == after.ctime_nsec(),
        "module summary cache entry changed while it was being read: {}",
        path.display()
    );
    let path_after = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        // The descriptor already provided a stable, authenticated snapshot.  A
        // concurrent cache eviction can remove the path without invalidating the
        // bytes we just read.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Some(bytes)),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    ensure!(
        path_after.file_type().is_file()
            && !path_after.file_type().is_symlink()
            && path_after.dev() == opened.dev()
            && path_after.ino() == opened.ino()
            && path_after.mode() & 0o777 == 0o600
            && path_after.uid() == current_uid(),
        "module summary cache entry changed while it was being read: {}",
        path.display()
    );
    Ok(Some(bytes))
}

pub(super) fn current_uid() -> u32 {
    // `geteuid` is a read-only libc query and is available on every Unix target
    // supported by this compiler (the binary already uses std::os::unix APIs).
    unsafe { libc::geteuid() }
}

struct ModuleSummaryCacheEntry {
    path: PathBuf,
    bytes: u64,
    modified: SystemTime,
    temporary: bool,
}

fn private_module_summary_cache_directory(path: &Path) -> Result<Option<fs::Metadata>> {
    let path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    ensure!(
        path_metadata.file_type().is_dir() && !path_metadata.file_type().is_symlink(),
        "module summary cache path is not a directory: {}",
        path.display()
    );
    ensure!(
        path_metadata.uid() == current_uid(),
        "module summary cache directory is not owned by the current user: {}",
        path.display()
    );
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let opened = directory
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        opened.is_dir()
            && opened.dev() == path_metadata.dev()
            && opened.ino() == path_metadata.ino()
            && opened.uid() == current_uid(),
        "module summary cache directory changed while it was opened: {}",
        path.display()
    );
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to secure {}", path.display()))?;
    let secured = directory
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    let path_after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        secured.is_dir()
            && path_after.file_type().is_dir()
            && !path_after.file_type().is_symlink()
            && secured.dev() == path_after.dev()
            && secured.ino() == path_after.ino()
            && secured.uid() == current_uid()
            && path_after.uid() == current_uid()
            && secured.mode() & 0o777 == 0o700
            && path_after.mode() & 0o777 == 0o700,
        "module summary cache directory is not stable and private: {}",
        path.display()
    );
    Ok(Some(secured))
}

fn create_private_module_summary_cache_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to create {}", path.display()));
        }
    }
    ensure!(
        private_module_summary_cache_directory(path)?.is_some(),
        "module summary cache directory disappeared: {}",
        path.display()
    );
    Ok(())
}

pub(super) fn prepare_module_summary_cache_parent(
    cache_dir: &Path,
    cache_key: &str,
) -> Result<PathBuf> {
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("failed to create {}", cache_dir.display()))?;
    let root = cache_dir.join("module-summaries");
    create_private_module_summary_cache_directory(&root)?;
    let parent = root.join(&cache_key[..2]);
    create_private_module_summary_cache_directory(&parent)?;
    Ok(parent)
}

pub(super) fn module_summary_cache_key(
    module_key: &str,
    source_hash: &str,
    compiler_pipeline_sha256: &str,
    context_policy_fingerprint: &str,
) -> String {
    hash_bytes(
        format!(
            "{MODULE_SUMMARY_SCHEMA}\0{OXC_VERSION}\0{compiler_pipeline_sha256}\0\
             {context_policy_fingerprint}\0{module_key}\0{source_hash}"
        )
        .as_bytes(),
    )
}
fn module_summary_cache_file_kind(path: &Path) -> Result<bool> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("module summary cache file name is not UTF-8")?;
    let (cache_key, temporary) = if let Some(cache_key) = name.strip_suffix(".json") {
        (cache_key, false)
    } else if let Some(temporary) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    {
        let mut parts = temporary.split('.');
        let cache_key = parts.next().unwrap_or_default();
        let pid = parts.next().unwrap_or_default();
        ensure!(
            !pid.is_empty()
                && pid.bytes().all(|byte| byte.is_ascii_digit())
                && parts.next().is_none(),
            "invalid module summary cache temporary file name: {}",
            path.display()
        );
        (cache_key, true)
    } else {
        bail!(
            "unsupported module summary cache file name: {}",
            path.display()
        );
    };
    ensure!(
        cache_key.len() == 64
            && cache_key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid module summary cache key in {}",
        path.display()
    );
    let prefix = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .context("module summary cache file has no UTF-8 prefix directory")?;
    ensure!(
        prefix == &cache_key[..2],
        "module summary cache prefix disagrees with its key: {}",
        path.display()
    );
    Ok(temporary)
}

fn module_summary_cache_entries(root: &Path) -> Result<Vec<ModuleSummaryCacheEntry>> {
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Some(before) = private_module_summary_cache_directory(&directory)? else {
            continue;
        };
        let children = match fs::read_dir(&directory) {
            Ok(children) => children,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read {}", directory.display()));
            }
        };
        for child in children {
            let child = child
                .with_context(|| format!("failed to read an entry in {}", directory.display()))?;
            let file_type = child
                .file_type()
                .with_context(|| format!("failed to inspect {}", child.path().display()))?;
            ensure!(
                !file_type.is_symlink(),
                "module summary cache must not contain a symbolic link: {}",
                child.path().display()
            );
            if file_type.is_dir() {
                pending.push(child.path());
                continue;
            }
            ensure!(
                file_type.is_file(),
                "module summary cache contains an unsupported entry: {}",
                child.path().display()
            );
            let metadata = child
                .metadata()
                .with_context(|| format!("failed to inspect {}", child.path().display()))?;
            entries.push(ModuleSummaryCacheEntry {
                path: child.path(),
                bytes: metadata.len(),
                modified: metadata.modified().with_context(|| {
                    format!(
                        "failed to read modification time for {}",
                        child.path().display()
                    )
                })?,
                temporary: module_summary_cache_file_kind(&child.path())?,
            });
        }
        let after = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", directory.display()));
            }
        };
        if !(after.file_type().is_dir()
            && !after.file_type().is_symlink()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.uid() == after.uid()
            && before.mode() & 0o777 == after.mode() & 0o777
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec())
        {
            // Concurrent publication changes directory metadata. Skip this GC pass
            // instead of deleting from an enumeration that is no longer stable.
            return Ok(Vec::new());
        }
    }
    Ok(entries)
}

fn remove_module_summary_cache_entry(entry: &ModuleSummaryCacheEntry) -> Result<bool> {
    match fs::remove_file(&entry.path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {}", entry.path.display()))
        }
    }
}

pub(super) fn prune_module_summary_cache(
    cache_dir: &Path,
    max_bytes: u64,
    max_age: Duration,
    now: SystemTime,
) -> Result<ModuleSummaryCacheGc> {
    ensure!(
        max_bytes > 0,
        "module summary cache byte limit must be positive"
    );
    let root = cache_dir.join("module-summaries");
    let entries = module_summary_cache_entries(&root)?;
    let mut result = ModuleSummaryCacheGc::default();
    let mut published = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.temporary {
            let stale = now
                .duration_since(entry.modified)
                .is_ok_and(|age| age > MODULE_SUMMARY_TEMP_MAX_AGE);
            if stale && remove_module_summary_cache_entry(&entry)? {
                result.removed_stale_temp_files += 1;
                result.removed_stale_temp_bytes = result
                    .removed_stale_temp_bytes
                    .checked_add(entry.bytes)
                    .context("module summary stale-temp byte count overflow")?;
            }
            continue;
        }
        result.initial_files += 1;
        result.initial_bytes = result
            .initial_bytes
            .checked_add(entry.bytes)
            .context("module summary cache size overflow")?;
        published.push(entry);
    }
    let mut retained = Vec::with_capacity(published.len());
    for entry in published {
        let expired = now
            .duration_since(entry.modified)
            .is_ok_and(|age| age > max_age);
        if expired && remove_module_summary_cache_entry(&entry)? {
            result.removed_age_files += 1;
            result.removed_age_bytes = result
                .removed_age_bytes
                .checked_add(entry.bytes)
                .context("module summary age-prune byte count overflow")?;
        } else {
            retained.push(entry);
        }
    }
    retained.sort_by(|left, right| (left.modified, &left.path).cmp(&(right.modified, &right.path)));
    let mut retained_bytes = retained.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.bytes)
            .context("module summary retained size overflow")
    })?;
    for entry in retained {
        if retained_bytes <= max_bytes {
            break;
        }
        if remove_module_summary_cache_entry(&entry)? {
            retained_bytes = retained_bytes
                .checked_sub(entry.bytes)
                .context("module summary size-prune byte count underflow")?;
            result.removed_size_files += 1;
            result.removed_size_bytes = result
                .removed_size_bytes
                .checked_add(entry.bytes)
                .context("module summary size-prune byte count overflow")?;
        }
    }
    let remaining = module_summary_cache_entries(&root)?;
    for entry in remaining {
        if entry.temporary {
            result.active_temp_files += 1;
            result.active_temp_bytes = result
                .active_temp_bytes
                .checked_add(entry.bytes)
                .context("module summary active-temp byte count overflow")?;
        } else {
            result.remaining_files += 1;
            result.remaining_bytes = result
                .remaining_bytes
                .checked_add(entry.bytes)
                .context("module summary remaining size overflow")?;
        }
    }
    ensure!(
        result.remaining_bytes <= max_bytes,
        "module summary cache still exceeds its byte limit: {} > {}",
        result.remaining_bytes,
        max_bytes
    );
    Ok(result)
}

pub(super) fn touch_module_summary_cache_entry(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "module summary cache entry is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.mode() & 0o777 == 0o600 && metadata.uid() == current_uid(),
        "module summary cache entry is not a private file owned by the current user: {}",
        path.display()
    );
    let file = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        // A concurrent prune may remove the entry after the metadata check. The
        // touch is only an LRU hint, so losing that hint is harmless.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to open {}", path.display()));
        }
    };
    let opened = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        opened.is_file()
            && opened.dev() == metadata.dev()
            && opened.ino() == metadata.ino()
            && opened.mode() & 0o777 == 0o600
            && opened.uid() == current_uid(),
        "module summary cache entry changed before it was touched: {}",
        path.display()
    );
    file.set_modified(SystemTime::now())
        .with_context(|| format!("failed to touch {}", path.display()))?;
    let path_after = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        // Pruning may unlink the entry immediately after it is touched.  The
        // touch is only an LRU hint, so losing that hint is harmless.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    ensure!(
        path_after.file_type().is_file()
            && !path_after.file_type().is_symlink()
            && path_after.dev() == opened.dev()
            && path_after.ino() == opened.ino()
            && path_after.mode() & 0o777 == 0o600
            && path_after.uid() == current_uid(),
        "module summary cache entry changed while it was being touched: {}",
        path.display()
    );
    Ok(())
}

pub(crate) fn prune_and_log_module_summary_cache(cache_dir: &Path, phase: &str) -> Result<()> {
    let result = prune_module_summary_cache(
        cache_dir,
        MODULE_SUMMARY_CACHE_MAX_BYTES,
        MODULE_SUMMARY_CACHE_MAX_AGE,
        SystemTime::now(),
    )?;
    log_module_summary_cache_gc(phase, &result);
    Ok(())
}

fn log_module_summary_cache_gc(phase: &str, result: &ModuleSummaryCacheGc) {
    eprintln!(
        "convex-wasm-module-summary-gc phase={phase} \
         maxBytes={MODULE_SUMMARY_CACHE_MAX_BYTES} \
         maxAgeSeconds={} \
         tempMaxAgeSeconds={} \
         initialFiles={} initialBytes={} \
         removedAgeFiles={} removedAgeBytes={} \
         removedSizeFiles={} removedSizeBytes={} \
         removedStaleTempFiles={} removedStaleTempBytes={} \
         activeTempFiles={} activeTempBytes={} \
         remainingFiles={} remainingBytes={}",
        MODULE_SUMMARY_CACHE_MAX_AGE.as_secs(),
        MODULE_SUMMARY_TEMP_MAX_AGE.as_secs(),
        result.initial_files,
        result.initial_bytes,
        result.removed_age_files,
        result.removed_age_bytes,
        result.removed_size_files,
        result.removed_size_bytes,
        result.removed_stale_temp_files,
        result.removed_stale_temp_bytes,
        result.active_temp_files,
        result.active_temp_bytes,
        result.remaining_files,
        result.remaining_bytes
    );
}
