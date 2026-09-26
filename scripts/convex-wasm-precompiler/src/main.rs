use std::{
    error::Error,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    hash::{Hash, Hasher},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use wasmtime::{Config, Engine, Precompiled, ProfilingStrategy};

const USAGE: &str = "usage: convex-wasm-precompiler INPUT.wasm OUTPUT.cwasm \
    --engine-identity ENGINE_IDENTITY.json \
    --consume-fuel true \
    --epoch-interruption true \
    --wasm-exceptions true \
    --profiling-strategy perf-map \
    --target-triple TARGET_TRIPLE \
    --target-cpu baseline \
    --parallel-compilation-workers POSITIVE_INTEGER_UP_TO_AVAILABLE_CPUS";
const MAX_CORE_WASM_BYTES: usize = 320 * 1024 * 1024;
const MAX_AOT_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineConfigIdentity {
    consume_fuel: bool,
    epoch_interruption: bool,
    profiling_strategy: &'static str,
    wasm_exceptions: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetIdentity<'a> {
    cpu: &'static str,
    triple: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineIdentity<'a> {
    engine_compatibility_sha256: String,
    engine_config: EngineConfigIdentity,
    kind: &'static str,
    target: TargetIdentity<'a>,
}

#[derive(Default)]
struct Sha256CompatibilityHasher(Sha256);

impl Sha256CompatibilityHasher {
    fn finalize(self) -> String {
        format!("{:x}", self.0.finalize())
    }
}

impl Hasher for Sha256CompatibilityHasher {
    fn finish(&self) -> u64 {
        let digest = self.0.clone().finalize();
        u64::from_le_bytes(
            digest[..8]
                .try_into()
                .expect("SHA-256 digest prefix has eight bytes"),
        )
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn write_u8(&mut self, value: u8) {
        self.write(&value.to_le_bytes());
    }

    fn write_u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    fn write_u128(&mut self, value: u128) {
        self.write(&value.to_le_bytes());
    }

    fn write_usize(&mut self, value: usize) {
        self.write(
            &u64::try_from(value)
                .expect("generated Wasm compatibility hashing requires at most 64-bit usize")
                .to_le_bytes(),
        );
    }

    fn write_i8(&mut self, value: i8) {
        self.write(&value.to_le_bytes());
    }

    fn write_i16(&mut self, value: i16) {
        self.write(&value.to_le_bytes());
    }

    fn write_i32(&mut self, value: i32) {
        self.write(&value.to_le_bytes());
    }

    fn write_i64(&mut self, value: i64) {
        self.write(&value.to_le_bytes());
    }

    fn write_i128(&mut self, value: i128) {
        self.write(&value.to_le_bytes());
    }

    fn write_isize(&mut self, value: isize) {
        self.write(
            &i64::try_from(value)
                .expect("generated Wasm compatibility hashing requires at most 64-bit isize")
                .to_le_bytes(),
        );
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "convex-wasm-precompiler: {}",
                format_error_chain(error.as_ref())
            );
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let input = PathBuf::from(required_argument(arguments.next(), "input Core Wasm path")?);
    let output = PathBuf::from(required_argument(
        arguments.next(),
        "output precompiled artifact path",
    )?);
    require_option(&mut arguments, "--engine-identity")?;
    let engine_identity_path = PathBuf::from(required_argument(
        arguments.next(),
        "engine identity output path",
    )?);
    require_option(&mut arguments, "--consume-fuel")?;
    let consume_fuel = required_bool(arguments.next(), "consume-fuel value")?;
    if !consume_fuel {
        return Err("consume-fuel must be true".into());
    }
    require_option(&mut arguments, "--epoch-interruption")?;
    let epoch_interruption = required_bool(arguments.next(), "epoch-interruption value")?;
    if !epoch_interruption {
        return Err("epoch-interruption must be true".into());
    }
    require_option(&mut arguments, "--wasm-exceptions")?;
    let wasm_exceptions = required_bool(arguments.next(), "wasm-exceptions value")?;
    if !wasm_exceptions {
        return Err("wasm-exceptions must be true".into());
    }
    require_option(&mut arguments, "--profiling-strategy")?;
    let profiling_strategy = required_utf8(arguments.next(), "profiling-strategy value")?;
    if profiling_strategy != "perf-map" {
        return Err("profiling-strategy must be perf-map".into());
    }
    require_option(&mut arguments, "--target-triple")?;
    let target_triple = required_utf8(arguments.next(), "target-triple value")?;
    require_option(&mut arguments, "--target-cpu")?;
    let target_cpu = required_utf8(arguments.next(), "target-cpu value")?;
    if target_cpu != "baseline" {
        return Err("target-cpu must be baseline".into());
    }
    require_option(&mut arguments, "--parallel-compilation-workers")?;
    let parallel_compilation_workers = required_parallel_compilation_workers(arguments.next())?;
    if arguments.next().is_some() {
        return Err(USAGE.into());
    }

    ensure_distinct_new_outputs(&output, &engine_identity_path)?;

    let mut config = Config::new();
    config
        .target(&target_triple)?
        .consume_fuel(consume_fuel)
        .epoch_interruption(epoch_interruption)
        .wasm_exceptions(wasm_exceptions)
        .parallel_compilation(true)
        .profiler(ProfilingStrategy::PerfMap);
    let engine = Engine::new(&config)?;
    let wasm = read_bounded_file(&input, MAX_CORE_WASM_BYTES, "Core Wasm input")?;
    let precompiled = precompile_module_with_workers(&engine, &wasm, parallel_compilation_workers)?;
    if Engine::detect_precompiled(&precompiled) != Some(Precompiled::Module) {
        return Err("Wasmtime did not produce a precompiled core module".into());
    }
    if precompiled.len() > MAX_AOT_BYTES {
        return Err("precompiled AOT output exceeds 1 GiB".into());
    }
    let input_bytes = wasm.len();
    let precompiled_bytes = precompiled.len();
    write_and_sync_new_file(&output, &precompiled)?;
    drop(wasm);
    drop(precompiled);
    // Compilation may target another host. The backend's readiness check owns executable
    // loading and module-contract validation before the matching source is activated.
    let engine_identity = EngineIdentity {
        engine_compatibility_sha256: engine_compatibility_sha256(&engine),
        engine_config: EngineConfigIdentity {
            consume_fuel,
            epoch_interruption,
            profiling_strategy: "perf-map",
            wasm_exceptions,
        },
        kind: "convex-wasm-wasmtime-engine-identity",
        target: TargetIdentity {
            cpu: "baseline",
            triple: &target_triple,
        },
    };
    let mut encoded_identity = serde_json::to_vec(&engine_identity)?;
    encoded_identity.push(b'\n');
    write_and_sync_new_file(&engine_identity_path, &encoded_identity)?;
    println!(
        "precompiled {} bytes of Core Wasm into {} bytes with {} worker(s) at {}",
        input_bytes,
        precompiled_bytes,
        parallel_compilation_workers,
        output.display()
    );
    Ok(())
}

fn ensure_distinct_new_outputs(
    output: &Path,
    engine_identity: &Path,
) -> Result<(), Box<dyn Error>> {
    let normalize = |path: &Path| -> Result<PathBuf, Box<dyn Error>> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = path.file_name().ok_or("output path must name a file")?;
        Ok(parent.canonicalize()?.join(file_name))
    };
    let output = normalize(output)?;
    let engine_identity = normalize(engine_identity)?;
    if output == engine_identity {
        return Err("AOT and engine identity outputs must be distinct".into());
    }
    for path in [&output, &engine_identity] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(format!("output already exists: {}", path.display()).into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn format_error_chain(error: &(dyn Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str("\ncaused by: ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

fn precompile_module_with_workers(
    engine: &Engine,
    wasm: &[u8],
    parallel_compilation_workers: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Wasmtime's parallel compiler uses the current Rayon pool. The pool
    // controls resource use only; its width is not an engine or output identity input.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallel_compilation_workers)
        .thread_name(|index| format!("convex-wasm-aot-{index}"))
        .build()?;
    Ok(pool.install(|| engine.precompile_module(wasm))?)
}

fn engine_compatibility_sha256(engine: &Engine) -> String {
    let mut compatibility_hasher = Sha256CompatibilityHasher::default();
    engine
        .precompile_compatibility_hash()
        .hash(&mut compatibility_hasher);
    compatibility_hasher.finalize()
}

fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    description: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let input = File::open(path)?;
    let mut limited = input.take(u64::try_from(max_bytes)? + 1);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(format!("{description} exceeds {max_bytes} bytes").into());
    }
    Ok(bytes)
}

fn write_and_sync_new_file(path: &Path, bytes: &[u8]) -> Result<File, Box<dyn Error>> {
    let mut output = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    if output.metadata()?.len() != u64::try_from(bytes.len())? {
        return Err("precompiled output size changed while it was written".into());
    }
    Ok(output)
}

fn required_argument(argument: Option<OsString>, description: &str) -> Result<OsString, String> {
    argument.ok_or_else(|| format!("missing {description}"))
}

fn required_utf8(argument: Option<OsString>, description: &str) -> Result<String, String> {
    required_argument(argument, description)?
        .into_string()
        .map_err(|_| format!("{description} must be valid UTF-8"))
}

fn required_bool(argument: Option<OsString>, description: &str) -> Result<bool, String> {
    match required_utf8(argument, description)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{description} must be true or false")),
    }
}

fn required_parallel_compilation_workers(argument: Option<OsString>) -> Result<usize, String> {
    let value = required_utf8(argument, "parallel-compilation-workers value")?;
    let workers = value
        .parse::<usize>()
        .map_err(|_| "parallel-compilation-workers must be a positive integer".to_owned())?;
    let available_workers = std::thread::available_parallelism()
        .map_err(|error| format!("failed to determine available parallelism: {error}"))?
        .get();
    if workers == 0 || workers > available_workers {
        return Err(format!(
            "parallel-compilation-workers must be an integer from 1 through {available_workers} available CPUs"
        ));
    }
    Ok(workers)
}

fn require_option(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &str,
) -> Result<(), String> {
    let actual = required_utf8(arguments.next(), expected)?;
    if actual != expected {
        return Err(format!("expected {expected}, got {actual}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::Module;

    #[test]
    fn cross_target_compilation_does_not_require_local_executable_loading() {
        let native_target = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
            ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
            ("macos", "x86_64") => "x86_64-apple-darwin",
            ("macos", "aarch64") => "aarch64-apple-darwin",
            _ => panic!("unsupported precompiler test host"),
        };
        // Include a function so each target actually exercises machine-code generation.
        let wasm = b"\0asm\x01\0\0\0\x01\x05\x01\x60\x00\x01\x7f\x03\x02\x01\x00\x07\x0a\x01\x06answer\x00\x00\x0a\x06\x01\x04\x00\x41\x2a\x0b";
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ] {
            let mut config = Config::new();
            config
                .target(target)
                .unwrap()
                .consume_fuel(true)
                .epoch_interruption(true)
                .wasm_exceptions(true)
                .parallel_compilation(true);
            let engine = Engine::new(&config).unwrap();
            let artifact = precompile_module_with_workers(&engine, wasm, 1).unwrap();
            assert_eq!(
                Engine::detect_precompiled(&artifact),
                Some(Precompiled::Module)
            );
            // These bytes were produced by this exact engine in the test process.
            let loaded = unsafe { Module::deserialize(&engine, &artifact) };
            if target == native_target {
                assert!(loaded.is_ok(), "{target}: {loaded:?}");
            } else {
                assert!(
                    loaded.is_err(),
                    "foreign output must not be locally executable"
                );
            }
        }
    }

    #[test]
    fn output_preflight_rejects_existing_and_aliased_paths() {
        let root = std::env::temp_dir().join(format!(
            "convex-wasm-precompiler-output-preflight-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let output = root.join("artifact.cwasm");
        let identity = root.join("engine.json");
        ensure_distinct_new_outputs(&output, &identity).unwrap();
        assert!(ensure_distinct_new_outputs(&output, &root.join("./artifact.cwasm")).is_err());
        fs::write(&identity, b"existing").unwrap();
        assert!(ensure_distinct_new_outputs(&output, &identity).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compatibility_hasher_uses_stable_primitive_encodings() {
        let mut hasher = Sha256CompatibilityHasher::default();
        hasher.write_u16(0x1234);
        hasher.write_usize(5);
        hasher.write_isize(-2);

        let mut expected = Sha256::new();
        expected.update(0x1234_u16.to_le_bytes());
        expected.update(5_u64.to_le_bytes());
        expected.update((-2_i64).to_le_bytes());
        let expected = expected.finalize();
        assert_eq!(
            hasher.finish(),
            u64::from_le_bytes(expected[..8].try_into().unwrap())
        );
        assert_eq!(hasher.finalize(), format!("{expected:x}"));
    }

    #[test]
    fn parallel_compilation_workers_are_bounded_by_available_parallelism() {
        let available_workers = std::thread::available_parallelism().unwrap().get();
        assert_eq!(
            required_parallel_compilation_workers(Some(available_workers.to_string().into()))
                .unwrap(),
            available_workers
        );
        assert!(required_parallel_compilation_workers(Some("0".into())).is_err());
        assert!(
            required_parallel_compilation_workers(Some((available_workers + 1).to_string().into()))
                .is_err()
        );
    }

    #[test]
    fn bounded_input_reader_rejects_bytes_beyond_the_limit() {
        let root = std::env::temp_dir().join(format!(
            "convex-wasm-precompiler-bounded-input-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&root);
        fs::write(&root, b"four").unwrap();

        assert_eq!(read_bounded_file(&root, 4, "fixture").unwrap(), b"four");
        let error = read_bounded_file(&root, 3, "fixture").unwrap_err();
        assert_eq!(error.to_string(), "fixture exceeds 3 bytes");

        fs::remove_file(root).unwrap();
    }

    #[test]
    fn worker_count_does_not_change_aot_output_or_engine_identity() {
        const WASM: &[u8] = &[
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01,
            0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, 0x61, 0x6e, 0x73, 0x77, 0x65,
            0x72, 0x00, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
        ];
        let mut single_config = Config::new();
        single_config.parallel_compilation(true);
        let single_engine = Engine::new(&single_config).unwrap();
        let mut parallel_config = Config::new();
        parallel_config.parallel_compilation(true);
        let parallel_engine = Engine::new(&parallel_config).unwrap();

        let single = precompile_module_with_workers(&single_engine, WASM, 1).unwrap();
        let parallel = precompile_module_with_workers(&parallel_engine, WASM, 2).unwrap();

        assert_eq!(single, parallel);
        assert_eq!(
            engine_compatibility_sha256(&single_engine),
            engine_compatibility_sha256(&parallel_engine)
        );
    }

    #[test]
    fn precompile_diagnostics_include_too_many_locals_cause() {
        let mut config = Config::new();
        config.parallel_compilation(true);
        let engine = Engine::new(&config).unwrap();
        // One function declares 50,001 locals, above wasmparser's 50,000-local limit.
        let malformed_wasm = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
            0x03, 0x02, 0x01, 0x00, 0x0a, 0x08, 0x01, 0x06, 0x01, 0xd1, 0x86, 0x03, 0x7f, 0x0b,
        ];

        let error = precompile_module_with_workers(&engine, &malformed_wasm, 1).unwrap_err();
        let diagnostic = format_error_chain(error.as_ref());

        assert_eq!(
            diagnostic,
            "failed to compile: wasm[0]::function[0]\
             \ncaused by: WebAssembly translation error\
             \ncaused by: Invalid input WebAssembly code at offset 23: too many locals: locals exceed maximum"
        );
    }
}
