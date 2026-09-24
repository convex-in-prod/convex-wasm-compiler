use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::mpsc,
    thread,
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::adapter_material::{
    DependencyAdapterMaterial, RegistrationAdapterMaterial, validate_dependency_adapter_material,
    validate_registration_adapter_material,
};
use super::context_reuse::{SourceInventory, build_source_inventory};
use super::diagnostic_census::{
    BatchDiagnosticCensusEntry, DiagnosticCensusAccumulator, DiagnosticCensusMembership,
    DiagnosticCensusMembershipTelemetry,
};
use super::{
    CompilerModeOutput, CompilerOutput, EffectExecutionMode, EsbuildMetafile, GeneratedSourceMode,
    GraphInput, PhaseMeasurements, Toolchain, compile_export, is_normalized_functions_root,
    preload_compiler_modules, process_memory_kib, prune_and_log_module_summary_cache,
    serialized_json_size,
};

pub(super) const BATCH_REQUEST_KIND: &str = "convex-wasm-compiler-batch-request";
const BATCH_RESPONSE_KIND: &str = "convex-wasm-compiler-batch-response";
const BATCH_READY_RECORD_KIND: &str = "convex-wasm-compiler-batch-ready-record";
const BATCH_READY_SEAL_KIND: &str = "convex-wasm-compiler-batch-ready-seal";
const MAX_BATCH_RESPONSE_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_BATCH_EXPORT_WORKERS: usize = 6;

fn batch_ready_ordering_key(index: usize, result_count: usize) -> String {
    format!("{index:08x}/{result_count:08x}")
}

fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut canonical = serde_json::to_value(value)?;
    canonical.sort_all_objects();
    serde_json::to_vec(&canonical).context("failed to encode canonical batch ready JSON")
}

fn first_batch_export_failure(
    failures_by_index: Vec<Option<anyhow::Error>>,
) -> Option<(usize, anyhow::Error)> {
    failures_by_index
        .into_iter()
        .enumerate()
        .find_map(|(index, error)| error.map(|error| (index, error)))
}

fn available_batch_export_workers() -> Result<usize> {
    thread::available_parallelism()
        .context("failed to determine available batch export parallelism")
        .map(std::num::NonZeroUsize::get)
}

fn parse_batch_export_workers(value: &str, available_workers: usize) -> Result<usize> {
    let parsed = value
        .parse::<usize>()
        .context("--jobs must be a positive integer")?;
    ensure!(
        (1..=available_workers).contains(&parsed),
        "--jobs must be an integer from 1 through {available_workers} available CPUs"
    );
    Ok(parsed)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchRequest {
    pub(super) kind: String,
    pub(super) mode: String,
    pub(super) compile_selection: Option<BatchCompileSelection>,
    pub(super) common_graph: BatchCommonGraph,
    #[serde(default)]
    pub(super) entry_candidates: Vec<String>,
    #[serde(default)]
    pub(super) authoritative_exports: Vec<BatchAuthoritativeExport>,
    #[serde(default)]
    pub(super) compile_targets: Vec<BatchExport>,
    pub(super) exports: Vec<BatchExport>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchCompileSelection {
    pub(super) kind: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BatchProtocol {
    ExplicitTargets,
    AllEligible,
    ExplicitAuthority,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchCommonGraph {
    pub(super) kind: String,
    pub(super) repo_root: PathBuf,
    pub(super) functions_root: String,
    pub(super) toolchain: Toolchain,
    pub(super) dependency_adapter: DependencyAdapterMaterial,
    pub(super) registration_adapter: RegistrationAdapterMaterial,
    #[serde(default)]
    pub(super) effect_execution_mode: EffectExecutionMode,
    pub(super) assumptions: Option<BatchGraphAssumptions>,
    pub(super) metafile: EsbuildMetafile,
    #[serde(default)]
    pub(super) phase_timings_us: BTreeMap<String, u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchGraphAssumptions {
    pub(super) platform: String,
    pub(super) format: String,
    pub(super) target: String,
    pub(super) conditions: Vec<String>,
    pub(super) graph_construction_semantic_revision: String,
    pub(super) inner_esbuild_source_sha256: String,
    pub(super) plugins: Vec<String>,
    pub(super) production_artifact: bool,
    pub(super) resolution_authority: String,
    pub(super) splitting: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchExport {
    pub(super) entry_path: String,
    pub(super) export_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchAuthoritativeExport {
    pub(super) entry_path: String,
    pub(super) export_name: String,
    pub(super) udf_kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchResult {
    entry_path: String,
    export_name: String,
    output: CompilerOutput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchResponse {
    kind: String,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    compile_selection: Option<BatchCompileSelection>,
    inventory: Option<SourceInventory>,
    auto_selected_exports: Vec<BatchExport>,
    authoritative_selections: Vec<BatchAuthoritativeSelection>,
    compile_targets: Vec<BatchExport>,
    preload: BatchPreloadOutput,
    diagnostic_census: Vec<BatchDiagnosticCensusEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic_census_membership: Option<DiagnosticCensusMembership>,
    ready_seal: BatchReadySeal,
    results: Vec<BatchResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchReadyCompilerContract<'a> {
    output_kind: &'a str,
    compiler: &'a super::CompilerMetadata,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchReadyRecordHeader<'a> {
    kind: &'static str,
    index: usize,
    result_count: usize,
    ordering_key: String,
    entry_path: &'a str,
    export_name: &'a str,
    compiler_contract: BatchReadyCompilerContract<'a>,
    payload_bytes: usize,
    payload_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchReadySeal {
    kind: &'static str,
    records: Vec<BatchReadySealRecord>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchReadySealRecord {
    index: usize,
    result_count: usize,
    ordering_key: String,
    entry_path: String,
    export_name: String,
    payload_bytes: usize,
    payload_sha256: String,
}

struct BatchReadySpool {
    output: Option<BufWriter<File>>,
    records_by_index: Vec<Option<BatchReadySealRecord>>,
}

impl BatchReadySpool {
    fn new(output_path: Option<PathBuf>, result_count: usize) -> Result<Self> {
        let output = output_path
            .map(|path| {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!(
                            "failed to create batch ready output parent {}",
                            parent.display()
                        )
                    })?;
                }
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .with_context(|| {
                        format!("failed to create batch ready output {}", path.display())
                    })
                    .map(BufWriter::new)
            })
            .transpose()?;
        Ok(Self {
            output,
            records_by_index: (0..result_count).map(|_| None).collect(),
        })
    }

    fn record(&mut self, index: usize, result_count: usize, result: &BatchResult) -> Result<()> {
        ensure!(
            index < result_count,
            "batch ready result index {index} is out of range"
        );
        // The final response does not retain each payload's original byte slice. Canonical bytes
        // let the consumer reauthenticate every seal record from parsed final or cached results.
        let payload = canonical_json_bytes(result)?;
        let payload_sha256 = hex::encode(Sha256::digest(&payload));
        let ordering_key = batch_ready_ordering_key(index, result_count);
        let seal_record = BatchReadySealRecord {
            index,
            result_count,
            ordering_key: ordering_key.clone(),
            entry_path: result.entry_path.clone(),
            export_name: result.export_name.clone(),
            payload_bytes: payload.len(),
            payload_sha256: payload_sha256.clone(),
        };
        ensure!(
            self.records_by_index[index].replace(seal_record).is_none(),
            "batch ready result index {index} was recorded twice"
        );
        if let Some(output) = &mut self.output {
            let header = serde_json::to_vec(&BatchReadyRecordHeader {
                kind: BATCH_READY_RECORD_KIND,
                index,
                result_count,
                ordering_key,
                entry_path: &result.entry_path,
                export_name: &result.export_name,
                compiler_contract: BatchReadyCompilerContract {
                    output_kind: &result.output.kind,
                    compiler: &result.output.compiler,
                },
                payload_bytes: payload.len(),
                payload_sha256,
            })?;
            let header_bytes = u32::try_from(header.len())
                .context("batch ready record header exceeds the framing limit")?;
            let payload_bytes = u64::try_from(payload.len())
                .context("batch ready record payload exceeds the framing limit")?;
            output.write_all(&header_bytes.to_be_bytes())?;
            output.write_all(&payload_bytes.to_be_bytes())?;
            output.write_all(&header)?;
            output.write_all(&payload)?;
            output.flush()?;
        }
        Ok(())
    }

    fn seal(mut self) -> Result<BatchReadySeal> {
        if let Some(output) = &mut self.output {
            output.flush()?;
        }
        Ok(BatchReadySeal {
            kind: BATCH_READY_SEAL_KIND,
            records: self
                .records_by_index
                .into_iter()
                .enumerate()
                .map(|(index, record)| {
                    record.with_context(|| format!("batch ready seal omitted result index {index}"))
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchPreloadOutput {
    modules: usize,
    source_bytes: usize,
    worker_count: usize,
    source_read_us: u64,
    cache_lookup_us: u64,
    parse_us: u64,
    semantic_us: u64,
    module_cache_hits: usize,
    module_cache_misses: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchAuthoritativeSelection {
    entry_path: String,
    export_name: String,
    udf_kind: String,
    decision: String,
    reason: String,
}

pub(super) fn batch_protocol(request: &BatchRequest) -> Result<BatchProtocol> {
    ensure!(
        request.kind == BATCH_REQUEST_KIND,
        "unsupported batch request kind {}",
        request.kind
    );
    if request.mode == "analysis" {
        ensure!(
            request.compile_selection.is_none(),
            "analysis mode does not accept compileSelection"
        );
        ensure!(
            request.compile_targets.is_empty(),
            "analysis batch mode requires no compileTargets"
        );
        return Ok(BatchProtocol::ExplicitTargets);
    }
    ensure!(
        request.mode == "compile",
        "unsupported batch mode {}",
        request.mode
    );
    ensure!(
        request.common_graph.assumptions.is_some(),
        "compile mode requires commonGraph assumptions"
    );
    let selection = request
        .compile_selection
        .as_ref()
        .context("compile mode requires compileSelection")?;
    match selection.kind.as_str() {
        "explicitTargets" => {
            ensure!(
                !request.compile_targets.is_empty(),
                "explicitTargets mode requires at least one compileTarget"
            );
            Ok(BatchProtocol::ExplicitTargets)
        }
        "allEligible" => {
            ensure!(
                request.compile_targets.is_empty(),
                "allEligible mode requires no compileTargets"
            );
            ensure!(
                request.exports.is_empty(),
                "allEligible mode requires no exports"
            );
            ensure!(
                !request.entry_candidates.is_empty(),
                "allEligible mode requires entryCandidates"
            );
            ensure!(
                !request.authoritative_exports.is_empty(),
                "allEligible mode requires authoritativeExports"
            );
            Ok(BatchProtocol::AllEligible)
        }
        "explicitAuthority" => {
            ensure!(
                !request.compile_targets.is_empty(),
                "explicitAuthority mode requires at least one compileTarget"
            );
            ensure!(
                request.exports.is_empty(),
                "explicitAuthority mode requires no exports"
            );
            ensure!(
                !request.entry_candidates.is_empty(),
                "explicitAuthority mode requires entryCandidates"
            );
            ensure!(
                !request.authoritative_exports.is_empty(),
                "explicitAuthority mode requires authoritativeExports"
            );
            Ok(BatchProtocol::ExplicitAuthority)
        }
        _ => bail!("unsupported compileSelection kind {}", selection.kind),
    }
}

pub(super) fn run_batch(arguments: Vec<String>) -> Result<()> {
    let available_workers = available_batch_export_workers()?;
    let mut request_path = None;
    let mut cache_dir = None;
    let mut jobs = None;
    let mut output_path = None;
    let mut ready_output_path = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--batch-request" => {
                ensure!(
                    request_path.is_none(),
                    "--batch-request may be specified only once"
                );
                request_path = Some(PathBuf::from(
                    arguments.next().context("--batch-request needs a path")?,
                ));
            }
            "--batch-output" => {
                ensure!(
                    output_path.is_none(),
                    "--batch-output may be specified only once"
                );
                output_path = Some(PathBuf::from(
                    arguments.next().context("--batch-output needs a path")?,
                ));
            }
            "--batch-ready-output" => {
                ensure!(
                    ready_output_path.is_none(),
                    "--batch-ready-output may be specified only once"
                );
                ready_output_path = Some(PathBuf::from(
                    arguments
                        .next()
                        .context("--batch-ready-output needs a path")?,
                ));
            }
            "--cache-dir" => {
                ensure!(
                    cache_dir.is_none(),
                    "--cache-dir may be specified only once"
                );
                cache_dir = Some(PathBuf::from(
                    arguments.next().context("--cache-dir needs a path")?,
                ));
            }
            "--jobs" => {
                ensure!(jobs.is_none(), "--jobs may be specified only once");
                jobs = Some(parse_batch_export_workers(
                    &arguments
                        .next()
                        .context("--jobs needs a positive integer")?,
                    available_workers,
                )?);
            }
            _ => bail!(
                "unknown batch argument {argument}; batch arguments are mutually exclusive with --graph/--output"
            ),
        }
    }
    let request_path = request_path.context("--batch-request is required")?;
    let output_path = output_path.context("--batch-output is required")?;
    let cache_dir = cache_dir.context("--cache-dir is required")?;
    let jobs = jobs.unwrap_or(DEFAULT_BATCH_EXPORT_WORKERS.min(available_workers));
    prune_and_log_module_summary_cache(&cache_dir, "start")?;
    let request_bytes = super::read_bounded_control_file(&request_path, "batch request")?;
    let request: BatchRequest = serde_json::from_slice(&request_bytes)
        .with_context(|| format!("invalid batch JSON {}", request_path.display()))?;
    let protocol = batch_protocol(&request)?;
    ensure!(
        request.common_graph.kind == "convex-wasm-esbuild-graph",
        "unsupported common graph kind {}",
        request.common_graph.kind
    );
    ensure!(
        is_normalized_functions_root(&request.common_graph.functions_root),
        "batch functions root must be a normalized repository-relative directory"
    );
    if let Some(assumptions) = &request.common_graph.assumptions {
        ensure!(
            assumptions.platform == "browser"
                && assumptions.format == "esm"
                && assumptions.target == "esnext"
                && assumptions.conditions == ["convex", "module"]
                && assumptions.graph_construction_semantic_revision
                    == "convex-wasm-deployment-graph-construction"
                && assumptions.inner_esbuild_source_sha256.len() == 64
                && assumptions
                    .inner_esbuild_source_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && assumptions.plugins
                    == [
                        "convex-source-material-snapshot",
                        "convex-async-hooks-shim",
                        "convex-server-only",
                        "convex-node-externals(empty-browser-map)",
                        "convex-wasm",
                    ]
                && !assumptions.production_artifact
                && assumptions.resolution_authority == "esbuild-metafile"
                && assumptions.splitting,
            "unsupported common graph assumptions"
        );
    }
    ensure!(
        request.exports.len() <= 2_048,
        "batch must contain at most 2048 exports"
    );
    ensure!(
        request.entry_candidates.len() <= 2_048,
        "batch must contain at most 2048 entryCandidates"
    );
    ensure!(
        request.authoritative_exports.len() <= 2_048,
        "batch must contain at most 2048 authoritativeExports"
    );
    ensure!(
        request.compile_targets.len() <= 2_048,
        "batch must contain at most 2048 compileTargets"
    );
    ensure!(
        !request.exports.is_empty() || !request.entry_candidates.is_empty(),
        "batch must contain exports or entryCandidates"
    );
    for pair in request.exports.windows(2) {
        ensure!(
            (&pair[0].entry_path, &pair[0].export_name)
                < (&pair[1].entry_path, &pair[1].export_name),
            "batch exports must be lexically sorted and unique"
        );
    }
    for pair in request.entry_candidates.windows(2) {
        ensure!(
            pair[0] < pair[1],
            "batch entryCandidates must be lexically sorted and unique"
        );
    }
    for pair in request.authoritative_exports.windows(2) {
        ensure!(
            (&pair[0].entry_path, &pair[0].export_name)
                < (&pair[1].entry_path, &pair[1].export_name),
            "batch authoritativeExports must be lexically sorted and unique"
        );
    }
    for pair in request.compile_targets.windows(2) {
        ensure!(
            (&pair[0].entry_path, &pair[0].export_name)
                < (&pair[1].entry_path, &pair[1].export_name),
            "batch compileTargets must be lexically sorted and unique"
        );
    }
    for export in &request.authoritative_exports {
        ensure!(
            matches!(export.udf_kind.as_str(), "query" | "mutation" | "action"),
            "authoritative export {}:{} has unsupported kind {}",
            export.entry_path,
            export.export_name,
            export.udf_kind
        );
    }

    let graph = GraphInput {
        kind: request.common_graph.kind,
        repo_root: request.common_graph.repo_root,
        functions_root: request.common_graph.functions_root,
        entry_path: String::new(),
        export_name: String::new(),
        toolchain: request.common_graph.toolchain,
        dependency_adapter: request.common_graph.dependency_adapter,
        registration_adapter: request.common_graph.registration_adapter,
        assumptions: None,
        effect_execution_mode: request.common_graph.effect_execution_mode,
        metafile: request.common_graph.metafile,
        phase_timings_us: request.common_graph.phase_timings_us,
    };
    validate_registration_adapter_material(&graph.repo_root, &graph.registration_adapter)?;
    validate_dependency_adapter_material(&graph.repo_root, &graph.dependency_adapter)?;
    let mut modules = BTreeMap::new();
    let mut preload_phases = PhaseMeasurements::default();
    let inventory = if request.entry_candidates.is_empty() {
        None
    } else {
        let source_inventory = build_source_inventory(
            &graph.repo_root,
            &graph.metafile,
            &request.entry_candidates,
            &cache_dir,
            &mut modules,
            &mut preload_phases,
            &graph.registration_adapter,
            &graph.functions_root,
        )
        .with_context(|| {
            format!(
                "source inventory failed after sourceRead={}us cacheLookup={}us parse={}us semantic={}us cacheHits={} cacheMisses={}",
                preload_phases.source_read_us,
                preload_phases.cache_lookup_us,
                preload_phases.parse_us,
                preload_phases.semantic_us,
                preload_phases.module_cache_hits,
                preload_phases.module_cache_misses
            )
        })?;
        Some(source_inventory)
    };
    ensure!(
        request.authoritative_exports.is_empty() || inventory.is_some(),
        "authoritativeExports requires entryCandidates"
    );
    let compile_target_keys = request
        .compile_targets
        .iter()
        .map(|target| (target.entry_path.clone(), target.export_name.clone()))
        .collect::<BTreeSet<_>>();
    let mut exports = request.exports;
    let mut authoritative_selections = Vec::new();
    let auto_selected_exports = if exports.is_empty() {
        ensure!(
            !request.authoritative_exports.is_empty(),
            "empty exports requires authoritativeExports"
        );
        let source_inventory = inventory.as_ref().context("source inventory is missing")?;
        for authoritative in &request.authoritative_exports {
            let source = source_inventory.functions.iter().find(|source| {
                source.entry_path == authoritative.entry_path
                    && source.export_name == authoritative.export_name
            });
            let unresolved = source_inventory.unresolved_exports.iter().find(|source| {
                source.entry_path == authoritative.entry_path
                    && source.export_name == authoritative.export_name
            });
            let (decision, reason) = if authoritative.udf_kind == "action" {
                ("v8Fallback", "action-runtime")
            } else if let Some(source) = source {
                if source.udf_kind != authoritative.udf_kind {
                    ("v8Fallback", "generated-source-kind-mismatch")
                } else if !source.direct {
                    ("v8Fallback", "registration-reexport")
                } else if protocol == BatchProtocol::ExplicitAuthority
                    && !compile_target_keys.contains(&(
                        authoritative.entry_path.clone(),
                        authoritative.export_name.clone(),
                    ))
                {
                    ("v8Fallback", "not-selected")
                } else {
                    exports.push(BatchExport {
                        entry_path: authoritative.entry_path.clone(),
                        export_name: authoritative.export_name.clone(),
                    });
                    ("compile", "direct-admitted-registration")
                }
            } else if unresolved.is_some_and(|source| source.classification == "objectDestructure")
            {
                ("v8Fallback", "unsupported-registration-builder")
            } else {
                ("v8Fallback", "generated-source-registration-mismatch")
            };
            authoritative_selections.push(BatchAuthoritativeSelection {
                entry_path: authoritative.entry_path.clone(),
                export_name: authoritative.export_name.clone(),
                udf_kind: authoritative.udf_kind.clone(),
                decision: decision.to_string(),
                reason: reason.to_string(),
            });
        }
        exports
            .iter()
            .map(|export| BatchExport {
                entry_path: export.entry_path.clone(),
                export_name: export.export_name.clone(),
            })
            .collect()
    } else if protocol == BatchProtocol::AllEligible {
        exports.clone()
    } else {
        Vec::new()
    };
    let export_count = exports.len();
    let export_keys = exports
        .iter()
        .map(|export| (export.entry_path.clone(), export.export_name.clone()))
        .collect::<BTreeSet<_>>();
    for target in &request.compile_targets {
        ensure!(
            export_keys.contains(&(target.entry_path.clone(), target.export_name.clone())),
            "compile target {}:{} is unknown or not compiler-selected",
            target.entry_path,
            target.export_name
        );
    }
    let requested_compile_targets = request.compile_targets;
    preload_compiler_modules(
        &graph,
        exports.iter().map(|export| export.entry_path.as_str()),
        &cache_dir,
        &mut modules,
        &mut preload_phases,
        jobs,
    )?;
    eprintln!(
        "convex-wasm-batch-preload modules={} sourceBytes={} sourceReadUs={} cacheLookupUs={} \
         parseUs={} semanticUs={} cacheHits={} cacheMisses={}",
        modules.len(),
        modules
            .values()
            .map(|module| module.source.len())
            .sum::<usize>(),
        preload_phases.source_read_us,
        preload_phases.cache_lookup_us,
        preload_phases.parse_us,
        preload_phases.semantic_us,
        preload_phases.module_cache_hits,
        preload_phases.module_cache_misses
    );
    let batch_started = Instant::now();
    let mut diagnostic_census =
        DiagnosticCensusAccumulator::new(export_count, request.mode == "analysis");
    let mut max_result_json_bytes = 0usize;
    let mut retained_results_json_bytes = 0usize;
    let mut results_by_index = (0..export_count)
        .map(|_| None)
        .collect::<Vec<Option<BatchResult>>>();
    let mut actual_compile_targets = Vec::new();
    let mut ready_spool = BatchReadySpool::new(ready_output_path, export_count)?;
    let mut failures_by_index = (0..export_count)
        .map(|_| None)
        .collect::<Vec<Option<anyhow::Error>>>();
    let worker_count = export_count.min(available_workers.min(jobs));
    eprintln!("convex-wasm-batch-workers workers={worker_count} exports={export_count}");
    thread::scope(|scope| -> Result<()> {
        let (sender, receiver) = mpsc::channel();
        for worker_index in 0..worker_count {
            let sender = sender.clone();
            let mut worker_graph = graph.clone();
            let exports = &exports;
            let modules = &modules;
            let cache_dir = &cache_dir;
            let compile_target_keys = &compile_target_keys;
            scope.spawn(move || {
                for index in (worker_index..export_count).step_by(worker_count) {
                    let export = &exports[index];
                    worker_graph.entry_path.clone_from(&export.entry_path);
                    worker_graph.export_name.clone_from(&export.export_name);
                    let compile_target = protocol == BatchProtocol::AllEligible
                        || compile_target_keys
                            .contains(&(export.entry_path.clone(), export.export_name.clone()));
                    let started = Instant::now();
                    let mut phases = PhaseMeasurements::default();
                    let compiled = compile_export(
                        &worker_graph,
                        cache_dir,
                        &mut phases,
                        started,
                        modules,
                        if compile_target {
                            GeneratedSourceMode::Cache
                        } else {
                            GeneratedSourceMode::None
                        },
                    )
                    .with_context(|| {
                        format!(
                            "failed to compile batch export {}:{}",
                            export.entry_path, export.export_name
                        )
                    });
                    if sender
                        .send((index, export.clone(), compile_target, compiled))
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
        drop(sender);
        for completed in 1..=export_count {
            let (index, export, compile_target, compiled) = receiver
                .recv()
                .context("batch export workers stopped before completing every export")?;
            let processed = compiled.and_then(|compiled| {
                if protocol != BatchProtocol::AllEligible {
                    ensure!(
                        !compile_target || compiled.output.eligible,
                        "compile target {}:{} is statically ineligible",
                        export.entry_path,
                        export.export_name
                    );
                } else if compiled.output.eligible {
                    let CompilerModeOutput::Compile(output) = &compiled.output.mode_output else {
                        bail!(
                            "eligible auto-compile target {}:{} did not produce compile output",
                            export.entry_path,
                            export.export_name
                        );
                    };
                    ensure!(
                        output.generated_javascript_artifact.is_some(),
                        "eligible auto-compile target {}:{} did not emit generated source",
                        export.entry_path,
                        export.export_name
                    );
                    actual_compile_targets.push(export.clone());
                } else {
                    ensure!(
                        matches!(
                            &compiled.output.mode_output,
                            CompilerModeOutput::Analysis(_)
                        ),
                        "ineligible auto-compile target {}:{} did not produce compact analysis output",
                        export.entry_path,
                        export.export_name
                    );
                }
                diagnostic_census.record_result(index, compiled.diagnostic_census)?;
                let result = BatchResult {
                    entry_path: export.entry_path,
                    export_name: export.export_name,
                    output: compiled.output,
                };
                ready_spool.record(index, export_count, &result)?;
                Ok(result)
            });
            match processed {
                Ok(result) => {
                    let result_json_bytes = serialized_json_size(&result)?;
                    max_result_json_bytes = max_result_json_bytes.max(result_json_bytes);
                    retained_results_json_bytes += result_json_bytes;
                    ensure!(
                        results_by_index[index].replace(result).is_none(),
                        "batch export worker returned duplicate result index {index}"
                    );
                }
                Err(error) => {
                    ensure!(
                        failures_by_index[index].replace(error).is_none(),
                        "batch export worker returned duplicate failure index {index}"
                    );
                }
            }
            if completed % 32 == 0 || completed == export_count {
                let diagnostic_telemetry = diagnostic_census.telemetry();
                let memory = process_memory_kib()?;
                let rss_kib = memory
                    .map(|(rss_kib, _)| rss_kib.to_string())
                    .unwrap_or_else(|| "unavailable".to_string());
                let peak_rss_kib = memory
                    .map(|(_, peak_rss_kib)| peak_rss_kib.to_string())
                    .unwrap_or_else(|| "unavailable".to_string());
                eprintln!(
                    "convex-wasm-batch-progress completed={completed} total={export_count} \
                 modules={} retainedResultsJsonBytes={retained_results_json_bytes} \
                 maxResultJsonBytes={max_result_json_bytes} \
                 diagnosticOccurrences={} \
                 distinctDiagnostics={} \
                 maxDiagnosticsPerExport={} \
                 rssKiB={rss_kib} peakRssKiB={peak_rss_kib} elapsedMs={}",
                    modules.len(),
                    diagnostic_telemetry.occurrence_count,
                    diagnostic_telemetry.distinct_count,
                    diagnostic_telemetry.max_diagnostics_per_export,
                    batch_started.elapsed().as_millis()
                );
            }
        }
        Ok(())
    })?;
    if let Some((index, error)) = first_batch_export_failure(failures_by_index) {
        return Err(error.context(format!("batch export index {index} failed")));
    }
    let results = results_by_index
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result.with_context(|| format!("batch export worker omitted result index {index}"))
        })
        .collect::<Result<Vec<_>>>()?;
    actual_compile_targets.sort_by(|left, right| {
        (&left.entry_path, &left.export_name).cmp(&(&right.entry_path, &right.export_name))
    });
    if protocol == BatchProtocol::AllEligible {
        let eligibility = results
            .iter()
            .map(|result| {
                (
                    (result.entry_path.as_str(), result.export_name.as_str()),
                    result.output.eligible,
                )
            })
            .collect::<BTreeMap<_, _>>();
        for selection in &mut authoritative_selections {
            if selection.decision != "compile" {
                continue;
            }
            let eligible = eligibility
                .get(&(
                    selection.entry_path.as_str(),
                    selection.export_name.as_str(),
                ))
                .with_context(|| {
                    format!(
                        "compiler candidate {}:{} has no result",
                        selection.entry_path, selection.export_name
                    )
                })?;
            if *eligible {
                selection.reason = "compiler-admitted".to_string();
            } else {
                selection.decision = "v8Fallback".to_string();
                selection.reason = "static-admission".to_string();
            }
        }
    }
    let finalized_diagnostic_census = diagnostic_census.finalize()?;
    let ready_seal = ready_spool.seal()?;
    let diagnostic_census_telemetry = finalized_diagnostic_census.telemetry;
    let diagnostic_census_membership_telemetry = finalized_diagnostic_census
        .membership
        .as_ref()
        .map(DiagnosticCensusMembership::telemetry)
        .transpose()?
        .unwrap_or_else(DiagnosticCensusMembershipTelemetry::default);
    if finalized_diagnostic_census.membership.is_some() {
        ensure!(
            diagnostic_census_membership_telemetry.reference_count
                == diagnostic_census_telemetry.membership_reference_count,
            "diagnostic census membership telemetry disagrees with accumulated references"
        );
    }
    let response = BatchResponse {
        kind: BATCH_RESPONSE_KIND.to_string(),
        mode: request.mode,
        compile_selection: request.compile_selection,
        inventory,
        auto_selected_exports,
        authoritative_selections,
        compile_targets: if protocol == BatchProtocol::AllEligible {
            actual_compile_targets
        } else {
            requested_compile_targets
        },
        preload: BatchPreloadOutput {
            modules: modules.len(),
            source_bytes: modules.values().map(|module| module.source.len()).sum(),
            worker_count,
            source_read_us: preload_phases.source_read_us,
            cache_lookup_us: preload_phases.cache_lookup_us,
            parse_us: preload_phases.parse_us,
            semantic_us: preload_phases.semantic_us,
            module_cache_hits: preload_phases.module_cache_hits,
            module_cache_misses: preload_phases.module_cache_misses,
        },
        diagnostic_census: finalized_diagnostic_census.entries,
        diagnostic_census_membership: finalized_diagnostic_census.membership,
        ready_seal,
        results,
    };
    let response_bytes = serialized_json_size(&response)?;
    let inventory_bytes = serialized_json_size(&response.inventory)?;
    let authoritative_selection_bytes = serialized_json_size(&response.authoritative_selections)?;
    let auto_selected_export_bytes = serialized_json_size(&response.auto_selected_exports)?;
    let compile_target_bytes = serialized_json_size(&response.compile_targets)?;
    let diagnostic_census_bytes = serialized_json_size(&response.diagnostic_census)?;
    let diagnostic_census_membership_bytes = diagnostic_census_membership_telemetry.bytes;
    let results_bytes = serialized_json_size(&response.results)?;
    let inventory_function_count = response
        .inventory
        .as_ref()
        .map_or(0, |inventory| inventory.functions.len());
    eprintln!(
        "convex-wasm-batch-response responseBytes={response_bytes} \
         inventoryBytes={inventory_bytes} \
         inventoryFunctions={inventory_function_count} \
         authoritativeSelectionBytes={authoritative_selection_bytes} \
         authoritativeSelections={} \
         autoSelectedExportBytes={auto_selected_export_bytes} \
         autoSelectedExports={} \
         compileTargetBytes={compile_target_bytes} \
         compileTargets={} \
         diagnosticCensusBytes={diagnostic_census_bytes} \
         diagnosticCensusEntries={} \
         diagnosticCensusMembershipBytes={diagnostic_census_membership_bytes} \
         diagnosticCensusMembershipReferences={} \
         maxDiagnosticCensusMembershipReferencesPerResult={} \
         resultsBytes={results_bytes} \
         results={} \
         diagnosticOccurrences={} \
         maxDiagnosticsPerExport={} \
         maxResultJsonBytes={max_result_json_bytes}",
        response.authoritative_selections.len(),
        response.auto_selected_exports.len(),
        response.compile_targets.len(),
        response.diagnostic_census.len(),
        diagnostic_census_membership_telemetry.reference_count,
        diagnostic_census_membership_telemetry.max_references_per_result,
        response.results.len(),
        diagnostic_census_telemetry.occurrence_count,
        diagnostic_census_telemetry.max_diagnostics_per_export
    );
    ensure!(
        response_bytes <= MAX_BATCH_RESPONSE_BYTES,
        "batch response exceeds {MAX_BATCH_RESPONSE_BYTES} bytes: \
         responseBytes={response_bytes} inventoryBytes={inventory_bytes} \
         inventoryFunctions={inventory_function_count} \
         authoritativeSelectionBytes={authoritative_selection_bytes} \
         authoritativeSelections={} \
         autoSelectedExportBytes={auto_selected_export_bytes} \
         autoSelectedExports={} \
         compileTargetBytes={compile_target_bytes} \
         compileTargets={} \
         diagnosticCensusBytes={diagnostic_census_bytes} \
         diagnosticCensusMembershipBytes={diagnostic_census_membership_bytes} \
         diagnosticCensusMembershipReferences={} \
         maxDiagnosticCensusMembershipReferencesPerResult={} \
         resultsBytes={results_bytes} \
         diagnosticCensusEntries={} results={} \
         diagnosticOccurrences={} \
         distinctDiagnostics={} maxDiagnosticsPerExport={} \
         maxResultJsonBytes={max_result_json_bytes}",
        response.authoritative_selections.len(),
        response.auto_selected_exports.len(),
        response.compile_targets.len(),
        diagnostic_census_membership_telemetry.reference_count,
        diagnostic_census_membership_telemetry.max_references_per_result,
        response.diagnostic_census.len(),
        response.results.len(),
        diagnostic_census_telemetry.occurrence_count,
        diagnostic_census_telemetry.distinct_count,
        diagnostic_census_telemetry.max_diagnostics_per_export
    );
    let encoded = serde_json::to_vec(&response)?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    prune_and_log_module_summary_cache(&cache_dir, "end")?;
    fs::write(&output_path, encoded)
        .with_context(|| format!("failed to write {}", output_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_jobs_are_bounded_by_available_parallelism() {
        let available_workers = available_batch_export_workers().unwrap();
        assert_eq!(
            parse_batch_export_workers(&available_workers.to_string(), available_workers).unwrap(),
            available_workers
        );
        assert!(parse_batch_export_workers("0", available_workers).is_err());
        assert!(
            parse_batch_export_workers(&(available_workers + 1).to_string(), available_workers)
                .is_err()
        );
    }

    #[test]
    fn batch_ready_order_and_failure_precedence_use_result_index() {
        assert_eq!(batch_ready_ordering_key(2, 17), "00000002/00000011");
        let failures = vec![
            Some(anyhow::anyhow!("index zero")),
            None,
            Some(anyhow::anyhow!("index two completed first")),
        ];
        let (index, error) = first_batch_export_failure(failures).unwrap();
        assert_eq!(index, 0);
        assert_eq!(error.to_string(), "index zero");
    }

    #[test]
    fn batch_ready_payload_uses_canonical_object_key_order() {
        #[derive(Serialize)]
        struct OutOfOrderFields {
            second: u8,
            first: u8,
        }

        assert_eq!(
            canonical_json_bytes(&OutOfOrderFields {
                second: 2,
                first: 1,
            })
            .unwrap(),
            br#"{"first":1,"second":2}"#
        );
    }
}
