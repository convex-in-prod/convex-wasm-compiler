use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env, fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, mpsc},
    thread,
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Program};
use oxc_codegen::{Codegen, CodegenOptions};
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, Scoping, SemanticBuilder};
use oxc_span::{GetSpan, SourceType};
use oxc_transformer::{TransformOptions, Transformer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

mod adapter_material;
mod adapter_semantics;
mod admission;
mod callable_control;
mod callable_effects;
mod callable_plan_builder;
mod callable_plans;
mod callable_resolution;
mod callable_value_flow;
mod capability_flow;
mod capability_predicates;
mod capability_specialization;
mod compiler_batch;
mod context_reuse;
mod diagnostic_census;
mod direct_batches;
mod effect_materialization;
mod effect_plan;
mod effect_site_rewrites;
mod generated_source;
mod module_summary_cache;
mod pipeline_identity;
mod query_materialization;
mod query_result_flow;
mod query_values;
mod source_graph;

pub(crate) use adapter_material::{
    RegistrationAdapterMaterial, validate_registration_adapter_material,
};

#[cfg(test)]
use adapter_material::{
    DependencyAdapterCurrentFile, DependencyAdapterCurrentMaterial, DependencyAdapterDescriptor,
    DependencyAdapterDescriptorEntry, DependencyAdapterExportIdentity,
    DependencyAdapterLockMaterial, DependencyAdapterPackageMaterial, DependencyAdapterSemantic,
    DependencyAdapterSemanticSource, DependencyAdapterSemanticUnit,
    DependencyAdapterSubstitutionIdentity, RegistrationAdapterAuthentication,
    RegistrationAdapterDescriptor, RegistrationAdapterDescriptorEntry,
    RegistrationAdapterExportIdentity, RegistrationAdapterSourceMaterial,
    RegistrationAdapterSourceOperation, RegistrationAdapterSourceOperationSemantic,
};
use adapter_material::{
    DependencyAdapterExpectedMaterial, DependencyAdapterMaterial,
    RegistrationAdapterResultParameter, validate_dependency_adapter_material,
};
use adapter_semantics::{
    AppliedDependencyAdapterCall, AppliedRegistrationAdapter, AppliedSourceOperation,
    DependencyAdapterAuthenticationCache, DependencyAdapterCallIndex, adapt_dependency_call,
    adapt_source_operation, apply_registration_adapter,
    diagnose_dependency_adapter_effect_value_flow,
};
#[cfg(test)]
use adapter_semantics::{dependency_adapter_iterable_is_owned, dependency_adapter_material_drift};
use admission::{admit_reachable, is_canonical_sha256_intrinsic, select_value_mode};
use callable_control::{collect_callable_control_skeletons, require_cfg};
use callable_plans::{
    CallableLeafPlanCandidate, ResolvedBinding, ResolvedBindingIndex, bind_callable_control_blocks,
    build_callable_effect_plan_index, collect_callable_leaf_plans,
};
use callable_resolution::{
    StaticSourceTargetCache, cached_static_source_target, index_reachable_static_calls,
};
use capability_flow::{
    LegacyInterproceduralEffectSpecialization, analyze_owned_capabilities,
    build_capability_flow_proof,
};
use capability_predicates::{
    CapabilityBranchCandidate, CapabilityPredicateTemplateCandidate, capability_branches,
    predicate_template, prove_branch_erasability,
};
use capability_specialization::specialize_proved_capability_branches;
use compiler_batch::run_batch;
use context_reuse::{ContextModuleSummary, run_context_reuse};
use diagnostic_census::{DiagnosticCensusKey, diagnostic_census_id};
#[cfg(test)]
use direct_batches::{
    DirectAsyncBatchArgumentAuthorization, DirectAsyncBatchAuthorizationShape,
    DirectAsyncBatchFixedChildAuthorization, DirectBatchHelperContinuationAuthorization,
    DirectBatchHelperDependencyAdapterContinuation, ProvedDirectAsyncBatchShape,
};
use direct_batches::{
    DirectAsyncBatchAuthorization, DirectAsyncBatchCandidate, DirectBatchHelperCandidate,
    PromiseAllSiteCandidate, ProvedDirectAsyncBatch, authenticated_batch_effect_value_closures,
    authorize_direct_async_batches, collect_direct_async_batches, collect_promise_all_sites,
    parse_direct_batch_helper, proved_direct_async_batch,
};
use effect_materialization::{
    AuthorizedEffectSiteIndex, append_legacy_interprocedural_effect_operations,
    materialize_authorized_effect_targets,
};
use effect_site_rewrites::{
    AuthorizedDirectEffectSite, append_direct_effect_site_edits,
    array_producing_direct_effect_site_helpers, direct_effect_site_helper_name,
    direct_effect_site_helper_source,
};
use generated_source::{
    GeneratedArrayArgumentAuthorization, GeneratedArrayFilterIneligibility,
    GeneratedFilterBindings, GeneratedForOfIneligibility, GeneratedJavascriptAuthority,
    GeneratedSourceBindingCollision, ProvedGeneratedFilter, apply_source_edits,
    bind_generated_direct_async_batches, bind_generated_filters,
    generated_top_level_function_spans, lower_generated_javascript_for_effect_execution_mode,
    source_edit,
};
#[cfg(test)]
use generated_source::{GeneratedFilterAuthorization, lower_generated_javascript};
pub(crate) use module_summary_cache::prune_and_log_module_summary_cache;
#[cfg(test)]
use module_summary_cache::prune_module_summary_cache;
use module_summary_cache::{
    current_uid, module_summary_cache_key, prepare_module_summary_cache_parent,
    read_module_summary_cache, touch_module_summary_cache_entry,
};
use pipeline_identity::compiler_pipeline_sha256;
use query_materialization::{authorize_query_value_plans, materialize_authorized_query_values};
use query_result_flow::{
    ProvedQueryResultFlow, QueryResultFlowOutcome, authenticated_query_result_seeds,
    prove_generated_query_result_flow,
};
use source_graph::{
    StaticFunctionReferenceAuthorization, adapt_generated_function_reference, is_admitted_import,
    is_admitted_module_path, is_dependency_adapter_module_path, resolve_graph_import,
    source_fingerprint, source_graph_fingerprint, validate_scheduler_function_references,
};
pub(crate) use source_graph::{
    generated_server_udf_kind, is_normalized_functions_root, is_resolved_generated_server_module,
};

const COMPILER_SCHEMA: &str = "convex-wasm-compiler-output";
const MODULE_SUMMARY_SCHEMA: &str = "convex-wasm-module-summary";
const ABI_VERSION: &str = "convex-wasm-opaque";
const OXC_VERSION: &str = "0.150.0";
const ADMITTED_LANGUAGE_VERSION: u32 = 29;
const MAX_CONTROL_INPUT_BYTES: usize = 512 * 1024 * 1024;
const MAX_BATCH_DIAGNOSTIC_CENSUS_IDS_PER_EXPORT: usize = 16;
const DEFAULT_MODULE_PRELOAD_WORKERS: usize = 6;
const CANONICAL_SHA256_HELPER_MODULE: &str = "shared/sha256.ts";
const CANONICAL_SHA256_HELPER_NAME: &str = "sha256Hex";
const CANONICAL_SHA256_HELPER_SOURCE: &str = include_str!("../../../shared/sha256.ts");
const COMPILER_REVISION: &str = env!("CARGO_PKG_VERSION");
static GENERATED_SOURCE_TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum ValueMode {
    #[serde(rename = "opaque")]
    Opaque,
    #[serde(rename = "guest-native-json")]
    GuestNativeJson,
}

impl ValueMode {
    fn identity(self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::GuestNativeJson => "guest-native-json",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum EffectExecutionMode {
    #[default]
    #[serde(rename = "blocking-fiber")]
    BlockingFiber,
    #[serde(rename = "guest-promise-event-loop")]
    GuestPromiseEventLoop,
}

impl EffectExecutionMode {
    fn identity(self) -> &'static str {
        match self {
            Self::BlockingFiber => "blocking-fiber",
            Self::GuestPromiseEventLoop => "guest-promise-event-loop",
        }
    }

    fn is_blocking(&self) -> bool {
        *self == Self::BlockingFiber
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GraphInput {
    kind: String,
    repo_root: PathBuf,
    functions_root: String,
    entry_path: String,
    export_name: String,
    toolchain: Toolchain,
    dependency_adapter: DependencyAdapterMaterial,
    registration_adapter: RegistrationAdapterMaterial,
    #[serde(default)]
    assumptions: Option<GraphAssumptions>,
    #[serde(default)]
    effect_execution_mode: EffectExecutionMode,
    metafile: EsbuildMetafile,
    #[serde(default)]
    phase_timings_us: BTreeMap<String, u64>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GraphAssumptions {
    platform: String,
    format: String,
    target: String,
    conditions: Vec<String>,
    production_artifact: bool,
    resolution_authority: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Toolchain {
    esbuild: String,
    convex: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct EsbuildMetafile {
    pub(crate) inputs: BTreeMap<String, EsbuildInput>,
    #[serde(default)]
    pub(crate) outputs: BTreeMap<String, EsbuildOutput>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct EsbuildInput {
    #[serde(default)]
    pub(crate) imports: Vec<EsbuildImport>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct EsbuildImport {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) original: Option<String>,
    #[serde(default)]
    pub(crate) external: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EsbuildOutput {
    pub(crate) entry_point: Option<String>,
    #[serde(default)]
    pub(crate) imports: Vec<EsbuildOutputImport>,
    #[serde(default)]
    pub(crate) inputs: BTreeMap<String, EsbuildOutputContribution>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct EsbuildOutputImport {
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) external: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EsbuildOutputContribution {
    pub(crate) bytes_in_output: usize,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportBinding {
    local: String,
    imported: String,
    specifier: String,
    type_only: bool,
    start: u32,
    end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnitSummary {
    name: String,
    kind: String,
    start: u32,
    end: u32,
    source: String,
    callable_range: Option<SourceRange>,
    exported_as: Vec<String>,
    parameters: Vec<ParameterSummary>,
    capability_predicate: Option<CapabilityPredicateTemplateCandidate>,
    static_callable_alias: Option<StaticCallableAliasCandidate>,
    effect_sites: Vec<CallableEffectSiteCandidate>,
    direct_batch_helper: Option<DirectBatchHelperCandidate>,
    registration: Option<RegistrationSummary>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticCallableAliasCandidate {
    target: String,
    reference: SourceRange,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallableEffectSiteCandidate {
    operation: OperationCandidate,
    capability_parameter_index: usize,
    static_operands: Vec<CallableStaticOperandCandidate>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallableStaticOperandCandidate {
    field: String,
    parameter_index: usize,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParameterSummary {
    index: usize,
    name: String,
    start: u32,
    end: u32,
    references: Vec<ReferenceOccurrence>,
    #[serde(default)]
    capability_projections: Vec<CapabilityProjectionSummary>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityProjectionSummary {
    path: Vec<String>,
    binding_start: u32,
    binding_end: u32,
    name: String,
    references: Vec<ReferenceOccurrence>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolvedBindingFact {
    name: String,
    start: u32,
    end: u32,
    references: Vec<ReferenceOccurrence>,
    initializer_start: Option<u32>,
    initializer_end: Option<u32>,
    constant: bool,
    #[serde(default)]
    array_elements: Option<Vec<SourceRange>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConditionalExpressionFact {
    start: u32,
    end: u32,
    consequent_start: u32,
    consequent_end: u32,
    alternate_start: u32,
    alternate_end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallableParameterFact {
    callable_start: u32,
    callable_end: u32,
    parameters: Vec<CallableParameterEntryFact>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallableParameterEntryFact {
    index: usize,
    name: String,
    start: u32,
    end: u32,
}

struct BindingInitializerFact {
    start: u32,
    end: u32,
    constant: bool,
    array_elements: Option<Vec<SourceRange>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PromiseAllAliasHandoffFact {
    binding_start: u32,
    binding_end: u32,
    promise_all_start: u32,
    promise_all_end: u32,
    argument_start: u32,
    argument_end: u32,
    await_start: u32,
    await_end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationSummary {
    kind: String,
    call_start: u32,
    call_end: u32,
    builder_local: String,
    builder_start: u32,
    builder_end: u32,
    handler_start: u32,
    handler_end: u32,
    handler_source: String,
    handler_type: String,
    context_parameter: Option<String>,
    context_parameter_start: Option<u32>,
    context_parameter_end: Option<u32>,
    context_references: Vec<ReferenceOccurrence>,
    argument_fields: Vec<String>,
    array_argument_fields: Vec<String>,
    argument_parameter: Option<String>,
    argument_parameter_start: Option<u32>,
    argument_parameter_end: Option<u32>,
    argument_references: Vec<ReferenceOccurrence>,
    #[serde(default)]
    diagnostics: Vec<RegistrationDiagnosticSummary>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppliedDependencyAdapterProvenance {
    adapter_id: String,
    semantic_kind: String,
    resolved_export: DependencyAdapterAppliedExport,
    #[serde(skip_serializing_if = "Option::is_none")]
    substitution: Option<DependencyAdapterAppliedSubstitution>,
    material: DependencyAdapterExpectedMaterial,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DependencyAdapterAppliedExport {
    module_path: String,
    export_name: String,
    unit_source_sha256: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DependencyAdapterAppliedSubstitution {
    module_specifier: String,
    export_name: String,
    unit_source_sha256: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppliedRegistrationAdapterProvenance {
    adapter_id: String,
    registration_kind: String,
    wrapper: RegistrationAdapterUnitProvenance,
    authentication: RegistrationAdapterAuthenticationProvenance,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationAdapterUnitProvenance {
    module_path: String,
    export_name: String,
    unit_source_sha256: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationAdapterAuthenticationProvenance {
    helper: RegistrationAdapterUnitProvenance,
    result_kind: String,
    result_parameters: Vec<RegistrationAdapterResultParameter>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationDiagnosticSummary {
    code: String,
    message: String,
    start: u32,
    construct: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceOccurrence {
    name: String,
    start: u32,
    end: u32,
    read: bool,
    write: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConstructOccurrence {
    kind: String,
    start: u32,
    end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TryStatementCandidate {
    start: u32,
    end: u32,
    protected_start: u32,
    protected_end: u32,
    catch_start: Option<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationCandidate {
    kind: String,
    start: u32,
    end: u32,
    table: Option<String>,
    index: Option<String>,
    index_constraints: Vec<IndexConstraintCandidate>,
    order: Option<String>,
    terminal: Option<String>,
    limit: Option<u32>,
    #[serde(default)]
    limit_argument_index: Option<u32>,
    algorithm: Option<String>,
    function_reference: Option<String>,
    function_reference_start: Option<u32>,
    function_reference_end: Option<u32>,
    effect_start: Option<u32>,
    effect_end: Option<u32>,
    effect_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalIndexQueryShape {
    order: String,
    terminal: String,
    limit: Option<u32>,
    dynamic_limit: bool,
}

fn canonical_index_query_shape(
    order: Option<&str>,
    terminal: &str,
    limit: Option<u32>,
    dynamic_limit: bool,
) -> Option<CanonicalIndexQueryShape> {
    let order = match order {
        None | Some("asc") => "ascending",
        Some("desc") => "descending",
        Some(_) => return None,
    };
    let (terminal, limit) = match (terminal, limit, dynamic_limit) {
        ("collect", None, false) => ("collect", None),
        ("first", None, false) => ("first", None),
        ("unique", None, false) => ("unique", None),
        ("take", Some(limit @ 1..=100_000), false) => ("collect", Some(limit)),
        ("take", None, true) => ("collect", None),
        _ => return None,
    };
    Some(CanonicalIndexQueryShape {
        order: order.to_string(),
        terminal: terminal.to_string(),
        limit,
        dynamic_limit,
    })
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct IndexConstraintCandidate {
    field: String,
    operator: String,
    value_source: String,
    value_start: u32,
    value_end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EffectCandidate {
    path: String,
    start: u32,
    end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallCandidate {
    callee: String,
    callee_start: u32,
    callee_end: u32,
    start: u32,
    end: u32,
    arguments: Vec<SourceRange>,
    argument_await_counts: Vec<usize>,
    #[serde(default)]
    argument_projections: Vec<Vec<CallArgumentProjectionCandidate>>,
    suspension: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallArgumentProjectionCandidate {
    path: Vec<String>,
    value: SourceRange,
    await_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SourceRange {
    start: u32,
    end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DocumentPropertyCandidate {
    table: String,
    property: String,
    value_type: String,
    start: u32,
    end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum OpaqueBindingOrigin {
    Operation { start: u32, end: u32 },
    Call { start: u32, end: u32 },
    Reference { start: u32, end: u32 },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct OpaqueBindingCandidate {
    name: String,
    binding_start: u32,
    origin: OpaqueBindingOrigin,
    references: Vec<ReferenceOccurrence>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DatabaseResultKind {
    Collection,
    Document,
}

struct DatabaseResultBindingCandidate {
    name: String,
    table: String,
    kind: DatabaseResultKind,
    binding_start: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalArrayBindingCandidate {
    name: String,
    binding_start: u32,
    binding_end: u32,
    initializer_start: u32,
    initializer_end: u32,
    operation_start: u32,
    operation_end: u32,
    enclosing_function_start: Option<u32>,
    enclosing_function_end: Option<u32>,
    references: Vec<ReferenceOccurrence>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConstantArrayBindingCandidate {
    name: String,
    binding_start: u32,
    binding_end: u32,
    initializer_start: u32,
    initializer_end: u32,
    values: Vec<Value>,
    enclosing_function_start: Option<u32>,
    enclosing_function_end: Option<u32>,
    references: Vec<ReferenceOccurrence>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalFilteredArrayCandidate {
    name: String,
    binding_start: u32,
    binding_end: u32,
    initializer_start: u32,
    initializer_end: u32,
    callback_start: u32,
    callback_end: u32,
    source_binding: String,
    source_reference_start: u32,
    source_reference_end: u32,
    argument_root: String,
    argument_root_start: u32,
    argument_root_end: u32,
    argument_field: String,
    predicate_field: String,
    enclosing_function_start: Option<u32>,
    enclosing_function_end: Option<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalSetBindingCandidate {
    name: String,
    binding_start: u32,
    binding_end: u32,
    set_global_start: u32,
    set_global_end: u32,
    enclosing_function_start: Option<u32>,
    enclosing_function_end: Option<u32>,
    references: Vec<ReferenceOccurrence>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticIterableCandidate {
    kind: String,
    start: u32,
    end: u32,
    global_start: Option<u32>,
    global_end: Option<u32>,
    source_start: Option<u32>,
    source_end: Option<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticMemberAccessCandidate {
    root: String,
    first_field: String,
    member_count: usize,
    write: bool,
    root_start: u32,
    root_end: u32,
    start: u32,
    end: u32,
    argument_count: Option<usize>,
    has_spread_argument: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectIdentifierInvocationCandidate {
    callee: String,
    callee_start: u32,
    callee_end: u32,
    start: u32,
    end: u32,
    argument_count: usize,
    has_spread_argument: bool,
    constructor: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectIdentifierOperandCandidate {
    identifier: String,
    start: u32,
    end: u32,
    expression_start: u32,
    expression_end: u32,
    operator: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticMemberChainCandidate {
    root: String,
    root_start: u32,
    root_end: u32,
    start: u32,
    end: u32,
    fields: Vec<String>,
    computed: bool,
    optional: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticFunctionReferenceConsumerCandidate {
    path: String,
    argument_index: usize,
    reference_start: u32,
    reference_end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedApiConventionSummary {
    any_api_local: String,
    any_api_specifier: String,
    any_api_import_start: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ModuleSummary {
    pub(crate) kind: String,
    pub(crate) cache_key: String,
    compiler_pipeline_sha256: String,
    context_policy_fingerprint: String,
    pub(crate) source_hash: String,
    pub(crate) source_bytes: usize,
    pub(crate) imports: BTreeMap<String, ImportBinding>,
    pub(crate) exports: BTreeMap<String, String>,
    pub(crate) units: BTreeMap<String, UnitSummary>,
    capability_branches: Vec<CapabilityBranchCandidate>,
    pub(crate) references: Vec<ReferenceOccurrence>,
    pub(crate) globals: Vec<ReferenceOccurrence>,
    pub(crate) constructs: Vec<ConstructOccurrence>,
    try_statements: Vec<TryStatementCandidate>,
    pub(crate) operations: Vec<OperationCandidate>,
    calls: Vec<CallCandidate>,
    effects: Vec<EffectCandidate>,
    callable_control_skeletons: Vec<callable_control::CallableControlSkeletonCandidate>,
    callable_leaf_plans: Vec<CallableLeafPlanCandidate>,
    resolved_binding_facts: Vec<ResolvedBindingFact>,
    conditional_expression_facts: Vec<ConditionalExpressionFact>,
    callable_parameter_facts: Vec<CallableParameterFact>,
    promise_all_sites: Vec<PromiseAllSiteCandidate>,
    #[serde(default)]
    promise_all_alias_handoffs: Vec<PromiseAllAliasHandoffFact>,
    direct_async_batches: Vec<DirectAsyncBatchCandidate>,
    constant_array_bindings: Vec<ConstantArrayBindingCandidate>,
    local_array_bindings: Vec<LocalArrayBindingCandidate>,
    proved_local_filters: Vec<LocalFilteredArrayCandidate>,
    local_set_bindings: Vec<LocalSetBindingCandidate>,
    static_iterables: Vec<StaticIterableCandidate>,
    static_member_accesses: Vec<StaticMemberAccessCandidate>,
    static_member_calls: Vec<StaticMemberAccessCandidate>,
    direct_identifier_invocations: Vec<DirectIdentifierInvocationCandidate>,
    direct_identifier_operands: Vec<DirectIdentifierOperandCandidate>,
    static_member_chains: Vec<StaticMemberChainCandidate>,
    static_function_reference_consumers: Vec<StaticFunctionReferenceConsumerCandidate>,
    generated_api_convention: Option<GeneratedApiConventionSummary>,
    pub(crate) document_properties: Vec<DocumentPropertyCandidate>,
    opaque_bindings: Vec<OpaqueBindingCandidate>,
    opaque_return_references: Vec<SourceRange>,
    pub(crate) context_reuse: ContextModuleSummary,
}

#[derive(Clone)]
pub(crate) struct LoadedModule {
    pub(crate) summary: Arc<ModuleSummary>,
    source: Arc<String>,
    line_starts: Arc<Vec<usize>>,
    construct_end_by_start: Arc<BTreeMap<u32, u32>>,
}

impl LoadedModule {
    fn new(summary: ModuleSummary, source: String) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        );
        let mut construct_end_by_start = BTreeMap::new();
        for construct in &summary.constructs {
            construct_end_by_start
                .entry(construct.start)
                .and_modify(|end: &mut u32| *end = (*end).min(construct.end))
                .or_insert(construct.end);
        }
        Self {
            summary: Arc::new(summary),
            source: Arc::new(source),
            line_starts: Arc::new(line_starts),
            construct_end_by_start: Arc::new(construct_end_by_start),
        }
    }

    fn line_column(&self, start: u32) -> (usize, usize) {
        let offset = (start as usize).min(self.source.len());
        let line_index = self
            .line_starts
            .partition_point(|line_start| *line_start <= offset)
            .saturating_sub(1);
        (
            line_index + 1,
            offset.saturating_sub(self.line_starts[line_index]) + 1,
        )
    }

    fn diagnostic_end(&self, start: u32) -> u32 {
        self.construct_end_by_start
            .get(&start)
            .copied()
            .unwrap_or_else(|| start.saturating_add(1))
    }
}

#[derive(Default)]
pub(crate) struct PhaseMeasurements {
    pub(crate) graph_read_us: u64,
    pub(crate) source_read_us: u64,
    pub(crate) cache_lookup_us: u64,
    pub(crate) parse_us: u64,
    pub(crate) semantic_us: u64,
    pub(crate) reachability_us: u64,
    pub(crate) admission_us: u64,
    pub(crate) lowering_us: u64,
    pub(crate) module_cache_hits: usize,
    pub(crate) module_cache_misses: usize,
}

impl PhaseMeasurements {
    fn add(&mut self, other: Self) -> Result<()> {
        macro_rules! add_measurement {
            ($field:ident) => {
                self.$field = self
                    .$field
                    .checked_add(other.$field)
                    .context(concat!("phase measurement overflow: ", stringify!($field)))?;
            };
        }
        add_measurement!(graph_read_us);
        add_measurement!(source_read_us);
        add_measurement!(cache_lookup_us);
        add_measurement!(parse_us);
        add_measurement!(semantic_us);
        add_measurement!(reachability_us);
        add_measurement!(admission_us);
        add_measurement!(lowering_us);
        add_measurement!(module_cache_hits);
        add_measurement!(module_cache_misses);
        Ok(())
    }
}

#[derive(Clone)]
struct ReachableUnit {
    id: String,
    module: String,
    name: String,
    start: u32,
    end: u32,
    source: String,
    kind: String,
    dependency_chain: Vec<String>,
    dependencies: BTreeMap<String, u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicReachableUnit {
    id: String,
    module: String,
    name: String,
    kind: String,
    start: u32,
    end: u32,
    line: usize,
    column: usize,
    source_hash: String,
    dependency_chain: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolvedImport {
    importer: String,
    specifier: String,
    imported_name: String,
    resolved: String,
    dependency_chain: Vec<String>,
}

struct ImportedBindingAlias {
    importer_module: String,
    local_binding: String,
    target_binding: String,
    target_unit_id: String,
    import_start: u32,
    dependency_chain: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Diagnostic {
    code: String,
    message: String,
    file: String,
    line: usize,
    column: usize,
    construct: Option<String>,
    source: String,
    dependency_chain: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmittedOperation {
    id: u32,
    stable_key: String,
    kind: String,
    table: Option<String>,
    index: Option<String>,
    index_constraints: Vec<AdmittedIndexConstraint>,
    order: Option<String>,
    terminal: Option<String>,
    limit: Option<u32>,
    limit_argument_index: Option<u32>,
    algorithm: Option<String>,
    function_reference: Option<String>,
    contract_version: Option<u32>,
    selector: Option<String>,
    file: String,
    start: u32,
    end: u32,
    line: usize,
    column: usize,
    source: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmittedIndexConstraint {
    field: String,
    operator: String,
    value_source: String,
}

struct OwnedAdmittedOperation {
    operation: AdmittedOperation,
    intrinsic_function_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Intrinsic {
    function_name: String,
    kind: String,
    operation_id: u32,
}

#[derive(Serialize, Ord, PartialOrd, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct DocumentProperty {
    table: String,
    property: String,
    value_type: String,
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhaseTimings {
    esbuild_graph: u64,
    graph_read: u64,
    source_read: u64,
    cache_lookup: u64,
    parse: u64,
    semantic: u64,
    reachability: u64,
    admission: u64,
    lowering: u64,
    total_rust: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompilerOutput {
    kind: String,
    source: SourceIdentity,
    compiler: CompilerMetadata,
    source_graph_fingerprint: String,
    export_fingerprint: String,
    routing: RoutingDecision,
    eligible: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    applied_dependency_adapters: Vec<AppliedDependencyAdapterProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    applied_registration_adapter: Option<AppliedRegistrationAdapterProvenance>,
    diagnostics: Vec<Diagnostic>,
    proved_direct_async_batches: Vec<ProvedDirectAsyncBatch>,
    #[cfg(test)]
    #[serde(skip)]
    callable_effect_plans: Vec<effect_plan::CallableEffectPlan>,
    #[cfg(test)]
    #[serde(skip)]
    callable_control_plans: Vec<callable_plans::CallableControlPlan>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnostic_census_ids: Vec<String>,
    #[serde(flatten)]
    mode_output: CompilerModeOutput,
    phase_timings_us: PhaseTimings,
    module_cache: ModuleCacheOutput,
}

struct CompiledExport {
    output: CompilerOutput,
    diagnostic_census: Vec<DiagnosticCensusKey>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum CompilerModeOutput {
    Analysis(AnalysisOutput),
    Compile(CompileOutput),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisOutput {
    analysis_summary: AnalysisSummary,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisSummary {
    argument_field_count: usize,
    document_property_count: usize,
    intrinsic_count: usize,
    operation_count: usize,
    operations_by_kind: BTreeMap<String, usize>,
    reachable_module_count: usize,
    reachable_unit_count: usize,
    resolved_import_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompileOutput {
    target: TargetOutput,
    toolchain: OutputToolchain,
    abi_version: String,
    opaque_value_abi_version: u32,
    runtime_inputs: Vec<String>,
    value_mode: ValueMode,
    #[serde(skip_serializing_if = "EffectExecutionMode::is_blocking")]
    effect_execution_mode: EffectExecutionMode,
    limits: ExecutionLimits,
    argument_fields: Vec<String>,
    array_argument_fields: Vec<String>,
    reachable_modules: Vec<String>,
    reachable_units: Vec<PublicReachableUnit>,
    resolved_imports: Vec<ResolvedImport>,
    operations_sha256: String,
    operations: Vec<AdmittedOperation>,
    intrinsics: Vec<Intrinsic>,
    direct_async_batches: Vec<DirectAsyncBatchAuthorization>,
    document_properties: Vec<DocumentProperty>,
    generated_javascript_artifact: Option<GeneratedJavaScriptArtifact>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetOutput {
    entry: String,
    export: String,
    registration_kind: String,
    handler_source: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceIdentity {
    module_path: String,
    export_name: String,
    udf_kind: String,
    resolved_graph_sha256: String,
    export_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompilerMetadata {
    pipeline_sha256: String,
    compiler_revision: String,
    admitted_language_version: u32,
    static_hermes_global_policy: StaticHermesGlobalPolicyIdentity,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StaticHermesGlobalPolicyIdentity {
    kind: String,
    inventory_sha256: String,
    runtime_surface_policy_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoutingDecision {
    decision: String,
}

#[derive(Serialize)]
struct OutputToolchain {
    convex: String,
    esbuild: String,
    oxc: String,
    compiler: String,
    abi: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionLimits {
    execution_time_ms: u64,
    argument_bytes: u64,
    result_bytes: u64,
    documents_read: u64,
    read_bytes: u64,
    documents_written: u64,
    write_bytes: u64,
    scheduled_functions: u64,
    scheduled_argument_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedJavaScriptArtifact {
    suggested_path: String,
    bytes: usize,
    sha256: String,
    source: Option<String>,
    cache_path: Option<String>,
}

#[derive(Copy, Clone)]
enum GeneratedSourceMode {
    None,
    Inline,
    Cache,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleCacheOutput {
    hits: usize,
    misses: usize,
    summary_schema: String,
}

fn main() -> Result<()> {
    let started = Instant::now();
    let mut arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|argument| argument == "context-reuse")
    {
        arguments.remove(0);
        return run_context_reuse(arguments, started);
    }
    if arguments
        .iter()
        .any(|argument| argument == "--batch-request")
    {
        return run_batch(arguments);
    }
    let (graph_path, cache_dir, output_path) = parse_arguments(arguments)?;
    prune_and_log_module_summary_cache(&cache_dir, "start")?;
    let graph_read_started = Instant::now();
    let graph_bytes = read_bounded_control_file(&graph_path, "source graph")?;
    let graph: GraphInput = serde_json::from_slice(&graph_bytes)
        .with_context(|| format!("invalid graph JSON {}", graph_path.display()))?;
    ensure!(
        graph.kind == "convex-wasm-esbuild-graph",
        "unsupported graph kind {}",
        graph.kind
    );
    ensure!(
        is_normalized_functions_root(&graph.functions_root)
            && graph
                .entry_path
                .starts_with(&format!("{}/", graph.functions_root)),
        "source graph entry must be under its configured functions root"
    );
    let assumptions = graph
        .assumptions
        .as_ref()
        .context("source graph assumptions are required")?;
    ensure!(
        assumptions.platform == "browser"
            && assumptions.format == "esm"
            && assumptions.target == "esnext"
            && assumptions.conditions == ["convex", "module"]
            && !assumptions.production_artifact
            && assumptions.resolution_authority == "esbuild-metafile",
        "unsupported source graph assumptions"
    );
    validate_registration_adapter_material(&graph.repo_root, &graph.registration_adapter)?;
    validate_dependency_adapter_material(&graph.repo_root, &graph.dependency_adapter)?;
    let mut phases = PhaseMeasurements {
        graph_read_us: elapsed_us(graph_read_started),
        ..Default::default()
    };
    let mut modules = BTreeMap::new();
    preload_compiler_modules(
        &graph,
        std::iter::once(graph.entry_path.as_str()),
        &cache_dir,
        &mut modules,
        &mut phases,
        module_preload_worker_limit()?,
    )?;
    let compiled = compile_export(
        &graph,
        &cache_dir,
        &mut phases,
        started,
        &modules,
        GeneratedSourceMode::Inline,
    )?;
    ensure!(
        compiled.diagnostic_census.is_empty(),
        "single-export compilation returned batch diagnostic census data"
    );
    let output = compiled.output;
    let encoded = serde_json::to_vec_pretty(&output)?;
    prune_and_log_module_summary_cache(&cache_dir, "end")?;
    if let Some(path) = output_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &encoded)
            .with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", String::from_utf8(encoded)?);
    }
    Ok(())
}

pub(crate) fn read_bounded_control_file(path: &Path, description: &str) -> Result<Vec<u8>> {
    let input = fs::File::open(path)
        .with_context(|| format!("failed to open {description} {}", path.display()))?;
    let mut limited = input.take(u64::try_from(MAX_CONTROL_INPUT_BYTES)? + 1);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {description} {}", path.display()))?;
    ensure!(
        bytes.len() <= MAX_CONTROL_INPUT_BYTES,
        "{description} exceeds {MAX_CONTROL_INPUT_BYTES} bytes: {}",
        path.display()
    );
    Ok(bytes)
}

fn parse_arguments(arguments: Vec<String>) -> Result<(PathBuf, PathBuf, Option<PathBuf>)> {
    let mut graph = None;
    let mut cache_dir = None;
    let mut output = None;
    let mut args = arguments.into_iter();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--graph" => {
                ensure!(graph.is_none(), "--graph may be specified only once");
                graph = Some(PathBuf::from(args.next().context("--graph needs a path")?));
            }
            "--cache-dir" => {
                ensure!(
                    cache_dir.is_none(),
                    "--cache-dir may be specified only once"
                );
                cache_dir = Some(PathBuf::from(
                    args.next().context("--cache-dir needs a path")?,
                ));
            }
            "--output" => {
                ensure!(output.is_none(), "--output may be specified only once");
                output = Some(PathBuf::from(args.next().context("--output needs a path")?));
            }
            _ => bail!("unknown argument {argument}"),
        }
    }
    Ok((
        graph.context("usage: convex-wasm-compiler --graph <graph.json> --cache-dir <dir>")?,
        cache_dir.context("--cache-dir is required")?,
        output,
    ))
}

fn source_range_string(source: &str, range: &SourceRange) -> Option<String> {
    let value = source_slice(source, range.start, range.end).ok()?;
    let allocator = Allocator::default();
    let expression = Parser::new(&allocator, value, SourceType::ts())
        .parse_expression()
        .ok()?;
    let expression_span = expression.span();
    if expression_span.start != 0 || expression_span.end != u32::try_from(value.len()).ok()? {
        return None;
    }
    match expression {
        Expression::StringLiteral(literal) => Some(literal.value.to_string()),
        _ => None,
    }
}

fn compile_export(
    graph: &GraphInput,
    cache_dir: &Path,
    phases: &mut PhaseMeasurements,
    total_started: Instant,
    modules: &BTreeMap<String, LoadedModule>,
    generated_source_mode: GeneratedSourceMode,
) -> Result<CompiledExport> {
    let original_modules = modules;
    let mut specialized_modules = None;
    let mut specialization_pending = true;
    let mut dependency_adapter_authentication_cache = DependencyAdapterAuthenticationCache::new();
    loop {
        let modules = specialized_modules.as_ref().unwrap_or(original_modules);
        let reachability_started = Instant::now();
        let entry = modules
            .get(&graph.entry_path)
            .context("entry module was not preloaded")?;
        let root_local = entry
            .summary
            .exports
            .get(&graph.export_name)
            .with_context(|| {
                format!(
                    "{} has no value export named {}",
                    graph.entry_path, graph.export_name
                )
            })?
            .clone();
        let root_unit =
            entry.summary.units.get(&root_local).with_context(|| {
                format!("export {} has no runtime declaration", graph.export_name)
            })?;
        let mut registration = root_unit.registration.clone().with_context(|| {
            format!(
                "export {} is not a direct Convex registration",
                graph.export_name
            )
        })?;

        let root_dependency_chain = vec![format!("{}#{}", graph.entry_path, graph.export_name)];
        let mut diagnostics = registration
            .diagnostics
            .iter()
            .map(|diagnostic| {
                diagnostic_at(
                    graph,
                    modules,
                    &diagnostic.code,
                    diagnostic.message.clone(),
                    &graph.entry_path,
                    diagnostic.start,
                    Some(diagnostic.construct.clone()),
                    root_dependency_chain.clone(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        // Predicate specialization preserves byte offsets but can change authenticated helper text.
        // Registration identity remains anchored to the original source graph across the reparse.
        let applied_registration_adapter = apply_registration_adapter(
            graph,
            original_modules,
            &mut registration,
            &root_dependency_chain,
            &mut diagnostics,
        )?;
        let root_id = format!("{}#{}:handler", graph.entry_path, graph.export_name);
        let mut queue = VecDeque::from([(
            graph.entry_path.clone(),
            root_local,
            registration.handler_start,
            registration.handler_end,
            root_id,
            root_dependency_chain.clone(),
            registration.handler_source.clone(),
            "handler".to_string(),
        )]);
        let mut reachable = BTreeMap::<String, ReachableUnit>::new();
        let mut resolved_imports = Vec::new();
        let mut imported_binding_aliases = Vec::new();
        let mut static_function_references = Vec::new();
        let mut generated_api_materials = BTreeMap::new();
        let mut applied_dependency_calls = Vec::new();
        let mut applied_source_operations = Vec::new();
        if let Some(adapter) = &applied_registration_adapter {
            resolved_imports.push(ResolvedImport {
                importer: graph.entry_path.clone(),
                specifier: adapter.wrapper_specifier.clone(),
                imported_name: adapter.descriptor.wrapper.export_name.clone(),
                resolved: adapter.wrapper_module.clone(),
                dependency_chain: root_dependency_chain.clone(),
            });
            let helper_module = modules
                .get(&adapter.helper_module)
                .context("registration adapter helper module disappeared")?;
            let helper_unit = helper_module
                .summary
                .units
                .get(&adapter.helper_unit_name)
                .context("registration adapter helper unit disappeared")?;
            let helper_id = format!("{}#{}", adapter.helper_module, adapter.helper_unit_name);
            let mut helper_chain = root_dependency_chain.clone();
            helper_chain.push(helper_id.clone());
            queue.push_back((
                adapter.helper_module.clone(),
                adapter.helper_unit_name.clone(),
                helper_unit.start,
                helper_unit.end,
                helper_id,
                helper_chain,
                helper_unit.source.clone(),
                helper_unit.kind.clone(),
            ));
        }

        while let Some((module_key, name, start, end, id, chain, source, kind)) = queue.pop_front()
        {
            if reachable.contains_key(&id) {
                continue;
            }
            reachable.insert(
                id.clone(),
                ReachableUnit {
                    id: id.clone(),
                    module: module_key.clone(),
                    name: name.clone(),
                    start,
                    end,
                    source,
                    kind,
                    dependency_chain: chain.clone(),
                    dependencies: BTreeMap::new(),
                },
            );
            let references = {
                let module = modules
                    .get(&module_key)
                    .context("reachable module disappeared")?;
                module
                    .summary
                    .references
                    .iter()
                    .filter(|reference| {
                        reference.read && reference.start >= start && reference.end <= end
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            };
            for reference in references {
                let (local_unit, import_binding) = {
                    let module = modules
                        .get(&module_key)
                        .context("reachable module disappeared")?;
                    (
                        module.summary.units.get(&reference.name).cloned(),
                        module.summary.imports.get(&reference.name).cloned(),
                    )
                };
                if let Some(unit) = local_unit {
                    let dependency_id = format!("{module_key}#{}", unit.name);
                    reachable
                        .get_mut(&id)
                        .expect("current reachable unit must remain present")
                        .dependencies
                        .entry(dependency_id.clone())
                        .or_insert(reference.start);
                    let mut dependency_chain = chain.clone();
                    dependency_chain.push(dependency_id.clone());
                    queue.push_back((
                        module_key.clone(),
                        unit.name.clone(),
                        unit.start,
                        unit.end,
                        dependency_id,
                        dependency_chain,
                        unit.source,
                        unit.kind,
                    ));
                    continue;
                }
                let Some(binding) = import_binding else {
                    continue;
                };
                if binding.type_only {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "runtime-type-only-import",
                        format!(
                            "runtime code references type-only import {} from {}",
                            binding.local, binding.specifier
                        ),
                        &module_key,
                        reference.start,
                        Some("ImportDeclaration".to_string()),
                        chain.clone(),
                    )?);
                    continue;
                }
                let resolved = resolve_graph_import(graph, &module_key, &binding.specifier)?;
                resolved_imports.push(ResolvedImport {
                    importer: module_key.clone(),
                    specifier: binding.specifier.clone(),
                    imported_name: binding.imported.clone(),
                    resolved: resolved.clone(),
                    dependency_chain: chain.clone(),
                });
                if adapt_source_operation(
                    graph,
                    modules,
                    &module_key,
                    &id,
                    start,
                    end,
                    &binding,
                    &resolved,
                    &reference,
                    &chain,
                    &mut applied_source_operations,
                    &mut diagnostics,
                )? {
                    continue;
                }
                if adapt_generated_function_reference(
                    graph,
                    modules,
                    &module_key,
                    &binding,
                    &resolved,
                    &reference,
                    &id,
                    &chain,
                    &mut resolved_imports,
                    &mut generated_api_materials,
                    &mut static_function_references,
                    &mut diagnostics,
                )? {
                    continue;
                }
                if adapt_dependency_call(
                    graph,
                    modules,
                    &module_key,
                    &id,
                    start,
                    end,
                    &binding,
                    &resolved,
                    &reference,
                    &registration,
                    &chain,
                    &mut dependency_adapter_authentication_cache,
                    &mut applied_dependency_calls,
                    &mut diagnostics,
                )? {
                    continue;
                }
                if !is_admitted_import(&resolved, &binding.imported) {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-runtime-import",
                        format!(
                            "runtime import {} from {} resolves to unsupported module {}",
                            binding.imported, binding.specifier, resolved
                        ),
                        &module_key,
                        binding.start,
                        Some("ImportDeclaration".to_string()),
                        chain.clone(),
                    )?);
                    continue;
                }
                let target_module = modules
                .get(&resolved)
                .with_context(|| {
                    format!(
                        "admitted module {resolved} resolved from {module_key} was not in the preloaded esbuild graph closure"
                    )
                })?;
                let Some(target_local) = target_module.summary.exports.get(&binding.imported)
                else {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "missing-runtime-export",
                        format!(
                            "{} does not export imported value {}",
                            resolved, binding.imported
                        ),
                        &module_key,
                        binding.start,
                        Some("ImportDeclaration".to_string()),
                        chain.clone(),
                    )?);
                    continue;
                };
                let Some(unit) = target_module.summary.units.get(target_local) else {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "non-runtime-export",
                        format!(
                            "{}#{} has no runtime declaration",
                            resolved, binding.imported
                        ),
                        &module_key,
                        binding.start,
                        Some("ImportDeclaration".to_string()),
                        chain.clone(),
                    )?);
                    continue;
                };
                let dependency_id = format!("{resolved}#{}", unit.name);
                if binding.local != unit.name {
                    imported_binding_aliases.push(ImportedBindingAlias {
                        importer_module: module_key.clone(),
                        local_binding: binding.local.clone(),
                        target_binding: unit.name.clone(),
                        target_unit_id: dependency_id.clone(),
                        import_start: binding.start,
                        dependency_chain: chain.clone(),
                    });
                }
                reachable
                    .get_mut(&id)
                    .expect("current reachable unit must remain present")
                    .dependencies
                    .entry(dependency_id.clone())
                    .or_insert(reference.start);
                let mut dependency_chain = chain.clone();
                dependency_chain.push(dependency_id.clone());
                queue.push_back((
                    resolved,
                    unit.name.clone(),
                    unit.start,
                    unit.end,
                    dependency_id,
                    dependency_chain,
                    unit.source.clone(),
                    unit.kind.clone(),
                ));
            }
        }
        imported_binding_aliases.sort_by(|left, right| {
            (
                &left.importer_module,
                &left.local_binding,
                &left.target_binding,
                &left.target_unit_id,
            )
                .cmp(&(
                    &right.importer_module,
                    &right.local_binding,
                    &right.target_binding,
                    &right.target_unit_id,
                ))
        });
        for pair in imported_binding_aliases.windows(2) {
            if (&pair[0].importer_module, &pair[0].local_binding)
                == (&pair[1].importer_module, &pair[1].local_binding)
            {
                ensure!(
                    pair[0].target_binding == pair[1].target_binding
                        && pair[0].target_unit_id == pair[1].target_unit_id,
                    "imported local binding has conflicting flattened targets"
                );
            }
        }
        imported_binding_aliases.dedup_by(|left, right| {
            left.importer_module == right.importer_module
                && left.local_binding == right.local_binding
                && left.target_binding == right.target_binding
                && left.target_unit_id == right.target_unit_id
        });
        let module_dependencies = reachable_module_dependencies(&reachable)?;
        if let Some((from_module, to_module)) = reachable_module_cycle_edge(&module_dependencies) {
            let dependency = module_dependencies
                .get(from_module)
                .and_then(|dependencies| dependencies.get(to_module))
                .context("reachable module cycle edge lost its source provenance")?;
            let unit = reachable
                .get(&dependency.unit_id)
                .context("reachable module cycle unit disappeared")?;
            diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-module-initialization-cycle",
            "reachable runtime module cycle cannot preserve ESM initialization order in flattened source"
                .to_string(),
            &unit.module,
            dependency.reference_start,
            Some("Identifier".to_string()),
            unit.dependency_chain.clone(),
        )?);
        }
        phases.reachability_us += elapsed_us(reachability_started);
        let dependency_adapter_call_index =
            DependencyAdapterCallIndex::new(&applied_dependency_calls);
        let value_mode = select_value_mode(modules, &reachable)?;
        let static_calls = index_reachable_static_calls(graph, modules, &reachable)?;
        let capability_flow_proof = build_capability_flow_proof(
            modules,
            &reachable,
            &static_calls,
            &registration,
            applied_registration_adapter.as_ref(),
        )?;
        if specialization_pending {
            specialization_pending = false;
            if let Some(updated_modules) = specialize_proved_capability_branches(
                graph,
                modules,
                &reachable,
                &capability_flow_proof,
                phases,
            )? {
                specialized_modules = Some(updated_modules);
                continue;
            }
        }

        let admission_started = Instant::now();
        diagnose_flattened_runtime_binding_collisions(
            graph,
            modules,
            &reachable,
            &imported_binding_aliases,
            &applied_dependency_calls,
            &applied_source_operations,
            &mut diagnostics,
        )?;
        validate_scheduler_function_references(
            graph,
            modules,
            &reachable,
            &static_function_references,
            &mut diagnostics,
        )?;
        let callable_effect_plans = build_callable_effect_plan_index(
            modules,
            &reachable,
            &static_calls,
            graph.effect_execution_mode,
        )?;
        let authorized_query_values = authorize_query_value_plans(
            modules,
            &capability_flow_proof,
            &reachable,
            &callable_effect_plans,
        )?;
        let authorized_query_value_identities = authorized_query_values.construction_identities();
        let authorized_query_result_identities =
            authorized_query_values.result_consumer_identities();
        let represented_query_constructions = authorized_query_values.represented_constructions();
        let capability_analysis = analyze_owned_capabilities(
            graph,
            modules,
            &reachable,
            &static_calls,
            &capability_flow_proof,
            &callable_effect_plans,
            callable_effect_plans.effect_value_graph(),
            &authorized_query_value_identities,
            &represented_query_constructions,
            &dependency_adapter_call_index,
            &mut diagnostics,
        )?;
        let admitted_operation_identities = capability_analysis.admitted_operations.clone();
        let mut query_owned_effect_identities = authorized_query_result_identities.clone();
        query_owned_effect_identities.extend(authorized_query_value_identities.iter().cloned());
        let authorized_callable_effect_targets =
            capability_analysis.authorized_callable_effects.clone();
        let authorized_effect_sites = AuthorizedEffectSiteIndex::new(
            callable_effect_plans.effect_value_graph(),
            callable_effect_plans.plans(),
            &authorized_callable_effect_targets,
        )?;
        let authorized_batch_effect_sites = AuthorizedEffectSiteIndex::with_current_batch_leaves(
            callable_effect_plans.effect_value_graph(),
            callable_effect_plans
                .control_plans()
                .filter_map(|plan| plan.current_batch_leaf()),
            callable_effect_plans.plans(),
            &authorized_callable_effect_targets,
        )?;
        // A graph-represented effect must not fall back to legacy raw authority merely because its
        // exact value/control route cannot yet materialize a consumer plan.
        let mut semantic_plan_targets = callable_effect_plans
            .effect_value_graph()
            .represented_effect_targets();
        semantic_plan_targets.extend(authorized_effect_sites.materialized_target_identities());
        semantic_plan_targets.extend(authorized_query_result_identities);
        semantic_plan_targets.extend(capability_analysis.authorized_query_values.iter().cloned());
        let raw_admitted_operation_identities = admitted_operation_identities
            .difference(&semantic_plan_targets)
            .cloned()
            .collect();
        admit_raw_context_reuse_facts(modules, &reachable, &mut diagnostics)?;
        admit_reachable(
            graph,
            modules,
            &reachable,
            &registration.kind,
            &admitted_operation_identities,
            &dependency_adapter_call_index,
            graph.effect_execution_mode,
            value_mode,
            &mut diagnostics,
        )?;
        if diagnostics.is_empty() {
            diagnose_flattened_runtime_global_collisions(
                graph,
                modules,
                &reachable,
                &imported_binding_aliases,
                &applied_dependency_calls,
                &applied_source_operations,
                applied_registration_adapter.as_ref(),
                &mut diagnostics,
            )?;
        }
        let (mut operations, intrinsics) = admitted_operations(
            modules,
            &reachable,
            &applied_dependency_calls,
            &raw_admitted_operation_identities,
        )?;
        append_legacy_interprocedural_effect_operations(
            modules,
            &capability_analysis.legacy_interprocedural_effects,
            &semantic_plan_targets,
            &mut operations,
        )?;
        let direct_effect_sites = materialize_authorized_effect_targets(
            modules,
            &authorized_effect_sites,
            &query_owned_effect_identities,
            &mut operations,
        )?;
        materialize_authorized_query_values(
            modules,
            &authorized_query_values,
            &capability_analysis.authorized_query_values,
            &mut operations,
        )?;
        append_source_operations(modules, &mut applied_source_operations, &mut operations)?;
        let mut direct_async_batches =
            if graph.effect_execution_mode == EffectExecutionMode::BlockingFiber {
                authorize_direct_async_batches(
                    graph,
                    modules,
                    &reachable,
                    &registration,
                    &dependency_adapter_call_index,
                    &admitted_operation_identities,
                    &callable_effect_plans,
                    &authorized_batch_effect_sites,
                    &mut operations,
                    value_mode,
                    &mut diagnostics,
                )?
            } else {
                Vec::new()
            };
        ensure!(
            operations.len() <= u16::MAX as usize,
            "opaque ABI operation count exceeds {} after direct batch helper aliases",
            u16::MAX
        );
        let proved_direct_async_batches = direct_async_batches
            .iter()
            .map(proved_direct_async_batch)
            .collect();
        let batch_effect_value_closures =
            authenticated_batch_effect_value_closures(&direct_async_batches);
        diagnose_dependency_adapter_effect_value_flow(
            graph,
            modules,
            &applied_dependency_calls,
            callable_effect_plans.effect_value_graph(),
            &batch_effect_value_closures,
            &mut diagnostics,
        )?;
        if !diagnostics.is_empty() {
            direct_async_batches.clear();
        }
        // The guest-Promise application unit owns guest-native values without an opaque document
        // ABI. Document-property admission and query-result proofs belong to the typed blocking
        // boundary and must not authorize rewrites in this untyped unit.
        let untyped_guest_native_application = graph.effect_execution_mode
            == EffectExecutionMode::GuestPromiseEventLoop
            && value_mode == ValueMode::GuestNativeJson;
        let mut document_properties = if untyped_guest_native_application {
            Vec::new()
        } else {
            admitted_document_properties(
                graph,
                modules,
                &reachable,
                &operations,
                &capability_analysis.legacy_interprocedural_effects,
                &callable_effect_plans,
                &dependency_adapter_call_index,
            )?
        };
        phases.admission_us = elapsed_us(admission_started);

        let source_graph_fingerprint = source_graph_fingerprint(
            graph,
            modules,
            &reachable,
            &resolved_imports,
            &generated_api_materials,
            &applied_dependency_calls,
            applied_registration_adapter.as_ref(),
            &applied_source_operations,
            value_mode,
            graph.effect_execution_mode,
        );
        let fingerprint = source_fingerprint(
            graph,
            &reachable,
            &resolved_imports,
            &generated_api_materials,
            &applied_dependency_calls,
            applied_registration_adapter.as_ref(),
            &applied_source_operations,
            value_mode,
            graph.effect_execution_mode,
        );
        let mut proved_local_filters = Vec::new();
        for unit in reachable.values() {
            let module = modules
                .get(&unit.module)
                .context("reachable proved-filter module disappeared")?;
            let generated_unit_binding = if unit.kind == "handler" {
                "__convexWasmHandler"
            } else {
                unit.name.as_str()
            };
            for filter in module
                .summary
                .proved_local_filters
                .iter()
                .filter(|filtered| {
                    filtered.initializer_start >= unit.start && filtered.initializer_end <= unit.end
                })
            {
                proved_local_filters.push(ProvedGeneratedFilter {
                    filter: filter.clone(),
                    generated_unit_binding: generated_unit_binding.to_string(),
                    file: unit.module.clone(),
                    dependency_chain: unit.dependency_chain.clone(),
                });
            }
        }
        let lowering_started = Instant::now();
        let mut runtime_inputs = Vec::new();
        let generated_javascript_artifact = if diagnostics.is_empty() {
            let generated_direct_effect_sites =
                if graph.effect_execution_mode == EffectExecutionMode::GuestPromiseEventLoop {
                    direct_effect_sites.as_slice()
                } else {
                    &[]
                };
            let generated_javascript = generate_javascript(
                &reachable,
                &registration.handler_source,
                &graph.entry_path,
                &imported_binding_aliases,
                &static_function_references,
                &applied_dependency_calls,
                &applied_source_operations,
                applied_registration_adapter.as_ref(),
                generated_direct_effect_sites,
            )?;
            let generated_source = generated_javascript.source;
            // Guest-native values execute in the untyped application unit, so their ordinary
            // object and array behavior must not depend on opaque-result projection proofs.
            let proved_query_result_flow = if untyped_guest_native_application {
                ProvedQueryResultFlow::default()
            } else {
                let query_result_seeds =
                    authenticated_query_result_seeds(&authorized_query_values, &reachable)?;
                match prove_generated_query_result_flow(&generated_source, &query_result_seeds)? {
                    QueryResultFlowOutcome::Proved(proof) => proof,
                    QueryResultFlowOutcome::Rejected(rejection) => {
                        let unit = reachable
                            .values()
                            .find(|unit| {
                                unit.module == rejection.consumer.module
                                    && rejection.consumer.start >= unit.start
                                    && rejection.consumer.end <= unit.end
                            })
                            .context("rejected query-result consumer owner disappeared")?;
                        diagnostics.push(diagnostic_at(
                            graph,
                            modules,
                            "unsupported-query-result-flow",
                            rejection.reason,
                            &rejection.consumer.module,
                            rejection.consumer.start,
                            Some("query result".to_string()),
                            unit.dependency_chain.clone(),
                        )?);
                        direct_async_batches.clear();
                        ProvedQueryResultFlow::default()
                    }
                }
            };
            for property in proved_query_result_flow.document_properties() {
                if !document_properties.iter().any(|existing| {
                    existing.table == property.table && existing.property == property.property
                }) {
                    document_properties.push(DocumentProperty {
                        table: property.table.clone(),
                        property: property.property.clone(),
                        value_type: "opaque".to_string(),
                        reason: "opaque-property-read".to_string(),
                    });
                }
            }
            document_properties.sort();
            let filter_bindings = if value_mode == ValueMode::GuestNativeJson {
                GeneratedFilterBindings::Authorized(BTreeMap::new())
            } else {
                bind_generated_filters(&generated_source, &proved_local_filters)?
            };
            match filter_bindings {
                GeneratedFilterBindings::Rejected(index) => {
                    let rejected = &proved_local_filters[index];
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-array-filter-lowering",
                        "proved array filter did not bind to one exact generated top-level unit"
                            .to_string(),
                        &rejected.file,
                        rejected.filter.initializer_start,
                        Some("filter".to_string()),
                        rejected.dependency_chain.clone(),
                    )?);
                    direct_async_batches.clear();
                    None
                }
                GeneratedFilterBindings::Authorized(authorized_filters) => {
                    if graph.effect_execution_mode == EffectExecutionMode::BlockingFiber {
                        bind_generated_direct_async_batches(
                            &generated_source,
                            &operations,
                            &mut direct_async_batches,
                            value_mode,
                        )?;
                    }
                    let mut array_producing_functions = applied_dependency_calls
                        .iter()
                        .filter(|call| {
                            matches!(
                                call.descriptor.semantic.kind.as_str(),
                                "databaseIndexCollect"
                                    | "databaseGetBatch"
                                    | "databaseGetBatchOrThrow"
                            )
                        })
                        .map(|call| call.generated_function_name.clone())
                        .collect::<BTreeSet<_>>();
                    array_producing_functions.extend(array_producing_direct_effect_site_helpers(
                        generated_direct_effect_sites,
                    )?);
                    let array_argument_authorization = registration
                        .argument_parameter
                        .as_ref()
                        .filter(|_| !registration.array_argument_fields.is_empty())
                        .map(|parameter_name| GeneratedArrayArgumentAuthorization {
                            parameter_name: parameter_name.clone(),
                            fields: registration.array_argument_fields.iter().cloned().collect(),
                        });
                    match lower_generated_javascript_for_effect_execution_mode(
                        &generated_source,
                        &intrinsics,
                        &direct_async_batches,
                        &authorized_filters,
                        &array_producing_functions,
                        array_argument_authorization.as_ref(),
                        proved_query_result_flow.array_expressions(),
                        proved_query_result_flow.host_array_expressions(),
                        graph.effect_execution_mode,
                        value_mode,
                        true,
                        Some(&generated_javascript.authority),
                    ) {
                        Ok(lowered)
                            if matches!(generated_source_mode, GeneratedSourceMode::None) =>
                        {
                            runtime_inputs = lowered.runtime_inputs;
                            None
                        }
                        Ok(lowered) => {
                            runtime_inputs = lowered.runtime_inputs;
                            let source = lowered.source;
                            let sha256 = hash_bytes(source.as_bytes());
                            let bytes = source.len();
                            let (source, cache_path) = match generated_source_mode {
                                GeneratedSourceMode::Inline => (Some(source), None),
                                GeneratedSourceMode::Cache => (
                                    None,
                                    Some(publish_generated_source(
                                        cache_dir,
                                        &sha256,
                                        source.as_bytes(),
                                    )?),
                                ),
                                GeneratedSourceMode::None => unreachable!(),
                            };
                            Some(GeneratedJavaScriptArtifact {
                                suggested_path: format!("generated/{fingerprint}.js"),
                                bytes,
                                sha256,
                                source,
                                cache_path,
                            })
                        }
                        Err(error) => {
                            if let Some(rejection) =
                                error.downcast_ref::<GeneratedArrayFilterIneligibility>()
                            {
                                diagnostics.push(generated_array_filter_ineligibility_diagnostic(
                                    graph,
                                    modules,
                                    &reachable,
                                    &generated_source,
                                    rejection,
                                )?);
                            } else if let Some(rejection) =
                                error.downcast_ref::<GeneratedForOfIneligibility>()
                            {
                                diagnostics.push(generated_for_of_ineligibility_diagnostic(
                                    graph,
                                    modules,
                                    &reachable,
                                    &generated_source,
                                    rejection,
                                )?);
                            } else if let Some(rejection) =
                                error.downcast_ref::<GeneratedSourceBindingCollision>()
                            {
                                diagnostics.extend(generated_source_binding_collision_diagnostics(
                                    graph,
                                    modules,
                                    &reachable,
                                    &imported_binding_aliases,
                                    rejection,
                                )?);
                            } else {
                                return Err(error);
                            }
                            direct_async_batches.clear();
                            None
                        }
                    }
                }
            }
        } else {
            None
        };
        phases.lowering_us = elapsed_us(lowering_started);

        let mut module_keys = reachable
            .values()
            .map(|unit| unit.module.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        module_keys.sort();
        let public_units = if matches!(generated_source_mode, GeneratedSourceMode::None) {
            Vec::new()
        } else {
            reachable
                .values()
                .map(|unit| {
                    let source = module_source(modules, &unit.module)?;
                    let (line, column) = line_column(&source, unit.start);
                    Ok(PublicReachableUnit {
                        id: unit.id.clone(),
                        module: unit.module.clone(),
                        name: unit.name.clone(),
                        kind: unit.kind.clone(),
                        start: unit.start,
                        end: unit.end,
                        line,
                        column,
                        source_hash: hash_bytes(unit.source.as_bytes()),
                        dependency_chain: if matches!(
                            generated_source_mode,
                            GeneratedSourceMode::Inline
                        ) {
                            unit.dependency_chain.clone()
                        } else {
                            Vec::new()
                        },
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };
        diagnostics.sort_by(|left, right| {
            (
                &left.file,
                left.line,
                left.column,
                &left.code,
                &left.message,
                &left.construct,
                &left.source,
                &left.dependency_chain,
            )
                .cmp(&(
                    &right.file,
                    right.line,
                    right.column,
                    &right.code,
                    &right.message,
                    &right.construct,
                    &right.source,
                    &right.dependency_chain,
                ))
        });
        if !matches!(generated_source_mode, GeneratedSourceMode::None) {
            resolved_imports.sort_by(|left, right| {
                (&left.importer, &left.specifier, &left.imported_name).cmp(&(
                    &right.importer,
                    &right.specifier,
                    &right.imported_name,
                ))
            });
        }
        let eligible = diagnostics.is_empty();
        let (diagnostics, diagnostic_census, diagnostic_census_ids) =
            if matches!(generated_source_mode, GeneratedSourceMode::Inline) {
                (diagnostics, Vec::new(), Vec::new())
            } else {
                let diagnostic_census = diagnostics
                    .iter()
                    .map(DiagnosticCensusKey::from)
                    .collect::<Vec<_>>();
                let mut seen_ids = BTreeSet::new();
                let mut diagnostic_census_ids = Vec::new();
                for diagnostic in &diagnostic_census {
                    let id = diagnostic_census_id(diagnostic)?;
                    if seen_ids.insert(id.clone()) {
                        diagnostic_census_ids.push(id);
                        if diagnostic_census_ids.len() == MAX_BATCH_DIAGNOSTIC_CENSUS_IDS_PER_EXPORT
                        {
                            break;
                        }
                    }
                }
                (
                    diagnostics.into_iter().take(1).collect(),
                    diagnostic_census,
                    diagnostic_census_ids,
                )
            };
        let udf_kind = match registration.kind.as_str() {
            "internalQuery" | "query" => "query",
            "internalMutation" | "mutation" => "mutation",
            other => bail!(
                "registration builder {} has unsupported kind {other} after binding authentication",
                registration.builder_local
            ),
        };
        let applied_registration_adapter = applied_registration_adapter
            .as_ref()
            .map(registration_adapter_provenance);
        let applied_dependency_adapters = dependency_adapter_provenance(&applied_dependency_calls)?;
        let pipeline_sha256 = compiler_pipeline_sha256().to_string();
        let mode_output = if matches!(generated_source_mode, GeneratedSourceMode::None)
            || (!eligible && matches!(generated_source_mode, GeneratedSourceMode::Cache))
        {
            let mut operations_by_kind = BTreeMap::new();
            for operation in &operations {
                *operations_by_kind
                    .entry(operation.kind.clone())
                    .or_insert(0) += 1;
            }
            CompilerModeOutput::Analysis(AnalysisOutput {
                analysis_summary: AnalysisSummary {
                    argument_field_count: registration.argument_fields.len(),
                    document_property_count: document_properties.len(),
                    intrinsic_count: intrinsics.len(),
                    operation_count: operations.len(),
                    operations_by_kind,
                    reachable_module_count: module_keys.len(),
                    reachable_unit_count: reachable.len(),
                    resolved_import_count: resolved_imports.len(),
                },
            })
        } else {
            let operations_sha256 = hash_bytes(&canonical_compiler_json_bytes(
                &serde_json::to_value(&operations)?,
            )?);
            CompilerModeOutput::Compile(CompileOutput {
                target: TargetOutput {
                    entry: graph.entry_path.clone(),
                    export: graph.export_name.clone(),
                    registration_kind: registration.kind,
                    handler_source: if matches!(generated_source_mode, GeneratedSourceMode::Inline)
                    {
                        registration.handler_source
                    } else {
                        String::new()
                    },
                },
                toolchain: OutputToolchain {
                    convex: graph.toolchain.convex.clone(),
                    esbuild: graph.toolchain.esbuild.clone(),
                    oxc: OXC_VERSION.to_string(),
                    compiler: COMPILER_SCHEMA.to_string(),
                    abi: ABI_VERSION.to_string(),
                },
                abi_version: ABI_VERSION.to_string(),
                opaque_value_abi_version: 3,
                runtime_inputs,
                value_mode,
                effect_execution_mode: graph.effect_execution_mode,
                limits: ExecutionLimits {
                    execution_time_ms: 1_000,
                    argument_bytes: 1 << 24,
                    result_bytes: 1 << 24,
                    documents_read: 32_000,
                    read_bytes: 1 << 24,
                    documents_written: 16_000,
                    write_bytes: 1 << 24,
                    scheduled_functions: 1_000,
                    scheduled_argument_bytes: 1 << 24,
                },
                argument_fields: registration.argument_fields,
                array_argument_fields: registration.array_argument_fields,
                reachable_modules: module_keys,
                reachable_units: public_units,
                resolved_imports,
                operations_sha256,
                operations,
                intrinsics,
                direct_async_batches,
                document_properties,
                generated_javascript_artifact,
            })
        };
        break Ok(CompiledExport {
            output: CompilerOutput {
                kind: COMPILER_SCHEMA.to_string(),
                source: SourceIdentity {
                    module_path: graph.entry_path.clone(),
                    export_name: graph.export_name.clone(),
                    udf_kind: udf_kind.to_string(),
                    resolved_graph_sha256: source_graph_fingerprint.clone(),
                    export_sha256: fingerprint.clone(),
                },
                compiler: CompilerMetadata {
                    pipeline_sha256,
                    compiler_revision: COMPILER_REVISION.to_string(),
                    admitted_language_version: ADMITTED_LANGUAGE_VERSION,
                    static_hermes_global_policy: admission::static_hermes_global_policy_identity()
                        .clone(),
                },
                source_graph_fingerprint,
                export_fingerprint: fingerprint.clone(),
                routing: RoutingDecision {
                    decision: if eligible { "wasm" } else { "v8Fallback" }.to_string(),
                },
                eligible,
                applied_dependency_adapters,
                applied_registration_adapter,
                diagnostics,
                proved_direct_async_batches,
                #[cfg(test)]
                callable_effect_plans: callable_effect_plans.plans().cloned().collect(),
                #[cfg(test)]
                callable_control_plans: callable_effect_plans.control_plans().cloned().collect(),
                diagnostic_census_ids,
                mode_output,
                phase_timings_us: PhaseTimings {
                    esbuild_graph: graph
                        .phase_timings_us
                        .get("esbuildGraph")
                        .copied()
                        .unwrap_or(0),
                    graph_read: phases.graph_read_us,
                    source_read: phases.source_read_us,
                    cache_lookup: phases.cache_lookup_us,
                    parse: phases.parse_us,
                    semantic: phases.semantic_us,
                    reachability: phases.reachability_us,
                    admission: phases.admission_us,
                    lowering: phases.lowering_us,
                    total_rust: elapsed_us(total_started),
                },
                module_cache: ModuleCacheOutput {
                    hits: phases.module_cache_hits,
                    misses: phases.module_cache_misses,
                    summary_schema: MODULE_SUMMARY_SCHEMA.to_string(),
                },
            },
            diagnostic_census,
        });
    }
}

pub(crate) fn load_module(
    repo_root: &Path,
    cache_dir: &Path,
    module_key: &str,
    modules: &mut BTreeMap<String, LoadedModule>,
    phases: &mut PhaseMeasurements,
) -> Result<()> {
    if modules.contains_key(module_key) {
        return Ok(());
    }
    let (module, module_phases) = load_compiler_module(repo_root, cache_dir, module_key, None)?;
    phases.add(module_phases)?;
    modules.insert(module_key.to_string(), module);
    Ok(())
}

fn load_compiler_module(
    repo_root: &Path,
    cache_dir: &Path,
    module_key: &str,
    captured_source: Option<&str>,
) -> Result<(LoadedModule, PhaseMeasurements)> {
    let mut phases = PhaseMeasurements::default();
    let source_started = Instant::now();
    // Captured graph inputs already own their source text; do not reopen a worktree file
    // that may now contain a different revision. Standalone compilation still reads disk.
    let (path, source) = match captured_source {
        Some(source) => (repo_root.join(module_key), source.to_string()),
        None => {
            let (path, source_bytes) = read_checked_module(repo_root, module_key)?;
            let source = String::from_utf8(source_bytes)
                .with_context(|| format!("failed to decode {} as UTF-8", path.display()))?;
            (path, source)
        }
    };
    phases.source_read_us += elapsed_us(source_started);
    let source_hash = hash_bytes(source.as_bytes());
    let pipeline_sha256 = compiler_pipeline_sha256();
    let policy_fingerprint = context_reuse::context_policy_fingerprint();
    let cache_key = module_summary_cache_key(
        module_key,
        &source_hash,
        pipeline_sha256,
        policy_fingerprint,
    );
    let cache_path = cache_dir
        .join("module-summaries")
        .join(&cache_key[..2])
        .join(format!("{cache_key}.json"));
    let cache_started = Instant::now();
    let cached = match read_module_summary_cache(&cache_path)? {
        Some(bytes) => {
            let summary: ModuleSummary = serde_json::from_slice(&bytes)
                .with_context(|| format!("corrupt module cache {}", cache_path.display()))?;
            ensure!(
                summary.kind == MODULE_SUMMARY_SCHEMA
                    && summary.cache_key == cache_key
                    && summary.compiler_pipeline_sha256 == pipeline_sha256
                    && summary.context_policy_fingerprint == policy_fingerprint
                    && summary.source_hash == source_hash,
                "corrupt module cache identity {}",
                cache_path.display()
            );
            touch_module_summary_cache_entry(&cache_path)?;
            Some(summary)
        }
        None => None,
    };
    phases.cache_lookup_us += elapsed_us(cache_started);
    let summary = if let Some(summary) = cached {
        phases.module_cache_hits += 1;
        summary
    } else {
        phases.module_cache_misses += 1;
        let summary = summarize_module(
            module_key,
            &path,
            &source,
            &source_hash,
            &cache_key,
            pipeline_sha256,
            policy_fingerprint,
            &mut phases,
        )?;
        let encoded = serde_json::to_vec(&summary)?;
        let parent = prepare_module_summary_cache_parent(cache_dir, &cache_key)?;
        let temporary = parent.join(format!(".{cache_key}.{}.tmp", std::process::id()));
        let mut temporary_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        temporary_file.write_all(&encoded)?;
        // Module summaries are reconstructible cache data, not publication-critical output.
        // Atomic rename hides partial writes; cache admission detects damaged data after a crash.
        drop(temporary_file);
        match fs::rename(&temporary, &cache_path) {
            Ok(()) => {}
            Err(error) if cache_path.exists() => {
                fs::remove_file(&temporary)?;
                let _ = error;
            }
            Err(error) => return Err(error).with_context(|| cache_path.display().to_string()),
        }
        summary
    };
    Ok((LoadedModule::new(summary, source), phases))
}

fn module_preload_worker_limit() -> Result<usize> {
    thread::available_parallelism()
        .context("failed to determine compiler preload parallelism")
        .map(|available| DEFAULT_MODULE_PRELOAD_WORKERS.min(available.get()))
}

fn preload_compiler_modules<'a>(
    graph: &GraphInput,
    roots: impl Iterator<Item = &'a str>,
    cache_dir: &Path,
    modules: &mut BTreeMap<String, LoadedModule>,
    phases: &mut PhaseMeasurements,
    workers: usize,
) -> Result<()> {
    ensure!(
        workers > 0,
        "compiler preload worker limit must be positive"
    );
    let mut pending = roots.map(str::to_string).collect::<BTreeSet<_>>();
    let mut traversed = BTreeSet::new();
    while let Some(module_key) = pending.pop_first() {
        if !traversed.insert(module_key.clone()) {
            continue;
        }
        let input = graph
            .metafile
            .inputs
            .get(&module_key)
            .with_context(|| format!("esbuild metafile has no preload input {module_key}"))?;
        for resolved in input.imports.iter().filter(|resolved| !resolved.external) {
            // Export reachability can consult only emitted graph edges. Following the
            // same admitted module paths here makes the complete mutable load/cache
            // phase precede immutable parallel export analysis without reintroducing
            // source imports that esbuild removed.
            if is_admitted_module_path(&resolved.path)
                || is_dependency_adapter_module_path(graph, &resolved.path)
            {
                pending.insert(resolved.path.clone());
            }
        }
    }

    let missing = traversed
        .into_iter()
        .filter(|module_key| !modules.contains_key(module_key))
        .collect::<Vec<_>>();
    preload_modules(missing, modules, phases, workers, |module_key| {
        load_compiler_module(&graph.repo_root, cache_dir, module_key, None)
            .with_context(|| format!("failed to preload compiler module {module_key}"))
    })
}

fn preload_modules(
    missing: Vec<String>,
    modules: &mut BTreeMap<String, LoadedModule>,
    phases: &mut PhaseMeasurements,
    workers: usize,
    load: impl Fn(&str) -> Result<(LoadedModule, PhaseMeasurements)> + Sync,
) -> Result<()> {
    ensure!(
        workers > 0,
        "compiler preload worker limit must be positive"
    );
    if missing.len() <= 1 {
        for module_key in missing {
            let (module, module_phases) = load(&module_key)?;
            phases.add(module_phases)?;
            ensure!(
                modules.insert(module_key, module).is_none(),
                "compiler preload attempted to replace an existing module"
            );
        }
        return Ok(());
    }

    let worker_count = missing.len().min(workers);
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| -> Result<()> {
        let mut worker_handles = Vec::with_capacity(worker_count);
        for worker_index in 0..worker_count {
            let sender = sender.clone();
            let load = &load;
            let assigned = missing
                .iter()
                .skip(worker_index)
                .step_by(worker_count)
                .cloned()
                .collect::<Vec<_>>();
            worker_handles.push(scope.spawn(move || {
                for module_key in assigned {
                    let loaded = load(&module_key);
                    if sender.send((module_key, loaded)).is_err() {
                        return;
                    }
                }
            }));
        }
        drop(sender);
        // Drain every worker before returning an error or exposing modules to analysis.
        let mut worker_panicked = false;
        for worker in worker_handles {
            worker_panicked |= worker.join().is_err();
        }
        ensure!(!worker_panicked, "compiler preload worker panicked");
        let mut loaded = BTreeMap::new();
        for _ in 0..missing.len() {
            let (module_key, module) = receiver
                .recv()
                .context("compiler preload workers stopped before loading every module")?;
            ensure!(
                loaded.insert(module_key, module).is_none(),
                "compiler preload worker returned a duplicate module"
            );
        }
        for module_key in missing {
            let (module, module_phases) = loaded
                .remove(&module_key)
                .context("compiler preload worker omitted a module")??;
            phases.add(module_phases)?;
            ensure!(
                modules.insert(module_key, module).is_none(),
                "compiler preload attempted to replace an existing module"
            );
        }
        Ok(())
    })
}

fn summarize_module(
    module_key: &str,
    path: &Path,
    source: &str,
    source_hash: &str,
    cache_key: &str,
    compiler_pipeline_sha256: &str,
    context_policy_fingerprint: &str,
    phases: &mut PhaseMeasurements,
) -> Result<ModuleSummary> {
    let source_type = SourceType::from_path(path)
        .with_context(|| format!("unsupported source type {}", path.display()))?;
    let allocator = Allocator::default();
    let parse_started = Instant::now();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    phases.parse_us += elapsed_us(parse_started);
    if !parsed.diagnostics.is_empty() {
        bail!(
            "Oxc parser rejected {module_key} with {} diagnostics",
            parsed.diagnostics.len()
        );
    }
    let semantic_started = Instant::now();
    let semantic = SemanticBuilder::new_compiler()
        .with_build_nodes(true)
        .with_cfg(true)
        .build(&parsed.program);
    phases.semantic_us += elapsed_us(semantic_started);
    if !semantic.diagnostics.is_empty() {
        bail!(
            "Oxc semantic analysis rejected {module_key} with {} diagnostics",
            semantic.diagnostics.len()
        );
    }
    let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false))
        .with_context(|| format!("Oxc emitted invalid ESTree JSON for {module_key}"))?;
    let mut binding_initializer_facts = BTreeMap::new();
    collect_binding_initializer_facts(&ast, &mut binding_initializer_facts)?;
    let mut promise_all_alias_handoffs = Vec::new();
    collect_promise_all_alias_handoffs(&ast, &mut promise_all_alias_handoffs)?;
    promise_all_alias_handoffs.sort_by_key(|handoff| {
        (
            handoff.binding_start,
            handoff.binding_end,
            handoff.promise_all_start,
            handoff.promise_all_end,
        )
    });
    promise_all_alias_handoffs.dedup_by(|left, right| {
        left.binding_start == right.binding_start
            && left.binding_end == right.binding_end
            && left.promise_all_start == right.promise_all_start
            && left.promise_all_end == right.promise_all_end
            && left.argument_start == right.argument_start
            && left.argument_end == right.argument_end
            && left.await_start == right.await_start
            && left.await_end == right.await_end
    });
    let mut conditional_expression_facts = Vec::new();
    collect_conditional_expression_facts(&ast, &mut conditional_expression_facts)?;
    conditional_expression_facts.sort_by_key(|fact| (fact.start, fact.end));
    let mut callable_parameter_facts = Vec::new();
    collect_callable_parameter_facts(&ast, &mut callable_parameter_facts)?;
    callable_parameter_facts.sort_by_key(|fact| (fact.callable_start, fact.callable_end));
    let (imports, exports, mut units) =
        index_module(source, &ast).with_context(|| format!("failed to index {module_key}"))?;
    for unit in units.values().filter(|unit| unit.callable_range.is_some()) {
        let callable = unit
            .callable_range
            .as_ref()
            .expect("filtered callable unit lost its range");
        let matching = callable_parameter_facts
            .iter()
            .filter(|fact| {
                fact.callable_start == callable.start && fact.callable_end == callable.end
            })
            .collect::<Vec<_>>();
        let [fact] = matching.as_slice() else {
            bail!("indexed callable unit has no unique independent parameter fact");
        };
        ensure!(
            unit.parameters.len() == fact.parameters.len()
                && unit
                    .parameters
                    .iter()
                    .zip(&fact.parameters)
                    .all(|(parameter, fact)| {
                        parameter.index == fact.index
                            && parameter.name == fact.name
                            && parameter.start == fact.start
                            && parameter.end == fact.end
                    }),
            "indexed callable parameters conflict with independent callable parameter facts"
        );
    }
    let mut capability_branches = capability_branches(&ast);
    let scoping = semantic.semantic.scoping();
    let nodes = semantic.semantic.nodes();
    let callable_control_skeletons =
        collect_callable_control_skeletons(nodes, require_cfg(semantic.semantic.cfg())?)?;
    let mut resolved_bindings = ResolvedBindingIndex::new();
    let mut resolved_binding_facts = BTreeMap::new();
    for symbol_id in scoping.symbol_ids() {
        let declaration = scoping.symbol_span(symbol_id);
        let binding = ResolvedBinding {
            name: scoping.symbol_name(symbol_id).to_string(),
            declaration_start: declaration.start,
            declaration_end: declaration.end,
        };
        let mut binding_references = Vec::new();
        for reference in scoping.get_resolved_references(symbol_id) {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            binding_references.push(ReferenceOccurrence {
                name: binding.name.clone(),
                start: reference_span.start,
                end: reference_span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            });
            ensure!(
                resolved_bindings
                    .insert((reference_span.start, reference_span.end), binding.clone(),)
                    .is_none(),
                "Oxc value reference span resolves to more than one binding"
            );
        }
        binding_references
            .sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
        let initializer = binding_initializer_facts.get(&(declaration.start, declaration.end));
        ensure!(
            resolved_binding_facts
                .insert(
                    (declaration.start, declaration.end),
                    ResolvedBindingFact {
                        name: binding.name.clone(),
                        start: declaration.start,
                        end: declaration.end,
                        references: binding_references,
                        initializer_start: initializer.map(|initializer| initializer.start),
                        initializer_end: initializer.map(|initializer| initializer.end),
                        constant: initializer.is_some_and(|initializer| initializer.constant),
                        array_elements: initializer
                            .and_then(|initializer| initializer.array_elements.clone()),
                    },
                )
                .is_none(),
            "Oxc binding declaration span resolves to more than one symbol"
        );
    }
    let mut callable_leaf_plans = Vec::new();
    let binding_reference_index = resolved_binding_facts
        .iter()
        .map(|(&(start, end), binding)| ((start, end), binding.references.clone()))
        .collect();
    collect_callable_leaf_plans(
        &ast,
        &resolved_bindings,
        &binding_reference_index,
        &mut callable_leaf_plans,
    )?;
    bind_callable_control_blocks(&callable_control_skeletons, &mut callable_leaf_plans)?;
    callable_leaf_plans.sort_by_key(|plan| (plan.callable_start, plan.callable_end));
    prove_branch_erasability(&mut capability_branches, scoping, nodes);
    let mut references = Vec::new();
    for (name, symbol_id) in scoping.get_bindings(scoping.root_scope_id()) {
        for reference in scoping.get_resolved_references(*symbol_id) {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let span = nodes.get_node(reference.node_id()).kind().span();
            references.push(ReferenceOccurrence {
                name: name.to_string(),
                start: span.start,
                end: span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            });
        }
    }
    let mut globals = Vec::new();
    for (name, reference_ids) in scoping.root_unresolved_references() {
        for reference_id in reference_ids {
            let reference = scoping.get_reference(*reference_id);
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let span = nodes.get_node(reference.node_id()).kind().span();
            globals.push(ReferenceOccurrence {
                name: name.to_string(),
                start: span.start,
                end: span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            });
        }
    }
    references.sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
    globals.sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
    for unit in units.values_mut() {
        for parameter in &mut unit.parameters {
            let matching_symbols = scoping
                .symbol_ids()
                .filter(|symbol_id| {
                    let symbol_span = scoping.symbol_span(*symbol_id);
                    symbol_span.start == parameter.start
                        && scoping.symbol_name(*symbol_id) == parameter.name
                })
                .collect::<Vec<_>>();
            ensure!(
                matching_symbols.len() == 1,
                "parameter {} at {}..{} resolved to {} symbols",
                parameter.name,
                parameter.start,
                parameter.end,
                matching_symbols.len()
            );
            for reference in scoping.get_resolved_references(matching_symbols[0]) {
                let flags = reference.flags();
                if !flags.is_value() || flags.is_value_as_type() {
                    continue;
                }
                let reference_span = nodes.get_node(reference.node_id()).kind().span();
                ensure!(
                    reference_span.start >= unit.start && reference_span.end <= unit.end,
                    "parameter reference escaped its source unit"
                );
                parameter.references.push(ReferenceOccurrence {
                    name: parameter.name.clone(),
                    start: reference_span.start,
                    end: reference_span.end,
                    read: flags.is_read(),
                    write: flags.is_write(),
                });
            }
            parameter
                .references
                .sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
        }
        let Some(registration) = &mut unit.registration else {
            continue;
        };
        if let (Some(argument_name), Some(argument_start)) = (
            &registration.argument_parameter,
            registration.argument_parameter_start,
        ) {
            let matching_symbols = scoping
                .symbol_ids()
                .filter(|symbol_id| {
                    let symbol_span = scoping.symbol_span(*symbol_id);
                    symbol_span.start == argument_start
                        && scoping.symbol_name(*symbol_id) == argument_name
                })
                .collect::<Vec<_>>();
            ensure!(
                matching_symbols.len() == 1,
                "registration argument parameter {} at {} resolved to {} symbols",
                argument_name,
                argument_start,
                matching_symbols.len()
            );
            for reference in scoping.get_resolved_references(matching_symbols[0]) {
                let flags = reference.flags();
                if !flags.is_value() || flags.is_value_as_type() {
                    continue;
                }
                let reference_span = nodes.get_node(reference.node_id()).kind().span();
                ensure!(
                    reference_span.start >= registration.handler_start
                        && reference_span.end <= registration.handler_end,
                    "registration argument reference escaped its handler span"
                );
                registration.argument_references.push(ReferenceOccurrence {
                    name: argument_name.clone(),
                    start: reference_span.start,
                    end: reference_span.end,
                    read: flags.is_read(),
                    write: flags.is_write(),
                });
            }
            registration
                .argument_references
                .sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
        }
        let (Some(context_name), Some(context_start)) = (
            &registration.context_parameter,
            registration.context_parameter_start,
        ) else {
            continue;
        };
        let matching_symbols = scoping
            .symbol_ids()
            .filter(|symbol_id| {
                let symbol_span = scoping.symbol_span(*symbol_id);
                symbol_span.start == context_start
                    && scoping.symbol_name(*symbol_id) == context_name
            })
            .collect::<Vec<_>>();
        ensure!(
            matching_symbols.len() == 1,
            "registration context parameter {} at {} resolved to {} symbols",
            context_name,
            context_start,
            matching_symbols.len()
        );
        for reference in scoping.get_resolved_references(matching_symbols[0]) {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            ensure!(
                reference_span.start >= registration.handler_start
                    && reference_span.end <= registration.handler_end,
                "registration context reference escaped its handler span"
            );
            registration.context_references.push(ReferenceOccurrence {
                name: context_name.clone(),
                start: reference_span.start,
                end: reference_span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            });
        }
        registration
            .context_references
            .sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
    }
    let mut constructs = Vec::new();
    collect_constructs(&ast, false, &mut constructs);
    constructs.sort_by_key(|construct| (construct.start, construct.end, construct.kind.clone()));
    let mut try_statements = Vec::new();
    collect_try_statements(&ast, &mut try_statements);
    try_statements.sort_by_key(|statement| (statement.start, statement.end));
    let mut operations = Vec::new();
    collect_operations(&ast, source, &mut operations);
    operations.sort_by_key(|operation| (operation.start, operation.end, operation.kind.clone()));
    let mut calls = Vec::new();
    collect_calls(&ast, &references, None, &mut calls);
    calls.sort_by_key(|call| (call.start, call.end, call.callee.clone()));
    let context_parameters = units
        .values()
        .filter_map(|unit| {
            let registration = unit.registration.as_ref()?;
            registration.context_parameter.clone()
        })
        .collect::<BTreeSet<_>>();
    let mut effects = Vec::new();
    for unit in units.values() {
        if let Some(registration) = &unit.registration {
            for reference in &registration.context_references {
                effects.push(EffectCandidate {
                    path: reference.name.clone(),
                    start: reference.start,
                    end: reference.end,
                });
            }
        }
    }
    collect_effects(&ast, &context_parameters, &mut effects);
    effects.sort_by_key(|effect| (effect.start, effect.end, effect.path.clone()));
    effects.dedup_by(|left, right| {
        left.start == right.start && left.end == right.end && left.path == right.path
    });
    let mut maximal_effects = Vec::<EffectCandidate>::new();
    for effect in effects {
        if let Some(previous) = maximal_effects.last()
            && previous.start == effect.start
        {
            if previous.end >= effect.end {
                continue;
            }
            maximal_effects.pop();
        }
        maximal_effects.push(effect);
    }
    let mut direct_async_batches = Vec::new();
    collect_direct_async_batches(
        &ast,
        None,
        None,
        DatabaseOperationSource::Raw,
        &mut direct_async_batches,
    );
    direct_async_batches.sort_by_key(|batch| (batch.start, batch.end));
    let mut promise_all_sites = Vec::new();
    collect_promise_all_sites(&ast, None, &mut promise_all_sites);
    promise_all_sites.sort_by_key(|site| (site.start, site.end));
    let mut constant_array_bindings = Vec::new();
    collect_constant_array_bindings(&ast, None, &mut constant_array_bindings);
    for binding in &mut constant_array_bindings {
        let matching_symbols = scoping
            .symbol_ids()
            .filter(|symbol_id| {
                let symbol_span = scoping.symbol_span(*symbol_id);
                symbol_span.start == binding.binding_start
                    && scoping.symbol_name(*symbol_id) == binding.name
            })
            .collect::<Vec<_>>();
        ensure!(
            matching_symbols.len() == 1,
            "constant array binding {} at {} resolved to {} symbols",
            binding.name,
            binding.binding_start,
            matching_symbols.len()
        );
        for reference in scoping.get_resolved_references(matching_symbols[0]) {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            binding.references.push(ReferenceOccurrence {
                name: binding.name.clone(),
                start: reference_span.start,
                end: reference_span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            });
        }
        binding
            .references
            .sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
    }
    constant_array_bindings.sort_by_key(|binding| {
        (
            binding.binding_start,
            binding.binding_end,
            binding.name.clone(),
        )
    });
    let mut local_array_bindings = Vec::new();
    collect_local_array_bindings(&ast, source, None, &mut local_array_bindings);
    let mut static_member_accesses = Vec::new();
    collect_static_member_accesses(&ast, false, &mut static_member_accesses);
    static_member_accesses.sort_by_key(|access| {
        (
            access.start,
            access.end,
            access.root.clone(),
            access.first_field.clone(),
        )
    });
    populate_capability_projections(
        &ast,
        &mut units,
        &resolved_bindings,
        &resolved_binding_facts,
        &static_member_accesses,
    );
    let mut static_member_calls = Vec::new();
    collect_static_member_calls(&ast, &mut static_member_calls);
    static_member_calls.sort_by_key(|call| {
        (
            call.start,
            call.end,
            call.root.clone(),
            call.first_field.clone(),
        )
    });
    let mut direct_identifier_invocations = Vec::new();
    collect_direct_identifier_invocations(&ast, &mut direct_identifier_invocations);
    direct_identifier_invocations
        .sort_by_key(|invocation| (invocation.start, invocation.end, invocation.callee.clone()));
    let mut direct_identifier_operands = Vec::new();
    collect_direct_identifier_operands(&ast, &mut direct_identifier_operands);
    direct_identifier_operands
        .sort_by_key(|operand| (operand.start, operand.end, operand.identifier.clone()));
    let mut static_member_chains = Vec::new();
    collect_static_member_chains(&ast, &mut static_member_chains);
    static_member_chains
        .sort_by_key(|chain| (chain.start, chain.end, chain.root_start, chain.root_end));
    let mut static_function_reference_consumers = Vec::new();
    collect_static_function_reference_consumers(&ast, &mut static_function_reference_consumers);
    static_function_reference_consumers.sort_by_key(|consumer| {
        (
            consumer.reference_start,
            consumer.reference_end,
            consumer.path.clone(),
            consumer.argument_index,
        )
    });
    for binding in &mut local_array_bindings {
        let matching_symbols = scoping
            .symbol_ids()
            .filter(|symbol_id| {
                let symbol_span = scoping.symbol_span(*symbol_id);
                symbol_span.start == binding.binding_start
                    && scoping.symbol_name(*symbol_id) == binding.name
            })
            .collect::<Vec<_>>();
        ensure!(
            matching_symbols.len() == 1,
            "local array binding {} at {} resolved to {} symbols",
            binding.name,
            binding.binding_start,
            matching_symbols.len()
        );
        for reference in scoping.get_resolved_references(matching_symbols[0]) {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            binding.references.push(ReferenceOccurrence {
                name: binding.name.clone(),
                start: reference_span.start,
                end: reference_span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            });
        }
        binding
            .references
            .sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
    }
    let mut local_filtered_arrays = Vec::new();
    collect_local_filtered_array_candidates(&ast, None, &mut local_filtered_arrays);
    local_filtered_arrays.sort_by_key(|binding| {
        (
            binding.binding_start,
            binding.binding_end,
            binding.name.clone(),
        )
    });
    let mut derived_array_binding_starts = BTreeSet::new();
    for filtered in &local_filtered_arrays {
        let matching_sources = local_array_bindings
            .iter()
            .filter(|binding| {
                binding.name == filtered.source_binding
                    && binding.enclosing_function_start == filtered.enclosing_function_start
                    && binding.enclosing_function_end == filtered.enclosing_function_end
            })
            .collect::<Vec<_>>();
        if matching_sources.len() != 1 {
            continue;
        }
        let source_binding = matching_sources[0];
        let source_references_are_owned = source_binding.references.iter().all(|reference| {
            reference.read
                && !reference.write
                && ((reference.start == filtered.source_reference_start
                    && reference.end == filtered.source_reference_end)
                    || static_member_accesses.iter().any(|access| {
                        access.root == source_binding.name
                            && access.first_field == "length"
                            && access.root_start == reference.start
                            && access.root_end == reference.end
                    }))
        }) && source_binding.references.iter().any(|reference| {
            reference.start == filtered.source_reference_start
                && reference.end == filtered.source_reference_end
        }) && static_member_calls.iter().any(|call| {
            call.root == source_binding.name
                && call.first_field == "filter"
                && call.root_start == filtered.source_reference_start
                && call.root_end == filtered.source_reference_end
        });
        let registration_owns_argument = units
            .values()
            .filter_map(|unit| unit.registration.as_ref())
            .find(|registration| {
                Some(registration.handler_start) == filtered.enclosing_function_start
                    && Some(registration.handler_end) == filtered.enclosing_function_end
            })
            .is_some_and(|registration| {
                registration.argument_parameter.as_ref() == Some(&filtered.argument_root)
                    && registration
                        .argument_fields
                        .contains(&filtered.argument_field)
                    && registration.argument_references.iter().any(|reference| {
                        reference.read
                            && !reference.write
                            && reference.start == filtered.argument_root_start
                            && reference.end == filtered.argument_root_end
                    })
            });
        if !source_references_are_owned || !registration_owns_argument {
            continue;
        }
        let source_operation_start = source_binding.operation_start;
        let source_operation_end = source_binding.operation_end;
        drop(matching_sources);
        ensure!(
            derived_array_binding_starts.insert(filtered.binding_start),
            "filtered local array binding {} at {} is duplicated",
            filtered.name,
            filtered.binding_start
        );
        local_array_bindings.push(LocalArrayBindingCandidate {
            name: filtered.name.clone(),
            binding_start: filtered.binding_start,
            binding_end: filtered.binding_end,
            initializer_start: filtered.initializer_start,
            initializer_end: filtered.initializer_end,
            operation_start: source_operation_start,
            operation_end: source_operation_end,
            enclosing_function_start: filtered.enclosing_function_start,
            enclosing_function_end: filtered.enclosing_function_end,
            references: Vec::new(),
        });
    }
    let proved_local_filters = local_filtered_arrays
        .into_iter()
        .filter(|filtered| derived_array_binding_starts.contains(&filtered.binding_start))
        .collect::<Vec<_>>();
    for binding in local_array_bindings
        .iter_mut()
        .filter(|binding| derived_array_binding_starts.contains(&binding.binding_start))
    {
        let matching_symbols = scoping
            .symbol_ids()
            .filter(|symbol_id| {
                let symbol_span = scoping.symbol_span(*symbol_id);
                symbol_span.start == binding.binding_start
                    && scoping.symbol_name(*symbol_id) == binding.name
            })
            .collect::<Vec<_>>();
        ensure!(
            matching_symbols.len() == 1,
            "filtered local array binding {} at {} resolved to {} symbols",
            binding.name,
            binding.binding_start,
            matching_symbols.len()
        );
        for reference in scoping.get_resolved_references(matching_symbols[0]) {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            binding.references.push(ReferenceOccurrence {
                name: binding.name.clone(),
                start: reference_span.start,
                end: reference_span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            });
        }
        binding
            .references
            .sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
    }
    local_array_bindings.sort_by_key(|binding| {
        (
            binding.binding_start,
            binding.binding_end,
            binding.name.clone(),
        )
    });
    let mut local_set_bindings = Vec::new();
    collect_local_set_bindings(&ast, None, &mut local_set_bindings);
    for binding in &mut local_set_bindings {
        let matching_symbols = scoping
            .symbol_ids()
            .filter(|symbol_id| {
                let symbol_span = scoping.symbol_span(*symbol_id);
                symbol_span.start == binding.binding_start
                    && scoping.symbol_name(*symbol_id) == binding.name
            })
            .collect::<Vec<_>>();
        ensure!(
            matching_symbols.len() == 1,
            "local set binding {} at {} resolved to {} symbols",
            binding.name,
            binding.binding_start,
            matching_symbols.len()
        );
        for reference in scoping.get_resolved_references(matching_symbols[0]) {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            binding.references.push(ReferenceOccurrence {
                name: binding.name.clone(),
                start: reference_span.start,
                end: reference_span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            });
        }
        binding
            .references
            .sort_by_key(|reference| (reference.start, reference.end, reference.name.clone()));
    }
    local_set_bindings.sort_by_key(|binding| {
        (
            binding.binding_start,
            binding.binding_end,
            binding.name.clone(),
        )
    });
    let mut static_iterables = Vec::new();
    collect_static_iterables(&ast, &mut static_iterables);
    static_iterables.sort_by_key(|iterable| (iterable.start, iterable.end, iterable.kind.clone()));
    let document_properties = collect_document_properties(
        &ast,
        source,
        scoping,
        nodes,
        &proved_local_filters,
        &direct_async_batches,
    )?;
    let mut opaque_bindings = Vec::new();
    collect_opaque_binding_candidates(&ast, source, &mut opaque_bindings);
    for binding in &mut opaque_bindings {
        binding.references =
            resolved_binding_references(scoping, nodes, &binding.name, binding.binding_start)?
                .into_iter()
                .map(|(start, end)| ReferenceOccurrence {
                    name: binding.name.clone(),
                    start,
                    end,
                    read: true,
                    write: false,
                })
                .collect();
        binding
            .references
            .sort_by_key(|reference| (reference.start, reference.end));
    }
    opaque_bindings.sort_by_key(|binding| (binding.binding_start, binding.name.clone()));
    let mut opaque_return_references = Vec::new();
    collect_opaque_return_references(&ast, &mut opaque_return_references);
    opaque_return_references.sort_by_key(|reference| (reference.start, reference.end));
    let context_reuse = context_reuse::summarize_context_module(
        source,
        &ast,
        &imports,
        &units,
        &resolved_binding_facts,
        &exports,
        source_type.is_commonjs(),
    )
    .with_context(|| format!("failed to summarize context-reuse facts for {module_key}"))?;
    let generated_api_convention =
        summarize_generated_api_convention(module_key, &ast, &imports, &exports);
    Ok(ModuleSummary {
        kind: MODULE_SUMMARY_SCHEMA.to_string(),
        cache_key: cache_key.to_string(),
        compiler_pipeline_sha256: compiler_pipeline_sha256.to_string(),
        context_policy_fingerprint: context_policy_fingerprint.to_string(),
        source_hash: source_hash.to_string(),
        source_bytes: source.len(),
        imports,
        exports,
        units,
        capability_branches,
        references,
        globals,
        constructs,
        try_statements,
        operations,
        calls,
        effects: maximal_effects,
        callable_control_skeletons,
        callable_leaf_plans,
        resolved_binding_facts: resolved_binding_facts.into_values().collect(),
        conditional_expression_facts,
        callable_parameter_facts,
        promise_all_sites,
        promise_all_alias_handoffs,
        direct_async_batches,
        constant_array_bindings,
        local_array_bindings,
        proved_local_filters,
        local_set_bindings,
        static_iterables,
        static_member_accesses,
        static_member_calls,
        direct_identifier_invocations,
        direct_identifier_operands,
        static_member_chains,
        static_function_reference_consumers,
        generated_api_convention,
        document_properties,
        opaque_bindings,
        opaque_return_references,
        context_reuse,
    })
}

type ModuleIndex = (
    BTreeMap<String, ImportBinding>,
    BTreeMap<String, String>,
    BTreeMap<String, UnitSummary>,
);

fn index_module(source: &str, ast: &Value) -> Result<ModuleIndex> {
    let body = ast
        .get("body")
        .and_then(Value::as_array)
        .context("Oxc ESTree program has no body")?;
    let mut imports = BTreeMap::new();
    let mut exports = BTreeMap::new();
    let mut units = BTreeMap::new();
    for statement in body {
        let statement_type = node_type(statement)?;
        if statement_type == "ImportDeclaration" {
            index_import(statement, &mut imports)?;
            continue;
        }
        if statement_type == "ExportNamedDeclaration" {
            if let Some(declaration) = statement
                .get("declaration")
                .filter(|value| !value.is_null())
            {
                index_declaration(source, declaration, true, &mut exports, &mut units)?;
            }
            if let Some(specifiers) = statement.get("specifiers").and_then(Value::as_array) {
                for specifier in specifiers {
                    let local = static_name(
                        specifier
                            .get("local")
                            .context("export specifier has no local")?,
                    )?;
                    let exported = static_name(
                        specifier
                            .get("exported")
                            .context("export specifier has no exported")?,
                    )?;
                    if statement
                        .get("source")
                        .is_some_and(|value| !value.is_null())
                    {
                        // Re-exports outside the selected symbol closure do not affect this
                        // module summary. A selected re-export fails later as a missing runtime
                        // declaration instead of forcing a scan of its dependency.
                        continue;
                    }
                    exports.insert(exported, local);
                }
            }
            continue;
        }
        if statement_type == "ExportDefaultDeclaration" {
            if let Some(declaration) = statement
                .get("declaration")
                .filter(|declaration| !declaration.is_null())
            {
                index_declaration(source, declaration, false, &mut exports, &mut units)?;
            }
            continue;
        }
        index_declaration(source, statement, false, &mut exports, &mut units)?;
    }
    Ok((imports, exports, units))
}

fn index_import(statement: &Value, imports: &mut BTreeMap<String, ImportBinding>) -> Result<()> {
    let specifier = literal_string(
        statement
            .get("source")
            .context("import declaration has no source")?,
    )?;
    let declaration_type_only = statement.get("importKind").and_then(Value::as_str) == Some("type");
    for item in statement
        .get("specifiers")
        .and_then(Value::as_array)
        .context("import declaration has no specifiers")?
    {
        let local = identifier_name(item.get("local").context("import specifier has no local")?)?;
        let imported = match node_type(item)? {
            "ImportSpecifier" => static_name(
                item.get("imported")
                    .context("import has no imported name")?,
            )?,
            "ImportDefaultSpecifier" => "default".to_string(),
            "ImportNamespaceSpecifier" => "*".to_string(),
            other => bail!("unsupported import specifier {other}"),
        };
        let (start, end) = span(statement)?;
        let binding = ImportBinding {
            local: local.clone(),
            imported,
            specifier: specifier.clone(),
            type_only: declaration_type_only
                || item.get("importKind").and_then(Value::as_str) == Some("type"),
            start,
            end,
        };
        ensure!(
            imports.insert(local.clone(), binding).is_none(),
            "duplicate import binding {local}"
        );
    }
    Ok(())
}

fn index_declaration(
    source: &str,
    declaration: &Value,
    exported: bool,
    exports: &mut BTreeMap<String, String>,
    units: &mut BTreeMap<String, UnitSummary>,
) -> Result<()> {
    match node_type(declaration)? {
        "FunctionDeclaration" => {
            let Some(name) = declaration
                .get("id")
                .filter(|identifier| !identifier.is_null())
                .and_then(|identifier| identifier_name(identifier).ok())
            else {
                return Ok(());
            };
            let (start, end) = span(declaration)?;
            let parameters = parameter_summaries(declaration)?;
            let capability_predicate = predicate_template(declaration, &parameters);
            let effect_sites = callable_effect_sites(declaration, &parameters);
            let direct_batch_helper = Some(parse_direct_batch_helper(
                declaration,
                DatabaseOperationSource::Raw,
            ));
            add_unit(
                source,
                name,
                "function",
                start,
                end,
                Some(SourceRange { start, end }),
                exported,
                parameters,
                capability_predicate,
                None,
                effect_sites,
                direct_batch_helper,
                None,
                exports,
                units,
            )?;
        }
        "ClassDeclaration" => {
            let Some(name) = declaration
                .get("id")
                .filter(|identifier| !identifier.is_null())
                .and_then(|identifier| identifier_name(identifier).ok())
            else {
                return Ok(());
            };
            let (start, end) = span(declaration)?;
            add_unit(
                source,
                name,
                "class",
                start,
                end,
                None,
                exported,
                Vec::new(),
                None,
                None,
                Vec::new(),
                None,
                None,
                exports,
                units,
            )?;
        }
        "VariableDeclaration" => {
            let declarations = declaration
                .get("declarations")
                .and_then(Value::as_array)
                .context("variable declaration has no declarators")?;
            let (start, end) = span(declaration)?;
            for declarator in declarations {
                let Some(name) = declarator.get("id").and_then(|id| identifier_name(id).ok())
                else {
                    continue;
                };
                let registration = registration_summary(source, declarator)?;
                let function = declarator
                    .get("init")
                    .map(unwrap_runtime_expression)
                    .filter(|initializer| {
                        node_type(initializer).is_ok_and(|kind| {
                            matches!(kind, "ArrowFunctionExpression" | "FunctionExpression")
                        })
                    });
                let parameters = function
                    .map(parameter_summaries)
                    .transpose()?
                    .unwrap_or_default();
                let callable_range = function
                    .map(span)
                    .transpose()?
                    .map(|(start, end)| SourceRange { start, end });
                let capability_predicate =
                    function.and_then(|function| predicate_template(function, &parameters));
                let static_callable_alias = (declaration.get("kind").and_then(Value::as_str)
                    == Some("const"))
                .then(|| {
                    let target = declarator.get("init").map(unwrap_runtime_expression)?;
                    let name = identifier_name(target).ok()?;
                    let (start, end) = span(target).ok()?;
                    Some(StaticCallableAliasCandidate {
                        target: name,
                        reference: SourceRange { start, end },
                    })
                })
                .flatten();
                let effect_sites = function
                    .map(|function| callable_effect_sites(function, &parameters))
                    .unwrap_or_default();
                let direct_batch_helper = function.map(|function| {
                    parse_direct_batch_helper(function, DatabaseOperationSource::Raw)
                });
                add_unit(
                    source,
                    name,
                    "variable",
                    start,
                    end,
                    callable_range,
                    exported,
                    parameters,
                    capability_predicate,
                    static_callable_alias,
                    effect_sites,
                    direct_batch_helper,
                    registration,
                    exports,
                    units,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn add_unit(
    source: &str,
    name: String,
    kind: &str,
    start: u32,
    end: u32,
    callable_range: Option<SourceRange>,
    exported: bool,
    parameters: Vec<ParameterSummary>,
    capability_predicate: Option<CapabilityPredicateTemplateCandidate>,
    static_callable_alias: Option<StaticCallableAliasCandidate>,
    effect_sites: Vec<CallableEffectSiteCandidate>,
    direct_batch_helper: Option<DirectBatchHelperCandidate>,
    registration: Option<RegistrationSummary>,
    exports: &mut BTreeMap<String, String>,
    units: &mut BTreeMap<String, UnitSummary>,
) -> Result<()> {
    let exported_as = if exported {
        vec![name.clone()]
    } else {
        Vec::new()
    };
    if exported {
        exports.insert(name.clone(), name.clone());
    }
    let unit = UnitSummary {
        name: name.clone(),
        kind: kind.to_string(),
        start,
        end,
        source: source_slice(source, start, end)?.to_string(),
        callable_range,
        exported_as,
        parameters,
        capability_predicate,
        static_callable_alias,
        effect_sites,
        direct_batch_helper,
        registration,
    };
    ensure!(
        units.insert(name.clone(), unit).is_none(),
        "duplicate declaration {name}"
    );
    Ok(())
}

fn parameter_summaries(function: &Value) -> Result<Vec<ParameterSummary>> {
    function
        .get("params")
        .and_then(Value::as_array)
        .context("function has no parameters")?
        .iter()
        .enumerate()
        .filter_map(|(index, parameter)| {
            let name = identifier_name(parameter).ok()?;
            Some(span(parameter).map(|(start, end)| ParameterSummary {
                index,
                name,
                start,
                end,
                references: Vec::new(),
                capability_projections: Vec::new(),
            }))
        })
        .collect()
}

fn registration_summary(source: &str, declarator: &Value) -> Result<Option<RegistrationSummary>> {
    let Some(initializer) = declarator
        .get("init")
        .filter(|value| !value.is_null())
        .map(unwrap_runtime_expression)
    else {
        return Ok(None);
    };
    if node_type(initializer)? != "CallExpression" {
        return Ok(None);
    }
    let (call_start, call_end) = span(initializer)?;
    let Some(callee) = initializer.get("callee").map(unwrap_runtime_expression) else {
        return Ok(None);
    };
    if node_type(callee)? != "Identifier" {
        return Ok(None);
    }
    let kind = identifier_name(callee)?;
    let (builder_start, builder_end) = span(callee)?;
    let Some(arguments) = initializer.get("arguments").and_then(Value::as_array) else {
        return Ok(None);
    };
    if arguments.len() != 1 {
        return Ok(None);
    }
    let registration = unwrap_runtime_expression(&arguments[0]);
    if node_type(registration)? != "ObjectExpression" {
        return Ok(None);
    }
    let Some(properties) = registration.get("properties").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut argument_fields = Vec::new();
    let mut array_argument_fields = Vec::new();
    let mut diagnostics = Vec::new();
    if let Some(args_value) = object_property(properties, "args").map(unwrap_runtime_expression) {
        let args_type = node_type(args_value)?;
        if args_type == "ObjectExpression" {
            let argument_properties = args_value
                .get("properties")
                .and_then(Value::as_array)
                .context("argument validator object has no properties")?;
            for property in argument_properties {
                match property_name(property) {
                    Ok(name) => {
                        argument_fields.push(name.clone());
                        if property.get("value").is_some_and(is_direct_array_validator) {
                            array_argument_fields.push(name);
                        }
                    }
                    Err(error) => {
                        let (start, _) = span(property)?;
                        let construct = node_type(property)?.to_string();
                        diagnostics.push(RegistrationDiagnosticSummary {
                            code: "unsupported-argument-validator-shape".to_string(),
                            message: format!(
                                "Convex argument validator uses unsupported {construct}: {error}"
                            ),
                            start,
                            construct,
                        });
                    }
                }
            }
        } else {
            let (start, _) = span(args_value)?;
            diagnostics.push(RegistrationDiagnosticSummary {
                code: "unsupported-argument-validator-shape".to_string(),
                message: format!(
                    "Convex argument validator must be an inline object, found {args_type}"
                ),
                start,
                construct: args_type.to_string(),
            });
        }
    } else {
        let (start, _) = span(registration)?;
        diagnostics.push(RegistrationDiagnosticSummary {
            code: "unsupported-argument-validator-shape".to_string(),
            message: "Convex registration has no args validator".to_string(),
            start,
            construct: "ObjectExpression".to_string(),
        });
    }
    let handler = object_property(properties, "handler")
        .map(unwrap_runtime_expression)
        .unwrap_or(registration);
    let handler_type = node_type(handler)?;
    let (handler_start, handler_end) = span(handler)?;
    let context_parameter_node = handler
        .get("params")
        .and_then(Value::as_array)
        .and_then(|parameters| parameters.first());
    let context_parameter =
        context_parameter_node.and_then(|parameter| identifier_name(parameter).ok());
    let context_parameter_span = context_parameter_node.and_then(|parameter| span(parameter).ok());
    let argument_parameter_node = handler
        .get("params")
        .and_then(Value::as_array)
        .and_then(|parameters| parameters.get(1));
    let argument_parameter =
        argument_parameter_node.and_then(|parameter| identifier_name(parameter).ok());
    let argument_parameter_span =
        argument_parameter_node.and_then(|parameter| span(parameter).ok());
    if !matches!(
        handler_type,
        "ArrowFunctionExpression" | "FunctionExpression"
    ) {
        diagnostics.push(RegistrationDiagnosticSummary {
            code: "unsupported-construct".to_string(),
            message: if object_property(properties, "handler").is_some() {
                format!(
                    "Convex registration handler must be an inline function, found {handler_type}"
                )
            } else {
                "Convex registration has no handler".to_string()
            },
            start: handler_start,
            construct: handler_type.to_string(),
        });
    }
    Ok(Some(RegistrationSummary {
        call_start,
        call_end,
        builder_local: kind.clone(),
        builder_start,
        builder_end,
        kind,
        handler_start,
        handler_end,
        handler_source: source_slice(source, handler_start, handler_end)?.to_string(),
        handler_type: handler_type.to_string(),
        context_parameter,
        context_parameter_start: context_parameter_span.map(|(start, _)| start),
        context_parameter_end: context_parameter_span.map(|(_, end)| end),
        context_references: Vec::new(),
        argument_fields,
        array_argument_fields,
        argument_parameter,
        argument_parameter_start: argument_parameter_span.map(|(start, _)| start),
        argument_parameter_end: argument_parameter_span.map(|(_, end)| end),
        argument_references: Vec::new(),
        diagnostics,
    }))
}

fn is_direct_array_validator(value: &Value) -> bool {
    let value = unwrap_runtime_expression(value);
    node_type(value).ok() == Some("CallExpression")
        && !call_has_optional_callee(value)
        && value.get("callee").and_then(member_path).as_deref() == Some("v.array")
        && value
            .get("arguments")
            .and_then(Value::as_array)
            .is_some_and(|arguments| arguments.len() == 1)
}

fn object_property<'a>(properties: &'a [Value], name: &str) -> Option<&'a Value> {
    properties.iter().find_map(|property| {
        if property_name(property).ok().as_deref() == Some(name) {
            property.get("value")
        } else {
            None
        }
    })
}

fn property_name(property: &Value) -> Result<String> {
    let key = property.get("key").context("property has no key")?;
    match node_type(key)? {
        "Identifier" => identifier_name(key),
        "Literal" => literal_string(key),
        other => bail!("computed or unsupported property name {other}"),
    }
}

fn collect_constructs(value: &Value, inside_type: bool, output: &mut Vec<ConstructOccurrence>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_constructs(value, inside_type, output);
            }
        }
        Value::Object(object) => {
            let kind = object.get("type").and_then(Value::as_str);
            let runtime_kind = if kind == Some("ForOfStatement")
                && object.get("await").and_then(Value::as_bool) == Some(true)
            {
                Some("ForAwaitOfStatement")
            } else {
                kind
            };
            let is_type = kind.is_some_and(|kind| kind.starts_with("TS"));
            let transparent_type_wrapper = matches!(
                kind,
                Some(
                    "TSAsExpression"
                        | "TSSatisfiesExpression"
                        | "TSNonNullExpression"
                        | "TSTypeAssertion"
                        | "TSInstantiationExpression"
                )
            );
            let next_inside_type = inside_type || (is_type && !transparent_type_wrapper);
            if !next_inside_type
                && !transparent_type_wrapper
                && let (Some(kind), Some(start), Some(end)) = (
                    runtime_kind,
                    object.get("start").and_then(Value::as_u64),
                    object.get("end").and_then(Value::as_u64),
                )
                && !matches!(
                    kind,
                    "Program"
                        | "ImportDeclaration"
                        | "ImportSpecifier"
                        | "ImportDefaultSpecifier"
                        | "ImportNamespaceSpecifier"
                        | "ExportNamedDeclaration"
                        | "ExportSpecifier"
                )
            {
                output.push(ConstructOccurrence {
                    kind: kind.to_string(),
                    start: start as u32,
                    end: end as u32,
                });
            }
            for (key, child) in object {
                if key != "type" && key != "start" && key != "end" {
                    collect_constructs(child, next_inside_type, output);
                }
            }
        }
        _ => {}
    }
}

fn collect_try_statements(value: &Value, output: &mut Vec<TryStatementCandidate>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("TryStatement")
                && let (Some(block), Some(start), Some(end)) = (
                    object.get("block"),
                    object.get("start").and_then(Value::as_u64),
                    object.get("end").and_then(Value::as_u64),
                )
                && let Ok((protected_start, protected_end)) = span(block)
            {
                output.push(TryStatementCandidate {
                    start: start as u32,
                    end: end as u32,
                    protected_start,
                    protected_end,
                    catch_start: object
                        .get("handler")
                        .filter(|handler| !handler.is_null())
                        .and_then(|handler| span(handler).ok())
                        .map(|(catch_start, _)| catch_start),
                });
            }
            for child in object.values() {
                collect_try_statements(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_try_statements(child, output);
            }
        }
        _ => {}
    }
}

fn collect_operations(value: &Value, source: &str, output: &mut Vec<OperationCandidate>) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("CallExpression") {
            if let Some(operation) = parse_context_capability_operation(value) {
                output.push(operation);
            }
            if let Some(operation) = parse_db_operation(value, source) {
                output.push(operation);
            }
            if let Some(operation) = parse_scheduler_operation(value) {
                output.push(operation);
            }
            if let Some(operation) = parse_sha_operation(value) {
                output.push(operation);
            }
        }
        for child in object.values() {
            collect_operations(child, source, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_operations(child, source, output);
        }
    }
}

fn ordinary_constant_value(value: &Value) -> Option<Value> {
    let value = unwrap_runtime_expression(value);
    match node_type(value).ok()? {
        "Literal" => {
            let object = value.as_object()?;
            if object.contains_key("bigint") || object.contains_key("regex") {
                return None;
            }
            let literal = object.get("value")?;
            matches!(
                literal,
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
            )
            .then(|| literal.clone())
        }
        "ArrayExpression" => {
            let elements = value.get("elements")?.as_array()?;
            let mut constants = Vec::with_capacity(elements.len());
            for element in elements {
                if element.is_null() || node_type(element).ok() == Some("SpreadElement") {
                    return None;
                }
                constants.push(ordinary_constant_value(element)?);
            }
            Some(Value::Array(constants))
        }
        _ => None,
    }
}

fn collect_constant_array_bindings(
    value: &Value,
    enclosing_function: Option<(u32, u32)>,
    output: &mut Vec<ConstantArrayBindingCandidate>,
) {
    if let Value::Object(object) = value {
        let current_function = if matches!(
            object.get("type").and_then(Value::as_str),
            Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
        ) {
            span(value).ok().or(enclosing_function)
        } else {
            enclosing_function
        };
        if object.get("type").and_then(Value::as_str) == Some("VariableDeclaration")
            && object.get("kind").and_then(Value::as_str) == Some("const")
            && let Some(declarations) = object.get("declarations").and_then(Value::as_array)
        {
            for declaration in declarations {
                let (Some(identifier), Some(initializer)) =
                    (declaration.get("id"), declaration.get("init"))
                else {
                    continue;
                };
                let initializer_expression = unwrap_runtime_expression(initializer);
                if node_type(initializer_expression).ok() != Some("ArrayExpression") {
                    continue;
                }
                let Some(elements) = initializer_expression
                    .get("elements")
                    .and_then(Value::as_array)
                else {
                    continue;
                };
                let Some(values) = elements
                    .iter()
                    .map(|element| {
                        (!element.is_null() && node_type(element).ok() != Some("SpreadElement"))
                            .then(|| ordinary_constant_value(element))
                            .flatten()
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    continue;
                };
                let (
                    Ok(name),
                    Ok((binding_start, binding_end)),
                    Ok((initializer_start, initializer_end)),
                ) = (
                    identifier_name(identifier),
                    span(identifier),
                    span(initializer),
                )
                else {
                    continue;
                };
                output.push(ConstantArrayBindingCandidate {
                    name,
                    binding_start,
                    binding_end,
                    initializer_start,
                    initializer_end,
                    values,
                    enclosing_function_start: current_function.map(|(start, _)| start),
                    enclosing_function_end: current_function.map(|(_, end)| end),
                    references: Vec::new(),
                });
            }
        }
        for child in object.values() {
            collect_constant_array_bindings(child, current_function, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_constant_array_bindings(child, enclosing_function, output);
        }
    }
}

fn collect_local_array_bindings(
    value: &Value,
    source: &str,
    enclosing_function: Option<(u32, u32)>,
    output: &mut Vec<LocalArrayBindingCandidate>,
) {
    if let Value::Object(object) = value {
        let current_function = if matches!(
            object.get("type").and_then(Value::as_str),
            Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
        ) {
            span(value).ok().or(enclosing_function)
        } else {
            enclosing_function
        };
        if object.get("type").and_then(Value::as_str) == Some("VariableDeclaration")
            && object.get("kind").and_then(Value::as_str) == Some("const")
            && let Some(declarations) = object.get("declarations").and_then(Value::as_array)
        {
            for declaration in declarations {
                let (Some(identifier), Some(initializer)) =
                    (declaration.get("id"), declaration.get("init"))
                else {
                    continue;
                };
                let Ok(name) = identifier_name(identifier) else {
                    continue;
                };
                let operation_expression = unwrap_transparent_expression(initializer);
                let Some(operation) = parse_db_operation(operation_expression, source) else {
                    continue;
                };
                if operation.kind != "db.query" || operation.terminal.as_deref() != Some("collect")
                {
                    continue;
                }
                let Ok((binding_start, binding_end)) = span(identifier) else {
                    continue;
                };
                let Ok((initializer_start, initializer_end)) = span(initializer) else {
                    continue;
                };
                output.push(LocalArrayBindingCandidate {
                    name,
                    binding_start,
                    binding_end,
                    initializer_start,
                    initializer_end,
                    operation_start: operation.start,
                    operation_end: operation.end,
                    enclosing_function_start: current_function.map(|(start, _)| start),
                    enclosing_function_end: current_function.map(|(_, end)| end),
                    references: Vec::new(),
                });
            }
        }
        for child in object.values() {
            collect_local_array_bindings(child, source, current_function, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_local_array_bindings(child, source, enclosing_function, output);
        }
    }
}

fn collect_local_filtered_array_candidates(
    value: &Value,
    enclosing_function: Option<(u32, u32)>,
    output: &mut Vec<LocalFilteredArrayCandidate>,
) {
    if let Value::Object(object) = value {
        let current_function = if matches!(
            object.get("type").and_then(Value::as_str),
            Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
        ) {
            span(value).ok().or(enclosing_function)
        } else {
            enclosing_function
        };
        if object.get("type").and_then(Value::as_str) == Some("VariableDeclaration")
            && object.get("kind").and_then(Value::as_str) == Some("const")
            && let Some(declarations) = object.get("declarations").and_then(Value::as_array)
        {
            for declaration in declarations {
                let (Some(identifier), Some(initializer)) =
                    (declaration.get("id"), declaration.get("init"))
                else {
                    continue;
                };
                let initializer = unwrap_transparent_expression(initializer);
                if node_type(initializer).ok() != Some("CallExpression")
                    || call_method_name(initializer).as_deref() != Some("filter")
                {
                    continue;
                }
                let Some(source_expression) = initializer
                    .get("callee")
                    .and_then(|callee| callee.get("object"))
                    .map(unwrap_runtime_expression)
                else {
                    continue;
                };
                let Ok(source_binding) = identifier_name(source_expression) else {
                    continue;
                };
                let Some(arguments) = initializer.get("arguments").and_then(Value::as_array) else {
                    continue;
                };
                if arguments.len() != 1 {
                    continue;
                }
                let callback = unwrap_transparent_expression(&arguments[0]);
                if node_type(callback).ok() != Some("ArrowFunctionExpression")
                    || callback.get("async").and_then(Value::as_bool) == Some(true)
                {
                    continue;
                }
                let Some(parameters) = callback.get("params").and_then(Value::as_array) else {
                    continue;
                };
                if parameters.len() != 1 {
                    continue;
                }
                let Ok(parameter) = identifier_name(&parameters[0]) else {
                    continue;
                };
                let Some(predicate) = callback.get("body").map(unwrap_transparent_expression)
                else {
                    continue;
                };
                if node_type(predicate).ok() != Some("BinaryExpression")
                    || predicate.get("operator").and_then(Value::as_str) != Some("!==")
                {
                    continue;
                }
                let (Some(left), Some(right)) = (
                    predicate.get("left").map(unwrap_runtime_expression),
                    predicate.get("right").map(unwrap_runtime_expression),
                ) else {
                    continue;
                };
                if node_type(left).ok() != Some("MemberExpression")
                    || left.get("computed").and_then(Value::as_bool) == Some(true)
                    || node_type(right).ok() != Some("MemberExpression")
                    || right.get("computed").and_then(Value::as_bool) == Some(true)
                {
                    continue;
                }
                let (Some(left_segments), Some(right_segments)) =
                    (static_member_segments(left), static_member_segments(right))
                else {
                    continue;
                };
                if left_segments.len() != 2
                    || left_segments[0] != parameter
                    || right_segments.len() != 2
                {
                    continue;
                }
                let Some(argument_root) = static_member_root(right) else {
                    continue;
                };
                let (
                    Ok(name),
                    Ok((binding_start, binding_end)),
                    Ok((initializer_start, initializer_end)),
                    Ok((callback_start, callback_end)),
                    Ok((source_reference_start, source_reference_end)),
                    Ok((argument_root_start, argument_root_end)),
                ) = (
                    identifier_name(identifier),
                    span(identifier),
                    span(initializer),
                    span(callback),
                    span(source_expression),
                    span(argument_root),
                )
                else {
                    continue;
                };
                output.push(LocalFilteredArrayCandidate {
                    name,
                    binding_start,
                    binding_end,
                    initializer_start,
                    initializer_end,
                    callback_start,
                    callback_end,
                    source_binding,
                    source_reference_start,
                    source_reference_end,
                    argument_root: right_segments[0].clone(),
                    argument_root_start,
                    argument_root_end,
                    argument_field: right_segments[1].clone(),
                    predicate_field: left_segments[1].clone(),
                    enclosing_function_start: current_function.map(|(start, _)| start),
                    enclosing_function_end: current_function.map(|(_, end)| end),
                });
            }
        }
        for child in object.values() {
            collect_local_filtered_array_candidates(child, current_function, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_local_filtered_array_candidates(child, enclosing_function, output);
        }
    }
}

fn collect_local_set_bindings(
    value: &Value,
    enclosing_function: Option<(u32, u32)>,
    output: &mut Vec<LocalSetBindingCandidate>,
) {
    if let Value::Object(object) = value {
        let current_function = if matches!(
            object.get("type").and_then(Value::as_str),
            Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
        ) {
            span(value).ok().or(enclosing_function)
        } else {
            enclosing_function
        };
        if object.get("type").and_then(Value::as_str) == Some("VariableDeclaration")
            && object.get("kind").and_then(Value::as_str) == Some("const")
            && let Some(declarations) = object.get("declarations").and_then(Value::as_array)
        {
            for declaration in declarations {
                let (Some(identifier), Some(initializer)) =
                    (declaration.get("id"), declaration.get("init"))
                else {
                    continue;
                };
                let initializer = unwrap_runtime_expression(initializer);
                if node_type(initializer).ok() != Some("NewExpression")
                    || initializer
                        .get("callee")
                        .map(unwrap_runtime_expression)
                        .and_then(|callee| identifier_name(callee).ok())
                        .as_deref()
                        != Some("Set")
                    || !initializer
                        .get("arguments")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                {
                    continue;
                }
                let Ok(name) = identifier_name(identifier) else {
                    continue;
                };
                let Ok((binding_start, binding_end)) = span(identifier) else {
                    continue;
                };
                let Some(set_global) = initializer.get("callee").map(unwrap_runtime_expression)
                else {
                    continue;
                };
                let Ok((set_start, set_end)) = span(set_global) else {
                    continue;
                };
                output.push(LocalSetBindingCandidate {
                    name,
                    binding_start,
                    binding_end,
                    set_global_start: set_start,
                    set_global_end: set_end,
                    enclosing_function_start: current_function.map(|(start, _)| start),
                    enclosing_function_end: current_function.map(|(_, end)| end),
                    references: Vec::new(),
                });
            }
        }
        for child in object.values() {
            collect_local_set_bindings(child, current_function, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_local_set_bindings(child, enclosing_function, output);
        }
    }
}

fn collect_static_iterables(value: &Value, output: &mut Vec<StaticIterableCandidate>) {
    if let Value::Object(object) = value {
        match object.get("type").and_then(Value::as_str) {
            Some("ArrayExpression") => {
                if let Ok((start, end)) = span(value) {
                    output.push(StaticIterableCandidate {
                        kind: "array".to_string(),
                        start,
                        end,
                        global_start: None,
                        global_end: None,
                        source_start: None,
                        source_end: None,
                    });
                }
            }
            Some("NewExpression") => {
                let callee = object.get("callee").map(unwrap_runtime_expression);
                let arguments = object.get("arguments").and_then(Value::as_array);
                if callee
                    .and_then(|callee| identifier_name(callee).ok())
                    .as_deref()
                    == Some("Set")
                    && arguments.is_some_and(|arguments| arguments.len() <= 1)
                    && let (Ok((start, end)), Some(callee), Some(arguments)) =
                        (span(value), callee, arguments)
                    && let Ok((global_start, global_end)) = span(callee)
                {
                    let source = arguments
                        .first()
                        .map(unwrap_transparent_expression)
                        .and_then(|argument| span(argument).ok());
                    output.push(StaticIterableCandidate {
                        kind: "set".to_string(),
                        start,
                        end,
                        global_start: Some(global_start),
                        global_end: Some(global_end),
                        source_start: source.map(|(start, _)| start),
                        source_end: source.map(|(_, end)| end),
                    });
                }
            }
            _ => {}
        }
        for child in object.values() {
            collect_static_iterables(child, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_static_iterables(child, output);
        }
    }
}

fn collect_static_member_accesses(
    value: &Value,
    write: bool,
    output: &mut Vec<StaticMemberAccessCandidate>,
) {
    if let Value::Object(object) = value {
        let node_kind = object.get("type").and_then(Value::as_str);
        if node_kind == Some("MemberExpression")
            && let Some(segments) = static_member_segments(value)
            && segments.len() >= 2
            && let Some(root) = static_member_root(value)
            && let (Ok((root_start, root_end)), Ok((start, end))) = (span(root), span(value))
        {
            output.push(StaticMemberAccessCandidate {
                root: segments[0].clone(),
                first_field: segments[1].clone(),
                member_count: segments.len() - 1,
                write,
                root_start,
                root_end,
                start,
                end,
                argument_count: None,
                has_spread_argument: false,
            });
        }
        for (key, child) in object {
            let child_is_write = match (node_kind, key.as_str()) {
                (Some("AssignmentExpression"), "left")
                | (Some("AssignmentPattern"), "left")
                | (Some("UpdateExpression"), "argument")
                | (Some("ForInStatement" | "ForOfStatement"), "left") => true,
                (Some("UnaryExpression"), "argument")
                    if object.get("operator").and_then(Value::as_str) == Some("delete") =>
                {
                    true
                }
                (Some("MemberExpression"), "object" | "property") if write => true,
                _ => false,
            };
            collect_static_member_accesses(child, child_is_write, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_static_member_accesses(child, write, output);
        }
    }
}

fn collect_direct_parameter_projection_aliases(
    value: &Value,
    resolved_bindings: &ResolvedBindingIndex,
    binding_facts: &BTreeMap<(u32, u32), ResolvedBindingFact>,
    output: &mut Vec<(u32, CapabilityProjectionSummary)>,
) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("VariableDeclaration")
            && object.get("kind").and_then(Value::as_str) == Some("const")
            && let Some(declarations) = object.get("declarations").and_then(Value::as_array)
        {
            for declaration in declarations {
                let Some(initializer) = declaration
                    .get("init")
                    .filter(|initializer| !initializer.is_null())
                    .map(unwrap_runtime_expression)
                else {
                    continue;
                };
                let Ok(initializer_span) = span(initializer) else {
                    continue;
                };
                let Some(source) = resolved_bindings.get(&initializer_span) else {
                    continue;
                };
                let Some(pattern) = declaration.get("id") else {
                    continue;
                };
                if node_type(pattern).ok() != Some("ObjectPattern") {
                    continue;
                }
                let Some(properties) = pattern.get("properties").and_then(Value::as_array) else {
                    continue;
                };
                for property in properties {
                    if node_type(property).ok() != Some("Property")
                        || property.get("computed").and_then(Value::as_bool) == Some(true)
                        || property.get("kind").and_then(Value::as_str) != Some("init")
                    {
                        continue;
                    }
                    let Ok(field) = property_name(property) else {
                        continue;
                    };
                    let Some(binding_pattern) = property.get("value") else {
                        continue;
                    };
                    let binding_pattern = unwrap_runtime_expression(binding_pattern);
                    if node_type(binding_pattern).ok() != Some("Identifier") {
                        continue;
                    }
                    let Ok((binding_start, binding_end)) = span(binding_pattern) else {
                        continue;
                    };
                    let Some(binding) = binding_facts.get(&(binding_start, binding_end)) else {
                        continue;
                    };
                    output.push((
                        source.declaration_start,
                        CapabilityProjectionSummary {
                            path: vec![field],
                            binding_start: binding.start,
                            binding_end: binding.end,
                            name: binding.name.clone(),
                            references: binding.references.clone(),
                        },
                    ));
                }
            }
        }
        for child in object.values() {
            collect_direct_parameter_projection_aliases(
                child,
                resolved_bindings,
                binding_facts,
                output,
            );
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_direct_parameter_projection_aliases(
                child,
                resolved_bindings,
                binding_facts,
                output,
            );
        }
    }
}

fn populate_capability_projections(
    ast: &Value,
    units: &mut BTreeMap<String, UnitSummary>,
    resolved_bindings: &ResolvedBindingIndex,
    binding_facts: &BTreeMap<(u32, u32), ResolvedBindingFact>,
    static_member_accesses: &[StaticMemberAccessCandidate],
) {
    let mut aliases = Vec::new();
    collect_direct_parameter_projection_aliases(
        ast,
        resolved_bindings,
        binding_facts,
        &mut aliases,
    );
    for unit in units.values_mut() {
        for parameter in &mut unit.parameters {
            for access in static_member_accesses.iter().filter(|access| {
                access.member_count == 1
                    && access.start >= unit.start
                    && access.end <= unit.end
                    && resolved_bindings
                        .get(&(access.root_start, access.root_end))
                        .is_some_and(|binding| binding.declaration_start == parameter.start)
            }) {
                let path = vec![access.first_field.clone()];
                let name = format!("{}.{}", access.root, access.first_field);
                let projection = parameter
                    .capability_projections
                    .iter_mut()
                    .find(|projection| {
                        projection.binding_start == parameter.start
                            && projection.path == path
                            && projection.name == name
                    });
                let reference = ReferenceOccurrence {
                    name: name.clone(),
                    start: access.start,
                    end: access.end,
                    read: !access.write,
                    write: access.write,
                };
                if let Some(projection) = projection {
                    projection.references.push(reference);
                } else {
                    parameter
                        .capability_projections
                        .push(CapabilityProjectionSummary {
                            path,
                            binding_start: parameter.start,
                            binding_end: parameter.end,
                            name,
                            references: vec![reference],
                        });
                }
            }
            parameter.capability_projections.extend(
                aliases
                    .iter()
                    .filter(|(source_binding_start, projection)| {
                        *source_binding_start == parameter.start
                            && projection.binding_start >= unit.start
                            && projection.binding_end <= unit.end
                    })
                    .map(|(_, projection)| projection.clone()),
            );
            for projection in &mut parameter.capability_projections {
                projection.references.sort_by_key(|reference| {
                    (reference.start, reference.end, reference.name.clone())
                });
                projection.references.dedup_by(|left, right| {
                    left.start == right.start
                        && left.end == right.end
                        && left.name == right.name
                        && left.read == right.read
                        && left.write == right.write
                });
            }
            parameter.capability_projections.sort_by(|left, right| {
                (&left.path, left.binding_start, left.binding_end, &left.name).cmp(&(
                    &right.path,
                    right.binding_start,
                    right.binding_end,
                    &right.name,
                ))
            });
        }
    }
}

fn collect_static_member_calls(value: &Value, output: &mut Vec<StaticMemberAccessCandidate>) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("CallExpression")
            && let Some(callee) = object.get("callee").map(unwrap_runtime_expression)
            && let Some(arguments) = object.get("arguments").and_then(Value::as_array)
            && node_type(callee).ok() == Some("MemberExpression")
        {
            let argument_count = Some(arguments.len());
            let has_spread_argument = arguments
                .iter()
                .any(|argument| node_type(argument).ok() == Some("SpreadElement"));
            let candidate = static_member_segments(callee)
                .filter(|segments| segments.len() == 2)
                .and_then(|segments| {
                    let root = static_member_root(callee)?;
                    let (root_start, root_end) = span(root).ok()?;
                    let (start, end) = span(callee).ok()?;
                    Some(StaticMemberAccessCandidate {
                        root: segments[0].clone(),
                        first_field: segments[1].clone(),
                        member_count: 1,
                        write: false,
                        root_start,
                        root_end,
                        start,
                        end,
                        argument_count,
                        has_spread_argument,
                    })
                })
                .or_else(|| {
                    let receiver = callee.get("object").map(unwrap_runtime_expression)?;
                    let property = callee.get("property").map(unwrap_runtime_expression)?;
                    let first_field = if callee
                        .get("computed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        value_string(property)?
                    } else {
                        identifier_name(property).ok()?
                    };
                    let (root_start, root_end) = span(receiver).ok()?;
                    let (start, end) = span(callee).ok()?;
                    Some(StaticMemberAccessCandidate {
                        root: String::new(),
                        first_field,
                        member_count: 1,
                        write: false,
                        root_start,
                        root_end,
                        start,
                        end,
                        argument_count,
                        has_spread_argument,
                    })
                });
            if let Some(candidate) = candidate {
                output.push(candidate);
            }
        }
        for child in object.values() {
            collect_static_member_calls(child, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_static_member_calls(child, output);
        }
    }
}

fn collect_direct_identifier_invocations(
    value: &Value,
    output: &mut Vec<DirectIdentifierInvocationCandidate>,
) {
    if let Value::Object(object) = value {
        let node_kind = object.get("type").and_then(Value::as_str);
        if matches!(node_kind, Some("CallExpression" | "NewExpression"))
            && let Some(callee) = object.get("callee").map(unwrap_runtime_expression)
            && let Ok(callee_name) = identifier_name(callee)
            && let Some(arguments) = object.get("arguments").and_then(Value::as_array)
            && let (Ok((callee_start, callee_end)), Ok((start, end))) = (span(callee), span(value))
        {
            output.push(DirectIdentifierInvocationCandidate {
                callee: callee_name,
                callee_start,
                callee_end,
                start,
                end,
                argument_count: arguments.len(),
                has_spread_argument: arguments
                    .iter()
                    .any(|argument| node_type(argument).ok() == Some("SpreadElement")),
                constructor: node_kind == Some("NewExpression"),
            });
        }
        for child in object.values() {
            collect_direct_identifier_invocations(child, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_direct_identifier_invocations(child, output);
        }
    }
}

fn collect_direct_identifier_operands(
    value: &Value,
    output: &mut Vec<DirectIdentifierOperandCandidate>,
) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("BinaryExpression")
            && object.get("operator").and_then(Value::as_str) == Some("instanceof")
            && let Ok((expression_start, expression_end)) = span(value)
        {
            for (field, operator) in [("left", "instanceof-left"), ("right", "instanceof-right")] {
                let Some(operand) = object.get(field).map(unwrap_runtime_expression) else {
                    continue;
                };
                let (Ok(identifier), Ok((start, end))) = (identifier_name(operand), span(operand))
                else {
                    continue;
                };
                output.push(DirectIdentifierOperandCandidate {
                    identifier,
                    start,
                    end,
                    expression_start,
                    expression_end,
                    operator: operator.to_string(),
                });
            }
        }
        for child in object.values() {
            collect_direct_identifier_operands(child, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_direct_identifier_operands(child, output);
        }
    }
}

fn static_member_chain(value: &Value) -> Option<StaticMemberChainCandidate> {
    let value = unwrap_static_chain_expression(value);
    if node_type(value).ok()? != "MemberExpression" {
        return None;
    }
    let (start, end) = span(value).ok()?;
    let mut current = value;
    let mut fields = Vec::new();
    let mut computed = false;
    let mut optional = false;
    loop {
        current = unwrap_static_chain_expression(current);
        match node_type(current).ok()? {
            "MemberExpression" => {
                let is_computed = current
                    .get("computed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                computed |= is_computed;
                optional |= current
                    .get("optional")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let field = if is_computed {
                    "[computed]".to_string()
                } else {
                    identifier_name(current.get("property")?).ok()?
                };
                fields.push(field);
                current = current.get("object")?;
            }
            "Identifier" => {
                fields.reverse();
                let (root_start, root_end) = span(current).ok()?;
                return Some(StaticMemberChainCandidate {
                    root: identifier_name(current).ok()?,
                    root_start,
                    root_end,
                    start,
                    end,
                    fields,
                    computed,
                    optional,
                });
            }
            _ => return None,
        }
    }
}

fn collect_static_member_chains(value: &Value, output: &mut Vec<StaticMemberChainCandidate>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("MemberExpression")
                && let Some(chain) = static_member_chain(value)
            {
                output.push(chain);
            }
            for child in object.values() {
                collect_static_member_chains(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_static_member_chains(child, output);
            }
        }
        _ => {}
    }
}

fn collect_static_function_reference_consumers(
    value: &Value,
    output: &mut Vec<StaticFunctionReferenceConsumerCandidate>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && let Some(path) = object.get("callee").and_then(member_path)
            {
                let argument_index = if matches!(
                    path.rsplit_once('.').map(|(_, method)| method),
                    Some("runAfter" | "runAt")
                ) && path
                    .split('.')
                    .rev()
                    .nth(1)
                    .is_some_and(|owner| owner == "scheduler")
                {
                    Some(1)
                } else if matches!(
                    path.rsplit_once('.').map(|(_, method)| method),
                    Some("runQuery" | "runMutation" | "runAction")
                ) {
                    Some(0)
                } else {
                    None
                };
                if let Some(argument_index) = argument_index
                    && let Some(argument) = object
                        .get("arguments")
                        .and_then(Value::as_array)
                        .and_then(|arguments| arguments.get(argument_index))
                        .map(unwrap_runtime_expression)
                    && let Ok((reference_start, reference_end)) = span(argument)
                {
                    output.push(StaticFunctionReferenceConsumerCandidate {
                        path,
                        argument_index,
                        reference_start,
                        reference_end,
                    });
                }
            }
            for child in object.values() {
                collect_static_function_reference_consumers(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_static_function_reference_consumers(child, output);
            }
        }
        _ => {}
    }
}

fn is_generated_api_module_path(module_key: &str) -> bool {
    let mut components = module_key.rsplit('/');
    components.next() == Some("api.js") && components.next() == Some("_generated")
}

fn top_level_const_identifier_initializer(ast: &Value, local: &str) -> Option<String> {
    let body = ast.get("body")?.as_array()?;
    for statement in body {
        let declaration = if node_type(statement).ok()? == "ExportNamedDeclaration" {
            let Some(declaration) = statement
                .get("declaration")
                .filter(|declaration| !declaration.is_null())
            else {
                continue;
            };
            declaration
        } else {
            statement
        };
        if node_type(declaration).ok()? != "VariableDeclaration"
            || declaration.get("kind").and_then(Value::as_str) != Some("const")
        {
            continue;
        }
        for declarator in declaration.get("declarations")?.as_array()? {
            if declarator
                .get("id")
                .and_then(|identifier| identifier_name(identifier).ok())
                .as_deref()
                != Some(local)
            {
                continue;
            }
            return declarator
                .get("init")
                .map(unwrap_runtime_expression)
                .and_then(|initializer| identifier_name(initializer).ok());
        }
    }
    None
}

fn summarize_generated_api_convention(
    module_key: &str,
    ast: &Value,
    imports: &BTreeMap<String, ImportBinding>,
    exports: &BTreeMap<String, String>,
) -> Option<GeneratedApiConventionSummary> {
    if !is_generated_api_module_path(module_key) {
        return None;
    }
    let any_api_imports = imports
        .values()
        .filter(|binding| {
            !binding.type_only
                && binding.imported == "anyApi"
                && binding.specifier == "convex/server"
        })
        .collect::<Vec<_>>();
    if any_api_imports.len() != 1 {
        return None;
    }
    let any_api = any_api_imports[0];
    for visibility in ["api", "internal"] {
        let local = exports.get(visibility)?;
        if top_level_const_identifier_initializer(ast, local).as_deref()
            != Some(any_api.local.as_str())
        {
            return None;
        }
    }
    Some(GeneratedApiConventionSummary {
        any_api_local: any_api.local.clone(),
        any_api_specifier: any_api.specifier.clone(),
        any_api_import_start: any_api.start,
    })
}

fn static_member_root(mut value: &Value) -> Option<&Value> {
    loop {
        value = unwrap_static_chain_expression(value);
        match node_type(value).ok()? {
            "Identifier" => return Some(value),
            "MemberExpression"
                if !value
                    .get("computed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    || value.get("property").and_then(value_string).is_some() =>
            {
                value = value.get("object")?;
            }
            _ => return None,
        }
    }
}

fn parse_callsite_specializable_database_get(
    call: &Value,
    parameter_names: &[String],
) -> Option<(OperationCandidate, usize)> {
    let call = unwrap_runtime_expression(call);
    if node_type(call).ok()? != "CallExpression" || call_has_optional_callee(call) {
        return None;
    }
    let callee = call.get("callee")?;
    let chain = static_member_chain(callee)?;
    let segments = static_member_segments(callee)?;
    if chain.computed
        || chain.optional
        || !matches!(segments.as_slice(), [_, capability, method] if capability == "db" && method == "get")
    {
        return None;
    }
    let arguments = call.get("arguments")?.as_array()?;
    if arguments.len() != 2 {
        return None;
    }
    let table_name = identifier_name(unwrap_runtime_expression(&arguments[0])).ok()?;
    let table_parameter_index = parameter_names
        .iter()
        .position(|parameter| parameter == &table_name)?;
    let (start, end) = span(call).ok()?;
    let (effect_start, effect_end) = span(callee).ok()?;
    Some((
        OperationCandidate {
            kind: "db.get".to_string(),
            start,
            end,
            table: None,
            index: None,
            index_constraints: Vec::new(),
            order: None,
            terminal: None,
            limit: None,
            limit_argument_index: None,
            algorithm: None,
            function_reference: None,
            function_reference_start: None,
            function_reference_end: None,
            effect_start: Some(effect_start),
            effect_end: Some(effect_end),
            effect_path: Some(segments.join(".")),
        },
        table_parameter_index,
    ))
}

fn exact_parameter_index(value: &Value, parameters: &[ParameterSummary]) -> Option<usize> {
    let value = unwrap_runtime_expression(value);
    let name = identifier_name(value).ok()?;
    parameters
        .iter()
        .find(|parameter| parameter.name == name)
        .map(|parameter| parameter.index)
}

fn parameterized_database_effect_site(
    call: &Value,
    parameters: &[ParameterSummary],
) -> Option<CallableEffectSiteCandidate> {
    let operation = callable_plans::parse_parameterized_table_database_operation(call)?;
    let segments = operation
        .effect_path
        .as_deref()?
        .split('.')
        .collect::<Vec<_>>();
    let capability_parameter_index = parameters
        .iter()
        .find(|parameter| parameter.name == segments[0])?
        .index;
    let table_argument = unwrap_runtime_expression(call)
        .get("arguments")?
        .as_array()?
        .first()?;
    let table_parameter_index = exact_parameter_index(table_argument, parameters)?;
    if table_parameter_index == capability_parameter_index {
        return None;
    }
    Some(CallableEffectSiteCandidate {
        operation,
        capability_parameter_index,
        static_operands: vec![CallableStaticOperandCandidate {
            field: "table".to_string(),
            parameter_index: table_parameter_index,
        }],
    })
}

fn collect_callable_effect_sites(
    value: &Value,
    parameters: &[ParameterSummary],
    output: &mut Vec<CallableEffectSiteCandidate>,
) {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
            ) {
                return;
            }
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && let Some(effect) = parameterized_database_effect_site(value, parameters)
            {
                output.push(effect);
            }
            for child in object.values() {
                collect_callable_effect_sites(child, parameters, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_callable_effect_sites(child, parameters, output);
            }
        }
        _ => {}
    }
}

fn callable_effect_sites(
    function: &Value,
    parameters: &[ParameterSummary],
) -> Vec<CallableEffectSiteCandidate> {
    let mut output = Vec::new();
    if let Some(body) = function.get("body") {
        collect_callable_effect_sites(body, parameters, &mut output);
    }
    output.sort_by_key(|effect| (effect.operation.start, effect.operation.end));
    output
}

fn contains_node_type(value: &Value, expected: &str) -> bool {
    count_node_type(value, expected) > 0
}

fn count_node_type(value: &Value, expected: &str) -> usize {
    match value {
        Value::Object(object) => {
            usize::from(object.get("type").and_then(Value::as_str) == Some(expected))
                + object
                    .values()
                    .map(|child| count_node_type(child, expected))
                    .sum::<usize>()
        }
        Value::Array(values) => values
            .iter()
            .map(|child| count_node_type(child, expected))
            .sum(),
        _ => 0,
    }
}

fn complete_array_expression_elements(value: &Value) -> Result<Option<Vec<SourceRange>>> {
    let value = unwrap_runtime_expression(value);
    if node_type(value)? != "ArrayExpression" {
        return Ok(None);
    }
    let Some(elements) = value.get("elements").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut ranges = Vec::with_capacity(elements.len());
    for element in elements {
        if element.is_null() || node_type(element).ok() == Some("SpreadElement") {
            return Ok(None);
        }
        let (start, end) = span(unwrap_runtime_expression(element))?;
        ranges.push(SourceRange { start, end });
    }
    Ok(Some(ranges))
}

fn direct_awaited_promise_all(
    statement: &Value,
) -> Result<Option<(String, u32, u32, u32, u32, u32, u32)>> {
    let expression = match node_type(statement)? {
        "ExpressionStatement" => statement.get("expression"),
        "ReturnStatement" => statement
            .get("argument")
            .filter(|argument| !argument.is_null()),
        _ => None,
    };
    let Some(expression) = expression.map(unwrap_runtime_expression) else {
        return Ok(None);
    };
    if node_type(expression)? != "AwaitExpression" {
        return Ok(None);
    }
    let Some(call) = expression
        .get("argument")
        .map(unwrap_runtime_expression)
        .filter(|call| node_type(call).ok() == Some("CallExpression"))
    else {
        return Ok(None);
    };
    if !is_static_member_call(call, "Promise", "all") {
        return Ok(None);
    }
    let Some(arguments) = call.get("arguments").and_then(Value::as_array) else {
        return Ok(None);
    };
    let [argument] = arguments.as_slice() else {
        return Ok(None);
    };
    let argument = unwrap_runtime_expression(argument);
    if node_type(argument)? != "Identifier" {
        return Ok(None);
    }
    let Some(name) = argument.get("name").and_then(Value::as_str) else {
        return Ok(None);
    };
    let (promise_all_start, promise_all_end) = span(call)?;
    let (argument_start, argument_end) = span(argument)?;
    let (await_start, await_end) = span(expression)?;
    Ok(Some((
        name.to_string(),
        promise_all_start,
        promise_all_end,
        argument_start,
        argument_end,
        await_start,
        await_end,
    )))
}

fn collect_promise_all_alias_handoffs(
    value: &Value,
    output: &mut Vec<PromiseAllAliasHandoffFact>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("BlockStatement") {
                if let Some(statements) = object.get("body").and_then(Value::as_array) {
                    for statements in statements.windows(2) {
                        let [declaration, consumer] = statements else {
                            continue;
                        };
                        if node_type(declaration)? != "VariableDeclaration"
                            || declaration.get("kind").and_then(Value::as_str) != Some("const")
                        {
                            continue;
                        }
                        let Some(declarations) =
                            declaration.get("declarations").and_then(Value::as_array)
                        else {
                            continue;
                        };
                        // A second declarator can run arbitrary code between child creation and
                        // aggregate ownership, so this proof accepts one declaration only.
                        let [binding] = declarations.as_slice() else {
                            continue;
                        };
                        let Some(identifier) = binding.get("id") else {
                            continue;
                        };
                        if node_type(identifier)? != "Identifier" {
                            continue;
                        }
                        let Some((
                            argument_name,
                            promise_all_start,
                            promise_all_end,
                            argument_start,
                            argument_end,
                            await_start,
                            await_end,
                        )) = direct_awaited_promise_all(consumer)?
                        else {
                            continue;
                        };
                        if identifier.get("name").and_then(Value::as_str)
                            != Some(argument_name.as_str())
                        {
                            continue;
                        }
                        let (binding_start, binding_end) = span(identifier)?;
                        output.push(PromiseAllAliasHandoffFact {
                            binding_start,
                            binding_end,
                            promise_all_start,
                            promise_all_end,
                            argument_start,
                            argument_end,
                            await_start,
                            await_end,
                        });
                    }
                }
            }
            for child in object.values() {
                collect_promise_all_alias_handoffs(child, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_promise_all_alias_handoffs(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_binding_initializer_facts(
    value: &Value,
    output: &mut BTreeMap<(u32, u32), BindingInitializerFact>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("VariableDeclaration") {
                let constant = object.get("kind").and_then(Value::as_str) == Some("const");
                if let Some(declarations) = object.get("declarations").and_then(Value::as_array) {
                    for declaration in declarations {
                        let Some(identifier) = declaration.get("id") else {
                            continue;
                        };
                        if node_type(identifier).ok() != Some("Identifier") {
                            continue;
                        }
                        let Some(initializer_value) = declaration
                            .get("init")
                            .filter(|initializer| !initializer.is_null())
                            .map(unwrap_runtime_expression)
                        else {
                            continue;
                        };
                        let binding = span(identifier)?;
                        let initializer = span(initializer_value)?;
                        ensure!(
                            output
                                .insert(
                                    binding,
                                    BindingInitializerFact {
                                        start: initializer.0,
                                        end: initializer.1,
                                        constant,
                                        array_elements: complete_array_expression_elements(
                                            initializer_value,
                                        )?,
                                    },
                                )
                                .is_none(),
                            "Oxc binding declaration has duplicate initializer facts"
                        );
                    }
                }
            }
            for child in object.values() {
                collect_binding_initializer_facts(child, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_binding_initializer_facts(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_conditional_expression_facts(
    value: &Value,
    output: &mut Vec<ConditionalExpressionFact>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("ConditionalExpression") {
                let (start, end) = span(value)?;
                let consequent = object
                    .get("consequent")
                    .map(unwrap_runtime_expression)
                    .context("conditional expression has no consequent")?;
                let alternate = object
                    .get("alternate")
                    .map(unwrap_runtime_expression)
                    .context("conditional expression has no alternate")?;
                let (consequent_start, consequent_end) = span(consequent)?;
                let (alternate_start, alternate_end) = span(alternate)?;
                output.push(ConditionalExpressionFact {
                    start,
                    end,
                    consequent_start,
                    consequent_end,
                    alternate_start,
                    alternate_end,
                });
            }
            for child in object.values() {
                collect_conditional_expression_facts(child, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_conditional_expression_facts(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_callable_parameter_facts(
    value: &Value,
    output: &mut Vec<CallableParameterFact>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
            ) {
                let (callable_start, callable_end) = span(value)?;
                let parameters = object
                    .get("params")
                    .and_then(Value::as_array)
                    .context("callable has no parameter list")?
                    .iter()
                    .enumerate()
                    .filter_map(|(index, parameter)| {
                        let parameter = unwrap_runtime_expression(parameter);
                        let name = identifier_name(parameter).ok()?;
                        Some(
                            span(parameter).map(|(start, end)| CallableParameterEntryFact {
                                index,
                                name,
                                start,
                                end,
                            }),
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                output.push(CallableParameterFact {
                    callable_start,
                    callable_end,
                    parameters,
                });
            }
            for child in object.values() {
                collect_callable_parameter_facts(child, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_callable_parameter_facts(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_static_member_call(call: &Value, object_name: &str, property_name: &str) -> bool {
    let call = unwrap_runtime_expression(call);
    if call_has_optional_callee(call) {
        return false;
    }
    let Some(callee) = call.get("callee").map(unwrap_runtime_expression) else {
        return false;
    };
    node_type(callee).ok() == Some("MemberExpression")
        && !callee
            .get("computed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        && callee
            .get("object")
            .map(unwrap_runtime_expression)
            .and_then(|object| identifier_name(object).ok())
            .as_deref()
            == Some(object_name)
        && callee
            .get("property")
            .and_then(|property| identifier_name(property).ok())
            .as_deref()
            == Some(property_name)
}

fn call_has_optional_callee(call: &Value) -> bool {
    let call = unwrap_runtime_expression(call);
    node_type(call).ok() == Some("CallExpression")
        && (call.get("optional").and_then(Value::as_bool) == Some(true)
            || call
                .get("callee")
                .is_some_and(expression_has_optional_chain))
}

fn expression_has_optional_chain(value: &Value) -> bool {
    let value = unwrap_runtime_expression(value);
    match node_type(value).ok() {
        Some("ChainExpression") => true,
        Some("CallExpression") => {
            value.get("optional").and_then(Value::as_bool) == Some(true)
                || value
                    .get("callee")
                    .is_some_and(expression_has_optional_chain)
        }
        Some("MemberExpression") => {
            value.get("optional").and_then(Value::as_bool) == Some(true)
                || value
                    .get("object")
                    .is_some_and(expression_has_optional_chain)
        }
        _ => false,
    }
}

fn unwrap_runtime_expression(mut value: &Value) -> &Value {
    loop {
        let expression = match node_type(value).ok() {
            Some(
                "ParenthesizedExpression"
                | "TSAsExpression"
                | "TSSatisfiesExpression"
                | "TSNonNullExpression"
                | "TSTypeAssertion"
                | "TSInstantiationExpression",
            ) => value.get("expression"),
            _ => None,
        };
        let Some(expression) = expression else {
            break;
        };
        value = expression;
    }
    value
}

fn unwrap_static_chain_expression(value: &Value) -> &Value {
    let value = unwrap_runtime_expression(value);
    if node_type(value).ok() == Some("ChainExpression") {
        value
            .get("expression")
            .map(unwrap_runtime_expression)
            .unwrap_or(value)
    } else {
        value
    }
}

fn unwrap_transparent_expression(mut value: &Value) -> &Value {
    loop {
        let expression = match node_type(value).ok() {
            Some("AwaitExpression") => value.get("argument"),
            _ if !std::ptr::eq(unwrap_runtime_expression(value), value) => {
                Some(unwrap_runtime_expression(value))
            }
            _ => None,
        };
        let Some(expression) = expression else {
            break;
        };
        value = expression;
    }
    value
}

fn leading_await_count(mut value: &Value) -> usize {
    let mut count = 0;
    loop {
        match node_type(value).ok() {
            Some("AwaitExpression") => {
                count += 1;
                let Some(argument) = value.get("argument") else {
                    break;
                };
                value = argument;
            }
            _ if !std::ptr::eq(unwrap_runtime_expression(value), value) => {
                value = unwrap_runtime_expression(value);
            }
            _ => break,
        }
    }
    count
}

fn exact_call_argument_projections(value: &Value) -> Vec<CallArgumentProjectionCandidate> {
    fn collect(
        value: &Value,
        prefix: &[String],
        output: &mut Vec<CallArgumentProjectionCandidate>,
    ) -> Option<()> {
        let value = unwrap_runtime_expression(value);
        if node_type(value).ok()? != "ObjectExpression" {
            return Some(());
        }
        let properties = value.get("properties")?.as_array()?;
        let mut names = BTreeSet::new();
        for property in properties {
            if node_type(property).ok()? != "Property"
                || property.get("computed").and_then(Value::as_bool) == Some(true)
                || property.get("method").and_then(Value::as_bool) == Some(true)
                || property.get("kind").and_then(Value::as_str) != Some("init")
            {
                return None;
            }
            let name = property_name(property).ok()?;
            if !names.insert(name.clone()) {
                return None;
            }
            let property_value = property.get("value")?;
            let runtime_value = unwrap_transparent_expression(property_value);
            let (start, end) = span(runtime_value).ok()?;
            let mut path = prefix.to_vec();
            path.push(name);
            output.push(CallArgumentProjectionCandidate {
                path: path.clone(),
                value: SourceRange { start, end },
                await_count: count_node_type(property_value, "AwaitExpression"),
            });
            collect(runtime_value, &path, output)?;
        }
        Some(())
    }

    let mut output = Vec::new();
    if collect(value, &[], &mut output).is_none() {
        return Vec::new();
    }
    output.sort_by(|left, right| left.path.cmp(&right.path));
    output
}

fn collect_calls(
    value: &Value,
    references: &[ReferenceOccurrence],
    suspension: Option<&str>,
    output: &mut Vec<CallCandidate>,
) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("CallExpression")
            && let Some(callee) = object.get("callee").map(unwrap_runtime_expression)
            && let Ok(callee_name) = identifier_name(callee)
            && let Ok((callee_start, callee_end)) = span(callee)
            && references.iter().any(|reference| {
                reference.read
                    && reference.name == callee_name
                    && reference.start == callee_start
                    && reference.end == callee_end
            })
            && let (Ok((start, end)), Some(arguments)) = (
                span(value),
                object.get("arguments").and_then(Value::as_array),
            )
        {
            let argument_ranges = arguments
                .iter()
                .filter_map(|argument| {
                    span(unwrap_transparent_expression(argument))
                        .ok()
                        .map(|(start, end)| SourceRange { start, end })
                })
                .collect::<Vec<_>>();
            if argument_ranges.len() == arguments.len() {
                let argument_await_counts = arguments
                    .iter()
                    .map(|argument| count_node_type(argument, "AwaitExpression"))
                    .collect();
                let argument_projections = arguments
                    .iter()
                    .map(exact_call_argument_projections)
                    .collect();
                output.push(CallCandidate {
                    callee: callee_name,
                    callee_start,
                    callee_end,
                    start,
                    end,
                    arguments: argument_ranges,
                    argument_await_counts,
                    argument_projections,
                    suspension: suspension.map(str::to_string),
                });
            }
        }
        let kind = object.get("type").and_then(Value::as_str);
        for (key, child) in object {
            let child_suspension = match (kind, key.as_str()) {
                (Some("AwaitExpression"), "argument") => Some("await"),
                (Some("ReturnStatement"), "argument") => Some("return"),
                (Some("ArrowFunctionExpression"), "body")
                    if node_type(child).ok() != Some("BlockStatement") =>
                {
                    Some("return")
                }
                (
                    Some(
                        "ParenthesizedExpression"
                        | "TSAsExpression"
                        | "TSSatisfiesExpression"
                        | "TSNonNullExpression"
                        | "TSTypeAssertion"
                        | "TSInstantiationExpression",
                    ),
                    "expression",
                ) => suspension,
                _ => None,
            };
            collect_calls(child, references, child_suspension, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_calls(child, references, None, output);
        }
    }
}

fn static_member_segments(value: &Value) -> Option<Vec<String>> {
    let value = unwrap_static_chain_expression(value);
    match node_type(value).ok()? {
        "Identifier" => Some(vec![identifier_name(value).ok()?]),
        "MemberExpression" => {
            let mut segments = static_member_segments(value.get("object")?)?;
            let property = value.get("property")?;
            let segment = if value
                .get("computed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                value_string(property).unwrap_or_else(|| "[computed]".to_string())
            } else {
                identifier_name(property).ok()?
            };
            segments.push(segment);
            Some(segments)
        }
        _ => None,
    }
}

fn collect_effects(
    value: &Value,
    context_parameters: &BTreeSet<String>,
    output: &mut Vec<EffectCandidate>,
) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("CallExpression")
            && let Some(callee) = object.get("callee")
            && let Some(segments) = static_member_segments(callee)
            && (segments
                .first()
                .is_some_and(|root| context_parameters.contains(root))
                || segments.windows(2).any(|window| {
                    matches!(window[0].as_str(), "db" | "scheduler")
                        || (window[0] == "auth" && window[1] == "getUserIdentity")
                        || (window[0] == "storage"
                            && matches!(
                                window[1].as_str(),
                                "delete" | "generateUploadUrl" | "getMetadata" | "getUrl"
                            ))
                })
                || segments.last().is_some_and(|method| {
                    matches!(
                        method.as_str(),
                        "runAction" | "runMutation" | "runQuery" | "vectorSearch"
                    )
                }))
            && let Ok((start, end)) = span(callee)
        {
            output.push(EffectCandidate {
                path: segments.join("."),
                start,
                end,
            });
        }
        if object.get("type").and_then(Value::as_str) == Some("MemberExpression")
            && let Some(segments) = static_member_segments(value)
            && (segments
                .first()
                .is_some_and(|root| context_parameters.contains(root))
                || segments
                    .last()
                    .is_some_and(|capability| matches!(capability.as_str(), "db" | "scheduler")))
            && let Ok((start, end)) = span(value)
        {
            output.push(EffectCandidate {
                path: segments.join("."),
                start,
                end,
            });
        }
        for child in object.values() {
            collect_effects(child, context_parameters, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_effects(child, context_parameters, output);
        }
    }
}

fn context_capability_operation_candidate(
    call: &Value,
    kind: &str,
    table: Option<String>,
    effect_path: String,
) -> Option<OperationCandidate> {
    let (start, end) = span(call).ok()?;
    let (effect_start, effect_end) = span(call.get("callee")?).ok()?;
    Some(OperationCandidate {
        kind: kind.to_string(),
        start,
        end,
        table,
        index: None,
        index_constraints: Vec::new(),
        order: None,
        terminal: None,
        limit: None,
        limit_argument_index: None,
        algorithm: None,
        function_reference: None,
        function_reference_start: None,
        function_reference_end: None,
        effect_start: Some(effect_start),
        effect_end: Some(effect_end),
        effect_path: Some(effect_path),
    })
}

fn parse_context_capability_operation(call: &Value) -> Option<OperationCandidate> {
    let call = unwrap_runtime_expression(call);
    if node_type(call).ok()? != "CallExpression" {
        return None;
    }
    let callee = call.get("callee")?;
    let chain = static_member_chain(callee)?;
    let segments = static_member_segments(callee)?;
    if segments.len() != 3 || chain.fields.len() != 2 {
        return None;
    }
    let arguments = call.get("arguments")?.as_array()?;
    let effect_path = segments.join(".");
    match &segments[1..] {
        [capability, method] if capability == "auth" && method == "getUserIdentity" => {
            let kind = if chain.computed {
                "rejected.auth.getUserIdentity.computed"
            } else if chain.optional || call_has_optional_callee(call) {
                "rejected.auth.getUserIdentity.optional"
            } else if !arguments.is_empty() {
                "rejected.auth.getUserIdentity.arity"
            } else {
                "auth.getUserIdentity"
            };
            context_capability_operation_candidate(call, kind, None, effect_path)
        }
        [capability, method] if capability == "db" && method == "normalizeId" => {
            let kind = if chain.computed {
                "rejected.db.normalizeId.computed"
            } else if chain.optional || call_has_optional_callee(call) {
                "rejected.db.normalizeId.optional"
            } else if arguments.len() != 2 {
                "rejected.db.normalizeId.arity"
            } else if value_string(&arguments[0])
                .filter(|table| !table.is_empty())
                .is_none()
            {
                "rejected.db.normalizeId.dynamicTable"
            } else {
                "db.normalizeId"
            };
            context_capability_operation_candidate(
                call,
                kind,
                arguments
                    .first()
                    .and_then(value_string)
                    .filter(|table| !table.is_empty()),
                effect_path,
            )
        }
        _ => None,
    }
}

struct ParsedIndexConstraint<'a> {
    field: String,
    operator: String,
    value: &'a Value,
}

fn parse_index_constraints(callback: &Value) -> Option<Vec<ParsedIndexConstraint<'_>>> {
    let callback = unwrap_runtime_expression(callback);
    if !matches!(
        node_type(callback).ok()?,
        "ArrowFunctionExpression" | "FunctionExpression"
    ) {
        return None;
    }
    let parameters = callback.get("params")?.as_array()?;
    if parameters.len() != 1 {
        return None;
    }
    let range_parameter = identifier_name(&parameters[0]).ok()?;
    let mut current = callback.get("body").map(unwrap_runtime_expression)?;
    let mut reversed = Vec::new();
    loop {
        if node_type(current).ok()? != "CallExpression" || call_has_optional_callee(current) {
            return None;
        }
        let operator = call_method_name(current)?;
        if !matches!(operator.as_str(), "eq" | "gt" | "gte" | "lt" | "lte") {
            return None;
        }
        let arguments = current.get("arguments")?.as_array()?;
        if arguments.len() != 2 {
            return None;
        }
        let field = value_string(&arguments[0])?;
        if field.is_empty() {
            return None;
        }
        reversed.push(ParsedIndexConstraint {
            field,
            operator,
            value: unwrap_runtime_expression(&arguments[1]),
        });
        let receiver = current
            .get("callee")?
            .get("object")
            .map(unwrap_runtime_expression)?;
        if node_type(receiver).ok()? == "Identifier" {
            if identifier_name(receiver).ok()? != range_parameter {
                return None;
            }
            break;
        }
        current = receiver;
    }
    reversed.reverse();
    if reversed.first()?.operator != "eq" {
        return None;
    }
    let mut fields = BTreeSet::new();
    let mut saw_range = false;
    for (index, constraint) in reversed.iter().enumerate() {
        if !fields.insert(constraint.field.clone()) {
            return None;
        }
        if constraint.operator == "eq" {
            if saw_range {
                return None;
            }
        } else {
            if saw_range || index + 1 != reversed.len() {
                return None;
            }
            saw_range = true;
        }
    }
    (!reversed.is_empty()).then_some(reversed)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DatabaseOperationSource {
    Raw,
    CompilerGenerated,
}

fn parse_db_operation(call: &Value, source: &str) -> Option<OperationCandidate> {
    parse_db_operation_for_source(call, source, DatabaseOperationSource::Raw)
}

fn parse_db_operation_for_source(
    call: &Value,
    source: &str,
    operation_source: DatabaseOperationSource,
) -> Option<OperationCandidate> {
    let call = unwrap_runtime_expression(call);
    if call_has_optional_callee(call) {
        return None;
    }
    let callee_path = member_path(call.get("callee")?);
    let callee_segments = callee_path
        .as_deref()
        .map(|path| path.split('.').collect::<Vec<_>>())
        .unwrap_or_default();
    if matches!(callee_segments.as_slice(), [_, "db", "get"]) {
        let arguments = call.get("arguments")?.as_array()?;
        if arguments.len() != 2 {
            return None;
        }
        let table = value_string(&arguments[0]).filter(|table| !table.is_empty())?;
        let (start, end) = span(call).ok()?;
        let (effect_start, effect_end) = span(call.get("callee")?).ok()?;
        return Some(OperationCandidate {
            kind: "db.get".to_string(),
            start,
            end,
            table: Some(table),
            index: None,
            index_constraints: Vec::new(),
            order: None,
            terminal: None,
            limit: None,
            limit_argument_index: None,
            algorithm: None,
            function_reference: None,
            function_reference_start: None,
            function_reference_end: None,
            effect_start: Some(effect_start),
            effect_end: Some(effect_end),
            effect_path: callee_path,
        });
    }
    if let Some(kind) = match callee_segments.as_slice() {
        [_, "db", "insert"] => Some("db.insert"),
        [_, "db", "patch"] => Some("db.patch"),
        [_, "db", "replace"] => Some("db.replace"),
        [_, "db", "delete"] => Some("db.delete"),
        _ => None,
    } {
        let arguments = call.get("arguments")?.as_array()?;
        let expected_arguments = if kind == "db.insert" || kind == "db.delete" {
            2
        } else {
            3
        };
        if arguments.len() != expected_arguments {
            return None;
        }
        let table = value_string(&arguments[0]).filter(|table| !table.is_empty())?;
        let (start, end) = span(call).ok()?;
        let (effect_start, effect_end) = span(call.get("callee")?).ok()?;
        return Some(OperationCandidate {
            kind: kind.to_string(),
            start,
            end,
            table: Some(table),
            index: None,
            index_constraints: Vec::new(),
            order: None,
            terminal: None,
            limit: None,
            limit_argument_index: None,
            algorithm: None,
            function_reference: None,
            function_reference_start: None,
            function_reference_end: None,
            effect_start: Some(effect_start),
            effect_end: Some(effect_end),
            effect_path: callee_path,
        });
    }
    if operation_source == DatabaseOperationSource::CompilerGenerated
        && matches!(
            callee_identifier(call).as_deref(),
            Some(
                "__convexDependencyAdapter_databaseIndexCollect"
                    | "__convexDependencyAdapter_databaseIndexUnique"
                    | "__convexDependencyAdapter_databaseIndexUniqueOrThrow"
            )
        )
    {
        let arguments = call.get("arguments")?.as_array()?;
        if !matches!(arguments.len(), 4 | 5) {
            return None;
        }
        let table = value_string(&arguments[1]).filter(|table| !table.is_empty())?;
        let index = value_string(&arguments[2]).filter(|index| !index.is_empty())?;
        let effect_expression = unwrap_runtime_expression(&arguments[0]);
        let effect_path = member_path(effect_expression)?;
        let effect_segments = effect_path.split('.').collect::<Vec<_>>();
        if effect_segments.len() != 2 || effect_segments[1] != "db" {
            return None;
        }
        let eq_field = arguments
            .get(4)
            .and_then(value_string)
            .filter(|field| !field.is_empty())
            .unwrap_or_else(|| index.strip_prefix("by_").unwrap_or(&index).to_string());
        let (start, end) = span(call).ok()?;
        let (effect_start, effect_end) = span(effect_expression).ok()?;
        let value_span = span(unwrap_runtime_expression(&arguments[3])).ok()?;
        let terminal = if callee_identifier(call).as_deref()
            == Some("__convexDependencyAdapter_databaseIndexCollect")
        {
            "collect"
        } else {
            "unique"
        };
        let shape = canonical_index_query_shape(None, terminal, None, false)?;
        return Some(OperationCandidate {
            kind: "db.query".to_string(),
            start,
            end,
            table: Some(table),
            index: Some(index),
            index_constraints: vec![IndexConstraintCandidate {
                field: eq_field,
                operator: "eq".to_string(),
                value_source: source_slice(source, value_span.0, value_span.1)
                    .unwrap_or_default()
                    .to_string(),
                value_start: value_span.0,
                value_end: value_span.1,
            }],
            order: Some(shape.order),
            terminal: Some(shape.terminal),
            limit: shape.limit,
            limit_argument_index: None,
            algorithm: None,
            function_reference: None,
            function_reference_start: None,
            function_reference_end: None,
            effect_start: Some(effect_start),
            effect_end: Some(effect_end),
            effect_path: Some(effect_path),
        });
    }
    if operation_source == DatabaseOperationSource::CompilerGenerated
        && callee_identifier(call).as_deref()
            == Some("__convexDependencyAdapter_functionHandleCreate")
    {
        let arguments = call.get("arguments")?.as_array()?;
        if arguments.len() != 1 {
            return None;
        }
        let (start, end) = span(call).ok()?;
        let (effect_start, effect_end) = span(call.get("callee")?).ok()?;
        return Some(OperationCandidate {
            kind: "functionHandleCreate".to_string(),
            start,
            end,
            table: None,
            index: None,
            index_constraints: Vec::new(),
            order: None,
            terminal: None,
            limit: None,
            limit_argument_index: None,
            algorithm: None,
            function_reference: None,
            function_reference_start: None,
            function_reference_end: None,
            effect_start: Some(effect_start),
            effect_end: Some(effect_end),
            effect_path: Some("__convexDependencyAdapter_functionHandleCreate".to_string()),
        });
    }
    let terminal = call_method_name(call)?;
    if !matches!(terminal.as_str(), "collect" | "first" | "unique" | "take") {
        return None;
    }
    let terminal_arguments = call.get("arguments")?.as_array()?;
    let (limit, dynamic_limit) = if terminal == "take" {
        if terminal_arguments.len() != 1 {
            return None;
        }
        let literal = unwrap_runtime_expression(&terminal_arguments[0]);
        if node_type(literal).ok()? == "Literal" {
            let value = literal.get("value")?.as_f64()?;
            if value.fract() != 0.0 || !(1.0..=100_000.0).contains(&value) {
                return None;
            }
            (Some(value as u32), false)
        } else {
            if node_type(literal).ok()? == "SpreadElement" {
                return None;
            }
            (None, true)
        }
    } else {
        if !terminal_arguments.is_empty() {
            return None;
        }
        (None, false)
    };
    let mut stages = Vec::new();
    let mut current = call;
    loop {
        let method = call_method_name(current)?;
        stages.push((method, current));
        let callee = current.get("callee").map(unwrap_runtime_expression)?;
        let receiver = callee.get("object").map(unwrap_runtime_expression)?;
        if node_type(receiver).ok()? != "CallExpression" {
            break;
        }
        current = receiver;
    }
    stages.reverse();
    if stages.first().map(|stage| stage.0.as_str()) != Some("query") {
        return None;
    }
    let effect_path = member_path(stages[0].1.get("callee")?)?;
    let effect_segments = effect_path.split('.').collect::<Vec<_>>();
    if effect_segments.len() != 3 || effect_segments[1] != "db" || effect_segments[2] != "query" {
        return None;
    }
    if stages[0].1.get("arguments")?.as_array()?.len() != 1 {
        return None;
    }
    let table = call_argument_string(stages[0].1, 0).filter(|table| !table.is_empty())?;
    let mut with_index_stages = stages.iter().filter(|stage| stage.0 == "withIndex");
    let with_index = with_index_stages.next()?;
    if with_index_stages.next().is_some() {
        return None;
    }
    if with_index.1.get("arguments")?.as_array()?.len() != 2 {
        return None;
    }
    let index = call_argument_string(with_index.1, 0).filter(|index| !index.is_empty())?;
    let callback = with_index
        .1
        .get("arguments")?
        .as_array()?
        .get(1)
        .map(unwrap_runtime_expression)?;
    let parsed_constraints = parse_index_constraints(callback)?;
    let (start, end) = span(call).ok()?;
    let (effect_start, effect_end) = span(stages[0].1.get("callee")?).ok()?;
    let index_constraints = parsed_constraints
        .into_iter()
        .map(|constraint| {
            let (value_start, value_end) = span(constraint.value).ok()?;
            Some(IndexConstraintCandidate {
                field: constraint.field,
                operator: constraint.operator,
                value_source: source_slice(source, value_start, value_end)
                    .unwrap_or_default()
                    .to_string(),
                value_start,
                value_end,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let mut order_stages = stages.iter().filter(|stage| stage.0 == "order");
    let order = if let Some(order_stage) = order_stages.next() {
        if order_stages.next().is_some() || order_stage.1.get("arguments")?.as_array()?.len() != 1 {
            return None;
        }
        Some(call_argument_string(order_stage.1, 0)?)
    } else {
        None
    };
    let shape = canonical_index_query_shape(order.as_deref(), &terminal, limit, dynamic_limit)?;
    let limit_argument_index = if shape.dynamic_limit {
        Some(u32::try_from(index_constraints.len()).ok()?)
    } else {
        None
    };
    Some(OperationCandidate {
        kind: "db.query".to_string(),
        start,
        end,
        table: Some(table),
        index: Some(index),
        index_constraints,
        order: Some(shape.order),
        terminal: Some(shape.terminal),
        limit: shape.limit,
        limit_argument_index,
        algorithm: None,
        function_reference: None,
        function_reference_start: None,
        function_reference_end: None,
        effect_start: Some(effect_start),
        effect_end: Some(effect_end),
        effect_path: Some(effect_path),
    })
}

fn parse_scheduler_operation(call: &Value) -> Option<OperationCandidate> {
    let call = unwrap_runtime_expression(call);
    if call_has_optional_callee(call) {
        return None;
    }
    let effect_path = member_path(call.get("callee")?)?;
    let effect_segments = effect_path.split('.').collect::<Vec<_>>();
    let kind = match effect_segments.as_slice() {
        [_, "scheduler", "runAfter"] => "scheduler.runAfter",
        [_, "scheduler", "runAt"] => "scheduler.runAt",
        _ => return None,
    };
    let arguments = call.get("arguments")?.as_array()?;
    if arguments.len() != 3 {
        return None;
    }
    let function_expression = unwrap_runtime_expression(&arguments[1]);
    let function_chain = static_member_chain(function_expression);
    let function_reference = function_chain
        .as_ref()
        .filter(|chain| !chain.computed && !chain.optional && chain.fields.len() >= 2)
        .map(|chain| canonical_function_reference(&chain.fields))
        .or_else(|| {
            let arguments = function_expression.get("arguments")?.as_array()?;
            (callee_identifier(function_expression).as_deref() == Some("__convexFunctionReference")
                && arguments.len() == 1)
                .then(|| value_string(&arguments[0]))
                .flatten()
        });
    let (start, end) = span(call).ok()?;
    let (effect_start, effect_end) = span(call.get("callee")?).ok()?;
    let (function_reference_start, function_reference_end) = span(function_expression).ok()?;
    Some(OperationCandidate {
        kind: kind.to_string(),
        start,
        end,
        table: None,
        index: None,
        index_constraints: Vec::new(),
        order: None,
        terminal: None,
        limit: None,
        limit_argument_index: None,
        algorithm: None,
        function_reference,
        function_reference_start: Some(function_reference_start),
        function_reference_end: Some(function_reference_end),
        effect_start: Some(effect_start),
        effect_end: Some(effect_end),
        effect_path: Some(effect_path),
    })
}

fn canonical_function_reference(fields: &[String]) -> String {
    let function_name = fields
        .last()
        .expect("static function reference must have a function name");
    format!(
        "_reference/function/{}:{function_name}",
        fields[..fields.len() - 1].join("/")
    )
}

fn parse_sha_operation(call: &Value) -> Option<OperationCandidate> {
    let call = unwrap_runtime_expression(call);
    if call_has_optional_callee(call) {
        return None;
    }
    let callee = call.get("callee")?;
    if member_path(callee).as_deref() != Some("crypto.subtle.digest") {
        return None;
    }
    let arguments = call.get("arguments")?.as_array()?;
    if arguments.len() != 2 {
        return None;
    }
    let algorithm = call_argument_string(call, 0)?;
    if algorithm != "SHA-256" {
        return None;
    }
    let (start, end) = span(call).ok()?;
    Some(OperationCandidate {
        kind: "intrinsic.sha256".to_string(),
        start,
        end,
        table: None,
        index: None,
        index_constraints: Vec::new(),
        order: None,
        terminal: None,
        limit: None,
        limit_argument_index: None,
        algorithm: Some(algorithm),
        function_reference: None,
        function_reference_start: None,
        function_reference_end: None,
        effect_start: None,
        effect_end: None,
        effect_path: None,
    })
}

fn collect_document_properties(
    ast: &Value,
    source: &str,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    proved_local_filters: &[LocalFilteredArrayCandidate],
    direct_async_batches: &[DirectAsyncBatchCandidate],
) -> Result<Vec<DocumentPropertyCandidate>> {
    let mut binding_candidates = Vec::new();
    collect_db_result_bindings(ast, source, &mut binding_candidates);
    let mut document_references = BTreeMap::<(u32, u32), String>::new();
    let mut collection_references = BTreeMap::<(u32, u32), String>::new();
    let mut collection_binding_starts = BTreeSet::new();
    for binding in &binding_candidates {
        let references =
            resolved_binding_references(scoping, nodes, &binding.name, binding.binding_start)?;
        let target = match binding.kind {
            DatabaseResultKind::Collection => {
                collection_binding_starts.insert(binding.binding_start);
                &mut collection_references
            }
            DatabaseResultKind::Document => &mut document_references,
        };
        insert_bound_references(target, references, &binding.table)?;
    }
    loop {
        let previous_len = collection_binding_starts.len();
        for filtered in proved_local_filters {
            if collection_binding_starts.contains(&filtered.binding_start) {
                continue;
            }
            let Some(table) = collection_references
                .get(&(
                    filtered.source_reference_start,
                    filtered.source_reference_end,
                ))
                .cloned()
            else {
                continue;
            };
            let references = resolved_binding_references(
                scoping,
                nodes,
                &filtered.name,
                filtered.binding_start,
            )?;
            insert_bound_references(&mut collection_references, references, &table)?;
            collection_binding_starts.insert(filtered.binding_start);
        }
        if collection_binding_starts.len() == previous_len {
            break;
        }
    }
    let mut output = Vec::new();
    collect_bound_properties(ast, &document_references, None, &mut output);
    collect_collection_callback_properties(
        ast,
        scoping,
        nodes,
        &collection_references,
        proved_local_filters,
        direct_async_batches,
        &mut output,
    )?;
    Ok(output)
}

fn collect_db_result_bindings(
    value: &Value,
    source: &str,
    output: &mut Vec<DatabaseResultBindingCandidate>,
) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("VariableDeclarator")
            && let (Some(identifier), Some(initializer)) = (object.get("id"), object.get("init"))
            && let Ok(name) = identifier_name(identifier)
            && let Ok((binding_start, _)) = span(identifier)
        {
            let initializer = unwrap_await(initializer);
            let result = if let Some(operation) = parse_db_operation(initializer, source)
                && let Some(table) = operation.table
            {
                match (operation.kind.as_str(), operation.terminal.as_deref()) {
                    ("db.get", _) | ("db.query", Some("first" | "unique")) => {
                        Some((table, DatabaseResultKind::Document))
                    }
                    ("db.query", Some("collect")) => Some((table, DatabaseResultKind::Collection)),
                    _ => None,
                }
            } else if node_type(initializer).ok() == Some("CallExpression")
                && callee_identifier(initializer).is_some()
                && let Ok((start, end)) = span(initializer)
            {
                Some((
                    format!("__dependencyAdapterCall:{start}:{end}"),
                    DatabaseResultKind::Collection,
                ))
            } else {
                None
            };
            if let Some((table, kind)) = result {
                output.push(DatabaseResultBindingCandidate {
                    name,
                    table,
                    kind,
                    binding_start,
                });
            }
        }
        for child in object.values() {
            collect_db_result_bindings(child, source, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_db_result_bindings(child, source, output);
        }
    }
}

fn collect_opaque_binding_candidates(
    value: &Value,
    source: &str,
    output: &mut Vec<OpaqueBindingCandidate>,
) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("VariableDeclarator")
            && let (Some(identifier), Some(initializer)) = (object.get("id"), object.get("init"))
            && let Ok(name) = identifier_name(identifier)
            && let Ok((binding_start, _)) = span(identifier)
        {
            let initializer = unwrap_transparent_expression(initializer);
            let origin = parse_context_capability_operation(initializer)
                .filter(|operation| operation.kind == "auth.getUserIdentity")
                .map(|operation| OpaqueBindingOrigin::Operation {
                    start: operation.start,
                    end: operation.end,
                })
                .or_else(|| {
                    let operation = parse_db_operation(initializer, source)?;
                    matches!(
                        (operation.kind.as_str(), operation.terminal.as_deref()),
                        ("db.get", _) | ("db.query", Some("first" | "unique"))
                    )
                    .then_some(OpaqueBindingOrigin::Operation {
                        start: operation.start,
                        end: operation.end,
                    })
                })
                .or_else(|| {
                    (node_type(initializer).ok() == Some("CallExpression")
                        && callee_identifier(initializer).is_some())
                    .then(|| {
                        let (start, end) = span(initializer).ok()?;
                        Some(OpaqueBindingOrigin::Call { start, end })
                    })
                    .flatten()
                })
                .or_else(|| {
                    (node_type(initializer).ok() == Some("Identifier"))
                        .then(|| {
                            let (start, end) = span(initializer).ok()?;
                            Some(OpaqueBindingOrigin::Reference { start, end })
                        })
                        .flatten()
                });
            if let Some(origin) = origin {
                output.push(OpaqueBindingCandidate {
                    name,
                    binding_start,
                    origin,
                    references: Vec::new(),
                });
            }
        }
        for child in object.values() {
            collect_opaque_binding_candidates(child, source, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_opaque_binding_candidates(child, source, output);
        }
    }
}

fn collect_opaque_return_references(value: &Value, output: &mut Vec<SourceRange>) {
    if let Value::Object(object) = value {
        let returned = match object.get("type").and_then(Value::as_str) {
            Some("ReturnStatement") => object.get("argument"),
            Some("ArrowFunctionExpression") => object
                .get("body")
                .filter(|body| node_type(body).ok() != Some("BlockStatement")),
            _ => None,
        };
        if let Some(argument) = returned.map(unwrap_transparent_expression)
            && matches!(
                node_type(argument).ok(),
                Some("Identifier" | "CallExpression")
            )
            && let Ok((start, end)) = span(argument)
        {
            output.push(SourceRange { start, end });
        }
        for child in object.values() {
            collect_opaque_return_references(child, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_opaque_return_references(child, output);
        }
    }
}

fn resolved_binding_references(
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    name: &str,
    binding_start: u32,
) -> Result<Vec<(u32, u32)>> {
    let matching_symbols = scoping
        .symbol_ids()
        .filter(|symbol_id| {
            scoping.symbol_span(*symbol_id).start == binding_start
                && scoping.symbol_name(*symbol_id) == name
        })
        .collect::<Vec<_>>();
    ensure!(
        matching_symbols.len() == 1,
        "document binding {name} at {binding_start} resolved to {} symbols",
        matching_symbols.len()
    );
    Ok(scoping
        .get_resolved_references(matching_symbols[0])
        .filter_map(|reference| {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                return None;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            Some((reference_span.start, reference_span.end))
        })
        .collect())
}

fn insert_bound_references(
    target: &mut BTreeMap<(u32, u32), String>,
    references: Vec<(u32, u32)>,
    table: &str,
) -> Result<()> {
    for reference in references {
        ensure!(
            target.insert(reference, table.to_string()).is_none(),
            "document reference at {}..{} resolved to multiple database bindings",
            reference.0,
            reference.1
        );
    }
    Ok(())
}

fn collect_collection_callback_properties(
    value: &Value,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    collection_references: &BTreeMap<(u32, u32), String>,
    proved_local_filters: &[LocalFilteredArrayCandidate],
    direct_async_batches: &[DirectAsyncBatchCandidate],
    output: &mut Vec<DocumentPropertyCandidate>,
) -> Result<()> {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("CallExpression")
            && let Some(method) = call_method_name(value)
            && matches!(method.as_str(), "filter" | "map")
            && let Some(receiver) = object
                .get("callee")
                .and_then(|callee| callee.get("object"))
                .map(unwrap_transparent_expression)
            && identifier_name(receiver).is_ok()
            && let Ok((receiver_start, receiver_end)) = span(receiver)
            && let Some(table) = collection_references.get(&(receiver_start, receiver_end))
            && let Some(callback) = object
                .get("arguments")
                .and_then(Value::as_array)
                .and_then(|arguments| arguments.first())
                .map(unwrap_transparent_expression)
            && matches!(
                node_type(callback).ok(),
                Some("ArrowFunctionExpression" | "FunctionExpression")
            )
            && let Some(parameter) = callback
                .get("params")
                .and_then(Value::as_array)
                .and_then(|parameters| parameters.first())
            && let Ok(parameter_name) = identifier_name(parameter)
            && let Ok((parameter_start, _)) = span(parameter)
            && let Some(body) = callback.get("body")
            && let Ok((callback_start, callback_end)) = span(callback)
            && ((method == "filter"
                && proved_local_filters.iter().any(|filtered| {
                    filtered.source_reference_start == receiver_start
                        && filtered.source_reference_end == receiver_end
                        && filtered.callback_start == callback_start
                        && filtered.callback_end == callback_end
                }))
                || (method == "map"
                    && direct_async_batches.iter().any(|batch| {
                        batch.shape_error.is_none()
                            && batch.iterator_binding_start == Some(receiver_start)
                            && batch.iterator_binding_end == Some(receiver_end)
                            && batch.callback_start == Some(callback_start)
                            && batch.callback_end == Some(callback_end)
                    }))
                || table.starts_with("__dependencyAdapterCall:"))
        {
            let callback_binding =
                resolved_binding_references(scoping, nodes, &parameter_name, parameter_start)?
                    .into_iter()
                    .map(|reference| (reference, table.clone()))
                    .collect();
            collect_bound_properties(body, &callback_binding, None, output);
        }
        for child in object.values() {
            collect_collection_callback_properties(
                child,
                scoping,
                nodes,
                collection_references,
                proved_local_filters,
                direct_async_batches,
                output,
            )?;
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_collection_callback_properties(
                child,
                scoping,
                nodes,
                collection_references,
                proved_local_filters,
                direct_async_batches,
                output,
            )?;
        }
    }
    Ok(())
}

fn collect_bound_properties(
    value: &Value,
    bindings: &BTreeMap<(u32, u32), String>,
    parent: Option<&Map<String, Value>>,
    output: &mut Vec<DocumentPropertyCandidate>,
) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("MemberExpression")
            && !object
                .get("computed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            && let (Some(receiver), Some(property)) = (object.get("object"), object.get("property"))
            && let receiver = unwrap_runtime_expression(receiver)
            && identifier_name(receiver).is_ok()
            && let Ok(property) = identifier_name(property)
            && let Ok(receiver_span) = span(receiver)
            && let Some(table) = bindings.get(&receiver_span)
            && let Ok((start, end)) = span(value)
        {
            let value_type = if parent.is_some_and(|parent| {
                parent.get("type").and_then(Value::as_str) == Some("UnaryExpression")
                    && parent.get("operator").and_then(Value::as_str) == Some("!")
            }) {
                "boolean"
            } else {
                "opaque"
            };
            output.push(DocumentPropertyCandidate {
                table: table.clone(),
                property,
                value_type: value_type.to_string(),
                start,
                end,
            });
        }
        for child in object.values() {
            collect_bound_properties(child, bindings, Some(object), output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_bound_properties(child, bindings, parent, output);
        }
    }
}

type OperationIdentity = (String, u32, u32);
fn admit_raw_context_reuse_facts(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<()> {
    let mut shortest_chains = BTreeMap::<String, Vec<String>>::new();
    for unit in reachable.values() {
        shortest_chains
            .entry(unit.module.clone())
            .and_modify(|chain| {
                if unit.dependency_chain.len() < chain.len()
                    || (unit.dependency_chain.len() == chain.len()
                        && unit.dependency_chain.as_slice() < chain.as_slice())
                {
                    *chain = unit.dependency_chain.clone();
                }
            })
            .or_insert_with(|| unit.dependency_chain.clone());
    }

    let mut emitted = BTreeSet::new();
    for (module_key, dependency_chain) in shortest_chains {
        let module = modules
            .get(&module_key)
            .context("reachable context-reuse module disappeared")?;
        let source = module_source(modules, &module_key)?;
        for fact in module.summary.context_reuse.raw_hard_facts() {
            if !emitted.insert((
                module_key.clone(),
                fact.start,
                fact.end,
                fact.rule.to_string(),
                fact.category.to_string(),
                fact.message.to_string(),
            )) {
                continue;
            }
            let (line, column) = line_column(&source, fact.start);
            diagnostics.push(Diagnostic {
                code: fact.rule.to_string(),
                message: fact.message.to_string(),
                file: module_key.clone(),
                line,
                column,
                construct: Some(fact.category.to_string()),
                source: source_slice(&source, fact.start, fact.end)?.to_string(),
                dependency_chain: dependency_chain.clone(),
            });
        }
    }
    Ok(())
}

fn sorted_facts_starting_in_range<'a, T>(
    facts: &'a [T],
    start: u32,
    end: u32,
    fact_start: impl Fn(&T) -> u32,
) -> &'a [T] {
    let first = facts.partition_point(|fact| fact_start(fact) < start);
    let past_end = facts.partition_point(|fact| fact_start(fact) <= end);
    &facts[first..past_end]
}

fn admitted_operations(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    dependency_adapter_calls: &[AppliedDependencyAdapterCall],
    admitted_operation_identities: &BTreeSet<OperationIdentity>,
) -> Result<(Vec<AdmittedOperation>, Vec<Intrinsic>)> {
    let mut output = Vec::new();
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("reachable module was not loaded")?;
        let source = module_source(modules, &unit.module)?;
        let mut ordinal = 0usize;
        for operation in module
            .summary
            .operations
            .iter()
            .filter(|operation| operation.start >= unit.start && operation.end <= unit.end)
        {
            if matches!(
                operation.kind.as_str(),
                "scheduler.runAfter" | "scheduler.runAt"
            ) && operation.function_reference.is_none()
            {
                continue;
            }
            if operation.kind == "intrinsic.sha256"
                && !is_canonical_sha256_intrinsic(unit, operation)
            {
                continue;
            }
            if operation.kind != "intrinsic.sha256"
                && !admitted_operation_identities.contains(&(
                    unit.module.clone(),
                    operation.start,
                    operation.end,
                ))
            {
                continue;
            }
            ordinal += 1;
            let semantic_key = serde_json::to_string(&(
                &unit.id,
                ordinal,
                &operation.kind,
                &operation.table,
                &operation.index,
                operation
                    .index_constraints
                    .iter()
                    .map(|constraint| (&constraint.field, &constraint.operator))
                    .collect::<Vec<_>>(),
                &operation.order,
                &operation.terminal,
                operation.limit,
                operation.limit_argument_index,
                &operation.algorithm,
                &operation.function_reference,
            ))?;
            let stable_key = format!("op_{}", &hash_bytes(semantic_key.as_bytes())[..16]);
            let (line, column) = line_column(&source, operation.start);
            let intrinsic_function_name = if operation.kind == "intrinsic.sha256" {
                Some(unit.name.clone())
            } else {
                None
            };
            output.push(OwnedAdmittedOperation {
                operation: AdmittedOperation {
                    id: 0,
                    stable_key,
                    kind: match operation.kind.as_str() {
                        "auth.getUserIdentity" => "authenticationGetUserIdentity",
                        "db.normalizeId" => "databaseNormalizeId",
                        "db.query" => "databaseIndexQuery",
                        "db.get" => "databaseGet",
                        "db.insert" => "databaseInsert",
                        "db.patch" => "databasePatch",
                        "db.replace" => "databaseReplace",
                        "db.delete" => "databaseDelete",
                        "scheduler.runAfter" => "schedulerRunAfter",
                        "scheduler.runAt" => "schedulerRunAt",
                        "intrinsic.sha256" => "sha256",
                        other => other,
                    }
                    .to_string(),
                    table: operation.table.clone(),
                    index: operation.index.clone(),
                    index_constraints: operation
                        .index_constraints
                        .iter()
                        .map(|constraint| AdmittedIndexConstraint {
                            field: constraint.field.clone(),
                            operator: constraint.operator.clone(),
                            value_source: constraint.value_source.clone(),
                        })
                        .collect(),
                    order: operation.order.clone(),
                    terminal: operation.terminal.clone(),
                    limit: operation.limit,
                    limit_argument_index: operation.limit_argument_index,
                    algorithm: operation.algorithm.clone(),
                    function_reference: operation.function_reference.clone(),
                    contract_version: None,
                    selector: None,
                    file: unit.module.clone(),
                    start: operation.start,
                    end: operation.end,
                    line,
                    column,
                    source: source_slice(&source, operation.start, operation.end)?.to_string(),
                },
                intrinsic_function_name,
            });
        }
    }
    for call in dependency_adapter_calls {
        if !admitted_operation_identities.contains(&(
            call.importer_module.clone(),
            call.operation.start,
            call.operation.end,
        )) {
            continue;
        }
        let operation = &call.operation;
        let source = module_source(modules, &call.importer_module)?;
        let semantic_key = serde_json::to_string(&(
            &call.importer_unit_id,
            &call.descriptor.id,
            &call.descriptor.semantic.kind,
            &operation.kind,
            &operation.table,
            &operation.index,
            operation
                .index_constraints
                .iter()
                .map(|constraint| (&constraint.field, &constraint.operator))
                .collect::<Vec<_>>(),
            &operation.order,
            &operation.terminal,
            operation.limit,
            operation.limit_argument_index,
        ))?;
        let stable_key = format!("op_{}", &hash_bytes(semantic_key.as_bytes())[..16]);
        let (line, column) = line_column(&source, operation.start);
        output.push(OwnedAdmittedOperation {
            operation: AdmittedOperation {
                id: 0,
                stable_key,
                kind: match operation.kind.as_str() {
                    "db.query" => "databaseIndexQuery",
                    "db.get" => "databaseGet",
                    other => other,
                }
                .to_string(),
                table: operation.table.clone(),
                index: operation.index.clone(),
                index_constraints: operation
                    .index_constraints
                    .iter()
                    .map(|constraint| AdmittedIndexConstraint {
                        field: constraint.field.clone(),
                        operator: constraint.operator.clone(),
                        value_source: constraint.value_source.clone(),
                    })
                    .collect(),
                order: operation.order.clone(),
                terminal: operation.terminal.clone(),
                limit: operation.limit,
                limit_argument_index: operation.limit_argument_index,
                algorithm: None,
                function_reference: None,
                contract_version: None,
                selector: None,
                file: call.importer_module.clone(),
                start: operation.start,
                end: operation.end,
                line,
                column,
                source: source_slice(&source, operation.start, operation.end)?.to_string(),
            },
            intrinsic_function_name: None,
        });
    }
    output.sort_by(|left, right| {
        (
            &left.operation.file,
            left.operation.line,
            left.operation.column,
        )
            .cmp(&(
                &right.operation.file,
                right.operation.line,
                right.operation.column,
            ))
    });
    ensure!(
        output.len() <= u16::MAX as usize,
        "opaque ABI operation count exceeds {}",
        u16::MAX
    );
    let mut intrinsic_function_names = BTreeSet::new();
    let mut intrinsics = Vec::new();
    for (index, owned) in output.iter_mut().enumerate() {
        let operation_id = u32::try_from(index + 1)?;
        owned.operation.id = operation_id;
        if let Some(function_name) = &owned.intrinsic_function_name {
            ensure!(
                intrinsic_function_names.insert(function_name.clone()),
                "intrinsic function {function_name} contains more than one intrinsic operation"
            );
            intrinsics.push(Intrinsic {
                function_name: function_name.clone(),
                kind: owned.operation.kind.clone(),
                operation_id,
            });
        }
    }
    Ok((
        output.into_iter().map(|owned| owned.operation).collect(),
        intrinsics,
    ))
}

fn append_source_operations(
    modules: &BTreeMap<String, LoadedModule>,
    applied: &mut [AppliedSourceOperation],
    operations: &mut Vec<AdmittedOperation>,
) -> Result<()> {
    let mut operation_ids = BTreeMap::new();
    let mut descriptors = applied
        .iter()
        .map(|operation| operation.descriptor.clone())
        .collect::<Vec<_>>();
    descriptors.sort_by(|left, right| left.id.cmp(&right.id));
    descriptors.dedup_by(|left, right| left.id == right.id);
    for descriptor in descriptors {
        let call = applied
            .iter()
            .find(|operation| operation.descriptor.id == descriptor.id)
            .context("applied source operation call disappeared")?;
        let source = module_source(modules, &call.importer_module)?;
        let id = u32::try_from(operations.len() + 1)?;
        let (line, column) = line_column(&source, call.call_start);
        let stable_material = serde_json::to_vec(&(
            &descriptor.id,
            &descriptor.helper.module_path,
            &descriptor.helper.export_name,
            &call.helper_unit_source_sha256,
            &descriptor.semantic.kind,
            1u32,
            &descriptor.semantic.selector,
        ))?;
        operations.push(AdmittedOperation {
            id,
            stable_key: format!("op_{}", &hash_bytes(&stable_material)[..16]),
            kind: "hostSecretVerify".to_string(),
            table: None,
            index: None,
            index_constraints: Vec::new(),
            order: None,
            terminal: None,
            limit: None,
            limit_argument_index: None,
            algorithm: None,
            function_reference: None,
            contract_version: Some(1),
            selector: Some(descriptor.semantic.selector.clone()),
            file: call.importer_module.clone(),
            start: call.call_start,
            end: call.call_end,
            line,
            column,
            source: source_slice(&source, call.call_start, call.call_end)?.to_string(),
        });
        operation_ids.insert(descriptor.id, id);
    }
    for operation in applied {
        operation.operation_id = *operation_ids
            .get(&operation.descriptor.id)
            .context("source operation manifest ID was not assigned")?;
    }
    Ok(())
}

fn admitted_document_properties(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    operations: &[AdmittedOperation],
    legacy_interprocedural_effects: &[LegacyInterproceduralEffectSpecialization],
    callable_effect_plans: &callable_plans::CallableEffectPlanIndex,
    dependency_adapter_calls: &DependencyAdapterCallIndex<'_>,
) -> Result<Vec<DocumentProperty>> {
    let mut properties = BTreeSet::new();
    let mut identity_tables = BTreeSet::new();
    for operation in operations {
        if operation.kind == "databaseIndexQuery"
            && let Some(table) = &operation.table
        {
            identity_tables.insert(table.clone());
            properties.insert(DocumentProperty {
                table: table.clone(),
                property: "_id".to_string(),
                value_type: "string".to_string(),
                reason: "opaque-document-identity".to_string(),
            });
        }
    }
    let mut opaque_references = BTreeMap::<(String, u32, u32), String>::new();
    let admitted_operations = operations
        .iter()
        .map(|operation| {
            (
                (operation.file.clone(), operation.start, operation.end),
                operation,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut interprocedural_document_tables = BTreeMap::new();
    for specialization in legacy_interprocedural_effects
        .iter()
        .filter(|specialization| specialization.operation.kind == "db.get")
    {
        let Some(table) = &specialization.operation.table else {
            continue;
        };
        let key = (
            specialization.caller_module.clone(),
            specialization.call_start,
            specialization.call_end,
        );
        match interprocedural_document_tables.get_mut(&key) {
            Some(existing) if *existing != *table => *existing = "opaqueValue".to_string(),
            Some(_) => {}
            None => {
                interprocedural_document_tables.insert(key, table.clone());
            }
        }
    }
    for plan in callable_effect_plans.plans().filter(|plan| {
        plan.effect_key.operation_kind == "databaseGet" && plan.provenance.caller_callsite.is_some()
    }) {
        let Some(table) = plan.effect_key.static_operands.get("table") else {
            continue;
        };
        let target = &plan.provenance.target_effect;
        if !operations.iter().any(|operation| {
            operation.file == target.module
                && operation.start == target.start
                && operation.end == target.end
                && operation.kind == "databaseGet"
                && operation.table.as_ref() == Some(table)
        }) {
            continue;
        }
        let callsite = plan
            .provenance
            .caller_callsite
            .as_ref()
            .expect("filtered callable effect plan lost its callsite");
        let key = (callsite.module.clone(), callsite.start, callsite.end);
        match interprocedural_document_tables.get_mut(&key) {
            Some(existing) if *existing != *table => *existing = "opaqueValue".to_string(),
            Some(_) => {}
            None => {
                interprocedural_document_tables.insert(key, table.clone());
            }
        }
    }
    let insert_reference = |references: &mut BTreeMap<(String, u32, u32), String>,
                            module: &str,
                            reference: &ReferenceOccurrence,
                            table: &str| {
        let key = (module.to_string(), reference.start, reference.end);
        match references.get_mut(&key) {
            Some(existing) if existing != table => *existing = "opaqueValue".to_string(),
            Some(_) => {}
            None => {
                references.insert(key, table.to_string());
            }
        }
    };
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("reachable opaque-value module disappeared")?;
        for binding in sorted_facts_starting_in_range(
            &module.summary.opaque_bindings,
            unit.start,
            unit.end,
            |binding| binding.binding_start,
        ) {
            let table = match binding.origin {
                OpaqueBindingOrigin::Operation { start, end } => {
                    let Some(operation) =
                        admitted_operations.get(&(unit.module.clone(), start, end))
                    else {
                        continue;
                    };
                    match operation.kind.as_str() {
                        "authenticationGetUserIdentity" => "authenticationIdentity",
                        "databaseGet" | "databaseIndexQuery" => operation
                            .table
                            .as_deref()
                            .context("admitted database document operation has no table")?,
                        _ => continue,
                    }
                }
                OpaqueBindingOrigin::Call { start, end } => {
                    if let Some(table) =
                        interprocedural_document_tables.get(&(unit.module.clone(), start, end))
                    {
                        table
                    } else {
                        let Some(call) = dependency_adapter_calls
                            .call_at(&unit.module, start, end)
                            .filter(|call| {
                                matches!(
                                    call.descriptor.semantic.kind.as_str(),
                                    "databaseIndexUnique" | "databaseIndexUniqueOrThrow"
                                )
                            })
                        else {
                            continue;
                        };
                        call.operation.table.as_deref().context(
                            "admitted dependency adapter document operation has no table",
                        )?
                    }
                }
                OpaqueBindingOrigin::Reference { .. } => continue,
            };
            for reference in &binding.references {
                insert_reference(&mut opaque_references, &unit.module, reference, table);
            }
        }
    }

    let mut opaque_function_returns = BTreeMap::<(String, String), String>::new();
    let mut static_targets = StaticSourceTargetCache::new();
    loop {
        let previous_references = opaque_references.clone();
        let previous_returns = opaque_function_returns.clone();
        for unit in reachable.values() {
            let module = modules
                .get(&unit.module)
                .context("reachable opaque-value propagation module disappeared")?;
            for returned in sorted_facts_starting_in_range(
                &module.summary.opaque_return_references,
                unit.start,
                unit.end,
                |returned| returned.start,
            )
            .iter()
            .filter(|returned| returned.end <= unit.end)
            {
                let Some(table) = opaque_references
                    .get(&(unit.module.clone(), returned.start, returned.end))
                    .cloned()
                else {
                    continue;
                };
                let key = (unit.module.clone(), unit.name.clone());
                match opaque_function_returns.get_mut(&key) {
                    Some(existing) if *existing != table => *existing = "opaqueValue".to_string(),
                    Some(_) => {}
                    None => {
                        opaque_function_returns.insert(key, table);
                    }
                }
            }

            for binding in sorted_facts_starting_in_range(
                &module.summary.opaque_bindings,
                unit.start,
                unit.end,
                |binding| binding.binding_start,
            ) {
                let table = match binding.origin {
                    OpaqueBindingOrigin::Reference { start, end } => opaque_references
                        .get(&(unit.module.clone(), start, end))
                        .cloned(),
                    OpaqueBindingOrigin::Call { start, end } => {
                        let Some(call) = module
                            .summary
                            .calls
                            .iter()
                            .find(|call| call.start == start && call.end == end)
                        else {
                            continue;
                        };
                        let target = cached_static_source_target(
                            graph,
                            modules,
                            &mut static_targets,
                            &unit.module,
                            &call.callee,
                        )?;
                        target.and_then(|target| opaque_function_returns.get(&target).cloned())
                    }
                    OpaqueBindingOrigin::Operation { .. } => None,
                };
                let Some(table) = table else {
                    continue;
                };
                for reference in &binding.references {
                    insert_reference(&mut opaque_references, &unit.module, reference, &table);
                }
            }

            for call in sorted_facts_starting_in_range(
                &module.summary.calls,
                unit.start,
                unit.end,
                |call| call.start,
            )
            .iter()
            .filter(|call| call.end <= unit.end)
            {
                let Some((target_module, target_name)) = cached_static_source_target(
                    graph,
                    modules,
                    &mut static_targets,
                    &unit.module,
                    &call.callee,
                )?
                else {
                    continue;
                };
                let Some(target_unit) = modules
                    .get(&target_module)
                    .and_then(|module| module.summary.units.get(&target_name))
                else {
                    continue;
                };
                if let Some(table) = opaque_function_returns
                    .get(&(target_module.clone(), target_name.clone()))
                    .cloned()
                {
                    let key = (unit.module.clone(), call.start, call.end);
                    match opaque_references.get_mut(&key) {
                        Some(existing) if *existing != table => {
                            *existing = "opaqueValue".to_string()
                        }
                        Some(_) => {}
                        None => {
                            opaque_references.insert(key, table);
                        }
                    }
                }
                for (argument_index, argument) in call.arguments.iter().enumerate() {
                    let Some(table) = opaque_references
                        .get(&(unit.module.clone(), argument.start, argument.end))
                        .cloned()
                    else {
                        continue;
                    };
                    let Some(parameter) = target_unit
                        .parameters
                        .iter()
                        .find(|parameter| parameter.index == argument_index)
                    else {
                        continue;
                    };
                    for reference in &parameter.references {
                        insert_reference(&mut opaque_references, &target_module, reference, &table);
                    }
                }
            }
        }
        if opaque_references == previous_references && opaque_function_returns == previous_returns {
            break;
        }
    }
    for unit in reachable.values() {
        let Some(module) = modules.get(&unit.module) else {
            continue;
        };
        for property in module
            .summary
            .document_properties
            .iter()
            .filter(|property| property.start >= unit.start && property.end <= unit.end)
        {
            let table = if let Some(spans) = property.table.strip_prefix("__dependencyAdapterCall:")
            {
                let Some((start, end)) = spans.split_once(':').and_then(|(start, end)| {
                    Some((start.parse::<u32>().ok()?, end.parse::<u32>().ok()?))
                }) else {
                    continue;
                };
                let Some(call) = dependency_adapter_calls
                    .call_at(&unit.module, start, end)
                    .filter(|call| {
                        matches!(
                            call.descriptor.semantic.kind.as_str(),
                            "databaseGetBatch" | "databaseGetBatchOrThrow" | "databaseIndexCollect"
                        )
                    })
                else {
                    continue;
                };
                call.operation
                    .table
                    .clone()
                    .context("admitted dependency adapter collection has no table")?
            } else {
                property.table.clone()
            };
            if property.property == "_id" && identity_tables.contains(&table) {
                continue;
            }
            properties.insert(DocumentProperty {
                table,
                property: property.property.clone(),
                value_type: property.value_type.clone(),
                reason: "property-read".to_string(),
            });
        }
        for access in sorted_facts_starting_in_range(
            &module.summary.static_member_accesses,
            unit.start,
            unit.end,
            |access| access.start,
        )
        .iter()
        .filter(|access| access.end <= unit.end)
        {
            let Some(table) =
                opaque_references.get(&(unit.module.clone(), access.root_start, access.root_end))
            else {
                continue;
            };
            properties.insert(DocumentProperty {
                table: table.clone(),
                property: access.first_field.clone(),
                value_type: "opaque".to_string(),
                reason: "opaque-property-read".to_string(),
            });
        }
    }
    // Exact document evidence subsumes the generic opaque-value path for the same property.
    let exact_property_keys = properties
        .iter()
        .filter(|property| property.reason != "opaque-property-read")
        .map(|property| (property.table.clone(), property.property.clone()))
        .collect::<BTreeSet<_>>();
    properties.retain(|property| {
        property.reason != "opaque-property-read"
            || !exact_property_keys.contains(&(property.table.clone(), property.property.clone()))
    });
    Ok(properties.into_iter().collect())
}

fn collect_synchronous_for_of_spans(value: &Value, output: &mut Vec<(u32, u32)>) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("ForOfStatement")
                && object.get("await").and_then(Value::as_bool) != Some(true)
            {
                output.push(span(value)?);
            }
            for child in object.values() {
                collect_synchronous_for_of_spans(child, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_synchronous_for_of_spans(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn generated_source_binding_collision_diagnostics(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    imported_binding_aliases: &[ImportedBindingAlias],
    rejection: &GeneratedSourceBindingCollision,
) -> Result<Vec<Diagnostic>> {
    let collision_names = rejection.names.iter().cloned().collect::<BTreeSet<_>>();
    let mut mapped_names = BTreeSet::new();
    let mut reported = BTreeSet::new();
    let mut diagnostics = Vec::new();
    for alias in imported_binding_aliases
        .iter()
        .filter(|alias| collision_names.contains(&alias.local_binding))
    {
        if reported.insert((
            alias.local_binding.clone(),
            alias.importer_module.clone(),
            alias.import_start,
        )) {
            mapped_names.insert(alias.local_binding.clone());
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "unsupported-generated-helper-binding",
                rejection.to_string(),
                &alias.importer_module,
                alias.import_start,
                Some("ImportDeclaration".to_string()),
                alias.dependency_chain.clone(),
            )?);
        }
    }

    let reachable_modules = reachable
        .values()
        .map(|unit| unit.module.as_str())
        .collect::<BTreeSet<_>>();
    for module_key in reachable_modules {
        let module = modules
            .get(module_key)
            .context("reachable generated-helper collision module disappeared")?;
        let source_type = SourceType::from_path(Path::new(module_key))
            .with_context(|| format!("unsupported source type {module_key}"))?;
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, &module.source, source_type).parse();
        ensure!(
            parsed.diagnostics.is_empty(),
            "generated-helper collision source {module_key} has {} parser diagnostics",
            parsed.diagnostics.len()
        );
        let semantic = SemanticBuilder::new_compiler().build(&parsed.program);
        ensure!(
            semantic.diagnostics.is_empty(),
            "generated-helper collision source {module_key} has {} semantic diagnostics",
            semantic.diagnostics.len()
        );
        let scoping = semantic.semantic.scoping();
        for symbol_id in scoping.symbol_ids().filter(|symbol_id| {
            scoping.symbol_flags(*symbol_id).is_value()
                && collision_names.contains(scoping.symbol_name(*symbol_id))
        }) {
            let binding = scoping.symbol_span(symbol_id);
            let matching_units = reachable
                .values()
                .filter(|unit| {
                    unit.module == module_key
                        && binding.start >= unit.start
                        && binding.end <= unit.end
                })
                .collect::<Vec<_>>();
            let [unit] = matching_units.as_slice() else {
                continue;
            };
            let name = scoping.symbol_name(symbol_id).to_string();
            if !reported.insert((name.clone(), module_key.to_string(), binding.start)) {
                continue;
            }
            mapped_names.insert(name);
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "unsupported-generated-helper-binding",
                rejection.to_string(),
                module_key,
                binding.start,
                Some("Identifier".to_string()),
                unit.dependency_chain.clone(),
            )?);
        }
    }
    ensure!(
        mapped_names == collision_names,
        "generated JavaScript binding collision did not map to exact source bindings"
    );
    Ok(diagnostics)
}

fn generated_for_of_ineligibility_diagnostic(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    generated_source: &str,
    rejection: &GeneratedForOfIneligibility,
) -> Result<Diagnostic> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, generated_source, SourceType::mjs()).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "generated for...of diagnostic source has {} parser diagnostics",
        parsed.diagnostics.len()
    );
    let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false))
        .context("Oxc emitted invalid generated for...of diagnostic ESTree JSON")?;
    let generated_functions = generated_top_level_function_spans(&ast)?;
    let matching_functions = generated_functions
        .iter()
        .filter(|(_, (start, end))| *start <= rejection.start && rejection.start < *end)
        .collect::<Vec<_>>();
    let [(generated_binding, generated_function_span)] = matching_functions.as_slice() else {
        bail!(
            "rejected generated for...of at {} did not bind to one top-level function",
            rejection.start
        );
    };
    let matching_units = reachable
        .values()
        .filter(|unit| {
            if generated_binding.as_str() == "__convexWasmHandler" {
                unit.kind == "handler"
            } else {
                unit.kind != "handler" && unit.name == generated_binding.as_str()
            }
        })
        .collect::<Vec<_>>();
    let [unit] = matching_units.as_slice() else {
        bail!(
            "rejected generated for...of binding {} did not resolve to one reachable unit",
            generated_binding
        );
    };
    let mut generated_loops = Vec::new();
    collect_synchronous_for_of_spans(&ast, &mut generated_loops)?;
    generated_loops.retain(|(start, end)| {
        *start >= generated_function_span.0 && *end <= generated_function_span.1
    });
    generated_loops.sort_unstable();
    let ordinal = generated_loops
        .iter()
        .position(|(start, _)| *start == rejection.start)
        .context("rejected generated for...of span disappeared from its top-level function")?;
    let module = modules
        .get(&unit.module)
        .context("rejected generated for...of reachable module disappeared")?;
    let mut source_loops = module
        .summary
        .constructs
        .iter()
        .filter(|construct| {
            construct.kind == "ForOfStatement"
                && construct.start >= unit.start
                && construct.end <= unit.end
        })
        .collect::<Vec<_>>();
    source_loops.sort_by_key(|construct| (construct.start, construct.end));
    let construct = source_loops.get(ordinal).with_context(|| {
        format!(
            "rejected generated for...of ordinal {ordinal} has no authoritative source construct"
        )
    })?;
    diagnostic_at(
        graph,
        modules,
        "unsupported-array-for-of-lowering",
        rejection.reason.to_string(),
        &unit.module,
        construct.start,
        Some("ForOfStatement".to_string()),
        unit.dependency_chain.clone(),
    )
}

fn generated_array_filter_ineligibility_diagnostic(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    generated_source: &str,
    rejection: &GeneratedArrayFilterIneligibility,
) -> Result<Diagnostic> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, generated_source, SourceType::mjs()).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "generated array-filter diagnostic source has {} parser diagnostics",
        parsed.diagnostics.len()
    );
    let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false))
        .context("Oxc emitted invalid generated array-filter diagnostic ESTree JSON")?;
    let generated_functions = generated_top_level_function_spans(&ast)?;
    let matching_functions = generated_functions
        .iter()
        .filter(|(_, (start, end))| *start <= rejection.start && rejection.start < *end)
        .collect::<Vec<_>>();
    let [(generated_binding, generated_function_span)] = matching_functions.as_slice() else {
        bail!(
            "rejected generated array filter at {} did not bind to one top-level function",
            rejection.start
        );
    };
    let matching_units = reachable
        .values()
        .filter(|unit| {
            if generated_binding.as_str() == "__convexWasmHandler" {
                unit.kind == "handler"
            } else {
                unit.kind != "handler" && unit.name == generated_binding.as_str()
            }
        })
        .collect::<Vec<_>>();
    let [unit] = matching_units.as_slice() else {
        bail!(
            "rejected generated array-filter binding {} did not resolve to one reachable unit",
            generated_binding
        );
    };
    let mut generated_calls = Vec::new();
    collect_static_member_calls(&ast, &mut generated_calls);
    generated_calls.retain(|call| {
        call.first_field == "filter"
            && call.start >= generated_function_span.0
            && call.end <= generated_function_span.1
    });
    generated_calls.sort_by_key(|call| (call.start, call.end));
    let ordinal = generated_calls
        .iter()
        .position(|call| call.start == rejection.start)
        .context("rejected generated array-filter span disappeared from its top-level function")?;
    let module = modules
        .get(&unit.module)
        .context("rejected generated array-filter reachable module disappeared")?;
    let mut source_calls = module
        .summary
        .static_member_calls
        .iter()
        .filter(|call| {
            call.first_field == "filter" && call.start >= unit.start && call.end <= unit.end
        })
        .collect::<Vec<_>>();
    source_calls.sort_by_key(|call| (call.start, call.end));
    let call = source_calls.get(ordinal).with_context(|| {
        format!(
            "rejected generated array-filter ordinal {ordinal} has no authoritative source call"
        )
    })?;
    diagnostic_at(
        graph,
        modules,
        "unsupported-array-filter-lowering",
        rejection.reason.to_string(),
        &unit.module,
        call.start,
        Some("filter".to_string()),
        unit.dependency_chain.clone(),
    )
}

fn diagnose_flattened_runtime_binding_collisions(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    imported_binding_aliases: &[ImportedBindingAlias],
    dependency_adapter_calls: &[AppliedDependencyAdapterCall],
    source_operations: &[AppliedSourceOperation],
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<()> {
    let mut bindings = BTreeMap::from([(
        "__convexWasmHandler".to_string(),
        "generated handler".to_string(),
    )]);
    for call in dependency_adapter_calls {
        bindings
            .entry(call.generated_function_name.clone())
            .or_insert_with(|| format!("dependency adapter {}", call.descriptor.id));
    }
    for operation in source_operations {
        bindings
            .entry(format!(
                "__convexSourceOperation_{}",
                operation.descriptor.id
            ))
            .or_insert_with(|| format!("source operation {}", operation.descriptor.id));
    }
    for alias in imported_binding_aliases {
        if let Some(owner) = bindings.get(&alias.local_binding) {
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "flattened-runtime-binding-collision",
                format!(
                    "imported local binding {} conflicts with {owner}",
                    alias.local_binding
                ),
                &alias.importer_module,
                alias.import_start,
                Some("ImportDeclaration".to_string()),
                alias.dependency_chain.clone(),
            )?);
        } else {
            bindings.insert(
                alias.local_binding.clone(),
                format!("import alias to {}", alias.target_unit_id),
            );
        }
    }
    for unit in reachable.values().filter(|unit| unit.kind != "handler") {
        if let Some(owner) = bindings.get(&unit.name) {
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "flattened-runtime-binding-collision",
                format!(
                    "reachable runtime binding {} conflicts with {owner}",
                    unit.name
                ),
                &unit.module,
                unit.start,
                Some(unit.kind.clone()),
                unit.dependency_chain.clone(),
            )?);
        } else {
            bindings.insert(unit.name.clone(), unit.id.clone());
        }
    }
    Ok(())
}

fn diagnose_flattened_runtime_global_collisions(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    imported_binding_aliases: &[ImportedBindingAlias],
    dependency_adapter_calls: &[AppliedDependencyAdapterCall],
    source_operations: &[AppliedSourceOperation],
    registration_adapter: Option<&AppliedRegistrationAdapter>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<()> {
    let mut bindings = BTreeMap::from([(
        "__convexWasmHandler".to_string(),
        ("generated handler".to_string(), None),
    )]);
    for call in dependency_adapter_calls {
        bindings
            .entry(call.generated_function_name.clone())
            .or_insert_with(|| (format!("dependency adapter {}", call.descriptor.id), None));
    }
    for operation in source_operations {
        bindings
            .entry(format!(
                "__convexSourceOperation_{}",
                operation.descriptor.id
            ))
            .or_insert_with(|| {
                (
                    format!("source operation {}", operation.descriptor.id),
                    None,
                )
            });
    }
    if registration_adapter.is_some() {
        for name in [
            "__convexAdapterContext",
            "__convexAdapterArguments",
            "__convexAdapterAuthentication",
        ] {
            bindings.insert(
                name.to_string(),
                ("generated registration adapter binding".to_string(), None),
            );
        }
    }
    for alias in imported_binding_aliases {
        bindings
            .entry(alias.local_binding.clone())
            .or_insert_with(|| {
                (
                    format!("import alias to {}", alias.target_unit_id),
                    Some(alias.importer_module.clone()),
                )
            });
    }
    for unit in reachable.values().filter(|unit| unit.kind != "handler") {
        bindings
            .entry(unit.name.clone())
            .or_insert_with(|| (unit.id.clone(), Some(unit.module.clone())));
    }

    let mut reported = BTreeSet::new();
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("reachable module was not loaded")?;
        for global in sorted_facts_starting_in_range(
            &module.summary.globals,
            unit.start,
            unit.end,
            |global| global.start,
        )
        .into_iter()
        .filter(|global| global.end <= unit.end)
        {
            let Some((owner, owner_module)) = bindings.get(&global.name) else {
                continue;
            };
            if owner_module.as_deref() == Some(unit.module.as_str())
                || !reported.insert((global.name.clone(), owner.clone(), unit.id.clone()))
            {
                continue;
            }
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "flattened-runtime-binding-collision",
                format!(
                    "admitted runtime global {} in {} conflicts with {owner} after module flattening",
                    global.name, unit.module
                ),
                &unit.module,
                global.start,
                Some("Identifier".to_string()),
                unit.dependency_chain.clone(),
            )?);
        }
    }
    Ok(())
}

fn append_imported_binding_aliases(
    module: &str,
    aliases: &[ImportedBindingAlias],
    reachable: &BTreeMap<String, ReachableUnit>,
    bindings: &mut BTreeSet<String>,
    output: &mut String,
) -> Result<usize> {
    let mut emitted = 0usize;
    for alias in aliases
        .iter()
        .filter(|alias| alias.importer_module == module)
    {
        let target = reachable
            .get(&alias.target_unit_id)
            .context("imported alias target disappeared before source emission")?;
        ensure!(
            target.kind != "handler" && target.name == alias.target_binding,
            "imported alias target binding changed before source emission"
        );
        ensure!(
            bindings.insert(alias.local_binding.clone()),
            "flattened imported alias binding collision for {}",
            alias.local_binding
        );
        output.push_str(&format!(
            "const {} = {};\n",
            alias.local_binding, alias.target_binding
        ));
        emitted += 1;
    }
    if emitted > 0 {
        output.push('\n');
    }
    Ok(emitted)
}

struct GeneratedJavascript {
    source: String,
    authority: GeneratedJavascriptAuthority,
}

fn generated_javascript_authority(
    static_function_references: &[StaticFunctionReferenceAuthorization],
    dependency_adapter_calls: &[AppliedDependencyAdapterCall],
    source_operations: &[AppliedSourceOperation],
    direct_effect_sites: &[AuthorizedDirectEffectSite],
    registration_adapter: Option<&AppliedRegistrationAdapter>,
) -> Result<GeneratedJavascriptAuthority> {
    let mut authority = GeneratedJavascriptAuthority::default();
    authority
        .compiler_top_level_bindings
        .insert("__convexWasmHandler".to_string());
    for call in dependency_adapter_calls {
        authority
            .compiler_top_level_bindings
            .insert(call.generated_function_name.clone());
        match call.descriptor.semantic.kind.as_str() {
            "databaseIndexCollect" | "databaseIndexUnique" => {}
            "databaseIndexUniqueOrThrow" => {
                authority
                    .compiler_top_level_globals
                    .extend(["Error".to_string(), "String".to_string()]);
            }
            "databaseGetBatch" => {
                authority
                    .compiler_top_level_globals
                    .insert("__convexDependencyDatabaseGetBatch".to_string());
            }
            "databaseGetBatchOrThrow" => {
                authority.compiler_top_level_globals.extend([
                    "__convexDependencyIterableValues".to_string(),
                    "__convexDependencyDatabaseGetBatchFromValues".to_string(),
                    "Error".to_string(),
                    "String".to_string(),
                ]);
            }
            "functionHandleCreate" => {
                authority
                    .compiler_top_level_globals
                    .insert("__convexCreateFunctionHandle".to_string());
            }
            semantic => bail!("unsupported dependency adapter semantic {semantic}"),
        }
    }
    if !source_operations.is_empty() {
        authority
            .compiler_top_level_globals
            .extend(["__convexVerifyHostSecret".to_string(), "Error".to_string()]);
    }
    for operation in source_operations {
        authority.compiler_top_level_bindings.insert(format!(
            "__convexSourceOperation_{}",
            operation.descriptor.id
        ));
    }
    if !direct_effect_sites.is_empty() {
        authority
            .compiler_top_level_globals
            .insert("__convexStartAsyncOperation".to_string());
    }
    for site in direct_effect_sites {
        authority
            .compiler_top_level_bindings
            .insert(direct_effect_site_helper_name(site));
        let kind = site
            .variants
            .first()
            .context("authorized direct effect site has no exact variants")?
            .effect_key
            .operation_kind
            .as_str();
        if matches!(kind, "schedulerRunAfter" | "schedulerRunAt") {
            authority
                .compiler_top_level_globals
                .insert("__convexInternalFunctionReference".to_string());
        }
        if kind != "databaseIndexQuery" {
            authority
                .compiler_top_level_globals
                .insert("Error".to_string());
        }
    }
    if !static_function_references.is_empty() {
        authority
            .compiler_application_globals
            .insert("__convexFunctionReference".to_string());
    }
    if let Some(adapter) = registration_adapter {
        authority.compiler_scoped_binding_references.extend([
            ("__convexAdapterContext".to_string(), 2),
            ("__convexAdapterArguments".to_string(), 1),
            (
                "__convexAdapterAuthentication".to_string(),
                adapter.descriptor.authentication.result_parameters.len(),
            ),
        ]);
    }
    Ok(authority)
}

fn generate_javascript(
    reachable: &BTreeMap<String, ReachableUnit>,
    handler_source: &str,
    entry_path: &str,
    imported_binding_aliases: &[ImportedBindingAlias],
    static_function_references: &[StaticFunctionReferenceAuthorization],
    dependency_adapter_calls: &[AppliedDependencyAdapterCall],
    source_operations: &[AppliedSourceOperation],
    registration_adapter: Option<&AppliedRegistrationAdapter>,
    direct_effect_sites: &[AuthorizedDirectEffectSite],
) -> Result<GeneratedJavascript> {
    let mut bindings = dependency_adapter_calls
        .iter()
        .map(|call| call.generated_function_name.clone())
        .collect::<BTreeSet<_>>();
    let mut consumed_function_references = BTreeSet::new();
    let mut consumed_dependency_calls = BTreeSet::new();
    let mut consumed_source_operations = BTreeSet::new();
    let mut consumed_direct_effect_sites = BTreeSet::new();
    let mut emitted_alias_modules = BTreeSet::new();
    let mut emitted_aliases = 0usize;
    let mut combined = String::new();
    combined.push_str(&dependency_adapter_helper_source(dependency_adapter_calls)?);
    combined.push_str(&source_operation_helper_source(source_operations)?);
    combined.push_str(&direct_effect_site_helper_source(
        direct_effect_sites,
        &mut bindings,
    )?);
    for unit in reachable_unit_emission_order(reachable)? {
        if emitted_alias_modules.insert(unit.module.clone()) {
            emitted_aliases += append_imported_binding_aliases(
                &unit.module,
                imported_binding_aliases,
                reachable,
                &mut bindings,
                &mut combined,
            )?;
        }
        ensure!(
            bindings.insert(unit.name.clone()),
            "flattened runtime binding collision for {}",
            unit.name
        );
        combined.push_str(&lower_unit_compile_time_adapters(
            &unit.source,
            unit,
            static_function_references,
            &mut consumed_function_references,
            dependency_adapter_calls,
            &mut consumed_dependency_calls,
            source_operations,
            &mut consumed_source_operations,
            direct_effect_sites,
            &mut consumed_direct_effect_sites,
        )?);
        combined.push_str("\n\n");
    }
    let handler = reachable
        .values()
        .find(|unit| unit.kind == "handler")
        .context("reachable graph has no handler unit")?;
    if emitted_alias_modules.insert(handler.module.clone()) {
        emitted_aliases += append_imported_binding_aliases(
            &handler.module,
            imported_binding_aliases,
            reachable,
            &mut bindings,
            &mut combined,
        )?;
    }
    let callback_source = lower_unit_compile_time_adapters(
        handler_source,
        handler,
        static_function_references,
        &mut consumed_function_references,
        dependency_adapter_calls,
        &mut consumed_dependency_calls,
        source_operations,
        &mut consumed_source_operations,
        direct_effect_sites,
        &mut consumed_direct_effect_sites,
    )?;
    combined.push_str("const __convexWasmHandler = ");
    if let Some(adapter) = registration_adapter {
        combined.push_str(&registration_adapter_handler_source(
            &callback_source,
            adapter,
        )?);
    } else {
        combined.push_str(&callback_source);
    }
    combined.push_str(";\n");
    ensure!(
        emitted_aliases == imported_binding_aliases.len(),
        "generated source emitted {emitted_aliases} of {} imported binding aliases",
        imported_binding_aliases.len()
    );
    ensure!(
        consumed_function_references.len() == static_function_references.len(),
        "generated source consumed {} of {} authenticated static function references",
        consumed_function_references.len(),
        static_function_references.len()
    );
    ensure!(
        consumed_dependency_calls.len() == dependency_adapter_calls.len(),
        "generated source consumed {} of {} authenticated dependency adapter calls",
        consumed_dependency_calls.len(),
        dependency_adapter_calls.len()
    );
    ensure!(
        consumed_source_operations.len() == source_operations.len(),
        "generated source consumed {} of {} authenticated source operations",
        consumed_source_operations.len(),
        source_operations.len()
    );
    ensure!(
        consumed_direct_effect_sites.len() == direct_effect_sites.len(),
        "generated source consumed {} of {} authorized direct effect sites",
        consumed_direct_effect_sites.len(),
        direct_effect_sites.len()
    );
    Ok(GeneratedJavascript {
        source: transform_typescript(&combined, Path::new(entry_path))?,
        authority: generated_javascript_authority(
            static_function_references,
            dependency_adapter_calls,
            source_operations,
            direct_effect_sites,
            registration_adapter,
        )?,
    })
}

fn source_operation_helper_source(operations: &[AppliedSourceOperation]) -> Result<String> {
    let mut descriptors = BTreeMap::new();
    for operation in operations {
        if let Some(existing) = descriptors.insert(
            operation.descriptor.id.clone(),
            (&operation.descriptor, operation.operation_id),
        ) {
            ensure!(
                existing == (&operation.descriptor, operation.operation_id),
                "authenticated source operation ID has conflicting descriptors"
            );
        }
    }
    let mut source = String::new();
    for (id, (descriptor, operation_id)) in descriptors {
        source.push_str(&format!(
            "function __convexSourceOperation_{id}(providedValue) {{\n  const result = __convexVerifyHostSecret({operation_id}, providedValue);\n  if (result < 0) throw new Error({});\n  if (result !== 1) throw new Error({});\n}}\n",
            serde_json::to_string(&descriptor.semantic.missing_configuration_error)?,
            serde_json::to_string(&descriptor.semantic.mismatch_error)?,
        ));
    }
    Ok(source)
}

#[derive(Clone)]
struct ReachableModuleDependency {
    unit_id: String,
    reference_start: u32,
}

type ReachableModuleDependencies = BTreeMap<String, BTreeMap<String, ReachableModuleDependency>>;

fn reachable_module_dependencies(
    reachable: &BTreeMap<String, ReachableUnit>,
) -> Result<ReachableModuleDependencies> {
    let mut module_dependencies = ReachableModuleDependencies::new();
    for unit in reachable.values() {
        for (dependency_id, reference_start) in &unit.dependencies {
            let dependency = reachable.get(dependency_id).with_context(|| {
                format!("reachable dependency {dependency_id} was not retained")
            })?;
            if dependency.kind == "handler" || dependency.module == unit.module {
                continue;
            }
            let candidate = ReachableModuleDependency {
                unit_id: unit.id.clone(),
                reference_start: *reference_start,
            };
            let existing = module_dependencies
                .entry(unit.module.clone())
                .or_default()
                .entry(dependency.module.clone())
                .or_insert_with(|| candidate.clone());
            if (candidate.reference_start, &candidate.unit_id)
                < (existing.reference_start, &existing.unit_id)
            {
                *existing = candidate;
            }
        }
    }
    Ok(module_dependencies)
}

fn reachable_module_cycle_edge(
    module_dependencies: &ReachableModuleDependencies,
) -> Option<(&str, &str)> {
    fn visit<'a>(
        module: &'a str,
        module_dependencies: &'a ReachableModuleDependencies,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Option<(&'a str, &'a str)> {
        if visited.contains(module) {
            return None;
        }
        visiting.insert(module);
        for dependency in module_dependencies
            .get(module)
            .into_iter()
            .flat_map(BTreeMap::keys)
            .map(String::as_str)
        {
            if visiting.contains(dependency) {
                return Some((module, dependency));
            }
            if let Some(edge) = visit(dependency, module_dependencies, visiting, visited) {
                return Some(edge);
            }
        }
        visiting.remove(module);
        visited.insert(module);
        None
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for module in module_dependencies.keys().map(String::as_str) {
        if let Some(edge) = visit(module, module_dependencies, &mut visiting, &mut visited) {
            return Some(edge);
        }
    }
    None
}

fn reachable_unit_emission_order(
    reachable: &BTreeMap<String, ReachableUnit>,
) -> Result<Vec<&ReachableUnit>> {
    fn visit_module<'a>(
        module: &str,
        units_by_module: &BTreeMap<String, Vec<&'a ReachableUnit>>,
        module_dependencies: &ReachableModuleDependencies,
        visiting: &mut BTreeSet<String>,
        emitted: &mut BTreeSet<String>,
        output: &mut Vec<&'a ReachableUnit>,
    ) -> Result<()> {
        if emitted.contains(module) {
            return Ok(());
        }
        let units = units_by_module
            .get(module)
            .with_context(|| format!("reachable module {module} disappeared before emission"))?;
        if !visiting.insert(module.to_string()) {
            return Ok(());
        }
        for dependency in module_dependencies
            .get(module)
            .into_iter()
            .flat_map(BTreeMap::keys)
        {
            visit_module(
                dependency,
                units_by_module,
                module_dependencies,
                visiting,
                emitted,
                output,
            )?;
        }
        visiting.remove(module);
        if emitted.insert(module.to_string()) {
            output.extend(units.iter().copied());
        }
        Ok(())
    }

    let mut units_by_module = BTreeMap::<String, Vec<&ReachableUnit>>::new();
    for unit in reachable.values().filter(|unit| unit.kind != "handler") {
        units_by_module
            .entry(unit.module.clone())
            .or_default()
            .push(unit);
    }
    for units in units_by_module.values_mut() {
        units.sort_by_key(|unit| (unit.start, unit.end, unit.id.as_str()));
    }
    let module_dependencies = reachable_module_dependencies(reachable)?;
    ensure!(
        reachable_module_cycle_edge(&module_dependencies).is_none(),
        "reachable module initialization cycle reached source emission"
    );
    let mut visiting = BTreeSet::new();
    let mut emitted = BTreeSet::new();
    let mut output = Vec::with_capacity(
        reachable
            .values()
            .filter(|unit| unit.kind != "handler")
            .count(),
    );
    for module in units_by_module.keys() {
        visit_module(
            module,
            &units_by_module,
            &module_dependencies,
            &mut visiting,
            &mut emitted,
            &mut output,
        )?;
    }
    ensure!(
        output.len()
            == reachable
                .values()
                .filter(|unit| unit.kind != "handler")
                .count(),
        "reachable-unit emission omitted a retained non-handler unit"
    );
    Ok(output)
}

fn dependency_adapter_unique_or_throw_rejection(
    result: &str,
    table: &str,
    field: &str,
    value: &str,
) -> String {
    format!(
        "if ({result} === null) throw new Error(\"Can't find a document in \" + {table} + \" with field \" + {field} + \" equal to \" + String({value}));"
    )
}

fn dependency_adapter_helper_source(calls: &[AppliedDependencyAdapterCall]) -> Result<String> {
    let mut semantics = BTreeMap::new();
    for call in calls {
        if let Some(existing) = semantics.insert(
            call.generated_function_name.clone(),
            call.descriptor.semantic.kind.clone(),
        ) {
            ensure!(
                existing == call.descriptor.semantic.kind,
                "dependency adapter generated binding has conflicting semantics"
            );
        }
    }
    let mut output = String::new();
    for (name, semantic) in semantics {
        let source = match semantic.as_str() {
            "databaseIndexCollect" => format!(
                "function {name}(db, table, index, value, field) {{\n  const selectedField = field ? field : (index.startsWith(\"by_\") ? index.slice(3) : index);\n  return db.query(table).withIndex(index, (q) => q.eq(selectedField, value)).collect();\n}}\n"
            ),
            "databaseIndexUnique" => format!(
                "function {name}(db, table, index, value, field) {{\n  const selectedField = field ? field : (index.startsWith(\"by_\") ? index.slice(3) : index);\n  return db.query(table).withIndex(index, (q) => q.eq(selectedField, value)).unique();\n}}\n"
            ),
            "databaseIndexUniqueOrThrow" => {
                let rejection = dependency_adapter_unique_or_throw_rejection(
                    "result",
                    "table",
                    "selectedField",
                    "value",
                );
                format!(
                    "function {name}(db, table, index, value, field) {{\n  const selectedField = field ? field : (index.startsWith(\"by_\") ? index.slice(3) : index);\n  const result = db.query(table).withIndex(index, (q) => q.eq(selectedField, value)).unique();\n  {rejection}\n  return result;\n}}\n"
                )
            }
            "databaseGetBatch" => format!(
                "function {name}(db, table, ids) {{\n  return __convexDependencyDatabaseGetBatch(table, ids);\n}}\n"
            ),
            "databaseGetBatchOrThrow" => format!(
                "function {name}(db, table, ids) {{\n  const values = __convexDependencyIterableValues(ids);\n  const results = __convexDependencyDatabaseGetBatchFromValues(table, values);\n  for (let index = 0; index < results.length; index += 1) {{\n    if (results[index] === null) throw new Error(\"Could not find id \" + String(values[index]));\n  }}\n  return results;\n}}\n"
            ),
            "functionHandleCreate" => format!(
                "function {name}(functionReference) {{\n  return __convexCreateFunctionHandle(functionReference);\n}}\n"
            ),
            _ => bail!("unsupported dependency adapter semantic {semantic}"),
        };
        output.push_str(&source);
    }
    Ok(output)
}

fn registration_adapter_handler_source(
    callback_source: &str,
    adapter: &AppliedRegistrationAdapter,
) -> Result<String> {
    let mut parameters = adapter
        .descriptor
        .authentication
        .result_parameters
        .iter()
        .collect::<Vec<_>>();
    parameters.sort_by_key(|parameter| parameter.callback_parameter_index);
    for (offset, parameter) in parameters.iter().enumerate() {
        ensure!(
            parameter.callback_parameter_index == offset + 2,
            "registration adapter {} callback parameter indexes must be contiguous from 2",
            adapter.descriptor.id
        );
    }
    let authentication_arguments = parameters
        .iter()
        .map(|parameter| match &parameter.property {
            Some(property) => format!("__convexAdapterAuthentication.{property}"),
            None => "__convexAdapterAuthentication".to_string(),
        })
        .collect::<Vec<_>>();
    let mut callback_arguments = vec![
        "__convexAdapterContext".to_string(),
        "__convexAdapterArguments".to_string(),
    ];
    callback_arguments.extend(authentication_arguments);
    Ok(format!(
        "async (__convexAdapterContext, __convexAdapterArguments) => {{\n  const __convexAdapterAuthentication = await {}(__convexAdapterContext);\n  return await ({callback_source})({});\n}}",
        adapter.helper_unit_name,
        callback_arguments.join(", ")
    ))
}

fn registration_adapter_provenance(
    adapter: &AppliedRegistrationAdapter,
) -> AppliedRegistrationAdapterProvenance {
    AppliedRegistrationAdapterProvenance {
        adapter_id: adapter.descriptor.id.clone(),
        registration_kind: adapter.descriptor.registration_kind.clone(),
        wrapper: RegistrationAdapterUnitProvenance {
            module_path: adapter.wrapper_module.clone(),
            export_name: adapter.descriptor.wrapper.export_name.clone(),
            unit_source_sha256: adapter.wrapper_unit_source_sha256.clone(),
        },
        authentication: RegistrationAdapterAuthenticationProvenance {
            helper: RegistrationAdapterUnitProvenance {
                module_path: adapter.helper_module.clone(),
                export_name: adapter.descriptor.authentication.helper.export_name.clone(),
                unit_source_sha256: adapter.helper_unit_source_sha256.clone(),
            },
            result_kind: adapter.descriptor.authentication.result_kind.clone(),
            result_parameters: adapter.descriptor.authentication.result_parameters.clone(),
        },
    }
}

fn dependency_adapter_provenance(
    calls: &[AppliedDependencyAdapterCall],
) -> Result<Vec<AppliedDependencyAdapterProvenance>> {
    let mut descriptors = BTreeMap::new();
    for call in calls {
        if let Some(existing) = descriptors.insert(call.descriptor.id.clone(), &call.descriptor) {
            ensure!(
                existing == &call.descriptor,
                "applied dependency adapter ID has conflicting descriptors"
            );
        }
    }
    Ok(descriptors
        .into_values()
        .map(|descriptor| AppliedDependencyAdapterProvenance {
            adapter_id: descriptor.id.clone(),
            semantic_kind: descriptor.semantic.kind.clone(),
            resolved_export: DependencyAdapterAppliedExport {
                module_path: descriptor.export_identity.module_path.clone(),
                export_name: descriptor.export_identity.export_name.clone(),
                unit_source_sha256: descriptor.export_identity.unit_source_sha256.clone(),
            },
            substitution: descriptor.substitution.as_ref().map(|substitution| {
                DependencyAdapterAppliedSubstitution {
                    module_specifier: substitution.module_specifier.clone(),
                    export_name: substitution.export_name.clone(),
                    unit_source_sha256: substitution.unit_source_sha256.clone(),
                }
            }),
            material: descriptor.material.clone(),
        })
        .collect())
}

fn lower_unit_compile_time_adapters(
    source: &str,
    unit: &ReachableUnit,
    authorizations: &[StaticFunctionReferenceAuthorization],
    consumed: &mut BTreeSet<(String, u32, u32)>,
    dependency_adapter_calls: &[AppliedDependencyAdapterCall],
    consumed_dependency_calls: &mut BTreeSet<(String, u32, u32)>,
    source_operations: &[AppliedSourceOperation],
    consumed_source_operations: &mut BTreeSet<(String, u32, u32)>,
    direct_effect_sites: &[AuthorizedDirectEffectSite],
    consumed_direct_effect_sites: &mut BTreeSet<String>,
) -> Result<String> {
    let mut edits = Vec::new();
    for authorization in authorizations
        .iter()
        .filter(|authorization| authorization.unit_id == unit.id)
    {
        ensure!(
            authorization.module == unit.module
                && authorization.start >= unit.start
                && authorization.end <= unit.end,
            "authenticated static function reference escaped its source unit"
        );
        let start = authorization.start - unit.start;
        let end = authorization.end - unit.start;
        edits.push(source_edit(
            start,
            end,
            format!(
                "__convexFunctionReference({})",
                serde_json::to_string(&authorization.function_reference)?
            ),
            (start, end),
        ));
        ensure!(
            consumed.insert((
                authorization.module.clone(),
                authorization.start,
                authorization.end,
            )),
            "authenticated static function reference was consumed more than once"
        );
    }
    for call in dependency_adapter_calls
        .iter()
        .filter(|call| call.importer_unit_id == unit.id)
    {
        ensure!(
            call.importer_module == unit.module
                && call.callee_start >= unit.start
                && call.callee_end <= unit.end
                && call.call_start >= unit.start
                && call.call_end <= unit.end,
            "authenticated dependency adapter call escaped its source unit"
        );
        let start = call.callee_start - unit.start;
        let end = call.callee_end - unit.start;
        edits.push(source_edit(
            start,
            end,
            call.generated_function_name.clone(),
            (start, end),
        ));
        ensure!(
            consumed_dependency_calls.insert((
                call.importer_module.clone(),
                call.call_start,
                call.call_end,
            )),
            "authenticated dependency adapter call was consumed more than once"
        );
    }
    for operation in source_operations
        .iter()
        .filter(|operation| operation.importer_unit_id == unit.id)
    {
        ensure!(
            operation.importer_module == unit.module
                && operation.call_start >= unit.start
                && operation.call_end <= unit.end
                && operation.callee_end >= unit.start,
            "authenticated source operation escaped its source unit"
        );
        let start = operation.call_start - unit.start;
        let end = operation.call_end - unit.start;
        let callee_end = operation.callee_end - unit.start;
        ensure!(
            source.as_bytes().get(callee_end as usize) == Some(&b'(')
                && source.as_bytes().get(end.saturating_sub(1) as usize) == Some(&b')'),
            "authenticated source operation call lost its exact direct-call delimiters"
        );
        let argument = source_slice(source, callee_end + 1, end - 1)?;
        edits.push(source_edit(
            start,
            end,
            format!(
                "__convexSourceOperation_{}({argument})",
                operation.descriptor.id
            ),
            (start, end),
        ));
        ensure!(
            consumed_source_operations.insert((
                operation.importer_module.clone(),
                operation.call_start,
                operation.call_end,
            )),
            "authenticated source operation was consumed more than once"
        );
    }
    append_direct_effect_site_edits(
        source,
        unit,
        direct_effect_sites,
        consumed_direct_effect_sites,
        &mut edits,
    )?;
    apply_source_edits(source, 0, u32::try_from(source.len())?, &edits)
}

fn publish_generated_source(cache_dir: &Path, sha256: &str, source: &[u8]) -> Result<String> {
    ensure!(
        sha256.len() == 64
            && sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "generated source digest is invalid"
    );
    let relative_path = format!("generated-sources/{}/{}.js", &sha256[..2], sha256);
    fs::create_dir_all(cache_dir)?;
    let generated_root = cache_dir.join("generated-sources");
    prepare_private_generated_source_directory(&generated_root)?;
    let parent = generated_root.join(&sha256[..2]);
    prepare_private_generated_source_directory(&parent)?;
    let final_path = cache_dir.join(&relative_path);
    let validate_existing = || -> Result<()> {
        let metadata = fs::symlink_metadata(&final_path)?;
        ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "generated source cache entry is not a regular file: {}",
            final_path.display()
        );
        ensure!(
            metadata.permissions().mode() & 0o777 == 0o600,
            "generated source cache entry has non-private permissions: {}",
            final_path.display()
        );
        ensure!(
            metadata.uid() == current_uid(),
            "generated source cache entry is not owned by the current user: {}",
            final_path.display()
        );
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&final_path)?;
        let opened = file.metadata()?;
        ensure!(
            opened.is_file()
                && opened.dev() == metadata.dev()
                && opened.ino() == metadata.ino()
                && opened.uid() == metadata.uid()
                && opened.mode() & 0o777 == metadata.mode() & 0o777,
            "generated source cache entry changed before it was read: {}",
            final_path.display()
        );
        let mut bytes = Vec::with_capacity(source.len());
        Read::by_ref(&mut file)
            .take(u64::try_from(source.len())? + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() == source.len() && hash_bytes(&bytes) == sha256,
            "generated source cache entry is corrupt: {}",
            final_path.display()
        );
        Ok(())
    };
    match fs::symlink_metadata(&final_path) {
        Ok(_) => {
            validate_existing()?;
            return Ok(relative_path);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary_sequence = GENERATED_SOURCE_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_path = parent.join(format!(
        ".{sha256}.{}.{temporary_sequence}.tmp",
        std::process::id()
    ));
    let mut temporary = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary_path)?;
    let publication = (|| -> Result<()> {
        temporary.write_all(source)?;
        temporary.sync_all()?;
        drop(temporary);
        match fs::hard_link(&temporary_path, &final_path) {
            Ok(()) => {
                fs::File::open(&parent)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_existing()?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    })();
    let _ = fs::remove_file(&temporary_path);
    publication?;
    validate_existing()?;
    Ok(relative_path)
}

fn prepare_private_generated_source_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == current_uid(),
        "generated source cache path is not an owned directory: {}",
        path.display()
    );
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let opened = directory.metadata()?;
    ensure!(
        opened.is_dir()
            && opened.dev() == metadata.dev()
            && opened.ino() == metadata.ino()
            && opened.uid() == metadata.uid(),
        "generated source cache directory changed while it was opened: {}",
        path.display()
    );
    directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    ensure!(
        directory.metadata()?.mode() & 0o777 == 0o700,
        "generated source cache directory is not private: {}",
        path.display()
    );
    Ok(())
}

fn transform_typescript(source: &str, source_path: &Path) -> Result<String> {
    let allocator = Allocator::default();
    let source_type = SourceType::ts().with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "generated source has {} parser diagnostics",
        parsed.diagnostics.len()
    );
    let mut program = parsed.program;
    let semantic = SemanticBuilder::new().with_enum_eval(true).build(&program);
    ensure!(
        semantic.diagnostics.is_empty(),
        "generated source has {} semantic diagnostics",
        semantic.diagnostics.len()
    );
    let mut transform_options = TransformOptions::default();
    transform_options.env.es2020.optional_chaining = true;
    let transformed = Transformer::new(&allocator, source_path, &transform_options)
        .build_with_scoping(semantic.semantic.into_scoping(), &mut program);
    ensure!(
        transformed.diagnostics.is_empty(),
        "generated source has {} transform diagnostics",
        transformed.diagnostics.len()
    );
    Ok(codegen(&program))
}

fn codegen(program: &Program<'_>) -> String {
    Codegen::new()
        .with_options(CodegenOptions::default())
        .build(program)
        .code
}

pub(crate) fn checked_module_path(repo_root: &Path, module_key: &str) -> Result<PathBuf> {
    ensure!(
        !module_key.is_empty()
            && !Path::new(module_key).is_absolute()
            && !module_key.contains('\\')
            && module_key
                .split('/')
                .all(|part| !part.is_empty() && !matches!(part, "." | "..")),
        "module key must be a normalized repository-relative path"
    );
    let root = repo_root
        .canonicalize()
        .with_context(|| repo_root.display().to_string())?;
    let path = root.join(module_key);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("module does not exist: {}", path.display()))?;
    ensure!(
        canonical.starts_with(&root),
        "module escapes repository root: {module_key}"
    );
    Ok(canonical)
}

fn same_module_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

pub(crate) fn read_checked_module(
    repo_root: &Path,
    module_key: &str,
) -> Result<(PathBuf, Vec<u8>)> {
    let requested_path = repo_root.join(module_key);
    let root_before = repo_root
        .canonicalize()
        .with_context(|| repo_root.display().to_string())?;
    let path = checked_module_path(repo_root, module_key)?;
    let requested_before = requested_path
        .canonicalize()
        .with_context(|| format!("module does not exist: {}", requested_path.display()))?;
    ensure!(
        requested_before == path && path.starts_with(&root_before),
        "checked module path changed before it could be read: {}",
        requested_path.display()
    );
    let before_path = fs::metadata(&requested_path)
        .with_context(|| format!("failed to inspect checked module {}", path.display()))?;
    let mut file = fs::File::open(&path)
        .with_context(|| format!("failed to open checked module {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("failed to inspect open module {}", path.display()))?;
    ensure!(
        before.is_file() && same_module_file_state(&before_path, &before),
        "checked module changed before it could be read: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read checked module {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("failed to recheck open module {}", path.display()))?;
    let root_after = repo_root
        .canonicalize()
        .with_context(|| repo_root.display().to_string())?;
    let canonical_after = requested_path.canonicalize().with_context(|| {
        format!(
            "failed to resolve checked module {} after read",
            requested_path.display()
        )
    })?;
    let after_path = fs::metadata(&requested_path)
        .with_context(|| format!("failed to recheck module path {}", path.display()))?;
    ensure!(
        root_after == root_before
            && canonical_after == path
            && bytes.len() as u64 == before.len()
            && same_module_file_state(&before, &after)
            && same_module_file_state(&after, &after_path),
        "checked module changed while it was being read: {}",
        path.display()
    );
    Ok((path, bytes))
}

fn module_source<'a>(
    modules: &'a BTreeMap<String, LoadedModule>,
    module_key: &str,
) -> Result<&'a str> {
    modules
        .get(module_key)
        .map(|module| module.source.as_str())
        .with_context(|| format!("module source was not preloaded: {module_key}"))
}

#[expect(clippy::too_many_arguments)]
fn diagnostic_at(
    _graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    code: &str,
    message: String,
    module_key: &str,
    start: u32,
    construct: Option<String>,
    dependency_chain: Vec<String>,
) -> Result<Diagnostic> {
    let module = modules
        .get(module_key)
        .with_context(|| format!("module source was not preloaded: {module_key}"))?;
    let source = module.source.as_str();
    let (line, column) = module.line_column(start);
    let end = module.diagnostic_end(start);
    Ok(Diagnostic {
        code: code.to_string(),
        message,
        file: module_key.to_string(),
        line,
        column,
        construct,
        source: source_slice(&source, start, end.min(source.len() as u32))?.to_string(),
        dependency_chain,
    })
}

fn node_type(value: &Value) -> Result<&str> {
    value
        .get("type")
        .and_then(Value::as_str)
        .context("ESTree node has no type")
}

fn span(value: &Value) -> Result<(u32, u32)> {
    let start = value
        .get("start")
        .and_then(Value::as_u64)
        .context("ESTree node has no start")?;
    let end = value
        .get("end")
        .and_then(Value::as_u64)
        .context("ESTree node has no end")?;
    Ok((start as u32, end as u32))
}

fn identifier_name(value: &Value) -> Result<String> {
    ensure!(node_type(value)? == "Identifier", "expected Identifier");
    value
        .get("name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .context("Identifier has no name")
}

fn static_name(value: &Value) -> Result<String> {
    identifier_name(value).or_else(|_| literal_string(value))
}

fn literal_string(value: &Value) -> Result<String> {
    ensure!(node_type(value)? == "Literal", "expected Literal");
    value
        .get("value")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .context("Literal is not a string")
}

fn value_string(value: &Value) -> Option<String> {
    literal_string(unwrap_runtime_expression(value)).ok()
}

fn call_method_name(call: &Value) -> Option<String> {
    let call = unwrap_runtime_expression(call);
    let callee = call.get("callee").map(unwrap_runtime_expression)?;
    if node_type(callee).ok()? != "MemberExpression"
        || callee
            .get("computed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return None;
    }
    identifier_name(callee.get("property")?).ok()
}

fn callee_identifier(call: &Value) -> Option<String> {
    let call = unwrap_runtime_expression(call);
    if node_type(call).ok()? != "CallExpression" {
        return None;
    }
    identifier_name(call.get("callee").map(unwrap_runtime_expression)?).ok()
}

fn call_argument_string(call: &Value, index: usize) -> Option<String> {
    call.get("arguments")
        .and_then(Value::as_array)?
        .get(index)
        .and_then(value_string)
}

fn member_path(value: &Value) -> Option<String> {
    let value = unwrap_static_chain_expression(value);
    match node_type(value).ok()? {
        "Identifier" => identifier_name(value).ok(),
        "MemberExpression"
            if !value
                .get("computed")
                .and_then(Value::as_bool)
                .unwrap_or(false) =>
        {
            Some(format!(
                "{}.{}",
                member_path(value.get("object")?)?,
                identifier_name(value.get("property")?).ok()?
            ))
        }
        _ => None,
    }
}

fn unwrap_await(value: &Value) -> &Value {
    let value = unwrap_runtime_expression(value);
    if node_type(value).ok() == Some("AwaitExpression") {
        value
            .get("argument")
            .map(unwrap_runtime_expression)
            .unwrap_or(value)
    } else {
        value
    }
}

pub(crate) fn source_slice(source: &str, start: u32, end: u32) -> Result<&str> {
    source
        .get(start as usize..end as usize)
        .with_context(|| format!("invalid UTF-8 source span {start}..{end}"))
}

pub(crate) fn line_column(source: &str, start: u32) -> (usize, usize) {
    let prefix = source.get(..start as usize).unwrap_or(source);
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len() + 1, |(_, tail)| tail.len() + 1);
    (line, column)
}

#[derive(Default)]
struct ByteCounter {
    bytes: usize,
}

impl Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("serialized byte count overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialized_json_size<T: Serialize>(value: &T) -> Result<usize> {
    let mut counter = ByteCounter::default();
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.bytes)
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_compiler_json_bytes(value: &Value) -> Result<Vec<u8>> {
    fn write_value(value: &Value, output: &mut Vec<u8>) -> Result<()> {
        match value {
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write_value(value, output)?;
                }
                output.push(b']');
            }
            Value::Object(values) => {
                output.push(b'{');
                let mut keys = values.keys().collect::<Vec<_>>();
                // Operation descriptor keys are fixed ASCII schema fields, so byte ordering is
                // identical to the JavaScript contract's Array.prototype.sort ordering.
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    serde_json::to_writer(&mut *output, key)?;
                    output.push(b':');
                    write_value(&values[key], output)?;
                }
                output.push(b'}');
            }
            _ => serde_json::to_writer(output, value)?,
        }
        Ok(())
    }

    let mut output = Vec::new();
    write_value(value, &mut output)?;
    Ok(output)
}

#[cfg(target_os = "linux")]
fn process_memory_kib() -> Result<Option<(u64, u64)>> {
    let status =
        fs::read_to_string("/proc/self/status").context("failed to read process status")?;
    let field = |name: &str| -> Result<u64> {
        let line = status
            .lines()
            .find(|line| line.starts_with(name))
            .with_context(|| format!("process status has no {name} field"))?;
        let mut parts = line.split_whitespace();
        ensure!(
            parts.next() == Some(name),
            "invalid process status field {name}"
        );
        let value = parts
            .next()
            .with_context(|| format!("process status field {name} has no value"))?
            .parse::<u64>()
            .with_context(|| format!("process status field {name} is not an integer"))?;
        ensure!(
            parts.next() == Some("kB") && parts.next().is_none(),
            "process status field {name} has an unsupported unit"
        );
        Ok(value)
    };
    Ok(Some((field("VmRSS:")?, field("VmHWM:")?)))
}

#[cfg(not(target_os = "linux"))]
fn process_memory_kib() -> Result<Option<(u64, u64)>> {
    Ok(None)
}

pub(crate) fn elapsed_us(started: Instant) -> u64 {
    started.elapsed().as_micros().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
include!("tests.rs");
