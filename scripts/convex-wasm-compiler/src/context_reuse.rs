use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    rc::Rc,
    sync::OnceLock,
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    EsbuildImport, EsbuildMetafile, ImportBinding, LoadedModule, PhaseMeasurements,
    RegistrationAdapterMaterial, UnitSummary, elapsed_us, generated_server_udf_kind, hash_bytes,
    is_resolved_generated_server_module, line_column, load_module,
    prune_and_log_module_summary_cache, read_bounded_control_file, read_checked_module,
    validate_registration_adapter_material,
};

const INPUT_KIND: &str = "convex-context-reuse-graph";
const OUTPUT_KIND: &str = "convex-context-reuse-analysis";
const DIAGNOSTIC_ID_DOMAIN: &str = "context-reuse-diagnostic";
const SUPPRESSION_PREFIX: &str = "context-reuse-check-suppress";
const REVIEWED_THIRD_PARTY_POLICY_SOURCE: &str =
    include_str!("../../convex-context-reuse-reviewed-third-party-policy.json");
const POLICY_SOURCES: &[&str] = &[
    include_str!("context_reuse.rs"),
    REVIEWED_THIRD_PARTY_POLICY_SOURCE,
];

const REVIEWED_THIRD_PARTY_POLICY_KIND: &str = "convex-context-reuse-reviewed-third-party-policy";
const REVIEWED_THIRD_PARTY_POLICY_SCHEMA_VERSION: u32 = 1;
const ESBUILD_RUNTIME_PSEUDO_MODULE: &str = "<runtime>";

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewedThirdPartyPolicy {
    kind: String,
    schema_version: u32,
    surfaces: Vec<ReviewedThirdPartySurfaceConfig>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewedThirdPartySurfaceConfig {
    id: String,
    fingerprints: Vec<String>,
    admission: ReviewedThirdPartyAdmission,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
enum ReviewedThirdPartyAdmission {
    Accept {
        reason: String,
    },
    Reject {
        reason: String,
    },
    NamedImports {
        exports: Vec<String>,
        reason: String,
    },
    NamedDerivedMembers {
        imports: Vec<String>,
        members: Vec<String>,
        #[serde(rename = "forbiddenDerivedMembers")]
        forbidden_derived_members: Vec<String>,
        reason: String,
    },
    NamedImportUses {
        #[serde(rename = "instanceofTargets")]
        instanceof_targets: Vec<String>,
        #[serde(rename = "staticCalls")]
        static_calls: Vec<ReviewedThirdPartyStaticCall>,
        reason: String,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewedThirdPartyStaticCall {
    #[serde(rename = "import")]
    import_name: String,
    members: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContextModuleReference {
    specifier: String,
    kind: String,
    type_only: bool,
    start: u32,
    end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContextFact {
    rule: String,
    severity: String,
    category: String,
    message: String,
    start: u32,
    end: u32,
    anchor_start: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContextRegistration {
    pub(crate) export_name: String,
    pub(crate) local_name: String,
    pub(crate) registration_builder: String,
    pub(crate) udf_kind: Option<String>,
    pub(crate) call_start: u32,
    pub(crate) call_end: u32,
    pub(crate) callee_start: u32,
    pub(crate) callee_end: u32,
    pub(crate) start: u32,
    pub(crate) end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContextOpaqueExport {
    export_name: String,
    classification: String,
    start: u32,
    end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContextReexport {
    pub(crate) export_name: String,
    pub(crate) imported_name: String,
    pub(crate) specifier: String,
    pub(crate) start: u32,
    pub(crate) end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContextMarkerOccurrence {
    canonical: bool,
    message: String,
    start: u32,
    end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SuppressionDeclaration {
    line: usize,
    rule: Option<String>,
    reason: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContextModuleSummary {
    marker_occurrences: Vec<ContextMarkerOccurrence>,
    marker_reexports: Vec<ContextModuleReference>,
    references: Vec<ContextModuleReference>,
    facts: Vec<ContextFact>,
    suppressions: Vec<SuppressionDeclaration>,
    opaque_exports: Vec<ContextOpaqueExport>,
    pub(crate) registrations: Vec<ContextRegistration>,
    pub(crate) reexports: Vec<ContextReexport>,
}

pub(crate) struct RawHardContextFact<'a> {
    pub(crate) rule: &'a str,
    pub(crate) category: &'a str,
    pub(crate) message: &'a str,
    pub(crate) start: u32,
    pub(crate) end: u32,
}

impl ContextModuleSummary {
    pub(crate) fn raw_hard_facts(&self) -> impl Iterator<Item = RawHardContextFact<'_>> {
        self.facts
            .iter()
            .filter(|fact| fact.severity == "hard")
            .map(|fact| RawHardContextFact {
                rule: &fact.rule,
                category: &fact.category,
                message: &fact.message,
                start: fact.start,
                end: fact.end,
            })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContextInput {
    kind: String,
    repo_root: PathBuf,
    functions_root: String,
    roots: Vec<String>,
    // Standalone callers omit this; build callers supply every reviewed runtime input.
    source_texts: Option<BTreeMap<String, String>>,
    entry_candidates: Vec<String>,
    database_functions: Vec<GeneratedDatabaseFunction>,
    default_enabled: bool,
    default_database_entries: Vec<String>,
    exclusions: BTreeMap<String, String>,
    virtual_inputs: BTreeSet<String>,
    metafile: EsbuildMetafile,
    registration_adapter: RegistrationAdapterMaterial,
    external_dependencies: BTreeMap<String, ExternalDependency>,
    #[serde(default)]
    phase_timings_us: BTreeMap<String, u64>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GeneratedDatabaseFunction {
    entry_path: String,
    export_name: String,
    udf_kind: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalDependency {
    package_name: String,
    version: Option<String>,
}

#[derive(Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
struct DependencyEdge {
    from: String,
    to: String,
    specifier: String,
    span: SourceSpan,
}

#[derive(Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceSpan {
    start: u32,
    end: u32,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextDiagnostic {
    id: String,
    severity: String,
    rule: String,
    category: String,
    message: String,
    file: String,
    span: SourceSpan,
    entry: String,
    dependency_chain: Vec<DependencyEdge>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextDiagnosticDefinition {
    id: String,
    severity: String,
    rule: String,
    category: String,
    message: String,
    file: String,
    span: SourceSpan,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextDiagnosticGroup {
    entry: String,
    dependency_chain: Vec<DependencyEdge>,
    finding_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupedContextDiagnostics<Group = ContextDiagnosticGroup> {
    diagnostic_encoding: &'static str,
    diagnostic_definitions: Vec<ContextDiagnosticDefinition>,
    diagnostic_groups: Vec<Group>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionDiagnosticGroup {
    entry: String,
    finding_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ContextDiagnosticOutput {
    Expanded { diagnostics: Vec<ContextDiagnostic> },
    Grouped(GroupedContextDiagnostics),
    Admission(GroupedContextDiagnostics<AdmissionDiagnosticGroup>),
}

#[derive(Default)]
struct ContextDiagnosticDefinitions {
    definitions: BTreeMap<String, ContextDiagnosticDefinition>,
}

impl ContextDiagnosticDefinitions {
    fn insert(
        &mut self,
        diagnostic: ContextDiagnostic,
    ) -> Result<(String, String, Vec<DependencyEdge>)> {
        let ContextDiagnostic {
            id,
            severity,
            rule,
            category,
            message,
            file,
            span,
            entry,
            dependency_chain,
        } = diagnostic;
        let definition = ContextDiagnosticDefinition {
            id: id.clone(),
            severity,
            rule,
            category,
            message,
            file,
            span,
        };
        if let Some(existing) = self.definitions.get(&id) {
            ensure!(
                existing == &definition,
                "diagnostic ID {id} has inconsistent definition fields"
            );
        } else {
            self.definitions.insert(id.clone(), definition);
        }
        Ok((entry, id, dependency_chain))
    }
}

#[derive(Default)]
struct GroupedContextDiagnosticsBuilder {
    definitions: ContextDiagnosticDefinitions,
    groups: BTreeMap<(String, String, Vec<DependencyEdge>), BTreeSet<String>>,
    ids_by_entry: BTreeSet<(String, String)>,
}

impl GroupedContextDiagnosticsBuilder {
    fn insert(&mut self, diagnostic: ContextDiagnostic) -> Result<()> {
        let (entry, id, dependency_chain) = self.definitions.insert(diagnostic)?;
        ensure!(
            self.ids_by_entry.insert((entry.clone(), id.clone())),
            "diagnostic ID {id} occurs more than once for entry {entry}"
        );
        let terminal_file = dependency_chain
            .last()
            .map_or_else(|| entry.clone(), |edge| edge.to.clone());
        self.groups
            .entry((entry, terminal_file, dependency_chain))
            .or_default()
            .insert(id);
        Ok(())
    }

    fn finish(self) -> GroupedContextDiagnostics {
        GroupedContextDiagnostics {
            diagnostic_encoding: "grouped",
            diagnostic_definitions: self.definitions.definitions.into_values().collect(),
            diagnostic_groups: self
                .groups
                .into_iter()
                .map(
                    |((entry, _, dependency_chain), finding_ids)| ContextDiagnosticGroup {
                        entry,
                        dependency_chain,
                        finding_ids: finding_ids.into_iter().collect(),
                    },
                )
                .collect(),
        }
    }
}

#[derive(Default)]
struct AdmissionContextDiagnosticsBuilder {
    definitions: ContextDiagnosticDefinitions,
    groups: BTreeMap<String, BTreeSet<String>>,
}

impl AdmissionContextDiagnosticsBuilder {
    fn insert(&mut self, diagnostic: ContextDiagnostic) -> Result<()> {
        let (entry, id, _) = self.definitions.insert(diagnostic)?;
        // Keep exact occurrence identity even though admission does not consume trace paths.
        ensure!(
            self.groups
                .entry(entry.clone())
                .or_default()
                .insert(id.clone()),
            "diagnostic ID {id} occurs more than once for entry {entry}"
        );
        Ok(())
    }

    fn finish(self) -> GroupedContextDiagnostics<AdmissionDiagnosticGroup> {
        GroupedContextDiagnostics {
            diagnostic_encoding: "admission",
            diagnostic_definitions: self.definitions.definitions.into_values().collect(),
            diagnostic_groups: self
                .groups
                .into_iter()
                .map(|(entry, finding_ids)| AdmissionDiagnosticGroup {
                    entry,
                    finding_ids: finding_ids.into_iter().collect(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiagnosticEncoding {
    Expanded,
    Grouped,
    Admission,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextMetrics {
    wall_time_us: u64,
    esbuild_graph_us: u64,
    graph_read_us: u64,
    source_read_us: u64,
    cache_lookup_us: u64,
    parse_us: u64,
    semantic_us: u64,
    reachability_us: u64,
    modules_analyzed: usize,
    parsed_modules: usize,
    cache_hits: usize,
    cache_misses: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_cache_hits: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_cache_misses: Option<usize>,
    peak_rss_bytes: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextOutput {
    kind: String,
    safe: bool,
    entries: Vec<String>,
    #[serde(flatten)]
    diagnostic_output: ContextDiagnosticOutput,
    suppressed_findings: usize,
    diagnostic_counts: BTreeMap<String, usize>,
    category_counts: BTreeMap<String, usize>,
    metrics: ContextMetrics,
    module_summary_schema: String,
    policy_fingerprint: String,
    third_party_material_fingerprints: BTreeMap<String, String>,
}

#[cfg(test)]
impl ContextOutput {
    fn diagnostics(&self) -> &[ContextDiagnostic] {
        match &self.diagnostic_output {
            ContextDiagnosticOutput::Expanded { diagnostics } => diagnostics,
            ContextDiagnosticOutput::Grouped(_) | ContextDiagnosticOutput::Admission(_) => {
                panic!("compact context output has no expanded diagnostics")
            }
        }
    }

    fn grouped_diagnostics(&self) -> &GroupedContextDiagnostics {
        match &self.diagnostic_output {
            ContextDiagnosticOutput::Expanded { .. } | ContextDiagnosticOutput::Admission(_) => {
                panic!("context output has no full grouped diagnostics")
            }
            ContextDiagnosticOutput::Grouped(grouped) => grouped,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SourceInventory {
    kind: String,
    graph_sha256: String,
    pub(crate) functions: Vec<InventoryFunction>,
    pub(crate) diagnostics: Vec<InventoryDiagnostic>,
    pub(crate) unresolved_exports: Vec<InventoryUnresolvedExport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InventoryUnresolvedExport {
    pub(crate) entry_path: String,
    pub(crate) export_name: String,
    pub(crate) classification: String,
    source_span: SourceSpan,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InventoryFunction {
    pub(crate) entry_path: String,
    pub(crate) export_name: String,
    pub(crate) udf_kind: String,
    pub(crate) registration_builder: String,
    registration_call: InventoryRegistrationCall,
    source_span: SourceSpan,
    pub(crate) direct: bool,
    dependency_chain: Vec<DependencyEdge>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InventoryRegistrationCall {
    source_path: String,
    source_sha256: String,
    // Oxc spans and Rust source slices use UTF-8 byte offsets into the authenticated source.
    call_span: SourceOffsetSpan,
    callee_span: SourceOffsetSpan,
}

#[derive(Serialize)]
struct SourceOffsetSpan {
    start: u32,
    end: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InventoryDiagnostic {
    rule: String,
    message: String,
    file: String,
    span: SourceSpan,
    dependency_chain: Vec<DependencyEdge>,
}

#[derive(Clone, Deserialize, Serialize)]
struct PendingDiagnostic {
    severity: String,
    rule: String,
    category: String,
    message: String,
    file: String,
    start: u32,
    end: u32,
    anchor_line: usize,
    entry: String,
    dependency_chain: Vec<DependencyEdge>,
}

// Private computation material retained by the source-graph service, never analysis admission
// authority. Selection and suppressions are deliberately recomputed from the complete input.
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntryAnalysisCache {
    entries: BTreeMap<String, EntryAnalysisRecord>,
    hits: usize,
    misses: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntryAnalysisRecord {
    seed: String,
    input_nodes: BTreeMap<String, Option<String>>,
    third_party_materials: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    third_party_lock_complete: BTreeMap<String, bool>,
    boundary_pending: Vec<PendingDiagnostic>,
    // One parent edge per visited module reconstructs the original BFS paths without prefixes.
    paths: EntryDependencyPaths,
}

type EntryDependencyPaths = BTreeMap<String, Option<DependencyEdge>>;

fn dependency_chain(
    entry: &str,
    module_key: &str,
    paths: &EntryDependencyPaths,
) -> Result<Vec<DependencyEdge>> {
    let mut chain = Vec::new();
    let mut current = module_key;
    while let Some(edge) = paths
        .get(current)
        .context("dependency path has no parent record")?
    {
        ensure!(
            chain.len() < paths.len(),
            "dependency path contains a cycle"
        );
        chain.push(edge.clone());
        current = &edge.from;
    }
    ensure!(current == entry, "dependency path has the wrong root");
    chain.reverse();
    Ok(chain)
}

fn validate_cached_dependency_paths(entry: &str, paths: &EntryDependencyPaths) -> Result<()> {
    // Validate every retained module, including those with no findings, without rebuilding
    // shared prefixes. A previously validated ancestor already proves the remaining root path.
    let mut validated = BTreeSet::new();
    for module_key in paths.keys() {
        let mut current = module_key.as_str();
        let mut ancestors = BTreeSet::new();
        while !validated.contains(current) {
            ensure!(
                ancestors.insert(current),
                "cached dependency path contains a cycle"
            );
            match paths
                .get(current)
                .context("cached dependency path has no parent record")?
            {
                Some(edge) => current = &edge.from,
                None => {
                    ensure!(
                        current == entry,
                        "cached dependency path has the wrong root"
                    );
                    break;
                }
            }
        }
        validated.extend(ancestors);
    }
    Ok(())
}

#[derive(Clone)]
struct MarkerExport {
    occurrences: Vec<ContextMarkerOccurrence>,
}

struct SourceDatabaseFunction {
    udf_kind: String,
    start: u32,
    end: u32,
}

struct PatternBinding {
    name: String,
    start: u32,
    end: u32,
    suffix: String,
}

struct ContextScope {
    parent: Option<usize>,
    bindings_by_name: BTreeMap<String, usize>,
    start: u32,
    end: u32,
    depth: usize,
    function: bool,
    // Ordinary functions own an invocation-local `arguments` object. Arrow functions and
    // class-field initializer scopes inherit the nearest ordinary function's object instead.
    arguments_owner: bool,
    module_scope: bool,
    strict: bool,
    this_module_state: bool,
}

struct ContextBinding {
    name: String,
    module_state: bool,
    declarations: Vec<(u32, u32)>,
    alias_paths: Vec<(String, u32)>,
    // Union direct function values across the binding lifetime. This is conservative for
    // reassignment, but it prevents a later alias change from hiding import-time execution.
    callable_values: Vec<Value>,
}

#[derive(Clone)]
struct FreshValueOrigin {
    value: Value,
    fields: Vec<String>,
}

#[derive(Clone)]
struct DirectCallArguments {
    values: Vec<Value>,
    spread: bool,
}

struct PropertyValue {
    function: Value,
    accessor: bool,
}

struct BindingModel {
    scopes: Vec<ContextScope>,
    bindings: Vec<ContextBinding>,
    callable_return_expressions: RefCell<BTreeMap<(u32, u32), Rc<[Value]>>>,
    retained_receiver_functions: BTreeSet<(u32, u32)>,
    // Class constructors are constructible but not callable; keep them separate from ordinary
    // function aliases so `C()` does not receive `new C()`'s constructor execution semantics.
    constructible_values: BTreeMap<String, Vec<Value>>,
    // Instance fields are evaluated as part of construction, so their expressions must be
    // revisited when a class is instantiated during module evaluation.
    constructible_initializers: BTreeMap<String, Vec<Value>>,
    property_values: BTreeMap<String, Vec<PropertyValue>>,
    // Property aliases preserve global-require provenance through object holders such as
    // `{ load: require }` and later `holder.load(...)` calls.
    property_alias_paths: BTreeMap<String, Vec<(String, u32)>>,
    // A local binding with no alias path has unknown origin. Keep only bindings whose simple
    // initializer or later assignment is structurally fresh so known mutators do not silently
    // accept `const target = getTarget(); target.push(...)`.
    fresh_bindings: BTreeSet<usize>,
    // Freshness is monotone over a binding's lifetime. Once an unknown initializer or assignment
    // is observed, a later fresh assignment cannot retroactively authorize an earlier mutation.
    non_fresh_bindings: BTreeSet<usize>,
    // Preserve initializer structure for member-path freshness. Binding-wide freshness proves the
    // local holder, but it cannot prove that `holder.value` does not alias retained state.
    value_origins: BTreeMap<usize, Vec<FreshValueOrigin>>,
    // Parameters of a non-escaping local callable may inherit freshness from every direct call.
    // The origins retain destructuring paths so nested values are checked at the actual call site.
    direct_call_parameter_origins: BTreeMap<usize, Vec<FreshValueOrigin>>,
    reassigned_bindings: BTreeSet<usize>,
}

struct ResolvedStatePath {
    path: String,
    possible_paths: BTreeSet<String>,
    module_state: bool,
    global_state: bool,
}

#[derive(Clone)]
enum ResolvedReference {
    Local(String),
    External(String),
}

#[derive(Clone, Serialize)]
enum ResolvedGraphReference {
    Local {
        edge: DependencyEdge,
        target: String,
        emitted_only: bool,
    },
    ThirdParty {
        edge: DependencyEdge,
        identity: String,
        reference: ContextModuleReference,
        reviewed_identity: bool,
        target: String,
    },
    Unsupported {
        diagnostic: PendingDiagnostic,
        edge: DependencyEdge,
        target: Option<String>,
    },
    Unaccounted {
        diagnostic: PendingDiagnostic,
    },
}

fn normalized_entry_point(repo_root: &Path, entry_point: &str) -> Option<String> {
    let path = Path::new(entry_point);
    let relative = if path.is_absolute() {
        path.strip_prefix(repo_root).ok()?
    } else {
        path
    };
    let normalized = relative.to_string_lossy().replace('\\', "/");
    (!normalized.is_empty()
        && normalized != ".."
        && !normalized.starts_with("../")
        && !normalized.starts_with('/'))
    .then_some(normalized)
}

fn emitted_inputs_by_entry(
    input: &ContextInput,
    entries: &[String],
) -> BTreeMap<String, Option<BTreeSet<String>>> {
    let mut result = entries
        .iter()
        .map(|entry| (entry.clone(), None))
        .collect::<BTreeMap<_, _>>();
    if input.metafile.outputs.is_empty() {
        return result;
    }
    let mut output_by_entry = BTreeMap::<String, Option<String>>::new();
    for (output_path, output) in &input.metafile.outputs {
        let Some(entry_point) = output
            .entry_point
            .as_deref()
            .and_then(|entry_point| normalized_entry_point(&input.repo_root, entry_point))
        else {
            continue;
        };
        output_by_entry
            .entry(entry_point)
            .and_modify(|existing| *existing = None)
            .or_insert_with(|| Some(output_path.clone()));
    }
    for entry in entries {
        let Some(Some(root_output)) = output_by_entry.get(entry) else {
            continue;
        };
        let mut outputs = VecDeque::from([root_output.clone()]);
        let mut seen_outputs = BTreeSet::new();
        let mut emitted_inputs = BTreeSet::new();
        let mut complete = true;
        while let Some(output_path) = outputs.pop_front() {
            if !seen_outputs.insert(output_path.clone()) {
                continue;
            }
            let Some(output) = input.metafile.outputs.get(&output_path) else {
                complete = false;
                break;
            };
            emitted_inputs.extend(
                output
                    .inputs
                    .iter()
                    .filter(|(_, contribution)| contribution.bytes_in_output > 0)
                    .map(|(input_path, _)| input_path.clone()),
            );
            for imported in &output.imports {
                if input.metafile.outputs.contains_key(&imported.path) {
                    outputs.push_back(imported.path.clone());
                } else if !imported.external {
                    complete = false;
                    break;
                }
            }
            if !complete {
                break;
            }
        }
        if complete {
            result.insert(entry.clone(), Some(emitted_inputs));
        }
    }
    result
}

fn dependency_subgraph_contributes(
    metafile: &EsbuildMetafile,
    target: &str,
    emitted_inputs: Option<&BTreeSet<String>>,
) -> bool {
    let Some(emitted_inputs) = emitted_inputs else {
        return true;
    };
    let mut queue = VecDeque::from([target.to_string()]);
    let mut seen = BTreeSet::new();
    while let Some(module_key) = queue.pop_front() {
        if !seen.insert(module_key.clone()) {
            continue;
        }
        if emitted_inputs.contains(&module_key) {
            return true;
        }
        let Some(module) = metafile.inputs.get(&module_key) else {
            return true;
        };
        queue.extend(
            module
                .imports
                .iter()
                .filter(|imported| {
                    !imported.external && metafile.inputs.contains_key(&imported.path)
                })
                .map(|imported| imported.path.clone()),
        );
    }
    false
}

fn is_third_party_source(module_key: &str) -> bool {
    module_key.starts_with("node_modules/") && is_runtime_source(module_key)
}

#[derive(Clone)]
struct ThirdPartyMaterial {
    fingerprint: String,
    lock_complete: bool,
    unauthenticated_external_imports: BTreeSet<String>,
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_surface_id(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_policy_literal(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.chars().all(|character| {
            !character.is_control() && !matches!(character, '\u{2028}' | '\u{2029}')
        })
}

fn valid_policy_member_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

fn validate_sorted_unique_strings(values: &[String], field: &str) -> Result<()> {
    ensure!(
        !values.is_empty(),
        "reviewed third-party policy {field} must not be empty"
    );
    for value in values {
        ensure!(
            valid_policy_literal(value),
            "reviewed third-party policy {field} contains a non-literal value"
        );
    }
    ensure!(
        values.windows(2).all(|window| window[0] < window[1]),
        "reviewed third-party policy {field} must be sorted and unique"
    );
    Ok(())
}

fn validate_optional_sorted_unique_strings(values: &[String], field: &str) -> Result<()> {
    for value in values {
        ensure!(
            valid_policy_literal(value),
            "reviewed third-party policy {field} contains a non-literal value"
        );
    }
    ensure!(
        values.windows(2).all(|window| window[0] < window[1]),
        "reviewed third-party policy {field} must be sorted and unique"
    );
    Ok(())
}

fn validate_nonempty_literals(values: &[String], field: &str) -> Result<()> {
    ensure!(
        !values.is_empty(),
        "reviewed third-party policy {field} must not be empty"
    );
    for value in values {
        ensure!(
            valid_policy_literal(value),
            "reviewed third-party policy {field} contains a non-literal value"
        );
    }
    Ok(())
}

fn validate_reviewed_third_party_reason(reason: &str) -> Result<()> {
    ensure!(
        valid_policy_literal(reason),
        "reviewed third-party policy reason must be non-empty single-line text without control characters"
    );
    Ok(())
}

fn validate_reviewed_third_party_policy(policy: &ReviewedThirdPartyPolicy) -> Result<()> {
    ensure!(
        policy.kind == REVIEWED_THIRD_PARTY_POLICY_KIND,
        "reviewed third-party policy kind changed"
    );
    ensure!(
        policy.schema_version == REVIEWED_THIRD_PARTY_POLICY_SCHEMA_VERSION,
        "reviewed third-party policy version changed"
    );
    ensure!(
        !policy.surfaces.is_empty(),
        "reviewed third-party policy surfaces must not be empty"
    );
    let surface_ids = policy
        .surfaces
        .iter()
        .map(|surface| surface.id.as_str())
        .collect::<Vec<_>>();
    ensure!(
        surface_ids.windows(2).all(|window| window[0] < window[1]),
        "reviewed third-party policy surface IDs must be sorted and unique"
    );

    let mut all_fingerprints = BTreeSet::new();
    for surface in &policy.surfaces {
        ensure!(
            valid_surface_id(&surface.id),
            "reviewed third-party policy surface ID must be lowercase kebab-case"
        );
        ensure!(
            surface
                .fingerprints
                .windows(2)
                .all(|window| window[0] < window[1]),
            "reviewed third-party policy fingerprints must be sorted and unique"
        );
        ensure!(
            !surface.fingerprints.is_empty(),
            "reviewed third-party policy fingerprints must not be empty"
        );
        for fingerprint in &surface.fingerprints {
            ensure!(
                valid_sha256_digest(fingerprint),
                "reviewed third-party policy fingerprint must be a lowercase SHA-256 digest"
            );
            ensure!(
                all_fingerprints.insert(fingerprint),
                "reviewed third-party policy fingerprints must be globally unique"
            );
        }

        match &surface.admission {
            ReviewedThirdPartyAdmission::Accept { reason }
            | ReviewedThirdPartyAdmission::Reject { reason } => {
                validate_reviewed_third_party_reason(reason)?;
            }
            ReviewedThirdPartyAdmission::NamedImports { exports, reason } => {
                validate_reviewed_third_party_reason(reason)?;
                validate_sorted_unique_strings(exports, "named-import exports")?;
                ensure!(
                    exports
                        .iter()
                        .all(|export| export != "*" && export != "default"),
                    "reviewed third-party policy named-import exports must not include namespace or default access"
                );
            }
            ReviewedThirdPartyAdmission::NamedDerivedMembers {
                imports,
                members,
                forbidden_derived_members,
                reason,
            } => {
                validate_reviewed_third_party_reason(reason)?;
                validate_sorted_unique_strings(imports, "derived-surface imports")?;
                validate_sorted_unique_strings(members, "derived-surface members")?;
                validate_sorted_unique_strings(
                    forbidden_derived_members,
                    "derived-surface forbidden members",
                )?;
                ensure!(
                    imports.iter().all(|import| import != "*"),
                    "reviewed third-party derived-surface imports must not include namespace access"
                );
                ensure!(
                    forbidden_derived_members
                        .iter()
                        .all(|member| !members.contains(member)),
                    "reviewed third-party derived-surface members cannot be both allowed and forbidden"
                );
            }
            ReviewedThirdPartyAdmission::NamedImportUses {
                instanceof_targets,
                static_calls,
                reason,
            } => {
                validate_reviewed_third_party_reason(reason)?;
                validate_optional_sorted_unique_strings(
                    instanceof_targets,
                    "named-import instanceof targets",
                )?;
                ensure!(
                    instanceof_targets
                        .iter()
                        .all(|import| import != "*" && import != "default"),
                    "reviewed third-party instanceof targets must not include namespace or default access"
                );
                let mut previous_call = None::<String>;
                for call in static_calls {
                    ensure!(
                        valid_policy_literal(&call.import_name)
                            && call.import_name != "*"
                            && call.import_name != "default",
                        "reviewed third-party static-call import must be a named import"
                    );
                    validate_nonempty_literals(&call.members, "static-call members")?;
                    ensure!(
                        call.members
                            .iter()
                            .all(|member| valid_policy_member_identifier(member)),
                        "reviewed third-party static-call members must be identifier member names"
                    );
                    let key = format!("{}\0{}", call.import_name, call.members.join("\0"));
                    ensure!(
                        previous_call
                            .as_ref()
                            .is_none_or(|previous| previous < &key),
                        "reviewed third-party static calls must be sorted and unique"
                    );
                    previous_call = Some(key);
                }
                ensure!(
                    !instanceof_targets.is_empty() || !static_calls.is_empty(),
                    "reviewed third-party named-import uses must not be empty"
                );
                ensure!(
                    static_calls
                        .iter()
                        .all(|call| !instanceof_targets.contains(&call.import_name)),
                    "reviewed third-party named-import use cannot be both an instanceof target and a static-call root"
                );
            }
        }
    }
    Ok(())
}

fn parse_reviewed_third_party_policy(source: &str) -> Result<ReviewedThirdPartyPolicy> {
    let policy: ReviewedThirdPartyPolicy =
        serde_json::from_str(source).context("reviewed third-party policy must be valid JSON")?;
    validate_reviewed_third_party_policy(&policy)?;
    Ok(policy)
}

fn merge_reviewed_third_party_policy(
    supplemental: Option<ReviewedThirdPartyPolicy>,
) -> Result<ReviewedThirdPartyPolicy> {
    let mut policy = reviewed_third_party_policy().clone();
    if let Some(supplemental) = supplemental {
        validate_reviewed_third_party_policy(&supplemental)?;
        policy.surfaces.extend(supplemental.surfaces);
        policy
            .surfaces
            .sort_by(|left, right| left.id.cmp(&right.id));
        validate_reviewed_third_party_policy(&policy)?;
    }
    Ok(policy)
}

fn reviewed_third_party_policy() -> &'static ReviewedThirdPartyPolicy {
    static POLICY: OnceLock<ReviewedThirdPartyPolicy> = OnceLock::new();
    POLICY.get_or_init(|| {
        parse_reviewed_third_party_policy(REVIEWED_THIRD_PARTY_POLICY_SOURCE)
            .expect("checked-in reviewed third-party policy must be valid")
    })
}

fn reviewed_third_party_surface(
    fingerprint: &str,
) -> Option<&'static ReviewedThirdPartySurfaceConfig> {
    reviewed_third_party_surface_in_policy(reviewed_third_party_policy(), fingerprint)
}

fn reviewed_third_party_surface_in_policy<'a>(
    policy: &'a ReviewedThirdPartyPolicy,
    fingerprint: &str,
) -> Option<&'a ReviewedThirdPartySurfaceConfig> {
    policy.surfaces.iter().find(|surface| {
        surface
            .fingerprints
            .iter()
            .any(|value| value == fingerprint)
    })
}

#[derive(Clone)]
enum ThirdPartyDisposition {
    Accepted,
    Unsupported(String),
}

fn package_lock_key(module_key: &str) -> Option<String> {
    let components = module_key.split('/').collect::<Vec<_>>();
    if components.first().copied() != Some("node_modules") {
        return None;
    }

    // A package-lock entry is rooted at the innermost node_modules boundary.
    // Esbuild can preserve nested install paths (for example,
    // node_modules/parent/node_modules/child/index.js), so using only the first
    // package would bind the child module to the parent's lock entry and
    // package.json.
    let mut package_end = None;
    let mut index = 0;
    while index < components.len() {
        if components[index] != "node_modules" {
            index += 1;
            continue;
        }
        let package_start = index + 1;
        let Some(first) = components.get(package_start).copied() else {
            return None;
        };
        if matches!(first, "" | "." | "..") {
            return None;
        }
        let end = if first.starts_with('@') {
            package_start + 2
        } else {
            package_start + 1
        };
        let package_components = components.get(package_start..end)?;
        if package_components
            .iter()
            .any(|component| matches!(*component, "" | "." | ".."))
        {
            return None;
        }
        package_end = Some(end);
        index = end;
    }
    Some(components[..package_end?].join("/"))
}

fn load_package_lock_entries(repo_root: &Path) -> Result<Option<BTreeMap<String, Value>>> {
    let path = repo_root.join("package-lock.json");
    let source = match fs::symlink_metadata(&path) {
        Ok(_) => {
            // package-lock.json proves that every traversed package belongs to the admitted
            // installation. Keep that evidence inside the same checked repository as the package
            // modules and manifests even though metadata bytes do not define the reviewed source
            // closure fingerprint.
            let (_, bytes) = read_checked_module(repo_root, "package-lock.json")?;
            String::from_utf8(bytes)
                .with_context(|| format!("failed to decode {} as UTF-8", path.display()))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    let lock: Value = serde_json::from_str(&source)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let packages = lock
        .get("packages")
        .and_then(Value::as_object)
        .context("package-lock.json has no packages object")?;
    Ok(Some(
        packages
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}

fn third_party_material(
    input: &ContextInput,
    target: &str,
    package_lock_entries: Option<&BTreeMap<String, Value>>,
) -> Result<ThirdPartyMaterial> {
    let mut queue = VecDeque::from([target.to_string()]);
    let mut seen_modules = BTreeSet::new();
    let mut package_keys = BTreeSet::new();
    let mut unauthenticated_external_imports = BTreeSet::new();
    let mut material = format!("convex-context-reuse-third-party-source-material\0{target}\0");
    while let Some(module_key) = queue.pop_front() {
        if !seen_modules.insert(module_key.clone()) {
            continue;
        }
        ensure!(
            module_key.starts_with("node_modules/"),
            "third-party material traversal escaped installed package inputs at {module_key}"
        );
        package_keys.insert(
            package_lock_key(&module_key)
                .with_context(|| format!("invalid third-party module key {module_key}"))?,
        );
        let (_, source) = read_checked_module(&input.repo_root, &module_key)
            .with_context(|| format!("failed to read third-party material {module_key}"))?;
        material.push_str(&module_key);
        material.push('\0');
        material.push_str(&hash_bytes(&source));
        material.push('\0');
        let graph_input =
            input.metafile.inputs.get(&module_key).with_context(|| {
                format!("esbuild metafile has no third-party input {module_key}")
            })?;
        let mut imports = graph_input
            .imports
            .iter()
            .map(|imported| {
                (
                    imported.path.clone(),
                    imported.kind.clone(),
                    imported.original.clone(),
                    imported.external,
                )
            })
            .collect::<Vec<_>>();
        imports.sort();
        for (path, kind, original, external) in imports {
            material.push_str(&path);
            material.push('\0');
            material.push_str(&kind);
            material.push('\0');
            material.push_str(original.as_deref().unwrap_or(""));
            material.push('\0');
            material.push_str(if external { "external" } else { "local" });
            material.push('\0');
            if external && !path.starts_with("node:") && path != ESBUILD_RUNTIME_PSEUDO_MODULE {
                // Record this as a closed package disposition instead of aborting analysis. The
                // exact external bytes remain absent, so review rejects before any fingerprint
                // allowlist can grant authority. Node built-ins and esbuild's exact runtime
                // pseudo-module do not name separately resolved package bytes. Their edge fields
                // above remain part of the exact package fingerprint.
                unauthenticated_external_imports.insert(path.clone());
            }
            // Loader-managed assets are part of the exact package material too. Limiting this
            // walk by source extension would let their bytes drift under a reviewed identity.
            if !external {
                if input.virtual_inputs.contains(&path) {
                    ensure!(
                        input.metafile.inputs.contains_key(&path),
                        "esbuild virtual third-party dependency {path} is missing from the metafile"
                    );
                    continue;
                }
                // Every local edge is part of the authenticated package closure. A missing
                // metafile input is malformed graph evidence, not an optional tree-shaken edge;
                // silently omitting it would let a reviewed fingerprint ignore changed package
                // material behind that edge.
                ensure!(
                    input.metafile.inputs.contains_key(&path),
                    "esbuild third-party dependency {path} is missing from the metafile"
                );
                queue.push_back(path);
            }
        }
    }

    let mut lock_complete = package_lock_entries.is_some();
    for package_key in package_keys {
        let lock_entry = package_lock_entries.and_then(|entries| entries.get(&package_key));
        if lock_entry.is_none() {
            lock_complete = false;
        }
        let package_json_key = format!("{package_key}/package.json");
        // A manifest and complete lock representation remain admission requirements, but their
        // metadata bytes do not change the exact emitted source closure. Resolve the manifest
        // through the same repository-boundary check as module bytes so outside files cannot
        // satisfy that requirement.
        match fs::symlink_metadata(input.repo_root.join(&package_json_key)) {
            Ok(_) => {
                let _ = read_checked_module(&input.repo_root, &package_json_key)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                lock_complete = false;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {package_json_key}"));
            }
        }
    }
    Ok(ThirdPartyMaterial {
        fingerprint: hash_bytes(material.as_bytes()),
        lock_complete,
        unauthenticated_external_imports,
    })
}

fn first_member_after(source: &str, end: u32) -> Option<String> {
    let bytes = source.as_bytes();
    let mut index = end as usize;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    if bytes.get(index..index + 2) == Some(b"?.") {
        index += 2;
    } else if bytes.get(index) == Some(&b'.') {
        index += 1;
    } else if bytes.get(index) == Some(&b'[') {
        index += 1;
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        let quote = *bytes.get(index)?;
        if !matches!(quote, b'\'' | b'"') {
            return None;
        }
        index += 1;
        let start = index;
        while bytes
            .get(index)
            .is_some_and(|byte| *byte != quote && *byte != b'\\')
        {
            index += 1;
        }
        return (bytes.get(index) == Some(&quote))
            .then(|| String::from_utf8_lossy(&bytes[start..index]).into_owned());
    } else {
        return None;
    }
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let start = index;
    if !bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
    {
        return None;
    }
    index += 1;
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
    {
        index += 1;
    }
    Some(String::from_utf8_lossy(&bytes[start..index]).into_owned())
}

fn ast_runtime_children(value: &Value) -> impl Iterator<Item = &Value> {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "comments"
                    | "implements"
                    | "loc"
                    | "range"
                    | "returnType"
                    | "superTypeParameters"
                    | "tokens"
                    | "typeAnnotation"
                    | "typeArguments"
                    | "typeParameters"
            )
        })
        .flat_map(|(_, child)| match child {
            Value::Array(values) => values.as_slice(),
            Value::Object(_) => std::slice::from_ref(child),
            _ => &[],
        })
}

fn callable_returns_import_value(
    callable: &Value,
    bindings: &BindingModel,
    imported_bindings: &BTreeSet<usize>,
    active_callables: &mut BTreeSet<(u32, u32)>,
) -> bool {
    let Ok(span) = node_span(callable) else {
        return true;
    };
    if !active_callables.insert(span) {
        return true;
    }
    let body = callable.get("body");
    let result = body.is_none_or(|body| {
        bindings
            .return_expressions(span, body)
            .iter()
            .any(|argument| {
                expression_has_import_value(argument, bindings, imported_bindings, active_callables)
            })
    });
    active_callables.remove(&span);
    result
}

fn expression_has_import_value(
    value: &Value,
    bindings: &BindingModel,
    imported_bindings: &BTreeSet<usize>,
    active_callables: &mut BTreeSet<(u32, u32)>,
) -> bool {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("Identifier") => identifier(value)
            .and_then(|name| {
                node_span(value)
                    .ok()
                    .and_then(|(start, _)| bindings.binding_at(name, start))
            })
            .is_some_and(|binding| imported_bindings.contains(&binding)),
        Some("MemberExpression" | "OptionalMemberExpression") => {
            value.get("object").is_some_and(|object| {
                expression_has_import_value(object, bindings, imported_bindings, active_callables)
            })
        }
        Some("CallExpression" | "NewExpression") => {
            let callee = value.get("callee").map(unwrap_expression);
            let local_callables = callee
                .map(|callee| bindings.resolve_callable_values(callee))
                .unwrap_or_default();
            let terminal_schema_call = callee.is_some_and(|callee| {
                matches!(
                    static_member_name(callee),
                    Some(
                        "decode"
                            | "decodeAsync"
                            | "encode"
                            | "encodeAsync"
                            | "parse"
                            | "parseAsync"
                            | "safeDecode"
                            | "safeDecodeAsync"
                            | "safeEncode"
                            | "safeEncodeAsync"
                            | "safeParse"
                            | "safeParseAsync"
                            | "toJSONSchema"
                    )
                ) && callee.get("object").is_some_and(|object| {
                    expression_has_import_value(
                        object,
                        bindings,
                        imported_bindings,
                        active_callables,
                    )
                })
            });
            let callee_value = !terminal_schema_call
                && callee.is_some_and(|callee| {
                    expression_has_import_value(
                        callee,
                        bindings,
                        imported_bindings,
                        active_callables,
                    ) || local_callables.iter().copied().into_iter().any(|callable| {
                        callable_returns_import_value(
                            callable,
                            bindings,
                            imported_bindings,
                            active_callables,
                        )
                    })
                });
            callee_value
                || (!terminal_schema_call
                    && local_callables.is_empty()
                    && value
                        .get("arguments")
                        .and_then(Value::as_array)
                        .is_some_and(|arguments| {
                            arguments.iter().any(|argument| {
                                expression_has_import_value(
                                    argument,
                                    bindings,
                                    imported_bindings,
                                    active_callables,
                                )
                            })
                        }))
        }
        Some("ArrayExpression") => value
            .get("elements")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|element| !element.is_null())
            .any(|element| {
                expression_has_import_value(element, bindings, imported_bindings, active_callables)
            }),
        Some("ObjectExpression") => value
            .get("properties")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|property| match node_kind(property) {
                Some("SpreadElement") => property.get("argument").is_some_and(|argument| {
                    expression_has_import_value(
                        argument,
                        bindings,
                        imported_bindings,
                        active_callables,
                    )
                }),
                Some("Property") => property.get("value").is_some_and(|property_value| {
                    expression_has_import_value(
                        property_value,
                        bindings,
                        imported_bindings,
                        active_callables,
                    )
                }),
                _ => false,
            }),
        Some("SpreadElement") => value.get("argument").is_some_and(|argument| {
            expression_has_import_value(argument, bindings, imported_bindings, active_callables)
        }),
        Some("AssignmentExpression") => assignment_result_fields(value).iter().any(|field| {
            value.get(*field).is_some_and(|result| {
                expression_has_import_value(result, bindings, imported_bindings, active_callables)
            })
        }),
        Some("AwaitExpression" | "YieldExpression") => {
            value.get("argument").is_some_and(|argument| {
                expression_has_import_value(argument, bindings, imported_bindings, active_callables)
            })
        }
        Some("ConditionalExpression") => ["consequent", "alternate"].into_iter().any(|field| {
            value.get(field).is_some_and(|branch| {
                expression_has_import_value(branch, bindings, imported_bindings, active_callables)
            })
        }),
        Some("LogicalExpression") => ["left", "right"].into_iter().any(|field| {
            value.get(field).is_some_and(|branch| {
                expression_has_import_value(branch, bindings, imported_bindings, active_callables)
            })
        }),
        Some("SequenceExpression") => value
            .get("expressions")
            .and_then(Value::as_array)
            .and_then(|expressions| expressions.last())
            .is_some_and(|result| {
                expression_has_import_value(result, bindings, imported_bindings, active_callables)
            }),
        _ => false,
    }
}

fn callable_returns_import_binding_value(
    callable: &Value,
    bindings: &BindingModel,
    imported_binding_values: &BTreeSet<usize>,
    active_callables: &mut BTreeSet<(u32, u32)>,
) -> bool {
    let Ok(span) = node_span(callable) else {
        return true;
    };
    if !active_callables.insert(span) {
        return true;
    }
    let Some(body) = callable.get("body") else {
        active_callables.remove(&span);
        return false;
    };
    let result = bindings
        .return_expressions(span, body)
        .iter()
        .any(|argument| {
            expression_has_import_binding_value_inner(
                argument,
                bindings,
                imported_binding_values,
                true,
                active_callables,
            )
        });
    active_callables.remove(&span);
    result
}

fn expression_has_import_binding_value_inner(
    value: &Value,
    bindings: &BindingModel,
    imported_binding_values: &BTreeSet<usize>,
    follow_local_returns: bool,
    active_callables: &mut BTreeSet<(u32, u32)>,
) -> bool {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("Identifier") => identifier(value)
            .and_then(|name| {
                node_span(value)
                    .ok()
                    .and_then(|(start, _)| bindings.binding_at(name, start))
            })
            .is_some_and(|binding| imported_binding_values.contains(&binding)),
        Some("MemberExpression" | "OptionalMemberExpression") => {
            value.get("object").is_some_and(|object| {
                expression_has_import_binding_value_inner(
                    object,
                    bindings,
                    imported_binding_values,
                    follow_local_returns,
                    active_callables,
                )
            })
        }
        Some("CallExpression") => {
            value
                .get("callee")
                .map(unwrap_expression)
                .is_some_and(|callee| {
                    let mut direct_callables = Vec::new();
                    if collect_bound_callable_result_functions(
                        callee,
                        false,
                        bindings,
                        &mut direct_callables,
                    )
                    .is_err()
                    {
                        return true;
                    }
                    let function_member = direct_callables.is_empty()
                        && matches!(static_member_name(callee), Some("apply" | "bind" | "call"));
                    // call/apply expose the target's return immediately. Bound arguments are
                    // hidden inside the callable returned by bind, so preserve the same return
                    // provenance there before an unknown consumer can invoke the wrapper.
                    (function_member
                        && callee.get("object").is_some_and(|object| {
                            (static_member_name(callee) == Some("bind")
                                && expression_has_import_binding_value_inner(
                                    object,
                                    bindings,
                                    imported_binding_values,
                                    follow_local_returns,
                                    active_callables,
                                ))
                                || (follow_local_returns && {
                                    let mut object_callables = Vec::new();
                                    collect_bound_callable_result_functions(
                                        object,
                                        false,
                                        bindings,
                                        &mut object_callables,
                                    )
                                    .is_err()
                                        || object_callables.into_iter().any(|callable| {
                                            callable_returns_import_binding_value(
                                                callable,
                                                bindings,
                                                imported_binding_values,
                                                active_callables,
                                            )
                                        })
                                })
                        }))
                        || (follow_local_returns
                            && direct_callables.into_iter().any(|callable| {
                                callable_returns_import_binding_value(
                                    callable,
                                    bindings,
                                    imported_binding_values,
                                    active_callables,
                                )
                            }))
                })
        }
        Some("ArrayExpression") => value
            .get("elements")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|element| !element.is_null())
            .any(|element| {
                expression_has_import_binding_value_inner(
                    element,
                    bindings,
                    imported_binding_values,
                    follow_local_returns,
                    active_callables,
                )
            }),
        Some("ObjectExpression") => value
            .get("properties")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|property| match node_kind(property) {
                Some("SpreadElement") => property.get("argument").is_some_and(|argument| {
                    expression_has_import_binding_value_inner(
                        argument,
                        bindings,
                        imported_binding_values,
                        follow_local_returns,
                        active_callables,
                    )
                }),
                Some("Property") => property.get("value").is_some_and(|property_value| {
                    expression_has_import_binding_value_inner(
                        property_value,
                        bindings,
                        imported_binding_values,
                        follow_local_returns,
                        active_callables,
                    )
                }),
                _ => false,
            }),
        Some("SpreadElement") => value.get("argument").is_some_and(|argument| {
            expression_has_import_binding_value_inner(
                argument,
                bindings,
                imported_binding_values,
                follow_local_returns,
                active_callables,
            )
        }),
        Some("AwaitExpression") => value.get("argument").is_some_and(|argument| {
            expression_has_import_binding_value_inner(
                argument,
                bindings,
                imported_binding_values,
                follow_local_returns,
                active_callables,
            )
        }),
        Some("AssignmentExpression") => assignment_result_fields(value).iter().any(|field| {
            value.get(*field).is_some_and(|result| {
                expression_has_import_binding_value_inner(
                    result,
                    bindings,
                    imported_binding_values,
                    follow_local_returns,
                    active_callables,
                )
            })
        }),
        Some("ConditionalExpression") => ["consequent", "alternate"].into_iter().any(|field| {
            value.get(field).is_some_and(|branch| {
                expression_has_import_binding_value_inner(
                    branch,
                    bindings,
                    imported_binding_values,
                    follow_local_returns,
                    active_callables,
                )
            })
        }),
        Some("LogicalExpression") => ["left", "right"].into_iter().any(|field| {
            value.get(field).is_some_and(|branch| {
                expression_has_import_binding_value_inner(
                    branch,
                    bindings,
                    imported_binding_values,
                    follow_local_returns,
                    active_callables,
                )
            })
        }),
        Some("SequenceExpression") => value
            .get("expressions")
            .and_then(Value::as_array)
            .and_then(|expressions| expressions.last())
            .is_some_and(|result| {
                expression_has_import_binding_value_inner(
                    result,
                    bindings,
                    imported_binding_values,
                    follow_local_returns,
                    active_callables,
                )
            }),
        _ => false,
    }
}

fn expression_has_import_binding_value(
    value: &Value,
    bindings: &BindingModel,
    imported_binding_values: &BTreeSet<usize>,
) -> bool {
    expression_has_import_binding_value_inner(
        value,
        bindings,
        imported_binding_values,
        true,
        &mut BTreeSet::new(),
    )
}

fn taint_pattern_bindings(
    pattern: &Value,
    bindings: &BindingModel,
    imported_bindings: &mut BTreeSet<usize>,
) -> Result<bool> {
    let mut targets = Vec::new();
    collect_pattern_bindings(pattern, "", &mut targets)?;
    let mut changed = false;
    for target in targets {
        if let Some(binding) = bindings.binding_at(&target.name, target.start) {
            changed |= imported_bindings.insert(binding);
        }
    }
    Ok(changed)
}

fn pattern_has_import_binding_value(
    pattern: &Value,
    bindings: &BindingModel,
    imported_binding_values: &BTreeSet<usize>,
) -> Result<bool> {
    let mut targets = Vec::new();
    collect_pattern_bindings(pattern, "", &mut targets)?;
    Ok(targets.into_iter().any(|target| {
        bindings
            .binding_at(&target.name, target.start)
            .is_some_and(|binding| imported_binding_values.contains(&binding))
    }))
}

fn declaration_has_import_binding_value(
    declaration: &Value,
    bindings: &BindingModel,
    imported_binding_values: &BTreeSet<usize>,
) -> Result<bool> {
    match node_kind(declaration) {
        Some("VariableDeclaration") => {
            let declarators = declaration
                .get("declarations")
                .and_then(Value::as_array)
                .context("variable declaration has no declarations")?;
            for declarator in declarators {
                let pattern = declarator
                    .get("id")
                    .context("variable declarator has no binding")?;
                if pattern_has_import_binding_value(pattern, bindings, imported_binding_values)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Some(
            "ClassDeclaration" | "ClassExpression" | "FunctionDeclaration" | "FunctionExpression",
        ) => Ok(declaration.get("id").is_some_and(|identifier| {
            expression_has_import_binding_value(identifier, bindings, imported_binding_values)
        })),
        _ => Ok(false),
    }
}

fn jsx_element_name_has_import_binding_value(
    name: &Value,
    bindings: &BindingModel,
    imported_binding_values: &BTreeSet<usize>,
) -> bool {
    let is_member_name = node_kind(name) == Some("JSXMemberExpression");
    let mut root = name;
    while node_kind(root) == Some("JSXMemberExpression") {
        let Some(object) = root.get("object") else {
            return true;
        };
        root = object;
    }
    if node_kind(root) != Some("JSXIdentifier") {
        return false;
    }
    let Some(name) = root.get("name").and_then(Value::as_str) else {
        return true;
    };
    // A simple lowercase JSX name is an intrinsic string. The root of a member name remains a
    // runtime binding regardless of case, as in `<components.Item />`.
    if !is_member_name && name.as_bytes().first().is_some_and(u8::is_ascii_lowercase) {
        return false;
    }
    node_span(root)
        .ok()
        .and_then(|(start, _)| bindings.binding_at(name, start))
        .is_some_and(|binding| imported_binding_values.contains(&binding))
}

fn assignment_target_has_non_fresh_receiver(target: &Value, bindings: &BindingModel) -> bool {
    assignment_pattern_targets(target)
        .into_iter()
        .any(|target| {
            matches!(
                node_kind(unwrap_expression(target)),
                Some("MemberExpression" | "OptionalMemberExpression")
            ) && target.get("object").is_none_or(|object| {
                !bindings.value_path_is_known_fresh(
                    object,
                    &[],
                    &mut BTreeSet::new(),
                    &mut BTreeSet::new(),
                )
            })
        })
}

fn taint_assignment_target(
    pattern: &Value,
    bindings: &BindingModel,
    imported_bindings: &mut BTreeSet<usize>,
) -> Result<bool> {
    let mut changed = taint_pattern_bindings(pattern, bindings, imported_bindings)?;
    if matches!(
        node_kind(unwrap_expression(pattern)),
        Some("MemberExpression" | "OptionalMemberExpression")
    ) && let Some(path) = expression_base_path(pattern)
        && let Some(root) = path.split('.').next()
        && let Ok((start, _)) = node_span(pattern)
        && let Some(binding) = bindings.binding_at(root, start)
    {
        // A property assignment makes the containing local object capable of returning the
        // imported value through a later computed access.
        changed |= imported_bindings.insert(binding);
    }
    Ok(changed)
}

fn taint_callable_parameters(
    callable: &Value,
    arguments: &[&Value],
    uncertain_positions: bool,
    bindings: &BindingModel,
    imported_bindings: &mut BTreeSet<usize>,
    imported_binding_values: &mut BTreeSet<usize>,
) -> Result<bool> {
    let Some(parameters) = callable.get("params").and_then(Value::as_array) else {
        return Ok(false);
    };
    // Import-derived values may flow through reviewed helpers, while the named binding itself
    // must retain separate provenance so a nested unknown consumer remains an escape.
    let import_derived_arguments = arguments
        .iter()
        .map(|argument| {
            expression_has_import_value(argument, bindings, imported_bindings, &mut BTreeSet::new())
        })
        .collect::<Vec<_>>();
    let import_binding_arguments = arguments
        .iter()
        .map(|argument| {
            expression_has_import_binding_value(argument, bindings, imported_binding_values)
        })
        .collect::<Vec<_>>();
    let any_import_derived = import_derived_arguments.iter().any(|tainted| *tainted);
    let any_import_binding = import_binding_arguments.iter().any(|tainted| *tainted);
    let mut changed = false;
    for (index, parameter) in parameters.iter().enumerate() {
        let rest = node_kind(parameter) == Some("RestElement");
        let import_derived = if uncertain_positions {
            any_import_derived
        } else if rest {
            import_derived_arguments
                .get(index..)
                .is_some_and(|arguments| arguments.iter().any(|tainted| *tainted))
        } else {
            import_derived_arguments.get(index) == Some(&true)
        };
        if import_derived {
            changed |= taint_pattern_bindings(parameter, bindings, imported_bindings)?;
        }
        let import_binding = if uncertain_positions {
            any_import_binding
        } else if rest {
            import_binding_arguments
                .get(index..)
                .is_some_and(|arguments| arguments.iter().any(|tainted| *tainted))
        } else {
            import_binding_arguments.get(index) == Some(&true)
        };
        if import_binding {
            changed |= taint_pattern_bindings(parameter, bindings, imported_binding_values)?;
        }
    }
    Ok(changed)
}

fn propagate_import_value(
    value: &Value,
    bindings: &BindingModel,
    imported_bindings: &mut BTreeSet<usize>,
    imported_binding_values: &mut BTreeSet<usize>,
    reject_helper_escapes: bool,
) -> Result<(bool, bool)> {
    let mut changed = false;
    let mut helper_escape = false;
    match node_kind(value) {
        Some("VariableDeclarator") => {
            if let (Some(pattern), Some(initializer)) = (
                value.get("id"),
                value
                    .get("init")
                    .filter(|initializer| !initializer.is_null()),
            ) && expression_has_import_value(
                initializer,
                bindings,
                imported_bindings,
                &mut BTreeSet::new(),
            ) {
                changed |= taint_pattern_bindings(pattern, bindings, imported_bindings)?;
            }
            if let (Some(pattern), Some(initializer)) = (
                value.get("id"),
                value
                    .get("init")
                    .filter(|initializer| !initializer.is_null()),
            ) && expression_has_import_binding_value(
                initializer,
                bindings,
                imported_binding_values,
            ) {
                changed |= taint_pattern_bindings(pattern, bindings, imported_binding_values)?;
            }
        }
        Some("AssignmentExpression") => {
            if let (Some(pattern), Some(right)) = (value.get("left"), value.get("right"))
                && expression_has_import_value(
                    right,
                    bindings,
                    imported_bindings,
                    &mut BTreeSet::new(),
                )
            {
                changed |= taint_assignment_target(pattern, bindings, imported_bindings)?;
            }
            if let (Some(pattern), Some(right)) = (value.get("left"), value.get("right"))
                && expression_has_import_binding_value(right, bindings, imported_binding_values)
            {
                changed |= taint_assignment_target(pattern, bindings, imported_binding_values)?;
            }
            if reject_helper_escapes
                && !assignment_result_fields(value).is_empty()
                && let (Some(target), Some(right)) = (value.get("left"), value.get("right"))
                && expression_has_import_binding_value(right, bindings, imported_binding_values)
                && assignment_target_has_non_fresh_receiver(target, bindings)
            {
                // Only a receiver that remains structurally fresh keeps local provenance. An
                // unresolved, global, module, or parameter receiver can expose the reviewed
                // binding without any later lexical use that the flow analysis could inspect.
                helper_escape = true;
            }
        }
        Some("ForOfStatement") => {
            if let (Some(left), Some(right)) = (value.get("left"), value.get("right")) {
                let patterns = if node_kind(left) == Some("VariableDeclaration") {
                    left.get("declarations")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|declaration| declaration.get("id"))
                        .collect::<Vec<_>>()
                } else {
                    vec![left]
                };
                if expression_has_import_value(
                    right,
                    bindings,
                    imported_bindings,
                    &mut BTreeSet::new(),
                ) {
                    for pattern in &patterns {
                        changed |= taint_assignment_target(pattern, bindings, imported_bindings)?;
                    }
                }
                if expression_has_import_binding_value(right, bindings, imported_binding_values) {
                    for pattern in &patterns {
                        changed |=
                            taint_assignment_target(pattern, bindings, imported_binding_values)?;
                        if reject_helper_escapes
                            && assignment_target_has_non_fresh_receiver(pattern, bindings)
                        {
                            helper_escape = true;
                        }
                    }
                }
            }
        }
        Some("CallExpression" | "NewExpression") => {
            if let (Some(callee), Some(arguments)) = (
                value.get("callee").map(unwrap_expression),
                value.get("arguments").and_then(Value::as_array),
            ) {
                let member = static_member_name(callee);
                let direct_callables = bindings.resolve_callable_values(callee);
                // A real local method named call/apply/bind keeps ordinary method parameters.
                // Only an unresolved member can be the Function.prototype invocation form.
                let function_method = direct_callables.is_empty()
                    && matches!(member, Some("apply" | "bind" | "call"));
                let callables = if function_method {
                    bindings.resolve_callable_values(
                        callee
                            .get("object")
                            .map(unwrap_expression)
                            .unwrap_or(callee),
                    )
                } else {
                    direct_callables
                };
                let (effective_arguments, uncertain_positions) =
                    if function_method && member == Some("apply") {
                        let applied = arguments.get(1);
                        if let Some(elements) = applied
                            .map(unwrap_expression)
                            .filter(|argument| node_kind(argument) == Some("ArrayExpression"))
                            .and_then(|argument| argument.get("elements"))
                            .and_then(Value::as_array)
                        {
                            (
                                elements
                                    .iter()
                                    .filter(|element| !element.is_null())
                                    .collect::<Vec<_>>(),
                                elements.iter().any(|element| {
                                    element.is_null() || node_kind(element) == Some("SpreadElement")
                                }),
                            )
                        } else {
                            (applied.into_iter().collect::<Vec<_>>(), true)
                        }
                    } else {
                        let skip = if function_method && matches!(member, Some("bind" | "call")) {
                            1
                        } else {
                            0
                        };
                        let effective = arguments.iter().skip(skip).collect::<Vec<_>>();
                        let uncertain = effective
                            .iter()
                            .any(|argument| node_kind(argument) == Some("SpreadElement"));
                        (effective, uncertain)
                    };
                // Generic reviewed imports remain direct capabilities. Passing one as any call
                // argument escapes that direct-use contract even when the callee is a local
                // helper whose parameter provenance could otherwise be followed exactly.
                if reject_helper_escapes
                    && arguments.iter().any(|argument| {
                        expression_has_import_binding_value(
                            argument,
                            bindings,
                            imported_binding_values,
                        )
                    })
                {
                    helper_escape = true;
                }
                if reject_helper_escapes
                    && member == Some("bind")
                    && callee.get("object").is_some_and(|object| {
                        expression_has_import_binding_value(
                            object,
                            bindings,
                            imported_binding_values,
                        )
                    })
                {
                    // bind retains its target inside a new callable even when the wrapper is
                    // invoked locally and only the ordinary reviewed-call result is exported.
                    helper_escape = true;
                }
                if reject_helper_escapes
                    && node_kind(value) == Some("NewExpression")
                    && expression_has_import_binding_value(
                        callee,
                        bindings,
                        imported_binding_values,
                    )
                {
                    // A constructed value can expose the reviewed constructor through its
                    // prototype even when ordinary direct-call results carry no such provenance.
                    helper_escape = true;
                }
                for callable in callables {
                    changed |= taint_callable_parameters(
                        callable,
                        &effective_arguments,
                        uncertain_positions,
                        bindings,
                        imported_bindings,
                        imported_binding_values,
                    )?;
                }
            }
        }
        Some("ReturnStatement") if reject_helper_escapes => {
            helper_escape = value
                .get("argument")
                .filter(|argument| !argument.is_null())
                .is_some_and(|argument| {
                    expression_has_import_binding_value(argument, bindings, imported_binding_values)
                });
        }
        Some("ThrowStatement" | "YieldExpression") if reject_helper_escapes => {
            helper_escape = value
                .get("argument")
                .filter(|argument| !argument.is_null())
                .is_some_and(|argument| {
                    expression_has_import_binding_value(argument, bindings, imported_binding_values)
                });
        }
        Some("ArrowFunctionExpression") if reject_helper_escapes => {
            helper_escape = value
                .get("body")
                .filter(|body| node_kind(body) != Some("BlockStatement"))
                .is_some_and(|body| {
                    expression_has_import_binding_value(body, bindings, imported_binding_values)
                });
        }
        Some("AssignmentPattern") if reject_helper_escapes => {
            helper_escape = value.get("right").is_some_and(|right| {
                expression_has_import_binding_value(right, bindings, imported_binding_values)
            });
        }
        Some("TaggedTemplateExpression") if reject_helper_escapes => {
            helper_escape = value
                .get("quasi")
                .and_then(|quasi| quasi.get("expressions"))
                .and_then(Value::as_array)
                .is_some_and(|expressions| {
                    expressions.iter().any(|expression| {
                        expression_has_import_binding_value(
                            expression,
                            bindings,
                            imported_binding_values,
                        )
                    })
                });
        }
        Some("ClassDeclaration" | "ClassExpression") if reject_helper_escapes => {
            // A subclass retains its superclass as the constructor's prototype, so exporting or
            // otherwise returning the subclass would expose the reviewed binding indirectly.
            helper_escape = value
                .get("superClass")
                .filter(|super_class| !super_class.is_null())
                .is_some_and(|super_class| {
                    expression_has_import_binding_value(
                        super_class,
                        bindings,
                        imported_binding_values,
                    )
                });
        }
        Some("ExportNamedDeclaration") if reject_helper_escapes => {
            if value.get("exportKind").and_then(Value::as_str) != Some("type") {
                helper_escape = if let Some(declaration) = value.get("declaration") {
                    declaration_has_import_binding_value(
                        declaration,
                        bindings,
                        imported_binding_values,
                    )?
                } else {
                    false
                } || value
                    .get("specifiers")
                    .and_then(Value::as_array)
                    .is_some_and(|specifiers| {
                        specifiers.iter().any(|specifier| {
                            specifier.get("exportKind").and_then(Value::as_str) != Some("type")
                                && specifier.get("local").is_some_and(|local| {
                                    expression_has_import_binding_value(
                                        local,
                                        bindings,
                                        imported_binding_values,
                                    )
                                })
                        })
                    });
            }
        }
        Some("ExportDefaultDeclaration" | "TSExportAssignment") if reject_helper_escapes => {
            helper_escape = if let Some(exported) =
                value.get("declaration").or_else(|| value.get("expression"))
            {
                expression_has_import_binding_value(exported, bindings, imported_binding_values)
                    || declaration_has_import_binding_value(
                        exported,
                        bindings,
                        imported_binding_values,
                    )?
            } else {
                true
            };
        }
        Some("PropertyDefinition" | "AccessorProperty") if reject_helper_escapes => {
            // A class-field initializer stores the imported capability on an instance or
            // constructor without a lexical alias that later export analysis can follow.
            helper_escape = value
                .get("value")
                .filter(|initializer| !initializer.is_null())
                .is_some_and(|initializer| {
                    expression_has_import_binding_value(
                        initializer,
                        bindings,
                        imported_binding_values,
                    )
                });
        }
        Some("JSXExpressionContainer" | "JSXSpreadAttribute" | "JSXSpreadChild")
            if reject_helper_escapes =>
        {
            helper_escape = value
                .get("expression")
                .or_else(|| value.get("argument"))
                .is_some_and(|expression| {
                    expression_has_import_binding_value(
                        expression,
                        bindings,
                        imported_binding_values,
                    )
                });
        }
        Some("JSXOpeningElement") if reject_helper_escapes => {
            helper_escape = value.get("name").is_none_or(|name| {
                jsx_element_name_has_import_binding_value(name, bindings, imported_binding_values)
            });
        }
        _ => {}
    }
    Ok((changed, helper_escape))
}

fn collect_import_propagation_nodes<'a>(value: &'a Value, nodes: &mut Vec<&'a Value>) {
    nodes.push(value);
    for child in ast_runtime_children(value) {
        collect_import_propagation_nodes(child, nodes);
    }
}

fn propagate_import_values(
    nodes: &[&Value],
    bindings: &BindingModel,
    imported_bindings: &mut BTreeSet<usize>,
    imported_binding_values: &mut BTreeSet<usize>,
    reject_helper_escapes: bool,
) -> Result<(bool, bool)> {
    let mut changed = false;
    let mut helper_escape = false;
    for value in nodes {
        let (node_changed, node_helper_escape) = propagate_import_value(
            value,
            bindings,
            imported_bindings,
            imported_binding_values,
            reject_helper_escapes,
        )?;
        changed |= node_changed;
        helper_escape |= node_helper_escape;
    }
    Ok((changed, helper_escape))
}

fn has_unsupported_import_member_access(
    value: &Value,
    bindings: &BindingModel,
    imported_bindings: &BTreeSet<usize>,
    forbidden_static_members: &[&str],
) -> bool {
    if matches!(
        node_kind(value),
        Some("MemberExpression" | "OptionalMemberExpression")
    ) && value.get("object").is_some_and(|object| {
        expression_has_import_value(object, bindings, imported_bindings, &mut BTreeSet::new())
    }) {
        let member = static_member_name(value);
        if member.is_some_and(|member| forbidden_static_members.contains(&member))
            || (value.get("computed").and_then(Value::as_bool) == Some(true) && member.is_none())
        {
            return true;
        }
    }
    ast_runtime_children(value).any(|child| {
        has_unsupported_import_member_access(
            child,
            bindings,
            imported_bindings,
            forbidden_static_members,
        )
    })
}

struct ImportSurfaceModel {
    ast: Value,
    bindings: BindingModel,
}

#[cfg(test)]
thread_local! {
    static IMPORT_SURFACE_CONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl ImportSurfaceModel {
    fn parse(module_key: &str, source: &str) -> Result<Self, ()> {
        #[cfg(test)]
        IMPORT_SURFACE_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
        let source_type = SourceType::from_path(Path::new(module_key)).map_err(|_| ())?;
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, source_type).parse();
        if !parsed.diagnostics.is_empty() {
            return Err(());
        }
        let ast = serde_json::from_str::<Value>(&parsed.program.to_estree_json(true, false))
            .map_err(|_| ())?;
        let bindings = BindingModel::new(&ast).map_err(|_| ())?;
        Ok(Self { ast, bindings })
    }
}

// Module keys identify immutable source within one analysis. Cache construction failures too,
// while keeping import provenance and policy decisions outside this source-only representation.
type ImportSurfaceModels = BTreeMap<String, Result<ImportSurfaceModel, ()>>;

fn import_has_unsupported_member_access(
    surface_models: &mut ImportSurfaceModels,
    module_key: &str,
    module: &LoadedModule,
    source: &str,
    reference: &ContextModuleReference,
    forbidden_static_members: &[&str],
    inspect_derived_values: bool,
    reject_helper_escapes: bool,
) -> bool {
    let Ok(ImportSurfaceModel { ast, bindings }) = surface_models
        .entry(module_key.to_string())
        .or_insert_with(|| ImportSurfaceModel::parse(module_key, source))
        .as_ref()
    else {
        return true;
    };
    let mut imported_bindings = module
        .summary
        .imports
        .values()
        .filter(|binding| {
            binding.specifier == reference.specifier
                && binding.start == reference.start
                && binding.end == reference.end
                && !binding.type_only
        })
        .filter_map(|binding| bindings.binding_at(&binding.local, reference.end))
        .collect::<BTreeSet<_>>();
    if imported_bindings.is_empty() {
        return true;
    }
    let mut imported_binding_values = imported_bindings.clone();
    // Replay the original runtime preorder: earlier nodes can taint bindings used later in the
    // same pass. Only immutable syntax is retained; each pass still recomputes provenance.
    let mut propagation_nodes = Vec::new();
    collect_import_propagation_nodes(ast, &mut propagation_nodes);
    // Binding provenance is monotonic. Follow local flow so custom handlers can inspect derived
    // values and generic modes can detect an exact binding that reaches a helper escape.
    loop {
        match propagate_import_values(
            &propagation_nodes,
            bindings,
            &mut imported_bindings,
            &mut imported_binding_values,
            reject_helper_escapes,
        ) {
            Ok((_, true)) => return true,
            Ok((true, false)) => {}
            Ok((false, false)) => break,
            Err(_) => return true,
        }
    }
    // Generic named-import policy constrains the imported capability and its aliases. A derived
    // member policy additionally constrains APIs on values derived from that capability.
    // A stateless reviewed function's result is ordinary caller data and must not inherit the
    // capability's member restrictions.
    let inspected_bindings = if inspect_derived_values {
        &imported_bindings
    } else {
        &imported_binding_values
    };
    has_unsupported_import_member_access(
        ast,
        bindings,
        inspected_bindings,
        forbidden_static_members,
    )
}

fn named_derived_members_surface_is_supported(
    surface_models: &mut ImportSurfaceModels,
    module_key: &str,
    module: &LoadedModule,
    source: &str,
    reference: &ContextModuleReference,
    allowed_imports: &[String],
    safe_members: &[String],
    forbidden_derived_members: &[String],
) -> bool {
    let forbidden_derived_members = forbidden_derived_members
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if reference.kind != "import"
        || import_has_unsupported_member_access(
            surface_models,
            module_key,
            module,
            source,
            reference,
            &forbidden_derived_members,
            true,
            false,
        )
    {
        return false;
    }
    let bindings = module
        .summary
        .imports
        .values()
        .filter(|binding| {
            binding.specifier == reference.specifier
                && binding.start == reference.start
                && binding.end == reference.end
                && !binding.type_only
        })
        .collect::<Vec<_>>();
    !bindings.is_empty()
        && bindings.iter().all(|binding| {
            allowed_imports
                .iter()
                .any(|allowed| allowed == &binding.imported)
                && module
                    .summary
                    .references
                    .iter()
                    .filter(|occurrence| occurrence.name == binding.local)
                    .all(|occurrence| {
                        first_member_after(source, occurrence.end).is_some_and(|member| {
                            safe_members.iter().any(|allowed| allowed == &member)
                        })
                    })
        })
}

fn generic_named_import_surface_is_supported(
    surface_models: &mut ImportSurfaceModels,
    module_key: &str,
    module: &LoadedModule,
    source: &str,
    reference: &ContextModuleReference,
    import_is_reviewed: impl Fn(&str) -> bool,
) -> bool {
    if reference.kind != "import" {
        return false;
    }
    let bindings = module
        .summary
        .imports
        .values()
        .filter(|binding| {
            binding.specifier == reference.specifier
                && binding.start == reference.start
                && binding.end == reference.end
                && !binding.type_only
        })
        .collect::<Vec<_>>();
    !bindings.is_empty()
        && bindings.iter().all(|binding| {
            binding.imported != "*"
                && binding.imported != "default"
                && import_is_reviewed(&binding.imported)
        })
        && !import_has_unsupported_member_access(
            surface_models,
            module_key,
            module,
            source,
            reference,
            &[],
            false,
            true,
        )
}

fn exact_static_call_root<'a>(call: &'a Value, members: &[String]) -> Option<&'a Value> {
    if node_kind(call) != Some("CallExpression")
        || call.get("optional").and_then(Value::as_bool) == Some(true)
    {
        return None;
    }
    let mut current = call.get("callee")?;
    for member in members.iter().rev() {
        if node_kind(current) != Some("MemberExpression")
            || current.get("computed").and_then(Value::as_bool) != Some(false)
            || current.get("optional").and_then(Value::as_bool) == Some(true)
            || current.get("property").and_then(identifier) != Some(member.as_str())
        {
            return None;
        }
        current = current.get("object")?;
    }
    identifier(current)?;
    Some(current)
}

fn collect_allowed_named_import_uses(
    value: &Value,
    bindings: &BindingModel,
    binding_index: usize,
    allow_instanceof: bool,
    static_calls: &[&ReviewedThirdPartyStaticCall],
    allowed: &mut BTreeSet<(u32, u32)>,
) -> Result<()> {
    if allow_instanceof
        && node_kind(value) == Some("BinaryExpression")
        && value.get("operator").and_then(Value::as_str) == Some("instanceof")
        && let Some(target) = value.get("right")
        && let Some(name) = identifier(target)
        && let (start, end) = node_span(target)?
        && bindings.binding_at(name, start) == Some(binding_index)
    {
        allowed.insert((start, end));
    }
    if node_kind(value) == Some("CallExpression") {
        for call in static_calls {
            let Some(root) = exact_static_call_root(value, &call.members) else {
                continue;
            };
            let Some(root_name) = identifier(root) else {
                continue;
            };
            let (start, end) = node_span(root)?;
            if bindings.binding_at(root_name, start) == Some(binding_index) {
                allowed.insert((start, end));
            }
        }
    }
    for child in ast_runtime_children(value) {
        collect_allowed_named_import_uses(
            child,
            bindings,
            binding_index,
            allow_instanceof,
            static_calls,
            allowed,
        )?;
    }
    Ok(())
}

fn named_import_uses_surface_is_supported(
    surface_models: &mut ImportSurfaceModels,
    module_key: &str,
    module: &LoadedModule,
    source: &str,
    reference: &ContextModuleReference,
    instanceof_targets: &[String],
    static_calls: &[ReviewedThirdPartyStaticCall],
) -> bool {
    if reference.kind != "import" {
        return false;
    }
    let Ok(ImportSurfaceModel {
        ast,
        bindings: binding_model,
    }) = surface_models
        .entry(module_key.to_string())
        .or_insert_with(|| ImportSurfaceModel::parse(module_key, source))
        .as_ref()
    else {
        return false;
    };
    let resolved_binding_facts = module
        .summary
        .resolved_binding_facts
        .iter()
        .map(|fact| ((fact.start, fact.end), fact.clone()))
        .collect::<BTreeMap<_, _>>();
    let import_bindings = module
        .summary
        .imports
        .values()
        .filter(|binding| {
            binding.specifier == reference.specifier
                && binding.start == reference.start
                && binding.end == reference.end
                && !binding.type_only
        })
        .collect::<Vec<_>>();
    !import_bindings.is_empty()
        && import_bindings.iter().all(|binding| {
            let Some(binding_index) = binding_model.binding_at(&binding.local, reference.end)
            else {
                return false;
            };
            let calls = static_calls
                .iter()
                .filter(|call| call.import_name == binding.imported)
                .collect::<Vec<_>>();
            let allow_instanceof = instanceof_targets.contains(&binding.imported);
            if !allow_instanceof && calls.is_empty() {
                return false;
            }
            let occurrences =
                binding_model.binding_references(binding_index, &resolved_binding_facts);
            let mut allowed = BTreeSet::new();
            if collect_allowed_named_import_uses(
                ast,
                binding_model,
                binding_index,
                allow_instanceof,
                &calls,
                &mut allowed,
            )
            .is_err()
            {
                return false;
            }
            !occurrences.is_empty()
                && occurrences.iter().all(|occurrence| {
                    occurrence.read
                        && !occurrence.write
                        && allowed.contains(&(occurrence.start, occurrence.end))
                })
        })
}

fn review_third_party_boundary(
    surface_models: &mut ImportSurfaceModels,
    module_key: &str,
    module: &LoadedModule,
    source: &str,
    reference: &ContextModuleReference,
    material: &ThirdPartyMaterial,
) -> ThirdPartyDisposition {
    review_third_party_boundary_in_policy(
        reviewed_third_party_policy(),
        surface_models,
        module_key,
        module,
        source,
        reference,
        material,
    )
}

fn review_third_party_boundary_in_policy(
    policy: &ReviewedThirdPartyPolicy,
    surface_models: &mut ImportSurfaceModels,
    module_key: &str,
    module: &LoadedModule,
    source: &str,
    reference: &ContextModuleReference,
    material: &ThirdPartyMaterial,
) -> ThirdPartyDisposition {
    if !material.unauthenticated_external_imports.is_empty() {
        return ThirdPartyDisposition::Unsupported(format!(
            "The package closure contains {} external import(s) other than node:* without authenticated resolved material.",
            material.unauthenticated_external_imports.len()
        ));
    }
    if !material.lock_complete {
        return ThirdPartyDisposition::Unsupported(
            "The package closure is not completely represented in package-lock.json.".to_string(),
        );
    }
    let Some(surface_policy) =
        reviewed_third_party_surface_in_policy(policy, &material.fingerprint)
    else {
        return ThirdPartyDisposition::Unsupported(
            "The exact package source and lock material has no reviewed context-reuse disposition."
                .to_string(),
        );
    };
    review_third_party_surface_policy(
        surface_models,
        module_key,
        module,
        source,
        reference,
        surface_policy,
    )
}

fn review_third_party_surface_policy(
    surface_models: &mut ImportSurfaceModels,
    module_key: &str,
    module: &LoadedModule,
    source: &str,
    reference: &ContextModuleReference,
    surface_policy: &ReviewedThirdPartySurfaceConfig,
) -> ThirdPartyDisposition {
    match &surface_policy.admission {
        ReviewedThirdPartyAdmission::Accept { .. }
            if generic_named_import_surface_is_supported(
                surface_models,
                module_key,
                module,
                source,
                reference,
                |_| true,
            ) =>
        {
            ThirdPartyDisposition::Accepted
        }
        ReviewedThirdPartyAdmission::Accept { .. } => ThirdPartyDisposition::Unsupported(
            "The imported dependency is not limited to direct named ESM bindings without dynamic property selection."
                .to_string(),
        ),
        ReviewedThirdPartyAdmission::Reject { reason } => {
            ThirdPartyDisposition::Unsupported(reason.clone())
        }
        ReviewedThirdPartyAdmission::NamedImports { exports, .. }
            if generic_named_import_surface_is_supported(
                surface_models,
                module_key,
                module,
                source,
                reference,
                |imported| exports.iter().any(|allowed| allowed.as_str() == imported),
            ) =>
        {
            ThirdPartyDisposition::Accepted
        }
        ReviewedThirdPartyAdmission::NamedImports { reason, .. } => {
            ThirdPartyDisposition::Unsupported(reason.clone())
        }
        ReviewedThirdPartyAdmission::NamedDerivedMembers {
            imports,
            members,
            forbidden_derived_members,
            ..
        } if named_derived_members_surface_is_supported(
            surface_models,
            module_key,
            module,
            source,
            reference,
            imports,
            members,
            forbidden_derived_members,
        ) => {
            ThirdPartyDisposition::Accepted
        }
        ReviewedThirdPartyAdmission::NamedDerivedMembers { reason, .. } => {
            ThirdPartyDisposition::Unsupported(reason.clone())
        }
        ReviewedThirdPartyAdmission::NamedImportUses {
            instanceof_targets,
            static_calls,
            ..
        } if named_import_uses_surface_is_supported(
            surface_models,
            module_key,
            module,
            source,
            reference,
            instanceof_targets,
            static_calls,
        ) => ThirdPartyDisposition::Accepted,
        ReviewedThirdPartyAdmission::NamedImportUses { reason, .. } => {
            ThirdPartyDisposition::Unsupported(reason.clone())
        }
    }
}

fn collect_pattern_bindings(
    pattern: &Value,
    suffix: &str,
    bindings: &mut Vec<PatternBinding>,
) -> Result<()> {
    match node_kind(pattern) {
        Some("Identifier") => {
            let (start, end) = node_span(pattern)?;
            bindings.push(PatternBinding {
                name: identifier(pattern)
                    .context("identifier pattern has no name")?
                    .to_string(),
                start,
                end,
                suffix: suffix.to_string(),
            });
        }
        Some("AssignmentPattern") => collect_pattern_bindings(
            pattern
                .get("left")
                .context("assignment pattern has no target")?,
            suffix,
            bindings,
        )?,
        Some("RestElement") => collect_pattern_bindings(
            pattern
                .get("argument")
                .context("rest pattern has no target")?,
            suffix,
            bindings,
        )?,
        Some("ArrayPattern") => {
            for (index, element) in pattern
                .get("elements")
                .and_then(Value::as_array)
                .context("array pattern has no elements")?
                .iter()
                .enumerate()
            {
                if !element.is_null() {
                    collect_pattern_bindings(element, &format!("{suffix}.{index}"), bindings)?;
                }
            }
        }
        Some("ObjectPattern") => {
            for property in pattern
                .get("properties")
                .and_then(Value::as_array)
                .context("object pattern has no properties")?
            {
                if node_kind(property) == Some("RestElement") {
                    collect_pattern_bindings(
                        property
                            .get("argument")
                            .context("object rest pattern has no target")?,
                        suffix,
                        bindings,
                    )?;
                    continue;
                }
                let property_name = property
                    .get("key")
                    .and_then(static_name)
                    .map(|name| format!("{suffix}.{name}"))
                    .unwrap_or_else(|| suffix.to_string());
                collect_pattern_bindings(
                    property
                        .get("value")
                        .context("object pattern property has no value")?,
                    &property_name,
                    bindings,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn pattern_contains_default_or_rest(pattern: &Value) -> bool {
    matches!(
        node_kind(pattern),
        Some("AssignmentPattern" | "RestElement")
    ) || ast_runtime_children(pattern).any(pattern_contains_default_or_rest)
}

fn pattern_suffix_fields(suffix: &str) -> Option<Vec<String>> {
    if suffix.is_empty() {
        return Some(Vec::new());
    }
    let fields = suffix
        .strip_prefix('.')?
        .split('.')
        .map(str::to_string)
        .collect::<Vec<_>>();
    fields
        .iter()
        .all(|field| !field.is_empty())
        .then_some(fields)
}

fn retained_receiver_functions(ast: &Value) -> Result<BTreeSet<(u32, u32)>> {
    let body = ast
        .get("body")
        .and_then(Value::as_array)
        .context("ESTree program has no body")?;
    let mut retained = BTreeSet::new();
    let mut retained_instance_classes = BTreeSet::new();
    for statement in body {
        let declaration = if node_kind(statement) == Some("ExportNamedDeclaration") {
            statement
                .get("declaration")
                .filter(|declaration| !declaration.is_null())
        } else {
            Some(statement)
        };
        let Some(declaration) = declaration else {
            continue;
        };
        if node_kind(declaration) != Some("VariableDeclaration") {
            continue;
        }
        for declarator in declaration
            .get("declarations")
            .and_then(Value::as_array)
            .context("variable declaration has no declarations")?
        {
            if let Some(initializer) = declarator
                .get("init")
                .filter(|initializer| !initializer.is_null())
            {
                collect_retained_object_receiver_functions(initializer, &mut retained)?;
                let initializer = unwrap_expression(initializer);
                if node_kind(initializer) == Some("NewExpression")
                    && let Some(class_name) = initializer
                        .get("callee")
                        .and_then(identifier)
                        .map(ToString::to_string)
                {
                    retained_instance_classes.insert(class_name);
                } else if let Some(callee) = initializer
                    .get("callee")
                    .map(unwrap_expression)
                    .filter(|callee| node_kind(callee) == Some("ClassExpression"))
                {
                    collect_retained_class_receiver_functions(callee, &mut retained)?;
                }
            }
        }
    }
    for statement in body {
        let declaration = if node_kind(statement) == Some("ExportNamedDeclaration") {
            statement
                .get("declaration")
                .filter(|declaration| !declaration.is_null())
        } else {
            Some(statement)
        };
        let Some(declaration) = declaration else {
            continue;
        };
        if node_kind(declaration) == Some("ClassDeclaration")
            && declaration
                .get("id")
                .and_then(identifier)
                .is_some_and(|name| retained_instance_classes.contains(name))
        {
            collect_retained_class_receiver_functions(declaration, &mut retained)?;
        } else if node_kind(declaration) == Some("VariableDeclaration") {
            for declarator in declaration
                .get("declarations")
                .and_then(Value::as_array)
                .context("variable declaration has no declarations")?
            {
                if declarator
                    .get("id")
                    .and_then(identifier)
                    .is_some_and(|name| retained_instance_classes.contains(name))
                    && let Some(initializer) = declarator
                        .get("init")
                        .map(unwrap_expression)
                        .filter(|initializer| node_kind(initializer) == Some("ClassExpression"))
                {
                    collect_retained_class_receiver_functions(initializer, &mut retained)?;
                }
            }
        }
    }
    Ok(retained)
}

fn collect_retained_object_receiver_functions(
    value: &Value,
    retained: &mut BTreeSet<(u32, u32)>,
) -> Result<()> {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("ObjectExpression") => {
            for property in value
                .get("properties")
                .and_then(Value::as_array)
                .context("object expression has no properties")?
            {
                if node_kind(property) != Some("Property") {
                    continue;
                }
                let Some(property_value) = property.get("value") else {
                    continue;
                };
                if node_kind(property_value) == Some("FunctionExpression") {
                    retained.insert(node_span(property_value)?);
                } else {
                    collect_retained_object_receiver_functions(property_value, retained)?;
                }
            }
        }
        Some("AssignmentExpression") => {
            for field in assignment_result_fields(value) {
                if let Some(result) = value.get(*field) {
                    collect_retained_object_receiver_functions(result, retained)?;
                }
            }
        }
        Some("ConditionalExpression" | "LogicalExpression") => {
            for field in ["consequent", "alternate", "left", "right"] {
                if let Some(result) = value.get(field) {
                    collect_retained_object_receiver_functions(result, retained)?;
                }
            }
        }
        Some("SequenceExpression") => {
            if let Some(result) = value
                .get("expressions")
                .and_then(Value::as_array)
                .and_then(|expressions| expressions.last())
            {
                collect_retained_object_receiver_functions(result, retained)?;
            }
        }
        Some("AwaitExpression") => {
            if let Some(result) = value.get("argument") {
                collect_retained_object_receiver_functions(result, retained)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_retained_class_receiver_functions(
    value: &Value,
    retained: &mut BTreeSet<(u32, u32)>,
) -> Result<()> {
    for element in value
        .get("body")
        .and_then(|body| body.get("body"))
        .and_then(Value::as_array)
        .context("class body has no elements")?
    {
        if element.get("static").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        match node_kind(element) {
            Some("MethodDefinition") => {
                if let Some(function) = element.get("value") {
                    retained.insert(node_span(function)?);
                }
            }
            Some("PropertyDefinition" | "AccessorProperty") => {
                if let Some(initializer) = element.get("value").filter(|value| !value.is_null()) {
                    retained.insert(node_span(initializer)?);
                }
                if let Some(function) = element.get("value").filter(|value| {
                    matches!(
                        node_kind(value),
                        Some("FunctionExpression" | "ArrowFunctionExpression")
                    )
                }) {
                    retained.insert(node_span(function)?);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn class_constructor_values(value: &Value) -> Result<Vec<Value>> {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("ClassExpression" | "ClassDeclaration") => Ok(class_constructor_functions(value)?
            .into_iter()
            .cloned()
            .collect()),
        Some("ConditionalExpression" | "LogicalExpression") => {
            let mut constructors = Vec::new();
            for field in ["consequent", "alternate", "left", "right"] {
                if let Some(branch) = value.get(field) {
                    constructors.extend(class_constructor_values(branch)?);
                }
            }
            Ok(constructors)
        }
        Some("SequenceExpression") => value
            .get("expressions")
            .and_then(Value::as_array)
            .and_then(|expressions| expressions.last())
            .map(class_constructor_values)
            .transpose()
            .map(|constructors| constructors.unwrap_or_default()),
        Some("AssignmentExpression") => {
            let mut constructors = Vec::new();
            for field in assignment_result_fields(value) {
                if let Some(result) = value.get(*field) {
                    constructors.extend(class_constructor_values(result)?);
                }
            }
            Ok(constructors)
        }
        Some("AwaitExpression") => value
            .get("argument")
            .map(class_constructor_values)
            .transpose()
            .map(|constructors| constructors.unwrap_or_default()),
        _ => Ok(Vec::new()),
    }
}

fn class_constructor_functions<'a>(value: &'a Value) -> Result<Vec<&'a Value>> {
    let value = unwrap_expression(value);
    let mut constructors = Vec::new();
    for element in value
        .get("body")
        .and_then(|body| body.get("body"))
        .and_then(Value::as_array)
        .context("class body has no elements")?
    {
        if node_kind(element) == Some("MethodDefinition")
            && element.get("static").and_then(Value::as_bool) != Some(true)
            && element.get("kind").and_then(Value::as_str) == Some("constructor")
            && let Some(function) = element.get("value")
        {
            constructors.push(function);
        }
    }
    Ok(constructors)
}

fn class_instance_initializers(value: &Value) -> Result<Vec<Value>> {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("ClassExpression" | "ClassDeclaration") => value
            .get("body")
            .and_then(|body| body.get("body"))
            .and_then(Value::as_array)
            .context("class body has no elements")
            .map(|elements| {
                elements
                    .iter()
                    .filter(|element| {
                        node_kind(element) == Some("PropertyDefinition")
                            && element.get("static").and_then(Value::as_bool) != Some(true)
                    })
                    .filter_map(|element| element.get("value"))
                    .filter(|initializer| !initializer.is_null())
                    .cloned()
                    .collect()
            }),
        Some("ConditionalExpression" | "LogicalExpression") => {
            let mut initializers = Vec::new();
            for field in ["consequent", "alternate", "left", "right"] {
                if let Some(branch) = value.get(field) {
                    initializers.extend(class_instance_initializers(branch)?);
                }
            }
            Ok(initializers)
        }
        Some("SequenceExpression") => value
            .get("expressions")
            .and_then(Value::as_array)
            .and_then(|expressions| expressions.last())
            .map(class_instance_initializers)
            .transpose()
            .map(|initializers| initializers.unwrap_or_default()),
        Some("AssignmentExpression") => {
            let mut initializers = Vec::new();
            for field in assignment_result_fields(value) {
                if let Some(result) = value.get(*field) {
                    initializers.extend(class_instance_initializers(result)?);
                }
            }
            Ok(initializers)
        }
        Some("AwaitExpression") => value
            .get("argument")
            .map(class_instance_initializers)
            .transpose()
            .map(|initializers| initializers.unwrap_or_default()),
        _ => Ok(Vec::new()),
    }
}

fn collect_property_values(
    value: &Value,
    prefix: &str,
    properties: &mut BTreeMap<String, Vec<PropertyValue>>,
) -> Result<()> {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("ObjectExpression") => {
            for property in value
                .get("properties")
                .and_then(Value::as_array)
                .context("object expression has no properties")?
            {
                if node_kind(property) == Some("SpreadElement") {
                    if let Some(argument) = property.get("argument") {
                        collect_property_values(argument, prefix, properties)?;
                    }
                    continue;
                }
                if node_kind(property) != Some("Property") {
                    continue;
                }
                let Some(name) = property.get("key").and_then(static_name) else {
                    continue;
                };
                let path = format!("{prefix}.{name}");
                let Some(property_value) = property.get("value") else {
                    continue;
                };
                if matches!(
                    node_kind(property_value),
                    Some("FunctionExpression" | "ArrowFunctionExpression")
                ) {
                    properties
                        .entry(path.clone())
                        .or_default()
                        .push(PropertyValue {
                            function: property_value.clone(),
                            accessor: matches!(
                                property.get("kind").and_then(Value::as_str),
                                Some("get" | "set")
                            ),
                        });
                } else {
                    collect_property_values(property_value, &path, properties)?;
                }
            }
        }
        Some("ClassExpression" | "ClassDeclaration") => {
            for element in value
                .get("body")
                .and_then(|body| body.get("body"))
                .and_then(Value::as_array)
                .context("class body has no elements")?
            {
                if element.get("static").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
                let Some(name) = element.get("key").and_then(static_name) else {
                    continue;
                };
                let path = format!("{prefix}.{name}");
                let Some(function) = element.get("value").filter(|value| {
                    matches!(
                        node_kind(value),
                        Some("FunctionExpression" | "ArrowFunctionExpression")
                    )
                }) else {
                    continue;
                };
                properties.entry(path).or_default().push(PropertyValue {
                    function: function.clone(),
                    accessor: matches!(
                        element.get("kind").and_then(Value::as_str),
                        Some("get" | "set")
                    ),
                });
            }
        }
        Some("ConditionalExpression" | "LogicalExpression") => {
            for field in ["consequent", "alternate", "left", "right"] {
                if let Some(branch) = value.get(field) {
                    collect_property_values(branch, prefix, properties)?;
                }
            }
        }
        Some("SequenceExpression") => {
            if let Some(result) = value
                .get("expressions")
                .and_then(Value::as_array)
                .and_then(|expressions| expressions.last())
            {
                collect_property_values(result, prefix, properties)?;
            }
        }
        Some("AssignmentExpression") => {
            for field in assignment_result_fields(value) {
                if let Some(result) = value.get(*field) {
                    collect_property_values(result, prefix, properties)?;
                }
            }
        }
        Some("AwaitExpression") => {
            if let Some(argument) = value.get("argument") {
                collect_property_values(argument, prefix, properties)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_property_alias_paths(
    value: &Value,
    prefix: &str,
    aliases: &mut BTreeMap<String, Vec<(String, u32)>>,
) -> Result<()> {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("ObjectExpression") => {
            for property in value
                .get("properties")
                .and_then(Value::as_array)
                .context("object expression has no properties")?
            {
                if node_kind(property) == Some("SpreadElement") {
                    if let Some(argument) = property.get("argument") {
                        collect_property_alias_paths(argument, prefix, aliases)?;
                    }
                    continue;
                }
                if node_kind(property) != Some("Property") {
                    continue;
                }
                let Some(name) = property.get("key").and_then(static_name) else {
                    continue;
                };
                let path = format!("{prefix}.{name}");
                let Some(property_value) = property.get("value") else {
                    continue;
                };
                let alias_position = node_span(property_value)?.0;
                let property_aliases = possible_alias_paths(property_value);
                if !property_aliases.is_empty() {
                    aliases.entry(path.clone()).or_default().extend(
                        property_aliases
                            .into_iter()
                            .map(|alias| (alias, alias_position)),
                    );
                }
                collect_property_alias_paths(property_value, &path, aliases)?;
            }
        }
        Some("ClassExpression" | "ClassDeclaration") => {
            for element in value
                .get("body")
                .and_then(|body| body.get("body"))
                .and_then(Value::as_array)
                .context("class body has no elements")?
            {
                if element.get("static").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
                let Some(name) = element.get("key").and_then(static_name) else {
                    continue;
                };
                let path = format!("{prefix}.{name}");
                let Some(property_value) = element
                    .get("value")
                    .filter(|property_value| !property_value.is_null())
                else {
                    continue;
                };
                let alias_position = node_span(property_value)?.0;
                let property_aliases = possible_alias_paths(property_value);
                if !property_aliases.is_empty() {
                    aliases.entry(path.clone()).or_default().extend(
                        property_aliases
                            .into_iter()
                            .map(|alias| (alias, alias_position)),
                    );
                }
                collect_property_alias_paths(property_value, &path, aliases)?;
            }
        }
        Some("ConditionalExpression" | "LogicalExpression") => {
            for field in ["consequent", "alternate", "left", "right"] {
                if let Some(branch) = value.get(field) {
                    collect_property_alias_paths(branch, prefix, aliases)?;
                }
            }
        }
        Some("SequenceExpression") => {
            if let Some(result) = value
                .get("expressions")
                .and_then(Value::as_array)
                .and_then(|expressions| expressions.last())
            {
                collect_property_alias_paths(result, prefix, aliases)?;
            }
        }
        Some("AssignmentExpression") => {
            for field in assignment_result_fields(value) {
                if let Some(result) = value.get(*field) {
                    collect_property_alias_paths(result, prefix, aliases)?;
                }
            }
        }
        Some("AwaitExpression") => {
            if let Some(argument) = value.get("argument") {
                collect_property_alias_paths(argument, prefix, aliases)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_destructured_property_alias_paths(
    pattern: &Value,
    value: &Value,
    aliases: &mut BTreeMap<String, Vec<(String, u32)>>,
) -> Result<()> {
    let pattern = unwrap_expression(pattern);
    let value = unwrap_expression(value);
    match node_kind(pattern) {
        Some("AssignmentPattern") => {
            if let Some(left) = pattern.get("left") {
                collect_destructured_property_alias_paths(left, value, aliases)?;
            }
        }
        Some("ObjectPattern") => {
            let Some(source_properties) = value.get("properties").and_then(Value::as_array) else {
                return Ok(());
            };
            for property in pattern
                .get("properties")
                .and_then(Value::as_array)
                .context("object pattern has no properties")?
            {
                if node_kind(property) == Some("RestElement") {
                    continue;
                }
                let Some(name) = property.get("key").and_then(static_name) else {
                    continue;
                };
                let Some(source_property) =
                    source_properties.iter().rev().find(|source_property| {
                        node_kind(source_property) == Some("Property")
                            && source_property.get("key").and_then(static_name).as_deref()
                                == Some(name.as_str())
                    })
                else {
                    continue;
                };
                let Some(target) = property.get("value") else {
                    continue;
                };
                let Some(source_value) = source_property.get("value") else {
                    continue;
                };
                collect_destructured_property_alias_paths(target, source_value, aliases)?;
            }
        }
        Some("ArrayPattern") => {
            let Some(source_elements) = value.get("elements").and_then(Value::as_array) else {
                return Ok(());
            };
            for (index, target) in pattern
                .get("elements")
                .and_then(Value::as_array)
                .context("array pattern has no elements")?
                .iter()
                .enumerate()
            {
                if target.is_null() {
                    continue;
                }
                let Some(source_value) =
                    source_elements.get(index).filter(|value| !value.is_null())
                else {
                    continue;
                };
                collect_destructured_property_alias_paths(target, source_value, aliases)?;
            }
        }
        Some("Identifier") => {
            if matches!(
                node_kind(value),
                Some("ObjectExpression" | "ClassExpression" | "ClassDeclaration")
            ) && let Some(name) = identifier(pattern)
            {
                collect_property_alias_paths(value, name, aliases)?;
            }
            let alias_position = node_span(value)?.0;
            let property_aliases = possible_alias_paths(value);
            if !property_aliases.is_empty() {
                let name = identifier(pattern).context("identifier pattern has no name")?;
                aliases.entry(name.to_string()).or_default().extend(
                    property_aliases
                        .into_iter()
                        .map(|alias| (alias, alias_position)),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn has_use_strict_directive(value: &Value) -> bool {
    ["directives", "body"].into_iter().any(|field| {
        value
            .get(field)
            .and_then(Value::as_array)
            .is_some_and(|statements| {
                statements.iter().any(|statement| {
                    statement.get("directive").and_then(Value::as_str) == Some("use strict")
                })
            })
    })
}

impl BindingModel {
    fn return_expressions(&self, span: (u32, u32), body: &Value) -> Rc<[Value]> {
        if let Some(expressions) = self.callable_return_expressions.borrow().get(&span) {
            return Rc::clone(expressions);
        }
        fn collect_returns(value: &Value, expressions: &mut Vec<Value>) {
            match node_kind(value) {
                Some("FunctionDeclaration" | "FunctionExpression" | "ArrowFunctionExpression") => {
                    return;
                }
                Some("ReturnStatement") => {
                    if let Some(argument) =
                        value.get("argument").filter(|argument| !argument.is_null())
                    {
                        expressions.push(argument.clone());
                    }
                    return;
                }
                _ => {}
            }
            for child in ast_runtime_children(value) {
                collect_returns(child, expressions);
            }
        }
        let mut expressions = Vec::new();
        if node_kind(body) == Some("BlockStatement") {
            collect_returns(body, &mut expressions);
        } else {
            expressions.push(body.clone());
        }
        // Callable spans identify immutable syntax within this model. Cache only return syntax:
        // imported binding sets grow during propagation and cycle outcomes depend on the caller.
        let expressions: Rc<[Value]> = expressions.into();
        self.callable_return_expressions
            .borrow_mut()
            .insert(span, Rc::clone(&expressions));
        expressions
    }

    fn new(ast: &Value) -> Result<Self> {
        Self::new_with_module_this_state(ast, false)
    }

    fn new_with_module_this_state(ast: &Value, module_this_state: bool) -> Result<Self> {
        let (start, end) = node_span(ast)?;
        let mut model = Self {
            scopes: vec![ContextScope {
                parent: None,
                bindings_by_name: BTreeMap::new(),
                start,
                end,
                depth: 0,
                function: true,
                // CommonJS modules execute inside an ordinary wrapper function. ESM modules do
                // not have an implicit `arguments` binding at top level.
                arguments_owner: module_this_state,
                module_scope: true,
                strict: !module_this_state || has_use_strict_directive(ast),
                // In CommonJS, top-level `this` is `module.exports` and therefore survives
                // module evaluation. ESM top-level `this` is not a retained application object.
                this_module_state: module_this_state,
            }],
            bindings: Vec::new(),
            callable_return_expressions: RefCell::new(BTreeMap::new()),
            retained_receiver_functions: retained_receiver_functions(ast)?,
            constructible_values: BTreeMap::new(),
            constructible_initializers: BTreeMap::new(),
            property_values: BTreeMap::new(),
            property_alias_paths: BTreeMap::new(),
            fresh_bindings: BTreeSet::new(),
            non_fresh_bindings: BTreeSet::new(),
            value_origins: BTreeMap::new(),
            direct_call_parameter_origins: BTreeMap::new(),
            reassigned_bindings: BTreeSet::new(),
        };
        // Function declarations are hoisted within their containing program/block. Register the
        // direct declarations before walking source order so a factory call that appears before
        // its declaration still resolves the callable that JavaScript invokes.
        model.collect_node(ast, 0, true)?;
        model.collect_assignment_aliases(ast)?;
        model.collect_fresh_bindings(ast)?;
        Ok(model)
    }

    fn collect_fresh_bindings(&mut self, value: &Value) -> Result<()> {
        if node_kind(value) == Some("VariableDeclarator")
            && let (Some(id), Some(name)) = (value.get("id"), value.get("id").and_then(identifier))
        {
            let binding_index = self.binding_at(name, node_span(id)?.0);
            if let Some(binding_index) = binding_index {
                let fresh = value
                    .get("init")
                    .filter(|initializer| !initializer.is_null())
                    .is_some_and(|initializer| {
                        self.value_is_fresh(initializer, &mut BTreeSet::new())
                    });
                if fresh && !self.non_fresh_bindings.contains(&binding_index) {
                    self.fresh_bindings.insert(binding_index);
                } else {
                    self.fresh_bindings.remove(&binding_index);
                    self.non_fresh_bindings.insert(binding_index);
                }
            }
        } else if node_kind(value) == Some("AssignmentExpression")
            && let (Some(left), Some(right)) = (value.get("left"), value.get("right"))
        {
            // Compound assignment can replace even a structurally fresh value (`0 ||= unknown`,
            // `object += unknown`). Keep freshness fail-closed unless the assignment is plain `=`
            // and the target is one direct identifier. Destructuring assignment can replace a
            // fresh slot with an arbitrary property value, so all destructured targets become
            // non-fresh even when the RHS expression itself is a fresh object literal.
            let mut targets = Vec::new();
            collect_pattern_bindings(left, "", &mut targets)?;
            let fresh = targets.len() == 1
                && targets[0].suffix.is_empty()
                && value.get("operator").and_then(Value::as_str) == Some("=")
                && self.value_is_fresh(right, &mut BTreeSet::new());
            for target in targets {
                let Some(binding_index) = self.binding_at(&target.name, target.start) else {
                    continue;
                };
                self.reassigned_bindings.insert(binding_index);
                if fresh && !self.non_fresh_bindings.contains(&binding_index) {
                    self.fresh_bindings.insert(binding_index);
                } else {
                    self.fresh_bindings.remove(&binding_index);
                    self.non_fresh_bindings.insert(binding_index);
                }
            }
            // A logical member assignment can retain an existing property value, and a plain
            // member assignment can install an unknown RHS. The containing local object therefore
            // cannot remain a freshness proof for a later member mutator unless a plain assignment
            // writes a structurally fresh RHS. Direct aliases denote the same object and must lose
            // freshness together; other alias paths stay dependent through
            // `binding_is_known_fresh` below.
            let member_assignment_is_fresh = value.get("operator").and_then(Value::as_str)
                == Some("=")
                && self.value_is_fresh(right, &mut BTreeSet::new());
            if !member_assignment_is_fresh
                && let Some(path) = expression_base_path(left)
                && let Some(root) = path.split('.').next()
                && let Some(position) = node_span(left).ok().map(|span| span.0)
                && let Some(binding_index) = self.binding_at(root, position)
            {
                self.invalidate_binding_and_direct_aliases(binding_index);
            }
        }
        match value {
            Value::Array(values) => {
                for child in values {
                    self.collect_fresh_bindings(child)?;
                }
            }
            Value::Object(object) => {
                for (key, child) in object {
                    if !matches!(key.as_str(), "loc" | "range" | "tokens" | "comments") {
                        self.collect_fresh_bindings(child)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn invalidate_binding_and_direct_aliases(&mut self, binding_index: usize) {
        let mut pending = VecDeque::from([binding_index]);
        let mut visited = BTreeSet::new();
        while let Some(binding_index) = pending.pop_front() {
            if !visited.insert(binding_index) {
                continue;
            }
            self.fresh_bindings.remove(&binding_index);
            self.non_fresh_bindings.insert(binding_index);

            // A direct alias denotes the same object, so an unknown member write through either
            // name invalidates the freshness proof for both. Property aliases are not equivalent
            // roots and stay directional.
            for alias_index in 0..self.bindings.len() {
                for (path, position) in &self.bindings[alias_index].alias_paths {
                    if path.contains('.') {
                        continue;
                    }
                    let Some(source_index) = self.binding_at(path, *position) else {
                        continue;
                    };
                    if alias_index == binding_index {
                        pending.push_back(source_index);
                    } else if source_index == binding_index {
                        pending.push_back(alias_index);
                    }
                }
            }
        }
    }

    fn value_is_fresh(&self, value: &Value, active: &mut BTreeSet<usize>) -> bool {
        let value = unwrap_expression(value);
        if self.value_is_structurally_fresh(value) {
            return true;
        }
        match node_kind(value) {
            Some("Identifier") => {
                let Some(name) = identifier(value) else {
                    return false;
                };
                let Some(position) = node_span(value).ok().map(|span| span.0) else {
                    return false;
                };
                let Some(binding_index) = self.binding_at(name, position) else {
                    return false;
                };
                if !active.insert(binding_index) {
                    return false;
                }
                let fresh = self.binding_is_known_fresh(binding_index, &mut BTreeSet::new());
                active.remove(&binding_index);
                fresh
            }
            Some("ConditionalExpression" | "LogicalExpression") => {
                ["consequent", "alternate", "left", "right"]
                    .into_iter()
                    .filter_map(|field| value.get(field))
                    .all(|branch| self.value_is_fresh(branch, active))
            }
            Some("SequenceExpression") => value
                .get("expressions")
                .and_then(Value::as_array)
                .and_then(|expressions| expressions.last())
                .is_some_and(|result| self.value_is_fresh(result, active)),
            Some("AssignmentExpression") => {
                value.get("operator").and_then(Value::as_str) == Some("=")
                    && value
                        .get("right")
                        .is_some_and(|right| self.value_is_fresh(right, active))
            }
            Some("AwaitExpression") => value
                .get("argument")
                .is_some_and(|argument| self.value_is_fresh(argument, active)),
            _ => false,
        }
    }

    fn collect_node(&mut self, value: &Value, scope: usize, program: bool) -> Result<()> {
        let Some(kind) = node_kind(value) else {
            return self.collect_children(value, scope);
        };
        if matches!(
            kind,
            "FunctionDeclaration" | "FunctionExpression" | "ArrowFunctionExpression"
        ) {
            if kind == "FunctionDeclaration"
                && let Some(identifier) = value.get("id").filter(|id| !id.is_null())
            {
                self.add_identifier_binding(identifier, scope, &[], std::slice::from_ref(value))?;
            }
            let this_module_state = self
                .retained_receiver_functions
                .contains(&node_span(value)?)
                || (kind == "ArrowFunctionExpression" && self.scopes[scope].this_module_state);
            let function_scope = self.add_scope(
                value,
                scope,
                true,
                this_module_state,
                kind != "ArrowFunctionExpression",
                self.scopes[scope].strict
                    || value.get("body").is_some_and(has_use_strict_directive),
            )?;
            if kind == "FunctionExpression"
                && let Some(identifier) = value.get("id").filter(|id| !id.is_null())
            {
                self.add_identifier_binding(
                    identifier,
                    function_scope,
                    &[],
                    std::slice::from_ref(value),
                )?;
            }
            for parameter in value
                .get("params")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                self.add_pattern_bindings(parameter, function_scope, &[], &[])?;
            }
            return self.collect_children(value, function_scope);
        }
        if matches!(kind, "ClassDeclaration" | "ClassExpression") {
            if kind == "ClassDeclaration"
                && let Some(identifier_node) = value.get("id").filter(|id| !id.is_null())
            {
                self.add_identifier_binding(identifier_node, scope, &[], &[])?;
                if let Some(name) = identifier(identifier_node) {
                    self.constructible_values
                        .entry(name.to_string())
                        .or_default()
                        .extend(class_constructor_values(value)?);
                    self.constructible_initializers
                        .entry(name.to_string())
                        .or_default()
                        .extend(class_instance_initializers(value)?);
                    collect_property_values(value, name, &mut self.property_values)?;
                    collect_property_alias_paths(value, name, &mut self.property_alias_paths)?;
                }
            }
            return self.collect_class(value, scope);
        }
        if kind == "BlockStatement" && !program {
            let block_scope = self.add_scope(
                value,
                scope,
                false,
                self.scopes[scope].this_module_state,
                false,
                self.scopes[scope].strict,
            )?;
            self.collect_hoisted_function_bindings(value, block_scope)?;
            if !self.scopes[block_scope].strict {
                // Annex B gives a sloppy-script block function a second var-like binding in the
                // containing function. Esbuild preserves that CommonJS behavior when it wraps the
                // source in strict ESM output, so calls after the block must follow the callable.
                let function_scope = self.nearest_function_scope(scope);
                self.collect_hoisted_function_bindings(value, function_scope)?;
            }
            return self.collect_children(value, block_scope);
        }
        if kind == "CatchClause" {
            let catch_scope = self.add_scope(
                value,
                scope,
                false,
                self.scopes[scope].this_module_state,
                false,
                self.scopes[scope].strict,
            )?;
            if let Some(parameter) = value.get("param").filter(|parameter| !parameter.is_null()) {
                self.add_pattern_bindings(parameter, catch_scope, &[], &[])?;
            }
            return self.collect_children(value, catch_scope);
        }
        if kind == "ImportDeclaration"
            && value.get("importKind").and_then(Value::as_str) != Some("type")
        {
            for specifier in value
                .get("specifiers")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                if specifier.get("importKind").and_then(Value::as_str) == Some("type") {
                    continue;
                }
                if let Some(local) = specifier.get("local") {
                    self.add_identifier_binding(local, scope, &[], &[])?;
                }
            }
        } else if kind == "VariableDeclaration" {
            let declaration_scope = if value.get("kind").and_then(Value::as_str) == Some("var") {
                self.nearest_function_scope(scope)
            } else {
                scope
            };
            for declarator in value
                .get("declarations")
                .and_then(Value::as_array)
                .context("variable declaration has no declarations")?
            {
                let initializer = declarator
                    .get("init")
                    .filter(|initializer| !initializer.is_null());
                let alias_position = initializer
                    .and_then(|initializer| node_span(initializer).ok())
                    .map_or(0, |span| span.0);
                let alias_paths = initializer
                    .map(possible_alias_paths)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|path| (path, alias_position))
                    .collect::<Vec<_>>();
                let mut callable_nodes = Vec::new();
                if let Some(initializer) = initializer {
                    self.collect_callable_result_function_nodes_with_bindings(
                        initializer,
                        false,
                        &mut callable_nodes,
                    )?;
                    collect_destructured_property_alias_paths(
                        declarator
                            .get("id")
                            .context("variable declarator has no binding")?,
                        initializer,
                        &mut self.property_alias_paths,
                    )?;
                }
                let callable_values = callable_nodes;
                if let (Some(name), Some(initializer)) =
                    (declarator.get("id").and_then(identifier), initializer)
                {
                    self.constructible_values
                        .entry(name.to_string())
                        .or_default()
                        .extend(class_constructor_values(initializer)?);
                    self.constructible_initializers
                        .entry(name.to_string())
                        .or_default()
                        .extend(class_instance_initializers(initializer)?);
                    collect_property_values(initializer, name, &mut self.property_values)?;
                    collect_property_alias_paths(
                        initializer,
                        name,
                        &mut self.property_alias_paths,
                    )?;
                }
                self.add_pattern_bindings(
                    declarator
                        .get("id")
                        .context("variable declarator has no binding")?,
                    declaration_scope,
                    &alias_paths,
                    &callable_values,
                )?;
                if let Some(initializer) = initializer {
                    self.record_pattern_value_origins(
                        declarator
                            .get("id")
                            .context("variable declarator has no binding")?,
                        initializer,
                    )?;
                }
            }
        } else if kind == "TSEnumDeclaration"
            && let Some(identifier) = value.get("id").filter(|id| !id.is_null())
        {
            self.add_identifier_binding(identifier, scope, &[], &[])?;
        }
        if kind == "Program" {
            self.collect_hoisted_function_bindings(value, scope)?;
        }
        self.collect_children(value, scope)
    }

    fn collect_hoisted_function_bindings(&mut self, value: &Value, scope: usize) -> Result<()> {
        let Some(body) = value.get("body").and_then(Value::as_array) else {
            return Ok(());
        };
        for statement in body {
            let declaration = match node_kind(statement) {
                Some("FunctionDeclaration") => Some(statement),
                Some("ExportNamedDeclaration" | "ExportDefaultDeclaration") => statement
                    .get("declaration")
                    .filter(|declaration| node_kind(declaration) == Some("FunctionDeclaration")),
                _ => None,
            };
            if let Some(declaration) = declaration
                && let Some(identifier) = declaration.get("id").filter(|id| !id.is_null())
            {
                self.add_identifier_binding(
                    identifier,
                    scope,
                    &[],
                    std::slice::from_ref(declaration),
                )?;
            }
        }
        Ok(())
    }

    fn collect_class(&mut self, value: &Value, scope: usize) -> Result<()> {
        for field in ["superClass", "decorators"] {
            if let Some(child) = value.get(field).filter(|child| !child.is_null()) {
                self.collect_node(child, scope, false)?;
            }
        }
        let retained_class = self.scopes[scope].module_scope;
        let elements = value
            .get("body")
            .and_then(|body| body.get("body"))
            .and_then(Value::as_array)
            .context("class body has no elements")?;
        for element in elements {
            let is_static = element.get("static").and_then(Value::as_bool) == Some(true);
            if element.get("computed").and_then(Value::as_bool) == Some(true)
                && let Some(key) = element.get("key")
            {
                self.collect_node(key, scope, false)?;
            }
            if let Some(decorators) = element.get("decorators") {
                self.collect_node(decorators, scope, false)?;
            }
            match node_kind(element) {
                Some("MethodDefinition") => {
                    if let Some(function) = element.get("value") {
                        let retained_receiver = self
                            .retained_receiver_functions
                            .contains(&node_span(function)?);
                        self.collect_function(
                            function,
                            scope,
                            (is_static && retained_class) || retained_receiver,
                        )?;
                    }
                }
                Some("PropertyDefinition" | "AccessorProperty") => {
                    if let Some(initializer) = element
                        .get("value")
                        .filter(|initializer| !initializer.is_null())
                    {
                        let initializer_scope = self.add_scope(
                            initializer,
                            scope,
                            !is_static,
                            self.retained_receiver_functions
                                .contains(&node_span(initializer)?)
                                || (is_static && retained_class),
                            false,
                            true,
                        )?;
                        self.collect_node(initializer, initializer_scope, false)?;
                    }
                }
                Some("StaticBlock") => {
                    let static_scope =
                        self.add_scope(element, scope, false, retained_class, false, true)?;
                    self.collect_children(element, static_scope)?;
                }
                _ => self.collect_node(element, scope, false)?,
            }
        }
        Ok(())
    }

    fn collect_function(
        &mut self,
        value: &Value,
        scope: usize,
        this_module_state: bool,
    ) -> Result<()> {
        let function_scope = self.add_scope(value, scope, true, this_module_state, true, true)?;
        if let Some(identifier) = value.get("id").filter(|id| !id.is_null()) {
            self.add_identifier_binding(
                identifier,
                function_scope,
                &[],
                std::slice::from_ref(value),
            )?;
        }
        for parameter in value
            .get("params")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            self.add_pattern_bindings(parameter, function_scope, &[], &[])?;
        }
        self.collect_children(value, function_scope)
    }

    fn collect_children(&mut self, value: &Value, scope: usize) -> Result<()> {
        match value {
            Value::Array(values) => {
                for child in values {
                    self.collect_node(child, scope, false)?;
                }
            }
            Value::Object(object) => {
                for (key, child) in object {
                    if !matches!(key.as_str(), "loc" | "range" | "tokens" | "comments") {
                        self.collect_node(child, scope, false)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn add_scope(
        &mut self,
        value: &Value,
        parent: usize,
        function: bool,
        this_module_state: bool,
        arguments_owner: bool,
        strict: bool,
    ) -> Result<usize> {
        let (start, end) = node_span(value)?;
        let id = self.scopes.len();
        self.scopes.push(ContextScope {
            parent: Some(parent),
            bindings_by_name: BTreeMap::new(),
            start,
            end,
            depth: self.scopes[parent].depth + 1,
            function,
            arguments_owner,
            module_scope: !function && self.scopes[parent].module_scope,
            strict,
            this_module_state,
        });
        Ok(id)
    }

    fn nearest_function_scope(&self, mut scope: usize) -> usize {
        loop {
            if self.scopes[scope].function {
                return scope;
            }
            scope = self.scopes[scope]
                .parent
                .expect("non-function scope must have a parent");
        }
    }

    fn add_identifier_binding(
        &mut self,
        identifier_node: &Value,
        scope: usize,
        alias_paths: &[(String, u32)],
        callable_values: &[Value],
    ) -> Result<()> {
        let name = identifier(identifier_node)
            .context("binding identifier has no name")?
            .to_string();
        self.add_binding(
            name,
            scope,
            node_span(identifier_node)?,
            alias_paths,
            callable_values,
        );
        Ok(())
    }

    fn add_pattern_bindings(
        &mut self,
        pattern: &Value,
        scope: usize,
        alias_paths: &[(String, u32)],
        callable_values: &[Value],
    ) -> Result<()> {
        let mut bindings = Vec::new();
        collect_pattern_bindings(pattern, "", &mut bindings)?;
        for binding in bindings {
            let binding_alias_paths = alias_paths
                .iter()
                .map(|(path, position)| (format!("{path}{}", binding.suffix), *position))
                .collect::<Vec<_>>();
            let binding_callable_values: &[Value] = if binding.suffix.is_empty() {
                callable_values
            } else {
                &[]
            };
            self.add_binding(
                binding.name,
                scope,
                (binding.start, binding.end),
                &binding_alias_paths,
                binding_callable_values,
            );
        }
        Ok(())
    }

    fn add_binding(
        &mut self,
        name: String,
        scope: usize,
        declaration: (u32, u32),
        alias_paths: &[(String, u32)],
        callable_values: &[Value],
    ) {
        // JavaScript `var` redeclarations (and function declarations sharing a `var` name) refer
        // to one hoisted slot. Merge same-scope records so a later declaration cannot hide an
        // earlier callable alias that executes before the redeclaration during module evaluation.
        if let Some(&index) = self.scopes[scope].bindings_by_name.get(&name) {
            let binding = &mut self.bindings[index];
            if !binding.declarations.contains(&declaration) {
                binding.declarations.push(declaration);
            }
            binding.alias_paths.extend(alias_paths.iter().cloned());
            binding
                .callable_values
                .extend(callable_values.iter().cloned());
            return;
        }
        self.scopes[scope]
            .bindings_by_name
            .insert(name.clone(), self.bindings.len());
        self.bindings.push(ContextBinding {
            name,
            module_state: self.scopes[scope].module_scope,
            declarations: vec![declaration],
            alias_paths: alias_paths.to_vec(),
            callable_values: callable_values.to_vec(),
        });
    }

    fn record_pattern_value_origins(&mut self, pattern: &Value, value: &Value) -> Result<()> {
        if pattern_contains_default_or_rest(pattern) {
            return Ok(());
        }
        let mut pattern_bindings = Vec::new();
        collect_pattern_bindings(pattern, "", &mut pattern_bindings)?;
        for pattern_binding in pattern_bindings {
            let Some(binding_index) = self.binding_at(&pattern_binding.name, pattern_binding.start)
            else {
                continue;
            };
            let Some(fields) = pattern_suffix_fields(&pattern_binding.suffix) else {
                continue;
            };
            self.value_origins
                .entry(binding_index)
                .or_default()
                .push(FreshValueOrigin {
                    value: value.clone(),
                    fields,
                });
        }
        Ok(())
    }

    fn add_direct_call_parameter_origins(
        &mut self,
        ast: &Value,
        resolved_binding_facts: &BTreeMap<(u32, u32), crate::ResolvedBindingFact>,
        exports: &BTreeMap<String, String>,
    ) -> Result<()> {
        for binding_index in 0..self.bindings.len() {
            if self
                .binding_references(binding_index, resolved_binding_facts)
                .iter()
                .any(|reference| reference.write)
            {
                self.reassigned_bindings.insert(binding_index);
            }
        }

        let mut direct_calls = BTreeMap::<usize, Vec<DirectCallArguments>>::new();
        let mut direct_call_references = BTreeMap::<usize, BTreeSet<(u32, u32)>>::new();
        self.collect_direct_calls(ast, &mut direct_calls, &mut direct_call_references)?;

        for (callable_binding_index, calls) in direct_calls {
            let callable_binding = &self.bindings[callable_binding_index];
            if callable_binding.module_state
                && exports
                    .values()
                    .any(|local_name| local_name == &callable_binding.name)
            {
                continue;
            }
            let allowed_references = direct_call_references
                .get(&callable_binding_index)
                .expect("direct call has no callee reference span");
            let references =
                self.binding_references(callable_binding_index, resolved_binding_facts);
            if references.is_empty()
                || references.iter().any(|reference| {
                    reference.write
                        || !reference.read
                        || !allowed_references.contains(&(reference.start, reference.end))
                })
            {
                continue;
            }

            let mut callables = callable_binding
                .callable_values
                .iter()
                .filter(|callable| {
                    self.callable_is_direct_binding_value(callable_binding_index, callable)
                })
                .collect::<Vec<_>>();
            callables.sort_by_key(|callable| node_span(callable).unwrap_or_default());
            callables.dedup_by_key(|callable| node_span(callable).unwrap_or_default());
            if callables.is_empty() {
                continue;
            }

            for callable in callables {
                let parameters = callable
                    .get("params")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                for (parameter_index, parameter) in parameters.iter().enumerate() {
                    if pattern_contains_default_or_rest(parameter)
                        || calls
                            .iter()
                            .any(|call| call.spread || parameter_index >= call.values.len())
                    {
                        continue;
                    }
                    let mut pattern_bindings = Vec::new();
                    collect_pattern_bindings(parameter, "", &mut pattern_bindings)?;
                    for pattern_binding in pattern_bindings {
                        let Some(parameter_binding_index) =
                            self.binding_at(&pattern_binding.name, pattern_binding.start)
                        else {
                            continue;
                        };
                        if self
                            .binding_references(parameter_binding_index, resolved_binding_facts)
                            .iter()
                            .any(|reference| reference.write)
                        {
                            continue;
                        }
                        let Some(fields) = pattern_suffix_fields(&pattern_binding.suffix) else {
                            continue;
                        };
                        self.direct_call_parameter_origins.insert(
                            parameter_binding_index,
                            calls
                                .iter()
                                .map(|call| FreshValueOrigin {
                                    value: call.values[parameter_index].clone(),
                                    fields: fields.clone(),
                                })
                                .collect(),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn binding_references<'a>(
        &self,
        binding_index: usize,
        resolved_binding_facts: &'a BTreeMap<(u32, u32), crate::ResolvedBindingFact>,
    ) -> Vec<&'a crate::ReferenceOccurrence> {
        let mut references = self.bindings[binding_index]
            .declarations
            .iter()
            .filter_map(|declaration| resolved_binding_facts.get(declaration))
            .flat_map(|binding| binding.references.iter())
            .collect::<Vec<_>>();
        references.sort_by_key(|reference| (reference.start, reference.end));
        references.dedup_by_key(|reference| (reference.start, reference.end));
        references
    }

    fn collect_direct_calls(
        &self,
        value: &Value,
        calls: &mut BTreeMap<usize, Vec<DirectCallArguments>>,
        call_references: &mut BTreeMap<usize, BTreeSet<(u32, u32)>>,
    ) -> Result<()> {
        if node_kind(value) == Some("CallExpression")
            && let Some(callee) = value.get("callee").map(unwrap_expression)
            && let Some(name) = identifier(callee)
            && let (start, end) = node_span(callee)?
            && let Some(binding_index) = self.binding_at(name, start)
        {
            let arguments = value
                .get("arguments")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            calls
                .entry(binding_index)
                .or_default()
                .push(DirectCallArguments {
                    values: arguments.to_vec(),
                    spread: arguments
                        .iter()
                        .any(|argument| node_kind(argument) == Some("SpreadElement")),
                });
            call_references
                .entry(binding_index)
                .or_default()
                .insert((start, end));
        }
        for child in ast_runtime_children(value) {
            self.collect_direct_calls(child, calls, call_references)?;
        }
        Ok(())
    }

    fn callable_is_direct_binding_value(&self, binding_index: usize, callable: &Value) -> bool {
        let callable = unwrap_expression(callable);
        if node_kind(callable) == Some("FunctionDeclaration") {
            return callable.get("id").and_then(identifier).and_then(|name| {
                node_span(callable)
                    .ok()
                    .and_then(|(start, _)| self.binding_at(name, start))
            }) == Some(binding_index);
        }
        let Ok(callable_span) = node_span(callable) else {
            return false;
        };
        self.value_origins
            .get(&binding_index)
            .into_iter()
            .flatten()
            .any(|origin| {
                origin.fields.is_empty()
                    && node_span(unwrap_expression(&origin.value)).ok() == Some(callable_span)
            })
    }

    // Resolve a callable returned by a local factory.  The ordinary binding model records direct
    // function literals and aliases, but a factory call such as `const initialize = make()` has
    // no expression path of its own.  Keep this structural step limited to known local callables;
    // arbitrary dispatch and cross-module calls remain outside the context-reuse proof.
    fn collect_callable_result_function_nodes_with_bindings(
        &self,
        value: &Value,
        constructible_only: bool,
        functions: &mut Vec<Value>,
    ) -> Result<()> {
        let mut active = BTreeSet::new();
        self.collect_callable_result_function_nodes_with_bindings_inner(
            value,
            constructible_only,
            functions,
            &mut active,
        )
    }

    fn collect_callable_result_function_nodes_with_bindings_inner(
        &self,
        value: &Value,
        constructible_only: bool,
        functions: &mut Vec<Value>,
        active: &mut BTreeSet<(u32, u32)>,
    ) -> Result<()> {
        let value = unwrap_expression(value);
        let resolved_callables = self.resolve_callable_values(value);
        if !resolved_callables.is_empty() {
            functions.extend(resolved_callables.into_iter().filter_map(|callable| {
                if matches!(
                    node_kind(callable),
                    Some("FunctionDeclaration" | "FunctionExpression")
                ) || (!constructible_only
                    && node_kind(callable) == Some("ArrowFunctionExpression"))
                {
                    Some(callable.clone())
                } else {
                    None
                }
            }));
            return Ok(());
        }
        let mut direct_functions = Vec::new();
        collect_callable_result_function_nodes(value, constructible_only, &mut direct_functions)?;
        functions.extend(direct_functions.into_iter().cloned());
        match node_kind(value) {
            Some("AssignmentExpression") => {
                for field in assignment_result_fields(value) {
                    let Some(child) = value.get(*field) else {
                        continue;
                    };
                    self.collect_callable_result_function_nodes_with_bindings_inner(
                        child,
                        constructible_only,
                        functions,
                        active,
                    )?;
                }
            }
            Some("AwaitExpression") => {
                if let Some(child) = value.get("argument") {
                    self.collect_callable_result_function_nodes_with_bindings_inner(
                        child,
                        constructible_only,
                        functions,
                        active,
                    )?;
                }
            }
            Some("ConditionalExpression" | "LogicalExpression") => {
                for field in ["consequent", "alternate", "left", "right"] {
                    if let Some(branch) = value.get(field) {
                        self.collect_callable_result_function_nodes_with_bindings_inner(
                            branch,
                            constructible_only,
                            functions,
                            active,
                        )?;
                    }
                }
            }
            Some("SequenceExpression") => {
                if let Some(result) = value
                    .get("expressions")
                    .and_then(Value::as_array)
                    .and_then(|expressions| expressions.last())
                {
                    self.collect_callable_result_function_nodes_with_bindings_inner(
                        result,
                        constructible_only,
                        functions,
                        active,
                    )?;
                }
            }
            Some("CallExpression") => {
                for (candidate, candidate_constructible_only) in
                    synchronously_invoked_callable_expressions(value, self)?
                {
                    if candidate_constructible_only {
                        continue;
                    }
                    for callable in self.resolve_callable_values(candidate) {
                        let span = node_span(callable)?;
                        if !active.insert(span) {
                            continue;
                        }
                        let mut returns = Vec::new();
                        collect_callable_return_values(callable, &mut returns)?;
                        for returned in returns {
                            self.collect_callable_result_function_nodes_with_bindings_inner(
                                returned,
                                constructible_only,
                                functions,
                                active,
                            )?;
                        }
                        active.remove(&span);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn collect_assignment_aliases(&mut self, value: &Value) -> Result<()> {
        if node_kind(value) == Some("AssignmentExpression")
            && matches!(
                value.get("operator").and_then(Value::as_str),
                Some("=" | "&&=" | "||=" | "??=")
            )
            && let (Some(left), Some(right)) = (value.get("left"), value.get("right"))
        {
            let alias_position = node_span(right)?.0;
            let alias_paths = possible_alias_paths(right);
            let mut callable_nodes = Vec::new();
            self.collect_callable_result_function_nodes_with_bindings(
                right,
                false,
                &mut callable_nodes,
            )?;
            let constructible_values = class_constructor_values(right)?;
            let constructible_initializers = class_instance_initializers(right)?;
            collect_destructured_property_alias_paths(left, right, &mut self.property_alias_paths)?;
            if let Some(path) = expression_path(left)
                && !alias_paths.is_empty()
            {
                self.property_alias_paths
                    .entry(path.clone())
                    .or_default()
                    .extend(
                        alias_paths
                            .iter()
                            .cloned()
                            .map(|alias| (alias, alias_position)),
                    );
            }
            if let Some(path) = expression_path(left)
                && matches!(
                    node_kind(unwrap_expression(right)),
                    Some("FunctionExpression" | "ArrowFunctionExpression")
                )
            {
                self.property_values
                    .entry(path)
                    .or_default()
                    .push(PropertyValue {
                        function: unwrap_expression(right).clone(),
                        accessor: false,
                    });
            }
            if !alias_paths.is_empty()
                || !callable_nodes.is_empty()
                || !constructible_values.is_empty()
                || !constructible_initializers.is_empty()
            {
                let mut targets = Vec::new();
                collect_pattern_bindings(left, "", &mut targets)?;
                for target in targets {
                    let Some(binding_index) = self.binding_at(&target.name, target.start) else {
                        continue;
                    };
                    self.bindings[binding_index].alias_paths.extend(
                        alias_paths
                            .iter()
                            .map(|path| (format!("{path}{}", target.suffix), alias_position)),
                    );
                    if target.suffix.is_empty() {
                        self.bindings[binding_index]
                            .callable_values
                            .extend(callable_nodes.iter().cloned());
                        self.constructible_values
                            .entry(target.name.clone())
                            .or_default()
                            .extend(constructible_values.iter().cloned());
                        self.constructible_initializers
                            .entry(target.name.clone())
                            .or_default()
                            .extend(constructible_initializers.iter().cloned());
                    }
                }
            }
        }
        match value {
            Value::Array(values) => {
                for child in values {
                    self.collect_assignment_aliases(child)?;
                }
            }
            Value::Object(object) => {
                for (key, child) in object {
                    if !matches!(key.as_str(), "loc" | "range" | "tokens" | "comments") {
                        self.collect_assignment_aliases(child)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn resolve_expression(&self, value: &Value) -> Option<ResolvedStatePath> {
        let value = unwrap_expression(value);
        if let Some(path) = expression_path(value).or_else(|| {
            matches!(
                node_kind(value),
                Some("MemberExpression" | "OptionalMemberExpression")
            )
            .then(|| value.get("object").and_then(expression_base_path))
            .flatten()
        }) {
            let position = node_span(value).ok()?.0;
            return Some(self.resolve_path(
                &path,
                position,
                &mut BTreeSet::new(),
                &mut BTreeSet::new(),
            ));
        }
        let fields: &[&str] = match node_kind(value) {
            Some("AssignmentExpression") => assignment_result_fields(value),
            Some("ConditionalExpression") => &["consequent", "alternate"],
            Some("LogicalExpression") => &["left", "right"],
            Some("AwaitExpression") => &["argument"],
            Some("SequenceExpression") => {
                return value
                    .get("expressions")
                    .and_then(Value::as_array)
                    .and_then(|expressions| expressions.last())
                    .and_then(|result| self.resolve_expression(result));
            }
            _ => return None,
        };
        let mut resolutions = fields
            .iter()
            .filter_map(|field| value.get(*field))
            .filter_map(|result| self.resolve_expression(result));
        let mut resolved = resolutions.next()?;
        for alternative in resolutions {
            if alternative.path != resolved.path {
                resolved.path.clear();
            }
            resolved.possible_paths.extend(alternative.possible_paths);
            resolved.module_state |= alternative.module_state;
            resolved.global_state |= alternative.global_state;
        }
        Some(resolved)
    }

    fn mutator_value_is_resolved_or_fresh(&self, value: &Value) -> bool {
        if let Some(resolved) = self.resolve_expression(value) {
            if resolved.module_state || resolved.global_state {
                return true;
            }
        }
        self.value_path_is_known_fresh(value, &[], &mut BTreeSet::new(), &mut BTreeSet::new())
    }

    fn value_path_is_known_fresh(
        &self,
        value: &Value,
        fields: &[String],
        active_paths: &mut BTreeSet<(usize, Vec<String>)>,
        active_bindings: &mut BTreeSet<usize>,
    ) -> bool {
        let value = unwrap_expression(value);
        match node_kind(value) {
            Some("Identifier") => {
                let Some(name) = identifier(value) else {
                    return false;
                };
                let Some(position) = node_span(value).ok().map(|span| span.0) else {
                    return false;
                };
                let Some(binding_index) = self.binding_at(name, position) else {
                    return false;
                };
                return self.binding_path_is_known_fresh(
                    binding_index,
                    fields,
                    active_paths,
                    active_bindings,
                );
            }
            Some("MemberExpression" | "OptionalMemberExpression") => {
                let Some(property) = value.get("property").and_then(static_name) else {
                    return false;
                };
                let Some(object) = value.get("object") else {
                    return false;
                };
                let mut nested_fields = Vec::with_capacity(fields.len() + 1);
                nested_fields.push(property);
                nested_fields.extend_from_slice(fields);
                return self.value_path_is_known_fresh(
                    object,
                    &nested_fields,
                    active_paths,
                    active_bindings,
                );
            }
            Some("ObjectExpression") if !fields.is_empty() => {
                let Some(properties) = value.get("properties").and_then(Value::as_array) else {
                    return false;
                };
                // A spread can overwrite an earlier key or provide an accessor for a missing key.
                // Keep object-path freshness closed unless every property is explicit.
                if properties
                    .iter()
                    .any(|property| node_kind(property) != Some("Property"))
                {
                    return false;
                }
                let Some(property) = properties.iter().rev().find(|property| {
                    property.get("key").and_then(static_name).as_deref() == Some(fields[0].as_str())
                }) else {
                    return false;
                };
                if property.get("kind").and_then(Value::as_str) != Some("init")
                    || property.get("method").and_then(Value::as_bool) == Some(true)
                {
                    return false;
                }
                let Some(property_value) = property.get("value") else {
                    return false;
                };
                return self.value_path_is_known_fresh(
                    property_value,
                    &fields[1..],
                    active_paths,
                    active_bindings,
                );
            }
            Some("ConditionalExpression" | "LogicalExpression") => {
                return ["consequent", "alternate", "left", "right"]
                    .into_iter()
                    .filter_map(|field| value.get(field))
                    .all(|branch| {
                        self.value_path_is_known_fresh(
                            branch,
                            fields,
                            active_paths,
                            active_bindings,
                        )
                    });
            }
            Some("SequenceExpression") => {
                return value
                    .get("expressions")
                    .and_then(Value::as_array)
                    .and_then(|expressions| expressions.last())
                    .is_some_and(|result| {
                        self.value_path_is_known_fresh(
                            result,
                            fields,
                            active_paths,
                            active_bindings,
                        )
                    });
            }
            Some("AssignmentExpression") => {
                let result_fields = assignment_result_fields(value);
                return !result_fields.is_empty()
                    && result_fields.iter().all(|field| {
                        value.get(*field).is_some_and(|result| {
                            self.value_path_is_known_fresh(
                                result,
                                fields,
                                active_paths,
                                active_bindings,
                            )
                        })
                    });
            }
            Some("AwaitExpression") => {
                return value.get("argument").is_some_and(|argument| {
                    self.value_path_is_known_fresh(argument, fields, active_paths, active_bindings)
                });
            }
            _ => {}
        }
        fields.is_empty() && self.value_is_structurally_fresh(value)
    }

    fn binding_path_is_known_fresh(
        &self,
        binding_index: usize,
        fields: &[String],
        active_paths: &mut BTreeSet<(usize, Vec<String>)>,
        active_bindings: &mut BTreeSet<usize>,
    ) -> bool {
        let binding = &self.bindings[binding_index];
        if binding.module_state
            || self.non_fresh_bindings.contains(&binding_index)
            || self.reassigned_bindings.contains(&binding_index)
        {
            return false;
        }
        let parameter_origins = self.direct_call_parameter_origins.get(&binding_index);
        if parameter_origins.is_none()
            && !self.binding_is_known_fresh(binding_index, &mut BTreeSet::new())
        {
            return false;
        }
        if parameter_origins.is_none() && fields.is_empty() {
            return true;
        }

        let active_key = (binding_index, fields.to_vec());
        if !active_paths.insert(active_key.clone()) {
            return false;
        }
        // Exact paths stay distinct, while one lexical binding also terminates aliases such as
        // `current = current.value` whose suffix would otherwise grow without bound.
        if !active_bindings.insert(binding_index) {
            active_paths.remove(&active_key);
            return false;
        }
        let origins = parameter_origins.or_else(|| self.value_origins.get(&binding_index));
        let fresh = origins.is_some_and(|origins| {
            !origins.is_empty()
                && origins.iter().all(|origin| {
                    let mut origin_fields = origin.fields.clone();
                    origin_fields.extend_from_slice(fields);
                    self.value_path_is_known_fresh(
                        &origin.value,
                        &origin_fields,
                        active_paths,
                        active_bindings,
                    )
                })
        });
        active_bindings.remove(&binding_index);
        active_paths.remove(&active_key);
        fresh
    }

    fn binding_is_known_fresh(&self, binding_index: usize, active: &mut BTreeSet<usize>) -> bool {
        if !active.insert(binding_index) {
            return false;
        }
        let binding = &self.bindings[binding_index];
        let fresh = self.fresh_bindings.contains(&binding_index)
            && !self.non_fresh_bindings.contains(&binding_index)
            && binding.alias_paths.iter().all(|(path, position)| {
                let root = path.split('.').next().unwrap_or(path);
                self.binding_at(root, *position)
                    .is_none_or(|alias_index| self.binding_is_known_fresh(alias_index, active))
            });
        active.remove(&binding_index);
        fresh
    }

    // A constructor name is fresh only when every resolved path is an unshadowed global
    // constructor.  Treating a local `Map` (or a mixed alias after reassignment) as the built-in
    // solely from its spelling would let a retained object escape the unresolved-target check.
    fn value_is_structurally_fresh(&self, value: &Value) -> bool {
        let value = unwrap_expression(value);
        match node_kind(value) {
            Some(
                "ArrayExpression"
                | "ObjectExpression"
                | "FunctionExpression"
                | "ArrowFunctionExpression"
                | "ClassExpression"
                | "RegExpLiteral"
                | "Literal",
            ) => true,
            Some("NewExpression") => {
                let Some(callee) = value.get("callee") else {
                    return false;
                };
                let Some(resolved) = self.resolve_expression(callee) else {
                    return false;
                };
                resolved.global_state
                    && !resolved.module_state
                    && !resolved.possible_paths.is_empty()
                    && resolved.possible_paths.iter().all(|path| {
                        is_known_fresh_constructor(
                            path.strip_prefix("globalThis.").unwrap_or(path).to_string(),
                        )
                    })
            }
            Some("ConditionalExpression" | "LogicalExpression") => {
                ["consequent", "alternate", "left", "right"]
                    .into_iter()
                    .filter_map(|field| value.get(field))
                    .all(|branch| self.value_is_structurally_fresh(branch))
            }
            Some("SequenceExpression") => value
                .get("expressions")
                .and_then(Value::as_array)
                .and_then(|expressions| expressions.last())
                .is_some_and(|result| self.value_is_structurally_fresh(result)),
            Some("AssignmentExpression") => {
                value.get("operator").and_then(Value::as_str) == Some("=")
                    && value
                        .get("right")
                        .is_some_and(|right| self.value_is_structurally_fresh(right))
            }
            _ => false,
        }
    }

    fn path_resolves_global_require(
        &self,
        path: &str,
        position: u32,
        active_paths: &mut BTreeSet<(String, u32)>,
        active_bindings: &mut BTreeSet<usize>,
    ) -> bool {
        let direct_global = (path == "globalThis.require"
            && self.binding_at("globalThis", position).is_none())
            || (path == "module.require" && self.binding_at("module", position).is_none())
            || (path == "require" && self.binding_at("require", position).is_none());
        if direct_global {
            return true;
        }
        if !active_paths.insert((path.to_string(), position)) {
            return false;
        }
        let (root, suffix) = path
            .split_once('.')
            .map_or((path, ""), |(root, suffix)| (root, suffix));
        let binding_index = self.binding_at(root, position);
        if self
            .property_alias_paths
            .get(path)
            .into_iter()
            .flatten()
            .any(|(alias, alias_position)| {
                // Property aliases are keyed by the textual root path. Keep a shadowed local
                // object from inheriting aliases recorded for a different lexical binding.
                self.binding_at(root, *alias_position) == binding_index
                    && self.path_resolves_global_require(
                        alias,
                        *alias_position,
                        active_paths,
                        active_bindings,
                    )
            })
        {
            active_paths.remove(&(path.to_string(), position));
            return true;
        }
        if let Some(binding_index) = binding_index
            // An assignment such as `current = current.cause` creates an alias that grows the
            // textual path forever. Property aliases above remain path-sensitive, but revisiting
            // one lexical binding cannot reveal a new binding-alias origin on this branch.
            && active_bindings.insert(binding_index)
        {
            let binding = &self.bindings[binding_index];
            let resolves = binding.alias_paths.iter().any(|(alias, alias_position)| {
                let alias = if suffix.is_empty() {
                    alias.clone()
                } else {
                    format!("{alias}.{suffix}")
                };
                self.path_resolves_global_require(
                    &alias,
                    *alias_position,
                    active_paths,
                    active_bindings,
                )
            });
            active_bindings.remove(&binding_index);
            if resolves {
                active_paths.remove(&(path.to_string(), position));
                return true;
            }
        }
        active_paths.remove(&(path.to_string(), position));
        false
    }

    fn is_local_identifier(&self, value: &Value) -> bool {
        let value = unwrap_expression(value);
        let Some(name) = identifier(value) else {
            return false;
        };
        let Some(position) = node_span(value).ok().map(|span| span.0) else {
            return false;
        };
        self.binding_at(name, position)
            .is_some_and(|index| !self.bindings[index].module_state)
    }

    fn resolve_path(
        &self,
        path: &str,
        position: u32,
        active_paths: &mut BTreeSet<(usize, String)>,
        active_bindings: &mut BTreeSet<usize>,
    ) -> ResolvedStatePath {
        let (root, suffix) = path
            .split_once('.')
            .map_or((path, ""), |(root, suffix)| (root, suffix));
        if root == "this" {
            let scope = self.scope_at(position);
            return ResolvedStatePath {
                path: path.to_string(),
                possible_paths: BTreeSet::from([path.to_string()]),
                module_state: self.scopes[scope].this_module_state,
                global_state: false,
            };
        }
        if root == "arguments" && self.binding_at(root, position).is_none() {
            // `arguments` is an implicit binding owned by ordinary functions, including the
            // CommonJS module wrapper. Arrow functions inherit the nearest owner. An ESM module
            // has no owner, so preserve the ordinary unresolved-global behavior there.
            if let Some(module_state) = self.arguments_state(position) {
                return ResolvedStatePath {
                    path: path.to_string(),
                    possible_paths: BTreeSet::from([path.to_string()]),
                    module_state,
                    global_state: false,
                };
            }
        }
        let Some(binding_index) = self.binding_at(root, position) else {
            return ResolvedStatePath {
                path: path.to_string(),
                possible_paths: BTreeSet::from([path.to_string()]),
                module_state: false,
                // Oxc leaves every value reference without a lexical binding on the global
                // environment. Preserve that provenance instead of maintaining an incomplete
                // list of built-ins or inferring it later from a shadowable identifier name.
                // The immutable primitive globals cannot retain a write through a local value
                // alias, so they must not turn `condition ? undefined : []` into global state.
                global_state: !matches!(root, "undefined" | "NaN" | "Infinity"),
            };
        };
        let binding = &self.bindings[binding_index];
        let active_key = (binding_index, path.to_string());
        if !active_paths.insert(active_key.clone()) {
            return ResolvedStatePath {
                path: path.to_string(),
                possible_paths: BTreeSet::from([path.to_string()]),
                module_state: binding.module_state,
                global_state: false,
            };
        }
        let mut resolved_aliases = self
            .property_alias_paths
            .get(path)
            .into_iter()
            .flatten()
            .filter(|(_, alias_position)| {
                // Property aliases share a textual path across the module. Only provenance
                // recorded for this lexical root may affect the resolved global or module value.
                self.binding_at(root, *alias_position) == Some(binding_index)
            })
            .map(|(alias_path, alias_position)| {
                self.resolve_path(alias_path, *alias_position, active_paths, active_bindings)
            })
            .collect::<Vec<_>>();
        // Binding aliases may append an existing suffix and revisit the same lexical binding with
        // a longer path forever, as in `current = current.cause`. Exact property aliases above
        // remain path-sensitive because they can reveal a callable or state origin at that path.
        if active_bindings.insert(binding_index) {
            resolved_aliases.extend(binding.alias_paths.iter().map(
                |(alias_path, alias_position)| {
                    let mut resolved = self.resolve_path(
                        alias_path,
                        *alias_position,
                        active_paths,
                        active_bindings,
                    );
                    if !suffix.is_empty() {
                        resolved.path.push('.');
                        resolved.path.push_str(suffix);
                        resolved.possible_paths = resolved
                            .possible_paths
                            .into_iter()
                            .map(|path| format!("{path}.{suffix}"))
                            .collect();
                    }
                    resolved
                },
            ));
            active_bindings.remove(&binding_index);
        }
        if !resolved_aliases.is_empty() {
            active_paths.remove(&active_key);
            let mut resolved = resolved_aliases
                .pop()
                .expect("non-empty alias paths produced no resolved aliases");
            for alias in resolved_aliases {
                if alias.path != resolved.path {
                    resolved.path = path.to_string();
                }
                resolved.possible_paths.extend(alias.possible_paths);
                resolved.module_state |= alias.module_state;
                resolved.global_state |= alias.global_state;
            }
            // Alias provenance describes the assigned value, but it does not shorten the lifetime
            // of the slot that retains that value. A write through a module binding remains a
            // module-state write even when the latest assigned value came from a local parameter.
            resolved.module_state |= binding.module_state;
            return resolved;
        }
        active_paths.remove(&active_key);
        ResolvedStatePath {
            path: path.to_string(),
            possible_paths: BTreeSet::from([path.to_string()]),
            module_state: binding.module_state,
            global_state: false,
        }
    }

    fn resolve_callable_values(&self, value: &Value) -> Vec<&Value> {
        let value = unwrap_expression(value);
        let Some(path) = expression_path(value) else {
            return Vec::new();
        };
        let Some(position) = node_span(value).ok().map(|span| span.0) else {
            return Vec::new();
        };
        self.resolve_callable_path(&path, position, &mut BTreeSet::new(), &mut BTreeSet::new())
    }

    fn resolve_constructible_values(&self, value: &Value) -> Vec<&Value> {
        let value = unwrap_expression(value);
        let Some(path) = expression_path(value) else {
            return Vec::new();
        };
        let Some(position) = node_span(value).ok().map(|span| span.0) else {
            return Vec::new();
        };
        self.resolve_constructible_path(&path, position, &mut BTreeSet::new())
    }

    fn resolve_constructible_initializers(&self, value: &Value) -> Vec<&Value> {
        let value = unwrap_expression(value);
        let Some(path) = expression_path(value) else {
            return Vec::new();
        };
        let Some(position) = node_span(value).ok().map(|span| span.0) else {
            return Vec::new();
        };
        self.resolve_constructible_initializers_path(&path, position, &mut BTreeSet::new())
    }

    fn resolve_constructible_initializers_path(
        &self,
        path: &str,
        position: u32,
        active: &mut BTreeSet<usize>,
    ) -> Vec<&Value> {
        if path.contains('.') {
            return Vec::new();
        }
        let Some(binding_index) = self.binding_at(path, position) else {
            return self
                .constructible_initializers
                .get(path)
                .map(|values| {
                    values
                        .iter()
                        .filter(|initializer| {
                            self.constructible_value_matches_binding(path, position, initializer)
                        })
                        .collect()
                })
                .unwrap_or_default();
        };
        if !active.insert(binding_index) {
            return Vec::new();
        }
        let binding = &self.bindings[binding_index];
        let mut values = self
            .constructible_initializers
            .get(path)
            .into_iter()
            .flat_map(|values| values.iter())
            .filter(|initializer| {
                self.constructible_value_matches_binding(path, position, initializer)
            })
            .collect::<Vec<_>>();
        for (alias_path, alias_position) in &binding.alias_paths {
            values.extend(self.resolve_constructible_initializers_path(
                alias_path,
                *alias_position,
                active,
            ));
        }
        active.remove(&binding_index);
        values
    }

    fn resolve_constructible_path(
        &self,
        path: &str,
        position: u32,
        active: &mut BTreeSet<usize>,
    ) -> Vec<&Value> {
        if path.contains('.') {
            return Vec::new();
        }
        let Some(binding_index) = self.binding_at(path, position) else {
            return self
                .constructible_values
                .get(path)
                .map(|values| {
                    values
                        .iter()
                        .filter(|constructor| {
                            self.constructible_value_matches_binding(path, position, constructor)
                        })
                        .collect()
                })
                .unwrap_or_default();
        };
        if !active.insert(binding_index) {
            return Vec::new();
        }
        let binding = &self.bindings[binding_index];
        let mut values = self
            .constructible_values
            .get(path)
            .into_iter()
            .flat_map(|values| values.iter())
            .filter(|constructor| {
                self.constructible_value_matches_binding(path, position, constructor)
            })
            .collect::<Vec<_>>();
        for (alias_path, alias_position) in &binding.alias_paths {
            values.extend(self.resolve_constructible_path(alias_path, *alias_position, active));
        }
        active.remove(&binding_index);
        values
    }

    fn resolve_accessor_values(&self, value: &Value) -> Vec<&Value> {
        let value = unwrap_expression(value);
        let Some(path) = expression_path(value) else {
            return Vec::new();
        };
        let Some(position) = node_span(value).ok().map(|span| span.0) else {
            return Vec::new();
        };
        self.resolve_property_path(&path, position, &mut BTreeSet::new())
            .into_iter()
            .filter(|property| property.accessor)
            .map(|property| &property.function)
            .collect()
    }

    fn resolve_property_path(
        &self,
        path: &str,
        position: u32,
        active: &mut BTreeSet<usize>,
    ) -> Vec<&PropertyValue> {
        let (root, suffix) = path
            .split_once('.')
            .map_or((path, ""), |(root, suffix)| (root, suffix));
        let mut values = self
            .property_values
            .get(path)
            .into_iter()
            .flat_map(|values| values.iter())
            .filter(|property| {
                self.property_value_matches_binding(root, position, &property.function)
            })
            .collect::<Vec<_>>();
        let Some(binding_index) = self.binding_at(root, position) else {
            return values;
        };
        if !active.insert(binding_index) {
            return values;
        }
        let binding = &self.bindings[binding_index];
        for (alias_path, alias_position) in &binding.alias_paths {
            let alias_path = if suffix.is_empty() {
                alias_path.clone()
            } else {
                format!("{alias_path}.{suffix}")
            };
            values.extend(self.resolve_property_path(&alias_path, *alias_position, active));
        }
        active.remove(&binding_index);
        values
    }

    fn resolve_callable_path(
        &self,
        path: &str,
        position: u32,
        active_paths: &mut BTreeSet<(usize, String)>,
        active_bindings: &mut BTreeSet<usize>,
    ) -> Vec<&Value> {
        let (root, suffix) = path
            .split_once('.')
            .map_or((path, ""), |(root, suffix)| (root, suffix));
        let mut values = self
            .property_values
            .get(path)
            .into_iter()
            .flat_map(|values| values.iter())
            .filter(|property| {
                self.property_value_matches_binding(root, position, &property.function)
            })
            .map(|property| &property.function)
            .collect::<Vec<_>>();
        let Some(binding_index) = self.binding_at(root, position) else {
            return values;
        };
        let active_key = (binding_index, path.to_string());
        if !active_paths.insert(active_key.clone()) {
            return values;
        }
        let binding = &self.bindings[binding_index];
        values.extend(
            self.property_alias_paths
                .get(path)
                .into_iter()
                .flatten()
                .filter(|(_, alias_position)| {
                    self.binding_at(root, *alias_position) == Some(binding_index)
                })
                .flat_map(|(alias_path, alias_position)| {
                    self.resolve_callable_path(
                        alias_path,
                        *alias_position,
                        active_paths,
                        active_bindings,
                    )
                }),
        );
        if suffix.is_empty() {
            values.extend(binding.callable_values.iter());
        }
        // Keep exact property aliases path-sensitive while stopping suffix-growing cycles through
        // one lexical binding's value aliases.
        if active_bindings.insert(binding_index) {
            for (alias_path, alias_position) in &binding.alias_paths {
                let alias_path = if suffix.is_empty() {
                    alias_path.clone()
                } else {
                    format!("{alias_path}.{suffix}")
                };
                values.extend(self.resolve_callable_path(
                    &alias_path,
                    *alias_position,
                    active_paths,
                    active_bindings,
                ));
            }
            active_bindings.remove(&binding_index);
        }
        active_paths.remove(&active_key);
        values
    }

    fn property_value_matches_binding(&self, root: &str, position: u32, function: &Value) -> bool {
        let Some(function_position) = node_span(function).ok().map(|span| span.0) else {
            return false;
        };
        self.binding_at(root, position) == self.binding_at(root, function_position)
    }

    fn constructible_value_matches_binding(
        &self,
        root: &str,
        position: u32,
        value: &Value,
    ) -> bool {
        let Some(value_position) = node_span(value).ok().map(|span| span.0) else {
            return false;
        };
        self.binding_at(root, position) == self.binding_at(root, value_position)
    }

    fn binding_at(&self, name: &str, position: u32) -> Option<usize> {
        let mut scope = self.scope_at(position);
        loop {
            if let Some(&index) = self.scopes[scope].bindings_by_name.get(name) {
                return Some(index);
            }
            scope = self.scopes[scope].parent?;
        }
    }

    fn scope_at(&self, position: u32) -> usize {
        self.scopes
            .iter()
            .enumerate()
            .filter(|(_, scope)| scope.start <= position && position <= scope.end)
            .max_by_key(|(_, scope)| scope.depth)
            .map(|(index, _)| index)
            .unwrap_or(0)
    }

    fn arguments_state(&self, position: u32) -> Option<bool> {
        let mut scope = self.scope_at(position);
        loop {
            if self.scopes[scope].arguments_owner {
                return Some(self.scopes[scope].module_scope);
            }
            scope = self.scopes[scope].parent?;
        }
    }
}

pub(crate) fn run_context_reuse(arguments: Vec<String>, started: Instant) -> Result<()> {
    let (
        graph_path,
        cache_dir,
        output_path,
        diagnostic_encoding,
        entry_cache_path,
        third_party_policy_path,
    ) = parse_arguments(arguments)?;
    prune_and_log_module_summary_cache(&cache_dir, "start")?;
    let graph_read_started = Instant::now();
    let graph_bytes = read_bounded_control_file(&graph_path, "context-reuse graph")?;
    let input: ContextInput = serde_json::from_slice(&graph_bytes)
        .with_context(|| format!("invalid graph JSON {}", graph_path.display()))?;
    ensure!(
        input.kind == INPUT_KIND,
        "unsupported context-reuse graph kind {}",
        input.kind
    );
    validate_registration_adapter_material(&input.repo_root, &input.registration_adapter)?;
    let supplemental_policy = third_party_policy_path
        .as_ref()
        .map(|path| {
            let source = String::from_utf8(read_bounded_control_file(path, "third-party policy")?)
                .with_context(|| format!("third-party policy is not UTF-8: {}", path.display()))?;
            parse_reviewed_third_party_policy(&source)
                .with_context(|| format!("invalid third-party policy {}", path.display()))
        })
        .transpose()?;
    let policy_fingerprint =
        context_policy_fingerprint_with_supplemental(supplemental_policy.as_ref())?;
    let third_party_policy = merge_reviewed_third_party_policy(supplemental_policy)?;
    let mut phases = PhaseMeasurements {
        graph_read_us: elapsed_us(graph_read_started),
        ..Default::default()
    };
    let mut entry_cache = match &entry_cache_path {
        Some(path) => Some(
            serde_json::from_slice::<Option<EntryAnalysisCache>>(&read_bounded_control_file(
                path,
                "context-reuse entry results",
            )?)?
            .unwrap_or_default(),
        ),
        None => None,
    };
    let output = analyze_context_reuse_with_encoding_and_policy(
        &input,
        &cache_dir,
        &mut phases,
        started,
        diagnostic_encoding,
        entry_cache.as_mut(),
        &third_party_policy,
        &policy_fingerprint,
    )?;
    prune_and_log_module_summary_cache(&cache_dir, "end")?;
    if let Some(path) = entry_cache_path {
        // Entry records contain expanded findings and paths even for grouped public output.
        // Stream them before encoding that output instead of retaining both serialized copies.
        let mut writer = BufWriter::new(fs::File::create(path)?);
        serde_json::to_writer(&mut writer, &entry_cache)?;
        writer.flush()?;
    }
    let encoded = serde_json::to_vec_pretty(&output)?;
    if let Some(path) = output_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, encoded).with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", String::from_utf8(encoded)?);
    }
    Ok(())
}

pub(crate) fn build_source_inventory(
    repo_root: &Path,
    metafile: &EsbuildMetafile,
    entry_candidates: &[String],
    cache_dir: &Path,
    modules: &mut BTreeMap<String, LoadedModule>,
    phases: &mut PhaseMeasurements,
    registration_adapter: &RegistrationAdapterMaterial,
    functions_root: &str,
) -> Result<SourceInventory> {
    let mut functions = Vec::new();
    let mut diagnostics = Vec::new();
    let mut unresolved_exports = Vec::new();
    for entry in entry_candidates {
        load_module(repo_root, cache_dir, entry, modules, phases)?;
        let (registrations, reexports, opaque_exports) = {
            let summary = &modules
                .get(entry)
                .context("inventory entry was not summarized")?
                .summary
                .context_reuse;
            (
                summary.registrations.clone(),
                summary.reexports.clone(),
                summary.opaque_exports.clone(),
            )
        };
        let source = modules
            .get(entry)
            .context("inventory entry source disappeared")?
            .source
            .clone();
        unresolved_exports.extend(opaque_exports.into_iter().map(|export| {
            InventoryUnresolvedExport {
                entry_path: entry.clone(),
                export_name: export.export_name,
                classification: export.classification,
                source_span: source_span(&source, export.start, export.end),
            }
        }));
        for registration in &registrations {
            let Some(udf_kind) = inventory_registration_kind(
                metafile,
                modules,
                entry,
                registration,
                registration_adapter,
                functions_root,
            )?
            else {
                continue;
            };
            functions.push(InventoryFunction {
                entry_path: entry.clone(),
                export_name: registration.export_name.clone(),
                udf_kind,
                registration_builder: registration.registration_builder.clone(),
                registration_call: inventory_registration_call(modules, entry, registration)?,
                source_span: source_span(&source, registration.start, registration.end),
                direct: true,
                dependency_chain: Vec::new(),
            });
        }
        for reexport in &reexports {
            let reference = ContextModuleReference {
                specifier: reexport.specifier.clone(),
                kind: "reexport".to_string(),
                type_only: false,
                start: reexport.start,
                end: reexport.end,
            };
            let mut chain = Vec::new();
            let mut visited = BTreeSet::new();
            match resolve_inventory_export(
                repo_root,
                metafile,
                cache_dir,
                modules,
                phases,
                entry,
                &reexport.imported_name,
                &reference,
                &mut chain,
                &mut visited,
                registration_adapter,
            )? {
                Some((registration_module, registration)) => {
                    match inventory_registration_kind(
                        metafile,
                        modules,
                        &registration_module,
                        &registration,
                        registration_adapter,
                        functions_root,
                    )? {
                        Some(udf_kind) => functions.push(InventoryFunction {
                            entry_path: entry.clone(),
                            export_name: reexport.export_name.clone(),
                            udf_kind,
                            registration_builder: registration.registration_builder.clone(),
                            registration_call: inventory_registration_call(
                                modules,
                                &registration_module,
                                &registration,
                            )?,
                            source_span: source_span(&source, reexport.start, reexport.end),
                            direct: false,
                            dependency_chain: chain,
                        }),
                        None => diagnostics.push(InventoryDiagnostic {
                            rule: "unresolved-registration-reexport".to_string(),
                            message: format!(
                                "Named re-export {} does not resolve to a supported Convex registration.",
                                reexport.export_name
                            ),
                            file: entry.clone(),
                            span: source_span(&source, reexport.start, reexport.end),
                            dependency_chain: chain,
                        }),
                    }
                }
                None => diagnostics.push(InventoryDiagnostic {
                    rule: "unresolved-registration-reexport".to_string(),
                    message: format!(
                        "Named re-export {} does not resolve to a supported Convex registration.",
                        reexport.export_name
                    ),
                    file: entry.clone(),
                    span: source_span(&source, reexport.start, reexport.end),
                    dependency_chain: chain,
                }),
            }
        }
    }
    functions.sort_by(|left, right| {
        (&left.entry_path, &left.export_name).cmp(&(&right.entry_path, &right.export_name))
    });
    diagnostics.sort_by(|left, right| {
        (&left.file, left.span.start, &left.rule).cmp(&(&right.file, right.span.start, &right.rule))
    });
    unresolved_exports.sort_by(|left, right| {
        (&left.entry_path, &left.export_name, left.source_span.start).cmp(&(
            &right.entry_path,
            &right.export_name,
            right.source_span.start,
        ))
    });
    let graph_sha256 = hash_bytes(
        &[
            b"convex-wasm-source-inventory-graph\0".as_slice(),
            serde_json::to_vec(metafile)?.as_slice(),
            b"\0",
            registration_adapter.source.sha256.as_bytes(),
        ]
        .concat(),
    );
    Ok(SourceInventory {
        kind: "convex-wasm-source-inventory".to_string(),
        graph_sha256,
        functions,
        diagnostics,
        unresolved_exports,
    })
}

fn inventory_registration_call(
    modules: &BTreeMap<String, LoadedModule>,
    module_key: &str,
    registration: &ContextRegistration,
) -> Result<InventoryRegistrationCall> {
    let module = modules
        .get(module_key)
        .context("inventory registration call module disappeared")?;
    ensure!(
        registration.call_start <= registration.callee_start
            && registration.callee_start < registration.callee_end
            && registration.callee_end <= registration.call_end,
        "authenticated registration callee span is outside its call span"
    );
    Ok(InventoryRegistrationCall {
        source_path: module_key.to_string(),
        source_sha256: module.summary.source_hash.clone(),
        call_span: SourceOffsetSpan {
            start: registration.call_start,
            end: registration.call_end,
        },
        callee_span: SourceOffsetSpan {
            start: registration.callee_start,
            end: registration.callee_end,
        },
    })
}

fn inventory_registration_kind(
    metafile: &EsbuildMetafile,
    modules: &BTreeMap<String, LoadedModule>,
    module_key: &str,
    registration: &ContextRegistration,
    registration_adapter: &RegistrationAdapterMaterial,
    functions_root: &str,
) -> Result<Option<String>> {
    let module = modules
        .get(module_key)
        .context("inventory registration module disappeared")?;
    let Some(compiled_registration) = module
        .summary
        .units
        .get(&registration.local_name)
        .and_then(|unit| unit.registration.as_ref())
    else {
        return Ok(None);
    };
    if compiled_registration.call_start != registration.call_start
        || compiled_registration.call_end != registration.call_end
        || compiled_registration.builder_start != registration.callee_start
        || compiled_registration.builder_end != registration.callee_end
    {
        return Ok(None);
    }
    let Some(binding) = module
        .summary
        .imports
        .get(&compiled_registration.builder_local)
    else {
        return Ok(None);
    };
    if binding.type_only
        || !module.summary.references.iter().any(|reference| {
            reference.name == compiled_registration.builder_local
                && reference.start == compiled_registration.builder_start
                && reference.end == compiled_registration.builder_end
                && reference.read
                && !reference.write
        })
    {
        return Ok(None);
    }
    let reference = ContextModuleReference {
        specifier: binding.specifier.clone(),
        kind: "import".to_string(),
        type_only: binding.type_only,
        start: binding.start,
        end: binding.end,
    };
    let ResolvedReference::Local(resolved) =
        resolve_metafile_reference(metafile, module_key, &reference)?
    else {
        return Ok(None);
    };
    if is_resolved_generated_server_module(&resolved, functions_root) {
        return Ok(generated_server_udf_kind(&binding.imported).map(str::to_string));
    }
    let matches = registration_adapter
        .descriptor
        .adapters
        .iter()
        .filter(|adapter| {
            adapter.wrapper.module_path == resolved
                && adapter.wrapper.export_name == binding.imported
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() <= 1,
        "registration adapter descriptor has duplicate wrapper identity {}#{}",
        resolved,
        binding.imported
    );
    Ok(matches
        .first()
        .map(|adapter| adapter.registration_kind.clone()))
}

#[expect(clippy::too_many_arguments)]
fn resolve_inventory_export(
    repo_root: &Path,
    metafile: &EsbuildMetafile,
    cache_dir: &Path,
    modules: &mut BTreeMap<String, LoadedModule>,
    phases: &mut PhaseMeasurements,
    importer: &str,
    imported_name: &str,
    reference: &ContextModuleReference,
    chain: &mut Vec<DependencyEdge>,
    visited: &mut BTreeSet<(String, String)>,
    registration_adapter: &RegistrationAdapterMaterial,
) -> Result<Option<(String, ContextRegistration)>> {
    let target = match resolve_metafile_reference(metafile, importer, reference)? {
        ResolvedReference::Local(target) => target,
        ResolvedReference::External(_) => return Ok(None),
    };
    let source = &modules
        .get(importer)
        .context("inventory importer source disappeared")?
        .source;
    chain.push(dependency_edge_from_source(
        source, importer, &target, reference,
    ));
    if !visited.insert((target.clone(), imported_name.to_string())) {
        return Ok(None);
    }
    load_module(repo_root, cache_dir, &target, modules, phases)?;
    let (registration, reexport) = {
        let summary = &modules
            .get(&target)
            .context("re-export target was not summarized")?
            .summary
            .context_reuse;
        (
            summary
                .registrations
                .iter()
                .find(|registration| registration.export_name == imported_name)
                .cloned(),
            summary
                .reexports
                .iter()
                .find(|reexport| reexport.export_name == imported_name)
                .cloned(),
        )
    };
    if let Some(registration) = registration {
        return Ok(Some((target, registration)));
    }
    let Some(reexport) = reexport else {
        return Ok(None);
    };
    let next_reference = ContextModuleReference {
        specifier: reexport.specifier.clone(),
        kind: "reexport".to_string(),
        type_only: false,
        start: reexport.start,
        end: reexport.end,
    };
    resolve_inventory_export(
        repo_root,
        metafile,
        cache_dir,
        modules,
        phases,
        &target,
        &reexport.imported_name,
        &next_reference,
        chain,
        visited,
        registration_adapter,
    )
}

fn parse_arguments(
    arguments: Vec<String>,
) -> Result<(
    PathBuf,
    PathBuf,
    Option<PathBuf>,
    DiagnosticEncoding,
    Option<PathBuf>,
    Option<PathBuf>,
)> {
    let mut graph = None;
    let mut cache_dir = None;
    let mut output = None;
    let mut diagnostic_encoding = None;
    let mut entry_cache = None;
    let mut third_party_policy = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--graph" => {
                ensure!(graph.is_none(), "--graph may only be specified once");
                graph = Some(PathBuf::from(
                    arguments.next().context("--graph needs a path")?,
                ));
            }
            "--cache-dir" => {
                ensure!(
                    cache_dir.is_none(),
                    "--cache-dir may only be specified once"
                );
                cache_dir = Some(PathBuf::from(
                    arguments.next().context("--cache-dir needs a path")?,
                ));
            }
            "--output" => {
                ensure!(output.is_none(), "--output may only be specified once");
                output = Some(PathBuf::from(
                    arguments.next().context("--output needs a path")?,
                ));
            }
            "--entry-results" => {
                ensure!(
                    entry_cache.is_none(),
                    "--entry-results may only be specified once"
                );
                entry_cache = Some(PathBuf::from(
                    arguments.next().context("--entry-results needs a path")?,
                ));
            }
            "--diagnostic-encoding" => {
                ensure!(
                    diagnostic_encoding.is_none(),
                    "--diagnostic-encoding may only be specified once"
                );
                let value = arguments
                    .next()
                    .context("--diagnostic-encoding needs a value")?;
                diagnostic_encoding = Some(match value.as_str() {
                    "grouped" => DiagnosticEncoding::Grouped,
                    "admission" => DiagnosticEncoding::Admission,
                    _ => bail!("unknown context-reuse diagnostic encoding {value}"),
                });
            }
            "--third-party-policy" => {
                ensure!(
                    third_party_policy.is_none(),
                    "--third-party-policy may only be specified once"
                );
                third_party_policy = Some(PathBuf::from(
                    arguments
                        .next()
                        .context("--third-party-policy needs a path")?,
                ));
            }
            _ => bail!("unknown context-reuse argument {argument}"),
        }
    }
    Ok((
        graph.context(
            "usage: convex-wasm-compiler context-reuse --graph <graph.json> --cache-dir <dir>",
        )?,
        cache_dir.context("--cache-dir is required")?,
        output,
        diagnostic_encoding.unwrap_or(DiagnosticEncoding::Expanded),
        entry_cache,
        third_party_policy,
    ))
}

#[cfg(test)]
fn analyze_context_reuse(
    input: &ContextInput,
    cache_dir: &Path,
    phases: &mut PhaseMeasurements,
    started: Instant,
) -> Result<ContextOutput> {
    analyze_context_reuse_with_encoding(
        input,
        cache_dir,
        phases,
        started,
        DiagnosticEncoding::Expanded,
        None,
    )
}

fn preload_context_modules(
    input: &ContextInput,
    cache_dir: &Path,
    phases: &mut PhaseMeasurements,
    workers: usize,
) -> Result<BTreeMap<String, LoadedModule>> {
    let mut modules = BTreeMap::<String, LoadedModule>::new();
    let module_keys = input
        .metafile
        .inputs
        .keys()
        .filter(|module_key| {
            is_runtime_source(module_key) && is_reviewed_root(module_key, &input.roots)
        })
        .cloned()
        .collect();
    crate::preload_modules(module_keys, &mut modules, phases, workers, |module_key| {
        let captured_source = match &input.source_texts {
            Some(sources) => Some(
                sources
                    .get(module_key)
                    .with_context(|| {
                        format!(
                            "captured source is missing for first-party runtime input {module_key}"
                        )
                    })?
                    .as_str(),
            ),
            None => None,
        };
        crate::load_compiler_module(&input.repo_root, cache_dir, module_key, captured_source)
    })?;
    Ok(modules)
}

fn analyze_context_reuse_with_encoding(
    input: &ContextInput,
    cache_dir: &Path,
    phases: &mut PhaseMeasurements,
    started: Instant,
    diagnostic_encoding: DiagnosticEncoding,
    mut entry_cache: Option<&mut EntryAnalysisCache>,
) -> Result<ContextOutput> {
    analyze_context_reuse_with_encoding_and_policy(
        input,
        cache_dir,
        phases,
        started,
        diagnostic_encoding,
        entry_cache.as_deref_mut(),
        reviewed_third_party_policy(),
        context_policy_fingerprint(),
    )
}

fn analyze_context_reuse_with_encoding_and_policy(
    input: &ContextInput,
    cache_dir: &Path,
    phases: &mut PhaseMeasurements,
    started: Instant,
    diagnostic_encoding: DiagnosticEncoding,
    mut entry_cache: Option<&mut EntryAnalysisCache>,
    third_party_policy: &ReviewedThirdPartyPolicy,
    policy_fingerprint: &str,
) -> Result<ContextOutput> {
    ensure!(
        crate::is_normalized_functions_root(&input.functions_root)
            && input.roots.contains(&input.functions_root),
        "context-reuse functions root must be normalized and included in the reviewed roots"
    );
    ensure!(
        input
            .entry_candidates
            .iter()
            .all(|entry| entry.starts_with(&format!("{}/", input.functions_root))),
        "context-reuse entries must be under the configured functions root"
    );
    let modules = preload_context_modules(
        input,
        cache_dir,
        phases,
        crate::module_preload_worker_limit()?,
    )?;
    for entry in &input.entry_candidates {
        ensure!(
            modules.contains_key(entry),
            "entry candidate {entry} is absent from the esbuild graph"
        );
    }

    let (entries, mut pending) = select_entries(input, &modules)?;
    let emitted_inputs = emitted_inputs_by_entry(input, &entries);
    // The lockfile is package review material, not graph-selection authority. Delay reading it
    // until emitted metadata proves that at least one third-party boundary contributes; otherwise
    // a fully tree-shaken package could be rejected by unrelated malformed lock material.
    let mut package_lock_entries = None::<Option<BTreeMap<String, Value>>>;
    let reachability_started = Instant::now();
    let sources = modules
        .iter()
        .map(|(module_key, module)| (module_key.clone(), module.source.as_ref().clone()))
        .collect::<BTreeMap<_, _>>();
    let mut graph = BTreeMap::<String, Vec<ResolvedGraphReference>>::new();
    for (module_key, module) in &modules {
        let source = sources
            .get(module_key)
            .context("summarized module has no source")?;
        let mut references = Vec::new();
        for reference in &module.summary.context_reuse.references {
            if reference.type_only || is_convex_runtime_package(&reference.specifier) {
                continue;
            }
            match resolve_context_reference(input, module_key, reference)? {
                None if import_is_proven_pruned(module, reference) => continue,
                None => {
                    references.push(ResolvedGraphReference::Unaccounted {
                        diagnostic: PendingDiagnostic {
                            severity: "hard".to_string(),
                            rule: "unaccounted-runtime-import".to_string(),
                            category: "dependency".to_string(),
                            message: format!(
                                "Runtime import {} has a value reference in source but no edge in the authoritative esbuild graph.",
                                serde_json::to_string(&reference.specifier)?
                            ),
                            file: module_key.clone(),
                            start: reference.start,
                            end: reference.end,
                            anchor_line: context_line_column(module, reference.start).0,
                            entry: String::new(),
                            dependency_chain: Vec::new(),
                        },
                    });
                }
                Some(ResolvedReference::Local(target)) if modules.contains_key(&target) => {
                    references.push(ResolvedGraphReference::Local {
                        edge: dependency_edge_from_source(source, module_key, &target, reference),
                        emitted_only: !is_reviewed_root(&target, &input.roots),
                        target,
                    });
                }
                Some(ResolvedReference::Local(target)) if is_third_party_source(&target) => {
                    let dependency = input.external_dependencies.get(&reference.specifier);
                    let identity = dependency.map_or_else(
                        || target.clone(),
                        |dependency| {
                            dependency.version.as_ref().map_or_else(
                                || dependency.package_name.clone(),
                                |version| format!("{}@{version}", dependency.package_name),
                            )
                        },
                    );
                    references.push(ResolvedGraphReference::ThirdParty {
                        edge: dependency_edge_from_source(source, module_key, &target, reference),
                        identity,
                        reference: reference.clone(),
                        reviewed_identity: dependency.is_some(),
                        target,
                    });
                }
                Some(ResolvedReference::Local(target)) => {
                    let dependency = input.external_dependencies.get(&reference.specifier);
                    let package_identity = dependency.map(|dependency| {
                        dependency.version.as_ref().map_or_else(
                            || dependency.package_name.clone(),
                            |version| format!("{}@{version}", dependency.package_name),
                        )
                    });
                    let quoted_specifier = serde_json::to_string(&reference.specifier)?;
                    references.push(ResolvedGraphReference::Unsupported {
                        diagnostic: PendingDiagnostic {
                            severity: if package_identity.is_some() {
                                "unsupported"
                            } else {
                                "hard"
                            }
                            .to_string(),
                            rule: "unsupported-runtime-dependency".to_string(),
                            category: "dependency".to_string(),
                            message: package_identity.map_or_else(
                                || {
                                    format!(
                                        "Runtime import {} resolves outside the reviewed roots to {target}.",
                                        quoted_specifier
                                    )
                                },
                                |identity| {
                                    format!(
                                        "Runtime import {} reaches unsupported dependency {identity} at {target}.",
                                        quoted_specifier
                                    )
                                },
                            ),
                            file: module_key.clone(),
                            start: reference.start,
                            end: reference.end,
                            anchor_line: context_line_column(module, reference.start).0,
                            entry: String::new(),
                            dependency_chain: Vec::new(),
                        },
                        edge: dependency_edge_from_source(
                            source, module_key, &target, reference,
                        ),
                        target: Some(target),
                    });
                }
                Some(ResolvedReference::External(specifier)) => {
                    if is_convex_runtime_package(&specifier) {
                        continue;
                    }
                    let dependency = input.external_dependencies.get(&specifier);
                    let identity = dependency.map_or_else(
                        || specifier.clone(),
                        |dependency| {
                            dependency.version.as_ref().map_or_else(
                                || dependency.package_name.clone(),
                                |version| format!("{}@{version}", dependency.package_name),
                            )
                        },
                    );
                    references.push(ResolvedGraphReference::Unsupported {
                        diagnostic: PendingDiagnostic {
                            // A bare external edge without a graph identity is malformed input,
                            // not merely an unsupported dependency. Keep the external-policy
                            // split aligned with local package boundaries: authenticated identity
                            // is an operator-review outcome, while missing identity is hard.
                            severity: if dependency.is_some() {
                                "unsupported"
                            } else {
                                "hard"
                            }
                            .to_string(),
                            rule: "unsupported-runtime-dependency".to_string(),
                            category: "dependency".to_string(),
                            message: format!(
                                "Runtime import {} reaches unsupported dependency {identity}.",
                                serde_json::to_string(&specifier)?
                            ),
                            file: module_key.clone(),
                            start: reference.start,
                            end: reference.end,
                            anchor_line: context_line_column(module, reference.start).0,
                            entry: String::new(),
                            dependency_chain: Vec::new(),
                        },
                        edge: dependency_edge_from_source(
                            source,
                            module_key,
                            &format!("<external>/{specifier}"),
                            reference,
                        ),
                        target: None,
                    });
                }
            }
        }
        graph.insert(module_key.clone(), references);
    }
    let mut reachable_modules = BTreeSet::new();
    let mut paths_by_entry = BTreeMap::<String, EntryDependencyPaths>::new();
    let mut third_party_materials = BTreeMap::<String, ThirdPartyMaterial>::new();
    let mut third_party_dispositions =
        BTreeMap::<(String, u32, u32, String), ThirdPartyDisposition>::new();
    let mut import_surface_models = ImportSurfaceModels::new();
    let cache_basis = if entry_cache.is_some() {
        let shared = hash_bytes(&serde_json::to_vec(&(
            policy_fingerprint,
            crate::MODULE_SUMMARY_SCHEMA,
            &input.repo_root,
            &input.roots,
            &input.external_dependencies,
        ))?);
        let nodes = input
            .metafile
            .inputs
            .iter()
            .map(|(key, node)| {
                let references = graph.get(key);
                // Paths and boundary findings consume resolved edges, not local module facts.
                // Package surface review also inspects importer usage beyond the import edge.
                let importer_source_hash = if references.is_some_and(|references| {
                    references.iter().any(|reference| {
                        matches!(reference, ResolvedGraphReference::ThirdParty { .. })
                    })
                }) {
                    Some(
                        modules
                            .get(key)
                            .context("third-party importer has no authenticated summary")?
                            .summary
                            .source_hash
                            .as_str(),
                    )
                } else {
                    None
                };
                Ok((
                    key.clone(),
                    hash_bytes(&serde_json::to_vec(&(
                        node,
                        references,
                        importer_source_hash,
                    ))?),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Some((shared, nodes))
    } else {
        None
    };
    let mut next_entry_cache = EntryAnalysisCache::default();
    for entry in &entries {
        let seed = cache_basis
            .as_ref()
            .map(|(shared, _)| {
                serde_json::to_vec(&(shared, entry, emitted_inputs.get(entry)))
                    .map(|bytes| hash_bytes(&bytes))
            })
            .transpose()?;
        if let Some(record) = entry_cache
            .as_mut()
            .and_then(|cache| cache.entries.remove(entry))
        {
            let (_, nodes) = cache_basis
                .as_ref()
                .context("entry cache has no input basis")?;
            let mut reusable = Some(&record.seed) == seed.as_ref()
                && record
                    .input_nodes
                    .iter()
                    .all(|(key, fingerprint)| fingerprint.as_ref() == nodes.get(key));
            // Package bytes and lock completeness are read only for a previously participating
            // boundary after its source topology and emitted-contribution basis still match.
            if reusable {
                for (target, fingerprint) in &record.third_party_materials {
                    if !third_party_materials.contains_key(target) {
                        if package_lock_entries.is_none() {
                            package_lock_entries =
                                Some(load_package_lock_entries(&input.repo_root)?);
                        }
                        third_party_materials.insert(
                            target.clone(),
                            third_party_material(
                                input,
                                target,
                                package_lock_entries.as_ref().and_then(Option::as_ref),
                            )?,
                        );
                    }
                    let material = third_party_materials
                        .get(target)
                        .context("cached package material disappeared")?;
                    if &material.fingerprint != fingerprint
                        || record.third_party_lock_complete.get(target)
                            != Some(&material.lock_complete)
                    {
                        reusable = false;
                    }
                }
            }
            if reusable {
                pending.extend(record.boundary_pending.iter().cloned());
                validate_cached_dependency_paths(entry, &record.paths)?;
                reachable_modules.extend(record.paths.keys().cloned());
                paths_by_entry.insert(entry.clone(), record.paths.clone());
                next_entry_cache.hits += 1;
                next_entry_cache.entries.insert(entry.clone(), record);
                continue;
            }
        }
        let pending_start = pending.len();
        let mut entry_third_party_materials = BTreeMap::new();
        let mut entry_third_party_lock_complete = BTreeMap::new();
        let mut queue = VecDeque::from([entry.clone()]);
        let mut paths = EntryDependencyPaths::from([(entry.clone(), None)]);
        while let Some(module_key) = queue.pop_front() {
            reachable_modules.insert(module_key.clone());
            let module = modules
                .get(&module_key)
                .with_context(|| format!("reachable module {module_key} was not summarized"))?;
            let source = sources
                .get(&module_key)
                .context("reachable module has no source")?;
            let entry_emitted_inputs = emitted_inputs.get(entry).and_then(Option::as_ref);
            for reference in graph
                .get(&module_key)
                .context("reachable module has no resolved references")?
            {
                match reference {
                    ResolvedGraphReference::Local {
                        edge,
                        target,
                        emitted_only,
                    } => {
                        if *emitted_only
                            && !dependency_subgraph_contributes(
                                &input.metafile,
                                target,
                                entry_emitted_inputs,
                            )
                        {
                            continue;
                        }
                        // FIFO discovery chooses the same first path as dequeue-time visitation,
                        // including diamonds and cycles. Retain only its parent edge so modules
                        // without findings never allocate or copy complete path prefixes.
                        if !paths.contains_key(target) {
                            paths.insert(target.clone(), Some(edge.clone()));
                            queue.push_back(target.clone());
                        }
                    }
                    ResolvedGraphReference::ThirdParty {
                        edge,
                        identity,
                        reference,
                        reviewed_identity,
                        target,
                    } => {
                        // Emitted contribution is the authority for whether this package boundary
                        // participates in the selected entry. Do not read or reject closure
                        // material for a source edge that the selected output fully removed.
                        if !dependency_subgraph_contributes(
                            &input.metafile,
                            target,
                            entry_emitted_inputs,
                        ) {
                            continue;
                        }
                        let material = if let Some(material) = third_party_materials.get(target) {
                            material.clone()
                        } else {
                            if package_lock_entries.is_none() {
                                package_lock_entries =
                                    Some(load_package_lock_entries(&input.repo_root)?);
                            }
                            let material = third_party_material(
                                input,
                                target,
                                package_lock_entries.as_ref().and_then(Option::as_ref),
                            )?;
                            third_party_materials.insert(target.clone(), material.clone());
                            material
                        };
                        if entry_cache.is_some() {
                            entry_third_party_materials
                                .insert(target.clone(), material.fingerprint.clone());
                            entry_third_party_lock_complete
                                .insert(target.clone(), material.lock_complete);
                        }
                        let disposition_key = (
                            module_key.clone(),
                            reference.start,
                            reference.end,
                            material.fingerprint.clone(),
                        );
                        let disposition = if let Some(disposition) =
                            third_party_dispositions.get(&disposition_key)
                        {
                            disposition.clone()
                        } else {
                            let disposition = review_third_party_boundary_in_policy(
                                third_party_policy,
                                &mut import_surface_models,
                                &module_key,
                                module,
                                source,
                                reference,
                                &material,
                            );
                            third_party_dispositions.insert(disposition_key, disposition.clone());
                            disposition
                        };
                        match disposition {
                            ThirdPartyDisposition::Accepted => {}
                            ThirdPartyDisposition::Unsupported(reason) => {
                                let mut dependency_chain =
                                    dependency_chain(entry, &module_key, &paths)?;
                                dependency_chain.push(edge.clone());
                                pending.push(PendingDiagnostic {
                                    severity: if *reviewed_identity {
                                        "unsupported"
                                    } else {
                                        "hard"
                                    }
                                    .to_string(),
                                    rule: "unsupported-runtime-dependency".to_string(),
                                    category: "dependency".to_string(),
                                    message: format!(
                                        "Runtime dependency {identity} has package material {}. {reason}",
                                        material.fingerprint
                                    ),
                                    file: target.clone(),
                                    start: 0,
                                    end: 1,
                                    anchor_line: 1,
                                    entry: entry.clone(),
                                    dependency_chain,
                                });
                            }
                        }
                    }
                    ResolvedGraphReference::Unsupported {
                        diagnostic,
                        edge,
                        target,
                    } => {
                        if target.as_deref().is_some_and(|target| {
                            !dependency_subgraph_contributes(
                                &input.metafile,
                                target,
                                entry_emitted_inputs,
                            )
                        }) {
                            continue;
                        }
                        let mut diagnostic = diagnostic.clone();
                        diagnostic.entry = entry.clone();
                        diagnostic.dependency_chain = dependency_chain(entry, &module_key, &paths)?;
                        if diagnostic.file == edge.to {
                            diagnostic.dependency_chain.push(edge.clone());
                        }
                        pending.push(diagnostic);
                    }
                    ResolvedGraphReference::Unaccounted { diagnostic } => {
                        let mut diagnostic = diagnostic.clone();
                        diagnostic.entry = entry.clone();
                        diagnostic.dependency_chain = dependency_chain(entry, &module_key, &paths)?;
                        pending.push(diagnostic);
                    }
                }
            }
        }
        if let Some(seed) = seed {
            let (_, nodes) = cache_basis
                .as_ref()
                .context("entry cache has no input basis")?;
            // Include the unfiltered input closure: source analysis follows reviewed-root edges
            // even when output removes them, and contribution checks inspect pruned subgraphs.
            // Recording absent nodes also invalidates a later graph that resolves that absence.
            let mut input_nodes = BTreeMap::new();
            let mut queue = VecDeque::from([entry.clone()]);
            while let Some(key) = queue.pop_front() {
                if input_nodes.contains_key(&key) {
                    continue;
                }
                input_nodes.insert(key.clone(), nodes.get(&key).cloned());
                if let Some(node) = input.metafile.inputs.get(&key) {
                    queue.extend(
                        node.imports
                            .iter()
                            .filter(|edge| !edge.external)
                            .map(|edge| edge.path.clone()),
                    );
                }
            }
            next_entry_cache.misses += 1;
            next_entry_cache.entries.insert(
                entry.clone(),
                EntryAnalysisRecord {
                    seed,
                    input_nodes,
                    third_party_materials: entry_third_party_materials,
                    third_party_lock_complete: entry_third_party_lock_complete,
                    boundary_pending: pending[pending_start..].to_vec(),
                    paths: paths.clone(),
                },
            );
        }
        paths_by_entry.insert(entry.clone(), paths);
    }
    // Binding models retain AST subtrees; release them before diagnostic expansion/serialization.
    drop(import_surface_models);
    // Module facts already live in the authenticated summaries. Replay them from the selected
    // paths for both hits and misses; only traversal-dependent boundary findings need retention.
    for (entry, paths) in &paths_by_entry {
        for module_key in paths.keys() {
            let module = modules
                .get(module_key)
                .context("reachable module has no summary for fact replay")?;
            if module.summary.context_reuse.facts.is_empty() {
                continue;
            }
            let chain = dependency_chain(entry, module_key, paths)?;
            for fact in &module.summary.context_reuse.facts {
                pending.push(PendingDiagnostic {
                    severity: fact.severity.clone(),
                    rule: fact.rule.clone(),
                    category: fact.category.clone(),
                    message: fact.message.clone(),
                    file: module_key.clone(),
                    start: fact.start,
                    end: fact.end,
                    anchor_line: context_line_column(module, fact.anchor_start).0,
                    entry: entry.clone(),
                    dependency_chain: chain.clone(),
                });
            }
        }
    }
    phases.reachability_us = elapsed_us(reachability_started);

    deduplicate_pending(&mut pending);
    let (pending, suppressed_findings) =
        apply_suppressions(&modules, &paths_by_entry, &sources, pending)?;
    let mut diagnostic_counts = BTreeMap::new();
    let mut category_counts = BTreeMap::new();
    for diagnostic in &pending {
        *diagnostic_counts
            .entry(diagnostic.severity.clone())
            .or_insert(0) += 1;
        *category_counts
            .entry(diagnostic.category.clone())
            .or_insert(0) += 1;
    }
    let safe = pending
        .iter()
        .all(|diagnostic| diagnostic.severity == "information");
    let public_diagnostics = pending.into_iter().map(|pending| {
        if let Some(module) = modules.get(&pending.file) {
            public_diagnostic(module.source.len(), pending, |offset| {
                context_line_column(module, offset)
            })
        } else {
            ensure!(
                input.source_texts.is_none() || !is_reviewed_root(&pending.file, &input.roots),
                "captured diagnostic source was not loaded: {}",
                pending.file
            );
            let source = module_source(&input.repo_root, &pending.file)?;
            public_diagnostic(source.len(), pending, |offset| line_column(&source, offset))
        }
    });
    let diagnostic_output = match diagnostic_encoding {
        DiagnosticEncoding::Expanded => {
            let mut diagnostics = public_diagnostics.collect::<Result<Vec<_>>>()?;
            diagnostics.sort_by(|left, right| {
                (
                    &left.entry,
                    &left.file,
                    left.span.start,
                    &left.rule,
                    &left.id,
                )
                    .cmp(&(
                        &right.entry,
                        &right.file,
                        right.span.start,
                        &right.rule,
                        &right.id,
                    ))
            });
            ContextDiagnosticOutput::Expanded { diagnostics }
        }
        DiagnosticEncoding::Grouped => {
            let mut grouped = GroupedContextDiagnosticsBuilder::default();
            for diagnostic in public_diagnostics {
                grouped.insert(diagnostic?)?;
            }
            ContextDiagnosticOutput::Grouped(grouped.finish())
        }
        DiagnosticEncoding::Admission => {
            let mut admission = AdmissionContextDiagnosticsBuilder::default();
            for diagnostic in public_diagnostics {
                admission.insert(diagnostic?)?;
            }
            ContextDiagnosticOutput::Admission(admission.finish())
        }
    };

    let output = ContextOutput {
        kind: OUTPUT_KIND.to_string(),
        safe,
        entries,
        diagnostic_output,
        suppressed_findings,
        diagnostic_counts,
        category_counts,
        metrics: ContextMetrics {
            wall_time_us: elapsed_us(started),
            esbuild_graph_us: input
                .phase_timings_us
                .get("esbuildGraph")
                .copied()
                .unwrap_or(0),
            graph_read_us: phases.graph_read_us,
            source_read_us: phases.source_read_us,
            cache_lookup_us: phases.cache_lookup_us,
            parse_us: phases.parse_us,
            semantic_us: phases.semantic_us,
            reachability_us: phases.reachability_us,
            modules_analyzed: reachable_modules.len(),
            parsed_modules: phases.module_cache_misses,
            cache_hits: phases.module_cache_hits,
            cache_misses: phases.module_cache_misses,
            entry_cache_hits: entry_cache.as_ref().map(|_| next_entry_cache.hits),
            entry_cache_misses: entry_cache.as_ref().map(|_| next_entry_cache.misses),
            peak_rss_bytes: peak_rss_bytes()?,
        },
        module_summary_schema: crate::MODULE_SUMMARY_SCHEMA.to_string(),
        policy_fingerprint: policy_fingerprint.to_string(),
        third_party_material_fingerprints: third_party_materials
            .into_iter()
            .map(|(target, material)| (target, material.fingerprint))
            .collect(),
    };
    if let Some(entry_cache) = entry_cache {
        *entry_cache = next_entry_cache;
    }
    Ok(output)
}

pub(crate) fn context_policy_fingerprint() -> &'static str {
    // Validate the embedded policy before exposing its identity. This keeps malformed policy
    // material from producing an apparently valid context-policy fingerprint on code paths that
    // do not happen to traverse a third-party boundary.
    let _ = reviewed_third_party_policy();
    static FINGERPRINT: OnceLock<String> = OnceLock::new();
    FINGERPRINT
        .get_or_init(|| context_policy_fingerprint_from_sources(POLICY_SOURCES.iter().copied()))
        .as_str()
}

fn context_policy_fingerprint_with_supplemental(
    supplemental: Option<&ReviewedThirdPartyPolicy>,
) -> Result<String> {
    let Some(supplemental) = supplemental else {
        return Ok(context_policy_fingerprint().to_string());
    };
    validate_reviewed_third_party_policy(supplemental)?;
    let encoded = serde_json::to_string(supplemental)?;
    Ok(context_policy_fingerprint_from_sources(
        POLICY_SOURCES
            .iter()
            .copied()
            .chain(std::iter::once(encoded.as_str())),
    ))
}

fn context_policy_fingerprint_from_sources<'a>(
    sources: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut policy = String::new();
    for source in sources {
        policy.push_str(&source.len().to_string());
        policy.push('\0');
        policy.push_str(source);
        policy.push('\0');
    }
    hash_bytes(policy.as_bytes())
}

fn select_entries(
    input: &ContextInput,
    modules: &BTreeMap<String, LoadedModule>,
) -> Result<(Vec<String>, Vec<PendingDiagnostic>)> {
    let mut pending = generated_source_diagnostics(input, modules)?;
    let mut entries = Vec::new();
    let marker_exports = discover_marker_exports(input, modules)?;
    if input.default_enabled {
        let database_entries = input
            .default_database_entries
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for entry in &database_entries {
            ensure!(
                input.entry_candidates.contains(entry),
                "database entry {entry} is not a Convex entry candidate"
            );
        }
        for (excluded, reason) in &input.exclusions {
            ensure!(
                reason.len() >= 32 && reason.trim() == reason,
                "context-reuse exclusion {excluded} must have a literal 32-character reason"
            );
            if !database_entries.contains(excluded) {
                pending.push(policy_diagnostic(
                    excluded,
                    "invalid-database-entry-exclusion",
                    format!(
                        "Database-entry exclusion for {excluded} is unused because the generated API contains no query or mutation from that entry."
                    ),
                ));
            }
        }
        for entry in database_entries {
            if !input.exclusions.contains_key(&entry) {
                entries.push(entry);
            }
        }
        for candidate in &input.entry_candidates {
            let marker = marker_exports
                .get(candidate)
                .context("entry candidate has no marker summary")?;
            if let Some(occurrence) = marker.occurrences.first() {
                pending.push(marker_policy_diagnostic(
                    candidate,
                    occurrence,
                    "redundant-context-reuse-marker",
                    "Source context-reuse marker is redundant because convex.json owns the database-UDF default.".to_string(),
                ));
            }
        }
    } else {
        for candidate in &input.entry_candidates {
            let marker = marker_exports
                .get(candidate)
                .context("entry candidate has no marker summary")?;
            if marker.occurrences.is_empty() {
                continue;
            }
            entries.push(candidate.clone());
            if marker.occurrences.len() == 1 && marker.occurrences[0].canonical {
                continue;
            }
            for occurrence in &marker.occurrences {
                pending.push(marker_policy_diagnostic(
                    candidate,
                    occurrence,
                    "noncanonical-context-reuse-marker",
                    if occurrence.canonical {
                        "Context-reuse entry has more than one marker export; keep only the canonical direct declaration.".to_string()
                    } else {
                        occurrence.message.clone()
                    },
                ));
            }
        }
    }
    entries.sort();
    entries.dedup();
    Ok((entries, pending))
}

fn generated_source_diagnostics(
    input: &ContextInput,
    modules: &BTreeMap<String, LoadedModule>,
) -> Result<Vec<PendingDiagnostic>> {
    let mut source_functions = BTreeMap::<(String, String), SourceDatabaseFunction>::new();
    let mut opaque_source_exports = BTreeSet::<(String, String)>::new();
    for entry in &input.entry_candidates {
        let summary = &modules
            .get(entry)
            .context("entry candidate was not summarized")?
            .summary
            .context_reuse;
        opaque_source_exports.extend(
            summary
                .opaque_exports
                .iter()
                .map(|export| (entry.clone(), export.export_name.clone())),
        );
        for registration in &summary.registrations {
            if let Some(udf_kind) = inventory_registration_kind(
                &input.metafile,
                modules,
                entry,
                registration,
                &input.registration_adapter,
                &input.functions_root,
            )? {
                source_functions.insert(
                    (entry.clone(), registration.export_name.clone()),
                    SourceDatabaseFunction {
                        udf_kind,
                        start: registration.start,
                        end: registration.end,
                    },
                );
            }
        }
        for reexport in &summary.reexports {
            let mut visited = BTreeSet::new();
            if let Some((registration_module, registration)) = resolve_source_registration(
                input,
                modules,
                entry,
                &reexport.imported_name,
                &ContextModuleReference {
                    specifier: reexport.specifier.clone(),
                    kind: "reexport".to_string(),
                    type_only: false,
                    start: reexport.start,
                    end: reexport.end,
                },
                &mut visited,
            )? && let Some(udf_kind) = inventory_registration_kind(
                &input.metafile,
                modules,
                &registration_module,
                &registration,
                &input.registration_adapter,
                &input.functions_root,
            )? {
                source_functions.insert(
                    (entry.clone(), reexport.export_name.clone()),
                    SourceDatabaseFunction {
                        udf_kind,
                        start: reexport.start,
                        end: reexport.end,
                    },
                );
            }
        }
    }

    let generated_functions = input
        .database_functions
        .iter()
        .map(|function| {
            (
                (function.entry_path.clone(), function.export_name.clone()),
                function.udf_kind.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut pending = Vec::new();
    for ((entry, export_name), generated_kind) in &generated_functions {
        ensure!(
            input.entry_candidates.contains(entry),
            "generated database function {entry}:{export_name} has no entry candidate"
        );
        match source_functions.get(&(entry.clone(), export_name.clone())) {
            Some(source) if source.udf_kind == *generated_kind => {}
            Some(source) => pending.push(source_mismatch_diagnostic(
                entry,
                source.start,
                source.end,
                format!(
                    "Generated inventory classifies {entry}:{export_name} as {generated_kind}, but source analysis classifies it as {}.",
                    source.udf_kind
                ),
            )),
            None if opaque_source_exports.contains(&(entry.clone(), export_name.clone())) => {}
            None => pending.push(policy_diagnostic(
                entry,
                "generated-inventory-source-mismatch",
                format!(
                    "Generated inventory selects {entry}:{export_name} as {generated_kind}, but source analysis cannot resolve that export to a supported direct or named re-exported database registration."
                ),
            )),
        }
    }
    for ((entry, export_name), source) in source_functions {
        if !generated_functions.contains_key(&(entry.clone(), export_name.clone())) {
            // Actions intentionally stay out of the database-function inventory because they
            // continue to run in V8. Only an omitted query or mutation is an inventory mismatch.
            if source.udf_kind == "action" {
                continue;
            }
            pending.push(source_mismatch_diagnostic(
                &entry,
                source.start,
                source.end,
                format!(
                    "Source analysis resolves {entry}:{export_name} as {}, but generated inventory does not contain that database function.",
                    source.udf_kind
                ),
            ));
        }
    }
    Ok(pending)
}

fn resolve_source_registration(
    input: &ContextInput,
    modules: &BTreeMap<String, LoadedModule>,
    importer: &str,
    imported_name: &str,
    reference: &ContextModuleReference,
    visited: &mut BTreeSet<(String, String)>,
) -> Result<Option<(String, ContextRegistration)>> {
    let target = match resolve_reference(input, importer, reference)? {
        ResolvedReference::Local(target)
            if is_reviewed_root(&target, &input.roots) && modules.contains_key(&target) =>
        {
            target
        }
        ResolvedReference::Local(_) | ResolvedReference::External(_) => return Ok(None),
    };
    if !visited.insert((target.clone(), imported_name.to_string())) {
        return Ok(None);
    }
    let summary = &modules
        .get(&target)
        .context("registration re-export target disappeared")?
        .summary
        .context_reuse;
    if let Some(registration) = summary
        .registrations
        .iter()
        .find(|registration| registration.export_name == imported_name)
    {
        return Ok(Some((target, registration.clone())));
    }
    let Some(reexport) = summary
        .reexports
        .iter()
        .find(|reexport| reexport.export_name == imported_name)
    else {
        return Ok(None);
    };
    resolve_source_registration(
        input,
        modules,
        &target,
        &reexport.imported_name,
        &ContextModuleReference {
            specifier: reexport.specifier.clone(),
            kind: "reexport".to_string(),
            type_only: false,
            start: reexport.start,
            end: reexport.end,
        },
        visited,
    )
}

fn source_mismatch_diagnostic(
    file: &str,
    start: u32,
    end: u32,
    message: String,
) -> PendingDiagnostic {
    PendingDiagnostic {
        severity: "hard".to_string(),
        rule: "generated-inventory-source-mismatch".to_string(),
        category: "entry-policy".to_string(),
        message,
        file: file.to_string(),
        start,
        end,
        anchor_line: 1,
        entry: file.to_string(),
        dependency_chain: Vec::new(),
    }
}

fn discover_marker_exports(
    input: &ContextInput,
    modules: &BTreeMap<String, LoadedModule>,
) -> Result<BTreeMap<String, MarkerExport>> {
    let mut cache = BTreeMap::new();
    let mut active = BTreeSet::new();
    for candidate in &input.entry_candidates {
        resolve_marker_export(input, modules, candidate, &mut cache, &mut active)?;
    }
    Ok(cache)
}

fn resolve_marker_export(
    input: &ContextInput,
    modules: &BTreeMap<String, LoadedModule>,
    module_key: &str,
    cache: &mut BTreeMap<String, MarkerExport>,
    active: &mut BTreeSet<String>,
) -> Result<MarkerExport> {
    if let Some(marker) = cache.get(module_key) {
        return Ok(marker.clone());
    }
    if !active.insert(module_key.to_string()) {
        return Ok(MarkerExport {
            occurrences: Vec::new(),
        });
    }
    let summary = &modules
        .get(module_key)
        .with_context(|| format!("marker module {module_key} was not summarized"))?
        .summary
        .context_reuse;
    let mut occurrences = summary.marker_occurrences.clone();
    for reference in &summary.marker_reexports {
        let target = resolve_reference(input, module_key, reference)?;
        let exported = match &target {
            ResolvedReference::Local(target)
                if is_reviewed_root(target, &input.roots) && modules.contains_key(target) =>
            {
                !resolve_marker_export(input, modules, target, cache, active)?
                    .occurrences
                    .is_empty()
            }
            ResolvedReference::Local(_) | ResolvedReference::External(_) => true,
        };
        if exported {
            occurrences.push(ContextMarkerOccurrence {
                canonical: false,
                message: match target {
                    ResolvedReference::Local(target)
                        if is_reviewed_root(&target, &input.roots) =>
                    {
                        format!(
                            "Context-reuse marker is re-exported from {}.",
                            serde_json::to_string(&reference.specifier)?
                        )
                    }
                    _ => format!(
                        "Context-reuse marker may be re-exported from unreviewed runtime module {}.",
                        serde_json::to_string(&reference.specifier)?
                    ),
                },
                start: reference.start,
                end: reference.end,
            });
        }
    }
    active.remove(module_key);
    occurrences.sort_by_key(|occurrence| {
        (
            occurrence.start,
            occurrence.end,
            occurrence.canonical,
            occurrence.message.clone(),
        )
    });
    occurrences.dedup_by(|left, right| {
        left.start == right.start
            && left.end == right.end
            && left.canonical == right.canonical
            && left.message == right.message
    });
    let marker = MarkerExport { occurrences };
    cache.insert(module_key.to_string(), marker.clone());
    Ok(marker)
}

fn marker_policy_diagnostic(
    file: &str,
    occurrence: &ContextMarkerOccurrence,
    rule: &str,
    message: String,
) -> PendingDiagnostic {
    PendingDiagnostic {
        severity: "hard".to_string(),
        rule: rule.to_string(),
        category: "entry-policy".to_string(),
        message,
        file: file.to_string(),
        start: occurrence.start,
        end: occurrence.end,
        anchor_line: 1,
        entry: file.to_string(),
        dependency_chain: Vec::new(),
    }
}

fn policy_diagnostic(file: &str, rule: &str, message: String) -> PendingDiagnostic {
    PendingDiagnostic {
        severity: "hard".to_string(),
        rule: rule.to_string(),
        category: "entry-policy".to_string(),
        message,
        file: file.to_string(),
        start: 0,
        end: 1,
        anchor_line: 1,
        entry: file.to_string(),
        dependency_chain: Vec::new(),
    }
}

fn resolve_reference(
    input: &ContextInput,
    importer: &str,
    reference: &ContextModuleReference,
) -> Result<ResolvedReference> {
    resolve_metafile_reference(&input.metafile, importer, reference)
}

fn resolve_context_reference(
    input: &ContextInput,
    importer: &str,
    reference: &ContextModuleReference,
) -> Result<Option<ResolvedReference>> {
    resolve_metafile_reference_optional(&input.metafile, importer, reference)
}

fn resolve_metafile_reference(
    metafile: &EsbuildMetafile,
    importer: &str,
    reference: &ContextModuleReference,
) -> Result<ResolvedReference> {
    resolve_metafile_reference_optional(metafile, importer, reference)?.with_context(|| {
        format!(
            "esbuild graph must resolve {} from {importer}, found no matching edge",
            reference.specifier
        )
    })
}

fn resolve_metafile_reference_optional(
    metafile: &EsbuildMetafile,
    importer: &str,
    reference: &ContextModuleReference,
) -> Result<Option<ResolvedReference>> {
    let graph_input = metafile
        .inputs
        .get(importer)
        .with_context(|| format!("esbuild metafile has no input {importer}"))?;
    let matches = graph_input
        .imports
        .iter()
        .filter(|import| {
            import.original.as_deref() == Some(&reference.specifier)
                && import_kind_matches(import, &reference.kind)
        })
        .collect::<Vec<_>>();
    let Some(first) = matches.first() else {
        return Ok(None);
    };
    ensure!(
        matches
            .iter()
            .all(|candidate| candidate.path == first.path && candidate.external == first.external),
        "esbuild graph resolves repeated {} edges from {importer} inconsistently",
        reference.specifier,
    );
    if first.external {
        Ok(Some(ResolvedReference::External(first.path.clone())))
    } else {
        Ok(Some(ResolvedReference::Local(first.path.clone())))
    }
}

fn import_is_proven_pruned(module: &LoadedModule, reference: &ContextModuleReference) -> bool {
    if reference.kind != "import" {
        return false;
    }
    let bindings = module
        .summary
        .imports
        .values()
        .filter(|binding| {
            binding.specifier == reference.specifier
                && binding.start == reference.start
                && binding.end == reference.end
        })
        .collect::<Vec<_>>();
    !bindings.is_empty()
        && bindings.iter().all(|binding| {
            binding.type_only
                || !module
                    .summary
                    .references
                    .iter()
                    .any(|occurrence| occurrence.name == binding.local)
        })
}

fn import_kind_matches(import: &EsbuildImport, reference_kind: &str) -> bool {
    match reference_kind {
        "import" | "reexport" => import.kind == "import-statement",
        "require" => import.kind == "require-call",
        _ => false,
    }
}

fn dependency_edge_from_source(
    source: &str,
    from: &str,
    to: &str,
    reference: &ContextModuleReference,
) -> DependencyEdge {
    DependencyEdge {
        from: from.to_string(),
        to: to.to_string(),
        specifier: reference.specifier.clone(),
        span: source_span(&source, reference.start, reference.end),
    }
}

fn apply_suppressions(
    modules: &BTreeMap<String, LoadedModule>,
    paths_by_entry: &BTreeMap<String, EntryDependencyPaths>,
    sources: &BTreeMap<String, String>,
    pending: Vec<PendingDiagnostic>,
) -> Result<(Vec<PendingDiagnostic>, usize)> {
    let mut declarations =
        BTreeMap::<(String, String, usize, String), SuppressionDeclaration>::new();
    let mut invalid = Vec::new();
    for (entry, paths) in paths_by_entry {
        for module_key in paths.keys() {
            let module = modules
                .get(module_key)
                .context("suppression module disappeared")?;
            let source = sources
                .get(module_key)
                .context("suppression module source disappeared")?;
            for declaration in &module.summary.context_reuse.suppressions {
                if let Some(error) = &declaration.error {
                    let start = line_start(source, declaration.line);
                    invalid.push(PendingDiagnostic {
                        severity: "hard".to_string(),
                        rule: "invalid-suppression".to_string(),
                        category: "suppression".to_string(),
                        message: error.clone(),
                        file: module_key.clone(),
                        start,
                        end: start.saturating_add(1),
                        anchor_line: declaration.line,
                        entry: entry.clone(),
                        dependency_chain: dependency_chain(entry, module_key, paths)?,
                    });
                } else {
                    let rule = declaration
                        .rule
                        .clone()
                        .context("valid suppression has no rule")?;
                    declarations.insert(
                        (
                            entry.clone(),
                            module_key.clone(),
                            declaration.line + 1,
                            rule,
                        ),
                        declaration.clone(),
                    );
                }
            }
        }
    }

    // Invalid declarations still produce findings, but only valid declarations need a
    // matching index. Most graphs have none, even when shared findings repeat across entries.
    if declarations.is_empty() {
        let mut active = pending;
        active.extend(invalid);
        return Ok((active, 0));
    }

    let mut findings_by_key = BTreeMap::<(String, String, usize, String), Vec<usize>>::new();
    for (index, diagnostic) in pending.iter().enumerate() {
        findings_by_key
            .entry((
                diagnostic.entry.clone(),
                diagnostic.file.clone(),
                diagnostic.anchor_line,
                diagnostic.rule.clone(),
            ))
            .or_default()
            .push(index);
    }
    let mut suppressed = BTreeSet::new();
    for (key, declaration) in declarations {
        let matches = findings_by_key.get(&key).cloned().unwrap_or_default();
        if matches.len() == 1 {
            suppressed.insert(matches[0]);
            continue;
        }
        let message = if matches.len() > 1 {
            format!(
                "Suppression for {} matches more than one finding on the next line; split the findings into separate statements.",
                key.3
            )
        } else {
            format!(
                "Suppression for {} does not match a finding on the next line.",
                key.3
            )
        };
        let entry = key.0;
        let file = key.1;
        let chain = dependency_chain(
            &entry,
            &file,
            paths_by_entry
                .get(&entry)
                .context("suppression has no entry dependency paths")?,
        )?;
        let source = sources
            .get(&file)
            .context("suppression source disappeared")?;
        let start = line_start(&source, declaration.line);
        invalid.push(PendingDiagnostic {
            severity: "hard".to_string(),
            rule: "invalid-suppression".to_string(),
            category: "suppression".to_string(),
            message,
            file,
            start,
            end: start.saturating_add(1),
            anchor_line: declaration.line,
            entry,
            dependency_chain: chain,
        });
    }
    let suppressed_count = suppressed.len();
    let mut active = pending
        .into_iter()
        .enumerate()
        .filter_map(|(index, diagnostic)| (!suppressed.contains(&index)).then_some(diagnostic))
        .collect::<Vec<_>>();
    active.extend(invalid);
    Ok((active, suppressed_count))
}

fn context_line_column(module: &LoadedModule, offset: u32) -> (usize, usize) {
    // Preserve the source-slice lookup's EOF coordinates for offsets inside UTF-8 codepoints.
    let offset = if module.source.is_char_boundary(offset as usize) {
        offset
    } else {
        module.source.len() as u32
    };
    module.line_column(offset)
}

fn public_diagnostic(
    source_len: usize,
    pending: PendingDiagnostic,
    line_column: impl Fn(u32) -> (usize, usize),
) -> Result<ContextDiagnostic> {
    let start = pending.start.min(source_len as u32);
    let end = pending
        .end
        .max(start.saturating_add(1))
        .min(source_len as u32);
    let (line, column) = line_column(start);
    let (end_line, end_column) = line_column(end);
    let mut identity = String::new();
    for component in [
        DIAGNOSTIC_ID_DOMAIN,
        &pending.rule,
        &pending.file,
        &start.to_string(),
        &end.to_string(),
        &pending.message,
    ] {
        identity.push_str(component);
        identity.push('\0');
    }
    Ok(ContextDiagnostic {
        id: format!("ctx-{}", &hash_bytes(identity.as_bytes())[..20]),
        severity: pending.severity,
        rule: pending.rule,
        category: pending.category,
        message: pending.message,
        file: pending.file,
        span: SourceSpan {
            start,
            end,
            line,
            column,
            end_line,
            end_column,
        },
        entry: pending.entry,
        dependency_chain: pending.dependency_chain,
    })
}

fn deduplicate_pending(pending: &mut Vec<PendingDiagnostic>) {
    pending.sort_by(|left, right| {
        (
            &left.file,
            left.start,
            left.end,
            &left.rule,
            &left.message,
            &left.entry,
        )
            .cmp(&(
                &right.file,
                right.start,
                right.end,
                &right.rule,
                &right.message,
                &right.entry,
            ))
    });
    pending.dedup_by(|left, right| {
        left.entry == right.entry
            && left.file == right.file
            && left.start == right.start
            && left.end == right.end
            && left.rule == right.rule
            && left.message == right.message
    });
}

fn source_span(source: &str, start: u32, end: u32) -> SourceSpan {
    let (line, column) = line_column(source, start);
    let (end_line, end_column) = line_column(source, end);
    SourceSpan {
        start,
        end,
        line,
        column,
        end_line,
        end_column,
    }
}

fn line_start(source: &str, one_based_line: usize) -> u32 {
    if one_based_line <= 1 {
        return 0;
    }
    let mut line = 1;
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            line += 1;
            if line == one_based_line {
                return (index + 1) as u32;
            }
        }
    }
    source.len() as u32
}

fn module_source(repo_root: &Path, module_key: &str) -> Result<String> {
    let (_, bytes) = read_checked_module(repo_root, module_key)?;
    String::from_utf8(bytes).with_context(|| format!("failed to decode {module_key} as UTF-8"))
}

fn is_runtime_source(module_key: &str) -> bool {
    [".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".jsx"]
        .iter()
        .any(|extension| module_key.ends_with(extension))
        && ![".d.ts", ".d.mts", ".d.cts"]
            .iter()
            .any(|extension| module_key.ends_with(extension))
}

fn is_reviewed_root(module_key: &str, roots: &[String]) -> bool {
    roots
        .iter()
        .any(|root| module_key == root || module_key.starts_with(&format!("{root}/")))
}

fn is_convex_runtime_package(specifier: &str) -> bool {
    matches!(specifier, "convex" | "convex/server" | "convex/values")
}

fn peak_rss_bytes() -> Result<Option<u64>> {
    #[cfg(target_os = "linux")]
    {
        let status = fs::read_to_string("/proc/self/status")?;
        let line = status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .context("/proc/self/status has no VmHWM")?;
        let kib = line
            .split_whitespace()
            .nth(1)
            .context("VmHWM has no value")?
            .parse::<u64>()?;
        Ok(Some(kib * 1024))
    }
    #[cfg(not(target_os = "linux"))]
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionContextDiagnosticsBuilder, ContextDiagnostic, ContextDiagnosticOutput,
        ContextInput, DependencyEdge, DiagnosticEncoding, ESBUILD_RUNTIME_PSEUDO_MODULE,
        EntryAnalysisCache, GroupedContextDiagnostics, GroupedContextDiagnosticsBuilder,
        INPUT_KIND, POLICY_SOURCES, REVIEWED_THIRD_PARTY_POLICY_SOURCE, SourceSpan,
        ThirdPartyDisposition, ThirdPartyMaterial, analyze_context_reuse,
        analyze_context_reuse_with_encoding, build_source_inventory,
        context_policy_fingerprint_from_sources, load_module, load_package_lock_entries,
        package_lock_key, parse_arguments, parse_reviewed_third_party_policy,
        review_third_party_boundary, review_third_party_surface_policy,
        reviewed_third_party_policy, reviewed_third_party_surface,
        reviewed_third_party_surface_in_policy, run_context_reuse, third_party_material,
    };
    use crate::{
        EsbuildImport, EsbuildInput, EsbuildMetafile, PhaseMeasurements,
        test_registration_adapter_material,
    };
    use serde_json::Value;
    use std::{
        collections::{BTreeMap, BTreeSet},
        env, fs,
        path::PathBuf,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    struct TemporaryDirectory(PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn fixture_repository_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|candidate| {
                candidate
                    .join("scripts/test-fixtures/convex-context-reuse")
                    .is_dir()
            })
            .expect("compiler fixture repository root must exist")
            .to_path_buf()
    }

    #[test]
    fn suppression_matching_without_valid_declarations_preserves_findings() {
        let file = "convex/suppressions.ts";
        for (source, invalid_count) in [
            ("let retained = 0;\n", 0),
            ("// context-reuse-check-suppress\nlet retained = 0;\n", 1),
        ] {
            let summary = crate::summarize_module(
                file,
                std::path::Path::new(file),
                source,
                "test-source-hash",
                "test-cache-key",
                "test-compiler-fingerprint",
                "test-policy-fingerprint",
                &mut PhaseMeasurements::default(),
            )
            .unwrap();
            assert_eq!(summary.context_reuse.suppressions.len(), invalid_count);
            let modules = BTreeMap::from([(
                file.to_string(),
                crate::LoadedModule::new(summary, source.to_string()),
            )]);
            let sources = BTreeMap::from([(file.to_string(), source.to_string())]);
            let paths =
                BTreeMap::from([(file.to_string(), BTreeMap::from([(file.to_string(), None)]))]);
            let pending = ["second", "first"]
                .into_iter()
                .map(|message| super::PendingDiagnostic {
                    severity: "hard".to_string(),
                    rule: "top-level-mutable-binding".to_string(),
                    category: "state".to_string(),
                    message: message.to_string(),
                    file: file.to_string(),
                    start: 0,
                    end: 1,
                    anchor_line: 1,
                    entry: file.to_string(),
                    dependency_chain: Vec::new(),
                })
                .collect::<Vec<_>>();
            let expected = serde_json::to_value(&pending).unwrap();
            let (active, suppressed) =
                super::apply_suppressions(&modules, &paths, &sources, pending).unwrap();
            assert_eq!(suppressed, 0);
            assert_eq!(active.len(), 2 + invalid_count);
            assert_eq!(serde_json::to_value(&active[..2]).unwrap(), expected);
            if invalid_count != 0 {
                let invalid = &active[2];
                assert_eq!(invalid.rule, "invalid-suppression");
                assert_eq!(invalid.severity, "hard");
                assert_eq!(invalid.file, file);
                assert_eq!(invalid.entry, file);
                assert_eq!((invalid.start, invalid.end, invalid.anchor_line), (0, 1, 1));
                assert!(invalid.dependency_chain.is_empty());
            }
        }
    }

    #[test]
    fn public_diagnostic_indexed_coordinates_preserve_output() {
        let source = "// é\r\n//中\n";
        let file = "convex/coordinates.ts";
        let summary = crate::summarize_module(
            file,
            std::path::Path::new(file),
            source,
            "test-source-hash",
            "test-cache-key",
            "test-compiler-fingerprint",
            "test-policy-fingerprint",
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let module = crate::LoadedModule::new(summary, source.to_string());
        for offset in 0..=source.len() as u32 + 2 {
            assert_eq!(
                super::context_line_column(&module, offset),
                crate::line_column(source, offset),
                "offset {offset}",
            );
        }
        for (start, end, expected_span, expected_id) in [
            (0, 1, [0, 1, 1, 1, 1, 2], "ctx-be19767374966d3f3775"),
            (3, 3, [3, 4, 1, 4, 3, 1], "ctx-9e9ff76154f1664731e5"),
            (4, 8, [4, 8, 3, 1, 2, 2], "ctx-5e7fda951048ffb435c3"),
            (7, u32::MAX, [7, 13, 2, 1, 3, 1], "ctx-c93c2ef49b8c7ee68c53"),
            (
                u32::MAX,
                0,
                [13, 13, 3, 1, 3, 1],
                "ctx-d611b2370292d6fdb7c8",
            ),
        ] {
            let pending = super::PendingDiagnostic {
                severity: "hard".to_string(),
                rule: "test-rule".to_string(),
                category: "test-category".to_string(),
                message: "Coordinate regression".to_string(),
                file: file.to_string(),
                start,
                end,
                anchor_line: 1,
                entry: file.to_string(),
                dependency_chain: Vec::new(),
            };
            let diagnostic = super::public_diagnostic(source.len(), pending, |offset| {
                super::context_line_column(&module, offset)
            })
            .unwrap();
            let [start, end, line, column, end_line, end_column] = expected_span;
            assert_eq!(
                serde_json::to_value(diagnostic).unwrap(),
                serde_json::json!({
                    "id": expected_id,
                    "severity": "hard",
                    "rule": "test-rule",
                    "category": "test-category",
                    "message": "Coordinate regression",
                    "file": file,
                    "span": {
                        "start": start, "end": end, "line": line, "column": column,
                        "endLine": end_line, "endColumn": end_column,
                    },
                    "entry": file,
                    "dependencyChain": [],
                }),
            );
        }
    }

    fn test_context_diagnostic(
        id: &str,
        entry: &str,
        severity: &str,
        terminal_file: Option<&str>,
    ) -> ContextDiagnostic {
        ContextDiagnostic {
            id: id.to_string(),
            severity: severity.to_string(),
            rule: format!("rule-{id}"),
            category: "test-category".to_string(),
            message: format!(
                "Repeated diagnostic definition {id} with enough detail to exercise compact encoding."
            ),
            file: "shared/finding.ts".to_string(),
            span: SourceSpan {
                start: 4,
                end: 12,
                line: 2,
                column: 3,
                end_line: 2,
                end_column: 11,
            },
            entry: entry.to_string(),
            dependency_chain: terminal_file
                .map(|terminal_file| {
                    vec![DependencyEdge {
                        from: entry.to_string(),
                        to: terminal_file.to_string(),
                        specifier: "../shared/finding".to_string(),
                        span: SourceSpan {
                            start: 0,
                            end: 3,
                            line: 1,
                            column: 0,
                            end_line: 1,
                            end_column: 3,
                        },
                    }]
                })
                .unwrap_or_default(),
        }
    }

    fn grouped_occurrences(grouped: &GroupedContextDiagnostics) -> BTreeSet<String> {
        let definitions = grouped
            .diagnostic_definitions
            .iter()
            .map(|definition| (definition.id.as_str(), definition))
            .collect::<BTreeMap<_, _>>();
        let mut occurrences = BTreeSet::new();
        for group in &grouped.diagnostic_groups {
            for id in &group.finding_ids {
                let definition = definitions.get(id.as_str()).unwrap();
                occurrences.insert(
                    serde_json::to_string(&ContextDiagnostic {
                        id: definition.id.clone(),
                        severity: definition.severity.clone(),
                        rule: definition.rule.clone(),
                        category: definition.category.clone(),
                        message: definition.message.clone(),
                        file: definition.file.clone(),
                        span: definition.span.clone(),
                        entry: group.entry.clone(),
                        dependency_chain: group.dependency_chain.clone(),
                    })
                    .unwrap(),
                );
            }
        }
        occurrences
    }

    fn repeated_finding_analysis_input(entry_count: usize) -> (TemporaryDirectory, ContextInput) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-grouped-{unique}")),
        );
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::create_dir_all(root.0.join("shared")).unwrap();
        let shared = "shared/common.ts";
        fs::write(
            root.0.join(shared),
            "import value from \"unlisted-package\";\nexport { value };\n",
        )
        .unwrap();
        let mut entry_candidates = Vec::new();
        let mut inputs = BTreeMap::new();
        for index in 0..entry_count {
            let entry = format!("convex/entry{index:03}.ts");
            fs::write(
                root.0.join(&entry),
                "import { value } from \"../shared/common\";\nexport const experimental_reuseContext = true;\nvoid value;\n",
            )
            .unwrap();
            inputs.insert(
                entry.clone(),
                EsbuildInput {
                    imports: vec![EsbuildImport {
                        path: shared.to_string(),
                        kind: "import-statement".to_string(),
                        original: Some("../shared/common".to_string()),
                        external: false,
                    }],
                },
            );
            entry_candidates.push(entry);
        }
        inputs.insert(
            shared.to_string(),
            EsbuildInput {
                imports: vec![EsbuildImport {
                    path: "unlisted-package".to_string(),
                    kind: "import-statement".to_string(),
                    original: Some("unlisted-package".to_string()),
                    external: true,
                }],
            },
        );
        let input = ContextInput {
            kind: INPUT_KIND.to_string(),
            repo_root: root.0.clone(),
            source_texts: None,
            functions_root: "convex".to_string(),
            roots: vec!["convex".to_string(), "shared".to_string()],
            entry_candidates,
            database_functions: Vec::new(),
            default_enabled: false,
            default_database_entries: Vec::new(),
            exclusions: BTreeMap::new(),
            virtual_inputs: BTreeSet::new(),
            metafile: EsbuildMetafile {
                inputs,
                outputs: BTreeMap::new(),
            },
            registration_adapter: test_registration_adapter_material(),
            external_dependencies: BTreeMap::new(),
            phase_timings_us: BTreeMap::new(),
        };
        (root, input)
    }

    #[test]
    fn context_module_preload_matches_serial_captured_sources_and_cache_hits() {
        let (root, mut input) = repeated_finding_analysis_input(4);
        let sources = input
            .metafile
            .inputs
            .keys()
            .map(|key| (key.clone(), fs::read_to_string(root.0.join(key)).unwrap()))
            .collect::<BTreeMap<_, _>>();
        input.source_texts = Some(sources.clone());
        fs::remove_file(root.0.join(&input.entry_candidates[0])).unwrap();
        for ignored in ["shared/data.json", "outside/ignored.ts"] {
            input.metafile.inputs.insert(
                ignored.to_string(),
                EsbuildInput {
                    imports: Vec::new(),
                },
            );
        }
        let mut results = Vec::new();
        for workers in [1, 3] {
            let cache_dir = root.0.join(format!("cache-{workers}"));
            for warm in [false, true] {
                let mut phases = PhaseMeasurements::default();
                let modules =
                    super::preload_context_modules(&input, &cache_dir, &mut phases, workers)
                        .unwrap();
                assert_eq!(
                    modules.keys().collect::<Vec<_>>(),
                    sources.keys().collect::<Vec<_>>()
                );
                assert_eq!(
                    phases.module_cache_hits,
                    if warm { sources.len() } else { 0 }
                );
                assert_eq!(
                    phases.module_cache_misses,
                    if warm { 0 } else { sources.len() }
                );
                results.push(
                    modules
                        .iter()
                        .map(|(key, module)| {
                            assert_eq!(module.source.as_str(), sources[key]);
                            (
                                key.clone(),
                                serde_json::to_value(module.summary.as_ref()).unwrap(),
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                );
            }
        }
        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn context_module_preload_drains_failures_and_reports_first_module() {
        let (root, mut input) = repeated_finding_analysis_input(3);
        let mut sources = input
            .metafile
            .inputs
            .keys()
            .map(|key| (key.clone(), fs::read_to_string(root.0.join(key)).unwrap()))
            .collect::<BTreeMap<_, _>>();
        sources.remove(&input.entry_candidates[0]);
        sources.remove(&input.entry_candidates[1]);
        input.source_texts = Some(sources.clone());
        for workers in [1, 3] {
            let cache_dir = root.0.join(format!("cache-{workers}"));
            let result = super::preload_context_modules(
                &input,
                &cache_dir,
                &mut PhaseMeasurements::default(),
                workers,
            );
            let error = match result {
                Ok(_) => panic!("missing captured sources must fail preload"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                format!(
                    "captured source is missing for first-party runtime input {}",
                    input.entry_candidates[0]
                )
            );
            // Even after earlier module failures, every other assigned load must finish before return.
            for (key, source) in &sources {
                let (_, phases) =
                    crate::load_compiler_module(&root.0, &cache_dir, key, Some(source)).unwrap();
                assert_eq!(phases.module_cache_hits, 1);
                assert_eq!(phases.module_cache_misses, 0);
            }
        }
    }

    fn captured_source_analysis_input() -> (TemporaryDirectory, ContextInput) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join(format!("context-captured-source-{unique}")),
        );
        fs::create_dir_all(root.0.join("convex")).unwrap();
        let entry = "convex/entry.ts".to_string();
        let source = "\u{feff}// café 😀\r\nexport const experimental_reuseContext = true;\r\nglobalThis.capturedWrite = 1;\r\n";
        let input = ContextInput {
            kind: INPUT_KIND.to_string(),
            repo_root: root.0.clone(),
            functions_root: "convex".to_string(),
            roots: vec!["convex".to_string()],
            source_texts: Some(BTreeMap::from([(entry.clone(), source.to_string())])),
            entry_candidates: vec![entry.clone()],
            database_functions: Vec::new(),
            default_enabled: false,
            default_database_entries: Vec::new(),
            exclusions: BTreeMap::new(),
            virtual_inputs: BTreeSet::new(),
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([(
                    entry,
                    EsbuildInput {
                        imports: Vec::new(),
                    },
                )]),
                outputs: BTreeMap::new(),
            },
            registration_adapter: test_registration_adapter_material(),
            external_dependencies: BTreeMap::new(),
            phase_timings_us: BTreeMap::new(),
        };
        (root, input)
    }

    #[test]
    fn captured_source_analysis_ignores_changed_and_removed_worktree_sources() {
        let (root, mut input) = captured_source_analysis_input();
        let cache = root.0.join("cache");
        let entry_path = root.0.join("convex/entry.ts");
        fs::write(
            &entry_path,
            "export const experimental_reuseContext = true;\n",
        )
        .unwrap();
        let captured = input.source_texts.take();
        input.kind = super::INPUT_KIND.to_string();
        let disk = analyze_context_reuse(
            &input,
            &cache,
            &mut PhaseMeasurements::default(),
            Instant::now(),
        )
        .unwrap();
        assert!(disk.safe);
        input.source_texts = captured;
        input.kind = INPUT_KIND.to_string();
        let first = analyze_context_reuse(
            &input,
            &cache,
            &mut PhaseMeasurements::default(),
            Instant::now(),
        )
        .unwrap();
        assert!(!first.safe);
        assert!(!first.diagnostics().is_empty());
        fs::remove_file(&entry_path).unwrap();
        let mut phases = PhaseMeasurements::default();
        let second = analyze_context_reuse(&input, &cache, &mut phases, Instant::now()).unwrap();
        assert_eq!(phases.module_cache_hits, 1);
        assert_eq!(phases.module_cache_misses, 0);
        assert_eq!(
            serde_json::to_value(first.diagnostics()).unwrap(),
            serde_json::to_value(second.diagnostics()).unwrap()
        );
        assert_eq!(first.safe, second.safe);

        input.source_texts.as_mut().unwrap().clear();
        let missing = analyze_context_reuse(
            &input,
            &cache,
            &mut PhaseMeasurements::default(),
            Instant::now(),
        )
        .err()
        .expect("missing captured input must fail");
        assert!(missing.to_string().contains("captured source is missing"));
    }

    #[test]
    fn captured_source_module_cache_hashes_consumed_text() {
        let (root, input) = captured_source_analysis_input();
        let entry = "convex/entry.ts";
        let cache = root.0.join("cache");
        let captured = &input.source_texts.as_ref().unwrap()[entry];
        let disk_source = "export const experimental_reuseContext = true;\n";
        fs::write(root.0.join(entry), disk_source).unwrap();
        let (supplied, supplied_phases) =
            crate::load_compiler_module(&root.0, &cache, entry, Some(captured)).unwrap();
        assert_eq!(supplied_phases.module_cache_misses, 1);
        assert_eq!(
            supplied.summary.source_hash,
            crate::hash_bytes(captured.as_bytes())
        );
        assert_eq!(supplied.source.as_str(), captured);
        let (disk, disk_phases) =
            crate::load_compiler_module(&root.0, &cache, entry, None).unwrap();
        assert_eq!(disk_phases.module_cache_misses, 1);
        assert_eq!(
            disk.summary.source_hash,
            crate::hash_bytes(disk_source.as_bytes())
        );
        assert_ne!(supplied.summary.cache_key, disk.summary.cache_key);
        let (same_text, same_phases) =
            crate::load_compiler_module(&root.0, &cache, entry, Some(disk_source)).unwrap();
        assert_eq!(same_phases.module_cache_hits, 1);
        assert_eq!(same_text.summary.cache_key, disk.summary.cache_key);
    }

    #[test]
    fn captured_source_inventory_reuses_loaded_text_for_reexport_spans() {
        let (root, mut input) = captured_source_analysis_input();
        let cache = root.0.join("cache");
        let entry = "convex/entry.ts";
        let target = "convex/target.ts";
        let entry_source = "\n\nexport { selected } from './target';\n";
        let target_source = "import { query } from './_generated/server';\nexport const selected = query({ handler: () => null });\n";
        input.metafile.inputs = BTreeMap::from([
            (
                entry.to_string(),
                EsbuildInput {
                    imports: vec![EsbuildImport {
                        path: target.to_string(),
                        kind: "import-statement".to_string(),
                        original: Some("./target".to_string()),
                        external: false,
                    }],
                },
            ),
            (
                target.to_string(),
                EsbuildInput {
                    imports: vec![EsbuildImport {
                        path: "convex/_generated/server.js".to_string(),
                        kind: "import-statement".to_string(),
                        original: Some("./_generated/server".to_string()),
                        external: false,
                    }],
                },
            ),
        ]);
        let mut modules = BTreeMap::new();
        for (key, source) in [(entry, entry_source), (target, target_source)] {
            let (module, _) =
                crate::load_compiler_module(&root.0, &cache, key, Some(source)).unwrap();
            modules.insert(key.to_string(), module);
        }
        // Neither first-party source exists on disk. Both call identity and displayed spans
        // must describe the already loaded text, including the re-export dependency edge.
        let inventory = build_source_inventory(
            &root.0,
            &input.metafile,
            &input.entry_candidates,
            &cache,
            &mut modules,
            &mut PhaseMeasurements::default(),
            &input.registration_adapter,
            &input.functions_root,
        )
        .unwrap();
        assert!(inventory.diagnostics.is_empty());
        assert_eq!(inventory.functions.len(), 1);
        let function = &inventory.functions[0];
        assert_eq!(function.udf_kind, "query");
        assert_eq!(
            function.registration_call.source_sha256,
            crate::hash_bytes(target_source.as_bytes())
        );
        assert_eq!(function.source_span.line, 3);
        assert_eq!(function.dependency_chain.len(), 1);
        assert_eq!(function.dependency_chain[0].span.line, 3);
    }

    #[test]
    fn context_reuse_diagnostic_encoding_argument_is_opt_in_and_strict() {
        let required = vec![
            "--graph".to_string(),
            "graph.json".to_string(),
            "--cache-dir".to_string(),
            "cache".to_string(),
        ];
        assert_eq!(
            parse_arguments(required.clone()).unwrap().3,
            DiagnosticEncoding::Expanded
        );
        let mut grouped = required.clone();
        grouped.extend(["--diagnostic-encoding".to_string(), "grouped".to_string()]);
        assert_eq!(
            parse_arguments(grouped.clone()).unwrap().3,
            DiagnosticEncoding::Grouped
        );
        let mut admission = required.clone();
        admission.extend(["--diagnostic-encoding".to_string(), "admission".to_string()]);
        assert_eq!(
            parse_arguments(admission).unwrap().3,
            DiagnosticEncoding::Admission
        );
        let mut supplemental = required.clone();
        supplemental.extend([
            "--third-party-policy".to_string(),
            "third-party-policy.json".to_string(),
        ]);
        assert_eq!(
            parse_arguments(supplemental.clone()).unwrap().5,
            Some(PathBuf::from("third-party-policy.json"))
        );
        supplemental.extend([
            "--third-party-policy".to_string(),
            "duplicate.json".to_string(),
        ]);
        assert!(parse_arguments(supplemental).is_err());

        let mut duplicate = grouped;
        duplicate.extend(["--diagnostic-encoding".to_string(), "grouped".to_string()]);
        assert!(parse_arguments(duplicate).is_err());
        let mut unknown = required;
        unknown.extend([
            "--diagnostic-encoding".to_string(),
            "unsupported".to_string(),
        ]);
        assert!(parse_arguments(unknown).is_err());

        for option in ["--graph", "--cache-dir", "--output"] {
            let mut duplicate = vec![
                "--graph".to_string(),
                "graph.json".to_string(),
                "--cache-dir".to_string(),
                "cache".to_string(),
            ];
            if option == "--output" {
                duplicate.extend(["--output".to_string(), "first.json".to_string()]);
            }
            duplicate.extend([option.to_string(), "second.json".to_string()]);
            assert!(parse_arguments(duplicate).is_err(), "{option}");
        }
    }

    #[test]
    fn grouped_diagnostics_preserve_occurrences_and_have_stable_order() {
        let diagnostics = vec![
            test_context_diagnostic("ctx-shared", "convex/entry-b.ts", "information", None),
            test_context_diagnostic(
                "ctx-z",
                "convex/entry-b.ts",
                "information",
                Some("shared/z.ts"),
            ),
            test_context_diagnostic(
                "ctx-d",
                "convex/entry-b.ts",
                "unsupported",
                Some("shared/a.ts"),
            ),
            test_context_diagnostic("ctx-a", "convex/entry-b.ts", "hard", Some("shared/a.ts")),
            test_context_diagnostic("ctx-shared", "convex/entry-a.ts", "information", None),
        ];
        let mut forward = GroupedContextDiagnosticsBuilder::default();
        for diagnostic in diagnostics.clone() {
            forward.insert(diagnostic).unwrap();
        }
        let forward = forward.finish();
        let mut reverse = GroupedContextDiagnosticsBuilder::default();
        for diagnostic in diagnostics.iter().cloned().rev() {
            reverse.insert(diagnostic).unwrap();
        }
        let reverse = reverse.finish();

        assert_eq!(
            serde_json::to_vec(&forward).unwrap(),
            serde_json::to_vec(&reverse).unwrap()
        );
        assert_eq!(
            forward
                .diagnostic_definitions
                .iter()
                .map(|definition| definition.id.as_str())
                .collect::<Vec<_>>(),
            ["ctx-a", "ctx-d", "ctx-shared", "ctx-z"]
        );
        assert_eq!(
            forward
                .diagnostic_groups
                .iter()
                .map(|group| group.entry.as_str())
                .collect::<Vec<_>>(),
            [
                "convex/entry-a.ts",
                "convex/entry-b.ts",
                "convex/entry-b.ts",
                "convex/entry-b.ts",
            ]
        );
        assert_eq!(forward.diagnostic_groups[1].finding_ids, ["ctx-shared"]);
        assert_eq!(forward.diagnostic_groups[2].finding_ids, ["ctx-a", "ctx-d"]);
        let expanded = diagnostics
            .iter()
            .map(|diagnostic| serde_json::to_string(diagnostic).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(grouped_occurrences(&forward), expanded);
    }

    #[test]
    fn grouped_diagnostics_reject_inconsistent_or_repeated_entry_identities() {
        let first = test_context_diagnostic("ctx-same", "convex/first.ts", "hard", None);
        let mut inconsistent =
            test_context_diagnostic("ctx-same", "convex/second.ts", "hard", None);
        inconsistent.category = "different-category".to_string();
        let mut builder = GroupedContextDiagnosticsBuilder::default();
        builder.insert(first.clone()).unwrap();
        assert!(
            builder
                .insert(inconsistent)
                .unwrap_err()
                .to_string()
                .contains("inconsistent definition fields")
        );

        let mut builder = GroupedContextDiagnosticsBuilder::default();
        builder.insert(first.clone()).unwrap();
        assert!(
            builder
                .insert(first)
                .unwrap_err()
                .to_string()
                .contains("occurs more than once for entry")
        );
    }

    fn assert_entry_result_parity(input: &ContextInput, retained: &mut EntryAnalysisCache) {
        let prior = serde_json::to_vec(&retained).unwrap();
        for encoding in [
            DiagnosticEncoding::Expanded,
            DiagnosticEncoding::Grouped,
            DiagnosticEncoding::Admission,
        ] {
            *retained = serde_json::from_slice(&prior).unwrap();
            let mut cached = serde_json::to_value(
                analyze_context_reuse_with_encoding(
                    input,
                    &input.repo_root.join("cache"),
                    &mut PhaseMeasurements::default(),
                    Instant::now(),
                    encoding,
                    Some(&mut *retained),
                )
                .unwrap(),
            )
            .unwrap();
            let mut fresh = serde_json::to_value(
                analyze_context_reuse_with_encoding(
                    input,
                    &input.repo_root.join("cache"),
                    &mut PhaseMeasurements::default(),
                    Instant::now(),
                    encoding,
                    None,
                )
                .unwrap(),
            )
            .unwrap();
            cached.as_object_mut().unwrap().remove("metrics");
            fresh.as_object_mut().unwrap().remove("metrics");
            assert_eq!(cached, fresh);
        }
    }

    #[test]
    fn entry_parent_paths_preserve_fifo_diamonds_cycles_and_finding_paths() {
        let (root, mut input) = repeated_finding_analysis_input(2);
        for (file, source, imports) in [
            (
                "shared/common.ts",
                "export { value } from \"./z-first\";\nexport { other } from \"./a-second\";\n",
                vec![
                    ("./z-first", "shared/z-first.ts", false),
                    ("./a-second", "shared/a-second.ts", false),
                ],
            ),
            (
                "shared/z-first.ts",
                "export { value } from \"./leaf\";\n",
                vec![("./leaf", "shared/leaf.ts", false)],
            ),
            (
                "shared/a-second.ts",
                "export { value as other } from \"./leaf\";\n",
                vec![("./leaf", "shared/leaf.ts", false)],
            ),
            (
                "shared/leaf.ts",
                concat!(
                    "export { other } from \"./common\";\n",
                    "export { missing } from \"unlisted-package\";\n",
                    "// context-reuse-check-suppress\nexport const value = 1;\n",
                    "// context-reuse-check-suppress top-level-mutable-binding: Verify unused declarations.\nexport const clean = 1;\n",
                    "// context-reuse-check-suppress top-level-mutable-binding: Verify selected findings.\nlet suppressed = 0;\n",
                    "let retained = 0;\n",
                ),
                vec![
                    ("./common", "shared/common.ts", false),
                    ("unlisted-package", "unlisted-package", true),
                ],
            ),
        ] {
            fs::write(root.0.join(file), source).unwrap();
            input.metafile.inputs.insert(
                file.to_string(),
                EsbuildInput {
                    imports: imports
                        .into_iter()
                        .map(|(specifier, target, external)| EsbuildImport {
                            path: target.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some(specifier.to_string()),
                            external,
                        })
                        .collect(),
                },
            );
        }
        let direct_entry = "convex/entry001.ts";
        let source = fs::read_to_string(root.0.join(direct_entry)).unwrap();
        fs::write(
            root.0.join(direct_entry),
            format!("{source}export {{ clean }} from \"../shared/leaf\";\n"),
        )
        .unwrap();
        input
            .metafile
            .inputs
            .get_mut(direct_entry)
            .unwrap()
            .imports
            .push(EsbuildImport {
                path: "shared/leaf.ts".to_string(),
                kind: "import-statement".to_string(),
                original: Some("../shared/leaf".to_string()),
                external: false,
            });
        let mut retained = EntryAnalysisCache::default();
        for expected_cache_counts in [(0, 2), (2, 0)] {
            let output = analyze_context_reuse_with_encoding(
                &input,
                &root.0.join("cache"),
                &mut PhaseMeasurements::default(),
                Instant::now(),
                DiagnosticEncoding::Expanded,
                Some(&mut retained),
            )
            .unwrap();
            assert_eq!((retained.hits, retained.misses), expected_cache_counts);
            assert_eq!(output.suppressed_findings, 2);
            let ContextDiagnosticOutput::Expanded { diagnostics } = output.diagnostic_output else {
                panic!("expected expanded diagnostics");
            };
            for entry in &input.entry_candidates {
                let leaf_findings = diagnostics
                    .iter()
                    .filter(|diagnostic| {
                        diagnostic.entry == *entry && diagnostic.file == "shared/leaf.ts"
                    })
                    .collect::<Vec<_>>();
                for rule in [
                    "top-level-mutable-binding",
                    "unsupported-runtime-dependency",
                    "invalid-suppression",
                ] {
                    assert!(
                        leaf_findings
                            .iter()
                            .any(|diagnostic| diagnostic.rule == rule)
                    );
                }
                let expected = if entry == direct_entry {
                    vec!["shared/leaf.ts"]
                } else {
                    vec!["shared/common.ts", "shared/z-first.ts", "shared/leaf.ts"]
                };
                for diagnostic in leaf_findings {
                    assert_eq!(
                        diagnostic
                            .dependency_chain
                            .iter()
                            .map(|edge| edge.to.as_str())
                            .collect::<Vec<_>>(),
                        expected
                    );
                    assert_eq!(diagnostic.dependency_chain[0].from, *entry);
                    for adjacent in diagnostic.dependency_chain.windows(2) {
                        assert_eq!(adjacent[0].to, adjacent[1].from);
                    }
                }
                let paths = &retained.entries[entry].paths;
                assert_eq!(paths.len(), 5);
                assert!(paths[entry].is_none());
                assert_eq!(paths.values().filter(|edge| edge.is_some()).count(), 4);
            }
            retained = serde_json::from_slice(&serde_json::to_vec(&retained).unwrap()).unwrap();
        }
        assert_entry_result_parity(&input, &mut retained);
    }

    #[test]
    fn cached_parent_paths_reject_missing_parents_cycles_and_wrong_roots() {
        let edge = test_context_diagnostic(
            "ctx-path",
            "convex/entry.ts",
            "hard",
            Some("shared/leaf.ts"),
        )
        .dependency_chain
        .pop()
        .unwrap();
        let entry = edge.from.clone();
        let leaf = edge.to.clone();
        let valid = BTreeMap::from([(entry.clone(), None), (leaf.clone(), Some(edge.clone()))]);
        super::validate_cached_dependency_paths(&entry, &valid).unwrap();
        assert_eq!(
            super::dependency_chain(&entry, &leaf, &valid)
                .unwrap()
                .len(),
            1
        );
        let mut missing = valid.clone();
        missing.remove(&entry);
        let mut cycle = valid.clone();
        cycle.insert(
            entry.clone(),
            Some(DependencyEdge {
                from: leaf,
                to: entry.clone(),
                ..edge
            }),
        );
        let mut wrong_root = valid;
        wrong_root.insert("shared/unrelated.ts".to_string(), None);
        for (paths, message) in [
            (missing, "no parent record"),
            (cycle, "contains a cycle"),
            (wrong_root, "wrong root"),
        ] {
            assert!(
                super::validate_cached_dependency_paths(&entry, &paths)
                    .unwrap_err()
                    .to_string()
                    .contains(message)
            );
        }
    }

    #[test]
    fn entry_results_reuse_unchanged_entries_and_preserve_complete_analysis() {
        let (root, mut input) = repeated_finding_analysis_input(2);
        let mut retained = EntryAnalysisCache::default();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (0, 2));
        // Exercise the same serialization boundary as successive native subprocesses.
        retained = serde_json::from_slice(&serde_json::to_vec(&retained).unwrap()).unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (2, 0));

        let leaf = root.0.join("convex/entry000.ts");
        let source = fs::read_to_string(&leaf).unwrap();
        fs::write(
            &leaf,
            format!("{source}\nlet retainedState = 1;\nvoid retainedState;\n"),
        )
        .unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (2, 0));

        // Moving a boundary's source position invalidates every consuming entry.
        fs::write(root.0.join("shared/common.ts"),
            "// context-reuse-check-suppress unsupported-runtime-dependency\nimport value from \"unlisted-package\";\nexport { value };\n").unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (0, 2));

        // Resolution changes are input changes even when every source byte is unchanged.
        input
            .metafile
            .inputs
            .get_mut("convex/entry000.ts")
            .unwrap()
            .imports[0]
            .external = true;
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (1, 1));

        // Selection is rerun, not retained as part of an otherwise reusable entry record.
        fs::write(&leaf, "export const noMarker = true;\n").unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (1, 0));
        assert_eq!(
            retained.entries.keys().collect::<Vec<_>>(),
            vec!["convex/entry001.ts"]
        );
        input.default_enabled = true;
        input.default_database_entries = vec!["convex/entry001.ts".to_string()];
        input
            .database_functions
            .push(super::GeneratedDatabaseFunction {
                entry_path: "convex/entry001.ts".to_string(),
                export_name: "missingRegistration".to_string(),
                udf_kind: "query".to_string(),
            });
        // Generated inventory and marker-policy diagnostics remain current even on a BFS hit.
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (1, 0));
    }

    #[test]
    fn entry_results_replay_module_facts_and_suppressions_without_serializing_facts() {
        let (root, mut input) = repeated_finding_analysis_input(2);
        let leaf = "shared/leaf.ts";
        fs::write(root.0.join(leaf), "export const value = 1;\n").unwrap();
        fs::write(
            root.0.join("shared/common.ts"),
            "export { value } from \"./leaf\";\n",
        )
        .unwrap();
        input
            .metafile
            .inputs
            .get_mut("shared/common.ts")
            .unwrap()
            .imports = vec![EsbuildImport {
            path: leaf.to_string(),
            kind: "import-statement".to_string(),
            original: Some("./leaf".to_string()),
            external: false,
        }];
        input.metafile.inputs.insert(
            leaf.to_string(),
            EsbuildInput {
                imports: Vec::new(),
            },
        );
        // Reviewed source still participates when emitted output removes every source edge.
        for index in 0..2 {
            input.metafile.outputs.insert(
                format!("out/entry{index:03}.js"),
                crate::EsbuildOutput {
                    entry_point: Some(format!("convex/entry{index:03}.ts")),
                    imports: Vec::new(),
                    inputs: BTreeMap::new(),
                },
            );
        }
        let mut retained = EntryAnalysisCache::default();
        assert_entry_result_parity(&input, &mut retained);
        let baseline_bytes = serde_json::to_vec(&retained).unwrap().len();
        for message in ["first failure", "changed failure text"] {
            fs::write(
                root.0.join(leaf),
                format!("export const value = 1;\nexport function fail() {{ throw new Error({message:?}); }}\n"),
            )
            .unwrap();
            assert_entry_result_parity(&input, &mut retained);
            assert_eq!((retained.hits, retained.misses), (2, 0));
        }
        let mut source = "export const value = 1;\n".to_string();
        for index in 0..64 {
            source.push_str(&format!("let retained{index} = 0;\n"));
        }
        fs::write(root.0.join(leaf), &source).unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (2, 0));
        // Public findings grow with the source; the retained transport does not duplicate them.
        assert!(serde_json::to_vec(&retained).unwrap().len() <= baseline_bytes + 32);
        for suppressed in [false, true] {
            if suppressed {
                source = source.replace(
                    "let retained0 = 0;",
                    "// context-reuse-check-suppress top-level-mutable-binding: This fixture verifies cached suppression replay.\nlet retained0 = 0;",
                );
                fs::write(root.0.join(leaf), &source).unwrap();
            }
            assert_entry_result_parity(&input, &mut retained);
            assert_eq!((retained.hits, retained.misses), (2, 0));
            let output = analyze_context_reuse_with_encoding(
                &input,
                &root.0.join("cache"),
                &mut PhaseMeasurements::default(),
                Instant::now(),
                DiagnosticEncoding::Expanded,
                Some(&mut retained),
            )
            .unwrap();
            assert_eq!((retained.hits, retained.misses), (2, 0));
            assert_eq!(output.suppressed_findings, if suppressed { 2 } else { 0 });
            let ContextDiagnosticOutput::Expanded { diagnostics } = output.diagnostic_output else {
                panic!("expected expanded diagnostics");
            };
            let mutable = diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.rule == "top-level-mutable-binding")
                .collect::<Vec<_>>();
            assert_eq!(mutable.len(), if suppressed { 126 } else { 128 });
            assert!(mutable.iter().all(|diagnostic| {
                diagnostic.file == leaf
                    && diagnostic.dependency_chain.len() == 2
                    && diagnostic.dependency_chain[0].from == diagnostic.entry
                    && diagnostic.dependency_chain[1].from == "shared/common.ts"
                    && diagnostic.dependency_chain[1].to == leaf
            }));
        }
    }

    #[test]
    fn entry_results_invalidate_when_pruned_import_usage_becomes_unaccounted() {
        let (root, mut input) = repeated_finding_analysis_input(2);
        input
            .metafile
            .inputs
            .get_mut("shared/common.ts")
            .unwrap()
            .imports
            .clear();
        let importer = root.0.join("shared/common.ts");
        let source = "import value from \"unlisted-package\";\n";
        fs::write(&importer, source).unwrap();
        let mut retained = EntryAnalysisCache::default();
        assert_entry_result_parity(&input, &mut retained);
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (2, 0));
        assert!(
            retained
                .entries
                .values()
                .all(|record| record.boundary_pending.is_empty())
        );

        // Metafile edges and the import span stay fixed; current usage changes graph findings.
        fs::write(&importer, format!("{source}void value;\n")).unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (0, 2));
        for record in retained.entries.values() {
            assert_eq!(record.boundary_pending.len(), 1);
            assert_eq!(
                record.boundary_pending[0].rule,
                "unaccounted-runtime-import"
            );
        }
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (2, 0));
        fs::write(&importer, source).unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (0, 2));
        assert!(
            retained
                .entries
                .values()
                .all(|record| record.boundary_pending.is_empty())
        );
    }

    #[test]
    fn entry_results_invalidate_missing_contribution_nodes_when_they_appear() {
        let (root, mut input) = repeated_finding_analysis_input(2);
        let asset = "assets/value.json";
        fs::create_dir_all(root.0.join("assets")).unwrap();
        fs::write(root.0.join(asset), "1").unwrap();
        let edge = &mut input
            .metafile
            .inputs
            .get_mut("shared/common.ts")
            .unwrap()
            .imports[0];
        edge.path = asset.to_string();
        edge.external = false;
        input.metafile.outputs.insert(
            "out/entry000.js".to_string(),
            crate::EsbuildOutput {
                entry_point: Some("convex/entry000.ts".to_string()),
                imports: Vec::new(),
                inputs: BTreeMap::new(),
            },
        );
        let mut retained = EntryAnalysisCache::default();
        assert_entry_result_parity(&input, &mut retained);
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (2, 0));
        assert_eq!(
            retained.entries["convex/entry000.ts"]
                .boundary_pending
                .len(),
            1
        );

        // Missing targets conservatively contribute; present empty targets can be pruned.
        input.metafile.inputs.insert(
            asset.to_string(),
            EsbuildInput {
                imports: Vec::new(),
            },
        );
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (0, 2));
        assert!(
            retained.entries["convex/entry000.ts"]
                .boundary_pending
                .is_empty()
        );
        assert_eq!(
            retained.entries["convex/entry001.ts"]
                .boundary_pending
                .len(),
            1
        );
        input.metafile.inputs.remove(asset).unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (0, 2));
        assert_eq!(
            retained.entries["convex/entry000.ts"]
                .boundary_pending
                .len(),
            1
        );
    }

    #[test]
    fn entry_results_invalidate_package_bytes_and_emitted_contributions() {
        let (root, mut input) = repeated_finding_analysis_input(2);
        let package = "node_modules/fixture-package/index.js";
        fs::create_dir_all(root.0.join("node_modules/fixture-package")).unwrap();
        fs::write(root.0.join(package), "export const value = 1;\n").unwrap();
        fs::write(
            root.0.join("node_modules/fixture-package/package.json"),
            r#"{"name":"fixture-package","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            root.0.join("package-lock.json"),
            r#"{"packages":{"node_modules/fixture-package":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        let edge = &mut input
            .metafile
            .inputs
            .get_mut("shared/common.ts")
            .unwrap()
            .imports[0];
        edge.path = package.to_string();
        edge.external = false;
        input.metafile.inputs.insert(
            package.to_string(),
            EsbuildInput {
                imports: Vec::new(),
            },
        );
        let mut retained = EntryAnalysisCache::default();
        assert_entry_result_parity(&input, &mut retained);
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (2, 0));
        // The import edge stays fixed, but package surface review consumes its usage too.
        let importer = root.0.join("shared/common.ts");
        let source = fs::read_to_string(&importer).unwrap();
        for usage in [
            "void value.member;",
            "void value[globalThis.selectedMember];",
        ] {
            fs::write(&importer, format!("{source}{usage}\n")).unwrap();
            assert_entry_result_parity(&input, &mut retained);
            assert_eq!((retained.hits, retained.misses), (0, 2));
        }
        fs::write(root.0.join(package), "export let value = 2;\n").unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (0, 2));

        input.metafile.outputs.insert(
            "out/entry000.js".to_string(),
            crate::EsbuildOutput {
                entry_point: Some("convex/entry000.ts".to_string()),
                imports: Vec::new(),
                inputs: BTreeMap::from([(
                    package.to_string(),
                    crate::EsbuildOutputContribution { bytes_in_output: 1 },
                )]),
            },
        );
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (1, 1));
        // Contribution magnitude is not traversal evidence; crossing zero changes membership.
        input
            .metafile
            .outputs
            .get_mut("out/entry000.js")
            .unwrap()
            .inputs
            .get_mut(package)
            .unwrap()
            .bytes_in_output = 100;
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (2, 0));
        input
            .metafile
            .outputs
            .get_mut("out/entry000.js")
            .unwrap()
            .inputs
            .get_mut(package)
            .unwrap()
            .bytes_in_output = 0;
        // A complete empty emitted set prunes the package only for this entry. The other
        // entry retains incomplete-output semantics and continues to consume package material.
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (1, 1));
        assert!(
            retained.entries["convex/entry000.ts"]
                .third_party_materials
                .is_empty()
        );
        fs::write(root.0.join(package), "export let value = 3;\n").unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (1, 1));
        fs::write(root.0.join("package-lock.json"), r#"{"packages":{}}"#).unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (1, 1));

        let asset = "node_modules/fixture-package/value.json";
        fs::write(root.0.join(asset), "1").unwrap();
        input
            .metafile
            .inputs
            .get_mut(package)
            .unwrap()
            .imports
            .push(EsbuildImport {
                path: asset.to_string(),
                kind: "import-statement".to_string(),
                original: Some("./value.json".to_string()),
                external: false,
            });
        input.metafile.inputs.insert(
            asset.to_string(),
            EsbuildInput {
                imports: Vec::new(),
            },
        );
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (0, 2));
        fs::write(root.0.join(asset), "2").unwrap();
        assert_entry_result_parity(&input, &mut retained);
        assert_eq!((retained.hits, retained.misses), (1, 1));
    }

    #[test]
    fn grouped_analysis_matches_expanded_shape_counts_and_safety() {
        let (root, input) = repeated_finding_analysis_input(2);
        let cache_dir = root.0.join("cache");
        let expanded = analyze_context_reuse(
            &input,
            &cache_dir,
            &mut PhaseMeasurements::default(),
            Instant::now(),
        )
        .unwrap();
        let grouped = analyze_context_reuse_with_encoding(
            &input,
            &cache_dir,
            &mut PhaseMeasurements::default(),
            Instant::now(),
            DiagnosticEncoding::Grouped,
            None,
        )
        .unwrap();

        let expanded_json = serde_json::to_value(&expanded).unwrap();
        let expanded_object = expanded_json.as_object().unwrap();
        assert_eq!(
            expanded_object
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "categoryCounts",
                "diagnosticCounts",
                "diagnostics",
                "entries",
                "kind",
                "metrics",
                "moduleSummarySchema",
                "policyFingerprint",
                "safe",
                "suppressedFindings",
                "thirdPartyMaterialFingerprints",
            ])
        );
        assert!(!expanded_object.contains_key("diagnosticEncoding"));
        assert!(!expanded_object.contains_key("diagnosticDefinitions"));
        assert!(!expanded_object.contains_key("diagnosticGroups"));
        let expanded_wire = serde_json::to_string(&expanded).unwrap();
        let field_offsets = [
            "kind",
            "safe",
            "entries",
            "diagnostics",
            "suppressedFindings",
            "diagnosticCounts",
            "categoryCounts",
            "metrics",
            "moduleSummarySchema",
            "policyFingerprint",
            "thirdPartyMaterialFingerprints",
        ]
        .map(|field| expanded_wire.find(&format!("\"{field}\":")).unwrap());
        assert!(field_offsets.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            expanded_object["diagnostics"].as_array().unwrap()[0]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "category",
                "dependencyChain",
                "entry",
                "file",
                "id",
                "message",
                "rule",
                "severity",
                "span",
            ])
        );
        let grouped_json = serde_json::to_value(&grouped).unwrap();
        let grouped_object = grouped_json.as_object().unwrap();
        assert!(!grouped_object.contains_key("diagnostics"));
        assert_eq!(grouped_object["diagnosticEncoding"], "grouped");
        assert!(grouped_object.contains_key("diagnosticDefinitions"));
        assert!(grouped_object.contains_key("diagnosticGroups"));
        let mut expected_grouped_keys = expanded_object.keys().cloned().collect::<BTreeSet<_>>();
        expected_grouped_keys.remove("diagnostics");
        expected_grouped_keys.extend([
            "diagnosticEncoding".to_string(),
            "diagnosticDefinitions".to_string(),
            "diagnosticGroups".to_string(),
        ]);
        assert_eq!(
            grouped_object.keys().cloned().collect::<BTreeSet<_>>(),
            expected_grouped_keys
        );

        assert_eq!(expanded.safe, grouped.safe);
        assert!(!expanded.safe);
        assert_eq!(expanded.diagnostic_counts, grouped.diagnostic_counts);
        assert_eq!(expanded.category_counts, grouped.category_counts);
        assert_eq!(expanded.suppressed_findings, grouped.suppressed_findings);
        assert_eq!(expanded.diagnostic_counts.get("hard"), Some(&2));
        let expanded_occurrences = expanded
            .diagnostics()
            .iter()
            .map(|diagnostic| serde_json::to_string(diagnostic).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            grouped_occurrences(grouped.grouped_diagnostics()),
            expanded_occurrences
        );
    }

    #[test]
    fn admission_diagnostics_merge_paths_preserve_occurrences_and_sort_entries() {
        let diagnostics = vec![
            test_context_diagnostic("ctx-z", "convex/entry-b.ts", "hard", Some("shared/z.ts")),
            test_context_diagnostic(
                "ctx-a",
                "convex/entry-b.ts",
                "unsupported",
                Some("shared/a.ts"),
            ),
            test_context_diagnostic("ctx-z", "convex/entry-a.ts", "hard", Some("shared/z.ts")),
            test_context_diagnostic("ctx-info", "convex/entry-a.ts", "information", None),
        ];
        let mut grouped = GroupedContextDiagnosticsBuilder::default();
        let mut admission = AdmissionContextDiagnosticsBuilder::default();
        let mut reverse = AdmissionContextDiagnosticsBuilder::default();
        for diagnostic in &diagnostics {
            grouped.insert(diagnostic.clone()).unwrap();
            admission.insert(diagnostic.clone()).unwrap();
        }
        for diagnostic in diagnostics.into_iter().rev() {
            reverse.insert(diagnostic).unwrap();
        }
        let grouped = serde_json::to_value(grouped.finish()).unwrap();
        let admission = serde_json::to_value(admission.finish()).unwrap();
        assert_eq!(admission, serde_json::to_value(reverse.finish()).unwrap());
        assert_eq!(
            admission["diagnosticDefinitions"],
            grouped["diagnosticDefinitions"]
        );
        assert_eq!(admission["diagnosticEncoding"], "admission");
        assert_eq!(
            admission["diagnosticGroups"],
            serde_json::json!([
                { "entry": "convex/entry-a.ts", "findingIds": ["ctx-info", "ctx-z"] },
                { "entry": "convex/entry-b.ts", "findingIds": ["ctx-a", "ctx-z"] },
            ])
        );
        assert_eq!(grouped["diagnosticGroups"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn admission_diagnostics_reject_inconsistent_or_repeated_entry_identities() {
        let first = test_context_diagnostic("ctx-same", "convex/first.ts", "hard", None);
        let mut inconsistent = first.clone();
        inconsistent.entry = "convex/second.ts".to_string();
        inconsistent.category = "different-category".to_string();
        let mut builder = AdmissionContextDiagnosticsBuilder::default();
        builder.insert(first.clone()).unwrap();
        assert!(
            builder
                .insert(inconsistent)
                .unwrap_err()
                .to_string()
                .contains("inconsistent definition fields")
        );

        let mut duplicate = first.clone();
        duplicate.dependency_chain = test_context_diagnostic(
            "ctx-same",
            "convex/first.ts",
            "hard",
            Some("shared/another-path.ts"),
        )
        .dependency_chain;
        let mut builder = AdmissionContextDiagnosticsBuilder::default();
        builder.insert(first).unwrap();
        assert!(
            builder
                .insert(duplicate)
                .unwrap_err()
                .to_string()
                .contains("occurs more than once for entry")
        );
    }

    #[test]
    fn admission_analysis_preserves_global_findings_suppression_and_policy() {
        let (root, mut input) = repeated_finding_analysis_input(3);
        input.default_enabled = true;
        input.default_database_entries = input.entry_candidates[..2].to_vec();
        let global_entry = input.entry_candidates[2].clone();
        input.exclusions.insert(
            global_entry.clone(),
            "This unused exclusion must remain a global blocker.".to_string(),
        );
        fs::write(root.0.join("shared/common.ts"), concat!(
            "import value from \"unlisted-package\";\nexport { value };\n",
            "// context-reuse-check-suppress top-level-mutable-binding: This fixture verifies compact suppression parity.\n",
            "let suppressed = 0;\nlet retained = 0;\n",
        )).unwrap();
        let mut outputs = Vec::new();
        for encoding in [
            DiagnosticEncoding::Expanded,
            DiagnosticEncoding::Grouped,
            DiagnosticEncoding::Admission,
        ] {
            let output = analyze_context_reuse_with_encoding(
                &input,
                &root.0.join("cache"),
                &mut PhaseMeasurements::default(),
                Instant::now(),
                encoding,
                None,
            )
            .unwrap();
            outputs.push(serde_json::to_value(output).unwrap());
        }
        let expanded = &outputs[0];
        let grouped = &outputs[1];
        let admission = &outputs[2];
        let mut by_entry = BTreeMap::<String, BTreeSet<String>>::new();
        for diagnostic in expanded["diagnostics"].as_array().unwrap() {
            by_entry
                .entry(diagnostic["entry"].as_str().unwrap().to_string())
                .or_default()
                .insert(diagnostic["id"].as_str().unwrap().to_string());
        }
        assert!(by_entry.contains_key(&global_entry));
        assert!(!input.default_database_entries.contains(&global_entry));
        let expected_groups = by_entry.into_iter().map(|(entry, finding_ids)| {
            serde_json::json!({ "entry": entry, "findingIds": finding_ids })
        }).collect::<Vec<_>>();
        assert_eq!(
            admission["diagnosticGroups"],
            serde_json::json!(expected_groups)
        );
        assert_eq!(
            admission["diagnosticDefinitions"],
            grouped["diagnosticDefinitions"]
        );
        assert_eq!(admission["safe"], false);
        assert!(admission["suppressedFindings"].as_u64().unwrap() > 0);
        for field in expanded
            .as_object()
            .unwrap()
            .keys()
            .filter(|field| !matches!(field.as_str(), "metrics" | "diagnostics"))
        {
            assert_eq!(admission[field], expanded[field], "{field}");
            assert_eq!(admission[field], grouped[field], "{field}");
        }
    }

    #[test]
    fn grouped_encoding_materially_reduces_repeated_finding_bytes() {
        let diagnostics = (0..256)
            .map(|index| {
                test_context_diagnostic(
                    "ctx-repeated",
                    &format!("convex/entry{index:03}.ts"),
                    "hard",
                    None,
                )
            })
            .collect::<Vec<_>>();
        let expanded_bytes = serde_json::to_vec(&ContextDiagnosticOutput::Expanded {
            diagnostics: diagnostics.clone(),
        })
        .unwrap()
        .len();
        let mut builder = GroupedContextDiagnosticsBuilder::default();
        for diagnostic in diagnostics {
            builder.insert(diagnostic).unwrap();
        }
        let grouped_bytes = serde_json::to_vec(&ContextDiagnosticOutput::Grouped(builder.finish()))
            .unwrap()
            .len();

        assert!(
            grouped_bytes * 2 < expanded_bytes,
            "grouped bytes {grouped_bytes} were not less than half of expanded bytes {expanded_bytes}"
        );
    }

    fn reviewed_policy_fingerprints(id: &str) -> &'static [String] {
        &reviewed_third_party_policy()
            .surfaces
            .iter()
            .find(|surface| surface.id == id)
            .unwrap()
            .fingerprints
    }

    fn reviewed_policy_surface_mut<'a>(source: &'a mut Value, id: &str) -> &'a mut Value {
        source["surfaces"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|surface| surface["id"] == id)
            .unwrap()
    }

    fn assert_reviewed_policy_mutation_rejected(
        source: &Value,
        description: &str,
        mutate: impl FnOnce(&mut Value),
    ) {
        let mut mutated = source.clone();
        mutate(&mut mutated);
        assert!(
            parse_reviewed_third_party_policy(&mutated.to_string()).is_err(),
            "accepted invalid reviewed third-party policy mutation: {description}"
        );
    }

    #[test]
    fn reviewed_third_party_policy_rotates_the_context_policy_fingerprint() {
        assert_eq!(
            POLICY_SOURCES.last().copied(),
            Some(REVIEWED_THIRD_PARTY_POLICY_SOURCE)
        );
        let current = context_policy_fingerprint_from_sources(POLICY_SOURCES.iter().copied());
        let changed_policy = format!("{REVIEWED_THIRD_PARTY_POLICY_SOURCE} ");
        let mut changed_sources = POLICY_SOURCES.to_vec();
        *changed_sources.last_mut().unwrap() = &changed_policy;
        assert_ne!(
            context_policy_fingerprint_from_sources(changed_sources.iter().copied()),
            current
        );
    }

    #[test]
    fn callable_return_syntax_reuse_preserves_provenance_growth_and_cycles() {
        let source = r#"import { make } from "package";
function direct() { if (flag) return 0; return make; }
function nestedOnly() { function hidden() { return make; } return; }
function derived() { return make(); }
function left() { return right(); }
function right() { return left(); }
const concise = () => make;
"#;
        let allocator = super::Allocator::default();
        let parsed = super::Parser::new(&allocator, source, super::SourceType::mjs()).parse();
        assert!(parsed.diagnostics.is_empty());
        let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false)).unwrap();
        let bindings = super::BindingModel::new(&ast).unwrap();
        let imported = BTreeSet::from([bindings.binding_at("make", source.len() as u32).unwrap()]);
        let mut callables = BTreeMap::new();
        for statement in ast["body"].as_array().unwrap() {
            if super::node_kind(statement) == Some("FunctionDeclaration") {
                callables.insert(super::identifier(&statement["id"]).unwrap(), statement);
            } else if super::node_kind(statement) == Some("VariableDeclaration") {
                let declaration = &statement["declarations"][0];
                callables.insert(
                    super::identifier(&declaration["id"]).unwrap(),
                    &declaration["init"],
                );
            }
        }
        for (name, expected_derived, expected_binding) in [
            ("direct", true, true),
            ("nestedOnly", false, false),
            ("derived", true, false),
            ("concise", true, true),
            ("left", true, true),
        ] {
            let callable = callables[name];
            let mut active = BTreeSet::new();
            // The same syntax must be reevaluated when a propagation pass adds import provenance.
            for imported_bindings in [&BTreeSet::new(), &imported, &BTreeSet::new()] {
                let cycle = name == "left";
                assert_eq!(
                    super::callable_returns_import_value(
                        callable,
                        &bindings,
                        imported_bindings,
                        &mut active
                    ),
                    cycle || (!imported_bindings.is_empty() && expected_derived),
                    "{name}"
                );
                assert!(active.is_empty());
                assert_eq!(
                    super::callable_returns_import_binding_value(
                        callable,
                        &bindings,
                        imported_bindings,
                        &mut active
                    ),
                    cycle || (!imported_bindings.is_empty() && expected_binding),
                    "{name}"
                );
                assert!(active.is_empty());
            }
        }
        let direct = callables["direct"];
        let span = super::node_span(direct).unwrap();
        let first = bindings.return_expressions(span, &direct["body"]);
        let reused = bindings.return_expressions(span, &direct.clone()["body"]);
        assert!(std::rc::Rc::ptr_eq(&first, &reused));
        // An active ancestor still controls cycle conservatism even after syntax has been cached.
        let mut active = BTreeSet::from([span]);
        assert!(super::callable_returns_import_binding_value(
            direct,
            &bindings,
            &BTreeSet::new(),
            &mut active
        ));
        assert_eq!(active, BTreeSet::from([span]));
    }

    #[test]
    fn import_propagation_preorder_replay_preserves_each_pass() {
        fn recursive_pass(
            value: &serde_json::Value,
            bindings: &super::BindingModel,
            derived: &mut BTreeSet<usize>,
            exact: &mut BTreeSet<usize>,
            escapes: bool,
        ) -> anyhow::Result<(bool, bool)> {
            let (mut changed, mut escaped) =
                super::propagate_import_value(value, bindings, derived, exact, escapes)?;
            for child in super::ast_runtime_children(value) {
                let (child_changed, child_escaped) =
                    recursive_pass(child, bindings, derived, exact, escapes)?;
                changed |= child_changed;
                escaped |= child_escaped;
            }
            Ok((changed, escaped))
        }

        let source = r#"
import { safe } from "pkg";
function forward(value) { const local = value; return local; }
const alias = safe;
const derived = forward(alias());
const holder = {};
holder.value = alias;
for (const item of [holder]) { forward(item); }
function shadow(safe) { const local = safe; return local; }
export const escaped = alias;
"#;
        let model = super::ImportSurfaceModel::parse("convex/replay.ts", source).unwrap();
        let seed = BTreeSet::from([model
            .bindings
            .binding_at("safe", source.len() as u32)
            .unwrap()]);
        let mut nodes = Vec::new();
        super::collect_import_propagation_nodes(&model.ast, &mut nodes);
        for escapes in [false, true] {
            let (mut derived, mut exact) = (seed.clone(), seed.clone());
            let (mut recursive_derived, mut recursive_exact) = (seed.clone(), seed.clone());
            loop {
                let replay = super::propagate_import_values(
                    &nodes,
                    &model.bindings,
                    &mut derived,
                    &mut exact,
                    escapes,
                )
                .unwrap();
                let recursive = recursive_pass(
                    &model.ast,
                    &model.bindings,
                    &mut recursive_derived,
                    &mut recursive_exact,
                    escapes,
                )
                .unwrap();
                assert_eq!(replay, recursive);
                assert_eq!(derived, recursive_derived);
                assert_eq!(exact, recursive_exact);
                if !replay.0 {
                    assert_eq!(replay.1, escapes);
                    break;
                }
            }
        }
    }

    #[test]
    fn import_surface_models_reuse_syntax_without_reusing_reference_policy() {
        let module_key = "convex/import_surface.ts";
        let source = r#"
import { safe } from "pkg";
import { unsafe } from "pkg";
import { derive } from "other";
import { escape } from "helper";
function inspect() {
    const alias = unsafe;
    alias.meta();
    const value = derive();
    value.meta();
    consume(escape);
    return safe();
}
"#;
        let summary = crate::summarize_module(
            module_key,
            std::path::Path::new(module_key),
            source,
            "test-source-hash",
            "test-cache-key",
            "test-compiler-fingerprint",
            "test-policy-fingerprint",
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let module = crate::LoadedModule::new(summary, source.to_string());
        let mut models = super::ImportSurfaceModels::new();
        let before = super::IMPORT_SURFACE_CONSTRUCTIONS.with(std::cell::Cell::get);
        for (local, derived, escapes, forbid_meta, expected) in [
            ("safe", true, true, true, false),
            ("unsafe", true, false, true, true),
            ("unsafe", true, false, false, false),
            ("unsafe", true, false, true, true),
            ("derive", true, false, true, true),
            ("derive", false, false, true, false),
            ("escape", false, true, true, true),
            ("escape", false, false, true, false),
            ("safe", true, true, true, false),
        ] {
            let binding = module
                .summary
                .imports
                .values()
                .find(|b| b.local == local)
                .unwrap();
            let reference = module
                .summary
                .context_reuse
                .references
                .iter()
                .find(|r| r.start == binding.start && r.end == binding.end)
                .unwrap();
            assert_eq!(
                super::import_has_unsupported_member_access(
                    &mut models,
                    module_key,
                    &module,
                    source,
                    reference,
                    if forbid_meta { &["meta"] } else { &[] },
                    derived,
                    escapes,
                ),
                expected,
                "{local}: derived={derived}, escapes={escapes}, forbid_meta={forbid_meta}",
            );
            assert_eq!(models.len(), 1);
            assert_eq!(
                super::IMPORT_SURFACE_CONSTRUCTIONS.with(std::cell::Cell::get),
                before + 1
            );
        }

        let reference = &module.summary.context_reuse.references[0];
        for _ in 0..2 {
            assert!(super::import_has_unsupported_member_access(
                &mut models,
                "convex/invalid.ts",
                &module,
                "const =",
                reference,
                &[],
                false,
                false,
            ));
            assert_eq!(models.len(), 2);
            assert_eq!(
                super::IMPORT_SURFACE_CONSTRUCTIONS.with(std::cell::Cell::get),
                before + 2
            );
        }
        assert!(models.get("convex/invalid.ts").unwrap().is_err());
    }

    #[test]
    fn generic_reviewed_third_party_policy_modes_are_data_driven() {
        let policy = parse_reviewed_third_party_policy(
            r#"{
  "kind":"convex-context-reuse-reviewed-third-party-policy",
  "schemaVersion":1,
  "surfaces":[
    {"id":"generic-accept","fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"admission":{"mode":"accept","reason":"The exact reviewed closure is stateless."}},
    {"id":"generic-named","fingerprints":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"admission":{"mode":"named-imports","exports":["getPage"],"reason":"Only getPage was reviewed."}},
    {"id":"generic-reject","fingerprints":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"admission":{"mode":"reject","reason":"The closure retains runtime state."}}
  ]
}"#,
        )
        .unwrap();
        let repo_root = fixture_repository_root();
        let module_key =
            "scripts/test-fixtures/convex-context-reuse/convex-helpers-surface/pagination.ts";
        let source = fs::read_to_string(repo_root.join(module_key)).unwrap();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let cache_dir =
            env::temp_dir().join(format!("convex-context-reuse-generic-policy-{unique}"));
        let mut modules = BTreeMap::new();
        load_module(
            &repo_root,
            &cache_dir,
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let module = modules.get(module_key).unwrap();
        let reference = module
            .summary
            .context_reuse
            .references
            .iter()
            .find(|reference| reference.specifier == "convex-helpers/server/pagination")
            .unwrap();
        for (fingerprint, expected) in [
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                true,
            ),
            (
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                true,
            ),
            (
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                false,
            ),
        ] {
            let surface = reviewed_third_party_surface_in_policy(&policy, fingerprint).unwrap();
            assert_eq!(
                matches!(
                    review_third_party_surface_policy(
                        &mut BTreeMap::new(),
                        module_key,
                        module,
                        &source,
                        reference,
                        surface
                    ),
                    ThirdPartyDisposition::Accepted
                ),
                expected
            );
        }
        fs::remove_dir_all(cache_dir).unwrap();
    }

    #[test]
    fn supplemental_policy_declares_exact_named_import_uses() {
        let supplemental = parse_reviewed_third_party_policy(
            r#"{
  "kind":"convex-context-reuse-reviewed-third-party-policy",
  "schemaVersion":1,
  "surfaces":[
    {"id":"error-inspection","fingerprints":["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"admission":{"mode":"named-import-uses","instanceofTargets":["ApiError"],"staticCalls":[{"import":"protocol","members":["RpcError","is"]}],"reason":"Only exact error inspection operations are reviewed."}}
  ]
}"#,
        )
        .unwrap();
        let fingerprint =
            super::context_policy_fingerprint_with_supplemental(Some(&supplemental)).unwrap();
        assert_ne!(fingerprint, super::context_policy_fingerprint());
        let policy = super::merge_reviewed_third_party_policy(Some(supplemental)).unwrap();
        let surface = reviewed_third_party_surface_in_policy(
            &policy,
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();

        for (source, expected) in [
            (
                r#"import { ApiError, protocol } from "@example/errors";
export function classify(error) {
  return error instanceof ApiError || protocol.RpcError.is(error);
}
"#,
                true,
            ),
            (
                r#"import { ApiError } from "@example/errors";
export function construct() { return new ApiError(); }
"#,
                false,
            ),
            (
                r#"import { protocol } from "@example/errors";
export function inspect(error) { return protocol.RpcError.wrap(error); }
"#,
                false,
            ),
            (
                r#"import { protocol as wireProtocol } from "@example/errors";
export function inspect(error) { return wireProtocol.RpcError.is(error); }
"#,
                true,
            ),
            (
                r#"import { protocol } from "@example/errors";
export function inspect(error) { return new protocol.RpcError.is(error); }
"#,
                false,
            ),
            (
                r#"import { protocol } from "@example/errors";
export function inspect(error) { return protocol["RpcError"].is(error); }
"#,
                false,
            ),
            (
                r#"import { ApiError } from "@example/errors";
function local(ApiError) { return new ApiError(); }
export function classify(error) { return error instanceof ApiError; }
"#,
                true,
            ),
            (
                r#"import { ApiError } from "@example/errors";
export function classify(ApiError, error) { return error instanceof ApiError; }
"#,
                false,
            ),
        ] {
            let module_key = "convex/error-inspection.ts";
            let summary = crate::summarize_module(
                module_key,
                std::path::Path::new(module_key),
                source,
                "test-source-hash",
                "test-cache-key",
                "test-compiler-fingerprint",
                "test-policy-fingerprint",
                &mut PhaseMeasurements::default(),
            )
            .unwrap();
            let module = crate::LoadedModule::new(summary, source.to_string());
            let reference = module
                .summary
                .context_reuse
                .references
                .iter()
                .find(|reference| reference.specifier == "@example/errors")
                .unwrap();
            assert_eq!(
                matches!(
                    review_third_party_surface_policy(
                        &mut BTreeMap::new(),
                        module_key,
                        &module,
                        source,
                        reference,
                        surface,
                    ),
                    ThirdPartyDisposition::Accepted
                ),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn named_import_use_policy_rejects_ambiguous_or_non_identifier_paths() {
        for (description, source) in [
            (
                "overlapping use kinds",
                r#"{
  "kind":"convex-context-reuse-reviewed-third-party-policy",
  "schemaVersion":1,
  "surfaces":[
    {"id":"error-inspection","fingerprints":["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"admission":{"mode":"named-import-uses","instanceofTargets":["ApiError"],"staticCalls":[{"import":"ApiError","members":["is"]}],"reason":"Only exact error inspection operations are reviewed."}}
  ]
}"#,
            ),
            (
                "encoded computed path",
                r#"{
  "kind":"convex-context-reuse-reviewed-third-party-policy",
  "schemaVersion":1,
  "surfaces":[
    {"id":"error-inspection","fingerprints":["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"admission":{"mode":"named-import-uses","instanceofTargets":[],"staticCalls":[{"import":"protocol","members":["RpcError['is']"]}],"reason":"Only exact error inspection operations are reviewed."}}
  ]
}"#,
            ),
        ] {
            assert!(
                parse_reviewed_third_party_policy(source).is_err(),
                "accepted {description}"
            );
        }
    }

    #[test]
    fn generic_reviewed_third_party_acceptance_requires_static_named_esm_imports() {
        let policy = parse_reviewed_third_party_policy(
            r#"{
  "kind":"convex-context-reuse-reviewed-third-party-policy",
  "schemaVersion":1,
  "surfaces":[
    {"id":"generic-accept","fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"admission":{"mode":"accept","reason":"The exact reviewed closure is stateless."}},
    {"id":"generic-named","fingerprints":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"admission":{"mode":"named-imports","exports":["getIndexFields","getPage","z"],"reason":"Only the declared named imports were reviewed."}}
  ]
}"#,
        )
        .unwrap();
        let repo_root = fixture_repository_root();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-generic-imports-{unique}")),
        );
        let cache_dir = root.0.join("cache");
        let mut surface_models = super::ImportSurfaceModels::new();
        for (fixture, expected) in [
            ("pagination.ts", true),
            ("pagination-result-dynamic.ts", true),
            ("stream-aliased.ts", true),
            ("stream-destructured-alias.ts", true),
            ("stream-instantiated-call.ts", true),
            ("stream-helper-apply-return.ts", false),
            ("stream-helper-call-result.ts", true),
            ("stream-helper-call-return.ts", false),
            ("stream-helper-awaited-return.ts", false),
            ("stream-helper-bound-invocation.ts", false),
            ("stream-helper-bound-unknown.ts", false),
            ("stream-helper-bound-return.ts", false),
            ("stream-helper-call-this.ts", false),
            ("stream-for-of-alias.ts", false),
            ("stream-for-of-property-alias.ts", false),
            ("stream-for-of-receiver.ts", false),
            ("stream-export-alias.ts", false),
            ("stream-export-declaration.ts", false),
            ("stream-export-default.ts", false),
            ("stream-export-instantiated-alias.ts", false),
            ("stream-export-reassigned-declaration.ts", false),
            ("stream-export-reassigned-default.ts", false),
            ("stream-commonjs-export.ts", false),
            ("stream-destructured-receiver-assignment.ts", false),
            ("stream-helper-receiver-assignment.ts", false),
            ("stream-class-field.ts", false),
            ("stream-class-extends.ts", false),
            ("stream-bound-import.ts", false),
            ("stream-constructed-import.ts", false),
            ("stream-jsx-component.tsx", false),
            ("stream-jsx-escape.tsx", false),
            ("stream-jsx-spread-child.tsx", false),
            ("pagination-namespace.ts", false),
            ("stream-default-namespace.ts", false),
            ("stream-helper-parameter.ts", false),
            ("stream-helper-nested-return.ts", false),
            ("stream-helper-return.ts", false),
            ("stream-helper-this-assignment.ts", false),
            ("stream-helper-throw.ts", false),
            ("stream-unknown-helper-parameter.ts", false),
            ("stream-reexport.ts", false),
            ("stream-require.ts", false),
            ("stream-side-effect.ts", false),
            ("zod-dynamic-direct.ts", false),
        ] {
            let module_key = format!(
                "scripts/test-fixtures/convex-context-reuse/convex-helpers-surface/{fixture}"
            );
            let source = fs::read_to_string(repo_root.join(&module_key)).unwrap();
            let mut modules = BTreeMap::new();
            load_module(
                &repo_root,
                &cache_dir,
                &module_key,
                &mut modules,
                &mut PhaseMeasurements::default(),
            )
            .unwrap();
            let module = modules.get(&module_key).unwrap();
            let references = &module.summary.context_reuse.references;
            assert_eq!(references.len(), 1, "fixture {fixture}");
            let before = super::IMPORT_SURFACE_CONSTRUCTIONS.with(std::cell::Cell::get);
            for fingerprint in [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ] {
                let surface = reviewed_third_party_surface_in_policy(&policy, fingerprint).unwrap();
                assert_eq!(
                    matches!(
                        review_third_party_surface_policy(
                            &mut surface_models,
                            &module_key,
                            module,
                            &source,
                            &references[0],
                            surface,
                        ),
                        ThirdPartyDisposition::Accepted
                    ),
                    expected,
                    "fixture {fixture}, policy {}",
                    surface.id,
                );
            }
            // Both policy modes share syntax, including when earlier modules remain retained.
            assert_eq!(
                super::IMPORT_SURFACE_CONSTRUCTIONS.with(std::cell::Cell::get) - before,
                usize::from(surface_models.contains_key(&module_key)),
                "fixture {fixture}",
            );
        }
    }

    #[test]
    fn reviewed_third_party_policy_schema_is_closed() {
        let source: Value = serde_json::from_str(REVIEWED_THIRD_PARTY_POLICY_SOURCE).unwrap();
        parse_reviewed_third_party_policy(REVIEWED_THIRD_PARTY_POLICY_SOURCE).unwrap();
        assert!(parse_reviewed_third_party_policy("{").is_err());

        assert_reviewed_policy_mutation_rejected(&source, "kind", |policy| {
            policy["kind"] = Value::String("unknown".into());
        });
        assert_reviewed_policy_mutation_rejected(&source, "schema version", |policy| {
            policy["schemaVersion"] = Value::from(2);
        });
        assert_reviewed_policy_mutation_rejected(&source, "unknown top-level field", |policy| {
            policy["unexpected"] = Value::Bool(true);
        });
        assert_reviewed_policy_mutation_rejected(&source, "unknown surface field", |policy| {
            policy["surfaces"][0]["unexpected"] = Value::Bool(true);
        });
        assert_reviewed_policy_mutation_rejected(&source, "unknown admission field", |policy| {
            policy["surfaces"][0]["admission"]["unexpected"] = Value::Bool(true);
        });
        assert_reviewed_policy_mutation_rejected(&source, "unknown admission mode", |policy| {
            policy["surfaces"][0]["admission"]["mode"] = Value::String("unknown".into());
        });
        assert_reviewed_policy_mutation_rejected(&source, "empty surfaces", |policy| {
            policy["surfaces"] = Value::Array(Vec::new());
        });

        for id in ["convex-helpers-pagination", "stateless", "zod"] {
            assert_reviewed_policy_mutation_rejected(&source, "empty reason", |policy| {
                reviewed_policy_surface_mut(policy, id)["admission"]["reason"] =
                    Value::String(String::new());
            });
        }
        assert_reviewed_policy_mutation_rejected(&source, "reason whitespace", |policy| {
            policy["surfaces"][0]["admission"]["reason"] = Value::String(" padded".into());
        });
        assert_reviewed_policy_mutation_rejected(&source, "reason line break", |policy| {
            policy["surfaces"][0]["admission"]["reason"] = Value::String("line\nbreak".into());
        });
        assert_reviewed_policy_mutation_rejected(&source, "reason Unicode line break", |policy| {
            policy["surfaces"][0]["admission"]["reason"] =
                Value::String("line\u{2028}break".into());
        });
    }

    #[test]
    fn reviewed_third_party_policy_requires_ordered_unique_identities() {
        let source: Value = serde_json::from_str(REVIEWED_THIRD_PARTY_POLICY_SOURCE).unwrap();

        assert_reviewed_policy_mutation_rejected(&source, "malformed surface ID", |policy| {
            policy["surfaces"][0]["id"] = Value::String("Not-Kebab-Case".into());
        });
        assert_reviewed_policy_mutation_rejected(&source, "unsorted surface IDs", |policy| {
            policy["surfaces"].as_array_mut().unwrap().swap(0, 1);
        });
        assert_reviewed_policy_mutation_rejected(&source, "duplicate surface IDs", |policy| {
            let id = policy["surfaces"][0]["id"].clone();
            policy["surfaces"][1]["id"] = id;
        });
        assert_reviewed_policy_mutation_rejected(&source, "empty fingerprints", |policy| {
            policy["surfaces"][0]["fingerprints"] = Value::Array(Vec::new());
        });
        assert_reviewed_policy_mutation_rejected(&source, "malformed fingerprint", |policy| {
            policy["surfaces"][0]["fingerprints"][0] = Value::String("not-a-digest".into());
        });
        assert_reviewed_policy_mutation_rejected(&source, "unsorted fingerprints", |policy| {
            reviewed_policy_surface_mut(policy, "zod")["fingerprints"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
        });
        assert_reviewed_policy_mutation_rejected(
            &source,
            "duplicate local fingerprint",
            |policy| {
                let fingerprints = reviewed_policy_surface_mut(policy, "zod")["fingerprints"]
                    .as_array_mut()
                    .unwrap();
                fingerprints[1] = fingerprints[0].clone();
            },
        );
        assert_reviewed_policy_mutation_rejected(
            &source,
            "duplicate global fingerprint",
            |policy| {
                let fingerprint = policy["surfaces"][0]["fingerprints"][0].clone();
                policy["surfaces"][1]["fingerprints"] = Value::Array(vec![fingerprint]);
            },
        );
    }

    #[test]
    fn reviewed_third_party_policy_admissions_are_closed() {
        let source: Value = serde_json::from_str(REVIEWED_THIRD_PARTY_POLICY_SOURCE).unwrap();

        for (description, exports) in [
            ("empty named exports", Vec::new()),
            (
                "non-literal named export",
                vec![Value::String(" getPage".into())],
            ),
            (
                "control character in named export",
                vec![Value::String("get\tPage".into())],
            ),
            ("namespace named export", vec![Value::String("*".into())]),
            (
                "default named export",
                vec![Value::String("default".into())],
            ),
            (
                "duplicate named export",
                vec![
                    Value::String("getPage".into()),
                    Value::String("getPage".into()),
                ],
            ),
        ] {
            assert_reviewed_policy_mutation_rejected(&source, description, |policy| {
                reviewed_policy_surface_mut(policy, "convex-helpers-pagination")["admission"]["exports"] =
                    Value::Array(exports);
            });
        }
        assert_reviewed_policy_mutation_rejected(&source, "unsorted named exports", |policy| {
            reviewed_policy_surface_mut(policy, "zod-converters")["admission"]["exports"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
        });
    }

    #[test]
    fn module_scope_var_in_nested_statement_is_rejected() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-nested-var-{unique}")),
        );
        let module_key = "convex/nested.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            "if (true) {\n  var retained = [];\n}\n",
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        assert!(
            modules
                .get(module_key)
                .unwrap()
                .summary
                .context_reuse
                .facts
                .iter()
                .any(|fact| fact.rule == "top-level-mutable-binding")
        );
    }

    #[test]
    fn binding_lookup_preserves_shadowing_hoisting_and_redeclaration_aliases() {
        let source = r#"var load = require;
{ var load = otherLoader; }
function outer(load) {
  before();
  function before() {}
  { let load = localLoader; void load; }
  return load;
}
void load;
"#;
        let allocator = super::Allocator::default();
        let parsed = super::Parser::new(&allocator, source, super::SourceType::mjs()).parse();
        assert!(parsed.diagnostics.is_empty());
        let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false)).unwrap();
        let bindings = super::BindingModel::new(&ast).unwrap();
        let module_load = bindings
            .binding_at("load", source.rfind("void load").unwrap() as u32)
            .unwrap();
        let parameter_load = bindings
            .binding_at("load", source.find("return load").unwrap() as u32)
            .unwrap();
        let block_load = bindings
            .binding_at("load", source.find("void load").unwrap() as u32)
            .unwrap();
        assert_ne!(module_load, parameter_load);
        assert_ne!(module_load, block_load);
        assert_ne!(parameter_load, block_load);
        assert!(bindings.bindings[module_load].module_state);
        assert!(!bindings.bindings[parameter_load].module_state);
        assert!(!bindings.bindings[block_load].module_state);
        assert_eq!(
            bindings.binding_at("load", source.find("otherLoader").unwrap() as u32),
            Some(module_load)
        );
        let declarations = &bindings.bindings[module_load].declarations;
        assert_eq!(declarations.len(), 2);
        assert_eq!(
            declarations[0].0 as usize,
            source.find("load = require").unwrap()
        );
        assert_eq!(
            declarations[1].0 as usize,
            source.find("load = otherLoader").unwrap()
        );
        assert_eq!(
            bindings.bindings[module_load]
                .alias_paths
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["require", "otherLoader"])
        );
        let before_call = bindings
            .binding_at("before", source.find("before();").unwrap() as u32)
            .unwrap();
        assert_eq!(
            bindings.binding_at("before", source.find("before() {}").unwrap() as u32),
            Some(before_call)
        );
        assert_eq!(
            bindings.binding_at("before", source.rfind("void load").unwrap() as u32),
            None
        );
        assert_eq!(
            bindings.binding_at("missing", source.find("return load").unwrap() as u32),
            None
        );
    }

    #[test]
    fn callable_resolution_merges_same_scope_redeclarations() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-var-redeclaration-{unique}")),
        );
        let module_key = "convex/redeclaration.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const retained = [];
function initialize() {
  var callback = () => retained.push("unsafe");
  callback();
  var callback = () => undefined;
}
initialize();
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert!(facts.iter().any(|fact| {
            fact.rule == "module-state-write" && fact.message.starts_with("push call")
        }));
    }

    #[test]
    fn optional_member_access_follows_import_time_accessor() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-optional-accessor-{unique}")),
        );
        let module_key = "convex/optional-accessor.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const helpers = {
  get value() {
    setTimeout(() => undefined, 1);
    return 1;
  },
};
void helpers?.value;
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert!(facts.iter().any(|fact| fact.rule == "import-time-timer"));
    }

    #[test]
    fn top_level_this_matches_the_module_system() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-commonjs-this-{unique}")),
        );
        fs::create_dir_all(root.0.join("convex")).unwrap();
        for (module_key, expected_writes) in [
            ("convex/commonjs-this.cjs", 2),
            ("convex/commonjs-this.cts", 2),
            ("convex/esm-this.mjs", 0),
        ] {
            fs::write(
                root.0.join(module_key),
                r#"this.contextReuseFixture = true;
this.contextReuseFixture.push("retained");
"#,
            )
            .unwrap();
            let mut modules = BTreeMap::new();
            load_module(
                &root.0,
                &root.0.join("cache"),
                module_key,
                &mut modules,
                &mut PhaseMeasurements::default(),
            )
            .unwrap();
            let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
            assert_eq!(
                facts
                    .iter()
                    .filter(|fact| fact.rule == "module-state-write")
                    .count(),
                expected_writes,
                "module {module_key}"
            );
        }
    }

    #[test]
    fn object_held_global_timer_preserves_provenance_without_crossing_shadowing() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-object-timer-{unique}")),
        );
        let module_key = "convex/object-timer.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const timers = { schedule: setTimeout };
timers.schedule(() => undefined, 1);

function invokeShadowedTimers() {
  const timers = { schedule: () => undefined };
  timers.schedule = () => undefined;
  timers.schedule(() => undefined, 1);
}

invokeShadowedTimers();
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert_eq!(
            facts
                .iter()
                .filter(|fact| fact.rule == "import-time-timer")
                .count(),
            1
        );
        assert!(!facts.iter().any(|fact| {
            matches!(
                fact.rule.as_str(),
                "global-state-write" | "module-state-write"
            )
        }));
    }

    #[test]
    fn logical_assignment_results_preserve_the_existing_dotted_alias() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-logical-alias-{unique}")),
        );
        let module_key = "convex/logical-alias.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const holder = { schedule: setTimeout };
const schedule = (holder.schedule ||= () => undefined);
schedule(() => undefined, 1);

const directHolder = { schedule: setTimeout };
(directHolder.schedule ??= () => undefined)(() => undefined, 1);

const receiverHolder = {};
const receiver = (receiverHolder.value ||= {
  mutate() {
    this.retained = [];
  },
});
receiver.mutate();
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;

        assert_eq!(
            facts
                .iter()
                .filter(|fact| fact.rule == "import-time-timer")
                .count(),
            2
        );
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let receiver_write_start = source.find("this.retained =").unwrap() as u32;
        assert!(facts.iter().any(|fact| {
            fact.rule == "module-state-write" && fact.start == receiver_write_start
        }));
    }

    #[test]
    fn direct_assignment_to_import_binding_remains_module_state_write() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-import-rebinding-{unique}")),
        );
        let module_key = "convex/import-rebinding.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"import { relationship } from "./relationship.js";

relationship = globalThis.relationship;
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let assignment_start = source.find("relationship =").unwrap() as u32;

        assert!(
            facts.iter().any(|fact| {
                fact.rule == "module-state-write" && fact.start == assignment_start
            })
        );
        assert!(
            !facts.iter().any(|fact| {
                fact.rule == "global-state-write" && fact.start == assignment_start
            })
        );
    }

    #[test]
    fn known_mutators_reject_unresolved_targets_but_accept_fresh_values() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-mutator-target-{unique}")),
        );
        let module_key = "convex/mutator-target.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const retained = [];
function getTarget() {
  return retained;
}

function exerciseMutatorTargets(): void {
  const unknownTarget = getTarget();
  const freshTarget = {};
  const freshMap = new Map();
  let unknownThenFresh = getTarget();
  const freshAlias = freshTarget;
  unknownTarget.push("value");
  Object.assign(unknownTarget, { value: true });
  freshTarget.push("value");
  Object.assign(freshTarget, { value: true });
  freshMap.set("value", true);
  freshAlias.push("value");
  unknownThenFresh.push("value");
  unknownThenFresh = {};
  unknownThenFresh.push("value");

  Object.assign(getTarget(), { value: true });
  Object.assign.call(undefined, getTarget(), { value: true });
  Object.assign.apply(undefined, [getTarget(), { value: true }]);
  Reflect.apply(Object.assign, undefined, [getTarget(), { value: true }]);
  getTarget().push("value");
  Array.prototype.push.call(getTarget(), "value");
  Array.prototype.push.apply(getTarget(), ["value"]);
  Reflect.apply(Array.prototype.push, getTarget(), ["value"]);
}

exerciseMutatorTargets();

Object.assign({}, { value: true });
Object.assign.call(undefined, {}, { value: true });
Object.assign.apply(undefined, [{}]);
Reflect.apply(Object.assign, undefined, [{}]);
[].push("value");
Array.prototype.push.call([], "value");
Array.prototype.push.apply([], ["value"]);
Reflect.apply(Array.prototype.push, [], ["value"]);
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let unresolved = facts
            .iter()
            .filter(|fact| fact.rule == "unresolved-mutator-application")
            .collect::<Vec<_>>();
        assert_eq!(
            unresolved.len(),
            12,
            "unresolved findings: {:?}",
            unresolved
                .iter()
                .map(|fact| (fact.start, fact.message.as_str()))
                .collect::<Vec<_>>()
        );
        let fresh_alias_start = source.find("freshAlias.push").unwrap() as u32;
        assert!(
            !unresolved
                .iter()
                .any(|fact| fact.start == fresh_alias_start)
        );
        let unknown_then_fresh_start = source.find("unknownThenFresh.push").unwrap() as u32;
        assert_eq!(
            unresolved
                .iter()
                .filter(|fact| fact.start == unknown_then_fresh_start)
                .count(),
            1
        );
        let later_unknown_start = source.rfind("unknownThenFresh.push").unwrap() as u32;
        assert_eq!(
            unresolved
                .iter()
                .filter(|fact| fact.start == later_unknown_start)
                .count(),
            1
        );
        assert!(facts.iter().all(|fact| {
            fact.rule != "unresolved-mutator-application"
                || fact.message.contains("neither a resolved state path")
        }));
    }

    #[test]
    fn local_helper_parameters_follow_fresh_member_paths_from_direct_calls() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-helper-parameter-freshness-{unique}"
        )));
        let module_key = "convex/helper-parameter-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const retainedLookup = { values: new Set<string>() };

function recordFresh(args: { lookup: { values: Set<string> } }): void {
  args.lookup.values.add("fresh");
}

function forwardFresh(lookup: { values: Set<string> }): void {
  recordFresh({ lookup });
}

function recordRetained(args: { lookup: { values: Set<string> } }): void {
  args.lookup.values.add("retained");
}

function recordEscaped(args: { lookup: { values: Set<string> } }): void {
  args.lookup.values.add("escaped");
}

function recordRecursive(args: { lookup: { values: Set<string> } }, again: boolean): void {
  args.lookup.values.add("recursive");
  if (again) recordRecursive(args, false);
}

function recordReassigned(args: { lookup: { values: Set<string> } }): void {
  args.lookup.values.add("before_reassignment");
  args = { lookup: { values: new Set<string>() } };
}

export const escaped = recordEscaped;

export function run(): void {
  const lookup = { values: new Set<string>() };
  forwardFresh(lookup);
  recordRetained({ lookup: retainedLookup });
  recordRecursive({ lookup }, true);
  recordReassigned({ lookup });
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let unresolved_starts = facts
            .iter()
            .filter(|fact| fact.rule == "unresolved-mutator-application")
            .map(|fact| fact.start)
            .collect::<BTreeSet<_>>();

        let fresh_start = source.find("args.lookup.values.add(\"fresh\")").unwrap() as u32;
        let retained_start = source.find("args.lookup.values.add(\"retained\")").unwrap() as u32;
        let escaped_start = source.find("args.lookup.values.add(\"escaped\")").unwrap() as u32;
        let recursive_start = source
            .find("args.lookup.values.add(\"recursive\")")
            .unwrap() as u32;
        let reassigned_start = source
            .find("args.lookup.values.add(\"before_reassignment\")")
            .unwrap() as u32;
        assert!(!unresolved_starts.contains(&fresh_start));
        assert!(unresolved_starts.contains(&retained_start));
        assert!(unresolved_starts.contains(&escaped_start));
        assert!(unresolved_starts.contains(&recursive_start));
        assert!(unresolved_starts.contains(&reassigned_start));
    }

    #[test]
    fn nested_freshness_reports_retained_member_through_a_fresh_holder() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-nested-holder-freshness-{unique}"
        )));
        let module_key = "convex/nested-holder-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const retained = new Set<string>();

export function mutate(): void {
  const holder = { value: retained };
  holder.value.add("retained");
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let add_start = source.find("holder.value.add").unwrap() as u32;

        assert!(
            facts
                .iter()
                .any(|fact| fact.rule == "module-state-write" && fact.start == add_start)
        );
    }

    #[test]
    fn fresh_constructor_proof_rejects_shadowed_builtins() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-shadowed-constructor-{unique}"
        )));
        let module_key = "convex/shadowed-constructor.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const retained = [];
const Map = class {
  constructor() {
    return retained;
  }
};

export function mutate(): void {
  const value = new Map();
  value.set("retained", true);
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let value_start = fs::read_to_string(root.0.join(module_key))
            .unwrap()
            .find("value.set")
            .unwrap() as u32;
        assert!(facts.iter().any(|fact| {
            fact.rule == "unresolved-mutator-application" && fact.start == value_start
        }));
        assert!(!facts.iter().any(|fact| {
            fact.start == value_start
                && matches!(
                    fact.rule.as_str(),
                    "module-state-write" | "global-state-write"
                )
        }));
    }

    #[test]
    fn logical_assignment_invalidates_fresh_mutator_targets() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-logical-freshness-{unique}")),
        );
        let module_key = "convex/logical-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"function getTarget() {
  return [];
}

export function mutate(): void {
  let target: unknown[] = [];
  target &&= getTarget();
  target.push("retained");
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let push_start = source.find("target.push").unwrap() as u32;
        assert!(facts.iter().any(|fact| {
            fact.rule == "unresolved-mutator-application" && fact.start == push_start
        }));
    }

    #[test]
    fn compound_assignment_invalidates_fresh_mutator_targets() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-compound-freshness-{unique}")),
        );
        let module_key = "convex/compound-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"function getTarget() {
  return [];
}

export function mutate(): void {
  let target: any = [];
  target += getTarget();
  target.push("retained");
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let push_start = source.find("target.push").unwrap() as u32;
        assert!(facts.iter().any(|fact| {
            fact.rule == "unresolved-mutator-application" && fact.start == push_start
        }));
    }

    #[test]
    fn logical_assignment_result_is_not_structurally_fresh() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-logical-result-freshness-{unique}"
        )));
        let module_key = "convex/logical-result-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"function getTarget() {
  return [];
}

export function mutate(): void {
  let unknown = getTarget();
  const value = (unknown ||= []);
  value.push("retained");
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let push_start = source.find("value.push").unwrap() as u32;
        assert!(facts.iter().any(|fact| {
            fact.rule == "unresolved-mutator-application" && fact.start == push_start
        }));
    }

    #[test]
    fn logical_assignment_property_result_is_not_fresh_through_holder() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-logical-property-result-freshness-{unique}"
        )));
        let module_key = "convex/logical-property-result-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"function getTarget() {
  return [];
}

export function mutate(): void {
  const holder: { target?: unknown[] } = {};
  holder.target ||= getTarget();
  holder.target.push("retained");
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let push_start = source.find("holder.target.push").unwrap() as u32;

        assert!(facts.iter().any(|fact| {
            fact.rule == "unresolved-mutator-application" && fact.start == push_start
        }));
    }

    #[test]
    fn member_assignment_invalidation_follows_direct_aliases() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-member-alias-freshness-{unique}"
        )));
        let module_key = "convex/member-alias-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"function getTarget() {
  return [];
}

export function mutate(): void {
  const holder: { target?: unknown[] } = {};
  const alias = holder;
  alias.target ||= getTarget();
  holder.target?.push("retained");
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let push_start = source.find("holder.target?.push").unwrap() as u32;

        assert!(facts.iter().any(|fact| {
            fact.rule == "unresolved-mutator-application" && fact.start == push_start
        }));
    }

    #[test]
    fn computed_member_assignment_invalidates_fresh_holder() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-computed-member-freshness-{unique}"
        )));
        let module_key = "convex/computed-member-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"function getTarget() {
  return [];
}

export function mutate(key: string): void {
  const holder: Record<string, unknown[]> = { target: [] };
  holder[key] = getTarget();
  holder.target.push("retained");
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let push_start = source.find("holder.target.push").unwrap() as u32;

        assert!(facts.iter().any(|fact| {
            fact.rule == "unresolved-mutator-application" && fact.start == push_start
        }));
    }

    #[test]
    fn external_edge_without_authenticated_identity_is_hard() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-external-edge-identity-{unique}"
        )));
        let entry = "convex/marked.ts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(entry),
            r#"import value from "unlisted-package";
export const experimental_reuseContext = true;
void value;
"#,
        )
        .unwrap();
        let input = ContextInput {
            kind: INPUT_KIND.to_string(),
            repo_root: root.0.clone(),
            functions_root: "convex".to_string(),
            roots: vec!["convex".to_string(), "shared".to_string()],
            source_texts: None,
            entry_candidates: vec![entry.to_string()],
            database_functions: Vec::new(),
            default_enabled: false,
            default_database_entries: Vec::new(),
            exclusions: BTreeMap::new(),
            virtual_inputs: BTreeSet::new(),
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([(
                    entry.to_string(),
                    crate::EsbuildInput {
                        imports: vec![EsbuildImport {
                            path: "unlisted-package".to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("unlisted-package".to_string()),
                            external: true,
                        }],
                    },
                )]),
                outputs: BTreeMap::new(),
            },
            registration_adapter: test_registration_adapter_material(),
            external_dependencies: BTreeMap::new(),
            phase_timings_us: BTreeMap::new(),
        };
        let result = analyze_context_reuse(
            &input,
            &root.0.join("cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
        )
        .unwrap();
        let diagnostic = result
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.rule == "unsupported-runtime-dependency")
            .expect("external edge must produce a boundary diagnostic");
        assert_eq!(diagnostic.severity, "hard");
    }

    #[test]
    fn destructuring_assignment_invalidates_fresh_mutator_targets() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-destructure-freshness-{unique}"
        )));
        let module_key = "convex/destructure-freshness.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"function getHolder() {
  return { target: [] };
}

export function mutate(): void {
  let target: unknown[] = [];
  ({ target } = getHolder());
  target.push("retained");
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        let source = fs::read_to_string(root.0.join(module_key)).unwrap();
        let push_start = source.find("target.push").unwrap() as u32;
        assert!(facts.iter().any(|fact| {
            fact.rule == "unresolved-mutator-application" && fact.start == push_start
        }));
    }

    #[test]
    fn import_time_callable_resolution_follows_object_property_aliases() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-property-alias-{unique}")),
        );
        let module_key = "convex/property-alias.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"function initialize() {
  setTimeout(() => undefined, 1);
}
const holder = { initialize };
holder.initialize();
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert!(facts.iter().any(|fact| fact.rule == "import-time-timer"));
    }

    #[test]
    fn import_time_callable_resolution_follows_local_factory_results() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-factory-result-{unique}")),
        );
        let module_key = "convex/factory-result.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const initialize = makeInitializer();
initialize();
function makeInitializer() {
  return () => {
    setTimeout(() => undefined, 1);
  };
}
const returnedInitializer = () => {
  setTimeout(() => undefined, 2);
};
const aliasInitialize = makeAliasInitializer();
aliasInitialize();
function makeAliasInitializer() {
  return returnedInitializer;
}
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert!(facts.iter().any(|fact| fact.rule == "import-time-timer"));
    }

    #[test]
    fn import_time_callable_resolution_follows_sloppy_commonjs_block_functions() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-commonjs-annex-b-{unique}")),
        );
        fs::create_dir_all(root.0.join("convex")).unwrap();
        for (module_key, source, expected_timer) in [
            (
                "convex/sloppy-block-function.cjs",
                r#"{
  function initialize() {
    setTimeout(() => undefined, 1);
  }
}
initialize();
"#,
                true,
            ),
            (
                "convex/strict-block-function.cjs",
                r#""use strict";
const initialize = () => undefined;
{
  function initialize() {
    setTimeout(() => undefined, 1);
  }
}
initialize();
"#,
                false,
            ),
        ] {
            fs::write(root.0.join(module_key), source).unwrap();
            let mut modules = BTreeMap::new();
            load_module(
                &root.0,
                &root.0.join("cache"),
                module_key,
                &mut modules,
                &mut PhaseMeasurements::default(),
            )
            .unwrap();
            let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
            assert_eq!(
                facts.iter().any(|fact| fact.rule == "import-time-timer"),
                expected_timer,
                "module {module_key}"
            );
        }

        let nested_module_key = "convex/strict-nested-block-function.cjs";
        fs::write(
            root.0.join(nested_module_key),
            r#"function outer() {
  "use strict";
  {
    function initialize() {
      setTimeout(() => undefined, 1);
    }
  }
  initialize();
}
outer();
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            nested_module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules
            .get(nested_module_key)
            .unwrap()
            .summary
            .context_reuse
            .facts;
        assert!(!facts.iter().any(|fact| fact.rule == "import-time-timer"));
    }

    #[test]
    fn callable_property_shadowing_does_not_cross_lexical_bindings() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-property-shadow-{unique}")),
        );
        let module_key = "convex/property-shadow.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const holder = {
  start() {
    setTimeout(() => undefined, 1);
  },
};

function invokeShadowedHolder() {
  const holder = { start: () => undefined };
  holder.start();
}

invokeShadowedHolder();
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert!(!facts.iter().any(|fact| fact.rule == "import-time-timer"));
    }

    #[test]
    fn class_constructor_shadowing_does_not_cross_lexical_bindings() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-constructor-shadow-{unique}")),
        );
        let module_key = "convex/constructor-shadow.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"class Service {
  constructor() {
    setTimeout(() => undefined, 1);
  }
}

function invokeShadowedService() {
  class Service {
    constructor() {}
  }
  new Service();
}

invokeShadowedService();
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert!(!facts.iter().any(|fact| fact.rule == "import-time-timer"));
    }

    #[test]
    fn spread_property_alias_preserves_global_require_provenance() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-spread-require-{unique}")),
        );
        let module_key = "convex/spread-require.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"const spreadHolder = { ...{ load: require } };
spreadHolder.load("./not-a-static-edge");
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert!(
            facts
                .iter()
                .any(|fact| fact.rule == "nonliteral-runtime-require")
        );
    }

    #[test]
    fn self_referential_property_alias_does_not_expand_global_require_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-cyclic-require-alias-{unique}"
        )));
        let module_key = "convex/cyclic-require-alias.mts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(module_key),
            r#"let current = new Error("outer");
current = current.cause;
current.toString();

const load = require;
load("./not-a-static-edge");
"#,
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &root.0.join("cache"),
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let facts = &modules.get(module_key).unwrap().summary.context_reuse.facts;
        assert_eq!(
            facts
                .iter()
                .filter(|fact| fact.rule == "nonliteral-runtime-require")
                .count(),
            1
        );
    }

    #[test]
    fn zod_review_rejects_unsupported_schema_members_without_rejecting_unrelated_access() {
        let zod_fingerprints = reviewed_policy_fingerprints("zod");
        let repo_root = fixture_repository_root();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-zod-surface-{unique}")),
        );
        let cache_dir = root.0.join("cache");
        for (fixture, expected) in [
            ("zod-safe-computed.ts", true),
            ("zod-safe-unrelated-sensitive.ts", true),
            ("zod-safe-local-consumer.ts", true),
            ("zod-dynamic-direct.ts", false),
            ("zod-dynamic-alias.ts", false),
            ("zod-dynamic-assignment.ts", false),
            ("zod-dynamic-logical-assignment.ts", false),
            ("zod-dynamic-property-assignment.ts", false),
            ("zod-dynamic-helper.ts", false),
            ("zod-dynamic-helper-apply.ts", false),
            ("zod-dynamic-helper-call.ts", false),
            ("zod-dynamic-helper-method.ts", false),
            ("zod-dynamic-return.ts", false),
            ("zod-escaped-sensitive.ts", false),
        ] {
            let module_key = format!(
                "scripts/test-fixtures/convex-context-reuse/convex-helpers-surface/{fixture}"
            );
            let source = fs::read_to_string(repo_root.join(&module_key)).unwrap();
            let mut modules = BTreeMap::new();
            let mut phases = PhaseMeasurements::default();
            load_module(
                &repo_root,
                &cache_dir,
                &module_key,
                &mut modules,
                &mut phases,
            )
            .unwrap();
            let module = modules.get(&module_key).unwrap();
            let references = module
                .summary
                .context_reuse
                .references
                .iter()
                .filter(|reference| reference.specifier == "zod")
                .collect::<Vec<_>>();
            assert_eq!(references.len(), 1, "fixture {fixture}");
            for fingerprint in zod_fingerprints {
                assert_eq!(
                    matches!(
                        review_third_party_boundary(
                            &mut BTreeMap::new(),
                            &module_key,
                            module,
                            &source,
                            references[0],
                            &ThirdPartyMaterial {
                                fingerprint: fingerprint.clone(),
                                lock_complete: true,
                                unauthenticated_external_imports: BTreeSet::new(),
                            },
                        ),
                        ThirdPartyDisposition::Accepted
                    ),
                    expected,
                    "fixture {fixture}, material {fingerprint}"
                );
            }
        }
    }

    #[test]
    fn package_lock_key_uses_the_innermost_nested_package() {
        assert_eq!(
            package_lock_key("node_modules/parent/lib/index.js").as_deref(),
            Some("node_modules/parent")
        );
        assert_eq!(
            package_lock_key("node_modules/parent/node_modules/child/lib/index.js").as_deref(),
            Some("node_modules/parent/node_modules/child")
        );
        assert_eq!(
            package_lock_key("node_modules/@scope/parent/node_modules/@scope/child/index.js")
                .as_deref(),
            Some("node_modules/@scope/parent/node_modules/@scope/child")
        );
        assert_eq!(package_lock_key("shared/index.js"), None);
        assert_eq!(
            package_lock_key("node_modules/parent").as_deref(),
            Some("node_modules/parent")
        );
        assert_eq!(package_lock_key("node_modules/@scope"), None);
    }

    #[test]
    fn third_party_material_binds_loader_managed_package_inputs() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-package-asset-{unique}")),
        );
        let package_directory = root.0.join("node_modules/asset-package");
        fs::create_dir_all(&package_directory).unwrap();
        fs::write(
            package_directory.join("index.js"),
            "import './state.bin';\n",
        )
        .unwrap();
        fs::write(package_directory.join("state.bin"), b"first").unwrap();
        fs::write(
            package_directory.join("package.json"),
            r#"{"name":"asset-package","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            root.0.join("package-lock.json"),
            r#"{"packages":{"node_modules/asset-package":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        let mut input = ContextInput {
            source_texts: None,
            kind: INPUT_KIND.to_string(),
            repo_root: root.0.clone(),
            functions_root: "convex".to_string(),
            roots: vec!["convex".to_string(), "shared".to_string()],
            entry_candidates: Vec::new(),
            database_functions: Vec::new(),
            default_enabled: false,
            default_database_entries: Vec::new(),
            exclusions: BTreeMap::new(),
            virtual_inputs: BTreeSet::new(),
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([
                    (
                        "node_modules/asset-package/index.js".to_string(),
                        EsbuildInput {
                            imports: vec![EsbuildImport {
                                path: "node_modules/asset-package/state.bin".to_string(),
                                kind: "import-statement".to_string(),
                                original: Some("./state.bin".to_string()),
                                external: false,
                            }],
                        },
                    ),
                    (
                        "node_modules/asset-package/state.bin".to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                ]),
                outputs: BTreeMap::new(),
            },
            registration_adapter: test_registration_adapter_material(),
            external_dependencies: BTreeMap::new(),
            phase_timings_us: BTreeMap::new(),
        };
        let package_lock_entries = load_package_lock_entries(&root.0).unwrap().unwrap();
        let first = third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&package_lock_entries),
        )
        .unwrap();

        fs::write(package_directory.join("state.bin"), b"second").unwrap();
        let second = third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&package_lock_entries),
        )
        .unwrap();

        assert!(first.lock_complete);
        assert!(second.lock_complete);
        assert_ne!(second.fingerprint, first.fingerprint);

        fs::write(
            package_directory.join("package.json"),
            r#"{"name":"asset-package","version":"2.0.0","metadata":"changed"}"#,
        )
        .unwrap();
        fs::write(
            root.0.join("package-lock.json"),
            r#"{"packages":{"node_modules/asset-package":{"version":"2.0.0","metadata":"changed"}}}"#,
        )
        .unwrap();
        let changed_lock_entries = load_package_lock_entries(&root.0).unwrap().unwrap();
        let metadata_changed = third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&changed_lock_entries),
        )
        .unwrap();
        assert!(metadata_changed.lock_complete);
        assert_eq!(metadata_changed.fingerprint, second.fingerprint);

        let missing_lock_entry = third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&BTreeMap::new()),
        )
        .unwrap();
        assert!(!missing_lock_entry.lock_complete);
        assert_eq!(missing_lock_entry.fingerprint, second.fingerprint);

        fs::remove_file(package_directory.join("package.json")).unwrap();
        let missing_manifest = third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&changed_lock_entries),
        )
        .unwrap();
        assert!(!missing_manifest.lock_complete);
        assert_eq!(missing_manifest.fingerprint, second.fingerprint);
        fs::write(
            package_directory.join("package.json"),
            r#"{"name":"asset-package","version":"2.0.0","metadata":"changed"}"#,
        )
        .unwrap();

        let package_input = input
            .metafile
            .inputs
            .get_mut("node_modules/asset-package/index.js")
            .unwrap();
        package_input.imports[0].path = "(disabled):fs".to_string();
        package_input.imports[0].original = Some("fs".to_string());
        input.metafile.inputs.insert(
            "(disabled):fs".to_string(),
            EsbuildInput {
                imports: Vec::new(),
            },
        );
        input.virtual_inputs.insert("(disabled):fs".to_string());
        let virtual_dependency = third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&package_lock_entries),
        )
        .unwrap();
        assert_ne!(virtual_dependency.fingerprint, second.fingerprint);

        input.metafile.inputs.remove("(disabled):fs");
        let error = match third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&package_lock_entries),
        ) {
            Ok(_) => panic!("missing virtual input must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("virtual third-party dependency (disabled):fs is missing")
        );
        input.metafile.inputs.insert(
            "(disabled):fs".to_string(),
            EsbuildInput {
                imports: Vec::new(),
            },
        );

        input.virtual_inputs.clear();
        let error = match third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&package_lock_entries),
        ) {
            Ok(_) => panic!("unadmitted virtual input must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("escaped installed package inputs")
        );

        input.metafile.inputs.remove("(disabled):fs");
        let package_input = input
            .metafile
            .inputs
            .get_mut("node_modules/asset-package/index.js")
            .unwrap();
        package_input.imports[0].path = "node_modules/asset-package/state.bin".to_string();
        package_input.imports[0].original = Some("./state.bin".to_string());

        #[cfg(unix)]
        {
            // Package metadata does not define the source fingerprint, but an escaping manifest
            // still cannot satisfy the package-completeness requirement.
            let outside_manifest = root.0.parent().unwrap().join(format!(
                "convex-context-reuse-package-asset-manifest-{unique}.json"
            ));
            fs::write(&outside_manifest, b"{\"name\":\"asset-package\"}").unwrap();
            fs::remove_file(package_directory.join("package.json")).unwrap();
            std::os::unix::fs::symlink(&outside_manifest, package_directory.join("package.json"))
                .unwrap();
            let error = match third_party_material(
                &input,
                "node_modules/asset-package/index.js",
                Some(&package_lock_entries),
            ) {
                Ok(_) => panic!("escaping package manifest must fail closed"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("escapes repository root"));
            fs::remove_file(&outside_manifest).unwrap();
        }

        #[cfg(unix)]
        {
            // Keep package-lock completeness evidence path-bound as well as the package manifest;
            // an escaping lockfile must not authenticate a closure with bytes outside the
            // repository.
            let outside_lock = root.0.parent().unwrap().join(format!(
                "convex-context-reuse-package-asset-lock-{unique}.json"
            ));
            fs::copy(root.0.join("package-lock.json"), &outside_lock).unwrap();
            fs::remove_file(root.0.join("package-lock.json")).unwrap();
            std::os::unix::fs::symlink(&outside_lock, root.0.join("package-lock.json")).unwrap();
            let error = load_package_lock_entries(&root.0).unwrap_err();
            assert!(error.to_string().contains("escapes repository root"));
            fs::remove_file(root.0.join("package-lock.json")).unwrap();
            fs::copy(&outside_lock, root.0.join("package-lock.json")).unwrap();
            fs::remove_file(&outside_lock).unwrap();
        }

        input
            .metafile
            .inputs
            .remove("node_modules/asset-package/state.bin");
        let error = match third_party_material(
            &input,
            "node_modules/asset-package/index.js",
            Some(&package_lock_entries),
        ) {
            Ok(_) => panic!("missing local package input must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("missing from the metafile"));
    }

    #[test]
    fn third_party_material_exempts_only_the_exact_esbuild_runtime_pseudo_module() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-package-external-{unique}")),
        );
        let package_directory = root.0.join("node_modules/external-edge-package");
        fs::create_dir_all(&package_directory).unwrap();
        fs::write(
            package_directory.join("index.js"),
            "import 'unbound-package';\nexport const value = 1;\n",
        )
        .unwrap();
        fs::write(
            package_directory.join("package.json"),
            r#"{"name":"external-edge-package","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            root.0.join("package-lock.json"),
            r#"{"packages":{"node_modules/external-edge-package":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        let mut input = ContextInput {
            source_texts: None,
            kind: INPUT_KIND.to_string(),
            repo_root: root.0.clone(),
            functions_root: "convex".to_string(),
            roots: vec!["convex".to_string(), "shared".to_string()],
            entry_candidates: Vec::new(),
            database_functions: Vec::new(),
            default_enabled: false,
            default_database_entries: Vec::new(),
            exclusions: BTreeMap::new(),
            virtual_inputs: BTreeSet::new(),
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([(
                    "node_modules/external-edge-package/index.js".to_string(),
                    EsbuildInput {
                        imports: vec![EsbuildImport {
                            path: "unbound-package".to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("unbound-package".to_string()),
                            external: true,
                        }],
                    },
                )]),
                outputs: BTreeMap::new(),
            },
            registration_adapter: test_registration_adapter_material(),
            external_dependencies: BTreeMap::new(),
            phase_timings_us: BTreeMap::new(),
        };
        let package_lock_entries = load_package_lock_entries(&root.0).unwrap().unwrap();
        let material = third_party_material(
            &input,
            "node_modules/external-edge-package/index.js",
            Some(&package_lock_entries),
        )
        .unwrap();
        assert_eq!(
            material.unauthenticated_external_imports,
            BTreeSet::from(["unbound-package".to_string()])
        );

        input
            .metafile
            .inputs
            .get_mut("node_modules/external-edge-package/index.js")
            .unwrap()
            .imports[0]
            .path = ESBUILD_RUNTIME_PSEUDO_MODULE.to_string();
        input
            .metafile
            .inputs
            .get_mut("node_modules/external-edge-package/index.js")
            .unwrap()
            .imports[0]
            .original = None;
        let runtime_material = third_party_material(
            &input,
            "node_modules/external-edge-package/index.js",
            Some(&package_lock_entries),
        )
        .unwrap();
        assert!(runtime_material.unauthenticated_external_imports.is_empty());

        // The pseudo-module remains exact fingerprint material even though it does not name
        // separately authenticated package bytes.
        input
            .metafile
            .inputs
            .get_mut("node_modules/external-edge-package/index.js")
            .unwrap()
            .imports
            .clear();
        let material_without_runtime = third_party_material(
            &input,
            "node_modules/external-edge-package/index.js",
            Some(&package_lock_entries),
        )
        .unwrap();
        assert_ne!(
            runtime_material.fingerprint,
            material_without_runtime.fingerprint
        );

        input
            .metafile
            .inputs
            .get_mut("node_modules/external-edge-package/index.js")
            .unwrap()
            .imports
            .push(EsbuildImport {
                path: "<runtime-extra>".to_string(),
                kind: "import-statement".to_string(),
                original: None,
                external: true,
            });
        let material = third_party_material(
            &input,
            "node_modules/external-edge-package/index.js",
            Some(&package_lock_entries),
        )
        .unwrap();
        assert_eq!(
            material.unauthenticated_external_imports,
            BTreeSet::from(["<runtime-extra>".to_string()])
        );

        // The explicit `node:` treatment is retained; it does not need a package closure
        // identity because the runtime owns Node built-ins rather than resolving installed bytes.
        input
            .metafile
            .inputs
            .get_mut("node_modules/external-edge-package/index.js")
            .unwrap()
            .imports[0]
            .path = "node:fs".to_string();
        input
            .metafile
            .inputs
            .get_mut("node_modules/external-edge-package/index.js")
            .unwrap()
            .imports[0]
            .original = Some("node:fs".to_string());
        let material = third_party_material(
            &input,
            "node_modules/external-edge-package/index.js",
            Some(&package_lock_entries),
        )
        .unwrap();
        assert!(material.unauthenticated_external_imports.is_empty());
    }

    #[test]
    fn tree_shaken_external_package_is_not_read_but_contributing_one_fails_closed() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(env::temp_dir().join(format!(
            "convex-context-reuse-tree-shaken-external-{unique}"
        )));
        let entry = "convex/marked.ts";
        let package = "node_modules/external-edge-package/index.js";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        fs::write(
            root.0.join(entry),
            r#"import { value } from "external-edge-package";
export const experimental_reuseContext = true;
void value;
"#,
        )
        .unwrap();

        let mut input = ContextInput {
            source_texts: None,
            kind: INPUT_KIND.to_string(),
            repo_root: root.0.clone(),
            functions_root: "convex".to_string(),
            roots: vec!["convex".to_string(), "shared".to_string()],
            entry_candidates: vec![entry.to_string()],
            database_functions: Vec::new(),
            default_enabled: false,
            default_database_entries: Vec::new(),
            exclusions: BTreeMap::new(),
            virtual_inputs: BTreeSet::new(),
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([
                    (
                        entry.to_string(),
                        EsbuildInput {
                            imports: vec![EsbuildImport {
                                path: package.to_string(),
                                kind: "import-statement".to_string(),
                                original: Some("external-edge-package".to_string()),
                                external: false,
                            }],
                        },
                    ),
                    (
                        package.to_string(),
                        EsbuildInput {
                            imports: vec![EsbuildImport {
                                path: "unbound-package".to_string(),
                                kind: "import-statement".to_string(),
                                original: Some("unbound-package".to_string()),
                                external: true,
                            }],
                        },
                    ),
                ]),
                outputs: BTreeMap::from([(
                    "out/marked.js".to_string(),
                    crate::EsbuildOutput {
                        entry_point: Some(entry.to_string()),
                        imports: Vec::new(),
                        inputs: BTreeMap::from([(
                            entry.to_string(),
                            crate::EsbuildOutputContribution {
                                bytes_in_output: 10,
                            },
                        )]),
                    },
                )]),
            },
            registration_adapter: test_registration_adapter_material(),
            external_dependencies: BTreeMap::new(),
            phase_timings_us: BTreeMap::new(),
        };

        // The package input is deliberately absent on disk and the lockfile is malformed. A
        // fully tree-shaken boundary must not read or reject any of its package review material.
        fs::write(root.0.join("package-lock.json"), "not valid JSON").unwrap();
        let cache_dir = root.0.join("cache");
        let mut phases = PhaseMeasurements::default();
        let result = analyze_context_reuse(&input, &cache_dir, &mut phases, Instant::now())
            .expect("tree-shaken package closure must not be read");
        assert!(result.safe);
        assert!(result.third_party_material_fingerprints.is_empty());

        fs::create_dir_all(root.0.join("node_modules/external-edge-package")).unwrap();
        fs::write(
            root.0.join(package),
            "import 'unbound-package';\nexport const value = 1;\n",
        )
        .unwrap();
        fs::write(
            root.0.join("package-lock.json"),
            r#"{"packages":{"node_modules/external-edge-package":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        input
            .metafile
            .outputs
            .get_mut("out/marked.js")
            .unwrap()
            .inputs
            .insert(
                package.to_string(),
                crate::EsbuildOutputContribution {
                    bytes_in_output: 10,
                },
            );
        let mut phases = PhaseMeasurements::default();
        let result = analyze_context_reuse(&input, &cache_dir, &mut phases, Instant::now())
            .expect("external package material must produce a closed disposition");
        assert!(!result.safe);
        assert_eq!(result.third_party_material_fingerprints.len(), 1);
        assert!(
            result
                .third_party_material_fingerprints
                .contains_key(package)
        );
        assert!(result.diagnostics().iter().any(|diagnostic| {
            diagnostic.rule == "unsupported-runtime-dependency"
                && diagnostic
                    .message
                    .contains("external import(s) other than node:*")
        }));
    }

    #[test]
    fn convex_helpers_review_admits_stateless_pagination_and_rejects_zod_registry_writes() {
        const STATEFUL_PAGINATION_SHA256S: &[&str] = &[
            "17afcfbc0ebf064e98bb32a96bc7f9e36d730e6d6a22a8db91482f1a73451704",
            "657cae9793317d23c5ecd68f76fd8a52ad32ee2d32f2537898fc1c852f46cb2c",
        ];
        const STATEFUL_STREAM_SHA256S: &[&str] = &[
            "1e4f79197cb3b19e60a95a37620636e6c538a0521d5777f9c2840ac387638df6",
            "df2ed6312c87f371ffefac4cedb19b18183f509fb78098f0eb1db4ce0fa85beb",
        ];
        let pagination_fingerprints = reviewed_policy_fingerprints("convex-helpers-pagination");
        let stream_fingerprints =
            reviewed_policy_fingerprints("convex-helpers-stream-index-fields");
        let zod4_fingerprints = reviewed_policy_fingerprints("zod-converters");
        for (fingerprints, expected_id) in [
            (pagination_fingerprints, "convex-helpers-pagination"),
            (stream_fingerprints, "convex-helpers-stream-index-fields"),
            (zod4_fingerprints, "zod-converters"),
        ] {
            for fingerprint in fingerprints {
                assert_eq!(
                    reviewed_third_party_surface(fingerprint).map(|surface| surface.id.as_str()),
                    Some(expected_id)
                );
                let mut drifted = fingerprint.to_string();
                drifted.replace_range(..1, if &drifted[..1] == "0" { "1" } else { "0" });
                assert!(reviewed_third_party_surface(&drifted).is_none());
            }
        }
        for fingerprint in STATEFUL_PAGINATION_SHA256S
            .iter()
            .chain(STATEFUL_STREAM_SHA256S)
        {
            assert!(reviewed_third_party_surface(fingerprint).is_none());
        }

        let repo_root = fixture_repository_root();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-convex-helpers-{unique}")),
        );
        let cache_dir = root.0.join("cache");
        for (fixture, specifier, fingerprints, expected) in [
            (
                "pagination.ts",
                "convex-helpers/server/pagination",
                pagination_fingerprints,
                true,
            ),
            (
                "pagination-namespace.ts",
                "convex-helpers/server/pagination",
                pagination_fingerprints,
                false,
            ),
            (
                "stream.ts",
                "convex-helpers/server/stream",
                stream_fingerprints,
                true,
            ),
            (
                "stream-aliased.ts",
                "convex-helpers/server/stream",
                stream_fingerprints,
                true,
            ),
            (
                "stream-default-namespace.ts",
                "convex-helpers/server/stream",
                stream_fingerprints,
                false,
            ),
            (
                "stream-reexport.ts",
                "convex-helpers/server/stream",
                stream_fingerprints,
                false,
            ),
            (
                "stream-require.ts",
                "convex-helpers/server/stream",
                stream_fingerprints,
                false,
            ),
            (
                "stream-query.ts",
                "convex-helpers/server/stream",
                stream_fingerprints,
                false,
            ),
            (
                "zod-converters.ts",
                "convex-helpers/server/zod4",
                zod4_fingerprints,
                true,
            ),
            (
                "zod-registry-writer.ts",
                "convex-helpers/server/zod4",
                zod4_fingerprints,
                false,
            ),
        ] {
            let module_key = format!(
                "scripts/test-fixtures/convex-context-reuse/convex-helpers-surface/{fixture}"
            );
            let source = fs::read_to_string(repo_root.join(&module_key)).unwrap();
            let mut modules = BTreeMap::new();
            let mut phases = PhaseMeasurements::default();
            load_module(
                &repo_root,
                &cache_dir,
                &module_key,
                &mut modules,
                &mut phases,
            )
            .unwrap();
            let module = modules.get(&module_key).unwrap();
            let references = module
                .summary
                .context_reuse
                .references
                .iter()
                .filter(|reference| reference.specifier == specifier)
                .collect::<Vec<_>>();
            assert_eq!(references.len(), 1, "fixture {fixture}");
            for fingerprint in fingerprints {
                assert_eq!(
                    matches!(
                        review_third_party_boundary(
                            &mut BTreeMap::new(),
                            &module_key,
                            module,
                            &source,
                            references[0],
                            &ThirdPartyMaterial {
                                fingerprint: fingerprint.clone(),
                                lock_complete: true,
                                unauthenticated_external_imports: BTreeSet::new(),
                            },
                        ),
                        ThirdPartyDisposition::Accepted
                    ),
                    expected,
                    "fixture {fixture}, material {fingerprint}"
                );
            }
        }
    }

    #[test]
    fn context_reuse_entry_path_prunes_the_shared_module_summary_cache() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-context-reuse-summary-gc-{unique}")),
        );
        let cache_dir = root.0.join("cache");
        let summary_directory = cache_dir.join("module-summaries/ab");
        fs::create_dir_all(&summary_directory).unwrap();
        let summary_path = summary_directory.join(format!("ab{}.json", "0".repeat(62)));
        fs::write(&summary_path, b"expired").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&summary_path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(31 * 24 * 60 * 60))
            .unwrap();
        let graph_path = root.0.join("invalid-graph.json");
        fs::write(&graph_path, b"{}").unwrap();

        let error = run_context_reuse(
            vec![
                "--graph".to_string(),
                graph_path.to_string_lossy().into_owned(),
                "--cache-dir".to_string(),
                cache_dir.to_string_lossy().into_owned(),
            ],
            Instant::now(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("invalid graph JSON"));
        assert!(!summary_path.exists());
    }

    #[test]
    fn source_inventory_attaches_exact_calls_only_to_authenticated_registration_imports() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-source-inventory-alias-{unique}")),
        );
        let alias_entry = "functions/alias.ts";
        let direct_entry = "functions/direct.ts";
        let local_entry = "functions/local.ts";
        let custom_entry = "functions/customEntry.ts";
        let object_entry = "functions/object.ts";
        let reexport_entry = "functions/reexport.ts";
        let wrapper_entry = "functions/wrapper.ts";
        let generated_server = "functions/_generated/server.js";
        let custom_builder = "functions/custom.ts";
        for (module, source) in [
            (
                alias_entry,
                r#"// UTF-8 registration span prefix: 🦀
import { query as registerQuery } from "./_generated/server";
export const selected = registerQuery({ args: {}, handler: async () => null });
"#,
            ),
            (
                direct_entry,
                r#"import { mutation } from "./_generated/server";
export const changed = mutation({ args: {}, handler: async () => null });
"#,
            ),
            (
                local_entry,
                r#"const query = (definition) => definition;
export const unsupportedShadow = query({ args: {}, handler: async () => null });
"#,
            ),
            (
                custom_entry,
                r#"import { registerQuery } from "./custom";
export const unsupportedCustom = registerQuery({ args: {}, handler: async () => null });
"#,
            ),
            (
                object_entry,
                r#"import * as server from "./_generated/server";
export const unsupportedObject = server.query({ args: {}, handler: async () => null });
"#,
            ),
            (
                reexport_entry,
                "export { changed as reexported } from \"./direct\";\n",
            ),
            (
                wrapper_entry,
                r#"import { query } from "./_generated/server";
const wrapped = (definition) => query(definition);
export const unsupportedWrapper = wrapped({ args: {}, handler: async () => null });
"#,
            ),
            (generated_server, "export const query = undefined;\n"),
            (
                custom_builder,
                "export const registerQuery = (definition) => definition;\n",
            ),
        ] {
            let path = root.0.join(module);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        let metafile = EsbuildMetafile {
            inputs: BTreeMap::from([
                (
                    alias_entry.to_string(),
                    EsbuildInput {
                        imports: vec![crate::EsbuildImport {
                            path: generated_server.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./_generated/server".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    direct_entry.to_string(),
                    EsbuildInput {
                        imports: vec![crate::EsbuildImport {
                            path: generated_server.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./_generated/server".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    local_entry.to_string(),
                    EsbuildInput {
                        imports: Vec::new(),
                    },
                ),
                (
                    custom_entry.to_string(),
                    EsbuildInput {
                        imports: vec![crate::EsbuildImport {
                            path: custom_builder.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./custom".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    object_entry.to_string(),
                    EsbuildInput {
                        imports: vec![crate::EsbuildImport {
                            path: generated_server.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./_generated/server".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    reexport_entry.to_string(),
                    EsbuildInput {
                        imports: vec![crate::EsbuildImport {
                            path: direct_entry.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./direct".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    wrapper_entry.to_string(),
                    EsbuildInput {
                        imports: vec![crate::EsbuildImport {
                            path: generated_server.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./_generated/server".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    generated_server.to_string(),
                    EsbuildInput {
                        imports: Vec::new(),
                    },
                ),
                (
                    custom_builder.to_string(),
                    EsbuildInput {
                        imports: Vec::new(),
                    },
                ),
            ]),
            outputs: BTreeMap::new(),
        };
        let inventory = build_source_inventory(
            &root.0,
            &metafile,
            &[
                alias_entry.to_string(),
                direct_entry.to_string(),
                local_entry.to_string(),
                custom_entry.to_string(),
                object_entry.to_string(),
                reexport_entry.to_string(),
                wrapper_entry.to_string(),
            ],
            &root.0.join("cache"),
            &mut BTreeMap::new(),
            &mut PhaseMeasurements::default(),
            &test_registration_adapter_material(),
            "functions",
        )
        .unwrap();

        assert!(inventory.diagnostics.is_empty());
        assert_eq!(inventory.functions.len(), 3);
        assert_eq!(inventory.functions[0].entry_path, alias_entry);
        assert_eq!(inventory.functions[0].export_name, "selected");
        assert_eq!(inventory.functions[0].udf_kind, "query");
        assert_eq!(inventory.functions[0].registration_builder, "registerQuery");
        assert_eq!(inventory.functions[1].entry_path, direct_entry);
        assert_eq!(inventory.functions[1].export_name, "changed");
        assert_eq!(inventory.functions[1].udf_kind, "mutation");
        assert_eq!(inventory.functions[1].registration_builder, "mutation");
        assert_eq!(inventory.functions[2].entry_path, reexport_entry);
        assert_eq!(inventory.functions[2].export_name, "reexported");
        assert_eq!(inventory.functions[2].udf_kind, "mutation");
        assert_eq!(inventory.functions[2].registration_builder, "mutation");
        for function in &inventory.functions {
            let registration_call = &function.registration_call;
            assert_eq!(
                registration_call.source_path,
                if function.entry_path == reexport_entry {
                    direct_entry
                } else {
                    function.entry_path.as_str()
                }
            );
            let source = fs::read_to_string(root.0.join(&registration_call.source_path)).unwrap();
            assert_eq!(
                registration_call.source_sha256,
                crate::hash_bytes(source.as_bytes())
            );
            let call = &source[registration_call.call_span.start as usize
                ..registration_call.call_span.end as usize];
            let callee = &source[registration_call.callee_span.start as usize
                ..registration_call.callee_span.end as usize];
            assert!(call.starts_with(callee));
            assert_eq!(callee, function.registration_builder);
            assert!(call.ends_with("})"));
        }
        assert_eq!(
            inventory.functions[1].registration_call.call_span.start,
            inventory.functions[2].registration_call.call_span.start
        );
        assert_eq!(
            inventory.functions[1].registration_call.source_sha256,
            inventory.functions[2].registration_call.source_sha256
        );
        let serialized = serde_json::to_value(&inventory).unwrap();
        assert_eq!(
            serialized["functions"][0]["registrationCall"],
            serde_json::json!({
                "callSpan": {
                    "end": inventory.functions[0].registration_call.call_span.end,
                    "start": inventory.functions[0].registration_call.call_span.start,
                },
                "calleeSpan": {
                    "end": inventory.functions[0].registration_call.callee_span.end,
                    "start": inventory.functions[0].registration_call.callee_span.start,
                },
                "sourcePath": alias_entry,
                "sourceSha256": inventory.functions[0].registration_call.source_sha256,
            })
        );
    }

    #[test]
    fn source_inventory_serializes_sorted_object_destructure_evidence() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            TemporaryDirectory(env::temp_dir().join(format!("convex-source-inventory-{unique}")));
        let entry = "convex/generated.ts";
        fs::create_dir_all(root.0.join("convex")).unwrap();
        let source = "export const { zed, first: alpha } = generatedRegistry;\n";
        fs::write(root.0.join(entry), source).unwrap();
        let metafile = EsbuildMetafile {
            inputs: BTreeMap::from([(
                entry.to_string(),
                EsbuildInput {
                    imports: Vec::new(),
                },
            )]),
            outputs: BTreeMap::new(),
        };
        let inventory = build_source_inventory(
            &root.0,
            &metafile,
            &[entry.to_string()],
            &root.0.join("cache"),
            &mut BTreeMap::new(),
            &mut PhaseMeasurements::default(),
            &test_registration_adapter_material(),
            "convex",
        )
        .unwrap();
        let value = serde_json::to_value(inventory).unwrap();
        assert_eq!(value["kind"], "convex-wasm-source-inventory");
        assert_eq!(
            value["unresolvedExports"],
            serde_json::json!([
                {
                    "classification": "objectDestructure",
                    "entryPath": entry,
                    "exportName": "alpha",
                    "sourceSpan": {
                        "column": 28,
                        "end": 32,
                        "endColumn": 33,
                        "endLine": 1,
                        "line": 1,
                        "start": 27
                    }
                },
                {
                    "classification": "objectDestructure",
                    "entryPath": entry,
                    "exportName": "zed",
                    "sourceSpan": {
                        "column": 16,
                        "end": 18,
                        "endColumn": 19,
                        "endLine": 1,
                        "line": 1,
                        "start": 15
                    }
                }
            ])
        );
        assert_ne!(value["graphSha256"], serde_json::Value::Null);
    }
}

pub(crate) fn summarize_context_module(
    source: &str,
    ast: &Value,
    _imports: &BTreeMap<String, ImportBinding>,
    _units: &BTreeMap<String, UnitSummary>,
    resolved_binding_facts: &BTreeMap<(u32, u32), crate::ResolvedBindingFact>,
    exports: &BTreeMap<String, String>,
    is_commonjs: bool,
) -> Result<ContextModuleSummary> {
    let mut bindings = BindingModel::new_with_module_this_state(ast, is_commonjs)?;
    bindings.add_direct_call_parameter_origins(ast, resolved_binding_facts, exports)?;
    let mut references = Vec::new();
    collect_module_references(ast, &bindings, &mut references)?;
    references
        .sort_by_key(|reference| (reference.start, reference.end, reference.specifier.clone()));
    references.dedup_by(|left, right| {
        left.start == right.start
            && left.end == right.end
            && left.specifier == right.specifier
            && left.kind == right.kind
    });

    let mut facts = Vec::new();
    collect_program_facts(ast, exports, &mut facts)?;
    let (marker_occurrences, marker_reexports) = collect_marker_syntax(ast, &bindings)?;
    let mut active_immediate_functions = BTreeSet::new();
    collect_context_facts(
        source,
        ast,
        ast,
        true,
        &[],
        &bindings,
        &mut active_immediate_functions,
        &mut facts,
    )?;
    facts.sort_by(|left, right| {
        (left.start, left.end, &left.rule, &left.message).cmp(&(
            right.start,
            right.end,
            &right.rule,
            &right.message,
        ))
    });
    facts.dedup_by(|left, right| {
        left.start == right.start
            && left.end == right.end
            && left.rule == right.rule
            && left.message == right.message
    });
    Ok(ContextModuleSummary {
        marker_occurrences,
        marker_reexports,
        references,
        facts,
        suppressions: parse_suppressions(source),
        opaque_exports: collect_opaque_exports(ast)?,
        registrations: collect_registrations(ast)?,
        reexports: collect_reexports(ast)?,
    })
}

fn collect_marker_syntax(
    ast: &Value,
    bindings: &BindingModel,
) -> Result<(Vec<ContextMarkerOccurrence>, Vec<ContextModuleReference>)> {
    let body = ast
        .get("body")
        .and_then(Value::as_array)
        .context("ESTree program has no body")?;
    let mut occurrences = Vec::new();
    let mut reexports = Vec::new();
    for statement in body {
        match node_kind(statement) {
            Some("ExportNamedDeclaration") => {
                if let Some(declaration) = statement
                    .get("declaration")
                    .filter(|declaration| !declaration.is_null())
                {
                    collect_exported_marker_declaration(statement, declaration, &mut occurrences)?;
                }
                for specifier in statement
                    .get("specifiers")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                {
                    if specifier.get("exportKind").and_then(Value::as_str) == Some("type")
                        || specifier.get("exported").and_then(static_name).as_deref()
                            != Some("experimental_reuseContext")
                    {
                        continue;
                    }
                    let (start, end) = node_span(specifier)?;
                    occurrences.push(ContextMarkerOccurrence {
                        canonical: false,
                        message: if statement
                            .get("source")
                            .is_some_and(|source| !source.is_null())
                        {
                            "Context-reuse marker is re-exported from another module.".to_string()
                        } else {
                            "Context-reuse marker is exported through an alias or export list."
                                .to_string()
                        },
                        start,
                        end,
                    });
                }
            }
            Some("ExportAllDeclaration") => {
                if statement.get("exported").and_then(static_name).as_deref()
                    == Some("experimental_reuseContext")
                {
                    let (start, end) = node_span(statement)?;
                    occurrences.push(ContextMarkerOccurrence {
                        canonical: false,
                        message: "Context-reuse marker is exported as a namespace re-export."
                            .to_string(),
                        start,
                        end,
                    });
                } else if let Some(specifier) = statement.get("source").and_then(literal_string) {
                    let (start, end) = node_span(statement)?;
                    reexports.push(ContextModuleReference {
                        specifier,
                        kind: "reexport".to_string(),
                        type_only: false,
                        start,
                        end,
                    });
                }
            }
            Some("TSExportAssignment") => {
                if statement
                    .get("expression")
                    .is_some_and(common_js_object_may_export_marker)
                {
                    let (start, end) = node_span(statement)?;
                    occurrences.push(ContextMarkerOccurrence {
                        canonical: false,
                        message:
                            "Context-reuse marker may be assigned through a TypeScript CommonJS export."
                                .to_string(),
                        start,
                        end,
                    });
                }
            }
            _ => {}
        }
    }
    collect_common_js_markers(ast, bindings, &mut occurrences, &mut reexports)?;
    occurrences.sort_by_key(|occurrence| {
        (
            occurrence.start,
            occurrence.end,
            occurrence.canonical,
            occurrence.message.clone(),
        )
    });
    occurrences.dedup_by(|left, right| {
        left.start == right.start
            && left.end == right.end
            && left.canonical == right.canonical
            && left.message == right.message
    });
    reexports.sort_by_key(|reference| {
        (
            reference.start,
            reference.end,
            reference.kind.clone(),
            reference.specifier.clone(),
        )
    });
    reexports.dedup_by(|left, right| {
        left.start == right.start
            && left.end == right.end
            && left.kind == right.kind
            && left.specifier == right.specifier
    });
    Ok((occurrences, reexports))
}

fn collect_exported_marker_declaration(
    statement: &Value,
    declaration: &Value,
    occurrences: &mut Vec<ContextMarkerOccurrence>,
) -> Result<()> {
    match node_kind(declaration) {
        Some("VariableDeclaration") => {
            let kind = declaration
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("");
            let declarators = declaration
                .get("declarations")
                .and_then(Value::as_array)
                .context("variable declaration has no declarations")?;
            for declarator in declarators {
                let mut bindings = Vec::new();
                collect_pattern_bindings(
                    declarator
                        .get("id")
                        .context("variable declarator has no binding")?,
                    "",
                    &mut bindings,
                )?;
                for binding in bindings
                    .iter()
                    .filter(|binding| binding.name == "experimental_reuseContext")
                {
                    let canonical = bindings.len() == 1
                        && declarators.len() == 1
                        && kind == "const"
                        && declarator
                            .get("id")
                            .and_then(identifier)
                            .is_some_and(|name| name == "experimental_reuseContext")
                        && declarator
                            .get("init")
                            .and_then(|value| value.get("value"))
                            .and_then(Value::as_bool)
                            == Some(true);
                    occurrences.push(ContextMarkerOccurrence {
                        canonical,
                        message: if canonical {
                            "Canonical direct context-reuse marker.".to_string()
                        } else {
                            "Context-reuse marker must be exactly `export const experimental_reuseContext = true`."
                                .to_string()
                        },
                        start: binding.start,
                        end: binding.end,
                    });
                }
            }
        }
        Some("FunctionDeclaration" | "ClassDeclaration" | "TSEnumDeclaration")
            if declaration.get("id").and_then(identifier) == Some("experimental_reuseContext") =>
        {
            let (start, end) = node_span(
                declaration
                    .get("id")
                    .context("export declaration has no name")?,
            )?;
            occurrences.push(ContextMarkerOccurrence {
                canonical: false,
                message: "Context-reuse marker is exported by a noncanonical declaration."
                    .to_string(),
                start,
                end,
            });
        }
        _ => {
            let _ = statement;
        }
    }
    Ok(())
}

fn collect_common_js_markers(
    value: &Value,
    bindings: &BindingModel,
    occurrences: &mut Vec<ContextMarkerOccurrence>,
    reexports: &mut Vec<ContextModuleReference>,
) -> Result<()> {
    if node_kind(value) == Some("AssignmentExpression") {
        let left = value.get("left").context("assignment has no target")?;
        let right = value.get("right").context("assignment has no value")?;
        let operator = value.get("operator").and_then(Value::as_str).unwrap_or("");
        if is_common_js_marker_export(left, bindings) {
            let (start, end) = node_span(left)?;
            occurrences.push(ContextMarkerOccurrence {
                canonical: false,
                message: "Context-reuse marker is assigned through CommonJS exports.".to_string(),
                start,
                end,
            });
        } else if operator == "="
            && is_common_js_exports_object(left, bindings)
            && literal_require_specifier(right, bindings).is_some()
        {
            let (start, end) = node_span(value)?;
            reexports.push(ContextModuleReference {
                specifier: literal_require_specifier(right, bindings)
                    .context("require disappeared")?,
                kind: "require".to_string(),
                type_only: false,
                start,
                end,
            });
        } else if (is_common_js_exports_object(left, bindings)
            && common_js_object_may_export_marker(right))
            || is_possibly_computed_common_js_export(left, bindings)
            || assignment_pattern_targets(left).iter().any(|target| {
                is_common_js_marker_export(target, bindings)
                    || is_possibly_computed_common_js_export(target, bindings)
            })
        {
            let (start, end) = node_span(left)?;
            occurrences.push(ContextMarkerOccurrence {
                canonical: false,
                message: "Context-reuse marker may be assigned through CommonJS exports."
                    .to_string(),
                start,
                end,
            });
        }
    }
    if node_kind(value) == Some("CallExpression") {
        let callee = value
            .get("callee")
            .and_then(expression_path)
            .unwrap_or_default();
        let resolved_callee = value
            .get("callee")
            .and_then(|callee| bindings.resolve_expression(callee));
        let builtin_kind = resolved_callee.as_ref().and_then(|resolved| {
            resolved
                .possible_paths
                .iter()
                .find_map(|path| match path.as_str() {
                    "Object.defineProperty" | "globalThis.Object.defineProperty" => {
                        Some("define-property")
                    }
                    "Object.defineProperties" | "globalThis.Object.defineProperties" => {
                        Some("define-properties")
                    }
                    "Object.assign" | "globalThis.Object.assign" => Some("assign"),
                    "Reflect.set" | "globalThis.Reflect.set" => Some("reflect-set"),
                    _ => None,
                })
        });
        let builtin_is_global = resolved_callee
            .as_ref()
            .is_some_and(|resolved| resolved.global_state);
        let builtin_wrapper = resolved_callee.as_ref().is_some_and(|resolved| {
            resolved.possible_paths.iter().any(|path| {
                let Some((base, method)) = path.rsplit_once('.') else {
                    return false;
                };
                matches!(method, "call" | "apply")
                    && matches!(
                        base,
                        "Object.defineProperty"
                            | "globalThis.Object.defineProperty"
                            | "Object.defineProperties"
                            | "globalThis.Object.defineProperties"
                            | "Object.assign"
                            | "globalThis.Object.assign"
                            | "Reflect.set"
                            | "globalThis.Reflect.set"
                    )
            })
        });
        let known_builtin_syntax = matches!(
            callee.as_str(),
            "Object.defineProperty"
                | "globalThis.Object.defineProperty"
                | "Object.defineProperties"
                | "globalThis.Object.defineProperties"
                | "Object.assign"
                | "globalThis.Object.assign"
                | "Reflect.set"
                | "globalThis.Reflect.set"
        );
        let arguments = value
            .get("arguments")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let exports_target = arguments
            .first()
            .is_some_and(|target| is_common_js_exports_object(target, bindings));
        let matching = match (builtin_kind, builtin_is_global) {
            (Some("define-property" | "reflect-set"), true) => {
                exports_target
                    && arguments.get(1).is_some_and(|argument| {
                        literal_string(argument).as_deref() == Some("experimental_reuseContext")
                            || literal_string(argument).is_none()
                    })
            }
            (Some("define-properties"), true) => {
                exports_target
                    && arguments
                        .get(1)
                        .is_some_and(common_js_object_may_export_marker)
            }
            (Some("assign"), true) => {
                exports_target
                    && arguments
                        .iter()
                        .skip(1)
                        .any(common_js_object_may_export_marker)
            }
            (Some(_), true) => false,
            (Some(_), false) => false,
            (None, false) if known_builtin_syntax || builtin_wrapper => false,
            (None, _) => {
                exports_target
                    && arguments
                        .iter()
                        .skip(1)
                        .any(common_js_helper_argument_may_export_marker)
            }
        };
        if matching {
            let (start, end) = node_span(value)?;
            occurrences.push(ContextMarkerOccurrence {
                canonical: false,
                message: match callee.as_str() {
                    "Object.defineProperty" | "Object.defineProperties" => {
                        "Context-reuse marker may be defined through CommonJS exports."
                    }
                    "Object.assign" => "Context-reuse marker may be copied into CommonJS exports.",
                    "Reflect.set" => {
                        "Context-reuse marker may be written through CommonJS exports."
                    }
                    _ => "Context-reuse marker may be written through a CommonJS export helper.",
                }
                .to_string(),
                start,
                end,
            });
        }
    }
    match value {
        Value::Array(values) => {
            for child in values {
                collect_common_js_markers(child, bindings, occurrences, reexports)?;
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                if !matches!(key.as_str(), "loc" | "range" | "tokens" | "comments") {
                    collect_common_js_markers(child, bindings, occurrences, reexports)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn common_js_object_may_export_marker(value: &Value) -> bool {
    let value = unwrap_expression(value);
    if node_kind(value) != Some("ObjectExpression") {
        return true;
    }
    value
        .get("properties")
        .and_then(Value::as_array)
        .is_none_or(|properties| {
            properties.iter().any(|property| {
                if node_kind(property) == Some("SpreadElement") {
                    return property
                        .get("argument")
                        .is_none_or(common_js_object_may_export_marker);
                }
                property
                    .get("key")
                    .and_then(static_name)
                    .is_none_or(|name| name == "experimental_reuseContext")
            })
        })
}

fn common_js_helper_argument_may_export_marker(value: &Value) -> bool {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("Literal") => {
            literal_string(value).as_deref() == Some("experimental_reuseContext")
                || value.get("value").is_some_and(Value::is_object)
        }
        _ => common_js_object_may_export_marker(value),
    }
}

fn literal_require_specifier(value: &Value, bindings: &BindingModel) -> Option<String> {
    let value = unwrap_expression(value);
    (node_kind(value) == Some("CallExpression")
        && value
            .get("callee")
            .and_then(|callee| bindings.resolve_expression(callee))
            .is_some_and(|resolved| {
                resolved.global_state
                    && resolved.possible_paths.iter().any(|path| path == "require")
            }))
    .then(|| {
        value
            .get("arguments")
            .and_then(Value::as_array)
            .and_then(|arguments| arguments.first())
            .and_then(literal_string)
    })
    .flatten()
}

fn is_common_js_exports_object(value: &Value, bindings: &BindingModel) -> bool {
    bindings.resolve_expression(value).is_some_and(|resolved| {
        resolved.global_state
            && resolved
                .possible_paths
                .iter()
                .any(|path| matches!(path.as_str(), "exports" | "module.exports"))
    })
}

fn is_common_js_marker_export(value: &Value, bindings: &BindingModel) -> bool {
    bindings.resolve_expression(value).is_some_and(|resolved| {
        resolved.global_state
            && resolved.possible_paths.iter().any(|path| {
                matches!(
                    path.as_str(),
                    "exports.experimental_reuseContext"
                        | "module.exports.experimental_reuseContext"
                )
            })
    })
}

fn is_possibly_computed_common_js_export(value: &Value, bindings: &BindingModel) -> bool {
    let value = unwrap_expression(value);
    matches!(
        node_kind(value),
        Some("MemberExpression" | "OptionalMemberExpression")
    ) && value.get("computed").and_then(Value::as_bool) == Some(true)
        && value.get("property").and_then(literal_string).is_none()
        && value
            .get("object")
            .is_some_and(|object| is_common_js_exports_object(object, bindings))
}

fn assignment_pattern_targets(value: &Value) -> Vec<&Value> {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("Identifier" | "MemberExpression" | "OptionalMemberExpression") => vec![value],
        Some("RestElement" | "SpreadElement") => value
            .get("argument")
            .map(assignment_pattern_targets)
            .unwrap_or_default(),
        Some("ArrayPattern" | "ArrayExpression") => value
            .get("elements")
            .and_then(Value::as_array)
            .map(|elements| {
                elements
                    .iter()
                    .filter(|element| !element.is_null())
                    .flat_map(assignment_pattern_targets)
                    .collect()
            })
            .unwrap_or_default(),
        Some("ObjectPattern" | "ObjectExpression") => value
            .get("properties")
            .and_then(Value::as_array)
            .map(|properties| {
                properties
                    .iter()
                    .flat_map(|property| {
                        if node_kind(property) == Some("Property") {
                            property
                                .get("value")
                                .map(assignment_pattern_targets)
                                .unwrap_or_default()
                        } else {
                            property
                                .get("argument")
                                .map(assignment_pattern_targets)
                                .unwrap_or_default()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        Some("AssignmentPattern") => value
            .get("left")
            .map(assignment_pattern_targets)
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn collect_program_facts(
    ast: &Value,
    exports: &BTreeMap<String, String>,
    facts: &mut Vec<ContextFact>,
) -> Result<()> {
    let body = ast
        .get("body")
        .and_then(Value::as_array)
        .context("ESTree program has no body")?;
    // `var` remains program-scoped when it appears inside a module-level block (`if`, loops,
    // `switch`, or `try`). Walk those statement forms while stopping at function/class bodies so
    // a nested var cannot evade the structural module-state rule.
    for statement in body {
        if !matches!(
            node_kind(statement),
            Some("VariableDeclaration" | "ExportNamedDeclaration")
        ) {
            collect_module_scope_var_facts(statement, facts)?;
        }
    }
    for statement in body {
        let (declaration, exported) = if node_kind(statement) == Some("ExportNamedDeclaration") {
            (
                statement
                    .get("declaration")
                    .filter(|declaration| !declaration.is_null()),
                true,
            )
        } else {
            (Some(statement), false)
        };
        let Some(declaration) = declaration else {
            continue;
        };
        if node_kind(declaration) != Some("VariableDeclaration") {
            continue;
        }
        let kind = declaration
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("");
        let declarators = declaration
            .get("declarations")
            .and_then(Value::as_array)
            .context("variable declaration has no declarations")?;
        if kind != "const" {
            for declarator in declarators {
                let (start, end) = node_span(
                    declarator
                        .get("id")
                        .context("variable declarator has no binding")?,
                )?;
                facts.push(fact(
                    "top-level-mutable-binding",
                    "hard",
                    "cross-invocation-state",
                    "Top-level let/var binding can retain state between invocations.",
                    start,
                    end,
                    node_span(statement)?.0,
                ));
            }
        }
        for declarator in declarators {
            let name = declarator
                .get("id")
                .and_then(identifier)
                .unwrap_or_default();
            if (exported || exports.values().any(|local| local == name))
                && declarator.get("init").is_some_and(is_mutable_initializer)
            {
                let (start, end) = node_span(declarator.get("id").context("export has no name")?)?;
                facts.push(fact(
                    "mutable-export",
                    "information",
                    "cross-invocation-state",
                    "Exported mutable value requires review of every invocation-time consumer.",
                    start,
                    end,
                    node_span(statement)?.0,
                ));
            }
        }
    }
    if let Some(directive) = body.iter().find(|statement| {
        node_kind(statement) == Some("ExpressionStatement")
            && statement
                .get("expression")
                .and_then(|expression| expression.get("value"))
                .and_then(Value::as_str)
                == Some("use node")
    }) {
        let (start, end) = node_span(directive)?;
        facts.push(fact(
            "node-runtime",
            "hard",
            "dependency",
            "Runtime graph reaches a \"use node\" module.",
            start,
            end,
            start,
        ));
    }
    Ok(())
}

fn collect_module_scope_var_facts(value: &Value, facts: &mut Vec<ContextFact>) -> Result<()> {
    let Some(kind) = node_kind(value) else {
        match value {
            Value::Array(values) => {
                for child in values {
                    collect_module_scope_var_facts(child, facts)?;
                }
            }
            Value::Object(object) => {
                for (key, child) in object {
                    if !matches!(key.as_str(), "loc" | "range" | "tokens" | "comments") {
                        collect_module_scope_var_facts(child, facts)?;
                    }
                }
            }
            _ => {}
        }
        return Ok(());
    };
    if matches!(
        kind,
        "FunctionDeclaration"
            | "FunctionExpression"
            | "ArrowFunctionExpression"
            | "ClassDeclaration"
            | "ClassExpression"
    ) {
        return Ok(());
    }
    if kind == "VariableDeclaration" && value.get("kind").and_then(Value::as_str) == Some("var") {
        let declarators = value
            .get("declarations")
            .and_then(Value::as_array)
            .context("variable declaration has no declarations")?;
        for declarator in declarators {
            let id = declarator
                .get("id")
                .context("variable declarator has no binding")?;
            let (start, end) = node_span(id)?;
            let (anchor_start, _) = node_span(value)?;
            facts.push(fact(
                "top-level-mutable-binding",
                "hard",
                "cross-invocation-state",
                "Top-level let/var binding can retain state between invocations.",
                start,
                end,
                anchor_start,
            ));
        }
    }
    match value {
        Value::Array(values) => {
            for child in values {
                collect_module_scope_var_facts(child, facts)?;
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                if !matches!(key.as_str(), "loc" | "range" | "tokens" | "comments") {
                    collect_module_scope_var_facts(child, facts)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn collect_context_facts(
    source: &str,
    value: &Value,
    statement_anchor: &Value,
    import_time: bool,
    immediate_function_spans: &[(u32, u32)],
    bindings: &BindingModel,
    active_immediate_functions: &mut BTreeSet<(u32, u32)>,
    facts: &mut Vec<ContextFact>,
) -> Result<()> {
    let Some(kind) = node_kind(value) else {
        visit_children(
            source,
            value,
            statement_anchor,
            import_time,
            immediate_function_spans,
            bindings,
            active_immediate_functions,
            facts,
        )?;
        return Ok(());
    };
    let current_anchor = if is_statement_anchor(kind) {
        value
    } else {
        statement_anchor
    };
    let (start, end) = node_span(value)?;
    let anchor_start = node_span(current_anchor)?.0;

    if matches!(kind, "PropertyDefinition" | "AccessorProperty")
        && value.get("static").and_then(Value::as_bool) != Some(true)
    {
        // Instance field initializers run only when an instance is constructed, not when the
        // class is evaluated. Computed keys and decorators still execute at class evaluation.
        for field in ["key", "decorators"] {
            if let Some(child) = value.get(field).filter(|child| !child.is_null()) {
                collect_context_facts(
                    source,
                    child,
                    current_anchor,
                    import_time,
                    immediate_function_spans,
                    bindings,
                    active_immediate_functions,
                    facts,
                )?;
            }
        }
        if let Some(initializer) = value.get("value").filter(|value| !value.is_null()) {
            collect_context_facts(
                source,
                initializer,
                current_anchor,
                false,
                immediate_function_spans,
                bindings,
                active_immediate_functions,
                facts,
            )?;
        }
        return Ok(());
    }

    if matches!(
        kind,
        "FunctionDeclaration" | "FunctionExpression" | "ArrowFunctionExpression"
    ) {
        let executes_now =
            immediate_function_spans
                .iter()
                .any(|&(immediate_start, immediate_end)| {
                    start >= immediate_start && end <= immediate_end
                });
        visit_children(
            source,
            value,
            current_anchor,
            import_time && executes_now,
            &[],
            bindings,
            active_immediate_functions,
            facts,
        )?;
        return Ok(());
    }

    match kind {
        "VariableDeclarator" if import_time => {
            if let (Some(pattern), Some(initializer)) = (
                value.get("id"),
                value
                    .get("init")
                    .filter(|initializer| !initializer.is_null()),
            ) && bindings
                .resolve_expression(initializer)
                .is_some_and(|resolved| {
                    resolved
                        .possible_paths
                        .iter()
                        .any(|path| matches!(path.as_str(), "process" | "globalThis.process"))
                })
            {
                let mut pattern_bindings = Vec::new();
                collect_pattern_bindings(pattern, "", &mut pattern_bindings)?;
                for binding in pattern_bindings
                    .into_iter()
                    .filter(|binding| binding.suffix == ".env")
                {
                    facts.push(fact(
                        "import-time-environment",
                        "information",
                        "import-time-nondeterminism",
                        "Import-time process.env destructuring has module-evaluation lifetime.",
                        binding.start,
                        binding.end,
                        anchor_start,
                    ));
                }
            }
        }
        "AssignmentExpression" => {
            if let Some(left) = value.get("left") {
                for target in assignment_pattern_targets(left) {
                    report_write(
                        target,
                        "Assignment",
                        (start, end, anchor_start),
                        true,
                        bindings,
                        facts,
                    );
                }
            }
        }
        "UpdateExpression" => {
            if let Some(target) = value.get("argument") {
                report_write(
                    target,
                    "Update",
                    (start, end, anchor_start),
                    true,
                    bindings,
                    facts,
                );
            }
        }
        "UnaryExpression" if value.get("operator").and_then(Value::as_str) == Some("delete") => {
            if let Some(target) = value.get("argument") {
                report_write(
                    target,
                    "Delete",
                    (start, end, anchor_start),
                    true,
                    bindings,
                    facts,
                );
            }
        }
        "AwaitExpression" if import_time => facts.push(fact(
            "import-time-promise",
            "hard",
            "import-time-nondeterminism",
            "Top-level await starts asynchronous module evaluation.",
            start,
            end,
            anchor_start,
        )),
        "TaggedTemplateExpression" => {
            if value
                .get("tag")
                .is_some_and(|tag| resolves_global_require(tag, bindings))
            {
                facts.push(fact(
                    "nonliteral-runtime-require",
                    "hard",
                    "unsupported-construct",
                    "Runtime require must be a direct call to require with a string literal target.",
                    start,
                    end,
                    anchor_start,
                ));
            }
        }
        "NewExpression" => {
            let resolved_constructor = value
                .get("callee")
                .and_then(|callee| bindings.resolve_expression(callee));
            let global_constructor = resolved_constructor
                .as_ref()
                .is_some_and(|resolved| resolved.global_state);
            // A bound loader can appear as a call expression rather than a path, so use the
            // syntactic resolver in addition to the ordinary constructor path resolution.
            let global_require = value
                .get("callee")
                .is_some_and(|callee| resolves_global_require(callee, bindings));
            let promise_constructor = resolved_constructor.as_ref().is_some_and(|resolved| {
                resolved
                    .possible_paths
                    .iter()
                    .any(|path| matches!(path.as_str(), "Promise" | "globalThis.Promise"))
            });
            let intl_constructor = resolved_constructor.as_ref().is_some_and(|resolved| {
                resolved
                    .possible_paths
                    .iter()
                    .any(|path| path.starts_with("Intl.") || path.starts_with("globalThis.Intl."))
            });
            if global_require {
                facts.push(fact(
                    "nonliteral-runtime-require",
                    "hard",
                    "unsupported-construct",
                    "Runtime require must be a direct call to require with a string literal target.",
                    start,
                    end,
                    anchor_start,
                ));
            } else if import_time && global_constructor && promise_constructor {
                facts.push(fact(
                    "import-time-promise",
                    "hard",
                    "import-time-nondeterminism",
                    "Promise construction runs during module evaluation.",
                    start,
                    end,
                    anchor_start,
                ));
            } else if import_time && global_constructor && intl_constructor {
                facts.push(fact(
                    "import-time-locale",
                    "information",
                    "import-time-nondeterminism",
                    "Import-time Intl construction requires explicit locale and timezone review.",
                    start,
                    end,
                    anchor_start,
                ));
            } else if import_time {
                let retained_constructor = resolved_constructor
                    .as_ref()
                    .is_some_and(|resolved| resolved.module_state);
                let allowed_constructor = resolved_constructor.as_ref().is_some_and(|resolved| {
                    resolved.possible_paths.iter().any(|path| {
                        is_allowed_top_level_constructor(
                            path.strip_prefix("globalThis.").unwrap_or(path),
                        )
                    })
                });
                if !allowed_constructor || retained_constructor {
                    facts.push(fact(
                        "unknown-top-level-constructor",
                        "information",
                        "cross-invocation-state",
                        "Top-level constructor may create mutable retained state and requires review.",
                        start,
                        end,
                        anchor_start,
                    ));
                }
                if global_constructor
                    && resolved_constructor.as_ref().is_some_and(|resolved| {
                        resolved
                            .possible_paths
                            .iter()
                            .any(|path| matches!(path.as_str(), "Date" | "globalThis.Date"))
                    })
                    && value
                        .get("arguments")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                {
                    facts.push(fact(
                        "import-time-time-random",
                        "information",
                        "import-time-nondeterminism",
                        "Import-time call captures time or randomness.",
                        start,
                        end,
                        anchor_start,
                    ));
                }
            }
        }
        "ForOfStatement" | "ForInStatement" => {
            if let Some(left) = value.get("left")
                && node_kind(left) != Some("VariableDeclaration")
            {
                for target in assignment_pattern_targets(left) {
                    report_write(
                        target,
                        "Loop assignment",
                        (start, end, anchor_start),
                        true,
                        bindings,
                        facts,
                    );
                }
            }
        }
        "ImportExpression" => facts.push(fact(
            "dynamic-import",
            "hard",
            "unsupported-construct",
            "Dynamic import is not supported in a reused context graph.",
            start,
            end,
            anchor_start,
        )),
        "CallExpression" => analyze_call(value, import_time, anchor_start, bindings, facts)?,
        "MemberExpression" | "OptionalMemberExpression" if import_time => {
            let reads_environment = bindings.resolve_expression(value).is_some_and(|resolved| {
                resolved
                    .possible_paths
                    .iter()
                    .any(|path| matches!(path.as_str(), "process.env" | "globalThis.process.env"))
            });
            if reads_environment {
                facts.push(fact(
                    "import-time-environment",
                    "information",
                    "import-time-nondeterminism",
                    "Import-time environment access has module-evaluation lifetime.",
                    start,
                    end,
                    anchor_start,
                ));
            }
            for function in bindings.resolve_accessor_values(value) {
                let span = node_span(function)?;
                // Accessors execute synchronously when their property is read or written. Treat
                // each known accessor as an immediate call so import-time work is not downgraded
                // to the handler-time classification used for otherwise deferred functions.
                if active_immediate_functions.insert(span) {
                    collect_context_facts(
                        source,
                        function,
                        current_anchor,
                        true,
                        std::slice::from_ref(&span),
                        bindings,
                        active_immediate_functions,
                        facts,
                    )?;
                    active_immediate_functions.remove(&span);
                }
            }
        }
        _ => {}
    }

    if import_time && matches!(kind, "CallExpression" | "NewExpression") {
        for function in synchronously_invoked_bound_functions(value, bindings)? {
            let span = node_span(function)?;
            // Analyze known local callees at the call site. The active set terminates recursion
            // while still allowing the same initializer to be reviewed from independent calls.
            if active_immediate_functions.insert(span) {
                collect_context_facts(
                    source,
                    function,
                    current_anchor,
                    true,
                    std::slice::from_ref(&span),
                    bindings,
                    active_immediate_functions,
                    facts,
                )?;
                active_immediate_functions.remove(&span);
            }
        }
        let constructed_target = if kind == "NewExpression" {
            value.get("callee").map(unwrap_expression)
        } else if kind == "CallExpression"
            && value
                .get("callee")
                .and_then(|callee| bindings.resolve_expression(callee))
                .is_some_and(|resolved| {
                    resolved.global_state
                        && resolved.possible_paths.iter().any(|path| {
                            matches!(
                                path.as_str(),
                                "Reflect.construct" | "globalThis.Reflect.construct"
                            )
                        })
                })
        {
            // Reflect.construct invokes a class constructor synchronously just like `new`; its
            // instance fields therefore run during module evaluation and must not be downgraded
            // to handler-time evidence.
            value
                .get("arguments")
                .and_then(Value::as_array)
                .and_then(|arguments| arguments.first())
                .map(unwrap_expression)
        } else {
            None
        };
        if let Some(callee) = constructed_target {
            let mut initializers = bindings
                .resolve_constructible_initializers(callee)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();
            if matches!(
                node_kind(callee),
                Some("ClassExpression" | "ClassDeclaration")
            ) {
                initializers.extend(class_instance_initializers(callee)?.into_iter());
            }
            for initializer in initializers {
                collect_context_facts(
                    source,
                    &initializer,
                    current_anchor,
                    true,
                    &[],
                    bindings,
                    active_immediate_functions,
                    facts,
                )?;
            }
        }
    }

    let invoked_function_spans = if matches!(kind, "CallExpression" | "NewExpression") {
        let spans = synchronously_invoked_function_spans(value, bindings)?;
        (!spans.is_empty()).then_some(spans)
    } else {
        None
    };
    let child_immediate_function_spans = invoked_function_spans
        .as_deref()
        .unwrap_or(immediate_function_spans);
    visit_children(
        source,
        value,
        current_anchor,
        import_time,
        child_immediate_function_spans,
        bindings,
        active_immediate_functions,
        facts,
    )
}

#[expect(clippy::too_many_arguments)]
fn visit_children(
    source: &str,
    value: &Value,
    statement_anchor: &Value,
    import_time: bool,
    immediate_function_spans: &[(u32, u32)],
    bindings: &BindingModel,
    active_immediate_functions: &mut BTreeSet<(u32, u32)>,
    facts: &mut Vec<ContextFact>,
) -> Result<()> {
    match value {
        Value::Array(values) => {
            for child in values {
                collect_context_facts(
                    source,
                    child,
                    statement_anchor,
                    import_time,
                    immediate_function_spans,
                    bindings,
                    active_immediate_functions,
                    facts,
                )?;
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(key.as_str(), "loc" | "range" | "tokens" | "comments") {
                    continue;
                }
                collect_context_facts(
                    source,
                    child,
                    statement_anchor,
                    import_time,
                    immediate_function_spans,
                    bindings,
                    active_immediate_functions,
                    facts,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn analyze_call(
    call: &Value,
    import_time: bool,
    anchor_start: u32,
    bindings: &BindingModel,
    facts: &mut Vec<ContextFact>,
) -> Result<()> {
    let (start, end) = node_span(call)?;
    let resolved_callee = call
        .get("callee")
        .and_then(|callee| bindings.resolve_expression(callee));
    let callee_path = resolved_callee
        .as_ref()
        .map(|resolved| resolved.path.as_str())
        .unwrap_or_default();
    let global_callee = resolved_callee
        .as_ref()
        .is_some_and(|resolved| resolved.global_state);
    let arguments = call
        .get("arguments")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let global_require = global_callee
        && resolved_callee.as_ref().is_some_and(|resolved| {
            resolved
                .possible_paths
                .iter()
                .any(|path| matches!(path.as_str(), "require" | "globalThis.require"))
        });
    if global_require {
        if call.get("callee").and_then(identifier) != Some("require")
            || arguments.first().and_then(literal_string).is_none()
        {
            facts.push(fact(
                "nonliteral-runtime-require",
                "hard",
                "unsupported-construct",
                "Runtime require must be a direct call to require with a string literal target.",
                start,
                end,
                anchor_start,
            ));
        }
        return Ok(());
    }
    if aliased_global_require_invocation(call, bindings) {
        facts.push(fact(
            "nonliteral-runtime-require",
            "hard",
            "unsupported-construct",
            "Runtime require must be a direct call to require with a string literal target.",
            start,
            end,
            anchor_start,
        ));
        return Ok(());
    }
    if call.get("callee").and_then(node_kind) == Some("Import") {
        facts.push(fact(
            "dynamic-import",
            "hard",
            "unsupported-construct",
            "Dynamic import is not supported in a reused context graph.",
            start,
            end,
            anchor_start,
        ));
    }
    // Preserve a statically named member operation even when its receiver is dynamic (for
    // example, getTarget().push(value)). The receiver then fails closed in
    // report_mutator_write instead of disappearing because the full callee has no state path.
    let method = callee_path
        .rsplit('.')
        .next()
        .filter(|method| !method.is_empty())
        .or_else(|| call.get("callee").and_then(static_member_name))
        .unwrap_or("");
    let possible_global_timer = global_callee
        && resolved_callee.as_ref().is_some_and(|resolved| {
            resolved
                .possible_paths
                .iter()
                .any(|path| is_timer(path.rsplit('.').next().unwrap_or("")))
        });
    if import_time {
        if possible_global_timer {
            facts.push(fact(
                "import-time-timer",
                "hard",
                "import-time-nondeterminism",
                "Timer or queued callback starts during module evaluation.",
                start,
                end,
                anchor_start,
            ));
        } else if method == "addEventListener"
            || matches!(
                method,
                "addListener"
                    | "on"
                    | "once"
                    | "prependListener"
                    | "prependOnceListener"
                    | "subscribe"
            )
        {
            facts.push(fact(
                "import-time-listener",
                "hard",
                "import-time-nondeterminism",
                "Listener registration runs during module evaluation.",
                start,
                end,
                anchor_start,
            ));
        } else if callee_path == "fetch" || method == "fetch" {
            facts.push(fact(
                "import-time-fetch",
                "hard",
                "import-time-nondeterminism",
                "External request starts during module evaluation.",
                start,
                end,
                anchor_start,
            ));
        }
        if (global_callee
            && resolved_callee.as_ref().is_some_and(|resolved| {
                resolved.possible_paths.iter().any(|path| {
                    matches!(path.as_str(), "Promise" | "globalThis.Promise")
                        || path.starts_with("Promise.")
                        || path.starts_with("globalThis.Promise.")
                })
            }))
            || matches!(method, "then" | "catch" | "finally")
            || call
                .get("callee")
                .map(unwrap_expression)
                .is_some_and(|callee| {
                    matches!(
                        node_kind(callee),
                        Some("ArrowFunctionExpression" | "FunctionExpression")
                    ) && callee.get("async").and_then(Value::as_bool) == Some(true)
                })
            || synchronously_invoked_bound_functions(call, bindings)?
                .iter()
                .any(|function| function.get("async").and_then(Value::as_bool) == Some(true))
            || arguments.iter().any(|argument| {
                matches!(
                    node_kind(argument),
                    Some("ArrowFunctionExpression" | "FunctionExpression")
                ) && argument.get("async").and_then(Value::as_bool) == Some(true)
            })
        {
            facts.push(fact(
                "import-time-promise",
                "hard",
                "import-time-nondeterminism",
                "Promise or async work starts during module evaluation.",
                start,
                end,
                anchor_start,
            ));
        }
        if global_callee
            && resolved_callee.as_ref().is_some_and(|resolved| {
                resolved.possible_paths.iter().any(|path| {
                    matches!(
                        path.as_str(),
                        "Date.now"
                            | "globalThis.Date.now"
                            | "Math.random"
                            | "globalThis.Math.random"
                            | "crypto.getRandomValues"
                            | "globalThis.crypto.getRandomValues"
                            | "crypto.randomUUID"
                            | "globalThis.crypto.randomUUID"
                            | "performance.now"
                            | "globalThis.performance.now"
                    ) || matches!(path.as_str(), "Date" | "globalThis.Date") && arguments.is_empty()
                })
            })
        {
            facts.push(fact(
                "import-time-time-random",
                "information",
                "import-time-nondeterminism",
                "Import-time call captures time or randomness.",
                start,
                end,
                anchor_start,
            ));
        }
        if (global_callee
            && resolved_callee.as_ref().is_some_and(|resolved| {
                resolved
                    .possible_paths
                    .iter()
                    .any(|path| path.starts_with("Intl.") || path.starts_with("globalThis.Intl."))
            }))
            || matches!(
                method,
                "getTimezoneOffset"
                    | "localeCompare"
                    | "toLocaleDateString"
                    | "toLocaleLowerCase"
                    | "toLocaleString"
                    | "toLocaleTimeString"
                    | "toLocaleUpperCase"
            )
        {
            facts.push(fact(
                "import-time-locale",
                "information",
                "import-time-nondeterminism",
                "Import-time locale operation requires explicit locale and timezone review.",
                start,
                end,
                anchor_start,
            ));
        }
    } else if possible_global_timer
        || method == "addEventListener"
        || matches!(method, "on" | "once" | "subscribe")
    {
        facts.push(fact(
            "handler-retained-work",
            "information",
            "cross-invocation-state",
            "Invocation-time work can outlive the handler in a reused context.",
            start,
            end,
            anchor_start,
        ));
    }

    if matches!(method, "exec" | "test")
        && let Some(resolved) =
            callee_target(call).and_then(|target| bindings.resolve_expression(target))
    {
        if resolved.module_state {
            facts.push(fact(
                "stateful-regexp",
                "information",
                "cross-invocation-state",
                "Module-scope regular expression use may retain mutable lastIndex.",
                start,
                end,
                anchor_start,
            ));
        }
    }

    if is_mutating_method(method) {
        if matches!(method, "call" | "apply") {
            if let Some(resolved_invoked) =
                callee_target(call).and_then(|target| bindings.resolve_expression(target))
            {
                let invoked_method = resolved_invoked.path.rsplit('.').next().unwrap_or("");
                let mut unresolved_target_first_application = false;
                let target = if resolves_to_target_first_mutator(&resolved_invoked) {
                    match method {
                        "call" => {
                            if arguments.first().is_some_and(is_spread_argument) {
                                unresolved_target_first_application = true;
                                None
                            } else {
                                match arguments.get(1) {
                                    Some(target) if is_spread_argument(target) => {
                                        unresolved_target_first_application = true;
                                        None
                                    }
                                    target => target,
                                }
                            }
                        }
                        "apply" => {
                            if arguments.first().is_some_and(is_spread_argument) {
                                unresolved_target_first_application = true;
                                None
                            } else {
                                match first_applied_argument(arguments.get(1)) {
                                    AppliedFirstArgument::Resolved(target) => Some(target),
                                    AppliedFirstArgument::Missing => None,
                                    AppliedFirstArgument::Unknown => {
                                        unresolved_target_first_application = true;
                                        None
                                    }
                                }
                            }
                        }
                        _ => None,
                    }
                } else if is_mutating_method(invoked_method) {
                    match arguments.first() {
                        Some(target) if is_spread_argument(target) => {
                            unresolved_target_first_application = true;
                            None
                        }
                        target => target,
                    }
                } else {
                    None
                };
                if let Some(target) = target {
                    report_mutator_write(
                        target,
                        &format!("{invoked_method}.{method}"),
                        (start, end, anchor_start),
                        bindings,
                        facts,
                    );
                }
                if unresolved_target_first_application {
                    facts.push(fact(
                        "unresolved-mutator-application",
                        "unsupported",
                        "unsupported-construct",
                        if method == "call"
                            && resolves_to_target_first_mutator(&resolved_invoked)
                        {
                            "Target-first mutator call arguments must expose the mutated target as a positional argument."
                        } else if method == "call" {
                            "Mutator call arguments must expose the mutated receiver as a positional argument."
                        } else {
                            if resolves_to_target_first_mutator(&resolved_invoked) {
                                "Target-first mutator apply arguments must expose the mutated target in an array literal."
                            } else {
                                "Mutator apply arguments must expose the mutated receiver as a positional argument."
                            }
                        },
                        start,
                        end,
                        anchor_start,
                    ));
                }
            }
        } else if !resolved_callee
            .as_ref()
            .is_some_and(|resolved| resolves_to_target_first_mutator(resolved))
            && let Some(target) = callee_target(call)
        {
            report_mutator_write(
                target,
                &format!("{method} call"),
                (start, end, anchor_start),
                bindings,
                facts,
            );
        }
    }
    if resolved_callee.as_ref().is_some_and(|resolved| {
        resolved.global_state
            && resolved.possible_paths.iter().any(|path| {
                matches!(
                    path.as_str(),
                    "Reflect.apply"
                        | "globalThis.Reflect.apply"
                        | "Reflect.construct"
                        | "globalThis.Reflect.construct"
                )
            })
    }) && let Some(invoked) = arguments.first()
        && let Some(resolved_invoked) = bindings.resolve_expression(invoked)
        && resolved_invoked.global_state
    {
        let invoked_method = resolved_invoked.path.rsplit('.').next().unwrap_or("");
        let mut unresolved_target_first_application = false;
        let target = if resolves_to_target_first_mutator(&resolved_invoked) {
            if arguments.get(1).is_some_and(is_spread_argument) {
                unresolved_target_first_application = true;
                None
            } else {
                match first_applied_argument(arguments.get(2)) {
                    AppliedFirstArgument::Resolved(target) => Some(target),
                    AppliedFirstArgument::Missing => None,
                    AppliedFirstArgument::Unknown => {
                        unresolved_target_first_application = true;
                        None
                    }
                }
            }
        } else if is_mutating_method(invoked_method) {
            match arguments.get(1) {
                Some(target) if is_spread_argument(target) => {
                    unresolved_target_first_application = true;
                    None
                }
                target => target,
            }
        } else {
            None
        };
        if let Some(target) = target {
            report_mutator_write(
                target,
                &format!("Reflect.apply of {invoked_method}"),
                (start, end, anchor_start),
                bindings,
                facts,
            );
        }
        if unresolved_target_first_application {
            facts.push(fact(
                "unresolved-mutator-application",
                "unsupported",
                "unsupported-construct",
                if resolves_to_target_first_mutator(&resolved_invoked) {
                    "Reflect.apply arguments for a target-first mutator must expose the mutated target in an array literal."
                } else {
                    "Reflect.apply arguments for a mutator must expose the mutated receiver as a positional argument."
                },
                start,
                end,
                anchor_start,
            ));
        }
    }
    if resolved_callee
        .as_ref()
        .is_some_and(resolves_to_target_first_mutator)
    {
        match arguments.first() {
            Some(target) if node_kind(unwrap_expression(target)) == Some("SpreadElement") => {
                facts.push(fact(
                    "unresolved-mutator-application",
                    "unsupported",
                    "unsupported-construct",
                    "Target-first mutator arguments must expose the mutated target as a positional argument.",
                    start,
                    end,
                    anchor_start,
                ));
            }
            Some(target) => report_mutator_write(
                target,
                callee_path,
                (start, end, anchor_start),
                bindings,
                facts,
            ),
            None => {}
        }
    }
    Ok(())
}

fn resolves_global_require(value: &Value, bindings: &BindingModel) -> bool {
    // `globalThis.require` and `module.require` are not admitted graph edges (only direct
    // unresolved `require` is), but they must still be rejected as runtime-require bypasses
    // instead of disappearing from the reference graph entirely.
    let value = unwrap_expression(value);
    if let (Some(path), Ok((position, _))) = (expression_path(value), node_span(value))
        && bindings.path_resolves_global_require(
            &path,
            position,
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
        )
    {
        return true;
    }
    if bindings.resolve_expression(value).is_some_and(|resolved| {
        resolved.global_state
            && resolved
                .possible_paths
                .iter()
                .any(|path| matches!(path.as_str(), "require" | "globalThis.require"))
    }) {
        return true;
    }
    match node_kind(value) {
        // Parenthesized direct calls resolve through `unwrap_expression`; these additional
        // expression forms preserve the last/possible callable value and must not hide a global
        // require behind an otherwise non-static invocation.
        Some("SequenceExpression") => value
            .get("expressions")
            .and_then(Value::as_array)
            .and_then(|expressions| expressions.last())
            .is_some_and(|last| resolves_global_require(last, bindings)),
        Some("AssignmentExpression") => assignment_result_fields(value).iter().any(|field| {
            value
                .get(*field)
                .is_some_and(|result| resolves_global_require(result, bindings))
        }),
        // `require.bind(...)` creates a callable alias without invoking require; the enclosing
        // call or construction is the non-direct runtime-require use.
        Some("CallExpression") => {
            let callee = value.get("callee").map(unwrap_expression);
            callee
                .filter(|callee| {
                    matches!(
                        node_kind(callee),
                        Some("MemberExpression" | "OptionalMemberExpression")
                    ) && static_member_name(callee) == Some("bind")
                })
                .and_then(|callee| callee.get("object"))
                .is_some_and(|target| resolves_global_require(target, bindings))
        }
        Some("TaggedTemplateExpression") => value
            .get("tag")
            .is_some_and(|tag| resolves_global_require(tag, bindings)),
        Some("ConditionalExpression" | "LogicalExpression") => {
            ["consequent", "alternate", "left", "right"]
                .into_iter()
                .filter_map(|field| value.get(field))
                .any(|branch| resolves_global_require(branch, bindings))
        }
        _ => false,
    }
}

fn aliased_global_require_invocation(call: &Value, bindings: &BindingModel) -> bool {
    let Some(callee) = call.get("callee").map(unwrap_expression) else {
        return false;
    };
    if matches!(
        node_kind(callee),
        Some("MemberExpression" | "OptionalMemberExpression")
    ) && matches!(static_member_name(callee), Some("call" | "apply"))
        && callee
            .get("object")
            .is_some_and(|target| resolves_global_require(target, bindings))
    {
        return true;
    }
    if bindings.resolve_expression(callee).is_some_and(|resolved| {
        resolved.global_state
            && resolved.possible_paths.iter().any(|path| {
                matches!(
                    path.as_str(),
                    "Reflect.apply"
                        | "globalThis.Reflect.apply"
                        | "Reflect.construct"
                        | "globalThis.Reflect.construct"
                )
            })
    }) && call
        .get("arguments")
        .and_then(Value::as_array)
        .and_then(|arguments| arguments.first())
        .is_some_and(|target| resolves_global_require(target, bindings))
    {
        return true;
    }
    // A binding alias such as `const load = require; load("./module")` is still a
    // non-direct runtime require. Direct `require(...)` calls return through the branch above,
    // so accepting identifier callees here cannot duplicate that diagnostic.
    resolves_global_require(callee, bindings)
}

enum AppliedFirstArgument<'a> {
    Missing,
    Resolved(&'a Value),
    Unknown,
}

fn is_spread_argument(value: &Value) -> bool {
    // A spread can change the positional target or receiver, so it cannot be treated as a
    // statically absent write just because its AST node has no state path.
    node_kind(unwrap_expression(value)) == Some("SpreadElement")
}

fn first_applied_argument(value: Option<&Value>) -> AppliedFirstArgument<'_> {
    let Some(value) = value else {
        return AppliedFirstArgument::Missing;
    };
    let value = unwrap_expression(value);
    if node_kind(value) != Some("ArrayExpression") {
        return AppliedFirstArgument::Unknown;
    }
    let Some(first) = value
        .get("elements")
        .and_then(Value::as_array)
        .and_then(|elements| elements.first())
        .filter(|element| !element.is_null())
    else {
        return AppliedFirstArgument::Missing;
    };
    if node_kind(first) == Some("SpreadElement") {
        AppliedFirstArgument::Unknown
    } else {
        AppliedFirstArgument::Resolved(first)
    }
}

fn report_write(
    target: &Value,
    operation: &str,
    location: (u32, u32, u32),
    rebinds_target: bool,
    bindings: &BindingModel,
    facts: &mut Vec<ContextFact>,
) {
    let (start, end, anchor_start) = location;
    if rebinds_target && bindings.is_local_identifier(target) {
        return;
    }
    let resolution_target = if rebinds_target
        && matches!(
            node_kind(unwrap_expression(target)),
            Some("MemberExpression" | "OptionalMemberExpression")
        ) {
        // Replacing a property mutates its containing object, not the value previously stored in
        // that property. Nested writes still resolve the containing member value and therefore
        // preserve alias provenance for `holder.shared.field = value`.
        unwrap_expression(target)
            .get("object")
            .expect("member assignment target has no object")
    } else {
        target
    };
    let Some(resolved) = bindings.resolve_expression(resolution_target) else {
        return;
    };
    // Direct assignment replaces the imported or module slot. Provenance from the assigned value
    // must not relabel that slot write as a write through to global state.
    let direct_module_rebinding =
        rebinds_target && identifier(unwrap_expression(target)).is_some() && resolved.module_state;
    if resolved.global_state && !direct_module_rebinding {
        facts.push(fact(
            "global-state-write",
            "hard",
            "cross-invocation-state",
            &format!("{operation} writes global, prototype, or built-in state."),
            start,
            end,
            anchor_start,
        ));
    } else if resolved.module_state {
        facts.push(fact(
            "module-state-write",
            "hard",
            "cross-invocation-state",
            &format!("{operation} writes module or imported state."),
            start,
            end,
            anchor_start,
        ));
    }
}

fn report_mutator_write(
    target: &Value,
    operation: &str,
    location: (u32, u32, u32),
    bindings: &BindingModel,
    facts: &mut Vec<ContextFact>,
) {
    if !bindings.mutator_value_is_resolved_or_fresh(target) {
        let (start, end, anchor_start) = location;
        facts.push(fact(
            "unresolved-mutator-application",
            "unsupported",
            "unsupported-construct",
            &format!(
                "Known mutator {operation} has a target or receiver that is neither a resolved state path nor a structurally fresh value."
            ),
            start,
            end,
            anchor_start,
        ));
        return;
    }
    report_write(target, operation, location, false, bindings, facts);
}

fn is_known_fresh_constructor(name: String) -> bool {
    let name = name.strip_prefix("globalThis.").unwrap_or(&name);
    matches!(
        name,
        "AbortController"
            | "Array"
            | "ArrayBuffer"
            | "DataView"
            | "Date"
            | "Headers"
            | "Map"
            | "RegExp"
            | "Request"
            | "Response"
            | "Set"
            | "TextDecoder"
            | "TextEncoder"
            | "URL"
            | "URLSearchParams"
            | "WeakMap"
            | "WeakSet"
            | "Float32Array"
            | "Float64Array"
            | "Int8Array"
            | "Int16Array"
            | "Int32Array"
            | "Uint8Array"
            | "Uint8ClampedArray"
            | "Uint16Array"
            | "Uint32Array"
    ) || name.starts_with("Intl.")
}

fn collect_module_references(
    value: &Value,
    bindings: &BindingModel,
    references: &mut Vec<ContextModuleReference>,
) -> Result<()> {
    let Some(kind) = node_kind(value) else {
        return visit_reference_children(value, bindings, references);
    };
    if matches!(
        kind,
        "ImportDeclaration" | "ExportNamedDeclaration" | "ExportAllDeclaration"
    ) {
        if let Some(specifier) = value.get("source").and_then(literal_string) {
            let (start, end) = node_span(value)?;
            let specifiers = value
                .get("specifiers")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let type_only = value.get("importKind").and_then(Value::as_str) == Some("type")
                || value.get("exportKind").and_then(Value::as_str) == Some("type")
                || (!specifiers.is_empty()
                    && specifiers.iter().all(|specifier| {
                        specifier.get("importKind").and_then(Value::as_str) == Some("type")
                            || specifier.get("exportKind").and_then(Value::as_str) == Some("type")
                    }));
            references.push(ContextModuleReference {
                specifier,
                kind: if kind == "ImportDeclaration" {
                    "import".to_string()
                } else {
                    "reexport".to_string()
                },
                type_only,
                start,
                end,
            });
        }
    } else if kind == "CallExpression"
        && value.get("callee").and_then(identifier) == Some("require")
        && value
            .get("callee")
            .and_then(|callee| bindings.resolve_expression(callee))
            .is_some_and(|resolved| {
                resolved.global_state
                    && resolved.possible_paths.iter().any(|path| path == "require")
            })
    {
        let arguments = value
            .get("arguments")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if let Some(specifier) = arguments.first().and_then(literal_string) {
            let (start, end) = node_span(value)?;
            references.push(ContextModuleReference {
                specifier,
                kind: "require".to_string(),
                type_only: false,
                start,
                end,
            });
        }
    }
    visit_reference_children(value, bindings, references)
}

fn collect_registrations(ast: &Value) -> Result<Vec<ContextRegistration>> {
    let body = ast
        .get("body")
        .and_then(Value::as_array)
        .context("ESTree program has no body")?;
    let mut local_registrations = BTreeMap::<String, ContextRegistration>::new();
    let mut exported_names = BTreeMap::<String, String>::new();
    for statement in body {
        let exported_declaration = node_kind(statement) == Some("ExportNamedDeclaration")
            && statement.get("source").is_none_or(Value::is_null);
        let declaration = if exported_declaration {
            statement
                .get("declaration")
                .filter(|declaration| !declaration.is_null())
        } else if node_kind(statement) == Some("VariableDeclaration") {
            Some(statement)
        } else {
            None
        };
        if let Some(declaration) =
            declaration.filter(|declaration| node_kind(declaration) == Some("VariableDeclaration"))
        {
            for declarator in declaration
                .get("declarations")
                .and_then(Value::as_array)
                .context("variable declaration has no declarations")?
            {
                let Some(local_name) = declarator.get("id").and_then(identifier) else {
                    continue;
                };
                let Some(initializer) = declarator
                    .get("init")
                    .filter(|initializer| !initializer.is_null())
                    .map(unwrap_expression)
                else {
                    continue;
                };
                if node_kind(initializer) != Some("CallExpression") {
                    continue;
                }
                let Some(builder) = initializer.get("callee").and_then(identifier) else {
                    continue;
                };
                let udf_kind = registration_kind(builder).map(str::to_string);
                let (call_start, call_end) = node_span(initializer)?;
                let (callee_start, callee_end) = node_span(
                    initializer
                        .get("callee")
                        .context("registration call has no callee")?,
                )?;
                let (start, end) = node_span(
                    declarator
                        .get("id")
                        .context("registration declarator has no name")?,
                )?;
                local_registrations.insert(
                    local_name.to_string(),
                    ContextRegistration {
                        export_name: local_name.to_string(),
                        local_name: local_name.to_string(),
                        registration_builder: builder.to_string(),
                        udf_kind,
                        call_start,
                        call_end,
                        callee_start,
                        callee_end,
                        start,
                        end,
                    },
                );
                if exported_declaration {
                    exported_names.insert(local_name.to_string(), local_name.to_string());
                }
            }
        }
        if node_kind(statement) == Some("ExportNamedDeclaration")
            && statement.get("source").is_none_or(Value::is_null)
        {
            for specifier in statement
                .get("specifiers")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                let Some(local) = specifier.get("local").and_then(static_name) else {
                    continue;
                };
                let Some(exported) = specifier.get("exported").and_then(static_name) else {
                    continue;
                };
                exported_names.insert(exported, local);
            }
        }
    }
    let mut registrations = exported_names
        .into_iter()
        .filter_map(|(export_name, local_name)| {
            local_registrations.get(&local_name).map(|registration| {
                let mut registration = registration.clone();
                registration.export_name = export_name;
                registration
            })
        })
        .collect::<Vec<_>>();
    registrations.sort_by(|left, right| left.export_name.cmp(&right.export_name));
    Ok(registrations)
}

fn collect_opaque_exports(ast: &Value) -> Result<Vec<ContextOpaqueExport>> {
    let body = ast
        .get("body")
        .and_then(Value::as_array)
        .context("ESTree program has no body")?;
    let mut exports = Vec::new();
    for statement in body {
        if node_kind(statement) != Some("ExportNamedDeclaration")
            || !statement.get("source").is_none_or(Value::is_null)
        {
            continue;
        }
        let Some(declaration) = statement
            .get("declaration")
            .filter(|declaration| node_kind(declaration) == Some("VariableDeclaration"))
        else {
            continue;
        };
        for declarator in declaration
            .get("declarations")
            .and_then(Value::as_array)
            .context("variable declaration has no declarations")?
        {
            let Some(pattern) = declarator
                .get("id")
                .filter(|pattern| node_kind(pattern) == Some("ObjectPattern"))
            else {
                continue;
            };
            let mut bindings = Vec::new();
            collect_pattern_bindings(pattern, "", &mut bindings)?;
            exports.extend(bindings.into_iter().map(|binding| ContextOpaqueExport {
                export_name: binding.name,
                classification: "objectDestructure".to_string(),
                start: binding.start,
                end: binding.end,
            }));
        }
    }
    exports.sort_by(|left, right| {
        (&left.export_name, left.start, left.end).cmp(&(&right.export_name, right.start, right.end))
    });
    exports.dedup_by(|left, right| {
        left.export_name == right.export_name && left.start == right.start && left.end == right.end
    });
    Ok(exports)
}

fn collect_reexports(ast: &Value) -> Result<Vec<ContextReexport>> {
    let body = ast
        .get("body")
        .and_then(Value::as_array)
        .context("ESTree program has no body")?;
    let mut reexports = Vec::new();
    for statement in body {
        if node_kind(statement) != Some("ExportNamedDeclaration")
            || statement.get("exportKind").and_then(Value::as_str) == Some("type")
        {
            continue;
        }
        let Some(specifier) = statement.get("source").and_then(literal_string) else {
            continue;
        };
        let (start, end) = node_span(statement)?;
        for item in statement
            .get("specifiers")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if item.get("exportKind").and_then(Value::as_str) == Some("type") {
                continue;
            }
            let Some(imported_name) = item.get("local").and_then(static_name) else {
                continue;
            };
            let Some(export_name) = item.get("exported").and_then(static_name) else {
                continue;
            };
            reexports.push(ContextReexport {
                export_name,
                imported_name,
                specifier: specifier.clone(),
                start,
                end,
            });
        }
    }
    reexports.sort_by(|left, right| {
        (&left.export_name, &left.specifier, &left.imported_name).cmp(&(
            &right.export_name,
            &right.specifier,
            &right.imported_name,
        ))
    });
    Ok(reexports)
}

fn registration_kind(builder: &str) -> Option<&'static str> {
    match builder {
        "internalQuery" | "query" => Some("query"),
        "internalMutation" | "mutation" => Some("mutation"),
        "action" | "internalAction" => Some("action"),
        "httpAction" => Some("httpAction"),
        _ => None,
    }
}

fn visit_reference_children(
    value: &Value,
    bindings: &BindingModel,
    references: &mut Vec<ContextModuleReference>,
) -> Result<()> {
    match value {
        Value::Array(values) => {
            for child in values {
                collect_module_references(child, bindings, references)?;
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                if matches!(key.as_str(), "loc" | "range" | "tokens" | "comments") {
                    continue;
                }
                collect_module_references(child, bindings, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_suppressions(source: &str) -> Vec<SuppressionDeclaration> {
    source
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            let Some(comment) = trimmed.strip_prefix("//") else {
                return None;
            };
            let comment = comment.trim();
            let body = comment.strip_prefix(SUPPRESSION_PREFIX)?;
            if body
                .chars()
                .next()
                .is_some_and(|character| !character.is_whitespace())
            {
                return None;
            }
            let Some((rule, reason)) = body.trim().split_once(':') else {
                return Some(invalid_suppression(
                    index + 1,
                    format!(
                        "Suppression must use // {SUPPRESSION_PREFIX} <rule>: <literal reason>."
                    ),
                ));
            };
            let rule = rule.trim();
            let reason = reason.trim();
            if !is_suppressible_rule(rule) {
                return Some(invalid_suppression(
                    index + 1,
                    format!("Suppression rule {rule} is unknown or cannot be suppressed."),
                ));
            }
            if reason.len() < 16 {
                return Some(invalid_suppression(
                    index + 1,
                    "Suppression reason must contain at least 16 literal characters.".to_string(),
                ));
            }
            Some(SuppressionDeclaration {
                line: index + 1,
                rule: Some(rule.to_string()),
                reason: Some(reason.to_string()),
                error: None,
            })
        })
        .collect()
}

fn invalid_suppression(line: usize, error: String) -> SuppressionDeclaration {
    SuppressionDeclaration {
        line,
        rule: None,
        reason: None,
        error: Some(error),
    }
}

fn is_suppressible_rule(rule: &str) -> bool {
    matches!(
        rule,
        "top-level-mutable-binding"
            | "module-state-write"
            | "global-state-write"
            | "import-time-promise"
            | "import-time-timer"
            | "import-time-listener"
            | "import-time-fetch"
            | "dynamic-import"
            | "handler-retained-work"
            | "import-time-environment"
            | "import-time-time-random"
            | "import-time-locale"
            | "stateful-regexp"
            | "unknown-top-level-constructor"
            | "mutable-export"
    )
}

fn fact(
    rule: &str,
    severity: &str,
    category: &str,
    message: &str,
    start: u32,
    end: u32,
    anchor_start: u32,
) -> ContextFact {
    ContextFact {
        rule: rule.to_string(),
        severity: severity.to_string(),
        category: category.to_string(),
        message: message.to_string(),
        start,
        end,
        anchor_start,
    }
}

fn node_kind(value: &Value) -> Option<&str> {
    value.get("type").and_then(Value::as_str)
}

fn node_span(value: &Value) -> Result<(u32, u32)> {
    Ok((
        value
            .get("start")
            .and_then(Value::as_u64)
            .context("ESTree node has no start")? as u32,
        value
            .get("end")
            .and_then(Value::as_u64)
            .context("ESTree node has no end")? as u32,
    ))
}

fn identifier(value: &Value) -> Option<&str> {
    (node_kind(value) == Some("Identifier"))
        .then(|| value.get("name").and_then(Value::as_str))
        .flatten()
}

fn static_name(value: &Value) -> Option<String> {
    identifier(value)
        .map(ToString::to_string)
        .or_else(|| literal_string(value))
}

fn unwrap_expression(mut value: &Value) -> &Value {
    while matches!(
        node_kind(value),
        Some(
            "TSAsExpression"
                | "TSTypeAssertion"
                | "TSNonNullExpression"
                | "TSSatisfiesExpression"
                | "TSInstantiationExpression"
                | "ChainExpression"
                | "ParenthesizedExpression"
        )
    ) {
        let Some(expression) = value.get("expression") else {
            break;
        };
        value = expression;
    }
    value
}

fn assignment_result_fields(value: &Value) -> &'static [&'static str] {
    match value.get("operator").and_then(Value::as_str) {
        Some("=") => &["right"],
        // A logical assignment evaluates to the existing left-hand value when its short-circuit
        // branch wins, and to the assigned right-hand value otherwise. Both provenances remain
        // possible even though only the right-hand side can perform the write.
        Some("&&=" | "||=" | "??=") => &["left", "right"],
        // Arithmetic and bitwise assignments coerce their operands and do not return either
        // operand object as an alias or callable value.
        _ => &[],
    }
}

fn literal_string(value: &Value) -> Option<String> {
    value
        .get("value")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn expression_path(value: &Value) -> Option<String> {
    match node_kind(value)? {
        "Identifier" => identifier(value).map(ToString::to_string),
        "ThisExpression" => Some("this".to_string()),
        "MemberExpression" | "OptionalMemberExpression" => {
            let object = expression_path(value.get("object")?)?;
            let property = if value.get("computed").and_then(Value::as_bool) == Some(true) {
                literal_string(value.get("property")?)?
            } else {
                identifier(value.get("property")?)?.to_string()
            };
            Some(format!("{object}.{property}"))
        }
        "TSAsExpression"
        | "TSTypeAssertion"
        | "TSNonNullExpression"
        | "TSSatisfiesExpression"
        | "ChainExpression"
        | "ParenthesizedExpression" => expression_path(value.get("expression")?),
        _ => None,
    }
}

fn expression_base_path(value: &Value) -> Option<String> {
    let value = unwrap_expression(value);
    expression_path(value).or_else(|| {
        matches!(
            node_kind(value),
            Some("MemberExpression" | "OptionalMemberExpression")
        )
        .then(|| value.get("object").and_then(expression_base_path))
        .flatten()
    })
}

fn possible_alias_paths(value: &Value) -> Vec<String> {
    let value = unwrap_expression(value);
    if let Some(path) = expression_path(value) {
        return vec![path];
    }
    let mut paths = match node_kind(value) {
        Some("CallExpression")
            if value
                .get("callee")
                .map(unwrap_expression)
                .is_some_and(|callee| {
                    matches!(
                        node_kind(callee),
                        Some("MemberExpression" | "OptionalMemberExpression")
                    ) && static_member_name(callee) == Some("bind")
                        && value
                            .get("arguments")
                            .and_then(Value::as_array)
                            .is_some_and(|arguments| {
                                arguments.len() <= 1
                                    && arguments.iter().all(|argument| {
                                        node_kind(argument) != Some("SpreadElement")
                                    })
                            })
                }) =>
        {
            value
                .get("callee")
                .and_then(|callee| unwrap_expression(callee).get("object"))
                .map(|target| possible_alias_paths(target))
                .unwrap_or_default()
        }
        Some("AwaitExpression") => value
            .get("argument")
            .map(possible_alias_paths)
            .unwrap_or_default(),
        Some("ConditionalExpression") => ["consequent", "alternate"]
            .into_iter()
            .flat_map(|field| {
                value
                    .get(field)
                    .map(possible_alias_paths)
                    .unwrap_or_default()
            })
            .collect(),
        Some("LogicalExpression") => ["left", "right"]
            .into_iter()
            .flat_map(|field| {
                value
                    .get(field)
                    .map(possible_alias_paths)
                    .unwrap_or_default()
            })
            .collect(),
        Some("SequenceExpression") => value
            .get("expressions")
            .and_then(Value::as_array)
            .and_then(|expressions| expressions.last())
            .map(possible_alias_paths)
            .unwrap_or_default(),
        Some("AssignmentExpression") => assignment_result_fields(value)
            .iter()
            .flat_map(|field| {
                value
                    .get(*field)
                    .map(possible_alias_paths)
                    .unwrap_or_default()
            })
            .collect(),
        _ => Vec::new(),
    };
    paths.sort();
    paths.dedup();
    paths
}

fn callee_target(call: &Value) -> Option<&Value> {
    let callee = call.get("callee")?;
    matches!(
        node_kind(callee),
        Some("MemberExpression" | "OptionalMemberExpression")
    )
    .then(|| callee.get("object"))
    .flatten()
}

fn synchronously_invoked_function_spans(
    value: &Value,
    bindings: &BindingModel,
) -> Result<Vec<(u32, u32)>> {
    let mut spans = Vec::new();
    for (candidate, constructible_only) in
        synchronously_invoked_callable_expressions(value, bindings)?
    {
        let mut functions = Vec::new();
        bindings.collect_callable_result_function_nodes_with_bindings(
            candidate,
            constructible_only,
            &mut functions,
        )?;
        for function in functions {
            spans.push(node_span(&function)?);
        }
    }
    spans.sort_unstable();
    spans.dedup();
    Ok(spans)
}

fn synchronously_invoked_callable_expressions<'a>(
    value: &'a Value,
    bindings: &BindingModel,
) -> Result<Vec<(&'a Value, bool)>> {
    let mut candidates = Vec::new();
    let callee = value
        .get("callee")
        .context("call or construction expression has no callee")?;
    match node_kind(value) {
        Some("CallExpression") => {
            candidates.push((callee, false));

            let callee = unwrap_expression(callee);
            if matches!(
                node_kind(callee),
                Some("MemberExpression" | "OptionalMemberExpression")
            ) && matches!(static_member_name(callee), Some("call" | "apply"))
                && let Some(target) = callee.get("object")
            {
                candidates.push((target, false));
            }

            let resolved_callee = bindings.resolve_expression(callee);
            if resolved_callee
                .as_ref()
                .is_some_and(|resolved| resolved.global_state)
            {
                let arguments = value
                    .get("arguments")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                let possible_paths = &resolved_callee
                    .as_ref()
                    .expect("resolved global callee disappeared")
                    .possible_paths;
                if possible_paths.iter().any(|path| {
                    matches!(path.as_str(), "Reflect.apply" | "globalThis.Reflect.apply")
                }) && let Some(target) = arguments.first()
                {
                    candidates.push((target, false));
                }
                if possible_paths.iter().any(|path| {
                    matches!(
                        path.as_str(),
                        "Reflect.construct" | "globalThis.Reflect.construct"
                    )
                }) && let Some(target) = arguments.first()
                {
                    candidates.push((target, true));
                }
            }
        }
        Some("NewExpression") => {
            candidates.push((callee, true));
            if bindings.resolve_expression(callee).is_some_and(|resolved| {
                resolved.global_state
                    && resolved
                        .possible_paths
                        .iter()
                        .any(|path| matches!(path.as_str(), "Promise" | "globalThis.Promise"))
            }) && let Some(executor) = value
                .get("arguments")
                .and_then(Value::as_array)
                .and_then(|arguments| arguments.first())
            {
                candidates.push((executor, false));
            }
        }
        _ => {}
    }
    Ok(candidates)
}

fn collect_callable_return_values<'a>(
    callable: &'a Value,
    values: &mut Vec<&'a Value>,
) -> Result<()> {
    let body = callable
        .get("body")
        .context("callable has no body while resolving factory result")?;
    if node_kind(body) != Some("BlockStatement") {
        values.push(body);
        return Ok(());
    }
    fn visit<'a>(value: &'a Value, root: bool, values: &mut Vec<&'a Value>) {
        if !root
            && matches!(
                node_kind(value),
                Some("FunctionDeclaration" | "FunctionExpression" | "ArrowFunctionExpression")
            )
        {
            return;
        }
        if node_kind(value) == Some("ReturnStatement") {
            if let Some(argument) = value.get("argument").filter(|argument| !argument.is_null()) {
                values.push(argument);
            }
            return;
        }
        for child in ast_runtime_children(value) {
            visit(child, false, values);
        }
    }
    visit(body, true, values);
    Ok(())
}

fn collect_callable_result_function_nodes<'a>(
    value: &'a Value,
    constructible_only: bool,
    functions: &mut Vec<&'a Value>,
) -> Result<()> {
    let value = unwrap_expression(value);
    match node_kind(value) {
        Some("FunctionDeclaration" | "FunctionExpression") => functions.push(value),
        Some("ArrowFunctionExpression") if !constructible_only => functions.push(value),
        Some("AssignmentExpression") => {
            for field in assignment_result_fields(value) {
                if let Some(result) = value.get(*field) {
                    collect_callable_result_function_nodes(result, constructible_only, functions)?;
                }
            }
        }
        Some("AwaitExpression") => {
            if let Some(argument) = value.get("argument") {
                collect_callable_result_function_nodes(argument, constructible_only, functions)?;
            }
        }
        Some("ConditionalExpression") => {
            for field in ["consequent", "alternate"] {
                if let Some(branch) = value.get(field) {
                    collect_callable_result_function_nodes(branch, constructible_only, functions)?;
                }
            }
        }
        Some("LogicalExpression") => {
            for field in ["left", "right"] {
                if let Some(branch) = value.get(field) {
                    collect_callable_result_function_nodes(branch, constructible_only, functions)?;
                }
            }
        }
        Some("SequenceExpression") => {
            if let Some(result) = value
                .get("expressions")
                .and_then(Value::as_array)
                .and_then(|expressions| expressions.last())
            {
                collect_callable_result_function_nodes(result, constructible_only, functions)?;
            }
        }
        Some("CallExpression") => {
            let Some(callee) = value.get("callee").map(unwrap_expression) else {
                return Ok(());
            };
            if matches!(
                node_kind(callee),
                Some("MemberExpression" | "OptionalMemberExpression")
            ) && static_member_name(callee) == Some("bind")
                && let Some(target) = callee.get("object")
            {
                collect_callable_result_function_nodes(target, constructible_only, functions)?;
            }
        }
        Some("ClassExpression" | "ClassDeclaration") if constructible_only => {
            for function in class_constructor_functions(value)? {
                functions.push(function);
            }
        }
        _ => {}
    }
    Ok(())
}

fn synchronously_invoked_bound_functions<'a>(
    value: &'a Value,
    bindings: &'a BindingModel,
) -> Result<Vec<&'a Value>> {
    let mut functions = Vec::new();
    for (candidate, constructible_only) in
        synchronously_invoked_callable_expressions(value, bindings)?
    {
        if constructible_only {
            functions.extend(
                bindings
                    .resolve_constructible_values(candidate)
                    .into_iter()
                    .filter(|function| {
                        matches!(
                            node_kind(function),
                            Some("FunctionDeclaration" | "FunctionExpression")
                        )
                    }),
            );
        }
        collect_bound_callable_result_functions(
            candidate,
            constructible_only,
            bindings,
            &mut functions,
        )?;
    }

    let mut functions_by_span = BTreeMap::new();
    for function in functions {
        functions_by_span.insert(node_span(function)?, function);
    }
    Ok(functions_by_span.into_values().collect())
}

fn collect_bound_callable_result_functions<'a>(
    value: &'a Value,
    constructible_only: bool,
    bindings: &'a BindingModel,
    functions: &mut Vec<&'a Value>,
) -> Result<()> {
    let value = unwrap_expression(value);
    let resolved = bindings.resolve_callable_values(value);
    if !resolved.is_empty() {
        functions.extend(resolved.into_iter().filter(|function| {
            matches!(
                node_kind(function),
                Some("FunctionDeclaration" | "FunctionExpression")
            ) || (!constructible_only && node_kind(function) == Some("ArrowFunctionExpression"))
        }));
        return Ok(());
    }
    match node_kind(value) {
        Some("AssignmentExpression") => {
            for field in assignment_result_fields(value) {
                if let Some(result) = value.get(*field) {
                    collect_bound_callable_result_functions(
                        result,
                        constructible_only,
                        bindings,
                        functions,
                    )?;
                }
            }
        }
        Some("AwaitExpression") => {
            if let Some(argument) = value.get("argument") {
                collect_bound_callable_result_functions(
                    argument,
                    constructible_only,
                    bindings,
                    functions,
                )?;
            }
        }
        Some("ConditionalExpression") => {
            for field in ["consequent", "alternate"] {
                if let Some(branch) = value.get(field) {
                    collect_bound_callable_result_functions(
                        branch,
                        constructible_only,
                        bindings,
                        functions,
                    )?;
                }
            }
        }
        Some("LogicalExpression") => {
            for field in ["left", "right"] {
                if let Some(branch) = value.get(field) {
                    collect_bound_callable_result_functions(
                        branch,
                        constructible_only,
                        bindings,
                        functions,
                    )?;
                }
            }
        }
        Some("SequenceExpression") => {
            if let Some(result) = value
                .get("expressions")
                .and_then(Value::as_array)
                .and_then(|expressions| expressions.last())
            {
                collect_bound_callable_result_functions(
                    result,
                    constructible_only,
                    bindings,
                    functions,
                )?;
            }
        }
        Some("CallExpression") => {
            let Some(callee) = value.get("callee").map(unwrap_expression) else {
                return Ok(());
            };
            if matches!(
                node_kind(callee),
                Some("MemberExpression" | "OptionalMemberExpression")
            ) && static_member_name(callee) == Some("bind")
                && let Some(target) = callee.get("object")
            {
                collect_bound_callable_result_functions(
                    target,
                    constructible_only,
                    bindings,
                    functions,
                )?;
            }
        }
        Some("ClassExpression" | "ClassDeclaration") if constructible_only => {
            functions.extend(class_constructor_functions(value)?);
        }
        _ => {}
    }
    Ok(())
}

fn static_member_name(value: &Value) -> Option<&str> {
    let value = unwrap_expression(value);
    if !matches!(
        node_kind(value),
        Some("MemberExpression" | "OptionalMemberExpression")
    ) {
        return None;
    }
    let property = value.get("property")?;
    if value.get("computed").and_then(Value::as_bool) == Some(true) {
        property.get("value").and_then(Value::as_str)
    } else {
        identifier(property)
    }
}

fn is_timer(path: &str) -> bool {
    matches!(
        path,
        "setTimeout" | "setInterval" | "setImmediate" | "queueMicrotask" | "requestAnimationFrame"
    )
}

fn is_mutating_method(method: &str) -> bool {
    matches!(
        method,
        "set"
            | "add"
            | "append"
            | "compile"
            | "delete"
            | "clear"
            | "push"
            | "pop"
            | "shift"
            | "unshift"
            | "splice"
            | "sort"
            | "reverse"
            | "copyWithin"
            | "fill"
            | "setDate"
            | "setFullYear"
            | "setHours"
            | "setMilliseconds"
            | "setMinutes"
            | "setMonth"
            | "setSeconds"
            | "setTime"
            | "setUTCDate"
            | "setUTCFullYear"
            | "setUTCHours"
            | "setUTCMilliseconds"
            | "setUTCMinutes"
            | "setUTCMonth"
            | "setUTCSeconds"
            | "setYear"
            | "setBigInt64"
            | "setBigUint64"
            | "setFloat16"
            | "setFloat32"
            | "setFloat64"
            | "setInt8"
            | "setInt16"
            | "setInt32"
            | "setUint8"
            | "setUint16"
            | "setUint32"
            | "resize"
            | "grow"
            | "transfer"
            | "transferToFixedLength"
            | "store"
            | "exchange"
            | "compareExchange"
            | "sub"
            | "and"
            | "or"
            | "xor"
            | "__defineGetter__"
            | "__defineSetter__"
            | "call"
            | "apply"
    )
}

fn is_target_first_mutator(path: &str) -> bool {
    let path = path.strip_prefix("globalThis.").unwrap_or(path);
    matches!(
        path,
        "Object.assign"
            | "Object.defineProperties"
            | "Object.defineProperty"
            | "Object.freeze"
            | "Object.preventExtensions"
            | "Object.seal"
            | "Object.setPrototypeOf"
            | "Reflect.defineProperty"
            | "Reflect.deleteProperty"
            | "Reflect.set"
            | "Reflect.setPrototypeOf"
            | "Atomics.add"
            | "Atomics.and"
            | "Atomics.compareExchange"
            | "Atomics.exchange"
            | "Atomics.or"
            | "Atomics.store"
            | "Atomics.sub"
            | "Atomics.xor"
    )
}

fn resolves_to_target_first_mutator(resolved: &ResolvedStatePath) -> bool {
    resolved.global_state
        && resolved
            .possible_paths
            .iter()
            .any(|path| is_target_first_mutator(path))
}

fn is_mutable_initializer(value: &Value) -> bool {
    matches!(
        node_kind(value),
        Some("ArrayExpression" | "ObjectExpression" | "RegExpLiteral")
    ) || (node_kind(value) == Some("NewExpression")
        && value
            .get("callee")
            .and_then(expression_path)
            .is_some_and(|name| {
                matches!(
                    name.as_str(),
                    "Array"
                        | "ArrayBuffer"
                        | "Date"
                        | "Headers"
                        | "Map"
                        | "RegExp"
                        | "Set"
                        | "URLSearchParams"
                        | "WeakMap"
                        | "WeakSet"
                )
            }))
}

fn is_allowed_top_level_constructor(name: &str) -> bool {
    matches!(
        name,
        "AbortController"
            | "Date"
            | "Headers"
            | "Intl.Collator"
            | "Intl.DateTimeFormat"
            | "Intl.ListFormat"
            | "Intl.NumberFormat"
            | "Intl.PluralRules"
            | "Intl.RelativeTimeFormat"
            | "Map"
            | "RegExp"
            | "Request"
            | "Response"
            | "Set"
            | "TextDecoder"
            | "TextEncoder"
            | "URL"
            | "URLSearchParams"
            | "WeakMap"
            | "WeakSet"
    )
}

fn is_statement_anchor(kind: &str) -> bool {
    kind.ends_with("Statement")
        || matches!(
            kind,
            "VariableDeclaration"
                | "FunctionDeclaration"
                | "ClassDeclaration"
                | "MethodDefinition"
                | "PropertyDefinition"
                | "StaticBlock"
        )
}
