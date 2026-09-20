#![no_main]

mod effect_value_graph;

use convex_wasm_compiler_invariant_validation::{
    EFFECT_VALUE_CORRUPTION_COUNT, HarnessDependencyAdapter, HarnessEffectExecutionMode,
    HarnessImport, HarnessModule, HarnessOutput, compile_modules,
    compile_modules_with_dependency_adapters_in_effect_mode, exercise_effect_value_corruption,
    summarize_source,
};
use effect_value_graph::{
    DependencyAdapterImport, EFFECT_VALUE_GRAPH_SHAPE_COUNT, render_effect_value_graph_case,
    render_parameterized_effect_value_graph_case,
};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeSet,
    sync::{Mutex, OnceLock},
};

const ENTRY: &str = "convex/invariant_validation_entry.ts";
const HELPER: &str = "convex/invariant_validation_helper.ts";
const GENERATED_SERVER: &str = "convex/_generated/server.js";
const DEPENDENCY_ADAPTER_MODULE: &str = "node_modules/invariant-validation-dependency-adapter/adapter.js";
const GENERATED_SERVER_SOURCE: &str = r#"export const query = undefined;
export const mutation = undefined;
"#;
const DEPENDENCY_ADAPTER_SOURCE: &str = r#"export async function getOneFrom() {}
export async function getManyFrom() {}
"#;
const MAX_SOURCE_BYTES: usize = 16 * 1024;
const BASE_STRUCTURED_SEED_COUNT: usize = 22;
const DEPENDENCY_ADAPTER_SHAPE_COUNT: usize = 10;
const EFFECT_VALUE_GRAPH_SEED_START: usize =
    BASE_STRUCTURED_SEED_COUNT + DEPENDENCY_ADAPTER_SHAPE_COUNT;
const STRUCTURED_SEED_COUNT: usize = EFFECT_VALUE_GRAPH_SEED_START + EFFECT_VALUE_GRAPH_SHAPE_COUNT;
const SEMANTIC_FEATURE_REPORT_ENV: &str = "CONVEX_WASM_INVARIANT_VALIDATION_SEMANTIC_FEATURE_REPORT";

struct StructuredCase {
    modules: Vec<HarnessModule>,
    dependency_adapters: Vec<HarnessDependencyAdapter>,
    effect_execution_mode: HarnessEffectExecutionMode,
    must_fallback: bool,
    must_admit: bool,
    expected_operation_kinds: Option<Vec<&'static str>>,
    forbidden_operation_kinds: Vec<&'static str>,
    semantic_feature: String,
    guest_consumer_position: Option<GuestConsumerPosition>,
}

impl StructuredCase {
    fn semantic_dimensions(
        &self,
    ) -> (
        &str,
        bool,
        bool,
        Option<GuestConsumerPosition>,
        Option<&[&'static str]>,
    ) {
        (
            &self.semantic_feature,
            self.must_admit,
            self.must_fallback,
            self.guest_consumer_position,
            self.expected_operation_kinds.as_deref(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuestConsumerPosition {
    DirectAwait,
    PendingAwait,
    PendingThenAwait,
}

impl GuestConsumerPosition {
    fn from_index(index: usize) -> Self {
        match index % 3 {
            0 => Self::DirectAwait,
            1 => Self::PendingAwait,
            _ => Self::PendingThenAwait,
        }
    }

    fn semantic_name(self) -> &'static str {
        match self {
            Self::DirectAwait => "direct-await",
            Self::PendingAwait => "pending-await",
            Self::PendingThenAwait => "pending-then-await",
        }
    }
}

fn report_semantic_feature(feature: &str) {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    if !*ENABLED.get_or_init(|| {
        std::env::var(SEMANTIC_FEATURE_REPORT_ENV)
            .is_ok_and(|value| matches!(value.as_str(), "1" | "stderr"))
    }) {
        return;
    }
    static REPORTED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let mut reported = REPORTED
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .expect("semantic-feature report lock was poisoned");
    if reported.insert(feature.to_string()) {
        eprintln!("CONVEX_WASM_SEMANTIC_FEATURE\t{feature}");
    }
}

fn module(module_key: &str, source: String) -> HarnessModule {
    HarnessModule {
        module_key: module_key.to_string(),
        source,
        imports: Vec::new(),
    }
}

fn generated_server_module() -> HarnessModule {
    module(GENERATED_SERVER, GENERATED_SERVER_SOURCE.to_string())
}

fn generated_server_import() -> HarnessImport {
    HarnessImport {
        original: "./_generated/server".to_string(),
        resolved: GENERATED_SERVER.to_string(),
    }
}

fn dependency_adapter_module() -> HarnessModule {
    module(
        DEPENDENCY_ADAPTER_MODULE,
        DEPENDENCY_ADAPTER_SOURCE.to_string(),
    )
}

fn dependency_adapter_import() -> HarnessImport {
    HarnessImport {
        original: "invariant-validation-dependency-adapter".to_string(),
        resolved: DEPENDENCY_ADAPTER_MODULE.to_string(),
    }
}

fn dependency_adapter(export_name: &str, semantic_kind: &str) -> HarnessDependencyAdapter {
    HarnessDependencyAdapter {
        id: format!("invariantValidation{export_name}"),
        module_path: DEPENDENCY_ADAPTER_MODULE.to_string(),
        export_name: export_name.to_string(),
        semantic_kind: semantic_kind.to_string(),
    }
}

#[derive(Clone, Copy)]
enum DependencyAdapterShape {
    Alias,
    HelperReturn,
    CallArgument,
    ConditionalChoice,
    MappedCollection,
    OptionalDispatch,
    SpreadDispatch,
    WrittenAlias,
    EscapedAlias,
    RecursiveForward,
}

impl DependencyAdapterShape {
    fn from_index(index: usize) -> Self {
        match index % DEPENDENCY_ADAPTER_SHAPE_COUNT {
            0 => Self::Alias,
            1 => Self::HelperReturn,
            2 => Self::CallArgument,
            3 => Self::ConditionalChoice,
            4 => Self::MappedCollection,
            5 => Self::OptionalDispatch,
            6 => Self::SpreadDispatch,
            7 => Self::WrittenAlias,
            8 => Self::EscapedAlias,
            _ => Self::RecursiveForward,
        }
    }

    fn semantic_name(self) -> &'static str {
        match self {
            Self::Alias => "alias",
            Self::HelperReturn => "helper-return",
            Self::CallArgument => "call-argument",
            Self::ConditionalChoice => "conditional-choice",
            Self::MappedCollection => "mapped-collection",
            Self::OptionalDispatch => "optional-dispatch",
            Self::SpreadDispatch => "spread-dispatch",
            Self::WrittenAlias => "written-alias",
            Self::EscapedAlias => "escaped-alias",
            Self::RecursiveForward => "recursive-forward",
        }
    }
}

fn render_dependency_adapter_case(
    shape: DependencyAdapterShape,
    metamorph: bool,
) -> StructuredCase {
    let semantic_name = shape.semantic_name();
    let context = if metamorph { "requestContext" } else { "ctx" };
    let arguments = if metamorph { "requestArgs" } else { "args" };
    let pending = if metamorph {
        "operationPromise"
    } else {
        "pending"
    };
    let prefix = if metamorph {
        "/* dependency-adapter value-flow metamorph */\n"
    } else {
        ""
    };
    let (export_name, semantic_kind, declarations, body, must_admit, expected_operation_kinds) =
        match shape {
            DependencyAdapterShape::Alias => (
                "getOneFrom",
                "databaseIndexUnique",
                String::new(),
                format!(
                    "const initial = getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.owner);\n    const {pending} = initial;\n    return await {pending};"
                ),
                true,
                Some(vec!["databaseIndexQuery"]),
            ),
            DependencyAdapterShape::HelperReturn => {
                let helper = if metamorph { "loadRecord" } else { "loadOne" };
                let helper_context = if metamorph {
                    "forwardedContext"
                } else {
                    "helperContext"
                };
                let owner = if metamorph { "ownerValue" } else { "owner" };
                (
                    "getOneFrom",
                    "databaseIndexUnique",
                    format!(
                        "async function {helper}({helper_context}, {owner}) {{\n  return getOneFrom({helper_context}.db, \"items\", \"by_owner\", {owner});\n}}\n"
                    ),
                    format!("return await {helper}({context}, {arguments}.owner);"),
                    true,
                    Some(vec!["databaseIndexQuery"]),
                )
            }
            DependencyAdapterShape::CallArgument => {
                let helper = if metamorph { "awaitValue" } else { "consume" };
                let parameter = if metamorph { "operationValue" } else { "value" };
                (
                    "getOneFrom",
                    "databaseIndexUnique",
                    format!(
                        "async function {helper}({parameter}) {{\n  return await {parameter};\n}}\n"
                    ),
                    format!(
                        "return await {helper}(getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.owner));"
                    ),
                    true,
                    Some(vec!["databaseIndexQuery"]),
                )
            }
            DependencyAdapterShape::ConditionalChoice => (
                "getOneFrom",
                "databaseIndexUnique",
                String::new(),
                format!(
                    "const {pending} = {arguments}.first\n      ? getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.owner)\n      : getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.otherOwner);\n    return await {pending};"
                ),
                true,
                Some(vec!["databaseIndexQuery", "databaseIndexQuery"]),
            ),
            DependencyAdapterShape::MappedCollection => {
                let helper = if metamorph { "loadRecords" } else { "loadMany" };
                let helper_context = if metamorph {
                    "forwardedContext"
                } else {
                    "helperContext"
                };
                let owner = if metamorph { "ownerValue" } else { "owner" };
                let records = if metamorph { "documents" } else { "records" };
                (
                    "getManyFrom",
                    "databaseIndexCollect",
                    format!(
                        "async function {helper}({helper_context}, {owner}) {{\n  return getManyFrom({helper_context}.db, \"items\", \"by_owner\", {owner});\n}}\n"
                    ),
                    format!(
                        "const {records} = await {helper}({context}, {arguments}.owner);\n    return {records}.map((record) => record._id);"
                    ),
                    true,
                    Some(vec!["databaseIndexQuery"]),
                )
            }
            DependencyAdapterShape::OptionalDispatch => {
                let helper = if metamorph { "awaitValue" } else { "consume" };
                let parameter = if metamorph { "operationValue" } else { "value" };
                (
                    "getOneFrom",
                    "databaseIndexUnique",
                    format!(
                        "async function {helper}({parameter}) {{\n  return await {parameter};\n}}\n"
                    ),
                    format!(
                        "return await {helper}?.(getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.owner));"
                    ),
                    false,
                    None,
                )
            }
            DependencyAdapterShape::SpreadDispatch => {
                let helper = if metamorph { "awaitValue" } else { "consume" };
                let parameter = if metamorph { "operationValue" } else { "value" };
                (
                    "getOneFrom",
                    "databaseIndexUnique",
                    format!(
                        "async function {helper}({parameter}) {{\n  return await {parameter};\n}}\n"
                    ),
                    format!(
                        "return await {helper}(...[getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.owner)]);"
                    ),
                    false,
                    None,
                )
            }
            DependencyAdapterShape::WrittenAlias => (
                "getOneFrom",
                "databaseIndexUnique",
                String::new(),
                format!(
                    "let {pending} = getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.owner);\n    {pending} = {arguments}.replacement;\n    return await {pending};"
                ),
                false,
                None,
            ),
            DependencyAdapterShape::EscapedAlias => (
                "getOneFrom",
                "databaseIndexUnique",
                String::new(),
                format!(
                    "const {pending} = getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.owner);\n    void {pending};\n    return await {pending};"
                ),
                false,
                None,
            ),
            DependencyAdapterShape::RecursiveForward => {
                let helper = if metamorph { "forwardValue" } else { "forward" };
                let parameter = if metamorph { "operationValue" } else { "value" };
                (
                    "getOneFrom",
                    "databaseIndexUnique",
                    format!(
                        "function {helper}({parameter}, depth) {{\n  return depth === 0 ? {parameter} : {helper}({parameter}, depth - 1);\n}}\n"
                    ),
                    format!(
                        "return await {helper}(getOneFrom({context}.db, \"items\", \"by_owner\", {arguments}.owner), 1);"
                    ),
                    false,
                    None,
                )
            }
        };
    let source = format!(
        "{prefix}import {{ query }} from \"./_generated/server\";\nimport {{ {export_name} }} from \"invariant-validation-dependency-adapter\";\n{declarations}export const selected = query({{\n  args: {{}},\n  handler: async ({context}, {arguments}) => {{\n    {body}\n  }},\n}});\n"
    );
    StructuredCase {
        modules: vec![
            HarnessModule {
                module_key: ENTRY.to_string(),
                source,
                imports: vec![generated_server_import(), dependency_adapter_import()],
            },
            dependency_adapter_module(),
            generated_server_module(),
        ],
        dependency_adapters: vec![dependency_adapter(export_name, semantic_kind)],
        effect_execution_mode: HarnessEffectExecutionMode::BlockingFiber,
        must_fallback: !must_admit,
        must_admit,
        expected_operation_kinds,
        forbidden_operation_kinds: Vec::new(),
        semantic_feature: serde_json::json!({
            "authorityConsumer": "dependency-adapter",
            "callFactState": if must_admit { "exact" } else { "blocked" },
            "executionMode": "blocking-fiber",
            "expectedRouting": if must_admit { "admit" } else { "fallback" },
            "family": "retained-dependency-adapter",
            "helperDepth": "fixed",
            "origin": "dependency-adapter-call-result",
            "placement": "entry-local",
            "scc": if matches!(shape, DependencyAdapterShape::RecursiveForward) {
                "value-carrying"
            } else {
                "none"
            },
            "siblingConsumers": "fixed",
            "sinkUse": semantic_name,
            "stepTopology": semantic_name,
            "widthBoundary": "not-applicable",
        })
        .to_string(),
        guest_consumer_position: None,
    }
}

fn render_effect_value_graph_structured_case(index: usize, metamorph: bool) -> StructuredCase {
    let case = render_effect_value_graph_case(index, metamorph);
    structured_effect_value_graph_case(case)
}

fn render_parameterized_effect_value_graph_structured_case(
    data: &[u8],
    metamorph: bool,
) -> StructuredCase {
    let case = render_parameterized_effect_value_graph_case(data, metamorph);
    structured_effect_value_graph_case(case)
}

fn structured_effect_value_graph_case(
    case: effect_value_graph::EffectValueGraphCase,
) -> StructuredCase {
    assert!(
        case.source.len() <= MAX_SOURCE_BYTES,
        "generated effect/value entry exceeds {MAX_SOURCE_BYTES} bytes: {}",
        case.semantic_feature
    );
    assert!(
        case.imported_helper_source
            .as_ref()
            .is_none_or(|source| source.len() <= MAX_SOURCE_BYTES),
        "generated effect/value helper exceeds {MAX_SOURCE_BYTES} bytes: {}",
        case.semantic_feature
    );
    let mut entry_imports = vec![generated_server_import()];
    let mut modules = Vec::new();
    if case.dependency_adapter_import == DependencyAdapterImport::Entry {
        entry_imports.push(dependency_adapter_import());
    }
    if case.imported_helper_source.is_some() {
        entry_imports.push(HarnessImport {
            original: "./invariant_validation_graph_helper.js".to_string(),
            resolved: HELPER.to_string(),
        });
    }
    modules.push(HarnessModule {
        module_key: ENTRY.to_string(),
        source: case.source,
        imports: entry_imports,
    });
    if let Some(helper_source) = case.imported_helper_source {
        modules.push(HarnessModule {
            module_key: HELPER.to_string(),
            source: helper_source,
            imports: if case.dependency_adapter_import == DependencyAdapterImport::Helper {
                vec![dependency_adapter_import()]
            } else {
                Vec::new()
            },
        });
    }
    let dependency_adapters = if case.dependency_adapter_import == DependencyAdapterImport::None {
        Vec::new()
    } else {
        modules.push(dependency_adapter_module());
        vec![dependency_adapter("getOneFrom", "databaseIndexUnique")]
    };
    modules.push(generated_server_module());
    StructuredCase {
        modules,
        dependency_adapters,
        effect_execution_mode: if case.guest_mode {
            HarnessEffectExecutionMode::GuestPromiseEventLoop
        } else {
            HarnessEffectExecutionMode::BlockingFiber
        },
        must_fallback: case.must_fallback,
        must_admit: case.must_admit,
        expected_operation_kinds: case.expected_operation_kinds,
        forbidden_operation_kinds: Vec::new(),
        semantic_feature: case.semantic_feature,
        guest_consumer_position: None,
    }
}

fn render_seed_case(index: usize, metamorph: bool) -> StructuredCase {
    let index = index % STRUCTURED_SEED_COUNT;
    if index >= EFFECT_VALUE_GRAPH_SEED_START {
        return render_effect_value_graph_structured_case(
            index - EFFECT_VALUE_GRAPH_SEED_START,
            metamorph,
        );
    }
    if index >= BASE_STRUCTURED_SEED_COUNT {
        return render_dependency_adapter_case(
            DependencyAdapterShape::from_index(index - BASE_STRUCTURED_SEED_COUNT),
            metamorph,
        );
    }
    let context = if metamorph { "context" } else { "ctx" };
    let arguments = if metamorph { "request" } else { "args" };
    let prefix = if metamorph {
        "type InvariantValidationTransparent = unknown;\n/* semantic-preserving invariant-validation variant */\n"
    } else {
        ""
    };
    let expression = |value: &str| {
        if metamorph {
            format!("(({value}) as InvariantValidationTransparent as typeof {value})")
        } else {
            value.to_string()
        }
    };
    let (body, must_fallback, forbidden_operation_kinds) = match index % STRUCTURED_SEED_COUNT {
        0 => (
            format!("return {};", expression(&format!("{arguments}.value"))),
            false,
            Vec::new(),
        ),
        1 => (
            format!(
                "const local = (value: string) => value.trim();\nreturn local({});",
                expression(&format!("{arguments}.value"))
            ),
            false,
            Vec::new(),
        ),
        2 => (
            format!(
                "const {{ value: renamed = \"fallback\" }} = {arguments};\nreturn (renamed satisfies string)!;"
            ),
            false,
            Vec::new(),
        ),
        3 => (
            format!("return await {context}.db?.get(\"items\", {arguments}.id);"),
            true,
            Vec::new(),
        ),
        4 => {
            let order = if metamorph { ".order(\"asc\")" } else { "" };
            (
                format!(
                    "return await ({context}.db.query(\"items\")).withIndex(\"by_owner\", (index) => (index.eq(\"owner\", {arguments}.owner))){order}.unique();"
                ),
                false,
                Vec::new(),
            )
        }
        5 => (
            format!(
                "await {context}.db.patch(\"items\", {arguments}.id, {{ state: \"done\" }});\nreturn null;"
            ),
            false,
            Vec::new(),
        ),
        6 => (
            format!(
                "await {context}.scheduler.runAfter(0, {arguments}.target, {{ id: {arguments}.id }});\nreturn null;"
            ),
            true,
            Vec::new(),
        ),
        7 => (
            format!(
                "return await Promise.all({arguments}.ids.map((id: string) => {context}.db.get(\"items\", id)));"
            ),
            false,
            Vec::new(),
        ),
        8 => ("return Date.now();".to_string(), false, Vec::new()),
        9 => (
            "sharedCounter += 1;\nreturn sharedCounter;".to_string(),
            true,
            Vec::new(),
        ),
        10 => ("return 1;".to_string(), true, Vec::new()),
        11 => (
            "return Promise.all([1, 2, 3]);".to_string(),
            true,
            vec!["databaseGet", "databaseIndexQuery", "databasePatch"],
        ),
        12 => (
            format!(
                "const database = {context}.db;\nreturn await database.get(\"items\", {arguments}.id);"
            ),
            true,
            Vec::new(),
        ),
        13 => (
            format!(
                "const {{ db: database }} = {context};\nreturn await database.get(\"items\", {arguments}.id);"
            ),
            true,
            Vec::new(),
        ),
        14 => (
            format!(
                "const value = ({arguments}.value as unknown as {{ nested?: string }});\nreturn value?.nested ?? \"none\";"
            ),
            false,
            Vec::new(),
        ),
        15 => {
            let helper_parameter = if metamorph { "input" } else { "value" };
            let helper_source = format!(
                "export function normalize({helper_parameter}: string) {{\n  return {helper_parameter}.trim();\n}}\n"
            );
            let entry_source = format!(
                "{prefix}import {{ query }} from \"./_generated/server\";\nimport {{ normalize }} from \"./invariant_validation_helper.js\";\nexport const selected = query({{\n  args: {{}},\n  handler: async ({context}, {arguments}) => {{\n    return normalize({});\n  }},\n}});\n",
                expression(&format!("{arguments}.value"))
            );
            return StructuredCase {
                modules: vec![
                    HarnessModule {
                        module_key: ENTRY.to_string(),
                        source: entry_source,
                        imports: vec![
                            generated_server_import(),
                            HarnessImport {
                                original: "./invariant_validation_helper.js".to_string(),
                                resolved: HELPER.to_string(),
                            },
                        ],
                    },
                    module(HELPER, helper_source),
                    generated_server_module(),
                ],
                dependency_adapters: Vec::new(),
                effect_execution_mode: HarnessEffectExecutionMode::BlockingFiber,
                must_fallback: false,
                must_admit: true,
                expected_operation_kinds: None,
                forbidden_operation_kinds: Vec::new(),
                semantic_feature: serde_json::json!({
                    "authorityConsumer": "retained-structured-contract",
                    "callFactState": "exact",
                    "executionMode": "blocking-fiber",
                    "expectedRouting": "admit",
                    "family": "retained-structured",
                    "helperDepth": "1",
                    "origin": "ordinary-value",
                    "placement": "imported",
                    "scc": "none",
                    "seedIndex": 15,
                    "siblingConsumers": "none",
                    "sinkUse": "return",
                    "stepTopology": "imported-helper",
                    "widthBoundary": "not-applicable",
                })
                .to_string(),
                guest_consumer_position: None,
            };
        }
        16 => (
            format!(
                "const привет = {arguments}.value ?? \"🙂\";\nreturn {{ ключ: привет, 終: \"é\" }};"
            ),
            false,
            Vec::new(),
        ),
        17 => (
            format!(
                "async function child(childContext: typeof {context}, id: string) {{\n  const first = await childContext.db.get(\"items\", id);\n  return await childContext.db.get(\"items\", first._id);\n}}\nreturn await Promise.all({arguments}.ids.map((id: string) => child({context}, id)));"
            ),
            true,
            Vec::new(),
        ),
        18 => (
            format!(
                "await {context}.db.patch(\"items\", {arguments}.id, {{ state: \"done\" }});\nawait {context}.db.delete(\"items\", {arguments}.otherId);\nreturn null;"
            ),
            false,
            Vec::new(),
        ),
        19 => (
            format!(
                "return {{ maximum: Math.max(1, Number({arguments}.value)), encoded: JSON.stringify([{arguments}.value]), present: new Set([{arguments}.value]).has({arguments}.value) }};"
            ),
            false,
            Vec::new(),
        ),
        20 => (
            format!("return await load({context}, \"items\", {arguments}.id);"),
            false,
            Vec::new(),
        ),
        _ => (
            format!(
                "return await Promise.all({arguments}.ids.map(async (id) => {{\n  const first = await {context}.db.get(\"items\", id);\n  return await {context}.db.get(\"items\", first._id);\n}}));"
            ),
            true,
            Vec::new(),
        ),
    };
    let declarations = match index % STRUCTURED_SEED_COUNT {
        9 => "let sharedCounter = 0;\n",
        10 => "const query = (definition: unknown) => definition;\n",
        11 => "const Promise = { all: (values: unknown[]) => values };\n",
        20 => {
            "async function load(effectContext, table, id) { return await effectContext.db.get(table, id); }\n"
        }
        _ => "",
    };
    let builder = if matches!(index % STRUCTURED_SEED_COUNT, 5 | 18) {
        "mutation"
    } else {
        "query"
    };
    let shadowed_registration = index % STRUCTURED_SEED_COUNT == 10;
    let registration_import = if shadowed_registration {
        String::new()
    } else {
        format!("import {{ {builder} }} from \"./_generated/server\";\n")
    };
    let mut modules = vec![HarnessModule {
        module_key: ENTRY.to_string(),
        source: format!(
            "{prefix}{registration_import}{declarations}export const selected = {builder}({{\n  args: {},\n  handler: async ({context}, {arguments}) => {{\n    {body}\n  }},\n}});\n",
            if matches!(index % STRUCTURED_SEED_COUNT, 7 | 21) {
                "{ ids: v.array(v.id(\"items\")) }"
            } else {
                "{}"
            },
        ),
        imports: if shadowed_registration {
            Vec::new()
        } else {
            vec![generated_server_import()]
        },
    }];
    if !shadowed_registration {
        modules.push(generated_server_module());
    }
    StructuredCase {
        modules,
        dependency_adapters: Vec::new(),
        effect_execution_mode: if matches!(index % STRUCTURED_SEED_COUNT, 20 | 21) {
            HarnessEffectExecutionMode::GuestPromiseEventLoop
        } else {
            HarnessEffectExecutionMode::BlockingFiber
        },
        must_fallback,
        must_admit: matches!(
            index % STRUCTURED_SEED_COUNT,
            0 | 1 | 2 | 4 | 5 | 7 | 8 | 14 | 16 | 18 | 19 | 20
        ),
        expected_operation_kinds: None,
        forbidden_operation_kinds,
        semantic_feature: serde_json::json!({
            "authorityConsumer": "retained-structured-contract",
            "callFactState": "fixed",
            "executionMode": if matches!(index % STRUCTURED_SEED_COUNT, 20 | 21) {
                "guest-promise-event-loop"
            } else {
                "blocking-fiber"
            },
            "expectedRouting": if must_fallback { "fallback" } else { "admit-or-probe" },
            "family": "retained-structured",
            "helperDepth": "fixed",
            "origin": "fixed",
            "placement": "fixed",
            "scc": "fixed",
            "seedIndex": index % STRUCTURED_SEED_COUNT,
            "siblingConsumers": "fixed",
            "sinkUse": "fixed",
            "stepTopology": "fixed",
            "widthBoundary": "fixed",
        })
        .to_string(),
        guest_consumer_position: None,
    }
}

fn render_guest_admission_case(index: usize, metamorph: bool) -> StructuredCase {
    let context = if metamorph { "requestContext" } else { "ctx" };
    let arguments = if metamorph { "requestArgs" } else { "args" };
    let (declarations, body, must_admit, expected_operation_kinds, feature) = match index % 5 {
        0 => {
            let load = if metamorph {
                "loadGuestDocument"
            } else {
                "loadDocument"
            };
            let document = if metamorph {
                "loadedDocument"
            } else {
                "document"
            };
            (
                format!(
                    "async function {load}(helperContext, table, id) {{\n  return await helperContext.db.get(table, id);\n}}\n"
                ),
                format!(
                    "const {document} = await {load}({context}, \"items\", {arguments}.id);\n    {load}({context}, \"items\", {arguments}.otherId);\n    return {document};"
                ),
                false,
                None,
                serde_json::json!({
                    "authorityConsumer": "guest-effect-site-closure",
                    "callFactState": "exact-plus-unawaited-inbound",
                    "executionMode": "guest-promise-event-loop",
                    "expectedRouting": "fallback",
                    "family": "retained-guest-admission",
                    "helperDepth": "1",
                    "origin": "database-effect",
                    "placement": "local-helper",
                    "scc": "none",
                    "siblingConsumers": "mixed-static-inbound",
                    "sinkUse": "await-plus-drop",
                    "stepTopology": "activation-root",
                    "widthBoundary": "not-applicable",
                })
                .to_string(),
            )
        }
        1 => {
            let pending = if metamorph {
                "operationPromise"
            } else {
                "pending"
            };
            (
                String::new(),
                format!(
                    "const {pending} = {context}.db.get(\"items\", {arguments}.id);\n    try {{\n      return {pending};\n    }} finally {{\n      return null;\n    }}"
                ),
                false,
                None,
                serde_json::json!({
                    "authorityConsumer": "guest-effect-site-closure",
                    "callFactState": "exact",
                    "executionMode": "guest-promise-event-loop",
                    "expectedRouting": "fallback",
                    "family": "retained-guest-admission",
                    "helperDepth": "0",
                    "origin": "database-effect",
                    "placement": "entry-direct",
                    "scc": "none",
                    "siblingConsumers": "none",
                    "sinkUse": "return-overridden-by-finally",
                    "stepTopology": "alias-return-finalize",
                    "widthBoundary": "not-applicable",
                })
                .to_string(),
            )
        }
        2 => {
            let load = if metamorph {
                "loadGuestDocument"
            } else {
                "loadDocument"
            };
            (
                format!(
                    "function {load}(helperContext, id) {{\n  return helperContext.db.get(\"items\", id);\n}}\n"
                ),
                format!(
                    "try {{\n      return {load}({context}, {arguments}.id);\n    }} finally {{\n      return null;\n    }}"
                ),
                false,
                None,
                serde_json::json!({
                    "authorityConsumer": "guest-effect-site-closure",
                    "callFactState": "exact-tail-return",
                    "executionMode": "guest-promise-event-loop",
                    "expectedRouting": "fallback",
                    "family": "retained-guest-admission",
                    "helperDepth": "1",
                    "origin": "database-effect",
                    "placement": "local-helper",
                    "scc": "none",
                    "siblingConsumers": "exact-tail-return",
                    "sinkUse": "return-overridden-by-finally",
                    "stepTopology": "tail-return-finalize",
                    "widthBoundary": "not-applicable",
                })
                .to_string(),
            )
        }
        3 => {
            let load = if metamorph {
                "loadGuestPair"
            } else {
                "loadPair"
            };
            let first = if metamorph { "firstDocument" } else { "first" };
            let second = if metamorph {
                "secondDocument"
            } else {
                "second"
            };
            (
                format!(
                    "async function {load}(helperContext, table, firstId, secondId) {{\n  const {first} = await helperContext.db.get(table, firstId);\n  const {second} = await helperContext.db.get(table, secondId);\n  return [{first}, {second}];\n}}\n"
                ),
                format!(
                    "return await {load}({context}, \"items\", {arguments}.firstId, {arguments}.secondId);"
                ),
                true,
                Some(vec!["databaseGet", "databaseGet"]),
                serde_json::json!({
                    "authorityConsumer": "guest-effect-site-closure",
                    "callFactState": "exact",
                    "executionMode": "guest-promise-event-loop",
                    "expectedRouting": "admit",
                    "family": "retained-guest-admission",
                    "helperDepth": "1",
                    "origin": "database-effect",
                    "placement": "local-helper",
                    "scc": "none",
                    "siblingConsumers": "one-exact-inbound",
                    "sinkUse": "await",
                    "stepTopology": "dynamic-table-multiple-effects",
                    "widthBoundary": "not-applicable",
                })
                .to_string(),
            )
        }
        _ => {
            let load = if metamorph {
                "loadGuestDocument"
            } else {
                "loadDocument"
            };
            let pending = if metamorph {
                "operationPromise"
            } else {
                "pending"
            };
            (
                format!(
                    "async function {load}(helperContext, table, id) {{\n  return await helperContext.db.get(table, id);\n}}\n"
                ),
                format!(
                    "const {pending} = {load}({context}, \"items\", {arguments}.id);\n    return await {pending};"
                ),
                false,
                None,
                serde_json::json!({
                    "authorityConsumer": "guest-effect-site-closure",
                    "callFactState": "exact",
                    "executionMode": "guest-promise-event-loop",
                    "expectedRouting": "fallback",
                    "family": "retained-guest-admission",
                    "helperDepth": "1",
                    "origin": "database-effect",
                    "placement": "local-helper",
                    "scc": "none",
                    "siblingConsumers": "one-exact-inbound",
                    "sinkUse": "same-block-pending-await",
                    "stepTopology": "unresolved-intra-block-order",
                    "widthBoundary": "not-applicable",
                })
                .to_string(),
            )
        }
    };
    StructuredCase {
        modules: vec![
            HarnessModule {
                module_key: ENTRY.to_string(),
                source: format!(
                    "import {{ query }} from \"./_generated/server\";\n{declarations}export const selected = query({{\n  args: {{}},\n  handler: async ({context}, {arguments}) => {{\n    {body}\n  }},\n}});\n"
                ),
                imports: vec![generated_server_import()],
            },
            generated_server_module(),
        ],
        dependency_adapters: Vec::new(),
        effect_execution_mode: HarnessEffectExecutionMode::GuestPromiseEventLoop,
        must_fallback: !must_admit,
        must_admit,
        expected_operation_kinds,
        forbidden_operation_kinds: Vec::new(),
        semantic_feature: feature,
        guest_consumer_position: None,
    }
}

struct ByteCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn choose(&mut self, alternatives: usize) -> usize {
        assert!(alternatives > 0);
        let value = self
            .data
            .get(self.offset)
            .copied()
            .unwrap_or_else(|| (self.offset as u8).wrapping_mul(73).wrapping_add(41));
        self.offset += 1;
        value as usize % alternatives
    }

    fn flag(&mut self) -> bool {
        self.choose(2) == 1
    }
}

#[derive(Clone, Copy)]
enum ContextShape {
    Direct,
    Alias,
    Destructure,
}

#[derive(Clone, Copy)]
enum HelperShape {
    Direct,
    Local,
    Imported,
}

#[derive(Clone, Copy)]
enum EffectShape {
    Pure,
    Get,
    SequentialHelperGet,
    GuestHelperGet,
    Index,
    Patch,
    Sequential,
    MappedBatch,
    FixedBatch,
    NestedSuspension,
    GuestNestedSuspension,
    GlobalMutation,
    DeterministicGlobal,
}

#[derive(Clone, Copy)]
enum ShadowShape {
    None,
    Promise,
    Registration,
}

fn render_generated_case(data: &[u8], metamorph: bool) -> StructuredCase {
    let mut cursor = ByteCursor::new(data);
    match cursor.choose(3) {
        1 => {
            return render_dependency_adapter_case(
                DependencyAdapterShape::from_index(cursor.choose(DEPENDENCY_ADAPTER_SHAPE_COUNT)),
                metamorph,
            );
        }
        2 => {
            return render_parameterized_effect_value_graph_structured_case(
                data.get(1..).unwrap_or_default(),
                metamorph,
            );
        }
        _ => {}
    }
    let mutation = cursor.flag();
    let context_shape_index = cursor.choose(3);
    let context_shape = match context_shape_index {
        0 => ContextShape::Direct,
        1 => ContextShape::Alias,
        _ => ContextShape::Destructure,
    };
    let helper_shape_index = cursor.choose(3);
    let helper_shape = match helper_shape_index {
        0 => HelperShape::Direct,
        1 => HelperShape::Local,
        _ => HelperShape::Imported,
    };
    let effect_index = cursor.choose(13);
    let effect = match effect_index {
        0 => EffectShape::Pure,
        1 => EffectShape::Get,
        2 => EffectShape::SequentialHelperGet,
        3 => EffectShape::GuestHelperGet,
        4 => EffectShape::Index,
        5 => EffectShape::Patch,
        6 => EffectShape::Sequential,
        7 => EffectShape::MappedBatch,
        8 => EffectShape::FixedBatch,
        9 => EffectShape::NestedSuspension,
        10 => EffectShape::GuestNestedSuspension,
        11 => EffectShape::GlobalMutation,
        _ => EffectShape::DeterministicGlobal,
    };
    let consumer_position = cursor.choose(3);
    let shadow_index = cursor.choose(3);
    let shadow = match shadow_index {
        0 => ShadowShape::None,
        1 => ShadowShape::Promise,
        _ => ShadowShape::Registration,
    };
    let optional_effect = cursor.flag();
    let type_wrappers = cursor.flag();
    let value_shape = cursor.choose(3);
    let unique_index_terminal = cursor.flag();
    let index_terminal = if unique_index_terminal {
        "unique"
    } else {
        "collect"
    };

    let context = if metamorph { "requestContext" } else { "ctx" };
    let arguments = if metamorph { "requestArgs" } else { "args" };
    let helper = if metamorph { "projectValue" } else { "project" };
    let prefix = if metamorph {
        "/* invariant-validation metamorph: whitespace and comments are semantically inert */\n\n"
    } else {
        ""
    };
    let mut declarations = String::new();
    if matches!(effect, EffectShape::GlobalMutation) {
        declarations.push_str("let retainedValue = 0;\n");
    }
    match shadow {
        ShadowShape::Promise => {
            declarations.push_str("const Promise = { all: (values: unknown[]) => values };\n")
        }
        ShadowShape::Registration => declarations.push_str(&format!(
            "const {} = (definition: unknown) => definition;\n",
            if mutation { "mutation" } else { "query" }
        )),
        ShadowShape::None => {}
    }

    let mut imports = Vec::new();
    let mut modules = Vec::new();
    if !matches!(shadow, ShadowShape::Registration) {
        imports.push(generated_server_import());
        declarations.push_str(&format!(
            "import {{ {} }} from \"./_generated/server\";\n",
            if mutation { "mutation" } else { "query" }
        ));
        modules.push(generated_server_module());
    }
    match (effect, helper_shape) {
        (EffectShape::SequentialHelperGet | EffectShape::GuestHelperGet, HelperShape::Direct) => {}
        (EffectShape::SequentialHelperGet | EffectShape::GuestHelperGet, HelperShape::Local) => declarations.push_str(&format!(
            "async function {helper}(helperContext, table, id) {{\n  const document = await helperContext.db.get(table, id);\n  if (!document) throw new Error(`Missing ${{table}} document`);\n  return document;\n}}\n"
        )),
        (EffectShape::SequentialHelperGet | EffectShape::GuestHelperGet, HelperShape::Imported) => {
            imports.push(HarnessImport {
                original: "./invariant_validation_helper.js".to_string(),
                resolved: HELPER.to_string(),
            });
            declarations.push_str(&format!(
                "import {{ {helper} }} from \"./invariant_validation_helper.js\";\n"
            ));
            modules.push(module(
                HELPER,
                format!(
                    "export async function {helper}(helperContext, table, id) {{\n  const document = await helperContext.db.get(table, id);\n  if (!document) throw new Error(`Missing ${{table}} document`);\n  return document;\n}}\n"
                ),
            ));
        }
        (_, HelperShape::Direct) => {}
        (_, HelperShape::Local) => declarations.push_str(&format!(
            "function {helper}(value: unknown) {{ return value; }}\n"
        )),
        (_, HelperShape::Imported) => {
            imports.push(HarnessImport {
                original: "./invariant_validation_helper.js".to_string(),
                resolved: HELPER.to_string(),
            });
            declarations.push_str(&format!(
                "import {{ {helper} }} from \"./invariant_validation_helper.js\";\n"
            ));
            modules.push(module(
                HELPER,
                format!("export function {helper}(value: unknown) {{ return value; }}\n"),
            ));
        }
    }
    let context_setup = match context_shape {
        ContextShape::Direct => String::new(),
        ContextShape::Alias => format!("const database = {context}.db;\n"),
        ContextShape::Destructure => format!("const {{ db: database }} = {context};\n"),
    };
    let database = match context_shape {
        ContextShape::Direct => format!("{context}.db"),
        ContextShape::Alias | ContextShape::Destructure => "database".to_string(),
    };
    let guest_consumer_position = if matches!(effect, EffectShape::GuestHelperGet)
        && matches!(helper_shape, HelperShape::Local | HelperShape::Imported)
    {
        Some(GuestConsumerPosition::from_index(consumer_position))
    } else {
        None
    };
    let argument = |field: &str| {
        let value = format!("{arguments}.{field}");
        let value = if type_wrappers || metamorph {
            format!("(({value}) as unknown as typeof {value})")
        } else {
            value
        };
        match (effect, helper_shape) {
            (EffectShape::SequentialHelperGet | EffectShape::GuestHelperGet, _)
            | (_, HelperShape::Direct) => value,
            (_, HelperShape::Local | HelperShape::Imported) => format!("{helper}({value})"),
        }
    };
    let value = argument("value");
    let pure_value = match value_shape {
        0 => value.clone(),
        1 => format!("{{ value: {value} }}"),
        _ => format!("[{value}, {value}]"),
    };
    let body = match effect {
        EffectShape::Pure => format!("return {pure_value};"),
        EffectShape::Get => {
            if optional_effect {
                format!(
                    "return await {database}?.get(\"items\", {});",
                    argument("id")
                )
            } else {
                format!(
                    "return await {database}.get(\"items\", {});",
                    argument("id")
                )
            }
        }
        EffectShape::SequentialHelperGet => match helper_shape {
            HelperShape::Direct => format!(
                "return await {database}.get(\"items\", {});",
                argument("id")
            ),
            HelperShape::Local | HelperShape::Imported => {
                let forwarded_context = if matches!(context_shape, ContextShape::Direct) {
                    context.to_string()
                } else {
                    format!("{{ db: {database} }}")
                };
                let forwarded_context = if optional_effect {
                    format!("await {forwarded_context}")
                } else {
                    forwarded_context
                };
                format!(
                    "const document = await {helper}({forwarded_context}, \"items\", {});\nreturn document.label;",
                    argument("id")
                )
            }
        },
        EffectShape::GuestHelperGet => match helper_shape {
            HelperShape::Direct => format!(
                "return await {database}.get(\"items\", {});",
                argument("id")
            ),
            HelperShape::Local | HelperShape::Imported => {
                let forwarded_context = if matches!(context_shape, ContextShape::Direct) {
                    context.to_string()
                } else {
                    format!("{{ db: {database} }}")
                };
                let forwarded_context = if optional_effect {
                    format!("await {forwarded_context}")
                } else {
                    forwarded_context
                };
                let call = format!(
                    "{helper}({forwarded_context}, \"items\", {})",
                    argument("id")
                );
                match guest_consumer_position
                    .expect("guest helper call has no consumer-position dimension")
                {
                    GuestConsumerPosition::DirectAwait => format!("return await {call};"),
                    GuestConsumerPosition::PendingAwait => {
                        format!("const pending = {call};\nreturn await pending;")
                    }
                    GuestConsumerPosition::PendingThenAwait => format!(
                        "const pending = {call};\nconst document = await pending;\nreturn document;"
                    ),
                }
            }
        },
        EffectShape::Index => {
            let order = if metamorph { ".order(\"asc\")" } else { "" };
            format!(
                "return await {database}.query(\"items\").withIndex(\"by_owner\", (builder) => builder.eq(\"owner\", {})){order}.{index_terminal}();",
                argument("owner")
            )
        }
        EffectShape::Patch => format!(
            "await {database}.patch(\"items\", {}, {{ state: \"done\" }});\nreturn null;",
            argument("id")
        ),
        EffectShape::Sequential => format!(
            "await {database}.patch(\"items\", {}, {{ state: \"done\" }});\nawait {database}.delete(\"items\", {});\nreturn null;",
            argument("id"),
            argument("otherId")
        ),
        EffectShape::MappedBatch => format!(
            "return await Promise.all({arguments}.ids.map((itemId: string) => {database}.get(\"items\", itemId)));"
        ),
        EffectShape::FixedBatch => format!(
            "return await Promise.all([{database}.get(\"items\", {}), {database}.get(\"items\", {})]);",
            argument("firstId"),
            argument("secondId")
        ),
        EffectShape::NestedSuspension => format!(
            "async function nested(childDatabase: typeof {database}, itemId: string) {{\n  const first = await childDatabase.get(\"items\", itemId);\n  return await childDatabase.get(\"items\", first._id);\n}}\nreturn await Promise.all({arguments}.ids.map((itemId: string) => nested({database}, itemId)));"
        ),
        EffectShape::GuestNestedSuspension => format!(
            "return await Promise.all({arguments}.ids.map(async (itemId: string) => {{\n  const first = await {database}.get(\"items\", itemId);\n  return await {database}.get(\"items\", first._id);\n}}));"
        ),
        EffectShape::GlobalMutation => "retainedValue += 1;\nreturn retainedValue;".to_string(),
        EffectShape::DeterministicGlobal => match value_shape {
            0 => format!("return Math.max(1, Number({value}));"),
            1 => format!("return JSON.stringify({{ value: String({value}) }});"),
            _ => format!("return new Set([String({value})]).has(String({value}));"),
        },
    };
    let effect_uses_database = matches!(
        effect,
        EffectShape::Get
            | EffectShape::SequentialHelperGet
            | EffectShape::GuestHelperGet
            | EffectShape::Index
            | EffectShape::Patch
            | EffectShape::Sequential
            | EffectShape::MappedBatch
            | EffectShape::FixedBatch
            | EffectShape::NestedSuspension
            | EffectShape::GuestNestedSuspension
    );
    let guest_helper_uses_pending_alias = matches!(effect, EffectShape::GuestHelperGet)
        && guest_consumer_position
            .is_some_and(|position| position != GuestConsumerPosition::DirectAwait);
    let must_fallback = matches!(
        effect,
        EffectShape::NestedSuspension
            | EffectShape::GuestNestedSuspension
            | EffectShape::GlobalMutation
    ) || matches!(shadow, ShadowShape::Registration)
        || (!mutation && matches!(effect, EffectShape::Patch | EffectShape::Sequential))
        || (matches!(shadow, ShadowShape::Promise)
            && matches!(effect, EffectShape::MappedBatch | EffectShape::FixedBatch))
        || (optional_effect
            && (matches!(effect, EffectShape::Get)
                || (matches!(
                    effect,
                    EffectShape::SequentialHelperGet | EffectShape::GuestHelperGet
                ) && !matches!(helper_shape, HelperShape::Direct))))
        || guest_helper_uses_pending_alias
        || (!matches!(context_shape, ContextShape::Direct) && effect_uses_database);
    let shadow_is_admissible = matches!(shadow, ShadowShape::None);
    let must_admit = !must_fallback
        && matches!(context_shape, ContextShape::Direct)
        && (matches!(helper_shape, HelperShape::Direct)
            || matches!(
                effect,
                EffectShape::SequentialHelperGet | EffectShape::GuestHelperGet
            ))
        && shadow_is_admissible;
    let expected_operation_kinds = must_admit.then(|| match effect {
        EffectShape::Pure | EffectShape::DeterministicGlobal => Vec::new(),
        EffectShape::Get
        | EffectShape::SequentialHelperGet
        | EffectShape::GuestHelperGet
        | EffectShape::MappedBatch => {
            vec!["databaseGet"]
        }
        EffectShape::FixedBatch => {
            vec!["databaseGet", "databaseGet"]
        }
        EffectShape::Index => vec!["databaseIndexQuery"],
        EffectShape::Patch => vec!["databasePatch"],
        EffectShape::Sequential => vec!["databasePatch", "databaseDelete"],
        EffectShape::NestedSuspension
        | EffectShape::GuestNestedSuspension
        | EffectShape::GlobalMutation => {
            unreachable!("fallback effect cannot require an admitted operation oracle")
        }
    });
    let helper_is_used = matches!(
        effect,
        EffectShape::Pure
            | EffectShape::Get
            | EffectShape::SequentialHelperGet
            | EffectShape::GuestHelperGet
            | EffectShape::Index
            | EffectShape::Patch
            | EffectShape::Sequential
            | EffectShape::FixedBatch
            | EffectShape::DeterministicGlobal
    );
    let optional_effect_is_used = matches!(effect, EffectShape::Get)
        || (matches!(
            effect,
            EffectShape::SequentialHelperGet | EffectShape::GuestHelperGet
        ) && !matches!(helper_shape, HelperShape::Direct));
    let type_wrappers_are_used = helper_is_used;
    let consumer_position_feature = guest_consumer_position.map_or_else(
        || serde_json::json!("not-applicable"),
        |position| serde_json::json!(position.semantic_name()),
    );
    let helper_shape_feature = if helper_is_used {
        match helper_shape {
            HelperShape::Direct => "direct",
            HelperShape::Local => "local",
            HelperShape::Imported => "imported",
        }
    } else {
        "not-applicable"
    };
    let helper_depth_feature = if helper_is_used {
        if matches!(helper_shape, HelperShape::Direct) {
            "0"
        } else {
            "1"
        }
    } else {
        "not-applicable"
    };
    let placement_feature = if helper_is_used {
        match helper_shape {
            HelperShape::Direct => "entry-direct",
            HelperShape::Local => "local-helper",
            HelperShape::Imported => "imported-helper",
        }
    } else {
        "not-applicable"
    };
    let call_fact_state_feature = if matches!(shadow, ShadowShape::Registration) {
        match (optional_effect_is_used, optional_effect) {
            (true, true) => "shadowed-registration+optional",
            _ => "shadowed-registration",
        }
    } else if optional_effect_is_used {
        if optional_effect { "optional" } else { "exact" }
    } else {
        "not-applicable"
    };
    let index_terminal_feature = if matches!(effect, EffectShape::Index) {
        serde_json::json!(if unique_index_terminal {
            "unique"
        } else {
            "collect"
        })
    } else {
        serde_json::json!("not-applicable")
    };
    let type_wrappers_feature = if type_wrappers_are_used {
        serde_json::json!(type_wrappers)
    } else {
        serde_json::json!("not-applicable")
    };
    let value_shape_feature =
        if matches!(effect, EffectShape::Pure | EffectShape::DeterministicGlobal) {
            serde_json::json!(value_shape)
        } else {
            serde_json::json!("not-applicable")
        };
    let validators = match effect {
        EffectShape::MappedBatch
        | EffectShape::NestedSuspension
        | EffectShape::GuestNestedSuspension => "{ ids: v.array(v.id(\"items\")) }",
        EffectShape::FixedBatch => "{ firstId: v.id(\"items\"), secondId: v.id(\"items\") }",
        _ => "{}",
    };

    let entry_source = format!(
        "{prefix}{declarations}export const selected = {}({{\n  args: {validators},\n  handler: async ({context}, {arguments}) => {{\n    {context_setup}{body}\n  }},\n}});\n",
        if mutation { "mutation" } else { "query" },
    );
    modules.insert(
        0,
        HarnessModule {
            module_key: ENTRY.to_string(),
            source: entry_source,
            imports,
        },
    );
    StructuredCase {
        modules,
        dependency_adapters: Vec::new(),
        effect_execution_mode: if matches!(
            effect,
            EffectShape::GuestHelperGet | EffectShape::GuestNestedSuspension
        ) {
            HarnessEffectExecutionMode::GuestPromiseEventLoop
        } else {
            HarnessEffectExecutionMode::BlockingFiber
        },
        must_fallback,
        must_admit,
        expected_operation_kinds,
        forbidden_operation_kinds: if matches!(shadow, ShadowShape::Promise)
            && matches!(effect, EffectShape::Pure | EffectShape::DeterministicGlobal)
        {
            vec!["databaseGet", "databaseIndexQuery", "databasePatch"]
        } else {
            Vec::new()
        },
        semantic_feature: serde_json::json!({
            "authorityConsumer": if matches!(
                effect,
                EffectShape::MappedBatch | EffectShape::FixedBatch
            ) {
                "direct-batch"
            } else if matches!(
                effect,
                EffectShape::GuestHelperGet | EffectShape::GuestNestedSuspension
            ) {
                "plan-owned-effect-site"
            } else {
                "ordinary-effect-or-value"
            },
            "callFactState": call_fact_state_feature,
            "consumerPosition": consumer_position_feature,
            "contextShape": context_shape_index,
            "effectShape": effect_index,
            "executionMode": if matches!(
                effect,
                EffectShape::GuestHelperGet | EffectShape::GuestNestedSuspension
            ) {
                "guest-promise-event-loop"
            } else {
                "blocking-fiber"
            },
            "expectedRouting": if must_fallback {
                "fallback"
            } else if must_admit {
                "admit"
            } else {
                "probe"
            },
            "family": "parameterized-general",
            "helperDepth": helper_depth_feature,
            "helperShape": helper_shape_feature,
            "indexTerminal": index_terminal_feature,
            "mutationRegistration": mutation,
            "origin": if effect_uses_database { "database-effect" } else { "ordinary-value" },
            "placement": placement_feature,
            "scc": if matches!(effect, EffectShape::NestedSuspension) {
                "nested-suspension"
            } else {
                "none"
            },
            "shadowShape": shadow_index,
            "siblingConsumers": "not-modeled",
            "sinkUse": consumer_position_feature,
            "stepTopology": effect_index,
            "typeWrappers": type_wrappers_feature,
            "valueShape": value_shape_feature,
            "widthBoundary": if matches!(effect, EffectShape::FixedBatch) {
                "fixed-width:2"
            } else {
                "not-applicable"
            },
        })
        .to_string(),
        guest_consumer_position,
    }
}

fn assert_guest_consumer_position_metamorph_matrix() {
    static CHECKED: OnceLock<()> = OnceLock::new();
    CHECKED.get_or_init(|| {
        for consumer_position in 0..3 {
            // selector, mutation, context, helper, effect, consumer, shadow, optional, wrappers
            let data = [0, 0, 0, 1, 3, consumer_position, 0, 0, 0];
            let base = render_generated_case(&data, false);
            let metamorph = render_generated_case(&data, true);
            assert_eq!(
                base.semantic_dimensions(),
                metamorph.semantic_dimensions(),
                "guest consumer-position metamorph changed its semantic dimensions for position {consumer_position}"
            );
        }
    });
}

fn assert_case(index: &str, case: &StructuredCase, output: &HarnessOutput) {
    if case.must_fallback {
        assert!(
            !output.eligible(),
            "structured case {index} failed open\nmodules: {:#?}\nprojection: {}",
            case.modules,
            output.semantic_projection
        );
    }
    if case.must_admit {
        assert!(
            output.eligible(),
            "structured case {index} regressed to fallback\nmodules: {:#?}\nprojection: {}",
            case.modules,
            output.semantic_projection
        );
    }
    if let Some(expected) = &case.expected_operation_kinds {
        let operations = output.compiler_output["operations"]
            .as_array()
            .expect("compiler output operations must be an array");
        let actual = operations
            .iter()
            .map(|operation| {
                operation["kind"]
                    .as_str()
                    .expect("compiler operation kind must be a string")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            &actual, expected,
            "structured case {index} operation kinds disagree with the generated-source oracle"
        );
        for operation in operations {
            if operation["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("database"))
            {
                assert_eq!(
                    operation["table"], "items",
                    "structured case {index} database table disagrees with the generated-source oracle"
                );
            }
        }
    }
    for kind in &case.forbidden_operation_kinds {
        assert!(
            output
                .compiler_output
                .get("operations")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|operations| operations
                    .iter()
                    .all(|operation| operation["kind"] != *kind)),
            "structured case {index} admitted a shadowed {kind} operation"
        );
    }
    if case.effect_execution_mode == HarnessEffectExecutionMode::GuestPromiseEventLoop
        && output.eligible()
    {
        let operations = output.compiler_output["operations"]
            .as_array()
            .expect("guest compiler output operations must be an array");
        let direct_operation_count = operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation["kind"].as_str(),
                    Some(
                        "databaseGet"
                            | "databaseInsert"
                            | "databasePatch"
                            | "databaseReplace"
                            | "databaseDelete"
                            | "schedulerRunAfter"
                            | "schedulerRunAt"
                    )
                )
            })
            .count();
        if direct_operation_count > 0 {
            let generated = output
                .generated_source()
                .expect("eligible guest direct-effect case has no generated source");
            assert_eq!(
                generated.matches("function __convexEffectSite_").count(),
                direct_operation_count,
                "structured case {index} did not consume every authorized guest target exactly once\n{generated}"
            );
            assert_eq!(
                generated
                    .matches("return __convexStartAsyncOperation(")
                    .count(),
                direct_operation_count,
                "structured case {index} did not bind every guest operation descriptor to one exact site branch\n{generated}"
            );
            assert!(
                !generated.contains(".db.get(")
                    && !generated.contains(".db.insert(")
                    && !generated.contains(".db.patch(")
                    && !generated.contains(".db.replace(")
                    && !generated.contains(".db.delete(")
                    && !generated.contains(".scheduler.runAfter(")
                    && !generated.contains(".scheduler.runAt("),
                "structured case {index} retained an admitted raw guest effect call\n{generated}"
            );
        }
    }
}

fn compile_case(index: &str, case: &StructuredCase) -> HarnessOutput {
    let output = compile_modules_with_dependency_adapters_in_effect_mode(
        &case.modules,
        ENTRY,
        "selected",
        &case.dependency_adapters,
        case.effect_execution_mode,
    )
    .unwrap_or_else(|error| panic!("structured compiler case {index} failed: {error}"));
    assert_case(index, case, &output);
    output
}

fn metamorphic_projection(output: &HarnessOutput) -> serde_json::Value {
    let mut projection = output.semantic_projection.clone();
    if let Some(diagnostics) = projection
        .get_mut("diagnostics")
        .and_then(serde_json::Value::as_array_mut)
    {
        for diagnostic in diagnostics {
            let Some(chain) = diagnostic
                .get_mut("dependencyChain")
                .and_then(serde_json::Value::as_array_mut)
            else {
                continue;
            };
            for unit in chain {
                let Some(spelled) = unit.as_str() else {
                    continue;
                };
                if (spelled.starts_with(&format!("{ENTRY}#"))
                    || spelled.starts_with(&format!("{HELPER}#")))
                    && let Some(canonical) = output.callable_labels.get(spelled)
                {
                    // Metamorphs preserve unit order while renaming local callables. Canonical
                    // ordinals still detect a dependency chain that selects a different local
                    // callable in the same module.
                    *unit = serde_json::Value::String(canonical.clone());
                }
            }
        }
    }
    let Some(operations) = projection
        .get_mut("operations")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return projection;
    };
    for operation in operations {
        let Some(constraints) = operation
            .get_mut("indexConstraints")
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };
        for constraint in constraints {
            // valueSource intentionally preserves source spelling, while these variants rename
            // bindings and add transparent wrappers. Field and operator still compare exactly.
            constraint
                .as_object_mut()
                .expect("projected index constraint must be an object")
                .remove("valueSource");
        }
    }
    projection
}

fn exercise_case(label: &str, base: StructuredCase, metamorph: StructuredCase) {
    assert_eq!(
        base.semantic_dimensions(),
        metamorph.semantic_dimensions(),
        "metamorph changed semantic dimensions before compiler execution for structured case {label}"
    );
    report_semantic_feature(&base.semantic_feature);
    let first = compile_case(label, &base);
    let repeated = compile_case(label, &base);
    assert_eq!(
        first.normalized_output, repeated.normalized_output,
        "compiler output is nondeterministic for structured case {label}"
    );
    assert_eq!(first.entry_summary, repeated.entry_summary);
    assert_eq!(first.context_reuse_summary, repeated.context_reuse_summary);
    assert_eq!(
        first.context_reuse_hard_rules,
        repeated.context_reuse_hard_rules
    );
    assert_eq!(
        first.context_reuse_loaded_hard_rules,
        repeated.context_reuse_loaded_hard_rules
    );

    let variant = compile_case(label, &metamorph);
    assert_eq!(
        metamorphic_projection(&first),
        metamorphic_projection(&variant),
        "semantic-preserving whitespace/comment/rename/type/index variant changed admission semantics for structured case {label}"
    );
}

fuzz_target!(|data: &[u8]| {
    assert_guest_consumer_position_metamorph_matrix();
    if data.len() > MAX_SOURCE_BYTES {
        return;
    }
    if let Some(source) = data.strip_prefix(b"// invariant-validation:raw\n") {
        report_semantic_feature(
            &serde_json::json!({
                "authorityConsumer": "raw-summary",
                "callFactState": "source-derived",
                "executionMode": "blocking-fiber",
                "expectedRouting": "probe",
                "family": "raw-typescript",
                "helperDepth": "unbounded-source",
                "origin": "raw-source",
                "placement": "entry",
                "scc": "source-derived",
                "siblingConsumers": "source-derived",
                "sinkUse": "source-derived",
                "stepTopology": "source-derived",
                "widthBoundary": "source-derived",
            })
            .to_string(),
        );
        let Ok(source) = std::str::from_utf8(source) else {
            return;
        };
        let first = summarize_source(ENTRY, source);
        let second = summarize_source(ENTRY, source);
        assert_eq!(first, second, "module summary result is nondeterministic");
        if first.is_ok() && source.contains("export const selected") && !source.contains("import ")
        {
            let modules = [module(ENTRY, source.to_string())];
            let first = compile_modules(&modules, ENTRY, "selected");
            let second = compile_modules(&modules, ENTRY, "selected");
            match (first, second) {
                (Ok(first), Ok(second)) => {
                    assert_eq!(first.normalized_output, second.normalized_output);
                    assert_eq!(first.entry_summary, second.entry_summary);
                    assert_eq!(first.context_reuse_summary, second.context_reuse_summary);
                    assert_eq!(
                        first.context_reuse_hard_rules,
                        second.context_reuse_hard_rules
                    );
                    assert_eq!(
                        first.context_reuse_loaded_hard_rules,
                        second.context_reuse_loaded_hard_rules
                    );
                }
                (Err(first), Err(second)) => assert_eq!(first, second),
                (first, second) => {
                    panic!("compiler result is nondeterministic: {first:?} != {second:?}")
                }
            }
        }
        return;
    }

    if let Ok(text) = std::str::from_utf8(data)
        && let Some(value) = text.strip_prefix("relation:")
        && let Ok(index) = value.trim().parse::<usize>()
    {
        report_semantic_feature(
            &serde_json::json!({
                "authorityConsumer": "relation-authentication",
                "callFactState": "corrupted",
                "corruptionSelector": index % EFFECT_VALUE_CORRUPTION_COUNT,
                "executionMode": "blocking-fiber",
                "expectedRouting": "authentication-rejection",
                "family": "retained-relation-corruption",
                "helperDepth": "fixed",
                "origin": "serialized-effect-value-fact",
                "placement": "entry",
                "scc": "fixed",
                "siblingConsumers": "fixed",
                "sinkUse": "fixed",
                "stepTopology": "fixed",
                "widthBoundary": "not-applicable",
            })
            .to_string(),
        );
        exercise_effect_value_corruption(index).unwrap_or_else(|error| {
            panic!("effect/value relation corruption case {index} failed: {error}")
        });
        return;
    }

    if let Ok(text) = std::str::from_utf8(data)
        && let Some(value) = text.strip_prefix("guest-admission:")
        && let Ok(index) = value.trim().parse::<usize>()
    {
        exercise_case(
            &format!("guest-admission-{index}"),
            render_guest_admission_case(index, false),
            render_guest_admission_case(index, true),
        );
        return;
    }

    if let Ok(text) = std::str::from_utf8(data)
        && let Some(value) = text.strip_prefix("structured:")
        && let Ok(index) = value.trim().parse::<usize>()
    {
        exercise_case(
            &format!("seed-{index}"),
            render_seed_case(index, false),
            render_seed_case(index, true),
        );
        return;
    }

    if data
        .first()
        .is_some_and(|selector| selector & 0b1111 == 0b1111)
    {
        let selector =
            data.get(1).copied().unwrap_or_default() as usize % EFFECT_VALUE_CORRUPTION_COUNT;
        report_semantic_feature(
            &serde_json::json!({
                "authorityConsumer": "relation-authentication",
                "callFactState": "corrupted",
                "corruptionSelector": selector,
                "executionMode": "blocking-fiber",
                "expectedRouting": "authentication-rejection",
                "family": "generated-relation-corruption",
                "helperDepth": "fixed",
                "origin": "serialized-effect-value-fact",
                "placement": "entry",
                "scc": "fixed",
                "siblingConsumers": "fixed",
                "sinkUse": "fixed",
                "stepTopology": "fixed",
                "widthBoundary": "not-applicable",
            })
            .to_string(),
        );
        exercise_effect_value_corruption(selector).unwrap_or_else(|error| {
            panic!("generated effect/value relation corruption case {selector} failed: {error}")
        });
        return;
    }

    let base = render_generated_case(data, false);
    let label = format!("generated:{}", base.semantic_feature);
    exercise_case(&label, base, render_generated_case(data, true));
});
