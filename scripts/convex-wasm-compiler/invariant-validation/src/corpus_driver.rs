use std::{collections::BTreeSet, env, fs, path::PathBuf};

use convex_wasm_compiler_invariant_validation::{
    HarnessDependencyAdapter, HarnessEffectExecutionMode, HarnessImport, HarnessModule,
    HarnessSourceOperation, compile_modules, compile_modules_in_effect_mode,
    compile_modules_with_dependency_adapters, compile_modules_with_source_operations,
};
use serde_json::{Value, json};

const EXPECTATION_FIELDS: &[&str] = &[
    "contextReuseHardRules",
    "diagnosticCodes",
    "diagnostics",
    "documentProperties",
    "eligible",
    "forbiddenOperations",
    "loadedContextReuseHardRules",
    "operations",
];
const GENERATED_SERVER: &str = "convex/_generated/server.js";
const GENERATED_API: &str = "convex/_generated/api.js";
const CONVEX_SERVER: &str = "node_modules/convex/dist/esm/server/index.js";
const DEPENDENCY_ADAPTER_MODULE: &str = "node_modules/invariant-validation-dependency-adapter/adapter.js";
const GENERATED_SERVER_SOURCE: &str = r#"export const query = undefined;
export const mutation = undefined;
"#;
const GENERATED_API_SOURCE: &str = r#"import { anyApi } from "convex/server";
export const api = anyApi;
export const internal = anyApi;
"#;

fn string_array(value: &Value, description: &str) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{description} must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{description}[{index}] must be a string"))
        })
        .collect()
}

fn validate_expectation(
    name: &str,
    expectation: &Value,
    compiled: &convex_wasm_compiler_invariant_validation::HarnessOutput,
) -> Result<(), String> {
    let object = expectation
        .as_object()
        .ok_or_else(|| format!("{name}: expectation must be an object"))?;
    let allowed = EXPECTATION_FIELDS.iter().copied().collect::<BTreeSet<_>>();
    for field in object.keys() {
        if !allowed.contains(field.as_str()) {
            return Err(format!("{name}: unknown expectation field {field}"));
        }
    }
    let expected_eligible = object
        .get("eligible")
        .ok_or_else(|| format!("{name}: expectation must contain eligible"))?
        .as_bool()
        .ok_or_else(|| format!("{name}: eligible must be Boolean"))?;
    if compiled.eligible() != expected_eligible {
        return Err(format!(
            "{name}: expected eligible={expected_eligible}, got {} ({})",
            compiled.eligible(),
            compiled.semantic_projection
        ));
    }
    let expected_operations = object
        .get("operations")
        .ok_or_else(|| format!("{name}: expectation must contain operations"))?;
    if !expected_operations.is_array() {
        return Err(format!("{name}: operations must be an array"));
    }
    let actual_operations_value = &compiled.semantic_projection["operations"];
    if actual_operations_value != expected_operations {
        return Err(format!(
            "{name}: operation projection differs\nexpected: {expected_operations}\nactual:   {actual_operations_value}"
        ));
    }
    if let Some(expected) = object.get("documentProperties")
        && &compiled.compiler_output["documentProperties"] != expected
    {
        return Err(format!(
            "{name}: document properties differ\nexpected: {expected}\nactual:   {}",
            compiled.compiler_output["documentProperties"]
        ));
    }
    if !expected_eligible
        && !object.contains_key("diagnosticCodes")
        && !object.contains_key("diagnostics")
    {
        return Err(format!(
            "{name}: ineligible expectation must contain exact diagnosticCodes or diagnostics; actual projection: {}",
            compiled.semantic_projection
        ));
    }
    let actual_operations = compiled.semantic_projection["operations"]
        .as_array()
        .ok_or_else(|| format!("{name}: compiler operation projection is not an array"))?;
    if let Some(forbidden) = object.get("forbiddenOperations") {
        for kind in string_array(forbidden, &format!("{name}: forbiddenOperations"))? {
            if actual_operations
                .iter()
                .any(|operation| operation["kind"] == kind)
            {
                return Err(format!(
                    "{name}: compiler emitted forbidden operation {kind}"
                ));
            }
        }
    }
    if let Some(expected) = object.get("diagnosticCodes") {
        let expected = string_array(expected, &format!("{name}: diagnosticCodes"))?;
        let actual = string_array(
            &compiled.semantic_projection["diagnosticCodes"],
            &format!("{name}: compiler diagnosticCodes"),
        )?;
        if actual != expected {
            return Err(format!(
                "{name}: diagnostic codes differ\nexpected: {expected:?}\nactual:   {actual:?}"
            ));
        }
    }
    if let Some(expected) = object.get("diagnostics")
        && &compiled.semantic_projection["diagnostics"] != expected
    {
        return Err(format!(
            "{name}: diagnostics differ\nexpected: {expected}\nactual:   {}",
            compiled.semantic_projection["diagnostics"]
        ));
    }
    if let Some(expected) = object.get("contextReuseHardRules") {
        let expected = string_array(expected, &format!("{name}: contextReuseHardRules"))?;
        if compiled.context_reuse_hard_rules != expected {
            return Err(format!(
                "{name}: context-reuse hard rules differ\nexpected: {expected:?}\nactual:   {:?}",
                compiled.context_reuse_hard_rules
            ));
        }
    }
    if let Some(expected) = object.get("loadedContextReuseHardRules") {
        let expected = string_array(expected, &format!("{name}: loadedContextReuseHardRules"))?;
        if compiled.context_reuse_loaded_hard_rules != expected {
            return Err(format!(
                "{name}: loaded context-reuse hard rules differ\nexpected: {expected:?}\nactual:   {:?}",
                compiled.context_reuse_loaded_hard_rules
            ));
        }
    }
    Ok(())
}

fn source_operation(
    id: &str,
    helper_module: &str,
    helper_export: &str,
    mismatch_error: &str,
) -> HarnessSourceOperation {
    HarnessSourceOperation {
        id: id.to_string(),
        helper_module: helper_module.to_string(),
        helper_export: helper_export.to_string(),
        selector: "INVARIANT_VALIDATION_SECRET".to_string(),
        missing_configuration_error: "INVARIANT_VALIDATION_SECRET is not set".to_string(),
        mismatch_error: mismatch_error.to_string(),
    }
}

fn validate_source_operation_identity() -> Result<convex_wasm_compiler_invariant_validation::HarnessOutput, String>
{
    const ENTRY: &str = "convex/source_operation.ts";
    const HELPER: &str = "convex/source_operation_helper.ts";
    const UNUSED: &str = "convex/unused_source_operation_helper.ts";
    let modules = vec![
        HarnessModule {
            module_key: ENTRY.to_string(),
            source: r#"import { query } from "./_generated/server";
import { requireSecret } from "./source_operation_helper.js";
export const selected = query({
  args: {},
  handler: async (_ctx, args) => {
    requireSecret(args.secret);
    return "accepted";
  },
});
"#
            .to_string(),
            imports: vec![
                HarnessImport {
                    original: "./_generated/server".to_string(),
                    resolved: GENERATED_SERVER.to_string(),
                },
                HarnessImport {
                    original: "./source_operation_helper.js".to_string(),
                    resolved: HELPER.to_string(),
                },
            ],
        },
        HarnessModule {
            module_key: GENERATED_SERVER.to_string(),
            source: GENERATED_SERVER_SOURCE.to_string(),
            imports: Vec::new(),
        },
        HarnessModule {
            module_key: HELPER.to_string(),
            source: r#"export function requireSecret(provided: string | undefined): void {
  const configured = process.env.INVARIANT_VALIDATION_SECRET;
  if (!configured) throw new Error("INVARIANT_VALIDATION_SECRET is not set");
  if (!provided || provided !== configured) throw new Error("Unauthorized");
}
"#
            .to_string(),
            imports: Vec::new(),
        },
        HarnessModule {
            module_key: UNUSED.to_string(),
            source: "export function unusedSecret(_provided: string): void {}\n".to_string(),
            imports: Vec::new(),
        },
    ];
    let baseline_descriptor = source_operation(
        "requireInvariantValidationSecret",
        HELPER,
        "requireSecret",
        "Unauthorized",
    );
    let baseline = compile_modules_with_source_operations(
        &modules,
        ENTRY,
        "selected",
        std::slice::from_ref(&baseline_descriptor),
    )?;
    if !baseline.eligible() {
        return Err(format!(
            "source-operation identity baseline was not admitted: {}",
            baseline.semantic_projection
        ));
    }
    let mut changed_descriptor = baseline_descriptor.clone();
    changed_descriptor.mismatch_error = "Access denied".to_string();
    let changed =
        compile_modules_with_source_operations(&modules, ENTRY, "selected", &[changed_descriptor])?;
    for field in ["exportFingerprint", "sourceGraphFingerprint"] {
        if baseline.compiler_output[field] == changed.compiler_output[field] {
            return Err(format!(
                "applied source-operation semantic drift did not invalidate {field}"
            ));
        }
    }
    if baseline.generated_source() == changed.generated_source() {
        return Err(
            "applied source-operation semantic drift did not invalidate generated source".into(),
        );
    }
    if baseline.compiler_output["operations"][0]["stableKey"]
        != changed.compiler_output["operations"][0]["stableKey"]
    {
        return Err("guest developer-error text changed the stable host operation contract".into());
    }

    let unused_descriptor = source_operation(
        "unusedInvariantValidationSecret",
        UNUSED,
        "unusedSecret",
        "Unused mismatch",
    );
    let with_unused = compile_modules_with_source_operations(
        &modules,
        ENTRY,
        "selected",
        &[baseline_descriptor, unused_descriptor],
    )?;
    for field in ["exportFingerprint", "sourceGraphFingerprint"] {
        if baseline.compiler_output[field] != with_unused.compiler_output[field] {
            return Err(format!(
                "unused source-operation descriptor changed {field}"
            ));
        }
    }
    if baseline.generated_source() != with_unused.generated_source() {
        return Err("unused source-operation descriptor changed generated source".into());
    }
    Ok(baseline)
}

fn compile_structured_lowering_cases()
-> Result<Vec<(String, convex_wasm_compiler_invariant_validation::HarnessOutput)>, String> {
    let cases = [
        (
            "structured-scheduler",
            r#"import { mutation } from "./_generated/server";
import { api } from "./_generated/api.js";
export const selected = mutation({
  args: {},
  handler: async (ctx, args) => {
    await ctx.scheduler.runAfter(args.delay, api.jobs.cleanup, { id: args.id });
    return null;
  },
});
"#,
            true,
            HarnessEffectExecutionMode::BlockingFiber,
            None,
            true,
        ),
        (
            "structured-mapped-batch",
            r#"import { query } from "./_generated/server";
export const selected = query({
  args: { ids: v.array(v.id("items")) },
  handler: async (ctx, args) =>
    await Promise.all(args.ids.map((id) => ctx.db.get("items", id))),
});
"#,
            false,
            HarnessEffectExecutionMode::BlockingFiber,
            None,
            true,
        ),
        (
            "structured-fixed-batch",
            r#"import { query } from "./_generated/server";
export const selected = query({
  args: {},
  handler: async (ctx, args) => await Promise.all([
    ctx.db.get("items", args.firstId),
    ctx.db.get("items", args.secondId),
  ]),
});
"#,
            false,
            HarnessEffectExecutionMode::BlockingFiber,
            None,
            true,
        ),
        (
            "structured-guest-effectful-promise-all",
            r#"import { query } from "./_generated/server";
async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
export const selected = query({
  args: {},
  handler: async (ctx, args) => await Promise.all([
    load(ctx, "documents", args.firstId),
    load(ctx, "accounts", args.secondId),
  ]),
});
"#,
            false,
            HarnessEffectExecutionMode::GuestPromiseEventLoop,
            None,
            true,
        ),
        (
            "structured-guest-sequential-effect-site",
            r#"import { query } from "./_generated/server";
function load(ctx, id) {
  return ctx.db.get("documents", id);
}
export const selected = query({
  args: {},
  handler: async (ctx, args) => await load(ctx, args.id),
});
"#,
            false,
            HarnessEffectExecutionMode::GuestPromiseEventLoop,
            Some(1),
            true,
        ),
    ];
    cases
        .into_iter()
        .map(|(
            name,
            source,
            needs_generated_api,
            effect_execution_mode,
            expected_effect_site_count,
            must_admit,
        )| {
            let mut imports = vec![HarnessImport {
                original: "./_generated/server".to_string(),
                resolved: GENERATED_SERVER.to_string(),
            }];
            let mut modules = vec![HarnessModule {
                module_key: format!("convex/{name}.ts"),
                source: source.to_string(),
                imports: Vec::new(),
            }];
            if needs_generated_api {
                imports.push(HarnessImport {
                    original: "./_generated/api.js".to_string(),
                    resolved: GENERATED_API.to_string(),
                });
                modules.push(HarnessModule {
                    module_key: GENERATED_API.to_string(),
                    source: GENERATED_API_SOURCE.to_string(),
                    imports: vec![HarnessImport {
                        original: "convex/server".to_string(),
                        resolved: CONVEX_SERVER.to_string(),
                    }],
                });
                modules.push(HarnessModule {
                    module_key: CONVEX_SERVER.to_string(),
                    source: "export const anyApi = undefined;\n".to_string(),
                    imports: Vec::new(),
                });
            }
            modules[0].imports = imports;
            modules.push(HarnessModule {
                module_key: GENERATED_SERVER.to_string(),
                source: GENERATED_SERVER_SOURCE.to_string(),
                imports: Vec::new(),
            });
            let entry = format!("convex/{name}.ts");
            let compiled = compile_modules_in_effect_mode(
                &modules,
                &entry,
                "selected",
                effect_execution_mode,
            )?;
            if compiled.eligible() != must_admit {
                return Err(format!(
                    "{name}: expected eligible={must_admit}, got {}: {}",
                    compiled.eligible(),
                    compiled.semantic_projection
                ));
            }
            if !must_admit {
                let diagnostic_codes = compiled.semantic_projection["diagnosticCodes"]
                    .as_array()
                    .ok_or_else(|| format!("{name}: fallback case has no diagnostic code array"))?;
                if !diagnostic_codes.iter().any(|code| {
                    code.as_str() == Some("unsupported-convex-effect")
                }) {
                    return Err(format!(
                        "{name}: effectful guest fallback has no effect rejection: {}",
                        compiled.semantic_projection
                    ));
                }
                if compiled
                    .generated_source()
                    .is_some_and(|generated| generated.contains("__convexStartAsyncOperation("))
                {
                    return Err(format!(
                        "{name}: rejected guest effect was lowered"
                    ));
                }
            }
            if let Some(expected_effect_site_count) = expected_effect_site_count {
                let generated = compiled
                    .generated_source()
                    .ok_or_else(|| format!("{name}: guest case has no generated source"))?;
                let expected_operation_start_count = compiled.compiler_output["operations"]
                    .as_array()
                    .ok_or_else(|| format!("{name}: guest case has no operation array"))?
                    .len();
                if generated.matches("function __convexEffectSite_").count()
                    != expected_effect_site_count
                    || generated
                        .matches("return __convexStartAsyncOperation(")
                        .count()
                        != expected_operation_start_count
                    || generated.contains("ctx.db.get")
                {
                    return Err(format!(
                        "{name}: guest effect-site lowering lost exact target ownership\n{generated}"
                    ));
                }
            }
            Ok((name.to_string(), compiled))
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let regression_directory = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: corpus-driver REGRESSION_DIRECTORY [--emit-admitted-json]")?;
    let emit_admitted_json = match arguments.next().as_deref() {
        None => false,
        Some("--emit-admitted-json") => true,
        Some(_) => {
            return Err("usage: corpus-driver REGRESSION_DIRECTORY [--emit-admitted-json]".into());
        }
    };
    if arguments.next().is_some() {
        return Err("usage: corpus-driver REGRESSION_DIRECTORY [--emit-admitted-json]".into());
    }
    let mut entries = fs::read_dir(&regression_directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let entry_names = entries
        .iter()
        .map(|entry| {
            entry
                .file_name()
                .into_string()
                .map_err(|_| "regression corpus contains a non-UTF-8 file name")
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let source_stems = entry_names
        .iter()
        .filter_map(|name| {
            name.strip_suffix(".ts").filter(|_| {
                !name.ends_with(".helper.ts")
                    && !name.ends_with(".unused.ts")
                    && !name.ends_with(".adapter.ts")
            })
        })
        .collect::<BTreeSet<_>>();
    let expectation_stems = entry_names
        .iter()
        .filter_map(|name| name.strip_suffix(".expect.json"))
        .collect::<BTreeSet<_>>();
    if source_stems != expectation_stems {
        return Err(format!(
            "regression source/expectation pairing differs; source-only={:?} expectation-only={:?}",
            source_stems
                .difference(&expectation_stems)
                .collect::<Vec<_>>(),
            expectation_stems
                .difference(&source_stems)
                .collect::<Vec<_>>()
        )
        .into());
    }
    let mut checked = 0;
    let mut admitted = Vec::new();
    for entry in entries {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err("regression corpus contains a non-UTF-8 file name".into());
        };
        if !file_name.ends_with(".ts")
            || file_name.ends_with(".helper.ts")
            || file_name.ends_with(".unused.ts")
            || file_name.ends_with(".adapter.ts")
        {
            continue;
        }
        let stem = file_name.strip_suffix(".ts").expect("checked suffix");
        let source = fs::read_to_string(&path)?;
        let entry_module = format!("convex/{file_name}");
        let helper_path = regression_directory.join(format!("{stem}.helper.ts"));
        let mut modules = vec![
            HarnessModule {
                module_key: entry_module.clone(),
                source,
                imports: vec![HarnessImport {
                    original: "./_generated/server".to_string(),
                    resolved: GENERATED_SERVER.to_string(),
                }],
            },
            HarnessModule {
                module_key: GENERATED_SERVER.to_string(),
                source: GENERATED_SERVER_SOURCE.to_string(),
                imports: Vec::new(),
            },
        ];
        if helper_path.exists() {
            let helper_module = format!("convex/{stem}.helper.ts");
            modules[0].imports.push(HarnessImport {
                original: "./helper.js".to_string(),
                resolved: helper_module.clone(),
            });
            modules.push(HarnessModule {
                module_key: helper_module,
                source: fs::read_to_string(helper_path)?,
                imports: Vec::new(),
            });
        }
        let unused_path = regression_directory.join(format!("{stem}.unused.ts"));
        if unused_path.exists() {
            modules.push(HarnessModule {
                module_key: format!("convex/{stem}.unused.ts"),
                source: fs::read_to_string(unused_path)?,
                imports: Vec::new(),
            });
        }
        let adapter_path = regression_directory.join(format!("{stem}.adapter.ts"));
        let mut dependency_adapters = Vec::new();
        if adapter_path.exists() {
            modules[0].imports.push(HarnessImport {
                original: "invariant-validation-dependency-adapter".to_string(),
                resolved: DEPENDENCY_ADAPTER_MODULE.to_string(),
            });
            modules.push(HarnessModule {
                module_key: DEPENDENCY_ADAPTER_MODULE.to_string(),
                source: fs::read_to_string(adapter_path)?,
                imports: Vec::new(),
            });
            dependency_adapters.push(HarnessDependencyAdapter {
                id: "invariantValidationGetManyFrom".to_string(),
                module_path: DEPENDENCY_ADAPTER_MODULE.to_string(),
                export_name: "getManyFrom".to_string(),
                semantic_kind: "databaseIndexCollect".to_string(),
            });
        }
        let compiled = if dependency_adapters.is_empty() {
            compile_modules(&modules, &entry_module, "selected")
        } else {
            compile_modules_with_dependency_adapters(
                &modules,
                &entry_module,
                "selected",
                &dependency_adapters,
            )
        }
        .map_err(|error| format!("{file_name}: {error}"))?;
        let expectation: Value = serde_json::from_str(&fs::read_to_string(
            regression_directory.join(format!("{stem}.expect.json")),
        )?)?;
        validate_expectation(stem, &expectation, &compiled)?;
        if compiled.eligible() {
            admitted.push(json!({
                "compilerOutput": compiled.compiler_output,
                "name": stem,
            }));
        }
        checked += 1;
    }
    let source_operation = validate_source_operation_identity()?;
    let structured = compile_structured_lowering_cases()?;
    let structured_count = structured.len();
    if emit_admitted_json {
        admitted.push(json!({
            "compilerOutput": source_operation.compiler_output,
            "name": "structured-host-secret",
        }));
        admitted.extend(
            structured
                .into_iter()
                .filter(|(_, compiled)| compiled.eligible())
                .map(|(name, compiled)| {
                    json!({
                        "compilerOutput": compiled.compiler_output,
                        "name": name,
                    })
                }),
        );
    }
    if emit_admitted_json {
        println!("{}", serde_json::to_string(&admitted)?);
    } else {
        println!(
            "checked {checked} compiler frontend regressions, source-operation identity, and {} structured lowering cases",
            structured_count
        );
    }
    Ok(())
}
