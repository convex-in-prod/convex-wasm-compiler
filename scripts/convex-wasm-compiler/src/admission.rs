use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::adapter_semantics::DependencyAdapterCallIndex;
use super::callable_plans::CallableLeafControlCandidate;
use super::query_values::{CallableQueryBuilderSinkCandidate, CallableQueryConsumerKind};
use super::{
    CANONICAL_SHA256_HELPER_MODULE, CANONICAL_SHA256_HELPER_NAME, CANONICAL_SHA256_HELPER_SOURCE,
    Diagnostic, DirectIdentifierInvocationCandidate, DirectIdentifierOperandCandidate, GraphInput,
    LoadedModule, OperationCandidate, OperationIdentity, ReachableUnit,
    StaticMemberAccessCandidate, ValueMode, diagnostic_at, sorted_facts_starting_in_range,
};

const STATIC_HERMES_GLOBAL_INVENTORY_SOURCE: &str =
    include_str!("../../convex-wasm-static-hermes-engine-globals.json");
const STATIC_HERMES_GLOBAL_POLICY_IDENTITY_SOURCE: &str =
    include_str!("../../convex-wasm-runtime-surface-policy-identity.json");
const APPLICATION_GLOBAL_THIS_BINDING: &str = "__convexWasmApplicationGlobalThis";

struct StaticHermesGlobalAccessPolicy {
    application_facade_admitted: BTreeSet<String>,
    compile_admitted: BTreeSet<String>,
}

pub(super) fn static_hermes_global_policy_identity()
-> &'static super::StaticHermesGlobalPolicyIdentity {
    static IDENTITY: OnceLock<super::StaticHermesGlobalPolicyIdentity> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let identity: super::StaticHermesGlobalPolicyIdentity =
            serde_json::from_str(STATIC_HERMES_GLOBAL_POLICY_IDENTITY_SOURCE)
                .expect("checked-in Static Hermes global policy identity must be valid JSON");
        assert_eq!(
            identity.kind, "convex-wasm-runtime-surface-policy-identity",
            "checked-in Static Hermes global policy identity kind changed"
        );
        for (name, digest) in [
            ("inventory", identity.inventory_sha256.as_str()),
            (
                "runtime-surface policy",
                identity.runtime_surface_policy_sha256.as_str(),
            ),
        ] {
            assert!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "Static Hermes {name} identity must be a lowercase SHA-256 digest"
            );
        }
        identity
    })
}

fn static_hermes_global_access_policy() -> &'static StaticHermesGlobalAccessPolicy {
    static POLICY: OnceLock<StaticHermesGlobalAccessPolicy> = OnceLock::new();
    POLICY.get_or_init(|| {
        let inventory: Value = serde_json::from_str(STATIC_HERMES_GLOBAL_INVENTORY_SOURCE)
            .expect("checked-in Static Hermes global inventory must be valid JSON");
        assert_eq!(
            inventory["kind"], "convex-wasm-static-hermes-global-inventory",
            "checked-in Static Hermes global inventory kind changed"
        );
        let access_policy = inventory["accessPolicy"]
            .as_object()
            .expect("Static Hermes global access policy must be an object");
        assert_eq!(
            access_policy
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "applicationGlobalFacade",
                "applicationGlobalFacadeComputedAccess",
                "applicationGlobalFacadeFlow",
                "globalBindingWrites",
                "rawGlobalObjectFlow",
            ]),
            "Static Hermes global access policy fields changed"
        );
        assert_eq!(
            access_policy["applicationGlobalFacade"],
            "inventory-derived-extensible-null-prototype-immutable-builtins",
            "Static Hermes application global facade changed"
        );
        assert_eq!(
            access_policy["applicationGlobalFacadeComputedAccess"], "admitted",
            "Static Hermes application global facade computed access changed"
        );
        assert_eq!(
            access_policy["applicationGlobalFacadeFlow"], "admitted",
            "Static Hermes application global facade flow changed"
        );
        assert_eq!(
            access_policy["globalBindingWrites"], "rejected",
            "Static Hermes global binding writes must remain rejected"
        );
        assert_eq!(
            access_policy["rawGlobalObjectFlow"], "rejected",
            "Static Hermes raw global object flow must remain rejected"
        );
        let canonical_inventory = serde_json::to_vec(&inventory)
            .expect("checked-in Static Hermes global inventory must serialize");
        let inventory_sha256 = hex::encode(Sha256::digest(&canonical_inventory));
        assert_eq!(
            inventory_sha256,
            static_hermes_global_policy_identity().inventory_sha256,
            "checked-in Static Hermes global inventory and policy identity disagree"
        );
        let target_globals = inventory["targetRuntimeProbe"]["globals"]
            .as_array()
            .expect("Static Hermes target runtime globals must be an array")
            .iter()
            .map(|name| {
                name.as_str()
                    .expect("Static Hermes target runtime global must be a string")
            })
            .collect::<BTreeSet<_>>();
        let semantics = inventory["semantics"]
            .as_object()
            .expect("Static Hermes global semantics must be an object");
        for name in &target_globals {
            assert!(
                semantics.contains_key(*name),
                "target runtime global {name} is unclassified"
            );
        }
        let compile_admitted = semantics
            .iter()
            .filter_map(|(name, semantic)| {
                (semantic["read"]["state"] == "admitted").then(|| {
                    if !target_globals.contains(name.as_str()) {
                        assert_eq!(
                            semantic["provider"], "shared-untyped-runtime-support",
                            "compile-admitted global {name} is absent from the target runtime without runtime support"
                        );
                    }
                    name.clone()
                })
            })
            .collect::<BTreeSet<_>>();
        let application_facade_admitted = semantics
            .iter()
            .filter_map(|(name, semantic)| {
                (semantic["read"]["state"] == "admitted"
                    && matches!(
                        semantic["class"].as_str(),
                        Some("deterministic-ecmascript" | "deterministic-web-like")
                    ))
                .then(|| {
                    assert!(
                        compile_admitted.contains(name),
                        "application-facade global {name} must be compile-admitted"
                    );
                    name.clone()
                })
            })
            .collect::<BTreeSet<_>>();
        StaticHermesGlobalAccessPolicy {
            application_facade_admitted,
            compile_admitted,
        }
    })
}

pub(super) fn compile_admitted_static_hermes_globals() -> &'static BTreeSet<String> {
    &static_hermes_global_access_policy().compile_admitted
}

fn compile_admitted_static_hermes_global(name: &str) -> bool {
    compile_admitted_static_hermes_globals().contains(name)
}

fn application_global_facade_engine_global(name: &str) -> bool {
    static_hermes_global_access_policy()
        .application_facade_admitted
        .contains(name)
}

fn application_global_facade_value(name: &str) -> bool {
    name == APPLICATION_GLOBAL_THIS_BINDING || application_global_facade_engine_global(name)
}

fn requires_guest_native_value_mode(name: &str) -> bool {
    matches!(
        name,
        "Date"
            | "JSON"
            | "Map"
            | "Math"
            | "Number"
            | "Object"
            | "RegExp"
            | "Set"
            | "String"
            | "TextEncoder"
    ) || (application_global_facade_value(name)
        && !matches!(name, "Array" | "Error" | "Uint8Array"))
}

fn unrestricted_application_global_facade_value(name: &str) -> bool {
    // The named exclusions remain compiler-owned capability roots. Their direct use must match
    // one of the exact invocation, member, constant, or operand proofs below.
    application_global_facade_value(name)
        && !matches!(
            name,
            "JSON" | "Map" | "Number" | "RegExp" | "Set" | "String"
        )
}

pub(super) fn select_value_mode(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
) -> Result<ValueMode> {
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("reachable value-mode module was not loaded")?;
        if module.summary.globals.iter().any(|global| {
            global.start >= unit.start
                && global.end <= unit.end
                && global.read
                && !global.write
                && requires_guest_native_value_mode(&global.name)
                && !(global.name == "Number"
                    && module.summary.static_member_calls.iter().any(|call| {
                        call.root == "Number"
                            && call.first_field == "isSafeInteger"
                            && call.root_start == global.start
                            && call.root_end == global.end
                    }))
                && !(global.name == "TextEncoder"
                    && unit.kind == "function"
                    && module.summary.operations.iter().any(|operation| {
                        is_canonical_sha256_intrinsic(unit, operation) && operation.end <= unit.end
                    }))
        }) || module.summary.static_member_calls.iter().any(|call| {
            call.first_field == "filter"
                && call.start >= unit.start
                && call.end <= unit.end
                && !module.summary.proved_local_filters.iter().any(|filtered| {
                    filtered.initializer_start == call.start
                        && filtered.initializer_end <= unit.end
                        && filtered.source_binding == call.root
                        && filtered.source_reference_start == call.root_start
                        && filtered.source_reference_end == call.root_end
                })
        }) || module.summary.callable_leaf_plans.iter().any(|plan| {
            plan.callable_start >= unit.start
                && plan.callable_end <= unit.end
                && match &plan.control {
                    CallableLeafControlCandidate::QueryValue(query) => query
                        .consumers
                        .iter()
                        .any(|consumer| consumer.kind == CallableQueryConsumerKind::Paginate),
                    CallableLeafControlCandidate::QueryBuilderFlow(flow) => {
                        flow.paths.iter().any(|path| {
                            matches!(
                                &path.sink,
                                CallableQueryBuilderSinkCandidate::Terminal { consumer }
                                    if consumer.kind == CallableQueryConsumerKind::Paginate
                            )
                        })
                    }
                    _ => false,
                }
        }) || module.summary.constructs.iter().any(|construct| {
            construct.start >= unit.start
                && construct.end <= unit.end
                && matches!(
                    construct.kind.as_str(),
                    "ArrayPattern"
                        | "AssignmentPattern"
                        | "CatchClause"
                        | "ForAwaitOfStatement"
                        | "ForOfStatement"
                        | "ObjectPattern"
                        | "SpreadElement"
                        | "TryStatement"
                        | "WhileStatement"
                )
        }) {
            return Ok(ValueMode::GuestNativeJson);
        }
    }
    Ok(ValueMode::Opaque)
}

fn runtime_capability_global(name: &str) -> bool {
    application_global_facade_value(name)
        || (compile_admitted_static_hermes_global(name) && matches!(name, "Date" | "Math"))
}

fn admitted_runtime_capability_invocation(
    name: &str,
    invocation: &DirectIdentifierInvocationCandidate,
) -> bool {
    match (name, invocation.constructor) {
        ("Array" | "Error", _) => true,
        ("Map" | "Set" | "Uint8Array", true) => true,
        ("RegExp", _) => invocation.argument_count <= 2 && !invocation.has_spread_argument,
        ("TextEncoder", true) => invocation.argument_count == 0 && !invocation.has_spread_argument,
        ("Date", true) => invocation.argument_count == 1 && !invocation.has_spread_argument,
        ("Number" | "Object" | "String", false) => true,
        _ => false,
    }
}

fn admitted_runtime_capability_member_call(name: &str, field: &str) -> bool {
    match name {
        "Array" => matches!(field, "from" | "isArray" | "of"),
        "Date" => field == "now",
        "JSON" => matches!(field, "parse" | "stringify"),
        "Math" => matches!(
            field,
            "abs"
                | "acos"
                | "acosh"
                | "asin"
                | "asinh"
                | "atan"
                | "atan2"
                | "atanh"
                | "cbrt"
                | "ceil"
                | "clz32"
                | "cos"
                | "cosh"
                | "exp"
                | "expm1"
                | "floor"
                | "fround"
                | "hypot"
                | "imul"
                | "log"
                | "log10"
                | "log1p"
                | "log2"
                | "max"
                | "min"
                | "pow"
                | "round"
                | "sign"
                | "sin"
                | "sinh"
                | "sqrt"
                | "tan"
                | "tanh"
                | "trunc"
        ),
        "Number" => matches!(
            field,
            "isFinite" | "isInteger" | "isNaN" | "isSafeInteger" | "parseFloat" | "parseInt"
        ),
        "Object" => matches!(
            field,
            "assign"
                | "create"
                | "defineProperties"
                | "defineProperty"
                | "entries"
                | "freeze"
                | "fromEntries"
                | "getOwnPropertyDescriptor"
                | "getOwnPropertyDescriptors"
                | "getOwnPropertyNames"
                | "getOwnPropertySymbols"
                | "getPrototypeOf"
                | "hasOwn"
                | "is"
                | "isExtensible"
                | "isFrozen"
                | "isSealed"
                | "keys"
                | "preventExtensions"
                | "seal"
                | "setPrototypeOf"
                | "values"
        ),
        "String" => matches!(field, "fromCharCode" | "fromCodePoint"),
        "Uint8Array" => matches!(field, "from" | "of"),
        _ => false,
    }
}

fn admitted_runtime_capability_constant(name: &str, field: &str) -> bool {
    match name {
        "Math" => matches!(
            field,
            "E" | "LN10" | "LN2" | "LOG10E" | "LOG2E" | "PI" | "SQRT1_2" | "SQRT2"
        ),
        "Number" => matches!(
            field,
            "EPSILON"
                | "MAX_SAFE_INTEGER"
                | "MAX_VALUE"
                | "MIN_SAFE_INTEGER"
                | "MIN_VALUE"
                | "NEGATIVE_INFINITY"
                | "NaN"
                | "POSITIVE_INFINITY"
        ),
        _ => false,
    }
}

fn represents_admitted_runtime_capability_use(
    name: &str,
    start: u32,
    end: u32,
    member_accesses: &[StaticMemberAccessCandidate],
    member_calls: &[StaticMemberAccessCandidate],
    invocations: &[DirectIdentifierInvocationCandidate],
    operands: &[DirectIdentifierOperandCandidate],
) -> bool {
    if unrestricted_application_global_facade_value(name) {
        return true;
    }
    invocations.iter().any(|invocation| {
        invocation.callee == name
            && invocation.callee_start == start
            && invocation.callee_end == end
            && admitted_runtime_capability_invocation(name, invocation)
    }) || member_calls.iter().any(|call| {
        call.root == name
            && call.root_start == start
            && call.root_end == end
            && admitted_runtime_capability_member_call(name, &call.first_field)
            && (name != "Date" || (call.argument_count == Some(0) && !call.has_spread_argument))
    }) || member_accesses.iter().any(|access| {
        access.root == name
            && access.root_start == start
            && access.root_end == end
            && access.member_count == 1
            && !access.write
            && admitted_runtime_capability_constant(name, &access.first_field)
    }) || operands.iter().any(|operand| {
        operand.identifier == name
            && operand.start == start
            && operand.end == end
            && operand.operator == "instanceof-right"
            && matches!(
                name,
                "Array"
                    | "Date"
                    | "Error"
                    | "Map"
                    | "Number"
                    | "Object"
                    | "RegExp"
                    | "Set"
                    | "String"
                    | "TextEncoder"
                    | "Uint8Array"
            )
    })
}

fn runtime_capability_nondeterminism(
    name: &str,
    start: u32,
    end: u32,
    member_accesses: &[StaticMemberAccessCandidate],
    member_calls: &[StaticMemberAccessCandidate],
    invocations: &[DirectIdentifierInvocationCandidate],
) -> Option<String> {
    let member = member_accesses.iter().find(|access| {
        access.root == name
            && access.root_start == start
            && access.root_end == end
            && !access.write
            && ((name == "Math" && access.first_field == "random")
                || (name == "Date" && access.first_field == "now"))
    });
    if let Some(member) = member {
        if name == "Date"
            && member.first_field == "now"
            && member.member_count == 1
            && member_calls.iter().any(|call| {
                call.root == "Date"
                    && call.first_field == "now"
                    && call.member_count == 1
                    && call.root_start == start
                    && call.root_end == end
                    && call.start == member.start
                    && call.end == member.end
                    && call.argument_count == Some(0)
                    && !call.has_spread_argument
            })
        {
            return None;
        }
        return Some(format!(
            "{}.{} is not admitted because guest execution must be deterministic",
            name, member.first_field
        ));
    }
    let invocation = invocations.iter().find(|invocation| {
        invocation.callee == name
            && invocation.callee_start == start
            && invocation.callee_end == end
    })?;
    if name == "Date"
        && (!invocation.constructor
            || invocation.argument_count == 0
            || invocation.has_spread_argument)
    {
        return Some(if invocation.constructor {
            if invocation.has_spread_argument {
                "Date construction with spread arguments is not admitted because runtime arity \
                 may read the current time or use timezone-sensitive semantics"
                    .to_string()
            } else {
                "zero-argument Date construction is not admitted because guest execution must be \
                 deterministic"
                    .to_string()
            }
        } else {
            "calling Date as a function is not admitted because it reads the current time"
                .to_string()
        });
    }
    None
}

fn unsupported_runtime_capability_diagnostic(
    name: &str,
    start: u32,
    end: u32,
    member_accesses: &[StaticMemberAccessCandidate],
    member_calls: &[StaticMemberAccessCandidate],
    invocations: &[DirectIdentifierInvocationCandidate],
) -> (&'static str, String) {
    if let Some(call) = member_calls
        .iter()
        .find(|call| call.root == name && call.root_start == start && call.root_end == end)
    {
        return (
            "unsupported-runtime-capability-member",
            format!(
                "{}.{} is not an admitted deterministic runtime capability call",
                name, call.first_field
            ),
        );
    }
    if let Some(access) = member_accesses.iter().find(|access| {
        access.root == name
            && access.root_start == start
            && access.root_end == end
            && access.member_count == 1
    }) {
        if access.write {
            return (
                "unsupported-runtime-capability-flow",
                format!(
                    "write to runtime capability member {}.{} is not admitted",
                    name, access.first_field
                ),
            );
        }
        if access.first_field == "[computed]" {
            return (
                "unsupported-runtime-capability-flow",
                format!("computed access on runtime capability {name} is not admitted"),
            );
        }
        if admitted_runtime_capability_member_call(name, &access.first_field) {
            return (
                "unsupported-runtime-capability-flow",
                format!(
                    "{}.{} may only be used as a direct call; extracting, passing, returning, or storing it is not admitted",
                    name, access.first_field
                ),
            );
        }
        return (
            "unsupported-runtime-capability-member",
            format!(
                "{}.{} is not an admitted runtime capability member",
                name, access.first_field
            ),
        );
    }
    if let Some(invocation) = invocations.iter().find(|invocation| {
        invocation.callee == name
            && invocation.callee_start == start
            && invocation.callee_end == end
    }) {
        return (
            "unsupported-runtime-capability-flow",
            if invocation.constructor {
                if name == "Date" {
                    "Date construction requires exactly one explicit input; zero arguments read current time and multiple arguments use timezone-sensitive semantics"
                        .to_string()
                } else {
                    format!(
                        "construction with {name} is not admitted until the constructed value's capability provenance is tracked"
                    )
                }
            } else {
                format!("calling runtime capability {name} in this form is not admitted")
            },
        );
    }
    (
        "unsupported-runtime-capability-flow",
        format!(
            "using runtime capability {name} through aliasing, destructuring, computed access, arguments, returns, or storage is not admitted"
        ),
    )
}

pub(super) fn admit_reachable(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    registration_kind: &str,
    admitted_operation_identities: &BTreeSet<OperationIdentity>,
    dependency_adapter_calls: &DependencyAdapterCallIndex<'_>,
    effect_execution_mode: super::EffectExecutionMode,
    value_mode: ValueMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<()> {
    let mut allowed_constructs = BTreeSet::from([
        "ArrayExpression",
        "ArrowFunctionExpression",
        "AssignmentExpression",
        "AwaitExpression",
        "BinaryExpression",
        "BlockStatement",
        "BreakStatement",
        "CallExpression",
        "ChainExpression",
        "ConditionalExpression",
        "ContinueStatement",
        "ExpressionStatement",
        "ForStatement",
        "FunctionDeclaration",
        "Identifier",
        "IfStatement",
        "Literal",
        "LogicalExpression",
        "MemberExpression",
        "NewExpression",
        "ObjectExpression",
        "ParenthesizedExpression",
        "Property",
        "RestElement",
        "ReturnStatement",
        "SwitchCase",
        "SwitchStatement",
        "TemplateElement",
        "TemplateLiteral",
        "ThrowStatement",
        "UnaryExpression",
        "UpdateExpression",
        "VariableDeclaration",
        "VariableDeclarator",
    ]);
    if value_mode == ValueMode::GuestNativeJson {
        allowed_constructs.extend([
            "ArrayPattern",
            "AssignmentPattern",
            "CatchClause",
            "ForOfStatement",
            "ObjectPattern",
            "SpreadElement",
            "TryStatement",
            "WhileStatement",
        ]);
    }
    if effect_execution_mode == super::EffectExecutionMode::GuestPromiseEventLoop {
        allowed_constructs.insert("ForAwaitOfStatement");
    }
    let mut allowed_globals = ["Array", "Error", "Uint8Array", "undefined"]
        .into_iter()
        .filter(|name| compile_admitted_static_hermes_global(name))
        .collect::<BTreeSet<_>>();
    if value_mode == ValueMode::GuestNativeJson {
        allowed_globals.extend(
            [
                "Date",
                "JSON",
                "Map",
                "Math",
                "Number",
                "Object",
                "RegExp",
                "Set",
                "String",
                "TextEncoder",
            ]
            .into_iter()
            .filter(|name| compile_admitted_static_hermes_global(name)),
        );
        allowed_globals.extend(
            static_hermes_global_access_policy()
                .application_facade_admitted
                .iter()
                .map(String::as_str),
        );
        allowed_globals.insert(APPLICATION_GLOBAL_THIS_BINDING);
    }
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("reachable module was not loaded")?;
        let constructs = sorted_facts_starting_in_range(
            &module.summary.constructs,
            unit.start,
            unit.end,
            |construct| construct.start,
        );
        let static_member_calls = sorted_facts_starting_in_range(
            &module.summary.static_member_calls,
            unit.start,
            unit.end,
            |call| call.start,
        );
        let local_array_bindings = sorted_facts_starting_in_range(
            &module.summary.local_array_bindings,
            unit.start,
            unit.end,
            |binding| binding.binding_start,
        );
        let operations = sorted_facts_starting_in_range(
            &module.summary.operations,
            unit.start,
            unit.end,
            |operation| operation.start,
        );
        let globals = sorted_facts_starting_in_range(
            &module.summary.globals,
            unit.start,
            unit.end,
            |global| global.start,
        );
        let direct_async_batches = sorted_facts_starting_in_range(
            &module.summary.direct_async_batches,
            unit.start,
            unit.end,
            |batch| batch.start,
        );
        let local_set_bindings = sorted_facts_starting_in_range(
            &module.summary.local_set_bindings,
            unit.start,
            unit.end,
            |binding| binding.binding_start,
        );
        for statement in module.summary.try_statements.iter().filter(|statement| {
            effect_execution_mode.is_blocking()
                && statement.start >= unit.start
                && statement.end <= unit.end
                && statement.catch_start.is_some()
        }) {
            let protected_await = constructs.iter().any(|construct| {
                construct.kind == "AwaitExpression"
                    && construct.start >= statement.protected_start
                    && construct.end <= statement.protected_end
            });
            let protected_operation = operations.iter().any(|operation| {
                operation.start >= statement.protected_start
                    && operation.end <= statement.protected_end
                    && !matches!(
                        operation.kind.as_str(),
                        "db.normalizeId" | "intrinsic.sha256"
                    )
            });
            let protected_capability_effect = module.summary.effects.iter().any(|effect| {
                effect.start >= statement.protected_start && effect.end <= statement.protected_end
            });
            if protected_await || protected_operation || protected_capability_effect {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-try-suspended-convex-error",
                    "a try block that may suspend on a Convex effect cannot catch its host error until guest catchability is implemented"
                        .to_string(),
                    &unit.module,
                    statement.start,
                    Some("TryStatement".to_string()),
                    unit.dependency_chain.clone(),
                )?);
            }
        }
        for construct in constructs
            .iter()
            .filter(|construct| construct.end <= unit.end)
        {
            if !allowed_constructs.contains(construct.kind.as_str()) {
                let message = match construct.kind.as_str() {
                    "ArrayPattern" => "array binding destructuring is not admitted until every bound alias is represented in capability and argument ownership proofs".to_string(),
                    "SpreadElement" => "spread is not admitted until operand provenance proves that iteration or property reads cannot hide mutable, global, or effectful behavior".to_string(),
                    _ => format!("unsupported runtime construct {}", construct.kind),
                };
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-construct",
                    message,
                    &unit.module,
                    construct.start,
                    Some(construct.kind.clone()),
                    unit.dependency_chain.clone(),
                )?);
            }
        }
        for call in static_member_calls.iter().filter(|call| {
            value_mode == ValueMode::Opaque
                && call.first_field == "filter"
                && call.end <= unit.end
                && !module.summary.proved_local_filters.iter().any(|filtered| {
                    filtered.initializer_start == call.start
                        && filtered.initializer_end <= unit.end
                        && filtered.source_binding == call.root
                        && filtered.source_reference_start == call.root_start
                        && filtered.source_reference_end == call.root_end
                })
        }) {
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "unsupported-array-filter",
                "array filter must match the proved local collect, predicate, and registration argument shape"
                    .to_string(),
                &unit.module,
                call.start,
                Some("filter".to_string()),
                unit.dependency_chain.clone(),
            )?);
        }
        for binding in local_array_bindings
            .iter()
            .filter(|binding| value_mode == ValueMode::Opaque && binding.binding_end <= unit.end)
        {
            for call in static_member_calls.iter().filter(|call| {
                call.root == binding.name
                    && binding.references.iter().any(|reference| {
                        reference.read
                            && !reference.write
                            && reference.start == call.root_start
                            && reference.end == call.root_end
                    })
            }) {
                if call.first_field == "filter" {
                    // The filter-specific check above owns both its admitted and rejected shapes.
                    continue;
                }
                let represented_direct_batch_map = call.first_field == "map"
                    && module.summary.direct_async_batches.iter().any(|batch| {
                        batch.iterator_binding.as_ref() == Some(&binding.name)
                            && batch.iterator_binding_start == Some(call.root_start)
                            && batch.iterator_binding_end == Some(call.root_end)
                    });
                if represented_direct_batch_map {
                    continue;
                }
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-document-collection-flow",
                    format!(
                        "collected document arrays support length reads, proved filters, and direct Promise.all maps; {} is not admitted",
                        call.first_field
                    ),
                    &unit.module,
                    call.start,
                    Some(call.first_field.clone()),
                    unit.dependency_chain.clone(),
                )?);
            }
        }
        for operation in operations.iter().filter(|operation| {
            operation.kind == "intrinsic.sha256"
                && operation.end <= unit.end
                && !is_canonical_sha256_intrinsic(unit, operation)
        }) {
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "unsupported-sha256-intrinsic-shape",
                "SHA-256 intrinsic admission requires the exact canonical shared helper"
                    .to_string(),
                &unit.module,
                operation.start,
                Some(operation.kind.clone()),
                unit.dependency_chain.clone(),
            )?);
        }
        for global in globals.iter().filter(|global| global.end <= unit.end) {
            let represented_intrinsic_global = match global.name.as_str() {
                "crypto" => operations.iter().any(|operation| {
                    is_canonical_sha256_intrinsic(unit, operation)
                        && operation.end <= unit.end
                        && global.start >= operation.start
                        && global.end <= operation.end
                }),
                "TextEncoder" => {
                    unit.kind == "function"
                        && operations.iter().any(|operation| {
                            is_canonical_sha256_intrinsic(unit, operation)
                                && operation.end <= unit.end
                        })
                }
                _ => false,
            };
            let represented_direct_batch_global = global.name == "Promise"
                && (effect_execution_mode == super::EffectExecutionMode::GuestPromiseEventLoop
                    || direct_async_batches.iter().any(|batch| {
                        batch.end <= unit.end
                            && batch.promise_start == global.start
                            && batch.promise_end == global.end
                    }));
            let represented_direct_batch_set_global = global.name == "Set"
                && local_set_bindings.iter().any(|binding| {
                    binding.binding_end <= unit.end
                        && binding.set_global_start == global.start
                        && binding.set_global_end == global.end
                        && direct_async_batches.iter().any(|batch| {
                            batch.end <= unit.end
                                && batch.iterator_array_global_start.is_some()
                                && batch.iterator_binding.as_ref() == Some(&binding.name)
                                && batch.enclosing_function_start
                                    == binding.enclosing_function_start
                                && batch.enclosing_function_end == binding.enclosing_function_end
                        })
                });
            let represented_dependency_adapter_global = dependency_adapter_calls.represents_global(
                &unit.module,
                &unit.id,
                global.start,
                global.end,
            );
            let represented_safe_integer_global = global.name == "Number"
                && static_member_calls.iter().any(|call| {
                    call.root == "Number"
                        && call.first_field == "isSafeInteger"
                        && call.root_start == global.start
                        && call.root_end == global.end
                });
            let available_runtime_capability = allowed_globals.contains(global.name.as_str())
                && runtime_capability_global(&global.name);
            let represented_runtime_capability = available_runtime_capability
                && represents_admitted_runtime_capability_use(
                    &global.name,
                    global.start,
                    global.end,
                    &module.summary.static_member_accesses,
                    &module.summary.static_member_calls,
                    &module.summary.direct_identifier_invocations,
                    &module.summary.direct_identifier_operands,
                );
            let rejected_runtime_capability =
                available_runtime_capability && !represented_runtime_capability;
            let nondeterminism = (value_mode == ValueMode::GuestNativeJson)
                .then(|| {
                    runtime_capability_nondeterminism(
                        &global.name,
                        global.start,
                        global.end,
                        &module.summary.static_member_accesses,
                        &module.summary.static_member_calls,
                        &module.summary.direct_identifier_invocations,
                    )
                })
                .flatten();
            if global.write
                || nondeterminism.is_some()
                || rejected_runtime_capability
                || (!allowed_globals.contains(global.name.as_str())
                    && !represented_intrinsic_global
                    && !represented_direct_batch_global
                    && !represented_direct_batch_set_global
                    && !represented_dependency_adapter_global
                    && !represented_safe_integer_global)
            {
                let capability_diagnostic = rejected_runtime_capability.then(|| {
                    unsupported_runtime_capability_diagnostic(
                        &global.name,
                        global.start,
                        global.end,
                        &module.summary.static_member_accesses,
                        &module.summary.static_member_calls,
                        &module.summary.direct_identifier_invocations,
                    )
                });
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    if global.write {
                        "global-write"
                    } else if nondeterminism.is_some() {
                        "unsupported-nondeterminism"
                    } else if let Some((code, _)) = &capability_diagnostic {
                        code
                    } else {
                        "unsupported-global"
                    },
                    if global.write {
                        format!("write to global {} is not admitted", global.name)
                    } else if let Some(message) = nondeterminism {
                        message
                    } else if let Some((_, message)) = capability_diagnostic {
                        message
                    } else {
                        format!("global {} is not in the admitted runtime ABI", global.name)
                    },
                    &unit.module,
                    global.start,
                    Some("Identifier".to_string()),
                    unit.dependency_chain.clone(),
                )?);
            }
        }
        if matches!(registration_kind, "internalQuery" | "query") {
            for operation in operations.iter().filter(|operation| {
                operation.end <= unit.end
                    && admitted_operation_identities.contains(&(
                        unit.module.clone(),
                        operation.start,
                        operation.end,
                    ))
                    && matches!(
                        operation.kind.as_str(),
                        "db.insert"
                            | "db.patch"
                            | "db.replace"
                            | "db.delete"
                            | "scheduler.runAfter"
                            | "scheduler.runAt"
                    )
            }) {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-construct",
                    format!(
                        "{} effects are not admitted in query functions",
                        operation.kind
                    ),
                    &unit.module,
                    operation.start,
                    Some(operation.kind.clone()),
                    unit.dependency_chain.clone(),
                )?);
            }
        }
    }
    Ok(())
}

pub(super) fn is_canonical_sha256_intrinsic(
    unit: &ReachableUnit,
    operation: &OperationCandidate,
) -> bool {
    operation.kind == "intrinsic.sha256"
        && operation.algorithm.as_deref() == Some("SHA-256")
        && unit.module == CANONICAL_SHA256_HELPER_MODULE
        && unit.name == CANONICAL_SHA256_HELPER_NAME
        && unit.kind == "function"
        && CANONICAL_SHA256_HELPER_SOURCE
            .strip_prefix("export ")
            .and_then(|source| source.strip_suffix('\n'))
            .is_some_and(|source| unit.source == source)
}
