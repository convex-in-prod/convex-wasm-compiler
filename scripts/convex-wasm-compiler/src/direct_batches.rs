use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::adapter_semantics::DependencyAdapterCallIndex;
use super::callable_plans::CallableEffectPlanIndex;
use super::callable_resolution::{
    StaticSourceTargetCache, cached_static_source_target, resolve_static_source_target,
};
use super::callable_value_flow::AuthenticatedFixedPromiseAllChildOrigin;
use super::effect_materialization::{AuthorizedEffectSiteIndex, materialize_authorized_batch_site};
use super::{
    AdmittedOperation, DatabaseOperationSource, Diagnostic, GraphInput, IndexConstraintCandidate,
    LoadedModule, OperationCandidate, OperationIdentity, ReachableUnit, RegistrationSummary,
    SourceRange, ValueMode, call_has_optional_callee, call_method_name, callee_identifier,
    contains_node_type, count_node_type, diagnostic_at, hash_bytes, identifier_name,
    is_static_member_call, leading_await_count, line_column, module_source, node_type,
    parse_callsite_specializable_database_get, parse_db_operation, parse_db_operation_for_source,
    parse_index_constraints, parse_scheduler_operation, source_slice, span,
    unwrap_runtime_expression, unwrap_transparent_expression,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectBatchHelperCandidate {
    pub(super) operation_start: Option<u32>,
    pub(super) operation_end: Option<u32>,
    pub(super) dynamic_argument_ranges: Vec<SourceRange>,
    pub(super) dynamic_parameter_indices: Vec<usize>,
    pub(super) capability_parameter_index: Option<usize>,
    pub(super) operation_kind: Option<String>,
    pub(super) table: Option<String>,
    pub(super) index: Option<String>,
    pub(super) index_constraints: Vec<IndexConstraintCandidate>,
    pub(super) order: Option<String>,
    pub(super) terminal: Option<String>,
    pub(super) limit: Option<u32>,
    #[serde(default)]
    pub(super) limit_argument_index: Option<u32>,
    pub(super) function_reference: Option<String>,
    pub(super) function_reference_start: Option<u32>,
    pub(super) function_reference_end: Option<u32>,
    pub(super) continuation: Option<DirectBatchHelperContinuationCandidate>,
    pub(super) shape_error: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectBatchHelperContinuationCandidate {
    pub(super) result_binding: String,
    pub(super) body_start: u32,
    pub(super) body_end: u32,
    pub(super) suspension_start: u32,
    pub(super) suspension_end: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectAsyncBatchCandidate {
    pub(super) batch_kind: String,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) promise_start: u32,
    pub(super) promise_end: u32,
    pub(super) enclosing_function_start: Option<u32>,
    pub(super) enclosing_function_end: Option<u32>,
    pub(super) iterator_start: Option<u32>,
    pub(super) iterator_end: Option<u32>,
    pub(super) iterator_root: Option<String>,
    pub(super) iterator_field: Option<String>,
    pub(super) iterator_binding: Option<String>,
    pub(super) iterator_binding_start: Option<u32>,
    pub(super) iterator_binding_end: Option<u32>,
    pub(super) iterator_array_global_start: Option<u32>,
    pub(super) iterator_array_global_end: Option<u32>,
    pub(super) callback_start: Option<u32>,
    pub(super) callback_end: Option<u32>,
    pub(super) callback_parameter: Option<String>,
    #[serde(default)]
    pub(super) implicit_undefined: bool,
    pub(super) operation_start: Option<u32>,
    pub(super) operation_end: Option<u32>,
    pub(super) dynamic_arguments: Vec<SourceRange>,
    pub(super) operation_kind: Option<String>,
    pub(super) table: Option<String>,
    pub(super) index: Option<String>,
    pub(super) index_constraints: Vec<IndexConstraintCandidate>,
    pub(super) order: Option<String>,
    pub(super) terminal: Option<String>,
    pub(super) limit: Option<u32>,
    #[serde(default)]
    pub(super) limit_argument_index: Option<u32>,
    pub(super) function_reference: Option<String>,
    pub(super) helper_callee: Option<String>,
    pub(super) helper_call_start: Option<u32>,
    pub(super) helper_call_end: Option<u32>,
    pub(super) helper_arguments: Vec<SourceRange>,
    pub(super) helper_identifier_arguments: Vec<bool>,
    pub(super) helper_has_spread_argument: bool,
    pub(super) fixed_children: Vec<DirectAsyncBatchFixedChildCandidate>,
    pub(super) shape_error: Option<String>,
    pub(super) sequential_value_map_safe: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PromiseAllSiteCandidate {
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) promise_start: u32,
    pub(super) promise_end: u32,
    pub(super) argument_start: Option<u32>,
    pub(super) argument_end: Option<u32>,
    #[serde(default)]
    pub(super) elements: Vec<SourceRange>,
    pub(super) directly_awaited: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectAsyncBatchFixedChildCandidate {
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) operation_start: Option<u32>,
    pub(super) operation_end: Option<u32>,
    pub(super) dynamic_arguments: Vec<SourceRange>,
    pub(super) operation_kind: Option<String>,
    pub(super) table: Option<String>,
    pub(super) index: Option<String>,
    pub(super) index_constraints: Vec<IndexConstraintCandidate>,
    pub(super) order: Option<String>,
    pub(super) terminal: Option<String>,
    pub(super) limit: Option<u32>,
    #[serde(default)]
    pub(super) limit_argument_index: Option<u32>,
    pub(super) function_reference: Option<String>,
    pub(super) helper_callee: Option<String>,
    pub(super) helper_call_start: Option<u32>,
    pub(super) helper_call_end: Option<u32>,
    pub(super) helper_arguments: Vec<SourceRange>,
    pub(super) helper_identifier_arguments: Vec<bool>,
    pub(super) helper_has_spread_argument: bool,
    pub(super) shape_error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectAsyncBatchAuthorization {
    pub(super) id: String,
    pub(super) file: String,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) line: usize,
    pub(super) column: usize,
    pub(super) source: String,
    pub(super) source_sha256: String,
    pub(super) generated_start: u32,
    pub(super) generated_end: u32,
    pub(super) generated_source_sha256: String,
    #[serde(flatten)]
    pub(super) shape: DirectAsyncBatchAuthorizationShape,
    #[serde(skip)]
    pub(super) dependency_chain: Vec<String>,
}

#[derive(Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum DirectAsyncBatchAuthorizationShape {
    #[serde(rename = "singleEffectMap")]
    SingleEffectMap {
        callback_start: u32,
        callback_end: u32,
        callback_parameter: String,
        operation_start: u32,
        operation_end: u32,
        operation_id: u32,
        operation_kind: String,
        result_kind: String,
        helper_continuation_prebound: bool,
        argument_field: Option<String>,
        dynamic_arguments: Vec<DirectAsyncBatchArgumentAuthorization>,
        #[serde(skip)]
        source_iterator_start: u32,
        #[serde(skip)]
        source_iterator_end: u32,
        generated_iterator_start: u32,
        generated_iterator_end: u32,
        generated_iterator_sha256: String,
        #[serde(skip)]
        operation_stable_key: String,
        #[serde(skip)]
        helper_callee: Option<String>,
        #[serde(skip)]
        helper_dynamic_argument_indices: Vec<usize>,
        #[serde(skip)]
        helper_continuation: Option<Box<DirectBatchHelperContinuationAuthorization>>,
    },
    #[serde(rename = "fixedEffectArray")]
    FixedEffectArray {
        children: Vec<DirectAsyncBatchFixedChildAuthorization>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectAsyncBatchFixedChildAuthorization {
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) operation_start: u32,
    pub(super) operation_end: u32,
    pub(super) operation_id: u32,
    pub(super) operation_kind: String,
    pub(super) result_kind: String,
    pub(super) source: String,
    pub(super) source_sha256: String,
    pub(super) dynamic_arguments: Vec<DirectAsyncBatchArgumentAuthorization>,
    pub(super) generated_start: u32,
    pub(super) generated_end: u32,
    pub(super) generated_source_sha256: String,
    pub(super) helper_continuation_prebound: bool,
    #[serde(skip)]
    pub(super) operation_stable_key: String,
    #[serde(skip)]
    pub(super) helper_callee: Option<String>,
    #[serde(skip)]
    pub(super) helper_dynamic_argument_indices: Vec<usize>,
    #[serde(skip)]
    pub(super) helper_continuation: Option<DirectBatchHelperContinuationAuthorization>,
}

pub(super) struct DirectBatchHelperContinuationAuthorization {
    pub(super) helper_binding: String,
    pub(super) helper_parameters: Vec<String>,
    pub(super) helper_arguments: Vec<DirectAsyncBatchArgumentAuthorization>,
    pub(super) source_sha256: String,
    pub(super) source_body_start: u32,
    pub(super) source_body_end: u32,
    pub(super) source_suspension_start: u32,
    pub(super) source_suspension_end: u32,
    pub(super) source_result_binding: String,
    pub(super) generated_body_start: u32,
    pub(super) generated_body_end: u32,
    pub(super) generated_suspension_start: u32,
    pub(super) generated_suspension_end: u32,
    pub(super) generated_result_binding: String,
    pub(super) generated_effect_arguments: Vec<SourceRange>,
    pub(super) dependency_adapter: Option<DirectBatchHelperDependencyAdapterContinuation>,
}

#[derive(Clone)]
pub(super) struct DirectBatchHelperDependencyAdapterContinuation {
    pub(super) table: String,
    pub(super) field: String,
}

struct DirectBatchHelperAuthorizationMetadata {
    callee: String,
    dynamic_argument_indices: Vec<usize>,
    operation_id: u32,
    continuation: Option<PendingDirectBatchHelperContinuation>,
}

struct AuthenticatedFixedBatchChild {
    candidate: DirectAsyncBatchFixedChildCandidate,
    operation_start: u32,
    operation_end: u32,
    operation_id: u32,
    dynamic_arguments: Vec<SourceRange>,
    helper_metadata: Option<DirectBatchHelperAuthorizationMetadata>,
}

struct PendingDirectBatchHelperContinuation {
    helper_binding: String,
    helper_parameters: Vec<String>,
    helper_arguments: Vec<SourceRange>,
    source_sha256: String,
    source_body_start: u32,
    source_body_end: u32,
    source_suspension_start: u32,
    source_suspension_end: u32,
    source_result_binding: String,
    dependency_adapter: Option<DirectBatchHelperDependencyAdapterContinuation>,
}

fn direct_batch_helper_authorization_metadata(
    callee: String,
    helper_arguments: Vec<SourceRange>,
    operation_id: u32,
    resolved: &ResolvedDirectBatchHelper,
) -> DirectBatchHelperAuthorizationMetadata {
    DirectBatchHelperAuthorizationMetadata {
        callee,
        dynamic_argument_indices: resolved.helper.dynamic_parameter_indices.clone(),
        operation_id,
        continuation: resolved.helper.continuation.as_ref().map(|continuation| {
            PendingDirectBatchHelperContinuation {
                helper_binding: resolved.target_binding.clone(),
                helper_parameters: resolved.target_parameters.clone(),
                helper_arguments,
                source_sha256: resolved.target_source_sha256.clone(),
                source_body_start: continuation.body_start,
                source_body_end: continuation.body_end,
                source_suspension_start: continuation.suspension_start,
                source_suspension_end: continuation.suspension_end,
                source_result_binding: continuation.result_binding.clone(),
                dependency_adapter: resolved.dependency_adapter_continuation.clone(),
            }
        }),
    }
}

fn planned_direct_batch_helper_authorization_metadata(
    callee: String,
    helper_arguments: Vec<SourceRange>,
    dynamic_arguments: &[SourceRange],
    operation_id: u32,
    resolved: &ResolvedDirectBatchHelper,
) -> Result<DirectBatchHelperAuthorizationMetadata> {
    let dynamic_argument_indices = dynamic_arguments
        .iter()
        .map(|argument| {
            helper_arguments
                .iter()
                .position(|candidate| candidate == argument)
                .context("effect plan operand does not map to one helper call argument")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DirectBatchHelperAuthorizationMetadata {
        callee,
        dynamic_argument_indices,
        operation_id,
        continuation: resolved.helper.continuation.as_ref().map(|continuation| {
            PendingDirectBatchHelperContinuation {
                helper_binding: resolved.target_binding.clone(),
                helper_parameters: resolved.target_parameters.clone(),
                helper_arguments,
                source_sha256: resolved.target_source_sha256.clone(),
                source_body_start: continuation.body_start,
                source_body_end: continuation.body_end,
                source_suspension_start: continuation.suspension_start,
                source_suspension_end: continuation.suspension_end,
                source_result_binding: continuation.result_binding.clone(),
                dependency_adapter: resolved.dependency_adapter_continuation.clone(),
            }
        }),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectAsyncBatchArgumentAuthorization {
    pub(super) source_start: u32,
    pub(super) source_end: u32,
    pub(super) source: String,
    pub(super) source_sha256: String,
    pub(super) generated_start: u32,
    pub(super) generated_end: u32,
    pub(super) generated_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProvedDirectAsyncBatch {
    pub(super) id: String,
    pub(super) file: String,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) line: usize,
    pub(super) column: usize,
    pub(super) dependency_chain: Vec<String>,
    pub(super) source: String,
    pub(super) source_sha256: String,
    #[serde(flatten)]
    pub(super) shape: ProvedDirectAsyncBatchShape,
}

#[derive(Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum ProvedDirectAsyncBatchShape {
    #[serde(rename = "singleEffectMap")]
    SingleEffectMap {
        callback_start: u32,
        callback_end: u32,
        callback_parameter: String,
        operation_start: u32,
        operation_end: u32,
        operation_id: u32,
        operation_stable_key: String,
        operation_kind: String,
        result_kind: String,
        helper_continuation_prebound: bool,
        argument_field: Option<String>,
        dynamic_arguments: Vec<ProvedDirectAsyncBatchArgument>,
    },
    #[serde(rename = "fixedEffectArray")]
    FixedEffectArray {
        children: Vec<ProvedDirectAsyncBatchFixedChild>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProvedDirectAsyncBatchFixedChild {
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) operation_start: u32,
    pub(super) operation_end: u32,
    pub(super) operation_id: u32,
    pub(super) operation_stable_key: String,
    pub(super) operation_kind: String,
    pub(super) result_kind: String,
    pub(super) source: String,
    pub(super) source_sha256: String,
    pub(super) dynamic_arguments: Vec<ProvedDirectAsyncBatchArgument>,
    pub(super) helper_continuation_prebound: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProvedDirectAsyncBatchArgument {
    pub(super) source_start: u32,
    pub(super) source_end: u32,
    pub(super) source: String,
    pub(super) source_sha256: String,
}

fn proved_direct_async_batch_argument(
    argument: &DirectAsyncBatchArgumentAuthorization,
) -> ProvedDirectAsyncBatchArgument {
    ProvedDirectAsyncBatchArgument {
        source_start: argument.source_start,
        source_end: argument.source_end,
        source: argument.source.clone(),
        source_sha256: argument.source_sha256.clone(),
    }
}

pub(super) fn proved_direct_async_batch(
    batch: &DirectAsyncBatchAuthorization,
) -> ProvedDirectAsyncBatch {
    let shape = match &batch.shape {
        DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            callback_start,
            callback_end,
            callback_parameter,
            operation_start,
            operation_end,
            operation_id,
            operation_stable_key,
            operation_kind,
            result_kind,
            helper_continuation_prebound,
            argument_field,
            dynamic_arguments,
            ..
        } => ProvedDirectAsyncBatchShape::SingleEffectMap {
            callback_start: *callback_start,
            callback_end: *callback_end,
            callback_parameter: callback_parameter.clone(),
            operation_start: *operation_start,
            operation_end: *operation_end,
            operation_id: *operation_id,
            operation_stable_key: operation_stable_key.clone(),
            operation_kind: operation_kind.clone(),
            result_kind: result_kind.clone(),
            helper_continuation_prebound: *helper_continuation_prebound,
            argument_field: argument_field.clone(),
            dynamic_arguments: dynamic_arguments
                .iter()
                .map(proved_direct_async_batch_argument)
                .collect(),
        },
        DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } => {
            ProvedDirectAsyncBatchShape::FixedEffectArray {
                children: children
                    .iter()
                    .map(|child| ProvedDirectAsyncBatchFixedChild {
                        start: child.start,
                        end: child.end,
                        operation_start: child.operation_start,
                        operation_end: child.operation_end,
                        operation_id: child.operation_id,
                        operation_stable_key: child.operation_stable_key.clone(),
                        operation_kind: child.operation_kind.clone(),
                        result_kind: child.result_kind.clone(),
                        source: child.source.clone(),
                        source_sha256: child.source_sha256.clone(),
                        dynamic_arguments: child
                            .dynamic_arguments
                            .iter()
                            .map(proved_direct_async_batch_argument)
                            .collect(),
                        helper_continuation_prebound: child.helper_continuation_prebound,
                    })
                    .collect(),
            }
        }
    };
    ProvedDirectAsyncBatch {
        id: batch.id.clone(),
        file: batch.file.clone(),
        start: batch.start,
        end: batch.end,
        line: batch.line,
        column: batch.column,
        dependency_chain: batch.dependency_chain.clone(),
        source: batch.source.clone(),
        source_sha256: batch.source_sha256.clone(),
        shape,
    }
}

pub(super) fn authenticated_batch_effect_value_closures(
    batches: &[DirectAsyncBatchAuthorization],
) -> BTreeSet<OperationIdentity> {
    batches
        .iter()
        .flat_map(|batch| match &batch.shape {
            DirectAsyncBatchAuthorizationShape::SingleEffectMap {
                operation_start,
                operation_end,
                ..
            } => vec![(batch.file.clone(), *operation_start, *operation_end)],
            DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } => children
                .iter()
                .map(|child| {
                    (
                        batch.file.clone(),
                        child.operation_start,
                        child.operation_end,
                    )
                })
                .collect(),
        })
        .collect()
}

pub(super) fn collect_direct_async_batches(
    value: &Value,
    enclosing_function: Option<(u32, u32)>,
    suspension: Option<&str>,
    database_operation_source: DatabaseOperationSource,
    output: &mut Vec<DirectAsyncBatchCandidate>,
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
        if object.get("type").and_then(Value::as_str) == Some("CallExpression")
            && is_static_member_call(value, "Promise", "all")
        {
            output.push(parse_direct_async_batch(
                value,
                current_function,
                suspension == Some("await"),
                database_operation_source,
            ));
        }
        let kind = object.get("type").and_then(Value::as_str);
        for (key, child) in object {
            let child_suspension = match (kind, key.as_str()) {
                (Some("AwaitExpression"), "argument") => Some("await"),
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
            collect_direct_async_batches(
                child,
                current_function,
                child_suspension,
                database_operation_source,
                output,
            );
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_direct_async_batches(
                child,
                enclosing_function,
                None,
                database_operation_source,
                output,
            );
        }
    }
}

pub(super) fn collect_promise_all_sites(
    value: &Value,
    suspension: Option<&str>,
    output: &mut Vec<PromiseAllSiteCandidate>,
) {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("CallExpression")
            && is_static_member_call(value, "Promise", "all")
            && let Ok((start, end)) = span(value)
            && let Some(promise) = value
                .get("callee")
                .map(unwrap_runtime_expression)
                .and_then(|callee| callee.get("object"))
                .map(unwrap_runtime_expression)
            && let Ok((promise_start, promise_end)) = span(promise)
        {
            let argument = value
                .get("arguments")
                .and_then(Value::as_array)
                .and_then(|arguments| (arguments.len() == 1).then(|| arguments.first()).flatten())
                .map(unwrap_transparent_expression)
                .and_then(|argument| span(argument).ok());
            let elements = value
                .get("arguments")
                .and_then(Value::as_array)
                .and_then(|arguments| (arguments.len() == 1).then(|| arguments.first()).flatten())
                .map(unwrap_transparent_expression)
                .filter(|argument| node_type(argument).ok() == Some("ArrayExpression"))
                .and_then(|argument| argument.get("elements").and_then(Value::as_array))
                .map(|elements| {
                    elements
                        .iter()
                        .map(unwrap_transparent_expression)
                        .map(span)
                        .map(|range| range.map(|(start, end)| SourceRange { start, end }))
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()
                .ok()
                .flatten()
                .unwrap_or_default();
            output.push(PromiseAllSiteCandidate {
                start,
                end,
                promise_start,
                promise_end,
                argument_start: argument.map(|(start, _)| start),
                argument_end: argument.map(|(_, end)| end),
                elements,
                directly_awaited: suspension == Some("await"),
            });
        }
        let kind = object.get("type").and_then(Value::as_str);
        for (key, child) in object {
            let child_suspension = match (kind, key.as_str()) {
                (Some("AwaitExpression"), "argument") => Some("await"),
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
            collect_promise_all_sites(child, child_suspension, output);
        }
    } else if let Value::Array(values) = value {
        for child in values {
            collect_promise_all_sites(child, None, output);
        }
    }
}

pub(super) fn parse_direct_async_batch(
    call: &Value,
    enclosing_function: Option<(u32, u32)>,
    directly_awaited: bool,
    database_operation_source: DatabaseOperationSource,
) -> DirectAsyncBatchCandidate {
    let (start, end) = span(call).expect("Promise.all call has a source span");
    let promise = call
        .get("callee")
        .map(unwrap_runtime_expression)
        .and_then(|callee| callee.get("object"))
        .map(unwrap_runtime_expression)
        .expect("Promise.all call has a receiver");
    let (promise_start, promise_end) =
        span(promise).expect("Promise.all receiver has a source span");
    let mut candidate = DirectAsyncBatchCandidate {
        batch_kind: "singleEffectMap".to_string(),
        start,
        end,
        promise_start,
        promise_end,
        enclosing_function_start: enclosing_function.map(|(start, _)| start),
        enclosing_function_end: enclosing_function.map(|(_, end)| end),
        iterator_start: None,
        iterator_end: None,
        iterator_root: None,
        iterator_field: None,
        iterator_binding: None,
        iterator_binding_start: None,
        iterator_binding_end: None,
        iterator_array_global_start: None,
        iterator_array_global_end: None,
        callback_start: None,
        callback_end: None,
        callback_parameter: None,
        implicit_undefined: false,
        operation_start: None,
        operation_end: None,
        dynamic_arguments: Vec::new(),
        operation_kind: None,
        table: None,
        index: None,
        index_constraints: Vec::new(),
        order: None,
        terminal: None,
        limit: None,
        limit_argument_index: None,
        function_reference: None,
        helper_callee: None,
        helper_call_start: None,
        helper_call_end: None,
        helper_arguments: Vec::new(),
        helper_identifier_arguments: Vec::new(),
        helper_has_spread_argument: false,
        fixed_children: Vec::new(),
        shape_error: None,
        sequential_value_map_safe: false,
    };
    let Some(arguments) = call.get("arguments").and_then(Value::as_array) else {
        candidate.shape_error = Some("Promise.all has no argument list".to_string());
        return candidate;
    };
    if arguments.len() != 1 {
        candidate.shape_error =
            Some("direct Promise.all admission requires exactly one array argument".to_string());
        return candidate;
    }
    let map_call = unwrap_transparent_expression(&arguments[0]);
    if node_type(map_call).ok() == Some("ArrayExpression") {
        candidate.batch_kind = "fixedEffectArray".to_string();
        if !directly_awaited {
            candidate.shape_error = Some("fixed Promise.all must be directly awaited".to_string());
            return candidate;
        }
        let Some(elements) = map_call.get("elements").and_then(Value::as_array) else {
            candidate.shape_error = Some("fixed Promise.all array has no elements".to_string());
            return candidate;
        };
        if elements.is_empty() {
            candidate.shape_error = Some(
                "fixed Promise.all arrays must contain at least one direct effect".to_string(),
            );
            return candidate;
        }
        for element in elements {
            if element.is_null() {
                candidate.shape_error =
                    Some("fixed Promise.all arrays cannot contain holes".to_string());
                return candidate;
            }
            if node_type(element).ok() == Some("SpreadElement") {
                candidate.shape_error =
                    Some("fixed Promise.all arrays cannot contain spreads".to_string());
                return candidate;
            }
            let child = parse_direct_async_batch_fixed_child(element, database_operation_source);
            if let Some(error) = &child.shape_error
                && error
                    != "direct Promise.all fixed child helper indirection is not mechanically lowered"
            {
                candidate.shape_error = Some(error.clone());
                return candidate;
            }
            candidate.fixed_children.push(child);
        }
        return candidate;
    }
    if node_type(map_call).ok() != Some("CallExpression")
        || call_has_optional_callee(map_call)
        || call_method_name(map_call).as_deref() != Some("map")
    {
        candidate.shape_error =
            Some("direct Promise.all admission requires values.map(callback)".to_string());
        return candidate;
    }
    let Some(iterator) = map_call
        .get("callee")
        .and_then(|callee| callee.get("object"))
        .map(unwrap_transparent_expression)
    else {
        candidate.shape_error = Some("mapped Promise.all has no iterator receiver".to_string());
        return candidate;
    };
    let Ok((iterator_start, iterator_end)) = span(iterator) else {
        candidate.shape_error = Some("mapped Promise.all iterator has no source span".to_string());
        return candidate;
    };
    candidate.iterator_start = Some(iterator_start);
    candidate.iterator_end = Some(iterator_end);
    if node_type(iterator).ok() == Some("Identifier") {
        candidate.iterator_binding = identifier_name(iterator).ok();
        candidate.iterator_binding_start = Some(iterator_start);
        candidate.iterator_binding_end = Some(iterator_end);
    } else if node_type(iterator).ok() == Some("CallExpression")
        && is_static_member_call(iterator, "Array", "from")
        && let Some(arguments) = iterator.get("arguments").and_then(Value::as_array)
        && arguments.len() == 1
        && let Some(binding_expression) = arguments.first().map(unwrap_transparent_expression)
        && let Ok(binding) = identifier_name(binding_expression)
        && let Ok((binding_start, binding_end)) = span(binding_expression)
        && let Some(array_global) = iterator
            .get("callee")
            .map(unwrap_runtime_expression)
            .and_then(|callee| callee.get("object"))
            .map(unwrap_runtime_expression)
        && let Ok((array_start, array_end)) = span(array_global)
    {
        candidate.iterator_binding = Some(binding);
        candidate.iterator_binding_start = Some(binding_start);
        candidate.iterator_binding_end = Some(binding_end);
        candidate.iterator_array_global_start = Some(array_start);
        candidate.iterator_array_global_end = Some(array_end);
    } else if node_type(iterator).ok() == Some("MemberExpression")
        && !iterator
            .get("computed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        candidate.iterator_root = iterator
            .get("object")
            .map(unwrap_runtime_expression)
            .and_then(|object| identifier_name(object).ok());
        candidate.iterator_field = iterator
            .get("property")
            .and_then(|property| identifier_name(property).ok());
    }
    if candidate.iterator_binding.is_none()
        && (candidate.iterator_root.is_none() || candidate.iterator_field.is_none())
    {
        candidate.shape_error = Some(
            if let Some(helper) = resumable_batch_helper_await(map_call) {
                format!(
                    "direct Promise.all callback awaits helper {helper} and resumes afterward; helper-backed resumable children are an intentional V8 boundary"
                )
            } else {
                "direct Promise.all iterator must be a proved local array or direct validated argument array"
                .to_string()
            },
        );
        return candidate;
    }
    let Some(map_arguments) = map_call.get("arguments").and_then(Value::as_array) else {
        candidate.shape_error = Some("mapped Promise.all has no callback list".to_string());
        return candidate;
    };
    if map_arguments.len() != 1 {
        candidate.shape_error =
            Some("direct Promise.all map requires exactly one callback".to_string());
        return candidate;
    }
    let callback = unwrap_transparent_expression(&map_arguments[0]);
    if node_type(callback).ok() != Some("ArrowFunctionExpression") {
        candidate.shape_error =
            Some("direct Promise.all map callback must be an inline function".to_string());
        return candidate;
    }
    let (callback_start, callback_end) =
        span(callback).expect("Promise.all callback has a source span");
    candidate.callback_start = Some(callback_start);
    candidate.callback_end = Some(callback_end);
    candidate.sequential_value_map_safe = guest_native_sequential_value_callback(callback);
    let Some(parameters) = callback.get("params").and_then(Value::as_array) else {
        candidate.shape_error = Some("Promise.all callback has no parameter list".to_string());
        return candidate;
    };
    if parameters.len() != 1 {
        candidate.shape_error =
            Some("direct Promise.all callback requires exactly one value parameter".to_string());
        return candidate;
    }
    let Ok(parameter) = identifier_name(&parameters[0]) else {
        candidate.shape_error =
            Some("direct Promise.all callback parameter must be an identifier".to_string());
        return candidate;
    };
    candidate.callback_parameter = Some(parameter.clone());
    let Some(body) = callback.get("body") else {
        candidate.shape_error = Some("Promise.all callback has no body".to_string());
        return candidate;
    };
    if count_node_type(body, "AwaitExpression") > 1 {
        candidate.shape_error = Some(
            "direct Promise.all callback has independently resumable multiple awaits".to_string(),
        );
        return candidate;
    }
    let (returned_expression, implicit_undefined) = if node_type(body).ok()
        == Some("BlockStatement")
    {
        let Some(statements) = body.get("body").and_then(Value::as_array) else {
            candidate.shape_error =
                Some("Promise.all callback block has no statements".to_string());
            return candidate;
        };
        if statements.len() != 1 {
            candidate.shape_error = Some(
                "direct Promise.all callback must contain only one awaited Convex effect"
                    .to_string(),
            );
            return candidate;
        }
        match node_type(&statements[0]).ok() {
            Some("ReturnStatement") => {
                let Some(argument) = statements[0]
                    .get("argument")
                    .filter(|argument| !argument.is_null())
                else {
                    candidate.shape_error =
                        Some("direct Promise.all callback return has no value".to_string());
                    return candidate;
                };
                (argument, false)
            }
            Some("ExpressionStatement") => {
                let Some(expression) = statements[0].get("expression") else {
                    candidate.shape_error = Some(
                        "direct Promise.all callback expression statement has no value".to_string(),
                    );
                    return candidate;
                };
                if leading_await_count(expression) != 1 {
                    candidate.shape_error = Some(
                        "direct Promise.all implicit undefined callback must await its only Convex effect"
                            .to_string(),
                    );
                    return candidate;
                }
                (expression, true)
            }
            _ => {
                candidate.shape_error = Some(
                    "direct Promise.all callback must contain only one awaited Convex effect"
                        .to_string(),
                );
                return candidate;
            }
        }
    } else {
        (body, false)
    };
    candidate.implicit_undefined = implicit_undefined;
    if leading_await_count(returned_expression) > 1 {
        candidate.shape_error =
            Some("direct Promise.all callback cannot contain a second await".to_string());
        return candidate;
    }
    let expression = unwrap_transparent_expression(returned_expression);
    if node_type(expression).ok() != Some("CallExpression") {
        candidate.shape_error =
            Some("direct Promise.all callback must return one Convex effect".to_string());
        return candidate;
    }
    if contains_node_type(expression, "AwaitExpression") {
        candidate.shape_error =
            Some("direct Promise.all callback effect arguments cannot await".to_string());
        return candidate;
    }
    let Some(operation) = parse_db_operation_for_source(expression, "", database_operation_source)
        .or_else(|| parse_scheduler_operation(expression))
    else {
        record_direct_batch_helper_call(expression, &mut candidate);
        candidate.shape_error = Some(
            "direct Promise.all single-effect helper indirection is not mechanically lowered"
                .to_string(),
        );
        return candidate;
    };
    if implicit_undefined
        && !matches!(
            operation.kind.as_str(),
            "db.patch" | "db.replace" | "db.delete"
        )
    {
        candidate.shape_error = Some(
            "direct Promise.all implicit undefined callback requires a void Convex effect"
                .to_string(),
        );
        return candidate;
    }
    let Some(dynamic_arguments) = direct_batch_dynamic_arguments(expression, &operation) else {
        candidate.shape_error = Some(
            "direct Promise.all callback effect has unsupported dynamic arguments".to_string(),
        );
        return candidate;
    };
    if dynamic_arguments
        .iter()
        .any(|argument| !is_direct_batch_argument_expression(argument))
    {
        candidate.shape_error = Some(
            "direct Promise.all callback dynamic arguments must be synchronous effect-free expressions"
                .to_string(),
        );
        return candidate;
    }
    let dynamic_argument_ranges = dynamic_arguments
        .iter()
        .map(|argument| {
            let (start, end) =
                span(argument).expect("direct Promise.all dynamic argument has a source span");
            SourceRange { start, end }
        })
        .collect();
    candidate.operation_start = Some(operation.start);
    candidate.operation_end = Some(operation.end);
    candidate.dynamic_arguments = dynamic_argument_ranges;
    candidate.operation_kind = Some(operation.kind);
    candidate.table = operation.table;
    candidate.index = operation.index;
    candidate.index_constraints = operation.index_constraints;
    candidate.order = operation.order;
    candidate.terminal = operation.terminal;
    candidate.limit = operation.limit;
    candidate.limit_argument_index = operation.limit_argument_index;
    candidate.function_reference = operation.function_reference;
    candidate
}

fn awaited_direct_helper_name(value: &Value) -> Option<String> {
    if let Value::Object(object) = value {
        if object.get("type").and_then(Value::as_str) == Some("AwaitExpression")
            && let Some(argument) = object.get("argument").map(unwrap_runtime_expression)
            && node_type(argument).ok() == Some("CallExpression")
            && parse_db_operation(argument, "").is_none()
            && parse_scheduler_operation(argument).is_none()
            && let Some(helper) = callee_identifier(argument)
        {
            return Some(helper);
        }
        for child in object.values() {
            if let Some(helper) = awaited_direct_helper_name(child) {
                return Some(helper);
            }
        }
    } else if let Value::Array(values) = value {
        for child in values {
            if let Some(helper) = awaited_direct_helper_name(child) {
                return Some(helper);
            }
        }
    }
    None
}

fn resumable_batch_helper_await(map_call: &Value) -> Option<String> {
    let callback = map_call
        .get("arguments")?
        .as_array()?
        .first()
        .map(unwrap_runtime_expression)?;
    if !matches!(
        node_type(callback).ok(),
        Some("ArrowFunctionExpression" | "FunctionExpression")
    ) {
        return None;
    }
    let body = callback.get("body")?;
    if node_type(body).ok() != Some("BlockStatement") {
        return None;
    }
    let statements = body.get("body")?.as_array()?;
    statements
        .iter()
        .take(statements.len().saturating_sub(1))
        .find_map(awaited_direct_helper_name)
}

fn parse_direct_async_batch_fixed_child(
    value: &Value,
    database_operation_source: DatabaseOperationSource,
) -> DirectAsyncBatchFixedChildCandidate {
    let expression = unwrap_runtime_expression(value);
    let (start, end) = span(expression).expect("fixed Promise.all child has a source span");
    let mut child = DirectAsyncBatchFixedChildCandidate {
        start,
        end,
        operation_start: None,
        operation_end: None,
        dynamic_arguments: Vec::new(),
        operation_kind: None,
        table: None,
        index: None,
        index_constraints: Vec::new(),
        order: None,
        terminal: None,
        limit: None,
        limit_argument_index: None,
        function_reference: None,
        helper_callee: None,
        helper_call_start: None,
        helper_call_end: None,
        helper_arguments: Vec::new(),
        helper_identifier_arguments: Vec::new(),
        helper_has_spread_argument: false,
        shape_error: None,
    };
    if contains_node_type(expression, "AwaitExpression") {
        child.shape_error =
            Some("fixed Promise.all children and effect arguments cannot await".to_string());
        return child;
    }
    if node_type(expression).ok() != Some("CallExpression") {
        child.shape_error =
            Some("fixed Promise.all children must be direct Convex effect calls".to_string());
        return child;
    }
    let Some(operation) = parse_db_operation_for_source(expression, "", database_operation_source)
        .or_else(|| parse_scheduler_operation(expression))
    else {
        record_fixed_direct_batch_helper_call(expression, &mut child);
        child.shape_error = Some(
            "direct Promise.all fixed child helper indirection is not mechanically lowered"
                .to_string(),
        );
        return child;
    };
    let Some(dynamic_arguments) = direct_batch_dynamic_arguments(expression, &operation) else {
        child.shape_error =
            Some("fixed Promise.all child has unsupported dynamic arguments".to_string());
        return child;
    };
    if dynamic_arguments
        .iter()
        .any(|argument| !is_direct_batch_argument_expression(argument))
    {
        child.shape_error = Some(
            "fixed Promise.all child arguments must be synchronous effect-free expressions"
                .to_string(),
        );
        return child;
    }
    child.operation_start = Some(operation.start);
    child.operation_end = Some(operation.end);
    child.dynamic_arguments = dynamic_arguments
        .iter()
        .map(|argument| {
            let (start, end) =
                span(argument).expect("fixed Promise.all dynamic argument has a source span");
            SourceRange { start, end }
        })
        .collect();
    child.operation_kind = Some(operation.kind);
    child.table = operation.table;
    child.index = operation.index;
    child.index_constraints = operation.index_constraints;
    child.order = operation.order;
    child.terminal = operation.terminal;
    child.limit = operation.limit;
    child.limit_argument_index = operation.limit_argument_index;
    child.function_reference = operation.function_reference;
    child
}

fn direct_batch_helper_call(
    expression: &Value,
) -> Option<(String, Vec<SourceRange>, Vec<bool>, bool)> {
    let expression = unwrap_runtime_expression(expression);
    if node_type(expression).ok()? != "CallExpression" || call_has_optional_callee(expression) {
        return None;
    }
    let callee = callee_identifier(expression)?;
    let arguments = expression.get("arguments")?.as_array()?;
    let has_spread_argument = arguments
        .iter()
        .any(|argument| node_type(argument).ok() == Some("SpreadElement"));
    let mut ranges = Vec::with_capacity(arguments.len());
    let mut identifiers = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let argument = unwrap_transparent_expression(argument);
        let (start, end) = span(argument).ok()?;
        ranges.push(SourceRange { start, end });
        identifiers.push(node_type(argument).ok() == Some("Identifier"));
        if !is_direct_batch_argument_expression(argument) {
            return None;
        }
    }
    Some((callee, ranges, identifiers, has_spread_argument))
}

fn record_direct_batch_helper_call(expression: &Value, candidate: &mut DirectAsyncBatchCandidate) {
    if let Some((callee, arguments, identifiers, has_spread_argument)) =
        direct_batch_helper_call(expression)
    {
        candidate.helper_callee = Some(callee);
        let (start, end) = span(unwrap_runtime_expression(expression))
            .expect("direct batch helper call has a source span");
        candidate.helper_call_start = Some(start);
        candidate.helper_call_end = Some(end);
        candidate.helper_arguments = arguments;
        candidate.helper_identifier_arguments = identifiers;
        candidate.helper_has_spread_argument = has_spread_argument;
    }
}

fn record_fixed_direct_batch_helper_call(
    expression: &Value,
    candidate: &mut DirectAsyncBatchFixedChildCandidate,
) {
    if let Some((callee, arguments, identifiers, has_spread_argument)) =
        direct_batch_helper_call(expression)
    {
        candidate.helper_callee = Some(callee);
        let (start, end) = span(unwrap_runtime_expression(expression))
            .expect("fixed direct batch helper call has a source span");
        candidate.helper_call_start = Some(start);
        candidate.helper_call_end = Some(end);
        candidate.helper_arguments = arguments;
        candidate.helper_identifier_arguments = identifiers;
        candidate.helper_has_spread_argument = has_spread_argument;
    }
}

fn rejected_direct_batch_helper(message: impl Into<String>) -> DirectBatchHelperCandidate {
    DirectBatchHelperCandidate {
        operation_start: None,
        operation_end: None,
        dynamic_argument_ranges: Vec::new(),
        dynamic_parameter_indices: Vec::new(),
        capability_parameter_index: None,
        operation_kind: None,
        table: None,
        index: None,
        index_constraints: Vec::new(),
        order: None,
        terminal: None,
        limit: None,
        limit_argument_index: None,
        function_reference: None,
        function_reference_start: None,
        function_reference_end: None,
        continuation: None,
        shape_error: Some(message.into()),
    }
}

fn direct_batch_helper_argument_parameter_index(
    argument: &Value,
    parameter_names: &[String],
) -> Option<usize> {
    let mut current = unwrap_runtime_expression(argument);
    loop {
        match node_type(current).ok()? {
            "Identifier" => {
                let name = identifier_name(current).ok()?;
                return parameter_names
                    .iter()
                    .position(|parameter| parameter == &name);
            }
            "MemberExpression"
                if !current
                    .get("computed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false) =>
            {
                current = current.get("object").map(unwrap_runtime_expression)?;
            }
            _ => return None,
        }
    }
}

pub(super) fn parse_direct_batch_helper(
    function: &Value,
    database_operation_source: DatabaseOperationSource,
) -> DirectBatchHelperCandidate {
    if function.get("generator").and_then(Value::as_bool) == Some(true) {
        return rejected_direct_batch_helper(
            "direct Promise.all helper must be a non-generator function",
        );
    }
    let Some(parameters) = function.get("params").and_then(Value::as_array) else {
        return rejected_direct_batch_helper("direct Promise.all helper has no parameter list");
    };
    let mut parameter_names = Vec::with_capacity(parameters.len());
    for parameter in parameters {
        let Ok(name) = identifier_name(parameter) else {
            return rejected_direct_batch_helper(
                "direct Promise.all helper parameters must be identifiers without defaults, rest, or destructuring",
            );
        };
        parameter_names.push(name);
    }
    let Some(body) = function.get("body") else {
        return rejected_direct_batch_helper("direct Promise.all helper has no body");
    };
    if count_node_type(body, "AwaitExpression") > 1 {
        return rejected_direct_batch_helper(
            "direct Promise.all helper has independently resumable multiple awaits",
        );
    }
    let mut continuation = None;
    let (returned_expression, implicit_undefined) = if node_type(body).ok()
        == Some("BlockStatement")
    {
        let Some(statements) = body.get("body").and_then(Value::as_array) else {
            return rejected_direct_batch_helper(
                "direct Promise.all helper block has no statements",
            );
        };
        if statements.len() > 1 {
            let declaration = &statements[0];
            let Some(declarations) = declaration
                .get("declarations")
                .and_then(Value::as_array)
                .filter(|declarations| declarations.len() == 1)
                .filter(|_| node_type(declaration).ok() == Some("VariableDeclaration"))
            else {
                return rejected_direct_batch_helper(
                    "direct Promise.all helper continuation must bind its one awaited effect in the first statement",
                );
            };
            let declarator = &declarations[0];
            let Some(identifier) = declarator.get("id") else {
                return rejected_direct_batch_helper(
                    "direct Promise.all helper continuation result binding is missing",
                );
            };
            let Ok(result_binding) = identifier_name(identifier) else {
                return rejected_direct_batch_helper(
                    "direct Promise.all helper continuation result must use one identifier binding",
                );
            };
            let Some(initializer) = declarator
                .get("init")
                .map(unwrap_runtime_expression)
                .filter(|initializer| node_type(initializer).ok() == Some("AwaitExpression"))
            else {
                return rejected_direct_batch_helper(
                    "direct Promise.all helper continuation must bind its one awaited effect in the first statement",
                );
            };
            let Some(effect) = initializer.get("argument") else {
                return rejected_direct_batch_helper(
                    "direct Promise.all helper continuation await has no effect",
                );
            };
            let (body_start, body_end) =
                span(body).expect("direct Promise.all helper body has a source span");
            let (suspension_start, suspension_end) =
                span(initializer).expect("direct Promise.all helper await has a source span");
            continuation = Some(DirectBatchHelperContinuationCandidate {
                result_binding,
                body_start: body_start + 1,
                body_end: body_end - 1,
                suspension_start,
                suspension_end,
            });
            (effect, false)
        } else if statements.len() == 1 {
            match node_type(&statements[0]).ok() {
                Some("ReturnStatement") => {
                    let Some(argument) = statements[0]
                        .get("argument")
                        .filter(|argument| !argument.is_null())
                    else {
                        return rejected_direct_batch_helper(
                            "direct Promise.all helper return has no value",
                        );
                    };
                    (argument, false)
                }
                Some("ExpressionStatement") => {
                    let Some(expression) = statements[0].get("expression") else {
                        return rejected_direct_batch_helper(
                            "direct Promise.all helper expression statement has no value",
                        );
                    };
                    if leading_await_count(expression) != 1 {
                        return rejected_direct_batch_helper(
                            "direct Promise.all implicit undefined helper must await its only Convex effect",
                        );
                    }
                    (expression, true)
                }
                _ => {
                    return rejected_direct_batch_helper(
                        "direct Promise.all helper must contain only one returned or awaited Convex effect",
                    );
                }
            }
        } else {
            return rejected_direct_batch_helper(
                "direct Promise.all helper block has no statements",
            );
        }
    } else {
        (body, false)
    };
    if leading_await_count(returned_expression) > 1 {
        return rejected_direct_batch_helper(
            "direct Promise.all helper cannot contain a second await",
        );
    }
    let expression = unwrap_transparent_expression(returned_expression);
    if node_type(expression).ok() != Some("CallExpression") {
        return rejected_direct_batch_helper(
            "direct Promise.all helper must return one admitted database or scheduler effect",
        );
    }
    if contains_node_type(expression, "AwaitExpression") {
        return rejected_direct_batch_helper(
            "direct Promise.all helper effect arguments cannot await",
        );
    }
    let (operation, table_parameter_index) = if let Some(operation) =
        parse_db_operation_for_source(expression, "", database_operation_source)
            .or_else(|| parse_scheduler_operation(expression))
    {
        (operation, None)
    } else if let Some((operation, table_parameter_index)) =
        parse_callsite_specializable_database_get(expression, &parameter_names)
    {
        (operation, Some(table_parameter_index))
    } else {
        let (operation_start, operation_end) =
            span(expression).expect("direct Promise.all helper effect call has a source span");
        return DirectBatchHelperCandidate {
            operation_start: Some(operation_start),
            operation_end: Some(operation_end),
            dynamic_argument_ranges: Vec::new(),
            dynamic_parameter_indices: Vec::new(),
            capability_parameter_index: None,
            operation_kind: None,
            table: None,
            index: None,
            index_constraints: Vec::new(),
            order: None,
            terminal: None,
            limit: None,
            limit_argument_index: None,
            function_reference: None,
            function_reference_start: None,
            function_reference_end: None,
            continuation,
            shape_error: Some(
                "direct Promise.all helper effect requires one direct database or scheduler operation"
                    .to_string(),
            ),
        };
    };
    if implicit_undefined
        && !matches!(
            operation.kind.as_str(),
            "db.patch" | "db.replace" | "db.delete"
        )
    {
        return rejected_direct_batch_helper(
            "direct Promise.all implicit undefined helper requires a void Convex effect",
        );
    }
    let Some(mut dynamic_arguments) = direct_batch_dynamic_arguments(expression, &operation) else {
        return rejected_direct_batch_helper(
            "direct Promise.all helper effect has unsupported dynamic arguments",
        );
    };
    if table_parameter_index.is_some() {
        let Some(table_argument) = expression
            .get("arguments")
            .and_then(Value::as_array)
            .and_then(|arguments| arguments.first())
        else {
            return rejected_direct_batch_helper(
                "callsite-specialized database get has no table argument",
            );
        };
        dynamic_arguments.insert(0, table_argument);
    }
    let mut dynamic_argument_ranges = Vec::with_capacity(dynamic_arguments.len());
    let mut dynamic_parameter_indices = Vec::with_capacity(dynamic_arguments.len());
    for argument in dynamic_arguments {
        let argument = unwrap_runtime_expression(argument);
        if !is_direct_batch_argument_expression(argument) {
            return rejected_direct_batch_helper(
                "direct Promise.all helper dynamic arguments must be synchronous effect-free expressions",
            );
        }
        let Some(index) = direct_batch_helper_argument_parameter_index(argument, &parameter_names)
        else {
            return rejected_direct_batch_helper(
                "direct Promise.all helper dynamic arguments must be rooted in one direct parameter",
            );
        };
        if continuation.is_none()
            && identifier_name(argument).ok() != Some(parameter_names[index].clone())
        {
            return rejected_direct_batch_helper(
                "direct Promise.all helper without a continuation requires exact parameter identifiers for its dynamic effect arguments",
            );
        }
        if continuation.is_none() && dynamic_parameter_indices.contains(&index) {
            return rejected_direct_batch_helper(
                "direct Promise.all helper cannot duplicate a caller argument",
            );
        }
        let (start, end) = span(argument).expect("helper dynamic argument has a source span");
        dynamic_argument_ranges.push(SourceRange { start, end });
        dynamic_parameter_indices.push(index);
    }
    if !dynamic_parameter_indices
        .windows(2)
        .all(|pair| pair[0] <= pair[1])
    {
        return rejected_direct_batch_helper(
            "direct Promise.all helper cannot reorder caller arguments",
        );
    }
    let Some(effect_path) = operation.effect_path.as_deref() else {
        return rejected_direct_batch_helper(
            "direct Promise.all helper effect has no owned capability path",
        );
    };
    let capability_name = effect_path.split('.').next().unwrap_or(effect_path);
    let Some(capability_parameter_index) = parameter_names
        .iter()
        .position(|parameter| parameter == capability_name)
    else {
        return rejected_direct_batch_helper(
            "direct Promise.all helper effect must use one direct capability parameter",
        );
    };
    if dynamic_parameter_indices.contains(&capability_parameter_index) {
        return rejected_direct_batch_helper(
            "direct Promise.all helper capability cannot also provide a dynamic effect argument",
        );
    }
    if continuation.is_none()
        && (0..parameter_names.len()).any(|index| {
            index != capability_parameter_index && !dynamic_parameter_indices.contains(&index)
        })
    {
        return rejected_direct_batch_helper(
            "direct Promise.all helper arguments must map exactly to its capability and effect parameters",
        );
    }
    DirectBatchHelperCandidate {
        operation_start: Some(operation.start),
        operation_end: Some(operation.end),
        dynamic_argument_ranges,
        dynamic_parameter_indices,
        capability_parameter_index: Some(capability_parameter_index),
        operation_kind: Some(operation.kind),
        table: operation.table,
        index: operation.index,
        index_constraints: operation.index_constraints,
        order: operation.order,
        terminal: operation.terminal,
        limit: operation.limit,
        limit_argument_index: operation.limit_argument_index,
        function_reference: operation.function_reference,
        function_reference_start: operation.function_reference_start,
        function_reference_end: operation.function_reference_end,
        continuation,
        shape_error: None,
    }
}

fn guest_native_sequential_value_callback(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some(
                    "AssignmentExpression"
                        | "AwaitExpression"
                        | "CallExpression"
                        | "ImportExpression"
                        | "NewExpression"
                        | "TaggedTemplateExpression"
                        | "UpdateExpression"
                        | "YieldExpression"
                )
            ) || object.get("async").and_then(Value::as_bool) == Some(true)
            {
                return false;
            }
            object.values().all(guest_native_sequential_value_callback)
        }
        Value::Array(values) => values.iter().all(guest_native_sequential_value_callback),
        _ => true,
    }
}

fn is_direct_batch_argument_expression(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some(
                    "AssignmentExpression"
                        | "AwaitExpression"
                        | "CallExpression"
                        | "ClassExpression"
                        | "FunctionExpression"
                        | "ArrowFunctionExpression"
                        | "ImportExpression"
                        | "NewExpression"
                        | "TaggedTemplateExpression"
                        | "UpdateExpression"
                        | "YieldExpression"
                )
            ) {
                return false;
            }
            object.values().all(is_direct_batch_argument_expression)
        }
        Value::Array(values) => values.iter().all(is_direct_batch_argument_expression),
        _ => true,
    }
}

pub(super) fn direct_batch_dynamic_arguments<'a>(
    call: &'a Value,
    operation: &OperationCandidate,
) -> Option<Vec<&'a Value>> {
    let call = unwrap_runtime_expression(call);
    let arguments = call.get("arguments")?.as_array()?;
    if callee_identifier(call)
        .as_deref()
        .is_some_and(|callee| callee.starts_with("__convexDependencyAdapter_databaseIndex"))
    {
        return Some(vec![arguments.get(3)?]);
    }
    if operation.kind == "functionHandleCreate" {
        return Some(vec![arguments.first()?]);
    }
    match operation.kind.as_str() {
        "db.normalizeId" | "db.get" | "db.delete" => Some(vec![arguments.get(1)?]),
        "db.insert" => Some(vec![arguments.get(1)?]),
        "db.patch" | "db.replace" => Some(vec![arguments.get(1)?, arguments.get(2)?]),
        "scheduler.runAfter" | "scheduler.runAt" => {
            Some(vec![arguments.first()?, arguments.get(2)?])
        }
        "db.query" => {
            let mut current = call;
            loop {
                if call_method_name(current).as_deref() == Some("withIndex") {
                    let callback = current
                        .get("arguments")?
                        .as_array()?
                        .get(1)
                        .map(unwrap_runtime_expression)?;
                    let mut dynamic_arguments = parse_index_constraints(callback)?
                        .into_iter()
                        .map(|item| item.value)
                        .collect::<Vec<_>>();
                    if let Some(limit_argument_index) = operation.limit_argument_index {
                        if usize::try_from(limit_argument_index).ok()
                            != Some(dynamic_arguments.len())
                        {
                            return None;
                        }
                        dynamic_arguments.push(arguments.first()?);
                    }
                    return Some(dynamic_arguments);
                }
                current = current
                    .get("callee")
                    .map(unwrap_runtime_expression)?
                    .get("object")
                    .map(unwrap_runtime_expression)?;
                if node_type(current).ok()? != "CallExpression" {
                    return None;
                }
            }
        }
        _ => None,
    }
}

struct ResolvedDirectBatchHelper {
    target_module: String,
    target_unit_id: String,
    target_binding: String,
    target_parameters: Vec<String>,
    target_source_sha256: String,
    target_operation: AdmittedOperation,
    helper: DirectBatchHelperCandidate,
    dependency_adapter_continuation: Option<DirectBatchHelperDependencyAdapterContinuation>,
}

struct DirectBatchHelperRejection {
    message: String,
    module: String,
    start: u32,
    dependency_chain: Vec<String>,
}

fn direct_batch_continuation_call_rejection(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    dependency_adapter_calls: &DependencyAdapterCallIndex<'_>,
    target: &ReachableUnit,
    helper: &DirectBatchHelperCandidate,
) -> Result<Option<String>> {
    let Some(continuation) = &helper.continuation else {
        return Ok(None);
    };
    let operation_span = helper
        .operation_start
        .zip(helper.operation_end)
        .context("continuation helper has no operation span")?;
    let mut pending = VecDeque::new();
    let target_module = modules
        .get(&target.module)
        .context("continuation helper module disappeared")?;
    for call in target_module.summary.calls.iter().filter(|call| {
        call.start >= continuation.body_start
            && call.end <= continuation.body_end
            && (call.start < operation_span.0 || call.end > operation_span.1)
    }) {
        pending.push_back((target.module.clone(), call.callee.clone()));
    }
    let mut visited = BTreeSet::new();
    while let Some((caller_module, callee)) = pending.pop_front() {
        let Some((module, name)) =
            resolve_static_source_target(graph, modules, &caller_module, &callee)?
        else {
            return Ok(Some(format!(
                "direct Promise.all helper continuation call {callee} is not one static source function"
            )));
        };
        if !visited.insert((module.clone(), name.clone())) {
            continue;
        }
        let Some(unit) = reachable
            .values()
            .find(|unit| unit.module == module && unit.name == name)
        else {
            return Ok(Some(format!(
                "direct Promise.all helper continuation call {callee} is not one reachable source function"
            )));
        };
        let summary = modules
            .get(&module)
            .context("continuation dependency module disappeared")?;
        let suspends = summary.summary.constructs.iter().any(|construct| {
            construct.start >= unit.start
                && construct.end <= unit.end
                && matches!(
                    construct.kind.as_str(),
                    "AwaitExpression" | "YieldExpression"
                )
        }) || summary
            .summary
            .direct_async_batches
            .iter()
            .any(|batch| batch.start >= unit.start && batch.end <= unit.end);
        let has_operation = summary
            .summary
            .operations
            .iter()
            .any(|operation| operation.start >= unit.start && operation.end <= unit.end)
            || !dependency_adapter_calls
                .calls_for(&module, &unit.id)
                .is_empty();
        if suspends || has_operation {
            return Ok(Some(format!(
                "direct Promise.all helper continuation call {callee} suspends or performs a Convex effect"
            )));
        }
        for call in summary
            .summary
            .calls
            .iter()
            .filter(|call| call.start >= unit.start && call.end <= unit.end)
        {
            pending.push_back((module.clone(), call.callee.clone()));
        }
    }
    Ok(None)
}

#[expect(clippy::too_many_arguments)]
fn resolve_direct_batch_helper(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    dependency_adapter_calls: &DependencyAdapterCallIndex<'_>,
    admitted_operation_identities: &BTreeSet<OperationIdentity>,
    operations: &[AdmittedOperation],
    caller: &ReachableUnit,
    call_start: u32,
    call_end: u32,
    callee: Option<&str>,
    arguments: &[SourceRange],
    identifier_arguments: &[bool],
    has_spread_argument: bool,
) -> Result<Result<ResolvedDirectBatchHelper, DirectBatchHelperRejection>> {
    let caller_rejection = |message: String| DirectBatchHelperRejection {
        message,
        module: caller.module.clone(),
        start: call_start,
        dependency_chain: caller.dependency_chain.clone(),
    };
    let Some(callee) = callee else {
        return Ok(Err(caller_rejection(
            "direct Promise.all helper call must use one direct local or imported binding"
                .to_string(),
        )));
    };
    if has_spread_argument {
        return Ok(Err(caller_rejection(format!(
            "direct Promise.all helper {callee} does not allow spread arguments"
        ))));
    }
    let caller_module = modules
        .get(&caller.module)
        .context("direct batch helper caller module disappeared")?;
    let matching_calls = caller_module
        .summary
        .calls
        .iter()
        .filter(|call| {
            call.start == call_start
                && call.end == call_end
                && call.callee == callee
                && call
                    .arguments
                    .iter()
                    .map(|argument| (argument.start, argument.end))
                    .eq(arguments
                        .iter()
                        .map(|argument| (argument.start, argument.end)))
        })
        .count();
    if matching_calls != 1 {
        return Ok(Err(caller_rejection(format!(
            "direct Promise.all helper {callee} call is ambiguous or not a direct static source call"
        ))));
    }
    let Some((target_module, target_name)) =
        resolve_static_source_target(graph, modules, &caller.module, callee)?
    else {
        return Ok(Err(caller_rejection(format!(
            "direct Promise.all helper {callee} does not resolve to one local or imported source function"
        ))));
    };
    let Some(target) = reachable
        .values()
        .find(|unit| unit.module == target_module && unit.name == target_name)
    else {
        return Ok(Err(caller_rejection(format!(
            "direct Promise.all helper {callee} is not one authenticated reachable source unit"
        ))));
    };
    let target_module_summary = modules
        .get(&target.module)
        .context("direct batch helper target module disappeared")?;
    let target_source_unit = target_module_summary
        .summary
        .units
        .get(&target.name)
        .context("direct batch helper target unit disappeared")?;
    let target_rejection = |message: String| DirectBatchHelperRejection {
        message,
        module: target.module.clone(),
        start: target.start,
        dependency_chain: target.dependency_chain.clone(),
    };
    let Some(mut helper) = target_source_unit.direct_batch_helper.clone() else {
        return Ok(Err(target_rejection(format!(
            "direct Promise.all helper {callee} is not a function declaration or function-valued binding"
        ))));
    };
    let helper_uses_dependency_adapter = helper.shape_error.as_deref()
        == Some(
            "direct Promise.all helper effect requires one direct database or scheduler operation",
        )
        && helper
            .operation_start
            .zip(helper.operation_end)
            .and_then(|(start, end)| dependency_adapter_calls.call_at(&target.module, start, end))
            .filter(|call| {
                matches!(
                    call.descriptor.semantic.kind.as_str(),
                    "databaseIndexCollect"
                        | "databaseIndexUnique"
                        | "databaseIndexUniqueOrThrow"
                        | "functionHandleCreate"
                )
            })
            .map(|call| {
                let dynamic_parameter_indices = call
                    .dynamic_arguments
                    .iter()
                    .map(|argument| {
                        let matches = target_source_unit
                            .parameters
                            .iter()
                            .filter(|parameter| {
                                parameter.references.iter().any(|reference| {
                                    reference.read
                                        && !reference.write
                                        && reference.start >= argument.start
                                        && reference.end <= argument.end
                                })
                            })
                            .map(|parameter| parameter.index)
                            .collect::<Vec<_>>();
                        let [parameter_index] = matches.as_slice() else {
                            return None;
                        };
                        Some(*parameter_index)
                    })
                    .collect::<Option<Vec<_>>>()?;
                let capability_parameters = target_source_unit
                    .parameters
                    .iter()
                    .filter(|parameter| {
                        parameter.references.iter().any(|reference| {
                            reference.read
                                && !reference.write
                                && reference.start >= call.effect_start
                                && reference.end <= call.effect_end
                        })
                    })
                    .map(|parameter| parameter.index)
                    .collect::<Vec<_>>();
                let capability_parameters_are_valid =
                    if call.descriptor.semantic.kind == "functionHandleCreate" {
                        capability_parameters.is_empty()
                    } else {
                        capability_parameters.len() == 1
                            && !dynamic_parameter_indices.contains(&capability_parameters[0])
                    };
                if !capability_parameters_are_valid {
                    return None;
                }
                helper.dynamic_argument_ranges = call.dynamic_arguments.clone();
                helper.dynamic_parameter_indices = dynamic_parameter_indices;
                helper.capability_parameter_index = capability_parameters.first().copied();
                helper.operation_kind = Some(call.operation.kind.clone());
                helper.table = call.operation.table.clone();
                helper.index = call.operation.index.clone();
                helper.index_constraints = call.operation.index_constraints.clone();
                helper.order = call.operation.order.clone();
                helper.terminal = call.operation.terminal.clone();
                helper.limit = call.operation.limit;
                helper.limit_argument_index = call.operation.limit_argument_index;
                helper.function_reference = call.operation.function_reference.clone();
                helper.function_reference_start = call.operation.function_reference_start;
                helper.function_reference_end = call.operation.function_reference_end;
                helper.shape_error = None;
                Some(())
            })
            .flatten()
            .is_some();
    let dependency_adapter_continuation = if helper_uses_dependency_adapter {
        let call = helper
            .operation_start
            .zip(helper.operation_end)
            .and_then(|(start, end)| dependency_adapter_calls.call_at(&target.module, start, end))
            .context("resolved direct batch helper dependency adapter disappeared")?;
        if call.descriptor.semantic.kind == "databaseIndexUniqueOrThrow" {
            let table = call
                .operation
                .table
                .clone()
                .context("unique-or-throw adapter operation has no table")?;
            let [constraint] = call.operation.index_constraints.as_slice() else {
                bail!("unique-or-throw adapter operation must have one index constraint");
            };
            Some(DirectBatchHelperDependencyAdapterContinuation {
                table,
                field: constraint.field.clone(),
            })
        } else {
            None
        }
    } else {
        None
    };
    if let Some(message) = &helper.shape_error {
        let message = if message
            == "direct Promise.all helper effect requires one direct database or scheduler operation"
        {
            "direct Promise.all helper must directly perform one database or scheduler effect; nested suspending helpers and nested batches are unsupported"
        } else {
            message
        };
        return Ok(Err(target_rejection(format!(
            "direct Promise.all helper {callee} is unsupported: {message}"
        ))));
    }
    if dependency_adapter_continuation.is_some() && helper.continuation.is_none() {
        return Ok(Err(target_rejection(format!(
            "direct Promise.all helper {callee} unique-or-throw adapter requires one modeled synchronous source continuation"
        ))));
    }
    if arguments.len() != target_source_unit.parameters.len()
        || identifier_arguments.len() != arguments.len()
    {
        return Ok(Err(caller_rejection(format!(
            "direct Promise.all helper {callee} arguments do not map exactly to its parameters"
        ))));
    }
    let capability_parameter_index = helper
        .capability_parameter_index
        .context("valid direct batch helper has no capability parameter")?;
    if !identifier_arguments[capability_parameter_index] {
        return Ok(Err(caller_rejection(format!(
            "direct Promise.all helper {callee} capability argument must be one direct owned identifier"
        ))));
    }
    let operation_start = helper
        .operation_start
        .context("valid direct batch helper has no operation start")?;
    let operation_end = helper
        .operation_end
        .context("valid direct batch helper has no operation end")?;
    let matching_operations = target_module_summary
        .summary
        .operations
        .iter()
        .filter(|operation| operation.start >= target.start && operation.end <= target.end)
        .collect::<Vec<_>>();
    if (!helper_uses_dependency_adapter
        && (matching_operations.len() != 1
            || matching_operations[0].start != operation_start
            || matching_operations[0].end != operation_end))
        || (helper_uses_dependency_adapter && !matching_operations.is_empty())
    {
        return Ok(Err(target_rejection(format!(
            "direct Promise.all helper {callee} must contain exactly one database or scheduler effect"
        ))));
    }
    for parameter in &target_source_unit.parameters {
        if parameter
            .references
            .iter()
            .any(|reference| !reference.read || reference.write)
        {
            return Ok(Err(target_rejection(format!(
                "direct Promise.all helper {callee} parameter {} cannot be written or used as a non-read reference",
                parameter.name
            ))));
        }
        let effect_references = parameter
            .references
            .iter()
            .filter(|reference| {
                reference.start >= operation_start && reference.end <= operation_end
            })
            .collect::<Vec<_>>();
        let expected_effect_ranges = helper
            .dynamic_parameter_indices
            .iter()
            .zip(&helper.dynamic_argument_ranges)
            .filter_map(|(index, range)| (*index == parameter.index).then_some(range))
            .collect::<Vec<_>>();
        let effect_references_are_valid = if parameter.index == capability_parameter_index {
            effect_references.len() == 1
        } else {
            effect_references.len() == expected_effect_ranges.len()
                && effect_references.iter().zip(expected_effect_ranges).all(
                    |(reference, expected)| {
                        reference.start >= expected.start && reference.end <= expected.end
                    },
                )
        };
        let continuation_references_are_valid = helper.continuation.as_ref().is_some_and(|body| {
            parameter.references.iter().all(|reference| {
                (reference.start >= operation_start && reference.end <= operation_end)
                    || (reference.start >= body.body_start && reference.end <= body.body_end)
            })
        });
        if !effect_references_are_valid
            || (helper.continuation.is_none()
                && parameter.references.len() != effect_references.len())
            || (helper.continuation.is_some() && !continuation_references_are_valid)
        {
            return Ok(Err(target_rejection(format!(
                "direct Promise.all helper {callee} parameter {} is not confined to its effect and synchronous continuation",
                parameter.name
            ))));
        }
    }
    for reference in target_module_summary
        .summary
        .references
        .iter()
        .filter(|reference| reference.start >= operation_start && reference.end <= operation_end)
    {
        let represented_function_reference = helper
            .function_reference_start
            .zip(helper.function_reference_end)
            .is_some_and(|(start, end)| reference.start >= start && reference.end <= end);
        if !represented_function_reference && !helper_uses_dependency_adapter {
            return Ok(Err(target_rejection(format!(
                "direct Promise.all helper {callee} effect captures unsupported binding {}",
                reference.name
            ))));
        }
    }
    if target_module_summary
        .summary
        .globals
        .iter()
        .any(|global| global.start >= operation_start && global.end <= operation_end)
    {
        return Ok(Err(target_rejection(format!(
            "direct Promise.all helper {callee} effect captures an unsupported runtime global"
        ))));
    }
    if let Some(message) = direct_batch_continuation_call_rejection(
        graph,
        modules,
        reachable,
        dependency_adapter_calls,
        target,
        &helper,
    )? {
        return Ok(Err(target_rejection(format!(
            "direct Promise.all helper {callee} is unsupported: {message}"
        ))));
    }

    let mut static_targets = StaticSourceTargetCache::new();
    let target_identity = (target.module.clone(), target.name.clone());
    for owner in reachable.values() {
        let owner_module = modules
            .get(&owner.module)
            .context("reachable helper reference owner module disappeared")?;
        for reference in owner_module.summary.references.iter().filter(|reference| {
            reference.read
                && !reference.write
                && reference.start >= owner.start
                && reference.end <= owner.end
        }) {
            if cached_static_source_target(
                graph,
                modules,
                &mut static_targets,
                &owner.module,
                &reference.name,
            )?
            .as_ref()
                != Some(&target_identity)
            {
                continue;
            }
            let direct_call_count = owner_module
                .summary
                .calls
                .iter()
                .filter(|call| {
                    call.callee_start == reference.start
                        && call.callee_end == reference.end
                        && call.start >= owner.start
                        && call.end <= owner.end
                })
                .count();
            if direct_call_count != 1 {
                return Ok(Err(target_rejection(format!(
                    "direct Promise.all helper {callee} escapes or has an ambiguous reference"
                ))));
            }
        }
    }
    let helper_operation_identity = (target.module.clone(), operation_start, operation_end);
    if !admitted_operation_identities.contains(&helper_operation_identity) {
        return Ok(Err(target_rejection(format!(
            "direct Promise.all helper {callee} effect is not one admitted owned Convex operation"
        ))));
    }
    let target_operation = operations
        .iter()
        .find(|operation| {
            operation.file == target.module
                && operation.start == operation_start
                && operation.end == operation_end
        })
        .context("admitted direct batch helper operation was not emitted")?
        .clone();
    Ok(Ok(ResolvedDirectBatchHelper {
        target_module,
        target_unit_id: target.id.clone(),
        target_binding: target.name.clone(),
        target_parameters: target_source_unit
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone())
            .collect(),
        target_source_sha256: hash_bytes(target.source.as_bytes()),
        target_operation,
        helper,
        dependency_adapter_continuation,
    }))
}

fn push_direct_batch_helper_alias_operation(
    modules: &BTreeMap<String, LoadedModule>,
    operations: &mut Vec<AdmittedOperation>,
    caller: &ReachableUnit,
    call_start: u32,
    call_end: u32,
    helper: &ResolvedDirectBatchHelper,
) -> Result<AdmittedOperation> {
    let source = module_source(modules, &caller.module)?;
    let call_source = source_slice(&source, call_start, call_end)?.to_string();
    let semantic_key = serde_json::to_string(&(
        "direct-batch-helper-call",
        &caller.id,
        call_start,
        call_end,
        &helper.target_module,
        &helper.target_unit_id,
        &helper.target_operation.stable_key,
    ))?;
    let (line, column) = line_column(&source, call_start);
    let mut operation = helper.target_operation.clone();
    operation.id = u32::try_from(operations.len() + 1)?;
    operation.stable_key = format!("op_{}", &hash_bytes(semantic_key.as_bytes())[..16]);
    operation.file = caller.module.clone();
    operation.start = call_start;
    operation.end = call_end;
    operation.line = line;
    operation.column = column;
    operation.source = call_source;
    operations.push(operation.clone());
    Ok(operation)
}

fn adapt_mapped_leaf_plan_candidate(
    modules: &BTreeMap<String, LoadedModule>,
    plans: &CallableEffectPlanIndex,
    authorized_effect_sites: &AuthorizedEffectSiteIndex,
    operations: &mut Vec<AdmittedOperation>,
    caller: &ReachableUnit,
    site: &PromiseAllSiteCandidate,
    candidate: &DirectAsyncBatchCandidate,
) -> Result<
    Option<(
        DirectAsyncBatchCandidate,
        Option<DirectBatchHelperAuthorizationMetadata>,
    )>,
> {
    if candidate.batch_kind != "singleEffectMap" {
        return Ok(None);
    }
    if candidate.shape_error.is_some()
        && candidate.shape_error.as_deref()
            != Some(
                "direct Promise.all single-effect helper indirection is not mechanically lowered",
            )
    {
        return Ok(None);
    }
    if candidate.implicit_undefined {
        return Ok(None);
    }
    let Some((callback_start, callback_end)) = candidate.callback_start.zip(candidate.callback_end)
    else {
        return Ok(None);
    };
    let Some((argument_start, argument_end)) = site.argument_start.zip(site.argument_end) else {
        return Ok(None);
    };
    if site.start != candidate.start
        || site.end != candidate.end
        || callback_start < argument_start
        || callback_end > argument_end
    {
        return Ok(None);
    }
    let Some(control_plan) =
        plans.control_plan_for_callable(&caller.module, callback_start, callback_end)
    else {
        return Ok(None);
    };
    let Some(plan) = control_plan.current_batch_leaf() else {
        return Ok(None);
    };
    if plan.effect_key.operation_kind != "databaseGet"
        || plan.effect_key.timing != super::effect_plan::SemanticEffectTiming::Suspending
        || plan.dynamic_operands.len() != 1
        || plan
            .dynamic_operands
            .iter()
            .any(|operand| operand.is_target_only())
    {
        return Ok(None);
    }
    let dynamic_arguments = plan
        .dynamic_operands
        .iter()
        .map(|operand| {
            let consumer_provenance = operand
                .consumer_provenance()
                .context("consumer-projectable callable effect operand lost its caller anchor")?;
            Ok(SourceRange {
                start: consumer_provenance.start,
                end: consumer_provenance.end,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let helper_projection = if let Some(callsite) = &plan.provenance.caller_callsite {
        if callsite.module != caller.module
            || candidate.helper_call_start != Some(callsite.start)
            || candidate.helper_call_end != Some(callsite.end)
        {
            return Ok(None);
        }
        let Some(callee) = candidate.helper_callee.clone() else {
            return Ok(None);
        };
        let dynamic_argument_indices = plan
            .dynamic_operands
            .iter()
            .map(|operand| {
                let consumer_provenance = operand.consumer_provenance().context(
                    "consumer-projectable callable effect operand lost its caller anchor",
                )?;
                candidate
                    .helper_arguments
                    .iter()
                    .position(|argument| {
                        argument.start == consumer_provenance.start
                            && argument.end == consumer_provenance.end
                    })
                    .context("callable effect plan operand does not map to one helper argument")
            })
            .collect::<Result<Vec<_>>>()?;
        Some((callee, dynamic_argument_indices))
    } else {
        None
    };
    let consumer = plan.consumer_site();
    if authorized_effect_sites.plan_at_site(&consumer.module, consumer.start, consumer.end)
        != Some(plan)
    {
        return Ok(None);
    }
    let Some(materialized) = materialize_authorized_batch_site(
        modules,
        authorized_effect_sites,
        operations,
        &consumer.module,
        consumer.start,
        consumer.end,
    )?
    else {
        return Ok(None);
    };
    let target_operation = operations
        .iter()
        .find(|operation| operation.id == materialized.operation_id)
        .context("authorized mapped batch operation was not materialized")?
        .clone();
    anyhow::ensure!(
        target_operation.file == consumer.module
            && target_operation.start == materialized.operation_span.start
            && target_operation.end == materialized.operation_span.end,
        "authorized mapped batch operation conflicts with its semantic consumer site"
    );
    let mut adapted = candidate.clone();
    adapted.shape_error = None;
    adapted.dynamic_arguments = dynamic_arguments;
    adapted.operation_start = Some(materialized.operation_span.start);
    adapted.operation_end = Some(materialized.operation_span.end);
    adapted.operation_kind =
        Some(direct_batch_candidate_operation_kind(&target_operation)?.to_string());
    adapted.table = target_operation.table.clone();
    adapted.index = target_operation.index.clone();
    adapted.index_constraints.clear();
    adapted.order = target_operation.order.clone();
    adapted.terminal = target_operation.terminal.clone();
    adapted.limit = target_operation.limit;
    adapted.limit_argument_index = target_operation.limit_argument_index;
    adapted.function_reference = target_operation.function_reference.clone();
    let helper_metadata = helper_projection.map(|(callee, dynamic_argument_indices)| {
        DirectBatchHelperAuthorizationMetadata {
            callee,
            dynamic_argument_indices,
            operation_id: materialized.operation_id,
            continuation: None,
        }
    });
    Ok(Some((adapted, helper_metadata)))
}

pub(super) fn authorize_direct_async_batches(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    registration: &RegistrationSummary,
    dependency_adapter_calls: &DependencyAdapterCallIndex<'_>,
    admitted_operation_identities: &BTreeSet<OperationIdentity>,
    callable_effect_plans: &CallableEffectPlanIndex,
    authorized_effect_sites: &AuthorizedEffectSiteIndex,
    operations: &mut Vec<AdmittedOperation>,
    value_mode: ValueMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<DirectAsyncBatchAuthorization>> {
    let mut authorizations = Vec::new();
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("reachable direct async batch module disappeared")?;
        let source = module_source(modules, &unit.module)?;
        let adapter_calls = dependency_adapter_calls.calls_for(&unit.module, &unit.id);
        for original_candidate in module
            .summary
            .direct_async_batches
            .iter()
            .filter(|candidate| candidate.start >= unit.start && candidate.end <= unit.end)
        {
            let mut matching_sites = module.summary.promise_all_sites.iter().filter(|site| {
                site.start == original_candidate.start && site.end == original_candidate.end
            });
            let promise_site = match (matching_sites.next(), matching_sites.next()) {
                (Some(site), None) => site,
                _ => {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-direct-promise-all",
                        "Promise.all consumer site is missing or ambiguous".to_string(),
                        &unit.module,
                        original_candidate.start,
                        Some("Promise.all".to_string()),
                        unit.dependency_chain.clone(),
                    )?);
                    continue;
                }
            };
            let unshadowed_global = module.summary.globals.iter().any(|global| {
                global.name == "Promise"
                    && global.read
                    && !global.write
                    && global.start == promise_site.promise_start
                    && global.end == promise_site.promise_end
            });
            if original_candidate.batch_kind == "fixedEffectArray" {
                let rejection = if !unshadowed_global {
                    Some("direct Promise.all requires the unshadowed global Promise".to_string())
                } else if let Some(shape_error) = &original_candidate.shape_error {
                    Some(shape_error.clone())
                } else {
                    original_candidate
                        .fixed_children
                        .iter()
                        .find_map(|child| {
                            child.shape_error.as_ref().and_then(|message| {
                                (message
                                    != "direct Promise.all fixed child helper indirection is not mechanically lowered")
                                    .then(|| message.clone())
                            })
                        })
                };
                if let Some(message) = rejection {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-direct-promise-all",
                        message,
                        &unit.module,
                        original_candidate.start,
                        Some("Promise.all".to_string()),
                        unit.dependency_chain.clone(),
                    )?);
                    continue;
                }
                let Some(fixed_plan) = callable_effect_plans
                    .effect_value_graph()
                    .fixed_promise_all_plan(
                        &unit.module,
                        original_candidate.start,
                        original_candidate.end,
                    )
                else {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-direct-promise-all",
                        "fixed Promise.all has no complete ordered plan in the authenticated callable value graph".to_string(),
                        &unit.module,
                        original_candidate.start,
                        Some("Promise.all".to_string()),
                        unit.dependency_chain.clone(),
                    )?);
                    continue;
                };
                let graph_plan_matches = fixed_plan.site.module == unit.module
                    && fixed_plan.site.start == original_candidate.start
                    && fixed_plan.site.end == original_candidate.end
                    && fixed_plan.promise.start == promise_site.promise_start
                    && fixed_plan.promise.end == promise_site.promise_end
                    && Some(fixed_plan.argument.start) == promise_site.argument_start
                    && Some(fixed_plan.argument.end) == promise_site.argument_end
                    && fixed_plan.children.len() == original_candidate.fixed_children.len()
                    && fixed_plan
                        .children
                        .iter()
                        .zip(&original_candidate.fixed_children)
                        .enumerate()
                        .all(|(index, (planned, child))| {
                            planned.child_index == index
                                && planned.child.module == unit.module
                                && planned.child.start == child.start
                                && planned.child.end == child.end
                        });
                if !graph_plan_matches {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-direct-promise-all",
                        "fixed Promise.all lowering shape conflicts with its authenticated ordered plan".to_string(),
                        &unit.module,
                        original_candidate.start,
                        Some("Promise.all".to_string()),
                        unit.dependency_chain.clone(),
                    )?);
                    continue;
                }

                let mut authenticated_children =
                    Vec::with_capacity(original_candidate.fixed_children.len());
                let mut child_authentication_failed = false;
                for (planned_child, child) in fixed_plan
                    .children
                    .iter()
                    .zip(&original_candidate.fixed_children)
                {
                    let origin_plan = match &planned_child.origin {
                        AuthenticatedFixedPromiseAllChildOrigin::EffectSite { plan } => Some(plan),
                        AuthenticatedFixedPromiseAllChildOrigin::CallResult { .. } => None,
                    };
                    if let Some(projected_plan) =
                        authorized_effect_sites.plan_at_site(&unit.module, child.start, child.end)
                    {
                        if origin_plan
                            .is_some_and(|origin| !projected_plan.same_target_effect(origin))
                        {
                            diagnostics.push(diagnostic_at(
                                graph,
                                modules,
                                "unsupported-direct-promise-all",
                                "fixed Promise.all effect projection conflicts with its exact target-side plan provenance".to_string(),
                                &unit.module,
                                child.start,
                                Some("Promise.all child".to_string()),
                                unit.dependency_chain.clone(),
                            )?);
                            child_authentication_failed = true;
                            break;
                        }
                        let Some(alias) = materialize_authorized_batch_site(
                            modules,
                            authorized_effect_sites,
                            operations,
                            &unit.module,
                            child.start,
                            child.end,
                        )?
                        else {
                            child_authentication_failed = true;
                            break;
                        };
                        let dynamic_arguments = alias
                            .arguments
                            .iter()
                            .map(|argument| SourceRange {
                                start: argument.start,
                                end: argument.end,
                            })
                            .collect::<Vec<_>>();
                        let helper_metadata = if child.shape_error.as_deref()
                            == Some(
                                "direct Promise.all fixed child helper indirection is not mechanically lowered",
                            ) {
                            let resolved = resolve_direct_batch_helper(
                                graph,
                                modules,
                                reachable,
                                dependency_adapter_calls,
                                admitted_operation_identities,
                                operations,
                                unit,
                                child.start,
                                child.end,
                                child.helper_callee.as_deref(),
                                &child.helper_arguments,
                                &child.helper_identifier_arguments,
                                child.helper_has_spread_argument,
                            )?;
                            let resolved = match resolved {
                                Ok(resolved) => resolved,
                                Err(rejected) => {
                                    diagnostics.push(diagnostic_at(
                                        graph,
                                        modules,
                                        "unsupported-direct-promise-all",
                                        rejected.message,
                                        &rejected.module,
                                        rejected.start,
                                        Some("helper".to_string()),
                                        rejected.dependency_chain,
                                    )?);
                                    child_authentication_failed = true;
                                    break;
                                }
                            };
                            let target = &projected_plan.provenance.target_effect;
                            if resolved.target_operation.file != target.module
                                || resolved.target_operation.start != target.start
                                || resolved.target_operation.end != target.end
                                || resolved.target_operation.kind
                                    != projected_plan.effect_key.operation_kind
                            {
                                diagnostics.push(diagnostic_at(
                                    graph,
                                    modules,
                                    "unsupported-direct-promise-all",
                                    "fixed Promise.all helper continuation does not suspend at its authorized target effect".to_string(),
                                    &unit.module,
                                    child.start,
                                    Some("helper".to_string()),
                                    unit.dependency_chain.clone(),
                                )?);
                                child_authentication_failed = true;
                                break;
                            }
                            Some(planned_direct_batch_helper_authorization_metadata(
                                child
                                    .helper_callee
                                    .clone()
                                    .expect("resolved helper has no callee"),
                                child.helper_arguments.clone(),
                                &dynamic_arguments,
                                alias.operation_id,
                                &resolved,
                            )?)
                        } else {
                            None
                        };
                        authenticated_children.push(AuthenticatedFixedBatchChild {
                            candidate: child.clone(),
                            operation_start: alias.operation_span.start,
                            operation_end: alias.operation_span.end,
                            operation_id: alias.operation_id,
                            dynamic_arguments,
                            helper_metadata,
                        });
                        continue;
                    }

                    if origin_plan.is_some() {
                        diagnostics.push(diagnostic_at(
                            graph,
                            modules,
                            "unsupported-direct-promise-all",
                            "fixed Promise.all effect site is not capability-authorized at its exact consumer".to_string(),
                            &unit.module,
                            child.start,
                            Some("Promise.all child".to_string()),
                            unit.dependency_chain.clone(),
                        )?);
                        child_authentication_failed = true;
                        break;
                    }
                    let AuthenticatedFixedPromiseAllChildOrigin::CallResult { callsite } =
                        &planned_child.origin
                    else {
                        unreachable!("effect-site origin was handled above")
                    };
                    if let Some(adapter_call) = dependency_adapter_calls.call_at(
                        &callsite.module,
                        callsite.start,
                        callsite.end,
                    ) {
                        if !matches!(
                            adapter_call.descriptor.semantic.kind.as_str(),
                            "databaseIndexCollect" | "databaseIndexUnique" | "functionHandleCreate"
                        ) {
                            diagnostics.push(diagnostic_at(
                                graph,
                                modules,
                                "unsupported-direct-promise-all",
                                "fixed Promise.all dependency-adapter child does not represent one raw operation result".to_string(),
                                &unit.module,
                                child.start,
                                Some("Promise.all child".to_string()),
                                unit.dependency_chain.clone(),
                            )?);
                            child_authentication_failed = true;
                            break;
                        }
                        let adapter_identity = (
                            adapter_call.importer_module.clone(),
                            adapter_call.operation.start,
                            adapter_call.operation.end,
                        );
                        let Some(adapter_operation) = operations
                            .iter()
                            .find(|operation| {
                                operation.file == adapter_call.importer_module
                                    && operation.start == adapter_call.operation.start
                                    && operation.end == adapter_call.operation.end
                            })
                            .cloned()
                        else {
                            child_authentication_failed = true;
                            break;
                        };
                        if !admitted_operation_identities.contains(&adapter_identity)
                            || !dependency_adapter_operation_matches(
                                &adapter_operation,
                                &adapter_call.operation,
                                adapter_call.dynamic_arguments.len(),
                            )
                        {
                            child_authentication_failed = true;
                            break;
                        }
                        authenticated_children.push(AuthenticatedFixedBatchChild {
                            candidate: child.clone(),
                            operation_start: adapter_operation.start,
                            operation_end: adapter_operation.end,
                            operation_id: adapter_operation.id,
                            dynamic_arguments: adapter_call.dynamic_arguments.clone(),
                            helper_metadata: None,
                        });
                        continue;
                    }

                    let resolved = resolve_direct_batch_helper(
                        graph,
                        modules,
                        reachable,
                        dependency_adapter_calls,
                        admitted_operation_identities,
                        operations,
                        unit,
                        child.start,
                        child.end,
                        child.helper_callee.as_deref(),
                        &child.helper_arguments,
                        &child.helper_identifier_arguments,
                        child.helper_has_spread_argument,
                    )?;
                    let resolved = match resolved {
                        Ok(resolved) => resolved,
                        Err(rejected) => {
                            diagnostics.push(diagnostic_at(
                                graph,
                                modules,
                                "unsupported-direct-promise-all",
                                rejected.message,
                                &rejected.module,
                                rejected.start,
                                Some("helper".to_string()),
                                rejected.dependency_chain,
                            )?);
                            child_authentication_failed = true;
                            break;
                        }
                    };
                    if authorized_effect_sites
                        .authorizes_target_operation(&resolved.target_operation)
                    {
                        let alias = push_direct_batch_helper_alias_operation(
                            modules,
                            operations,
                            unit,
                            child.start,
                            child.end,
                            &resolved,
                        )?;
                        let dynamic_arguments = resolved
                            .helper
                            .dynamic_parameter_indices
                            .iter()
                            .map(|index| child.helper_arguments[*index].clone())
                            .collect::<Vec<_>>();
                        authenticated_children.push(AuthenticatedFixedBatchChild {
                            candidate: child.clone(),
                            operation_start: child.start,
                            operation_end: child.end,
                            operation_id: alias.id,
                            dynamic_arguments,
                            helper_metadata: Some(direct_batch_helper_authorization_metadata(
                                child
                                    .helper_callee
                                    .clone()
                                    .expect("resolved helper has no callee"),
                                child.helper_arguments.clone(),
                                alias.id,
                                &resolved,
                            )),
                        });
                        continue;
                    }
                    let matching_adapters = dependency_adapter_calls
                        .calls
                        .iter()
                        .filter(|call| {
                            call.importer_module == resolved.target_module
                                && call.importer_unit_id == resolved.target_unit_id
                                && call.operation.start == resolved.target_operation.start
                                && call.operation.end == resolved.target_operation.end
                        })
                        .collect::<Vec<_>>();
                    let [adapter_call] = matching_adapters.as_slice() else {
                        diagnostics.push(diagnostic_at(
                            graph,
                            modules,
                            "unsupported-direct-promise-all",
                            "fixed Promise.all helper has neither one authorized effect plan nor one authenticated dependency-adapter projection".to_string(),
                            &unit.module,
                            child.start,
                            Some("helper".to_string()),
                            unit.dependency_chain.clone(),
                        )?);
                        child_authentication_failed = true;
                        break;
                    };
                    let adapter_identity = (
                        adapter_call.importer_module.clone(),
                        adapter_call.operation.start,
                        adapter_call.operation.end,
                    );
                    if !admitted_operation_identities.contains(&adapter_identity)
                        || !dependency_adapter_operation_matches(
                            &resolved.target_operation,
                            &adapter_call.operation,
                            adapter_call.dynamic_arguments.len(),
                        )
                    {
                        child_authentication_failed = true;
                        break;
                    }
                    let alias = push_direct_batch_helper_alias_operation(
                        modules,
                        operations,
                        unit,
                        child.start,
                        child.end,
                        &resolved,
                    )?;
                    let dynamic_arguments = resolved
                        .helper
                        .dynamic_parameter_indices
                        .iter()
                        .map(|index| child.helper_arguments[*index].clone())
                        .collect::<Vec<_>>();
                    authenticated_children.push(AuthenticatedFixedBatchChild {
                        candidate: child.clone(),
                        operation_start: child.start,
                        operation_end: child.end,
                        operation_id: alias.id,
                        dynamic_arguments,
                        helper_metadata: Some(direct_batch_helper_authorization_metadata(
                            child
                                .helper_callee
                                .clone()
                                .expect("resolved helper has no callee"),
                            child.helper_arguments.clone(),
                            alias.id,
                            &resolved,
                        )),
                    });
                }
                if child_authentication_failed {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-direct-promise-all",
                        "fixed Promise.all child failed authenticated semantic projection or mechanical lowering".to_string(),
                        &unit.module,
                        original_candidate.start,
                        Some("Promise.all child".to_string()),
                        unit.dependency_chain.clone(),
                    )?);
                    continue;
                }
                let mut children = Vec::with_capacity(original_candidate.fixed_children.len());
                let mut child_rejection = None;
                for authenticated in &authenticated_children {
                    let child = &authenticated.candidate;
                    let operation_start = authenticated.operation_start;
                    let operation_end = authenticated.operation_end;
                    let helper_metadata = authenticated.helper_metadata.as_ref();
                    let operation = operations
                        .iter()
                        .find(|operation| operation.id == authenticated.operation_id);
                    let Some(operation) = operation else {
                        child_rejection = Some(
                            "fixed Promise.all child is not an admitted owned Convex operation"
                                .to_string(),
                        );
                        break;
                    };
                    if operation.file != unit.module
                        || operation.start != operation_start
                        || operation.end != operation_end
                    {
                        child_rejection = Some(
                            "fixed Promise.all child materialization conflicts with its authenticated projection"
                                .to_string(),
                        );
                        break;
                    }
                    let dynamic_arguments = authenticated
                        .dynamic_arguments
                        .iter()
                        .map(|argument| {
                            direct_async_batch_argument_authorization(&source, argument)
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let child_source = source_slice(&source, child.start, child.end)?.to_string();
                    children.push(DirectAsyncBatchFixedChildAuthorization {
                        start: child.start,
                        end: child.end,
                        operation_start,
                        operation_end,
                        operation_id: operation.id,
                        operation_kind: operation.kind.clone(),
                        result_kind: direct_batch_result_kind(operation)?.to_string(),
                        source_sha256: hash_bytes(child_source.as_bytes()),
                        source: child_source,
                        dynamic_arguments,
                        generated_start: 0,
                        generated_end: 0,
                        generated_source_sha256: String::new(),
                        helper_continuation_prebound: helper_metadata
                            .as_ref()
                            .is_some_and(|metadata| metadata.continuation.is_some()),
                        operation_stable_key: operation.stable_key.clone(),
                        helper_callee: helper_metadata
                            .as_ref()
                            .map(|metadata| metadata.callee.clone()),
                        helper_dynamic_argument_indices: helper_metadata
                            .as_ref()
                            .map(|metadata| metadata.dynamic_argument_indices.clone())
                            .unwrap_or_default(),
                        helper_continuation: helper_metadata
                            .as_ref()
                            .and_then(|metadata| metadata.continuation.as_ref())
                            .map(|continuation| {
                                direct_batch_helper_continuation_authorization(
                                    &source,
                                    continuation,
                                )
                            })
                            .transpose()?,
                    });
                }
                if let Some(message) = child_rejection {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-direct-promise-all",
                        message,
                        &unit.module,
                        original_candidate.start,
                        Some("Promise.all".to_string()),
                        unit.dependency_chain.clone(),
                    )?);
                    continue;
                }
                let semantic_key = serde_json::to_string(&(
                    &unit.module,
                    original_candidate.start,
                    original_candidate.end,
                    children
                        .iter()
                        .map(|child| {
                            (
                                child.start,
                                child.end,
                                child.operation_start,
                                child.operation_end,
                                child.operation_id,
                                &child.operation_stable_key,
                                &child.operation_kind,
                                &child.result_kind,
                                child
                                    .dynamic_arguments
                                    .iter()
                                    .map(|argument| (argument.source_start, argument.source_end))
                                    .collect::<Vec<_>>(),
                                child.helper_continuation.as_ref().map(|continuation| {
                                    (
                                        &continuation.helper_binding,
                                        &continuation.source_sha256,
                                        continuation
                                            .helper_arguments
                                            .iter()
                                            .map(|argument| {
                                                (argument.source_start, argument.source_end)
                                            })
                                            .collect::<Vec<_>>(),
                                    )
                                }),
                            )
                        })
                        .collect::<Vec<_>>(),
                ))?;
                let (line, column) = line_column(&source, original_candidate.start);
                let batch_source =
                    source_slice(&source, original_candidate.start, original_candidate.end)?
                        .to_string();
                authorizations.push(DirectAsyncBatchAuthorization {
                    id: format!("batch_{}", &hash_bytes(semantic_key.as_bytes())[..16]),
                    file: unit.module.clone(),
                    start: original_candidate.start,
                    end: original_candidate.end,
                    line,
                    column,
                    source_sha256: hash_bytes(batch_source.as_bytes()),
                    source: batch_source,
                    generated_start: 0,
                    generated_end: 0,
                    generated_source_sha256: String::new(),
                    shape: DirectAsyncBatchAuthorizationShape::FixedEffectArray { children },
                    dependency_chain: unit.dependency_chain.clone(),
                });
                continue;
            }
            let plan_adaptation = adapt_mapped_leaf_plan_candidate(
                modules,
                callable_effect_plans,
                authorized_effect_sites,
                operations,
                unit,
                promise_site,
                original_candidate,
            )?;
            if plan_adaptation.is_none()
                && original_candidate.shape_error.is_none()
                && original_candidate.operation_kind.as_deref() == Some("db.get")
            {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-direct-promise-all",
                    "mapped database-get callback did not produce the required semantic callable effect plan"
                        .to_string(),
                    &unit.module,
                    original_candidate.start,
                    Some("Promise.all".to_string()),
                    unit.dependency_chain.clone(),
                )?);
                continue;
            }
            let adapted_call = original_candidate
                .callback_start
                .zip(original_candidate.callback_end)
                .and_then(|(callback_start, callback_end)| {
                    let mut matches = adapter_calls.iter().copied().filter(|call| {
                        call.call_start >= callback_start
                            && call.call_end <= callback_end
                            && matches!(
                                call.descriptor.semantic.kind.as_str(),
                                "databaseIndexCollect"
                                    | "databaseIndexUnique"
                                    | "functionHandleCreate"
                            )
                    });
                    match (matches.next(), matches.next()) {
                        (Some(matched), None) => Some(matched),
                        _ => None,
                    }
                });
            let mut adapted_candidate;
            let helper_metadata;
            let candidate = if let Some((plan_candidate, plan_helper_metadata)) = plan_adaptation {
                adapted_candidate = plan_candidate;
                helper_metadata = plan_helper_metadata;
                &adapted_candidate
            } else if original_candidate.shape_error.as_deref()
                == Some(
                    "direct Promise.all single-effect helper indirection is not mechanically lowered",
                )
                && let Some(call) = adapted_call
            {
                helper_metadata = None;
                adapted_candidate = original_candidate.clone();
                adapted_candidate.shape_error = None;
                adapted_candidate.operation_start = Some(call.operation.start);
                adapted_candidate.operation_end = Some(call.operation.end);
                adapted_candidate.dynamic_arguments = call.dynamic_arguments.clone();
                adapted_candidate.operation_kind = Some(call.operation.kind.clone());
                adapted_candidate.table = call.operation.table.clone();
                adapted_candidate.index = call.operation.index.clone();
                adapted_candidate.index_constraints = call.operation.index_constraints.clone();
                adapted_candidate.order = call.operation.order.clone();
                adapted_candidate.terminal = call.operation.terminal.clone();
                adapted_candidate.limit = call.operation.limit;
                adapted_candidate.limit_argument_index = call.operation.limit_argument_index;
                &adapted_candidate
            } else if original_candidate.shape_error.as_deref()
                == Some(
                    "direct Promise.all single-effect helper indirection is not mechanically lowered",
                )
            {
                let resolved = resolve_direct_batch_helper(
                    graph,
                    modules,
                    reachable,
                    dependency_adapter_calls,
                    admitted_operation_identities,
                    operations,
                    unit,
                    original_candidate
                        .helper_call_start
                        .unwrap_or(original_candidate.start),
                    original_candidate
                        .helper_call_end
                        .unwrap_or(original_candidate.end),
                    original_candidate.helper_callee.as_deref(),
                    &original_candidate.helper_arguments,
                    &original_candidate.helper_identifier_arguments,
                    original_candidate.helper_has_spread_argument,
                )?;
                let resolved = match resolved {
                    Ok(resolved) => resolved,
                    Err(rejected) => {
                        diagnostics.push(diagnostic_at(
                            graph,
                            modules,
                            "unsupported-direct-promise-all",
                            rejected.message,
                            &rejected.module,
                            rejected.start,
                            Some("helper".to_string()),
                            rejected.dependency_chain,
                        )?);
                        continue;
                    }
                };
                if original_candidate.implicit_undefined
                    && direct_batch_result_kind(&resolved.target_operation)? != "undefined"
                {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-direct-promise-all",
                        "direct Promise.all implicit undefined callback requires a void Convex effect"
                            .to_string(),
                        &unit.module,
                        original_candidate.start,
                        Some("Promise.all".to_string()),
                        unit.dependency_chain.clone(),
                    )?);
                    continue;
                }
                if resolved.helper.continuation.is_none()
                    && resolved.target_operation.kind == "databaseGet"
                {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-direct-promise-all",
                        "mapped database-get helper did not produce the required semantic callable effect plan"
                            .to_string(),
                        &unit.module,
                        original_candidate.start,
                        Some("helper".to_string()),
                        unit.dependency_chain.clone(),
                    )?);
                    continue;
                }
                let call_start = original_candidate
                    .helper_call_start
                    .context("resolved mapped helper has no call start")?;
                let call_end = original_candidate
                    .helper_call_end
                    .context("resolved mapped helper has no call end")?;
                let alias = push_direct_batch_helper_alias_operation(
                    modules, operations, unit, call_start, call_end, &resolved,
                )?;
                adapted_candidate = original_candidate.clone();
                adapted_candidate.shape_error = None;
                adapted_candidate.operation_start = Some(call_start);
                adapted_candidate.operation_end = Some(call_end);
                adapted_candidate.dynamic_arguments = resolved
                    .helper
                    .dynamic_parameter_indices
                    .iter()
                    .map(|index| original_candidate.helper_arguments[*index].clone())
                    .collect();
                adapted_candidate.operation_kind = resolved.helper.operation_kind.clone();
                adapted_candidate.table = resolved.helper.table.clone();
                adapted_candidate.index = resolved.helper.index.clone();
                adapted_candidate.index_constraints = resolved.helper.index_constraints.clone();
                adapted_candidate.order = resolved.helper.order.clone();
                adapted_candidate.terminal = resolved.helper.terminal.clone();
                adapted_candidate.limit = resolved.helper.limit;
                adapted_candidate.limit_argument_index = resolved.helper.limit_argument_index;
                adapted_candidate.function_reference = resolved.helper.function_reference.clone();
                helper_metadata = Some(direct_batch_helper_authorization_metadata(
                    original_candidate
                        .helper_callee
                        .clone()
                        .expect("resolved mapped helper has no callee"),
                    original_candidate.helper_arguments.clone(),
                    alias.id,
                    &resolved,
                ));
                &adapted_candidate
            } else {
                helper_metadata = None;
                original_candidate
            };
            let mut argument_field = None;
            let mut constant_iterator_identity = None;
            // The guest-native pure-map case intentionally bypasses its missing-effect shape
            // error, but it must still prove that removing Promise.all preserves array behavior.
            let iterator_rejection = if candidate.shape_error.is_some()
                && !candidate.sequential_value_map_safe
            {
                None
            } else if let (Some(iterator_root), Some(iterator_field)) =
                (&candidate.iterator_root, &candidate.iterator_field)
            {
                argument_field = Some(iterator_field.clone());
                if unit.kind != "handler" {
                    Some(
                        "direct Promise.all registration argument iterators are limited to the registration handler"
                            .to_string(),
                    )
                } else if Some(iterator_root) != registration.argument_parameter.as_ref() {
                    Some(
                        "direct Promise.all iterator must come from the registration argument parameter"
                            .to_string(),
                    )
                } else if !registration.array_argument_fields.contains(iterator_field) {
                    Some(
                        "direct Promise.all iterator field must use an inline v.array validator"
                            .to_string(),
                    )
                } else {
                    let iterator_start = candidate
                        .iterator_start
                        .context("valid argument iterator has no start")?;
                    let iterator_end = candidate
                        .iterator_end
                        .context("valid argument iterator has no end")?;
                    let selected_access =
                        module.summary.static_member_accesses.iter().find(|access| {
                            access.root == *iterator_root
                                && access.first_field == *iterator_field
                                && access.start == iterator_start
                                && access.end == iterator_end
                        });
                    if selected_access.is_none() {
                        Some(
                            "direct Promise.all iterator field does not match its static argument access"
                                .to_string(),
                        )
                    } else {
                        let selected_access = selected_access.expect("checked selected access");
                        let invalid_reference =
                            registration.argument_references.iter().any(|reference| {
                                if !reference.read || reference.write {
                                    return true;
                                }
                                let rooted_accesses = module
                                    .summary
                                    .static_member_accesses
                                    .iter()
                                    .filter(|access| {
                                        access.root == reference.name
                                            && access.root_start == reference.start
                                            && access.root_end == reference.end
                                    })
                                    .collect::<Vec<_>>();
                                if rooted_accesses.is_empty() {
                                    return true;
                                }
                                rooted_accesses.iter().any(|access| {
                                    access.first_field == *iterator_field
                                        && (reference.start != selected_access.root_start
                                            || reference.end != selected_access.root_end)
                                })
                            });
                        invalid_reference.then(|| {
                            "direct Promise.all selected argument field must not be written, computed, aliased, or read outside the authorized map receiver"
                                .to_string()
                        })
                    }
                }
            } else if let Some(iterator_binding) = &candidate.iterator_binding {
                let binding_start = candidate
                    .iterator_binding_start
                    .context("valid local iterator has no binding reference start")?;
                let binding_end = candidate
                    .iterator_binding_end
                    .context("valid local iterator has no binding reference end")?;
                if candidate.iterator_array_global_start.is_some() {
                    let array_global_is_unshadowed = candidate
                        .iterator_array_global_start
                        .zip(candidate.iterator_array_global_end)
                        .is_some_and(|(start, end)| {
                            module.summary.globals.iter().any(|global| {
                                global.name == "Array"
                                    && global.read
                                    && !global.write
                                    && global.start == start
                                    && global.end == end
                            })
                        });
                    let matching_sets = module
                        .summary
                        .local_set_bindings
                        .iter()
                        .filter(|binding| {
                            binding.name == *iterator_binding
                                && binding.enclosing_function_start
                                    == candidate.enclosing_function_start
                                && binding.enclosing_function_end
                                    == candidate.enclosing_function_end
                        })
                        .collect::<Vec<_>>();
                    if !array_global_is_unshadowed {
                        Some(
                            "direct Promise.all Array.from iterator requires the unshadowed global Array"
                                .to_string(),
                        )
                    } else if matching_sets.len() != 1 {
                        Some(
                            "direct Promise.all Array.from iterator must consume one proved local const Set"
                                .to_string(),
                        )
                    } else {
                        let binding = matching_sets[0];
                        let set_global_is_unshadowed =
                            module.summary.globals.iter().any(|global| {
                                global.name == "Set"
                                    && global.read
                                    && !global.write
                                    && global.start == binding.set_global_start
                                    && global.end == binding.set_global_end
                            });
                        let references_are_owned = !binding.references.is_empty()
                            && binding.references.iter().all(|reference| {
                                if !reference.read || reference.write {
                                    return false;
                                }
                                if reference.start == binding_start && reference.end == binding_end
                                {
                                    return true;
                                }
                                module.summary.static_member_calls.iter().any(|call| {
                                    call.root == binding.name
                                        && call.first_field == "add"
                                        && call.root_start == reference.start
                                        && call.root_end == reference.end
                                        && call.end < candidate.start
                                })
                            });
                        if binding.binding_start >= candidate.start {
                            Some(
                                "direct Promise.all local Set must be initialized before Array.from"
                                    .to_string(),
                            )
                        } else if !set_global_is_unshadowed {
                            Some(
                                "direct Promise.all local Set requires the unshadowed global Set"
                                    .to_string(),
                            )
                        } else if !references_are_owned {
                            Some(
                                "direct Promise.all local Set may only be populated by direct add calls before its authorized Array.from iterator"
                                    .to_string(),
                            )
                        } else {
                            None
                        }
                    }
                } else {
                    let matching_arrays = module
                        .summary
                        .local_array_bindings
                        .iter()
                        .filter(|binding| {
                            binding.name == *iterator_binding
                                && binding.enclosing_function_start
                                    == candidate.enclosing_function_start
                                && binding.enclosing_function_end
                                    == candidate.enclosing_function_end
                        })
                        .collect::<Vec<_>>();
                    if matching_arrays.len() != 1 {
                        let matching_constants = module
                            .summary
                            .constant_array_bindings
                            .iter()
                            .filter(|binding| {
                                binding.name == *iterator_binding
                                    && binding.references.iter().any(|reference| {
                                        reference.start == binding_start
                                            && reference.end == binding_end
                                    })
                            })
                            .collect::<Vec<_>>();
                        if matching_constants.len() != 1 {
                            Some(
                                "direct Promise.all identifier iterator must be one proved collected, filtered, or constant array"
                                    .to_string(),
                            )
                        } else {
                            let binding = matching_constants[0];
                            let selected_reference_count = binding
                                .references
                                .iter()
                                .filter(|reference| {
                                    reference.start == binding_start && reference.end == binding_end
                                })
                                .count();
                            let references_are_owned = selected_reference_count == 1
                                && !binding.references.is_empty()
                                && binding.references.iter().all(|reference| {
                                    reference.read
                                        && !reference.write
                                        && module.summary.direct_async_batches.iter().any(|batch| {
                                            batch.iterator_binding.as_ref() == Some(&binding.name)
                                                && batch.iterator_binding_start
                                                    == Some(reference.start)
                                                && batch.iterator_binding_end == Some(reference.end)
                                        })
                                });
                            let matching_owners = reachable
                                .values()
                                .filter(|owner| {
                                    owner.module == unit.module
                                        && binding.binding_start >= owner.start
                                        && binding.initializer_end <= owner.end
                                })
                                .collect::<Vec<_>>();
                            if binding.initializer_end > candidate.start {
                                Some(
                                    "direct Promise.all constant array must be initialized before its map"
                                        .to_string(),
                                )
                            } else if !references_are_owned {
                                Some(
                                    "direct Promise.all constant array must be never-written and used only by authorized map receivers"
                                        .to_string(),
                                )
                            } else if matching_owners.len() != 1 {
                                Some(
                                    "direct Promise.all constant array must belong to one authenticated reachable unit"
                                        .to_string(),
                                )
                            } else {
                                let initializer_source = source_slice(
                                    &source,
                                    binding.initializer_start,
                                    binding.initializer_end,
                                )?;
                                constant_iterator_identity = Some((
                                    matching_owners[0].id.clone(),
                                    binding.initializer_start,
                                    binding.initializer_end,
                                    hash_bytes(initializer_source.as_bytes()),
                                    binding.values.clone(),
                                ));
                                None
                            }
                        }
                    } else {
                        let binding = matching_arrays[0];
                        let selected_reference_count = binding
                            .references
                            .iter()
                            .filter(|reference| {
                                reference.start == binding_start && reference.end == binding_end
                            })
                            .count();
                        let references_are_owned = selected_reference_count == 1
                            && binding.references.iter().all(|reference| {
                                reference.read
                                    && !reference.write
                                    && ((reference.start == binding_start
                                        && reference.end == binding_end)
                                        || module.summary.static_member_accesses.iter().any(
                                            |access| {
                                                access.root == binding.name
                                                    && access.first_field == "length"
                                                    && access.root_start == reference.start
                                                    && access.root_end == reference.end
                                            },
                                        ))
                            });
                        let producer_identity = (
                            unit.module.clone(),
                            binding.operation_start,
                            binding.operation_end,
                        );
                        let admitted_producer = admitted_operation_identities
                            .contains(&producer_identity)
                            && operations.iter().any(|operation| {
                                operation.file == unit.module
                                    && operation.start == binding.operation_start
                                    && operation.end == binding.operation_end
                                    && operation.kind == "databaseIndexQuery"
                                    && matches!(operation.terminal.as_deref(), Some("collect"))
                            });
                        if binding.initializer_end > candidate.start {
                            Some(
                                "direct Promise.all local collect result must be initialized before its map"
                                    .to_string(),
                            )
                        } else if !references_are_owned {
                            Some(
                                "direct Promise.all local array may only be read by the authorized map receiver or through length"
                                    .to_string(),
                            )
                        } else if !admitted_producer {
                            Some(
                                "direct Promise.all local collect iterator is not produced by an admitted owned index query"
                                    .to_string(),
                            )
                        } else {
                            None
                        }
                    }
                }
            } else {
                Some("direct Promise.all iterator proof is missing".to_string())
            };
            let rejection = if !unshadowed_global {
                Some("direct Promise.all requires the unshadowed global Promise".to_string())
            } else if candidate.sequential_value_map_safe
                && let Some(iterator_rejection) = &iterator_rejection
            {
                Some(iterator_rejection.clone())
            } else if let Some(shape_error) = &candidate.shape_error {
                Some(shape_error.clone())
            } else if let Some(iterator_rejection) = &iterator_rejection {
                Some(iterator_rejection.clone())
            } else {
                let operation_identity = (
                    unit.module.clone(),
                    candidate
                        .operation_start
                        .context("valid direct async batch has no operation start")?,
                    candidate
                        .operation_end
                        .context("valid direct async batch has no operation end")?,
                );
                if helper_metadata.is_some() {
                    None
                } else if !admitted_operation_identities.contains(&operation_identity) {
                    Some(
                        "direct Promise.all effect is not an admitted owned Convex operation"
                            .to_string(),
                    )
                } else {
                    let callback_start = candidate
                        .callback_start
                        .context("valid direct async batch has no callback start")?;
                    let callback_end = candidate
                        .callback_end
                        .context("valid direct async batch has no callback end")?;
                    let represented_source_effects = module
                        .summary
                        .operations
                        .iter()
                        .filter(|operation| {
                            operation.start >= callback_start
                                && operation.end <= callback_end
                                && admitted_operation_identities.contains(&(
                                    unit.module.clone(),
                                    operation.start,
                                    operation.end,
                                ))
                        })
                        .count();
                    let represented_adapter_effects = adapter_calls
                        .iter()
                        .copied()
                        .filter(|call| {
                            call.call_start >= callback_start
                                && call.call_end <= callback_end
                                && admitted_operation_identities.contains(&(
                                    call.importer_module.clone(),
                                    call.operation.start,
                                    call.operation.end,
                                ))
                        })
                        .count();
                    let represented_effects =
                        represented_source_effects + represented_adapter_effects;
                    (represented_effects != 1).then(|| {
                        "direct Promise.all callback must contain exactly one admitted Convex effect"
                            .to_string()
                    })
                }
            };
            if value_mode == ValueMode::GuestNativeJson
                && unshadowed_global
                && candidate.sequential_value_map_safe
                && iterator_rejection.is_none()
                && candidate.iterator_start.is_some()
                && candidate.iterator_end.is_some()
                && candidate.callback_start.is_some()
                && candidate.callback_end.is_some()
                && candidate.callback_parameter.is_some()
            {
                // The callback has no calls, awaits, construction, assignment, or updates.
                // Convex boundary values cannot contain thenables or accessors, so this exact
                // mapped value form can become Array.prototype.map without observable Promise
                // scheduling or introducing child continuation state.
                continue;
            }
            if let Some(message) = rejection {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-direct-promise-all",
                    message,
                    &unit.module,
                    candidate.start,
                    Some("Promise.all".to_string()),
                    unit.dependency_chain.clone(),
                )?);
                continue;
            }
            let operation_start = candidate
                .operation_start
                .context("authorized direct async batch has no operation start")?;
            let operation_end = candidate
                .operation_end
                .context("authorized direct async batch has no operation end")?;
            let operation = if let Some(helper_metadata) = &helper_metadata {
                operations
                    .iter()
                    .find(|operation| operation.id == helper_metadata.operation_id)
            } else {
                operations.iter().find(|operation| {
                    operation.file == unit.module
                        && operation.start == operation_start
                        && operation.end == operation_end
                })
            }
            .context("authorized direct async batch operation was not emitted")?;
            if !direct_batch_operation_matches(operation, candidate) {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-direct-promise-all",
                    "direct Promise.all effect does not match its admitted operation descriptor"
                        .to_string(),
                    &unit.module,
                    candidate.start,
                    Some("Promise.all".to_string()),
                    unit.dependency_chain.clone(),
                )?);
                continue;
            }
            let callback_start = candidate
                .callback_start
                .context("authorized direct async batch has no callback start")?;
            let callback_end = candidate
                .callback_end
                .context("authorized direct async batch has no callback end")?;
            let callback_parameter = candidate
                .callback_parameter
                .clone()
                .context("authorized direct async batch has no callback parameter")?;
            let dynamic_arguments = candidate
                .dynamic_arguments
                .iter()
                .map(|argument| direct_async_batch_argument_authorization(&source, argument))
                .collect::<Result<Vec<_>>>()?;
            let result_kind = direct_batch_result_kind(operation)?.to_string();
            let semantic_key = serde_json::to_string(&(
                &unit.module,
                candidate.start,
                candidate.end,
                callback_start,
                callback_end,
                operation_start,
                operation_end,
                operation.id,
                &operation.kind,
                &result_kind,
                helper_metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.continuation.is_some()),
                &argument_field,
                &callback_parameter,
                &constant_iterator_identity,
                candidate
                    .dynamic_arguments
                    .iter()
                    .map(|argument| (argument.start, argument.end))
                    .collect::<Vec<_>>(),
            ))?;
            let (line, column) = line_column(&source, candidate.start);
            let mapped_helper_continuation = helper_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.continuation.is_some());
            authorizations.push(DirectAsyncBatchAuthorization {
                id: format!("batch_{}", &hash_bytes(semantic_key.as_bytes())[..16]),
                file: unit.module.clone(),
                start: candidate.start,
                end: candidate.end,
                line,
                column,
                source: source_slice(&source, candidate.start, candidate.end)?.to_string(),
                source_sha256: hash_bytes(
                    source_slice(&source, candidate.start, candidate.end)?.as_bytes(),
                ),
                generated_start: 0,
                generated_end: 0,
                generated_source_sha256: String::new(),
                shape: DirectAsyncBatchAuthorizationShape::SingleEffectMap {
                    callback_start,
                    callback_end,
                    callback_parameter,
                    operation_start,
                    operation_end,
                    operation_id: operation.id,
                    operation_kind: operation.kind.clone(),
                    result_kind,
                    helper_continuation_prebound: mapped_helper_continuation,
                    argument_field,
                    dynamic_arguments,
                    source_iterator_start: candidate
                        .iterator_start
                        .context("authorized direct async batch has no iterator start")?,
                    source_iterator_end: candidate
                        .iterator_end
                        .context("authorized direct async batch has no iterator end")?,
                    generated_iterator_start: 0,
                    generated_iterator_end: 0,
                    generated_iterator_sha256: String::new(),
                    operation_stable_key: operation.stable_key.clone(),
                    helper_callee: helper_metadata
                        .as_ref()
                        .map(|metadata| metadata.callee.clone()),
                    helper_dynamic_argument_indices: helper_metadata
                        .as_ref()
                        .map(|metadata| metadata.dynamic_argument_indices.clone())
                        .unwrap_or_default(),
                    helper_continuation: helper_metadata
                        .as_ref()
                        .and_then(|metadata| metadata.continuation.as_ref())
                        .map(|continuation| {
                            direct_batch_helper_continuation_authorization(&source, continuation)
                        })
                        .transpose()?
                        .map(Box::new),
                },
                dependency_chain: unit.dependency_chain.clone(),
            });
            if mapped_helper_continuation {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-direct-promise-all",
                    "mapped Promise.all helper continuations remain on V8 because Wasm batching cannot preserve source-order rejection when a later operation fails"
                        .to_string(),
                    &unit.module,
                    candidate.start,
                    Some("Promise.all".to_string()),
                    unit.dependency_chain.clone(),
                )?);
            }
        }
    }
    for authorization in &authorizations {
        super::effect_plan::current_direct_batch_authorization_layout(authorization)?;
    }
    Ok(authorizations)
}

fn direct_async_batch_argument_authorization(
    source: &str,
    argument: &SourceRange,
) -> Result<DirectAsyncBatchArgumentAuthorization> {
    let argument_source = source_slice(source, argument.start, argument.end)?.to_string();
    Ok(DirectAsyncBatchArgumentAuthorization {
        source_start: argument.start,
        source_end: argument.end,
        source_sha256: hash_bytes(argument_source.as_bytes()),
        source: argument_source,
        generated_start: 0,
        generated_end: 0,
        generated_sha256: String::new(),
    })
}

fn direct_batch_helper_continuation_authorization(
    source: &str,
    continuation: &PendingDirectBatchHelperContinuation,
) -> Result<DirectBatchHelperContinuationAuthorization> {
    Ok(DirectBatchHelperContinuationAuthorization {
        helper_binding: continuation.helper_binding.clone(),
        helper_parameters: continuation.helper_parameters.clone(),
        helper_arguments: continuation
            .helper_arguments
            .iter()
            .map(|argument| direct_async_batch_argument_authorization(source, argument))
            .collect::<Result<Vec<_>>>()?,
        source_sha256: continuation.source_sha256.clone(),
        source_body_start: continuation.source_body_start,
        source_body_end: continuation.source_body_end,
        source_suspension_start: continuation.source_suspension_start,
        source_suspension_end: continuation.source_suspension_end,
        source_result_binding: continuation.source_result_binding.clone(),
        generated_body_start: 0,
        generated_body_end: 0,
        generated_suspension_start: 0,
        generated_suspension_end: 0,
        generated_result_binding: String::new(),
        generated_effect_arguments: Vec::new(),
        dependency_adapter: continuation.dependency_adapter.clone(),
    })
}

pub(super) fn direct_fixed_child_operation_matches(
    operation: &AdmittedOperation,
    child: &DirectAsyncBatchFixedChildCandidate,
) -> bool {
    let expected_kind = match child.operation_kind.as_deref() {
        Some("db.query") => "databaseIndexQuery",
        Some("db.get") => "databaseGet",
        Some("db.insert") => "databaseInsert",
        Some("db.patch") => "databasePatch",
        Some("db.replace") => "databaseReplace",
        Some("db.delete") => "databaseDelete",
        Some("scheduler.runAfter") => "schedulerRunAfter",
        Some("scheduler.runAt") => "schedulerRunAt",
        Some("functionHandleCreate") => "functionHandleCreate",
        _ => return false,
    };
    operation.kind == expected_kind
        && operation.table == child.table
        && operation.index == child.index
        && operation
            .index_constraints
            .iter()
            .map(|constraint| (&constraint.field, &constraint.operator))
            .eq(child
                .index_constraints
                .iter()
                .map(|constraint| (&constraint.field, &constraint.operator)))
        && operation.order == child.order
        && operation.terminal == child.terminal
        && operation.limit == child.limit
        && operation.limit_argument_index == child.limit_argument_index
        && operation.function_reference == child.function_reference
        && operation_dynamic_argument_count(operation) == child.dynamic_arguments.len()
}

fn dependency_adapter_operation_matches(
    operation: &AdmittedOperation,
    candidate: &OperationCandidate,
    dynamic_argument_count: usize,
) -> bool {
    let expected_kind = match candidate.kind.as_str() {
        "db.query" => "databaseIndexQuery",
        "db.get" => "databaseGet",
        "db.insert" => "databaseInsert",
        "db.patch" => "databasePatch",
        "db.replace" => "databaseReplace",
        "db.delete" => "databaseDelete",
        "scheduler.runAfter" => "schedulerRunAfter",
        "scheduler.runAt" => "schedulerRunAt",
        "functionHandleCreate" => "functionHandleCreate",
        _ => return false,
    };
    operation.kind == expected_kind
        && operation.table == candidate.table
        && operation.index == candidate.index
        && operation
            .index_constraints
            .iter()
            .map(|constraint| (&constraint.field, &constraint.operator))
            .eq(candidate
                .index_constraints
                .iter()
                .map(|constraint| (&constraint.field, &constraint.operator)))
        && operation.order == candidate.order
        && operation.terminal == candidate.terminal
        && operation.limit == candidate.limit
        && operation.limit_argument_index == candidate.limit_argument_index
        && operation.function_reference == candidate.function_reference
        && operation_dynamic_argument_count(operation) == dynamic_argument_count
}

pub(super) fn direct_batch_operation_matches(
    operation: &AdmittedOperation,
    candidate: &DirectAsyncBatchCandidate,
) -> bool {
    let expected_kind = match candidate.operation_kind.as_deref() {
        Some("db.query") => "databaseIndexQuery",
        Some("db.get") => "databaseGet",
        Some("db.insert") => "databaseInsert",
        Some("db.patch") => "databasePatch",
        Some("db.replace") => "databaseReplace",
        Some("db.delete") => "databaseDelete",
        Some("scheduler.runAfter") => "schedulerRunAfter",
        Some("scheduler.runAt") => "schedulerRunAt",
        Some("functionHandleCreate") => "functionHandleCreate",
        _ => return false,
    };
    operation.kind == expected_kind
        && operation.table == candidate.table
        && operation.index == candidate.index
        && operation
            .index_constraints
            .iter()
            .map(|constraint| (&constraint.field, &constraint.operator))
            .eq(candidate
                .index_constraints
                .iter()
                .map(|constraint| (&constraint.field, &constraint.operator)))
        && operation.order == candidate.order
        && operation.terminal == candidate.terminal
        && operation.limit == candidate.limit
        && operation.limit_argument_index == candidate.limit_argument_index
        && operation.function_reference == candidate.function_reference
        && operation_dynamic_argument_count(operation) == candidate.dynamic_arguments.len()
}

fn operation_dynamic_argument_count(operation: &AdmittedOperation) -> usize {
    match operation.kind.as_str() {
        "databasePatch" | "databaseReplace" | "schedulerRunAfter" | "schedulerRunAt" => 2,
        "databaseIndexQuery" => {
            operation.index_constraints.len()
                + usize::from(operation.limit_argument_index.is_some())
        }
        "databaseGet" | "databaseInsert" | "databaseDelete" | "functionHandleCreate" => 1,
        _ => 0,
    }
}

pub(super) fn direct_batch_result_kind(operation: &AdmittedOperation) -> Result<&'static str> {
    match operation.kind.as_str() {
        "databaseIndexQuery" if operation.terminal.as_deref() == Some("collect") => Ok("hostArray"),
        "databasePatch" | "databaseReplace" | "databaseDelete" => Ok("undefined"),
        "databaseGet"
        | "databaseIndexQuery"
        | "databaseInsert"
        | "schedulerRunAfter"
        | "schedulerRunAt"
        | "functionHandleCreate" => Ok("hostValue"),
        kind => bail!("operation {kind} has no direct batch result contract"),
    }
}

pub(super) fn direct_batch_candidate_operation_kind(
    operation: &AdmittedOperation,
) -> Result<&'static str> {
    match operation.kind.as_str() {
        "databaseIndexQuery" => Ok("db.query"),
        "databaseGet" => Ok("db.get"),
        "databaseInsert" => Ok("db.insert"),
        "databasePatch" => Ok("db.patch"),
        "databaseReplace" => Ok("db.replace"),
        "databaseDelete" => Ok("db.delete"),
        "schedulerRunAfter" => Ok("scheduler.runAfter"),
        "schedulerRunAt" => Ok("scheduler.runAt"),
        "functionHandleCreate" => Ok("functionHandleCreate"),
        kind => bail!("operation {kind} cannot back a direct batch helper"),
    }
}
