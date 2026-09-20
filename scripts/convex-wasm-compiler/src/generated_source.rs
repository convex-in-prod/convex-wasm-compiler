use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, Scoping, SemanticBuilder};
use oxc_span::{GetSpan, SourceType};
use serde_json::Value;

use super::direct_batches::{
    DirectAsyncBatchArgumentAuthorization, DirectAsyncBatchAuthorization,
    DirectAsyncBatchAuthorizationShape, DirectAsyncBatchCandidate,
    DirectAsyncBatchFixedChildAuthorization, DirectAsyncBatchFixedChildCandidate,
    DirectBatchHelperContinuationAuthorization, collect_direct_async_batches,
    direct_batch_candidate_operation_kind, direct_batch_operation_matches,
    direct_batch_result_kind, direct_fixed_child_operation_matches, parse_direct_async_batch,
    parse_direct_batch_helper,
};
use super::effect_plan::{CurrentDirectBatchLayout, current_direct_batch_authorization_layout};
use super::{
    AdmittedOperation, DatabaseOperationSource, EffectExecutionMode, IndexConstraintCandidate,
    Intrinsic, LocalFilteredArrayCandidate, SourceRange, ValueMode, call_has_optional_callee,
    call_method_name, collect_local_filtered_array_candidates, collect_static_member_calls,
    contains_node_type, dependency_adapter_unique_or_throw_rejection, hash_bytes, identifier_name,
    is_static_member_call, node_type, resolved_binding_references, source_slice, span,
    static_member_root, static_member_segments, unwrap_runtime_expression,
    unwrap_transparent_expression,
};

pub(super) const INVOCATION_UNIX_TIMESTAMP_MS_RUNTIME_INPUT: &str = "invocationUnixTimestampMs";
const INVOCATION_UNIX_TIMESTAMP_MS_HELPER: &str = "__convexInvocationUnixTimestampMs";
const GUEST_PROMISE_GLOBAL_ALIAS: &str = "__convexGuestPromise";

#[derive(Debug)]
pub(super) struct LoweredGeneratedJavascript {
    pub(super) source: String,
    pub(super) runtime_inputs: Vec<String>,
}

#[derive(Debug, Default)]
pub(super) struct GeneratedJavascriptAuthority {
    pub(super) compiler_top_level_bindings: BTreeSet<String>,
    pub(super) compiler_scoped_binding_references: BTreeMap<String, usize>,
    pub(super) compiler_top_level_globals: BTreeSet<String>,
    pub(super) compiler_application_globals: BTreeSet<String>,
}

#[derive(Debug)]
pub(super) struct GeneratedSourceBindingCollision {
    pub(super) names: Vec<String>,
    message: String,
}

impl std::fmt::Display for GeneratedSourceBindingCollision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for GeneratedSourceBindingCollision {}

fn generated_source_binding_collision(
    names: Vec<String>,
    message: impl Into<String>,
) -> anyhow::Error {
    GeneratedSourceBindingCollision {
        names,
        message: message.into(),
    }
    .into()
}

fn generated_index_constraint_candidates(
    operation: &AdmittedOperation,
) -> Vec<IndexConstraintCandidate> {
    operation
        .index_constraints
        .iter()
        .map(|constraint| IndexConstraintCandidate {
            field: constraint.field.clone(),
            operator: constraint.operator.clone(),
            value_source: constraint.value_source.clone(),
            value_start: 0,
            value_end: 0,
        })
        .collect()
}

fn bind_generated_mapped_helper_candidate(
    mut candidate: DirectAsyncBatchCandidate,
    operation: &AdmittedOperation,
    helper_callee: &str,
    dynamic_argument_indices: &[usize],
) -> Result<DirectAsyncBatchCandidate> {
    ensure!(
        candidate.shape_error.as_deref()
            == Some(
                "direct Promise.all single-effect helper indirection is not mechanically lowered"
            )
            && candidate.helper_callee.as_deref() == Some(helper_callee)
            && dynamic_argument_indices
                .iter()
                .all(|index| *index < candidate.helper_arguments.len()),
        "generated mapped direct batch helper call changed shape"
    );
    candidate.shape_error = None;
    candidate.operation_start = candidate.helper_call_start;
    candidate.operation_end = candidate.helper_call_end;
    candidate.dynamic_arguments = dynamic_argument_indices
        .iter()
        .map(|index| candidate.helper_arguments[*index].clone())
        .collect();
    candidate.operation_kind = Some(direct_batch_candidate_operation_kind(operation)?.to_string());
    candidate.table = operation.table.clone();
    candidate.index = operation.index.clone();
    candidate.index_constraints = generated_index_constraint_candidates(operation);
    candidate.order = operation.order.clone();
    candidate.terminal = operation.terminal.clone();
    candidate.limit = operation.limit;
    candidate.function_reference = operation.function_reference.clone();
    Ok(candidate)
}

fn bind_generated_fixed_helper_candidate(
    mut candidate: DirectAsyncBatchFixedChildCandidate,
    operation: &AdmittedOperation,
    helper_callee: &str,
    dynamic_argument_indices: &[usize],
) -> Result<DirectAsyncBatchFixedChildCandidate> {
    ensure!(
        candidate.shape_error.as_deref()
            == Some(
                "direct Promise.all fixed child helper indirection is not mechanically lowered"
            )
            && candidate.helper_callee.as_deref() == Some(helper_callee)
            && dynamic_argument_indices
                .iter()
                .all(|index| *index < candidate.helper_arguments.len()),
        "generated fixed direct batch helper call changed shape"
    );
    candidate.shape_error = None;
    candidate.operation_start = candidate.helper_call_start;
    candidate.operation_end = candidate.helper_call_end;
    candidate.dynamic_arguments = dynamic_argument_indices
        .iter()
        .map(|index| candidate.helper_arguments[*index].clone())
        .collect();
    candidate.operation_kind = Some(direct_batch_candidate_operation_kind(operation)?.to_string());
    candidate.table = operation.table.clone();
    candidate.index = operation.index.clone();
    candidate.index_constraints = generated_index_constraint_candidates(operation);
    candidate.order = operation.order.clone();
    candidate.terminal = operation.terminal.clone();
    candidate.limit = operation.limit;
    candidate.function_reference = operation.function_reference.clone();
    Ok(candidate)
}

fn bind_generated_helper_continuation(
    source: &str,
    generated_functions: &[GeneratedTopLevelFunction<'_>],
    generated_helper_arguments: &[SourceRange],
    helper_dynamic_argument_indices: &[usize],
    continuation: &mut DirectBatchHelperContinuationAuthorization,
) -> Result<()> {
    let matching_functions = generated_functions
        .iter()
        .filter(|function| function.name == continuation.helper_binding)
        .collect::<Vec<_>>();
    ensure!(
        matching_functions.len() == 1,
        "generated continuation helper {} is missing or ambiguous",
        continuation.helper_binding
    );
    let function = matching_functions[0].function;
    let generated_helper =
        parse_direct_batch_helper(function, DatabaseOperationSource::CompilerGenerated);
    ensure!(
        generated_helper.shape_error.is_none()
            && generated_helper.dynamic_parameter_indices == helper_dynamic_argument_indices,
        "generated continuation helper changed its admitted effect shape"
    );
    let generated_continuation = generated_helper
        .continuation
        .context("generated continuation helper lost its continuation")?;
    let generated_parameters = function
        .get("params")
        .and_then(Value::as_array)
        .context("generated continuation helper has no parameters")?
        .iter()
        .map(identifier_name)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        generated_parameters == continuation.helper_parameters
            && continuation.helper_arguments.len() == generated_helper_arguments.len(),
        "generated continuation helper parameters or call arguments changed"
    );
    continuation.generated_body_start = generated_continuation.body_start;
    continuation.generated_body_end = generated_continuation.body_end;
    continuation.generated_suspension_start = generated_continuation.suspension_start;
    continuation.generated_suspension_end = generated_continuation.suspension_end;
    continuation.generated_result_binding = generated_continuation.result_binding;
    continuation.generated_effect_arguments = generated_helper.dynamic_argument_ranges;
    for (argument, generated_argument) in continuation
        .helper_arguments
        .iter_mut()
        .zip(generated_helper_arguments)
    {
        bind_generated_direct_async_batch_argument(source, argument, generated_argument)?;
    }
    Ok(())
}

pub(super) fn bind_generated_direct_async_batches(
    source: &str,
    operations: &[AdmittedOperation],
    authorizations: &mut [DirectAsyncBatchAuthorization],
    value_mode: ValueMode,
) -> Result<()> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "generated direct async batch source has {} parser diagnostics",
        parsed.diagnostics.len()
    );
    let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false))
        .context("Oxc emitted invalid generated direct async batch ESTree JSON")?;
    let generated_functions = generated_top_level_functions(&ast)?;
    let mut candidates = Vec::new();
    collect_direct_async_batches(
        &ast,
        None,
        None,
        DatabaseOperationSource::CompilerGenerated,
        &mut candidates,
    );
    if value_mode == ValueMode::GuestNativeJson {
        candidates.retain(|candidate| !candidate.sequential_value_map_safe);
    }
    candidates.sort_by_key(|candidate| (candidate.start, candidate.end));
    ensure!(
        candidates.len() == authorizations.len(),
        "generated source contains {} Promise.all batches but compiler authorized {}",
        candidates.len(),
        authorizations.len()
    );
    for (authorization, candidate) in authorizations.iter_mut().zip(candidates) {
        authorization.generated_start = candidate.start;
        authorization.generated_end = candidate.end;
        authorization.generated_source_sha256 =
            hash_bytes(source_slice(source, candidate.start, candidate.end)?.as_bytes());
        match &mut authorization.shape {
            DirectAsyncBatchAuthorizationShape::SingleEffectMap {
                callback_parameter,
                operation_id,
                operation_kind,
                result_kind,
                argument_field,
                dynamic_arguments,
                generated_iterator_start,
                generated_iterator_end,
                generated_iterator_sha256,
                helper_callee,
                helper_dynamic_argument_indices,
                helper_continuation,
                ..
            } => {
                ensure!(
                    candidate.batch_kind == "singleEffectMap",
                    "generated mapped batch changed kind"
                );
                let operation = operations
                    .iter()
                    .find(|operation| operation.id == *operation_id)
                    .context("generated direct async batch operation ID disappeared")?;
                let candidate = if let Some(helper_callee) = helper_callee.as_deref() {
                    bind_generated_mapped_helper_candidate(
                        candidate,
                        operation,
                        helper_callee,
                        helper_dynamic_argument_indices,
                    )?
                } else {
                    ensure!(
                        candidate.shape_error.is_none(),
                        "generated authorized mapped Promise.all changed to an unsupported shape"
                    );
                    candidate
                };
                if let Some(continuation) = helper_continuation {
                    bind_generated_helper_continuation(
                        source,
                        &generated_functions,
                        &candidate.helper_arguments,
                        helper_dynamic_argument_indices,
                        continuation,
                    )?;
                }
                ensure!(
                    direct_batch_operation_matches(operation, &candidate)
                        && candidate.iterator_field == *argument_field
                        && candidate.callback_parameter.as_deref()
                            == Some(callback_parameter.as_str()),
                    "generated direct async batch does not match its compiler authorization"
                );
                ensure!(
                    *operation_kind == operation.kind
                        && *result_kind == direct_batch_result_kind(operation)?
                        && dynamic_arguments.len() == candidate.dynamic_arguments.len(),
                    "generated direct async batch descriptor metadata changed"
                );
                let iterator_start = candidate
                    .iterator_start
                    .context("generated authorized batch has no iterator start")?;
                let iterator_end = candidate
                    .iterator_end
                    .context("generated authorized batch has no iterator end")?;
                *generated_iterator_start = iterator_start;
                *generated_iterator_end = iterator_end;
                *generated_iterator_sha256 =
                    hash_bytes(source_slice(source, iterator_start, iterator_end)?.as_bytes());
                for (argument, generated) in dynamic_arguments
                    .iter_mut()
                    .zip(candidate.dynamic_arguments)
                {
                    bind_generated_direct_async_batch_argument(source, argument, &generated)?;
                }
            }
            DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } => {
                ensure!(
                    candidate.batch_kind == "fixedEffectArray"
                        && children.len() == candidate.fixed_children.len(),
                    "generated fixed batch changed kind or child count"
                );
                for (authorization, generated) in children.iter_mut().zip(candidate.fixed_children)
                {
                    let operation = operations
                        .iter()
                        .find(|operation| operation.id == authorization.operation_id)
                        .context("generated fixed batch child operation ID disappeared")?;
                    let generated =
                        if let Some(helper_callee) = authorization.helper_callee.as_deref() {
                            bind_generated_fixed_helper_candidate(
                                generated,
                                operation,
                                helper_callee,
                                &authorization.helper_dynamic_argument_indices,
                            )?
                        } else {
                            ensure!(
                                generated.shape_error.is_none(),
                                "generated fixed batch child changed to an unsupported shape"
                            );
                            generated
                        };
                    if let Some(continuation) = &mut authorization.helper_continuation {
                        bind_generated_helper_continuation(
                            source,
                            &generated_functions,
                            &generated.helper_arguments,
                            &authorization.helper_dynamic_argument_indices,
                            continuation,
                        )?;
                    }
                    ensure!(
                        direct_fixed_child_operation_matches(operation, &generated)
                            && authorization.operation_kind == operation.kind
                            && authorization.result_kind == direct_batch_result_kind(operation)?
                            && authorization.dynamic_arguments.len()
                                == generated.dynamic_arguments.len(),
                        "generated fixed batch child does not match its compiler authorization"
                    );
                    authorization.generated_start = generated.start;
                    authorization.generated_end = generated.end;
                    authorization.generated_source_sha256 = hash_bytes(
                        source_slice(source, generated.start, generated.end)?.as_bytes(),
                    );
                    for (argument, generated_argument) in authorization
                        .dynamic_arguments
                        .iter_mut()
                        .zip(generated.dynamic_arguments)
                    {
                        bind_generated_direct_async_batch_argument(
                            source,
                            argument,
                            &generated_argument,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn bind_generated_direct_async_batch_argument(
    source: &str,
    authorization: &mut DirectAsyncBatchArgumentAuthorization,
    generated: &SourceRange,
) -> Result<()> {
    authorization.generated_start = generated.start;
    authorization.generated_end = generated.end;
    authorization.generated_sha256 =
        hash_bytes(source_slice(source, generated.start, generated.end)?.as_bytes());
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum SourceEditPlacement {
    Suffix,
    Plain,
    Prefix,
}

#[derive(Clone)]
pub(super) struct SourceEdit {
    start: u32,
    end: u32,
    replacement: String,
    placement: SourceEditPlacement,
    owner_start: u32,
    owner_end: u32,
    inserted_application_globals: BTreeSet<&'static str>,
}

pub(super) fn source_edit(
    start: u32,
    end: u32,
    replacement: impl Into<String>,
    owner: (u32, u32),
) -> SourceEdit {
    SourceEdit {
        start,
        end,
        replacement: replacement.into(),
        placement: SourceEditPlacement::Plain,
        owner_start: owner.0,
        owner_end: owner.1,
        inserted_application_globals: BTreeSet::new(),
    }
}

fn source_insertion(
    offset: u32,
    replacement: impl Into<String>,
    placement: SourceEditPlacement,
    owner: (u32, u32),
) -> SourceEdit {
    SourceEdit {
        start: offset,
        end: offset,
        replacement: replacement.into(),
        placement,
        owner_start: owner.0,
        owner_end: owner.1,
        inserted_application_globals: BTreeSet::new(),
    }
}

impl SourceEdit {
    fn with_inserted_application_globals(
        mut self,
        names: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        self.inserted_application_globals.extend(names);
        self
    }
}

pub(super) fn edit_is_owned_by(edit: &SourceEdit, start: u32, end: u32) -> bool {
    edit.owner_start >= start && edit.owner_end <= end
}

struct AppliedSourceEdits {
    source: String,
    inserted_application_globals: BTreeSet<&'static str>,
}

fn apply_source_edits_with_application_globals(
    source: &str,
    range_start: u32,
    range_end: u32,
    edits: &[SourceEdit],
) -> Result<AppliedSourceEdits> {
    source_slice(source, range_start, range_end)?;
    let mut selected = edits
        .iter()
        .filter(|edit| edit_is_owned_by(edit, range_start, range_end))
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| {
                let rank = |placement| match placement {
                    SourceEditPlacement::Suffix => 0u8,
                    SourceEditPlacement::Plain => 1,
                    SourceEditPlacement::Prefix => 2,
                };
                rank(left.placement).cmp(&rank(right.placement))
            })
            .then_with(|| match left.placement {
                SourceEditPlacement::Prefix => right.owner_end.cmp(&left.owner_end),
                SourceEditPlacement::Suffix => right.owner_start.cmp(&left.owner_start),
                SourceEditPlacement::Plain => left.end.cmp(&right.end),
            })
    });
    let replacements = selected
        .iter()
        .filter(|edit| edit.start < edit.end)
        .collect::<Vec<_>>();
    for pair in replacements.windows(2) {
        ensure!(
            pair[0].end <= pair[1].start,
            "compiler-owned generated-source edits overlap"
        );
    }
    for insertion in selected.iter().filter(|edit| edit.start == edit.end) {
        ensure!(
            replacements.iter().all(|replacement| {
                insertion.start <= replacement.start || insertion.start >= replacement.end
            }),
            "compiler-owned generated-source insertion is inside a replacement"
        );
    }

    let mut output = String::new();
    let mut inserted_application_globals = BTreeSet::new();
    let mut cursor = range_start;
    let mut index = 0usize;
    while index < selected.len() {
        let offset = selected[index].start;
        ensure!(
            offset >= cursor && offset <= range_end,
            "compiler-owned generated-source edit is outside its range"
        );
        output.push_str(source_slice(source, cursor, offset)?);
        while index < selected.len()
            && selected[index].start == offset
            && selected[index].start == selected[index].end
        {
            output.push_str(&selected[index].replacement);
            inserted_application_globals.extend(&selected[index].inserted_application_globals);
            index += 1;
        }
        if index < selected.len() && selected[index].start == offset {
            let replacement = &selected[index];
            ensure!(
                replacement.end <= range_end,
                "compiler-owned generated-source replacement exceeds its range"
            );
            output.push_str(&replacement.replacement);
            inserted_application_globals.extend(&replacement.inserted_application_globals);
            cursor = replacement.end;
            index += 1;
        } else {
            cursor = offset;
        }
    }
    output.push_str(source_slice(source, cursor, range_end)?);
    Ok(AppliedSourceEdits {
        source: output,
        inserted_application_globals,
    })
}

pub(super) fn apply_source_edits(
    source: &str,
    range_start: u32,
    range_end: u32,
    edits: &[SourceEdit],
) -> Result<String> {
    Ok(apply_source_edits_with_application_globals(source, range_start, range_end, edits)?.source)
}

fn collect_mutable_object_bindings(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("AssignmentExpression")
                && let Some(left) = object.get("left")
                && node_type(left).ok() == Some("MemberExpression")
                && let Some(receiver) = left.get("object")
                && let Ok(name) = identifier_name(receiver)
            {
                output.insert(name);
            }
            for child in object.values() {
                collect_mutable_object_bindings(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_mutable_object_bindings(child, output);
            }
        }
        _ => {}
    }
}

pub(super) struct GeneratedFilterAuthorization {
    pub(super) initializer_start: u32,
    pub(super) initializer_end: u32,
    pub(super) source_start: u32,
    pub(super) source_end: u32,
    pub(super) callback_start: u32,
    pub(super) callback_end: u32,
}

pub(super) struct ProvedGeneratedFilter {
    pub(super) filter: LocalFilteredArrayCandidate,
    pub(super) generated_unit_binding: String,
    pub(super) file: String,
    pub(super) dependency_chain: Vec<String>,
}

pub(super) fn generated_top_level_function_spans(
    ast: &Value,
) -> Result<BTreeMap<String, (u32, u32)>> {
    ensure!(
        node_type(ast)? == "Program",
        "generated filter proof root is not a Program"
    );
    let statements = ast
        .get("body")
        .and_then(Value::as_array)
        .context("generated filter proof Program has no body")?;
    let mut functions = BTreeMap::new();
    for statement in statements {
        if node_type(statement).ok() == Some("FunctionDeclaration")
            && let Some(identifier) = statement.get("id")
        {
            let name = identifier_name(identifier)?;
            ensure!(
                functions.insert(name.clone(), span(statement)?).is_none(),
                "generated top-level function binding {name} is duplicated"
            );
            continue;
        }
        if node_type(statement).ok() != Some("VariableDeclaration") {
            continue;
        }
        let declarations = statement
            .get("declarations")
            .and_then(Value::as_array)
            .context("generated top-level variable declaration has no declarations")?;
        for declaration in declarations {
            let (Some(identifier), Some(initializer)) =
                (declaration.get("id"), declaration.get("init"))
            else {
                continue;
            };
            let initializer = unwrap_transparent_expression(initializer);
            if !matches!(
                node_type(initializer).ok(),
                Some("ArrowFunctionExpression" | "FunctionExpression")
            ) {
                continue;
            }
            let name = identifier_name(identifier)?;
            ensure!(
                functions.insert(name.clone(), span(initializer)?).is_none(),
                "generated top-level function binding {name} is duplicated"
            );
        }
    }
    Ok(functions)
}

pub(super) enum GeneratedFilterBindings {
    Authorized(BTreeMap<(u32, u32), GeneratedFilterAuthorization>),
    Rejected(usize),
}

fn authorized_generated_filters(
    ast: &Value,
    proved_filters: &[ProvedGeneratedFilter],
) -> Result<GeneratedFilterBindings> {
    let mut filtered_arrays = Vec::new();
    collect_local_filtered_array_candidates(ast, None, &mut filtered_arrays);
    let top_level_functions = generated_top_level_function_spans(ast)?;
    let mut authorizations = BTreeMap::new();
    for (index, proved) in proved_filters.iter().enumerate() {
        let Some(generated_function_span) = top_level_functions.get(&proved.generated_unit_binding)
        else {
            return Ok(GeneratedFilterBindings::Rejected(index));
        };
        let matching_filters = filtered_arrays
            .iter()
            .filter(|filtered| {
                filtered.enclosing_function_start == Some(generated_function_span.0)
                    && filtered.enclosing_function_end == Some(generated_function_span.1)
                    && filtered.name == proved.filter.name
                    && filtered.source_binding == proved.filter.source_binding
                    && filtered.argument_root == proved.filter.argument_root
                    && filtered.argument_field == proved.filter.argument_field
                    && filtered.predicate_field == proved.filter.predicate_field
            })
            .collect::<Vec<_>>();
        if matching_filters.len() != 1 {
            return Ok(GeneratedFilterBindings::Rejected(index));
        }
        let filtered = matching_filters[0];
        let key = (filtered.initializer_start, filtered.initializer_end);
        if authorizations
            .insert(
                key,
                GeneratedFilterAuthorization {
                    initializer_start: filtered.initializer_start,
                    initializer_end: filtered.initializer_end,
                    source_start: filtered.source_reference_start,
                    source_end: filtered.source_reference_end,
                    callback_start: filtered.callback_start,
                    callback_end: filtered.callback_end,
                },
            )
            .is_some()
        {
            return Ok(GeneratedFilterBindings::Rejected(index));
        }
    }
    Ok(GeneratedFilterBindings::Authorized(authorizations))
}

fn find_generated_keyword(source: &str, start: u32, end: u32, keyword: &str) -> Result<(u32, u32)> {
    let text = source_slice(source, start, end)?;
    let mut matches = text.match_indices(keyword).filter(|(offset, _)| {
        let before = text[..*offset].chars().next_back();
        let after = text[*offset + keyword.len()..].chars().next();
        !before.is_some_and(|character| {
            character == '$' || character == '_' || character.is_alphanumeric()
        }) && !after.is_some_and(|character| {
            character == '$' || character == '_' || character.is_alphanumeric()
        })
    });
    let (offset, _) = matches
        .next()
        .with_context(|| format!("generated {keyword} keyword disappeared"))?;
    let keyword_start = start + u32::try_from(offset)?;
    let mut keyword_end = keyword_start + u32::try_from(keyword.len())?;
    while source
        .as_bytes()
        .get(usize::try_from(keyword_end)?)
        .is_some_and(u8::is_ascii_whitespace)
    {
        keyword_end += 1;
    }
    Ok((keyword_start, keyword_end))
}

fn collect_generated_source_edits(
    value: &Value,
    source: &str,
    mutable_objects: &BTreeSet<String>,
    intrinsics: &BTreeMap<String, u32>,
    consumed_intrinsics: &mut BTreeSet<String>,
    authorized_filters: &BTreeMap<(u32, u32), GeneratedFilterAuthorization>,
    consumed_filters: &mut BTreeSet<(u32, u32)>,
    effect_execution_mode: EffectExecutionMode,
    value_mode: ValueMode,
    proved_array_expressions: &BTreeSet<(u32, u32)>,
    output: &mut Vec<SourceEdit>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            let kind = object.get("type").and_then(Value::as_str);
            if matches!(
                kind,
                Some(
                    "ImportDeclaration"
                        | "ImportExpression"
                        | "ExportAllDeclaration"
                        | "ExportDefaultDeclaration"
                        | "ExportNamedDeclaration"
                )
            ) {
                bail!("unsupported module syntax remains in generated source");
            }
            let node_span = span(value).ok();
            if effect_execution_mode == EffectExecutionMode::BlockingFiber
                && value_mode == ValueMode::GuestNativeJson
                && kind == Some("CallExpression")
                && is_static_member_call(value, "Promise", "all")
                && parse_direct_async_batch(
                    value,
                    None,
                    false,
                    DatabaseOperationSource::CompilerGenerated,
                )
                .sequential_value_map_safe
                && let Some(arguments) = object.get("arguments").and_then(Value::as_array)
                && let [argument] = arguments.as_slice()
                && let Some((start, end)) = node_span
            {
                let (argument_start, argument_end) = span(argument)?;
                output.push(source_edit(
                    start,
                    end,
                    source_slice(source, argument_start, argument_end)?.to_string(),
                    (start, end),
                ));
                return Ok(());
            }
            if effect_execution_mode == EffectExecutionMode::BlockingFiber
                && kind == Some("AwaitExpression")
                && let (Some((start, end)), Some(argument)) = (node_span, object.get("argument"))
            {
                let (argument_start, _) = span(argument)?;
                output.push(source_edit(start, argument_start, "", (start, end)));
            }
            if effect_execution_mode == EffectExecutionMode::BlockingFiber
                && matches!(
                    kind,
                    Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
                )
                && object.get("async").and_then(Value::as_bool) == Some(true)
                && let Some((start, end)) = node_span
                && let Some(body) = object.get("body")
            {
                let (body_start, _) = span(body)?;
                let (async_start, async_end) =
                    find_generated_keyword(source, start, body_start, "async")?;
                output.push(source_edit(async_start, async_end, "", (start, end)));
            }
            if kind == Some("VariableDeclarator")
                && let (Some(identifier), Some(initializer)) =
                    (object.get("id"), object.get("init"))
                && node_type(initializer).ok() == Some("ObjectExpression")
                && let Ok(name) = identifier_name(identifier)
                && mutable_objects.contains(&name)
            {
                let (identifier_start, identifier_end) = span(identifier)?;
                output.push(source_insertion(
                    identifier_end,
                    ": any",
                    SourceEditPlacement::Plain,
                    (identifier_start, identifier_end),
                ));
            }

            let mut skip_body_span = None;
            let mut replace_entire_node = false;
            if kind == Some("FunctionDeclaration")
                && let Some(identifier) = object.get("id")
                && let Ok(name) = identifier_name(identifier)
                && let Some(operation_id) = intrinsics.get(&name)
            {
                let parameters = object
                    .get("params")
                    .and_then(Value::as_array)
                    .context("generated intrinsic has no parameter list")?;
                ensure!(
                    parameters.len() == 1,
                    "generated intrinsic {name} must have one parameter"
                );
                let parameter = identifier_name(&parameters[0]).with_context(|| {
                    format!("generated intrinsic {name} parameter is not an identifier")
                })?;
                let body = object
                    .get("body")
                    .context("generated intrinsic has no body")?;
                let body_span = span(body)?;
                output.retain(|edit| !edit_is_owned_by(edit, body_span.0, body_span.1));
                output.push(
                    source_edit(
                        body_span.0,
                        body_span.1,
                        format!("{{return __convexSha256({operation_id}, {parameter});}}"),
                        body_span,
                    )
                    .with_inserted_application_globals(["__convexSha256"]),
                );
                ensure!(
                    consumed_intrinsics.insert(name.clone()),
                    "generated intrinsic {name} is duplicated"
                );
                skip_body_span = Some(body_span);
            }

            if value_mode == ValueMode::Opaque
                && let Some(owner) = node_span
            {
                if let Some(filter) = authorized_filters.get(&owner) {
                    ensure!(
                        owner == (filter.initializer_start, filter.initializer_end),
                        "generated strict filter authorization span changed"
                    );
                    output.push(
                        source_edit(
                            owner.0,
                            owner.1,
                            format!(
                                "__convexMarkArray(__convexFilter({}, {}))",
                                source_slice(source, filter.source_start, filter.source_end)?,
                                source_slice(source, filter.callback_start, filter.callback_end)?
                            ),
                            owner,
                        )
                        .with_inserted_application_globals(["__convexFilter", "__convexMarkArray"]),
                    );
                    ensure!(
                        consumed_filters.insert(owner),
                        "generated strict filter authorization was consumed more than once"
                    );
                    replace_entire_node = true;
                } else if node_span.is_some_and(|span| proved_array_expressions.contains(&span)) {
                    output.push(
                        source_insertion(
                            owner.0,
                            "__convexMarkArray(",
                            SourceEditPlacement::Prefix,
                            owner,
                        )
                        .with_inserted_application_globals(["__convexMarkArray"]),
                    );
                    output.push(source_insertion(
                        owner.1,
                        ")",
                        SourceEditPlacement::Suffix,
                        owner,
                    ));
                }
            }
            for child in object.values() {
                if replace_entire_node {
                    continue;
                }
                if skip_body_span.is_some_and(|body_span| span(child).ok() == Some(body_span)) {
                    continue;
                }
                collect_generated_source_edits(
                    child,
                    source,
                    mutable_objects,
                    intrinsics,
                    consumed_intrinsics,
                    authorized_filters,
                    consumed_filters,
                    effect_execution_mode,
                    value_mode,
                    proved_array_expressions,
                    output,
                )?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_generated_source_edits(
                    child,
                    source,
                    mutable_objects,
                    intrinsics,
                    consumed_intrinsics,
                    authorized_filters,
                    consumed_filters,
                    effect_execution_mode,
                    value_mode,
                    proved_array_expressions,
                    output,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn bind_generated_filters(
    source: &str,
    proved_filters: &[ProvedGeneratedFilter],
) -> Result<GeneratedFilterBindings> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "generated filter binding source has {} parser diagnostics",
        parsed.diagnostics.len()
    );
    let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false))
        .context("Oxc emitted invalid generated filter binding ESTree JSON")?;
    authorized_generated_filters(&ast, proved_filters)
}

fn collect_guest_native_constructor_edits(
    value: &Value,
    global_references: &BTreeSet<(String, u32, u32)>,
    output: &mut Vec<SourceEdit>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("NewExpression")
                && let Some(callee) = object.get("callee")
                && let Ok(name) = identifier_name(callee)
                && matches!(name.as_str(), "Map" | "Set")
                && let Ok((start, end)) = span(callee)
                && global_references.contains(&(name.clone(), start, end))
            {
                output.push(source_insertion(
                    end,
                    if name == "Map" { "<any, any>" } else { "<any>" },
                    SourceEditPlacement::Plain,
                    (start, end),
                ));
            }
            for child in object.values() {
                collect_guest_native_constructor_edits(child, global_references, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_guest_native_constructor_edits(child, global_references, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_guest_native_typed_parameter_edits(
    value: &Value,
    output: &mut Vec<SourceEdit>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
            ) && let Some(parameters) = object.get("params").and_then(Value::as_array)
            {
                for parameter in parameters {
                    let parameter = unwrap_runtime_expression(parameter);
                    if node_type(parameter).ok() != Some("AssignmentPattern") {
                        continue;
                    }
                    let Some(left) = parameter.get("left").map(unwrap_runtime_expression) else {
                        continue;
                    };
                    if matches!(
                        node_type(left).ok(),
                        Some("ArrayPattern" | "Identifier" | "ObjectPattern")
                    ) {
                        let (start, end) = span(left)?;
                        output.push(source_insertion(
                            end,
                            ": any",
                            SourceEditPlacement::Plain,
                            (start, end),
                        ));
                    }
                }
            }
            for child in object.values() {
                collect_guest_native_typed_parameter_edits(child, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_guest_native_typed_parameter_edits(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone)]
struct GeneratedArrayBinding {
    name: String,
    binding_start: u32,
}

struct GeneratedFunctionParameter {
    function_name: String,
    function_binding_start: u32,
    index: usize,
    name: String,
    binding_start: u32,
}

struct GeneratedDirectCall<'a> {
    callee_name: String,
    callee_start: u32,
    callee_end: u32,
    arguments: Vec<&'a Value>,
}

#[derive(Clone)]
struct GeneratedForOfArrayLowering {
    start: u32,
    end: u32,
    right_start: u32,
    right_end: u32,
    binding_kind: String,
    binding_name: String,
    body_start: u32,
    body_end: u32,
    body_is_block: bool,
}

#[derive(Clone)]
struct GeneratedArrayFilterLowering {
    start: u32,
    end: u32,
    receiver_start: u32,
    receiver_end: u32,
    callback_start: u32,
    callback_end: u32,
}

#[derive(Debug)]
pub(super) struct GeneratedArrayFilterIneligibility {
    pub(super) start: u32,
    pub(super) reason: &'static str,
}

impl std::fmt::Display for GeneratedArrayFilterIneligibility {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for GeneratedArrayFilterIneligibility {}

fn generated_array_filter_ineligibility(start: u32, reason: &'static str) -> anyhow::Error {
    GeneratedArrayFilterIneligibility { start, reason }.into()
}

#[derive(Debug)]
pub(super) struct GeneratedForOfIneligibility {
    pub(super) start: u32,
    pub(super) reason: &'static str,
}

impl std::fmt::Display for GeneratedForOfIneligibility {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for GeneratedForOfIneligibility {}

fn generated_for_of_ineligibility(start: u32, reason: &'static str) -> anyhow::Error {
    GeneratedForOfIneligibility { start, reason }.into()
}

pub(super) struct GeneratedArrayArgumentAuthorization {
    pub(super) parameter_name: String,
    pub(super) fields: BTreeSet<String>,
}

fn generated_function_parameter_binding_start(
    function: &Value,
    parameter_name: &str,
) -> Option<u32> {
    let parameters = function.get("params")?.as_array()?;
    let parameter = parameters.get(1)?;
    (identifier_name(parameter).ok()?.as_str() == parameter_name)
        .then(|| span(parameter).ok().map(|span| span.0))
        .flatten()
}

fn collect_generated_adapter_callback_bindings(
    value: &Value,
    parameter_name: &str,
    output: &mut Vec<u32>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && let Some(arguments) = object.get("arguments").and_then(Value::as_array)
                && arguments
                    .get(1)
                    .and_then(|argument| identifier_name(argument).ok())
                    .as_deref()
                    == Some("__convexAdapterArguments")
                && let Some(callee) = object.get("callee").map(unwrap_transparent_expression)
                && matches!(
                    node_type(callee).ok(),
                    Some("ArrowFunctionExpression" | "FunctionExpression")
                )
                && let Some(binding_start) =
                    generated_function_parameter_binding_start(callee, parameter_name)
            {
                output.push(binding_start);
            }
            for child in object.values() {
                collect_generated_adapter_callback_bindings(child, parameter_name, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_generated_adapter_callback_bindings(child, parameter_name, output);
            }
        }
        _ => {}
    }
}

fn find_generated_handler(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("VariableDeclarator")
                && object
                    .get("id")
                    .and_then(|identifier| identifier_name(identifier).ok())
                    .as_deref()
                    == Some("__convexWasmHandler")
            {
                return object.get("init").map(unwrap_transparent_expression);
            }
            object.values().find_map(find_generated_handler)
        }
        Value::Array(values) => values.iter().find_map(find_generated_handler),
        _ => None,
    }
}

fn collect_authorized_array_argument_expressions(
    ast: &Value,
    authorization: Option<&GeneratedArrayArgumentAuthorization>,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    safe_array_references: &BTreeSet<(u32, u32)>,
) -> Result<BTreeSet<(u32, u32)>> {
    let Some(authorization) = authorization else {
        return Ok(BTreeSet::new());
    };
    let handler = find_generated_handler(ast)
        .context("generated source lost __convexWasmHandler while binding array arguments")?;
    let mut binding_starts = Vec::new();
    if let Some(binding_start) =
        generated_function_parameter_binding_start(handler, &authorization.parameter_name)
    {
        binding_starts.push(binding_start);
    }
    collect_generated_adapter_callback_bindings(
        handler,
        &authorization.parameter_name,
        &mut binding_starts,
    );
    binding_starts.sort_unstable();
    binding_starts.dedup();
    ensure!(
        binding_starts.len() == 1,
        "authenticated array argument parameter resolved to {} generated handler bindings",
        binding_starts.len()
    );
    let references = resolved_binding_references(
        scoping,
        nodes,
        &authorization.parameter_name,
        binding_starts[0],
    )?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut candidates = BTreeMap::<String, BTreeSet<(u32, u32)>>::new();
    fn visit(
        value: &Value,
        parameter_name: &str,
        fields: &BTreeSet<String>,
        references: &BTreeSet<(u32, u32)>,
        candidates: &mut BTreeMap<String, BTreeSet<(u32, u32)>>,
    ) {
        match value {
            Value::Object(object) => {
                if object.get("type").and_then(Value::as_str) == Some("MemberExpression")
                    && object.get("computed").and_then(Value::as_bool) == Some(false)
                    && let (Some(root), Some(property)) =
                        (object.get("object"), object.get("property"))
                    && identifier_name(root).ok().as_deref() == Some(parameter_name)
                    && let Ok(field) = identifier_name(property)
                    && fields.contains(&field)
                    && span(root)
                        .ok()
                        .is_some_and(|span| references.contains(&span))
                    && let Ok(member_span) = span(value)
                {
                    candidates.entry(field).or_default().insert(member_span);
                }
                for child in object.values() {
                    visit(child, parameter_name, fields, references, candidates);
                }
            }
            Value::Array(values) => {
                for child in values {
                    visit(child, parameter_name, fields, references, candidates);
                }
            }
            _ => {}
        }
    }
    visit(
        handler,
        &authorization.parameter_name,
        &authorization.fields,
        &references,
        &mut candidates,
    );
    let mut authorized = BTreeSet::new();
    for spans in candidates.values() {
        if spans
            .iter()
            .all(|span| safe_array_references.contains(span))
        {
            authorized.extend(spans);
        }
    }
    Ok(authorized)
}

fn generated_global_reference(
    value: &Value,
    expected: &str,
    global_references: &BTreeSet<(String, u32, u32)>,
) -> bool {
    let Ok(name) = identifier_name(value) else {
        return false;
    };
    let Ok((start, end)) = span(value) else {
        return false;
    };
    name == expected && global_references.contains(&(name, start, end))
}

fn generated_string_primitive(value: &Value) -> bool {
    let value = unwrap_runtime_expression(value);
    node_type(value).ok() == Some("TemplateLiteral")
        || (node_type(value).ok() == Some("Literal")
            && value.get("value").is_some_and(Value::is_string))
}

fn generated_regexp_literal(value: &Value) -> bool {
    let value = unwrap_runtime_expression(value);
    node_type(value).ok() == Some("Literal") && value.get("regex").is_some_and(Value::is_object)
}

fn collect_generated_safe_array_references(
    value: &Value,
    write: bool,
    output: &mut BTreeSet<(u32, u32)>,
) {
    match value {
        Value::Object(object) => {
            let kind = object.get("type").and_then(Value::as_str);
            if kind == Some("MemberExpression")
                && !write
                && let Some(receiver) = object.get("object").map(unwrap_transparent_expression)
                && let Ok(receiver_span) = span(receiver)
            {
                output.insert(receiver_span);
            }
            if kind == Some("ForOfStatement")
                && let Some(iterable) = object.get("right").map(unwrap_transparent_expression)
                && let Ok(iterable_span) = span(iterable)
            {
                output.insert(iterable_span);
            }
            for (key, child) in object {
                let child_is_write = match (kind, key.as_str()) {
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
                collect_generated_safe_array_references(child, child_is_write, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_generated_safe_array_references(child, write, output);
            }
        }
        _ => {}
    }
}

fn generated_expression_is_proved_array(
    value: &Value,
    source: &str,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    global_references: &BTreeSet<(String, u32, u32)>,
    array_producing_functions: &BTreeSet<String>,
    authorized_array_arguments: &BTreeSet<(u32, u32)>,
    authorized_batch_spans: &BTreeSet<(u32, u32)>,
    safe_array_references: &BTreeSet<(u32, u32)>,
    array_bindings: &[GeneratedArrayBinding],
) -> Result<bool> {
    let value = unwrap_runtime_expression(value);
    if span(value)
        .ok()
        .is_some_and(|span| authorized_array_arguments.contains(&span))
    {
        return Ok(true);
    }
    match node_type(value).ok() {
        Some("ArrayExpression") => Ok(true),
        Some("AwaitExpression") => {
            let Some(argument) = value.get("argument") else {
                return Ok(false);
            };
            generated_expression_is_proved_array(
                argument,
                source,
                scoping,
                nodes,
                global_references,
                array_producing_functions,
                authorized_array_arguments,
                authorized_batch_spans,
                safe_array_references,
                array_bindings,
            )
        }
        Some("NewExpression") => Ok(value.get("callee").is_some_and(|callee| {
            generated_global_reference(
                unwrap_runtime_expression(callee),
                "Array",
                global_references,
            )
        })),
        Some("CallExpression") => {
            if value.get("callee").is_some_and(|callee| {
                generated_global_reference(
                    unwrap_runtime_expression(callee),
                    "Array",
                    global_references,
                )
            }) {
                return Ok(true);
            }
            if value
                .get("callee")
                .and_then(|callee| identifier_name(callee).ok())
                .is_some_and(|name| array_producing_functions.contains(&name))
            {
                return Ok(true);
            }
            let Some(callee) = value.get("callee").map(unwrap_transparent_expression) else {
                return Ok(false);
            };
            if node_type(callee).ok() != Some("MemberExpression")
                || callee.get("computed").and_then(Value::as_bool) == Some(true)
                || call_has_optional_callee(value)
            {
                return Ok(false);
            }
            let Some(receiver) = callee.get("object").map(unwrap_transparent_expression) else {
                return Ok(false);
            };
            let Some(method) = callee
                .get("property")
                .and_then(|property| identifier_name(property).ok())
            else {
                return Ok(false);
            };
            if method == "all"
                && generated_global_reference(receiver, "Promise", global_references)
                && (span(value)
                    .ok()
                    .is_some_and(|span| authorized_batch_spans.contains(&span))
                    || parse_direct_async_batch(
                        value,
                        None,
                        false,
                        DatabaseOperationSource::CompilerGenerated,
                    )
                    .sequential_value_map_safe)
            {
                return Ok(true);
            }
            if matches!(method.as_str(), "from" | "of")
                && generated_global_reference(receiver, "Array", global_references)
            {
                return Ok(true);
            }
            if matches!(method.as_str(), "entries" | "keys" | "values")
                && generated_global_reference(receiver, "Object", global_references)
            {
                return Ok(true);
            }
            let arguments = value
                .get("arguments")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if method == "split"
                && generated_string_primitive(receiver)
                && arguments.first().is_none_or(|separator| {
                    generated_string_primitive(separator)
                        || generated_regexp_literal(separator)
                        || generated_global_reference(
                            unwrap_runtime_expression(separator),
                            "undefined",
                            global_references,
                        )
                })
            {
                return Ok(true);
            }
            if (method == "exec" && generated_regexp_literal(receiver))
                || (method == "match"
                    && generated_string_primitive(receiver)
                    && arguments
                        .first()
                        .is_some_and(|pattern| generated_regexp_literal(pattern)))
            {
                return Ok(true);
            }
            if matches!(
                method.as_str(),
                "concat"
                    | "filter"
                    | "flat"
                    | "flatMap"
                    | "map"
                    | "slice"
                    | "splice"
                    | "toReversed"
                    | "toSorted"
                    | "toSpliced"
                    | "with"
            ) {
                return generated_reference_is_proved_array(
                    receiver,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                );
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn collect_generated_array_declarations<'a>(
    value: &'a Value,
    output: &mut Vec<(String, u32, &'a Value)>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("VariableDeclarator")
                && let (Some(identifier), Some(initializer)) =
                    (object.get("id"), object.get("init"))
                && let Ok(name) = identifier_name(identifier)
                && let Ok((binding_start, _)) = span(identifier)
            {
                output.push((name, binding_start, initializer));
            }
            for child in object.values() {
                collect_generated_array_declarations(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_generated_array_declarations(child, output);
            }
        }
        _ => {}
    }
}

fn extend_generated_array_bindings_through_initializers(
    ast: &Value,
    source: &str,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    global_references: &BTreeSet<(String, u32, u32)>,
    array_producing_functions: &BTreeSet<String>,
    authorized_array_arguments: &BTreeSet<(u32, u32)>,
    authorized_batch_spans: &BTreeSet<(u32, u32)>,
    safe_array_references: &BTreeSet<(u32, u32)>,
    array_bindings: &mut Vec<GeneratedArrayBinding>,
) -> Result<()> {
    let mut declarations = Vec::new();
    collect_generated_array_declarations(ast, &mut declarations);
    loop {
        let mut additions = Vec::new();
        for (name, binding_start, initializer) in &declarations {
            if array_bindings
                .iter()
                .any(|binding| binding.name == *name && binding.binding_start == *binding_start)
            {
                continue;
            }
            if generated_expression_is_proved_array(
                initializer,
                source,
                scoping,
                nodes,
                global_references,
                array_producing_functions,
                authorized_array_arguments,
                authorized_batch_spans,
                safe_array_references,
                array_bindings,
            )? {
                additions.push(GeneratedArrayBinding {
                    name: name.clone(),
                    binding_start: *binding_start,
                });
            }
        }
        if additions.is_empty() {
            break;
        }
        array_bindings.extend(additions);
    }
    Ok(())
}

fn push_generated_function_parameters(
    function: &Value,
    function_name: String,
    function_binding_start: u32,
    output: &mut Vec<GeneratedFunctionParameter>,
) {
    let Some(parameters) = function.get("params").and_then(Value::as_array) else {
        return;
    };
    for (index, parameter) in parameters.iter().enumerate() {
        let (Ok(name), Ok((binding_start, _))) = (identifier_name(parameter), span(parameter))
        else {
            continue;
        };
        output.push(GeneratedFunctionParameter {
            function_name: function_name.clone(),
            function_binding_start,
            index,
            name,
            binding_start,
        });
    }
}

fn collect_generated_top_level_function_parameters(
    ast: &Value,
) -> Result<Vec<GeneratedFunctionParameter>> {
    ensure!(
        node_type(ast)? == "Program",
        "generated array parameter proof root is not a Program"
    );
    let statements = ast
        .get("body")
        .and_then(Value::as_array)
        .context("generated array parameter proof Program has no body")?;
    let mut parameters = Vec::new();
    for statement in statements {
        if node_type(statement).ok() == Some("FunctionDeclaration")
            && let Some(identifier) = statement.get("id")
            && let (Ok(name), Ok((binding_start, _))) =
                (identifier_name(identifier), span(identifier))
        {
            push_generated_function_parameters(statement, name, binding_start, &mut parameters);
            continue;
        }
        if node_type(statement).ok() != Some("VariableDeclaration") {
            continue;
        }
        let Some(declarations) = statement.get("declarations").and_then(Value::as_array) else {
            continue;
        };
        for declaration in declarations {
            let (Some(identifier), Some(initializer)) =
                (declaration.get("id"), declaration.get("init"))
            else {
                continue;
            };
            let initializer = unwrap_transparent_expression(initializer);
            if !matches!(
                node_type(initializer).ok(),
                Some("ArrowFunctionExpression" | "FunctionExpression")
            ) {
                continue;
            }
            let (Ok(name), Ok((binding_start, _))) =
                (identifier_name(identifier), span(identifier))
            else {
                continue;
            };
            push_generated_function_parameters(initializer, name, binding_start, &mut parameters);
        }
    }
    Ok(parameters)
}

fn collect_generated_direct_calls<'a>(value: &'a Value, output: &mut Vec<GeneratedDirectCall<'a>>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && !call_has_optional_callee(value)
                && let Some(callee) = object.get("callee").map(unwrap_transparent_expression)
                && let Ok(callee_name) = identifier_name(callee)
                && let Ok((callee_start, callee_end)) = span(callee)
                && let Some(arguments) = object.get("arguments").and_then(Value::as_array)
            {
                output.push(GeneratedDirectCall {
                    callee_name,
                    callee_start,
                    callee_end,
                    arguments: arguments.iter().collect(),
                });
            }
            for child in object.values() {
                collect_generated_direct_calls(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_generated_direct_calls(child, output);
            }
        }
        _ => {}
    }
}

fn generated_reference_is_proved_array(
    value: &Value,
    source: &str,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    global_references: &BTreeSet<(String, u32, u32)>,
    array_producing_functions: &BTreeSet<String>,
    authorized_array_arguments: &BTreeSet<(u32, u32)>,
    authorized_batch_spans: &BTreeSet<(u32, u32)>,
    safe_array_references: &BTreeSet<(u32, u32)>,
    array_bindings: &[GeneratedArrayBinding],
) -> Result<bool> {
    let value = unwrap_runtime_expression(value);
    if generated_expression_is_proved_array(
        value,
        source,
        scoping,
        nodes,
        global_references,
        array_producing_functions,
        authorized_array_arguments,
        authorized_batch_spans,
        safe_array_references,
        array_bindings,
    )? {
        return Ok(true);
    }
    let Ok(name) = identifier_name(value) else {
        return Ok(false);
    };
    let reference_span = span(value)?;
    let mut matching_bindings = 0;
    for binding in array_bindings.iter().filter(|binding| binding.name == name) {
        let references =
            resolved_binding_references(scoping, nodes, &binding.name, binding.binding_start)?;
        if references.contains(&reference_span)
            && references.iter().all(|reference| {
                *reference == reference_span || safe_array_references.contains(reference)
            })
        {
            matching_bindings += 1;
        }
    }
    Ok(matching_bindings == 1)
}

#[allow(clippy::too_many_arguments)]
fn collect_generated_proved_array_expressions(
    value: &Value,
    source: &str,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    global_references: &BTreeSet<(String, u32, u32)>,
    array_producing_functions: &BTreeSet<String>,
    authorized_array_arguments: &BTreeSet<(u32, u32)>,
    authorized_batch_spans: &BTreeSet<(u32, u32)>,
    safe_array_references: &BTreeSet<(u32, u32)>,
    array_bindings: &[GeneratedArrayBinding],
    pre_marked_array_expressions: &BTreeSet<(u32, u32)>,
    output: &mut BTreeSet<(u32, u32)>,
) -> Result<()> {
    let range = span(value).ok();
    // Mark each expression that creates or receives an array. Identifiers and transparent
    // wrappers only refer to an existing value. Query-result flow proves array provenance but
    // does not mark arrays created later by map, filter, or other built-in array operations.
    if matches!(
        node_type(value).ok(),
        Some("ArrayExpression" | "NewExpression" | "CallExpression")
    ) && range.is_some_and(|range| !pre_marked_array_expressions.contains(&range))
        && generated_expression_is_proved_array(
            value,
            source,
            scoping,
            nodes,
            global_references,
            array_producing_functions,
            authorized_array_arguments,
            authorized_batch_spans,
            safe_array_references,
            array_bindings,
        )?
        && range.is_some()
    {
        output.insert(range.expect("array expression span disappeared"));
    }
    match value {
        Value::Object(object) => {
            for child in object.values() {
                collect_generated_proved_array_expressions(
                    child,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                    pre_marked_array_expressions,
                    output,
                )?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_generated_proved_array_expressions(
                    child,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                    pre_marked_array_expressions,
                    output,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn extend_generated_array_bindings_through_parameters(
    ast: &Value,
    source: &str,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    global_references: &BTreeSet<(String, u32, u32)>,
    array_producing_functions: &BTreeSet<String>,
    authorized_array_arguments: &BTreeSet<(u32, u32)>,
    authorized_batch_spans: &BTreeSet<(u32, u32)>,
    safe_array_references: &BTreeSet<(u32, u32)>,
    array_bindings: &mut Vec<GeneratedArrayBinding>,
) -> Result<()> {
    let parameters = collect_generated_top_level_function_parameters(ast)?;
    let mut calls = Vec::new();
    collect_generated_direct_calls(ast, &mut calls);
    loop {
        let mut additions = Vec::new();
        for parameter in &parameters {
            if array_bindings.iter().any(|binding| {
                binding.name == parameter.name && binding.binding_start == parameter.binding_start
            }) {
                continue;
            }
            let function_references = resolved_binding_references(
                scoping,
                nodes,
                &parameter.function_name,
                parameter.function_binding_start,
            )?;
            let direct_calls = calls
                .iter()
                .filter(|call| {
                    call.callee_name == parameter.function_name
                        && function_references.contains(&(call.callee_start, call.callee_end))
                })
                .collect::<Vec<_>>();
            if direct_calls.is_empty() || function_references.len() != direct_calls.len() {
                continue;
            }
            let parameter_references = resolved_binding_references(
                scoping,
                nodes,
                &parameter.name,
                parameter.binding_start,
            )?;
            if !parameter_references
                .iter()
                .all(|reference| safe_array_references.contains(reference))
            {
                continue;
            }
            let mut arguments_are_arrays = true;
            for call in direct_calls {
                let Some(argument) = call.arguments.get(parameter.index) else {
                    arguments_are_arrays = false;
                    break;
                };
                if !generated_reference_is_proved_array(
                    argument,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                )? {
                    arguments_are_arrays = false;
                    break;
                }
            }
            if !arguments_are_arrays {
                continue;
            }
            additions.push(GeneratedArrayBinding {
                name: parameter.name.clone(),
                binding_start: parameter.binding_start,
            });
        }
        if additions.is_empty() {
            break;
        }
        array_bindings.extend(additions);
    }
    Ok(())
}

struct GeneratedTopLevelFunction<'a> {
    name: String,
    binding_start: u32,
    function: &'a Value,
}

fn generated_top_level_functions(ast: &Value) -> Result<Vec<GeneratedTopLevelFunction<'_>>> {
    ensure!(
        node_type(ast)? == "Program",
        "generated callback proof root is not a Program"
    );
    let statements = ast
        .get("body")
        .and_then(Value::as_array)
        .context("generated callback proof Program has no body")?;
    let mut functions = Vec::new();
    for statement in statements {
        if node_type(statement).ok() == Some("FunctionDeclaration")
            && let Some(identifier) = statement.get("id")
            && let (Ok(name), Ok((binding_start, _))) =
                (identifier_name(identifier), span(identifier))
        {
            functions.push(GeneratedTopLevelFunction {
                name,
                binding_start,
                function: statement,
            });
            continue;
        }
        if node_type(statement).ok() != Some("VariableDeclaration") {
            continue;
        }
        let Some(declarations) = statement.get("declarations").and_then(Value::as_array) else {
            continue;
        };
        for declaration in declarations {
            let (Some(identifier), Some(initializer)) =
                (declaration.get("id"), declaration.get("init"))
            else {
                continue;
            };
            let initializer = unwrap_transparent_expression(initializer);
            if !matches!(
                node_type(initializer).ok(),
                Some("ArrowFunctionExpression" | "FunctionExpression")
            ) {
                continue;
            }
            let (Ok(name), Ok((binding_start, _))) =
                (identifier_name(identifier), span(identifier))
            else {
                continue;
            };
            functions.push(GeneratedTopLevelFunction {
                name,
                binding_start,
                function: initializer,
            });
        }
    }
    Ok(functions)
}

fn resolved_generated_top_level_function<'a>(
    reference: &Value,
    functions: &'a [GeneratedTopLevelFunction<'a>],
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
) -> Result<Option<&'a GeneratedTopLevelFunction<'a>>> {
    let Ok(name) = identifier_name(reference) else {
        return Ok(None);
    };
    let reference_span = span(reference)?;
    let mut matches = Vec::new();
    for function in functions.iter().filter(|function| function.name == name) {
        let references =
            resolved_binding_references(scoping, nodes, &function.name, function.binding_start)?;
        if references.contains(&reference_span) {
            matches.push(function);
        }
    }
    ensure!(
        matches.len() <= 1,
        "generated callback reference {name} resolved to multiple top-level functions"
    );
    Ok(matches.pop())
}

fn validate_generated_filter_callback_node(
    value: &Value,
    root: bool,
    functions: &[GeneratedTopLevelFunction<'_>],
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    global_references: &BTreeSet<(String, u32, u32)>,
    visiting: &mut BTreeSet<u32>,
) -> Result<Option<&'static str>> {
    let Value::Object(object) = value else {
        if let Value::Array(values) = value {
            for child in values {
                if let Some(reason) = validate_generated_filter_callback_node(
                    child,
                    false,
                    functions,
                    scoping,
                    nodes,
                    global_references,
                    visiting,
                )? {
                    return Ok(Some(reason));
                }
            }
        }
        return Ok(None);
    };
    let kind = object.get("type").and_then(Value::as_str);
    if matches!(kind, Some("AwaitExpression" | "YieldExpression")) {
        return Ok(Some(
            "guest-native array filter callback cannot suspend or yield",
        ));
    }
    if matches!(
        kind,
        Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
    ) {
        if object.get("async").and_then(Value::as_bool) == Some(true)
            || object.get("generator").and_then(Value::as_bool) == Some(true)
        {
            return Ok(Some(
                "guest-native array filter callback must be synchronous and non-generator",
            ));
        }
        if !root {
            return Ok(Some(
                "guest-native array filter callback cannot contain a nested function",
            ));
        }
    }
    if kind == Some("CallExpression") {
        let Some(callee) = object.get("callee").map(unwrap_transparent_expression) else {
            return Ok(Some(
                "guest-native array filter callback call target is missing",
            ));
        };
        if let Some(segments) = static_member_segments(callee)
            && (segments.windows(2).any(|window| {
                matches!(window[0].as_str(), "db" | "scheduler")
                    || (window[0] == "auth" && window[1] == "getUserIdentity")
                    || (window[0] == "storage"
                        && matches!(
                            window[1].as_str(),
                            "delete" | "generateUploadUrl" | "getMetadata" | "getUrl"
                        ))
            }) || segments.last().is_some_and(|method| {
                matches!(
                    method.as_str(),
                    "runAction" | "runMutation" | "runQuery" | "vectorSearch"
                )
            }))
        {
            return Ok(Some(
                "guest-native array filter callback cannot perform a Convex effect",
            ));
        }
        if identifier_name(callee).is_ok() {
            if let Some(target) =
                resolved_generated_top_level_function(callee, functions, scoping, nodes)?
            {
                if visiting.insert(target.binding_start) {
                    let result = validate_generated_filter_callback_node(
                        target.function,
                        true,
                        functions,
                        scoping,
                        nodes,
                        global_references,
                        visiting,
                    )?;
                    visiting.remove(&target.binding_start);
                    if result.is_some() {
                        return Ok(result);
                    }
                }
            } else {
                let name = identifier_name(callee)?;
                let (start, end) = span(callee)?;
                if !global_references.contains(&(name, start, end)) {
                    return Ok(Some(
                        "guest-native array filter callback cannot invoke a dynamic function",
                    ));
                }
            }
        }
    }
    for child in object.values() {
        if let Some(reason) = validate_generated_filter_callback_node(
            child,
            false,
            functions,
            scoping,
            nodes,
            global_references,
            visiting,
        )? {
            return Ok(Some(reason));
        }
    }
    Ok(None)
}

fn generated_filter_callback<'a>(
    callback: &'a Value,
    functions: &'a [GeneratedTopLevelFunction<'a>],
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
) -> Result<Option<&'a Value>> {
    let callback = unwrap_transparent_expression(callback);
    if matches!(
        node_type(callback).ok(),
        Some("ArrowFunctionExpression" | "FunctionExpression")
    ) {
        return Ok(Some(callback));
    }
    Ok(
        resolved_generated_top_level_function(callback, functions, scoping, nodes)?
            .map(|function| function.function),
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_generated_array_filter_lowerings(
    value: &Value,
    source: &str,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    global_references: &BTreeSet<(String, u32, u32)>,
    array_producing_functions: &BTreeSet<String>,
    authorized_array_arguments: &BTreeSet<(u32, u32)>,
    authorized_batch_spans: &BTreeSet<(u32, u32)>,
    safe_array_references: &BTreeSet<(u32, u32)>,
    array_bindings: &[GeneratedArrayBinding],
    functions: &[GeneratedTopLevelFunction<'_>],
    output: &mut Vec<GeneratedArrayFilterLowering>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && call_method_name(value).as_deref() == Some("filter")
            {
                let (start, end) = span(value)?;
                if call_has_optional_callee(value) {
                    return Err(generated_array_filter_ineligibility(
                        start,
                        "guest-native array filter does not allow optional member access or calls",
                    ));
                }
                let callee = object
                    .get("callee")
                    .context("generated array-filter call has no callee")?;
                if callee.get("computed").and_then(Value::as_bool) == Some(true) {
                    return Err(generated_array_filter_ineligibility(
                        start,
                        "guest-native array filter requires direct .filter member syntax",
                    ));
                }
                let arguments = object
                    .get("arguments")
                    .and_then(Value::as_array)
                    .context("generated array-filter call has no arguments")?;
                let [callback] = arguments.as_slice() else {
                    return Err(generated_array_filter_ineligibility(
                        start,
                        "guest-native array filter requires exactly one callback and does not support thisArg",
                    ));
                };
                if node_type(callback).ok() == Some("SpreadElement") {
                    return Err(generated_array_filter_ineligibility(
                        start,
                        "guest-native array filter does not allow a spread callback argument",
                    ));
                }
                let Some(callback_function) =
                    generated_filter_callback(callback, functions, scoping, nodes)?
                else {
                    return Err(generated_array_filter_ineligibility(
                        start,
                        "guest-native array filter callback must be an inline function or one statically resolved top-level function",
                    ));
                };
                if let Some(reason) = validate_generated_filter_callback_node(
                    callback_function,
                    true,
                    functions,
                    scoping,
                    nodes,
                    global_references,
                    &mut BTreeSet::new(),
                )? {
                    return Err(generated_array_filter_ineligibility(start, reason));
                }
                let receiver = callee
                    .get("object")
                    .map(unwrap_transparent_expression)
                    .context("generated array-filter call has no receiver")?;
                if !generated_reference_is_proved_array(
                    receiver,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                )? {
                    return Err(generated_array_filter_ineligibility(
                        start,
                        "guest-native array filter receiver is not one non-escaping, statically proven ordinary array",
                    ));
                }
                let (receiver_start, receiver_end) = span(receiver)?;
                let callback = unwrap_transparent_expression(callback);
                let (callback_start, callback_end) = span(callback)?;
                output.push(GeneratedArrayFilterLowering {
                    start,
                    end,
                    receiver_start,
                    receiver_end,
                    callback_start,
                    callback_end,
                });
            }
            for child in object.values() {
                collect_generated_array_filter_lowerings(
                    child,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                    functions,
                    output,
                )?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_generated_array_filter_lowerings(
                    child,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                    functions,
                    output,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_generated_for_of_array_lowerings(
    value: &Value,
    source: &str,
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
    global_references: &BTreeSet<(String, u32, u32)>,
    array_producing_functions: &BTreeSet<String>,
    authorized_array_arguments: &BTreeSet<(u32, u32)>,
    authorized_batch_spans: &BTreeSet<(u32, u32)>,
    safe_array_references: &BTreeSet<(u32, u32)>,
    array_bindings: &[GeneratedArrayBinding],
    output: &mut Vec<GeneratedForOfArrayLowering>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("ForOfStatement")
                && object.get("await").and_then(Value::as_bool) != Some(true)
            {
                let (start, end) = span(value)?;
                let left = object
                    .get("left")
                    .context("generated for...of has no binding")?;
                if node_type(left)? != "VariableDeclaration" {
                    return Err(generated_for_of_ineligibility(
                        start,
                        "guest-native for...of requires one lexical identifier binding",
                    ));
                }
                let Some(binding_kind) = left
                    .get("kind")
                    .and_then(Value::as_str)
                    .filter(|kind| matches!(*kind, "const" | "let"))
                else {
                    return Err(generated_for_of_ineligibility(
                        start,
                        "guest-native for...of binding must be const or let",
                    ));
                };
                let binding_kind = binding_kind.to_string();
                let declarations = left
                    .get("declarations")
                    .and_then(Value::as_array)
                    .context("generated for...of binding declarations are missing")?;
                let [declaration] = declarations.as_slice() else {
                    return Err(generated_for_of_ineligibility(
                        start,
                        "guest-native for...of requires exactly one binding",
                    ));
                };
                if !declaration.get("init").is_none_or(Value::is_null) {
                    return Err(generated_for_of_ineligibility(
                        start,
                        "guest-native for...of binding must not have an initializer",
                    ));
                }
                let binding_identifier = declaration
                    .get("id")
                    .context("generated for...of binding identifier is missing")?;
                let binding_name = identifier_name(binding_identifier).map_err(|_| {
                    generated_for_of_ineligibility(
                        start,
                        "guest-native for...of destructuring bindings are unsupported",
                    )
                })?;
                let right = object
                    .get("right")
                    .context("generated for...of iterable is missing")?;
                let (right_start, right_end) = span(right)?;
                let right_is_array = generated_reference_is_proved_array(
                    right,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                )?;
                if !right_is_array {
                    return Err(generated_for_of_ineligibility(
                        start,
                        "guest-native for...of iterable is not one non-escaping, statically proven ordinary array",
                    ));
                }
                let body = object
                    .get("body")
                    .context("generated for...of body is missing")?;
                let (body_start, body_end) = span(body)?;
                output.push(GeneratedForOfArrayLowering {
                    start,
                    end,
                    right_start,
                    right_end,
                    binding_kind,
                    binding_name,
                    body_start,
                    body_end,
                    body_is_block: node_type(body)? == "BlockStatement",
                });
            }
            for child in object.values() {
                collect_generated_for_of_array_lowerings(
                    child,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                    output,
                )?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_generated_for_of_array_lowerings(
                    child,
                    source,
                    scoping,
                    nodes,
                    global_references,
                    array_producing_functions,
                    authorized_array_arguments,
                    authorized_batch_spans,
                    safe_array_references,
                    array_bindings,
                    output,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn contains_synchronous_for_of(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            (object.get("type").and_then(Value::as_str) == Some("ForOfStatement")
                && object.get("await").and_then(Value::as_bool) != Some(true))
                || object.values().any(contains_synchronous_for_of)
        }
        Value::Array(values) => values.iter().any(contains_synchronous_for_of),
        _ => false,
    }
}

fn collect_estree_identifier_names(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("Identifier")
                && let Some(name) = object.get("name").and_then(Value::as_str)
            {
                output.insert(name.to_string());
            }
            for child in object.values() {
                collect_estree_identifier_names(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_estree_identifier_names(child, output);
            }
        }
        _ => {}
    }
}

fn ensure_generated_helper_identifiers_are_available(
    source_value_symbol_names: &BTreeSet<String>,
    value_mode: ValueMode,
    effect_execution_mode: EffectExecutionMode,
    has_intrinsics: bool,
    has_proved_array_expressions: bool,
    has_authorized_filters: bool,
    batches: &[DirectAsyncBatchAuthorization],
) -> Result<BTreeSet<&'static str>> {
    let mut required = BTreeSet::new();
    if has_intrinsics {
        required.insert("__convexSha256");
    }
    if value_mode == ValueMode::Opaque && (has_proved_array_expressions || has_authorized_filters) {
        required.insert("__convexMarkArray");
    }
    if value_mode == ValueMode::Opaque && has_authorized_filters {
        required.insert("__convexFilter");
    }
    if effect_execution_mode == EffectExecutionMode::BlockingFiber {
        for batch in batches {
            match &batch.shape {
                DirectAsyncBatchAuthorizationShape::SingleEffectMap {
                    helper_continuation,
                    ..
                } => {
                    required.insert("__convexAsyncBatch");
                    if let Some(continuation) = helper_continuation {
                        required.insert("__convexMarkArray");
                        if continuation.dependency_adapter.is_some() {
                            required.extend(["Error", "String"]);
                        }
                    }
                }
                DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } => {
                    required.insert("__convexAsyncFixedBatch");
                    if children
                        .iter()
                        .any(|child| child.helper_continuation.is_some())
                    {
                        required.insert("__convexMarkArray");
                    }
                    if children.iter().any(|child| {
                        child
                            .helper_continuation
                            .as_ref()
                            .is_some_and(|continuation| continuation.dependency_adapter.is_some())
                    }) {
                        required.extend(["Error", "String"]);
                    }
                }
            }
        }
    }
    let collisions = required
        .iter()
        .copied()
        .filter(|name| source_value_symbol_names.contains(*name))
        .collect::<Vec<_>>();
    if !collisions.is_empty() {
        let message = format!(
            "generated source already binds reserved lowering helper identifier{} {}",
            if collisions.len() == 1 { "" } else { "s" },
            collisions.join(", ")
        );
        return Err(generated_source_binding_collision(
            collisions.into_iter().map(str::to_string).collect(),
            message,
        ));
    }
    Ok(required)
}

fn value_symbol_names(scoping: &Scoping) -> BTreeSet<String> {
    scoping
        .symbol_ids()
        .filter(|symbol_id| scoping.symbol_flags(*symbol_id).is_value())
        .map(|symbol_id| scoping.symbol_name(symbol_id).to_string())
        .collect()
}

fn unresolved_value_reference_count(scoping: &Scoping, name: &str) -> usize {
    scoping
        .root_unresolved_references()
        .iter()
        .find(|(unresolved, _)| unresolved.as_str() == name)
        .map_or(0, |(_, reference_ids)| {
            reference_ids
                .iter()
                .filter(|reference_id| {
                    let flags = scoping.get_reference(**reference_id).flags();
                    flags.is_value() && !flags.is_value_as_type()
                })
                .count()
        })
}

fn validate_generated_javascript_authority(
    scoping: &Scoping,
    authority: &GeneratedJavascriptAuthority,
    require_application_globals: bool,
) -> Result<()> {
    let root_scope = scoping.root_scope_id();
    for name in &authority.compiler_top_level_bindings {
        let matching_symbols = scoping
            .symbol_ids()
            .filter(|symbol_id| {
                scoping.symbol_flags(*symbol_id).is_value()
                    && scoping.symbol_name(*symbol_id) == name
            })
            .collect::<Vec<_>>();
        if matching_symbols.len() > 1 {
            return Err(generated_source_binding_collision(
                vec![name.clone()],
                format!(
                    "compiler-generated top-level binding {name} is missing or shadowed by a source binding"
                ),
            ));
        }
        ensure!(
            matching_symbols.len() == 1,
            "compiler-generated top-level binding {name} is missing or shadowed by a source binding"
        );
        let symbol = matching_symbols[0];
        if scoping.symbol_scope_id(symbol) != root_scope
            || !scoping.symbol_redeclarations(symbol).is_empty()
        {
            return Err(generated_source_binding_collision(
                vec![name.clone()],
                format!(
                    "compiler-generated top-level binding {name} is not one exact root declaration"
                ),
            ));
        }
    }
    for (name, expected_references) in &authority.compiler_scoped_binding_references {
        let matching_symbols = scoping
            .symbol_ids()
            .filter(|symbol_id| {
                scoping.symbol_flags(*symbol_id).is_value()
                    && scoping.symbol_name(*symbol_id) == name
            })
            .collect::<Vec<_>>();
        if matching_symbols.len() > 1 {
            return Err(generated_source_binding_collision(
                vec![name.clone()],
                format!(
                    "compiler-generated scoped binding {name} is missing or shadowed by a source binding"
                ),
            ));
        }
        ensure!(
            matching_symbols.len() == 1,
            "compiler-generated scoped binding {name} is missing or shadowed by a source binding"
        );
        let symbol = matching_symbols[0];
        if !scoping.symbol_redeclarations(symbol).is_empty() {
            return Err(generated_source_binding_collision(
                vec![name.clone()],
                format!(
                    "compiler-generated scoped binding {name} is redeclared by a source binding"
                ),
            ));
        }
        ensure!(
            scoping.get_resolved_references(symbol).count() == *expected_references,
            "compiler-generated scoped binding {name} did not retain its exact references"
        );
    }
    for name in &authority.compiler_top_level_globals {
        if scoping
            .get_binding(root_scope, name.as_str().into())
            .is_some()
        {
            return Err(generated_source_binding_collision(
                vec![name.clone()],
                format!(
                    "compiler-generated top-level reference {name} is captured by a source root binding"
                ),
            ));
        }
        ensure!(
            unresolved_value_reference_count(scoping, name) > 0,
            "compiler-generated top-level reference {name} did not retain global authority"
        );
    }
    let value_symbols = value_symbol_names(scoping);
    for name in &authority.compiler_application_globals {
        if value_symbols.contains(name) {
            return Err(generated_source_binding_collision(
                vec![name.clone()],
                format!(
                    "compiler-generated application reference {name} can be captured by a source binding"
                ),
            ));
        }
        if require_application_globals {
            ensure!(
                unresolved_value_reference_count(scoping, name) > 0,
                "compiler-generated application reference {name} did not retain global authority"
            );
        }
    }
    Ok(())
}

fn collect_invocation_unix_timestamp_ms_edits(
    value: &Value,
    global_references: &BTreeSet<(String, u32, u32)>,
    output: &mut Vec<SourceEdit>,
) -> Result<usize> {
    let mut count = 0;
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && let Some(callee) = object.get("callee").map(unwrap_runtime_expression)
                && node_type(callee).ok() == Some("MemberExpression")
                && let Some(segments) = static_member_segments(callee)
                && segments.as_slice() == ["Date", "now"]
                && let Some(root) = static_member_root(callee)
                && let Ok((root_start, root_end)) = span(root)
                && global_references.contains(&("Date".to_string(), root_start, root_end))
            {
                let arguments = object
                    .get("arguments")
                    .and_then(Value::as_array)
                    .context("generated Date.now call has no argument list")?;
                ensure!(
                    arguments.is_empty(),
                    "generated Date.now lowering requires exactly zero arguments"
                );
                let (start, end) = span(value)?;
                output.push(
                    source_edit(
                        start,
                        end,
                        format!("{INVOCATION_UNIX_TIMESTAMP_MS_HELPER}()"),
                        (start, end),
                    )
                    .with_inserted_application_globals([INVOCATION_UNIX_TIMESTAMP_MS_HELPER]),
                );
                count += 1;
            }
            for child in object.values() {
                count +=
                    collect_invocation_unix_timestamp_ms_edits(child, global_references, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                count +=
                    collect_invocation_unix_timestamp_ms_edits(child, global_references, output)?;
            }
        }
        _ => {}
    }
    Ok(count)
}

fn collect_guest_promise_global_edits(
    global_references: &BTreeSet<(String, u32, u32)>,
    output: &mut Vec<SourceEdit>,
) -> usize {
    let mut count = 0;
    for (name, start, end) in global_references {
        if name != "Promise" {
            continue;
        }
        output.push(
            source_edit(*start, *end, GUEST_PROMISE_GLOBAL_ALIAS, (*start, *end))
                .with_inserted_application_globals([GUEST_PROMISE_GLOBAL_ALIAS]),
        );
        count += 1;
    }
    count
}

fn direct_batch_synthesized_identifiers(
    suffix: &str,
    children: &[DirectAsyncBatchFixedChildAuthorization],
) -> BTreeSet<String> {
    let mut identifiers = BTreeSet::from([format!("__convexBatchResults_{suffix}")]);
    for (child_index, child) in children.iter().enumerate() {
        identifiers.insert(format!(
            "__convexBatchOperationArguments_{suffix}_{child_index}"
        ));
        if let Some(continuation) = &child.helper_continuation {
            identifiers.insert(format!(
                "__convexBatchContinuationResult_{suffix}_{child_index}"
            ));
            for argument_index in 0..continuation.helper_arguments.len() {
                identifiers.insert(format!(
                    "__convexBatchHelperArgument_{suffix}_{child_index}_{argument_index}"
                ));
            }
            if continuation.dependency_adapter.is_some() {
                identifiers.insert(format!(
                    "__convexDependencyAdapterResult_{suffix}_{child_index}"
                ));
            }
        }
    }
    identifiers
}

#[cfg(test)]
pub(super) fn lower_generated_javascript(
    source: &str,
    intrinsics: &[Intrinsic],
    batches: &[DirectAsyncBatchAuthorization],
    authorized_filters: &BTreeMap<(u32, u32), GeneratedFilterAuthorization>,
    array_producing_functions: &BTreeSet<String>,
    array_argument_authorization: Option<&GeneratedArrayArgumentAuthorization>,
    value_mode: ValueMode,
) -> Result<LoweredGeneratedJavascript> {
    lower_generated_javascript_for_effect_execution_mode(
        source,
        intrinsics,
        batches,
        authorized_filters,
        array_producing_functions,
        array_argument_authorization,
        &BTreeSet::new(),
        &BTreeSet::new(),
        EffectExecutionMode::BlockingFiber,
        value_mode,
        false,
        None,
    )
}

pub(super) fn lower_generated_javascript_for_effect_execution_mode(
    source: &str,
    intrinsics: &[Intrinsic],
    batches: &[DirectAsyncBatchAuthorization],
    authorized_filters: &BTreeMap<(u32, u32), GeneratedFilterAuthorization>,
    array_producing_functions: &BTreeSet<String>,
    array_argument_authorization: Option<&GeneratedArrayArgumentAuthorization>,
    authenticated_query_array_expressions: &BTreeSet<(u32, u32)>,
    pre_marked_query_array_expressions: &BTreeSet<(u32, u32)>,
    effect_execution_mode: EffectExecutionMode,
    value_mode: ValueMode,
    reject_reserved_helper_bindings: bool,
    generated_authority: Option<&GeneratedJavascriptAuthority>,
) -> Result<LoweredGeneratedJavascript> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "generated source lowering input has {} parser diagnostics",
        parsed.diagnostics.len()
    );
    let semantic = SemanticBuilder::new_compiler()
        .with_build_nodes(true)
        .build(&parsed.program);
    let scoping = semantic.semantic.scoping();
    let nodes = semantic.semantic.nodes();
    if let Some(authority) = generated_authority {
        validate_generated_javascript_authority(scoping, authority, true)?;
    }
    ensure!(
        semantic.diagnostics.is_empty(),
        "generated source lowering input has {} semantic diagnostics",
        semantic.diagnostics.len()
    );
    let mut global_references = BTreeSet::new();
    for (name, reference_ids) in scoping.root_unresolved_references() {
        for reference_id in reference_ids {
            let reference = scoping.get_reference(*reference_id);
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            global_references.insert((name.to_string(), reference_span.start, reference_span.end));
        }
    }
    let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false))
        .context("Oxc emitted invalid generated lowering ESTree JSON")?;
    ensure!(
        !contains_node_type(&ast, "ChainExpression"),
        "generated source retains optional chaining after the Oxc transform"
    );
    let mut source_identifier_names = BTreeSet::new();
    collect_estree_identifier_names(&ast, &mut source_identifier_names);
    let mut mutable_objects = BTreeSet::new();
    collect_mutable_object_bindings(&ast, &mut mutable_objects);
    let mut array_filter_lowerings = Vec::new();
    let mut for_of_array_lowerings = Vec::new();
    // The guest-Promise application unit is untyped and owns ordinary JavaScript array
    // semantics. Blocking-fiber output is still compiled as one typed unit and retains the
    // authenticated source rewrites required by that legacy path.
    let retains_ordinary_application_arrays = value_mode == ValueMode::GuestNativeJson
        && effect_execution_mode == EffectExecutionMode::GuestPromiseEventLoop;
    let lower_typed_guest_native_arrays =
        value_mode == ValueMode::GuestNativeJson && !retains_ordinary_application_arrays;
    let mut proved_array_expressions = BTreeSet::new();
    let mut safe_array_references = BTreeSet::new();
    let mut authorized_array_arguments = BTreeSet::new();
    let authorized_batch_spans = batches
        .iter()
        .map(|batch| (batch.generated_start, batch.generated_end))
        .collect::<BTreeSet<_>>();
    let mut array_bindings = Vec::new();
    if lower_typed_guest_native_arrays || value_mode == ValueMode::Opaque {
        collect_generated_safe_array_references(&ast, false, &mut safe_array_references);
        authorized_array_arguments = collect_authorized_array_argument_expressions(
            &ast,
            array_argument_authorization,
            scoping,
            nodes,
            &safe_array_references,
        )?;
        authorized_array_arguments.extend(authenticated_query_array_expressions);
        loop {
            let previous_len = array_bindings.len();
            extend_generated_array_bindings_through_initializers(
                &ast,
                source,
                scoping,
                nodes,
                &global_references,
                array_producing_functions,
                &authorized_array_arguments,
                &authorized_batch_spans,
                &safe_array_references,
                &mut array_bindings,
            )?;
            extend_generated_array_bindings_through_parameters(
                &ast,
                source,
                scoping,
                nodes,
                &global_references,
                array_producing_functions,
                &authorized_array_arguments,
                &authorized_batch_spans,
                &safe_array_references,
                &mut array_bindings,
            )?;
            if array_bindings.len() == previous_len {
                break;
            }
        }
    }
    if value_mode == ValueMode::Opaque {
        collect_generated_proved_array_expressions(
            &ast,
            source,
            scoping,
            nodes,
            &global_references,
            array_producing_functions,
            &authorized_array_arguments,
            &authorized_batch_spans,
            &safe_array_references,
            &array_bindings,
            pre_marked_query_array_expressions,
            &mut proved_array_expressions,
        )?;
    }
    if lower_typed_guest_native_arrays {
        let functions = generated_top_level_functions(&ast)?;
        collect_generated_array_filter_lowerings(
            &ast,
            source,
            scoping,
            nodes,
            &global_references,
            array_producing_functions,
            &authorized_array_arguments,
            &authorized_batch_spans,
            &safe_array_references,
            &array_bindings,
            &functions,
            &mut array_filter_lowerings,
        )?;
        array_filter_lowerings.sort_by_key(|lowering| (lowering.start, lowering.end));
        collect_generated_for_of_array_lowerings(
            &ast,
            source,
            scoping,
            nodes,
            &global_references,
            array_producing_functions,
            &authorized_array_arguments,
            &authorized_batch_spans,
            &safe_array_references,
            &array_bindings,
            &mut for_of_array_lowerings,
        )?;
        for_of_array_lowerings.sort_by_key(|lowering| (lowering.start, lowering.end));
        for pair in for_of_array_lowerings.windows(2) {
            if pair[0].end > pair[1].start {
                return Err(generated_for_of_ineligibility(
                    pair[1].start,
                    "nested guest-native for...of lowering is unsupported",
                ));
            }
        }
    }
    let source_value_symbol_names = value_symbol_names(scoping);
    let mut reserved_application_globals = if reject_reserved_helper_bindings {
        ensure_generated_helper_identifiers_are_available(
            &source_value_symbol_names,
            value_mode,
            effect_execution_mode,
            !intrinsics.is_empty(),
            !proved_array_expressions.is_empty(),
            !authorized_filters.is_empty(),
            batches,
        )?
    } else {
        BTreeSet::new()
    };
    let intrinsic_map = intrinsics
        .iter()
        .map(|intrinsic| (intrinsic.function_name.clone(), intrinsic.operation_id))
        .collect::<BTreeMap<_, _>>();
    let mut consumed_intrinsics = BTreeSet::new();
    let mut consumed_filters = BTreeSet::new();
    let mut basic_edits = Vec::new();
    let invocation_time_edit_count =
        collect_invocation_unix_timestamp_ms_edits(&ast, &global_references, &mut basic_edits)?;
    if invocation_time_edit_count > 0
        && source_value_symbol_names.contains(INVOCATION_UNIX_TIMESTAMP_MS_HELPER)
    {
        return Err(generated_source_binding_collision(
            vec![INVOCATION_UNIX_TIMESTAMP_MS_HELPER.to_string()],
            "generated source already uses reserved invocation-time helper identifier",
        ));
    }
    if reject_reserved_helper_bindings && invocation_time_edit_count > 0 {
        reserved_application_globals.insert(INVOCATION_UNIX_TIMESTAMP_MS_HELPER);
    }
    if effect_execution_mode == EffectExecutionMode::GuestPromiseEventLoop {
        let promise_global_edit_count =
            collect_guest_promise_global_edits(&global_references, &mut basic_edits);
        if promise_global_edit_count > 0
            && source_value_symbol_names.contains(GUEST_PROMISE_GLOBAL_ALIAS)
        {
            return Err(generated_source_binding_collision(
                vec![GUEST_PROMISE_GLOBAL_ALIAS.to_string()],
                "generated source already uses reserved guest Promise alias identifier",
            ));
        }
        if reject_reserved_helper_bindings && promise_global_edit_count > 0 {
            reserved_application_globals.insert(GUEST_PROMISE_GLOBAL_ALIAS);
        }
    }
    if value_mode == ValueMode::GuestNativeJson {
        collect_guest_native_constructor_edits(&ast, &global_references, &mut basic_edits)?;
        collect_guest_native_typed_parameter_edits(&ast, &mut basic_edits)?;
    }
    collect_generated_source_edits(
        &ast,
        source,
        &mutable_objects,
        &intrinsic_map,
        &mut consumed_intrinsics,
        authorized_filters,
        &mut consumed_filters,
        effect_execution_mode,
        value_mode,
        &proved_array_expressions,
        &mut basic_edits,
    )?;
    ensure!(
        consumed_intrinsics.len() == intrinsic_map.len(),
        "generated source consumed {} of {} admitted intrinsics",
        consumed_intrinsics.len(),
        intrinsic_map.len()
    );
    ensure!(
        consumed_filters.len() == authorized_filters.len(),
        "generated source consumed {} of {} authorized strict filters",
        consumed_filters.len(),
        authorized_filters.len()
    );

    let mut batch_edits = Vec::new();
    let mut synthesized_batch_identifiers = BTreeSet::new();
    for batch in batches
        .iter()
        .filter(|_| effect_execution_mode == EffectExecutionMode::BlockingFiber)
    {
        let layout = current_direct_batch_authorization_layout(batch)?;
        let mut replacement_application_globals = BTreeSet::new();
        let replacement = match (&batch.shape, layout) {
            (
                DirectAsyncBatchAuthorizationShape::SingleEffectMap {
                    callback_parameter,
                    dynamic_arguments,
                    generated_iterator_start,
                    generated_iterator_end,
                    helper_continuation,
                    ..
                },
                CurrentDirectBatchLayout::Mapped { child, .. },
            ) => {
                replacement_application_globals.insert("__convexAsyncBatch");
                let operation_id = child.effect.operation_id;
                let iterator = apply_source_edits_with_application_globals(
                    source,
                    *generated_iterator_start,
                    *generated_iterator_end,
                    &basic_edits,
                )?;
                let arguments = generated_direct_async_batch_arguments(
                    source,
                    dynamic_arguments,
                    &basic_edits,
                )?;
                replacement_application_globals.extend(iterator.inserted_application_globals);
                replacement_application_globals
                    .extend(arguments.inserted_application_globals.iter().copied());
                if child.continuation.is_some() {
                    replacement_application_globals.insert("__convexMarkArray");
                    let continuation = helper_continuation.as_deref().context(
                        "validated mapped effect plan lost its continuation authorization",
                    )?;
                    let mut suffix = batch.generated_start.to_string();
                    let (
                        iterator_binding,
                        helper_arguments_binding,
                        helper_tuple_binding,
                        helper_index_binding,
                        results_binding,
                        output_binding,
                        index_binding,
                    ) = loop {
                        let bindings = (
                            format!("__convexBatchIterator_{suffix}"),
                            format!("__convexBatchHelperArguments_{suffix}"),
                            format!("__convexBatchHelperTuple_{suffix}"),
                            format!("__convexBatchHelperIndex_{suffix}"),
                            format!("__convexBatchResults_{suffix}"),
                            format!("__convexBatchOutput_{suffix}"),
                            format!("__convexBatchIndex_{suffix}"),
                        );
                        let mut identifiers = BTreeSet::from([
                            bindings.0.clone(),
                            bindings.1.clone(),
                            bindings.2.clone(),
                            bindings.3.clone(),
                            bindings.4.clone(),
                            bindings.5.clone(),
                            bindings.6.clone(),
                            format!("__convexBatchContinuationResult_{suffix}"),
                        ]);
                        if continuation.dependency_adapter.is_some() {
                            identifiers.insert(format!("__convexDependencyAdapterResult_{suffix}"));
                        }
                        if identifiers.is_disjoint(&source_identifier_names)
                            && identifiers.is_disjoint(&synthesized_batch_identifiers)
                        {
                            synthesized_batch_identifiers.extend(identifiers);
                            break bindings;
                        }
                        suffix.push('_');
                    };
                    let helper_arguments = generated_direct_async_batch_arguments(
                        source,
                        &continuation.helper_arguments,
                        &basic_edits,
                    )?;
                    replacement_application_globals.extend(
                        helper_arguments
                            .inserted_application_globals
                            .iter()
                            .copied(),
                    );
                    ensure!(
                        helper_arguments.values.len() == continuation.helper_parameters.len(),
                        "mapped continuation helper argument count changed"
                    );
                    let effect_arguments = continuation
                        .generated_effect_arguments
                        .iter()
                        .map(|argument| {
                            apply_source_edits_with_application_globals(
                                source,
                                argument.start,
                                argument.end,
                                &basic_edits,
                            )
                        })
                        .collect::<Result<Vec<_>>>()?;
                    for argument in &effect_arguments {
                        replacement_application_globals
                            .extend(&argument.inserted_application_globals);
                    }
                    let tuple_arguments = (0..helper_arguments.values.len())
                        .map(|index| format!("{helper_tuple_binding}[{index}]"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let operation_arguments = format!(
                        "(({}) => [{}])({tuple_arguments})",
                        continuation.helper_parameters.join(", "),
                        effect_arguments
                            .iter()
                            .map(|argument| argument.source.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    let continuation_result = format!("__convexBatchContinuationResult_{suffix}");
                    let awaited_result = if let Some(adapter) = &continuation.dependency_adapter {
                        replacement_application_globals.extend(["Error", "String"]);
                        ensure!(
                            effect_arguments.len() == 1,
                            "unique-or-throw continuation must have one dynamic value"
                        );
                        let adapter_result = format!("__convexDependencyAdapterResult_{suffix}");
                        let table = serde_json::to_string(&adapter.table)?;
                        let field = serde_json::to_string(&adapter.field)?;
                        let rejection = dependency_adapter_unique_or_throw_rejection(
                            &adapter_result,
                            &table,
                            &field,
                            &effect_arguments[0].source,
                        );
                        format!(
                            "(() => {{ const {adapter_result} = {continuation_result}; {rejection} return {adapter_result}; }})()"
                        )
                    } else {
                        continuation_result.clone()
                    };
                    let mut continuation_edits = basic_edits
                        .iter()
                        .filter(|edit| {
                            !edit_is_owned_by(
                                edit,
                                continuation.generated_suspension_start,
                                continuation.generated_suspension_end,
                            )
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    continuation_edits.push(source_edit(
                        continuation.generated_suspension_start,
                        continuation.generated_suspension_end,
                        awaited_result,
                        (
                            continuation.generated_suspension_start,
                            continuation.generated_suspension_end,
                        ),
                    ));
                    let body = apply_source_edits_with_application_globals(
                        source,
                        continuation.generated_body_start,
                        continuation.generated_body_end,
                        &continuation_edits,
                    )?;
                    replacement_application_globals.extend(body.inserted_application_globals);
                    let mut continuation_parameters = continuation.helper_parameters.clone();
                    continuation_parameters.push(continuation_result);
                    let mut continuation_arguments = (0..helper_arguments.values.len())
                        .map(|argument_index| {
                            format!("{helper_arguments_binding}[{index_binding}][{argument_index}]")
                        })
                        .collect::<Vec<_>>();
                    continuation_arguments.push(format!("{results_binding}[{index_binding}]"));
                    format!(
                        "(() => {{\nconst {iterator_binding} = {iterator};\nconst {helper_arguments_binding} = [];\nfor (let {helper_index_binding} = 0; {helper_index_binding} < {iterator_binding}.length; {helper_index_binding} += 1) {{\n{helper_arguments_binding}[{helper_index_binding}] = (({callback_parameter}) => [{}])({iterator_binding}[{helper_index_binding}]);\n}}\nconst {results_binding} = __convexAsyncBatch({helper_arguments_binding}, {operation_id}, ({helper_tuple_binding}) => {operation_arguments});\nconst {output_binding} = [];\nfor (let {index_binding} = 0; {index_binding} < {results_binding}.length; {index_binding} += 1) {{\n{output_binding}[{index_binding}] = (({}) => {{{body}}})({});\n}}\nreturn __convexMarkArray({output_binding});\n}})()",
                        helper_arguments.values.join(", "),
                        continuation_parameters.join(", "),
                        continuation_arguments.join(", "),
                        iterator = iterator.source,
                        body = body.source,
                    )
                } else {
                    ensure!(
                        helper_continuation.is_none(),
                        "leaf-only mapped effect plan retained a continuation authorization"
                    );
                    format!(
                        "__convexAsyncBatch({iterator}, {operation_id}, ({callback_parameter}) => [{}])",
                        arguments.values.join(", "),
                        iterator = iterator.source,
                    )
                }
            }
            (
                DirectAsyncBatchAuthorizationShape::FixedEffectArray { children },
                CurrentDirectBatchLayout::Fixed(planned_children),
            ) => {
                replacement_application_globals.insert("__convexAsyncFixedBatch");
                ensure!(
                    children.len() == planned_children.len(),
                    "validated fixed effect plan changed child count"
                );
                let operation_ids = planned_children
                    .iter()
                    .map(|child| child.effect.operation_id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                if planned_children
                    .iter()
                    .all(|child| child.continuation.is_none())
                {
                    ensure!(
                        children
                            .iter()
                            .all(|child| child.helper_continuation.is_none()),
                        "leaf-only fixed effect plan retained a continuation authorization"
                    );
                    let arguments = children
                        .iter()
                        .map(|child| {
                            generated_direct_async_batch_arguments(
                                source,
                                &child.dynamic_arguments,
                                &basic_edits,
                            )
                        })
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .map(|arguments| {
                            replacement_application_globals
                                .extend(arguments.inserted_application_globals.iter().copied());
                            format!("[{}]", arguments.values.join(", "))
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("__convexAsyncFixedBatch([{operation_ids}], [{arguments}])")
                } else {
                    replacement_application_globals.insert("__convexMarkArray");
                    let mut suffix = batch.generated_start.to_string();
                    let batch_identifiers = loop {
                        let identifiers = direct_batch_synthesized_identifiers(&suffix, children);
                        if identifiers.is_disjoint(&source_identifier_names)
                            && identifiers.is_disjoint(&synthesized_batch_identifiers)
                        {
                            break identifiers;
                        }
                        suffix.push('_');
                    };
                    synthesized_batch_identifiers.extend(batch_identifiers);
                    let results_binding = format!("__convexBatchResults_{suffix}");
                    let mut prelude = String::new();
                    let mut operation_argument_bindings = Vec::with_capacity(children.len());
                    let mut result_expressions = Vec::with_capacity(children.len());
                    for (child_index, (child, planned_child)) in
                        children.iter().zip(&planned_children).enumerate()
                    {
                        let operation_arguments =
                            format!("__convexBatchOperationArguments_{suffix}_{child_index}");
                        operation_argument_bindings.push(operation_arguments.clone());
                        if planned_child.continuation.is_some() {
                            let continuation = child.helper_continuation.as_ref().context(
                                "validated fixed effect plan lost its continuation authorization",
                            )?;
                            let helper_arguments = generated_direct_async_batch_arguments(
                                source,
                                &continuation.helper_arguments,
                                &basic_edits,
                            )?;
                            replacement_application_globals.extend(
                                helper_arguments
                                    .inserted_application_globals
                                    .iter()
                                    .copied(),
                            );
                            let argument_bindings = helper_arguments
                                .values
                                .iter()
                                .enumerate()
                                .map(|(argument_index, argument)| {
                                    let binding = format!(
                                        "__convexBatchHelperArgument_{suffix}_{child_index}_{argument_index}"
                                    );
                                    prelude.push_str(&format!(
                                        "const {binding} = {argument};\n"
                                    ));
                                    binding
                                })
                                .collect::<Vec<_>>();
                            let effect_arguments = continuation
                                .generated_effect_arguments
                                .iter()
                                .map(|argument| {
                                    apply_source_edits_with_application_globals(
                                        source,
                                        argument.start,
                                        argument.end,
                                        &basic_edits,
                                    )
                                })
                                .collect::<Result<Vec<_>>>()?;
                            for argument in &effect_arguments {
                                replacement_application_globals
                                    .extend(&argument.inserted_application_globals);
                            }
                            prelude.push_str(&format!(
                                "const {operation_arguments} = (({}) => [{}])({});\n",
                                continuation.helper_parameters.join(", "),
                                effect_arguments
                                    .iter()
                                    .map(|argument| argument.source.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                argument_bindings.join(", ")
                            ));
                            let continuation_result =
                                format!("__convexBatchContinuationResult_{suffix}_{child_index}");
                            let awaited_result = if let Some(adapter) =
                                &continuation.dependency_adapter
                            {
                                replacement_application_globals.extend(["Error", "String"]);
                                ensure!(
                                    effect_arguments.len() == 1,
                                    "unique-or-throw continuation must have one dynamic value"
                                );
                                let adapter_result = format!(
                                    "__convexDependencyAdapterResult_{suffix}_{child_index}"
                                );
                                let table = serde_json::to_string(&adapter.table)?;
                                let field = serde_json::to_string(&adapter.field)?;
                                let value = format!("{operation_arguments}[0]");
                                let rejection = dependency_adapter_unique_or_throw_rejection(
                                    &adapter_result,
                                    &table,
                                    &field,
                                    &value,
                                );
                                format!(
                                    "(() => {{ const {adapter_result} = {continuation_result}; {rejection} return {adapter_result}; }})()"
                                )
                            } else {
                                continuation_result.clone()
                            };
                            let mut continuation_edits = basic_edits
                                .iter()
                                .filter(|edit| {
                                    !edit_is_owned_by(
                                        edit,
                                        continuation.generated_suspension_start,
                                        continuation.generated_suspension_end,
                                    )
                                })
                                .cloned()
                                .collect::<Vec<_>>();
                            continuation_edits.push(source_edit(
                                continuation.generated_suspension_start,
                                continuation.generated_suspension_end,
                                awaited_result,
                                (
                                    continuation.generated_suspension_start,
                                    continuation.generated_suspension_end,
                                ),
                            ));
                            let body = apply_source_edits_with_application_globals(
                                source,
                                continuation.generated_body_start,
                                continuation.generated_body_end,
                                &continuation_edits,
                            )?;
                            replacement_application_globals
                                .extend(body.inserted_application_globals);
                            let mut parameters = continuation.helper_parameters.clone();
                            parameters.push(continuation_result);
                            let mut call_arguments = argument_bindings;
                            call_arguments.push(format!("{results_binding}[{child_index}]"));
                            result_expressions.push(format!(
                                "(({}) => {{{body}}})({})",
                                parameters.join(", "),
                                call_arguments.join(", "),
                                body = body.source,
                            ));
                        } else {
                            ensure!(
                                child.helper_continuation.is_none(),
                                "leaf-only fixed effect-plan child retained a continuation authorization"
                            );
                            let arguments = generated_direct_async_batch_arguments(
                                source,
                                &child.dynamic_arguments,
                                &basic_edits,
                            )?;
                            replacement_application_globals
                                .extend(arguments.inserted_application_globals.iter().copied());
                            prelude.push_str(&format!(
                                "const {operation_arguments} = [{}];\n",
                                arguments.values.join(", ")
                            ));
                            result_expressions.push(format!("{results_binding}[{child_index}]"));
                        }
                    }
                    format!(
                        "(() => {{\n{prelude}const {results_binding} = __convexAsyncFixedBatch([{operation_ids}], [{}]);\nreturn __convexMarkArray([{}]);\n}})()",
                        operation_argument_bindings.join(", "),
                        result_expressions.join(", ")
                    )
                }
            }
            _ => bail!("direct batch authorization and validated effect-plan layout disagree"),
        };
        batch_edits.push(
            source_edit(
                batch.generated_start,
                batch.generated_end,
                replacement,
                (batch.generated_start, batch.generated_end),
            )
            .with_inserted_application_globals(replacement_application_globals),
        );
    }
    basic_edits.retain(|edit| {
        !batches
            .iter()
            .any(|batch| edit_is_owned_by(edit, batch.generated_start, batch.generated_end))
    });
    basic_edits.extend(batch_edits);
    let mut filter_edit_order = array_filter_lowerings.clone();
    filter_edit_order.sort_by_key(|lowering| {
        (
            lowering.end.saturating_sub(lowering.start),
            lowering.start,
            lowering.end,
        )
    });
    let mut filter_edits = Vec::new();
    for lowering in &filter_edit_order {
        let receiver = apply_source_edits_with_application_globals(
            source,
            lowering.receiver_start,
            lowering.receiver_end,
            &basic_edits,
        )?;
        let callback = apply_source_edits_with_application_globals(
            source,
            lowering.callback_start,
            lowering.callback_end,
            &basic_edits,
        )?;
        let mut replacement_application_globals = receiver.inserted_application_globals;
        replacement_application_globals.extend(callback.inserted_application_globals);
        let mut suffix = lowering.start.to_string();
        while ["Array", "Callback", "Length", "Result", "Index", "Value"]
            .iter()
            .any(|name| source_identifier_names.contains(&format!("__convexFilter{name}_{suffix}")))
        {
            suffix.push('_');
        }
        let array = format!("__convexFilterArray_{suffix}");
        let callback_binding = format!("__convexFilterCallback_{suffix}");
        let length = format!("__convexFilterLength_{suffix}");
        let result = format!("__convexFilterResult_{suffix}");
        let index = format!("__convexFilterIndex_{suffix}");
        let value = format!("__convexFilterValue_{suffix}");
        filter_edits.push(
            source_edit(
                lowering.start,
                lowering.end,
                format!(
                    "(({array}: any[]) => {{\n  const {callback_binding}: any = {callback};\n  const {length} = {array}.length;\n  const {result}: any[] = [];\n  for (let {index} = 0; {index} < {length}; {index} += 1) {{\n    if (!({index} in {array})) continue;\n    const {value} = {array}[{index}];\n    if ({callback_binding}({value}, {index}, {array})) {result}.push({value});\n  }}\n  return {result};\n}})({receiver})",
                    callback = callback.source,
                    receiver = receiver.source,
                ),
                (lowering.start, lowering.end),
            )
            .with_inserted_application_globals(replacement_application_globals),
        );
        basic_edits.retain(|edit| {
            !edit_is_owned_by(edit, lowering.start, lowering.end)
                || (edit.start == lowering.start && edit.end == lowering.end)
        });
        basic_edits.extend(filter_edits.drain(..));
    }
    let mut for_of_edits = Vec::new();
    for lowering in &for_of_array_lowerings {
        let iterable = apply_source_edits_with_application_globals(
            source,
            lowering.right_start,
            lowering.right_end,
            &basic_edits,
        )?;
        let (body_content_start, body_content_end) = if lowering.body_is_block {
            (
                lowering
                    .body_start
                    .checked_add(1)
                    .context("generated for...of body span overflowed")?,
                lowering
                    .body_end
                    .checked_sub(1)
                    .context("generated for...of block body is empty")?,
            )
        } else {
            (lowering.body_start, lowering.body_end)
        };
        let body = apply_source_edits_with_application_globals(
            source,
            body_content_start,
            body_content_end,
            &basic_edits,
        )?;
        let mut replacement_application_globals = iterable.inserted_application_globals;
        replacement_application_globals.extend(body.inserted_application_globals);
        let mut suffix = lowering.start.to_string();
        while source_identifier_names.contains(&format!("__convexForOfArray_{suffix}"))
            || source_identifier_names.contains(&format!("__convexForOfIndex_{suffix}"))
        {
            suffix.push('_');
        }
        let array = format!("__convexForOfArray_{suffix}");
        let index = format!("__convexForOfIndex_{suffix}");
        for_of_edits.push(
            source_edit(
                lowering.start,
                lowering.end,
                format!(
                    "for (let {array} = {iterable}, {index} = 0; {index} < {array}.length; {index} += \
                     1) {{{} {} {} = {array}[{index}]; {body}\n}}",
                    if lowering.body_is_block { "" } else { "\n" },
                    lowering.binding_kind,
                    lowering.binding_name,
                    iterable = iterable.source,
                    body = body.source,
                ),
                (lowering.start, lowering.end),
            )
            .with_inserted_application_globals(replacement_application_globals),
        );
    }
    basic_edits.retain(|edit| {
        !for_of_array_lowerings
            .iter()
            .any(|lowering| edit_is_owned_by(edit, lowering.start, lowering.end))
    });
    basic_edits.extend(for_of_edits);
    let lowered = apply_source_edits_with_application_globals(
        source,
        0,
        u32::try_from(source.len())?,
        &basic_edits,
    )?;
    // Reservation is deliberately conservative, but final authority describes only helpers
    // retained by the composed edit tree. Parent replacements can erase all child helper edits.
    let inserted_application_globals = &lowered.inserted_application_globals;
    if reject_reserved_helper_bindings {
        ensure!(
            inserted_application_globals.is_subset(&reserved_application_globals),
            "compiler lowering inserted an application global without reserving its identifier"
        );
    }
    let lowered_source = lowered.source;

    let validation_allocator = Allocator::default();
    let validation = Parser::new(
        &validation_allocator,
        &lowered_source,
        SourceType::ts().with_module(true),
    )
    .parse();
    ensure!(
        validation.diagnostics.is_empty(),
        "compiler-lowered source has {} parser diagnostics",
        validation.diagnostics.len()
    );
    let validation_semantic = SemanticBuilder::new_compiler()
        .with_build_nodes(true)
        .build(&validation.program);
    let validation_scoping = validation_semantic.semantic.scoping();
    let validation_nodes = validation_semantic.semantic.nodes();
    if let Some(authority) = generated_authority {
        // Authenticated effect lowering can consume a static application reference entirely. The
        // pre-lowering pass proves its source authority; the final pass still rejects capture for
        // every retained reference without requiring a consumed reference to remain.
        validate_generated_javascript_authority(validation_scoping, authority, false)?;
    }
    ensure!(
        validation_semantic.diagnostics.is_empty(),
        "compiler-lowered source has {} semantic diagnostics",
        validation_semantic.diagnostics.len()
    );
    if reject_reserved_helper_bindings {
        let validation_value_symbols = value_symbol_names(validation_scoping);
        for name in inserted_application_globals {
            if validation_value_symbols.contains(*name) {
                return Err(generated_source_binding_collision(
                    vec![(*name).to_string()],
                    format!(
                        "compiler-lowered application reference {name} is captured by a source binding"
                    ),
                ));
            }
            ensure!(
                unresolved_value_reference_count(validation_scoping, name) > 0,
                "compiler-lowered application reference {name} did not retain global authority"
            );
        }
    }
    let mut validation_global_references = BTreeSet::new();
    for (name, reference_ids) in validation_scoping.root_unresolved_references() {
        for reference_id in reference_ids {
            let reference = validation_scoping.get_reference(*reference_id);
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = validation_nodes.get_node(reference.node_id()).kind().span();
            validation_global_references.insert((
                name.to_string(),
                reference_span.start,
                reference_span.end,
            ));
        }
    }
    for name in &synthesized_batch_identifiers {
        let mut symbols = validation_scoping
            .symbol_ids()
            .filter(|symbol_id| validation_scoping.symbol_name(*symbol_id) == name);
        let symbol = symbols
            .next()
            .with_context(|| format!("compiler-lowered batch binding {name} is missing"))?;
        ensure!(
            symbols.next().is_none(),
            "compiler-lowered batch binding {name} is ambiguous"
        );
        ensure!(
            validation_scoping
                .get_resolved_references(symbol)
                .next()
                .is_some(),
            "compiler-lowered batch binding {name} has no owned references"
        );
        ensure!(
            validation_scoping.root_unresolved_references().iter().all(
                |(unresolved, references)| { unresolved.as_str() != name || references.is_empty() }
            ),
            "compiler-lowered batch binding {name} has an unresolved reference"
        );
    }
    let validation_ast: Value =
        serde_json::from_str(&validation.program.to_estree_json(true, false))
            .context("Oxc emitted invalid lowered ESTree JSON")?;
    let mut remaining_invocation_time_edits = Vec::new();
    ensure!(
        collect_invocation_unix_timestamp_ms_edits(
            &validation_ast,
            &validation_global_references,
            &mut remaining_invocation_time_edits,
        )? == 0,
        "compiler-lowered source retains global Date.now()"
    );
    if effect_execution_mode == EffectExecutionMode::BlockingFiber {
        ensure!(
            !contains_node_type(&validation_ast, "AwaitExpression"),
            "compiler-lowered source retains await"
        );
    }
    if !retains_ordinary_application_arrays {
        ensure!(
            !contains_synchronous_for_of(&validation_ast),
            "compiler-lowered source retains synchronous for...of"
        );
    }
    let mut remaining_batches = Vec::new();
    collect_direct_async_batches(
        &validation_ast,
        None,
        None,
        DatabaseOperationSource::Raw,
        &mut remaining_batches,
    );
    if effect_execution_mode == EffectExecutionMode::BlockingFiber {
        ensure!(
            remaining_batches.is_empty(),
            "compiler-lowered source retains Promise.all"
        );
    }
    let mut remaining_static_calls = Vec::new();
    collect_static_member_calls(&validation_ast, &mut remaining_static_calls);
    if !retains_ordinary_application_arrays {
        ensure!(
            remaining_static_calls
                .iter()
                .all(|call| call.first_field != "filter"),
            "compiler-lowered eligible source retains Array.prototype.filter"
        );
    }
    Ok(LoweredGeneratedJavascript {
        source: lowered_source,
        runtime_inputs: if !inserted_application_globals
            .contains(INVOCATION_UNIX_TIMESTAMP_MS_HELPER)
        {
            Vec::new()
        } else {
            vec![INVOCATION_UNIX_TIMESTAMP_MS_RUNTIME_INPUT.to_string()]
        },
    })
}

fn generated_direct_async_batch_arguments(
    source: &str,
    arguments: &[DirectAsyncBatchArgumentAuthorization],
    edits: &[SourceEdit],
) -> Result<AppliedSourceArguments> {
    let arguments = arguments
        .iter()
        .map(|argument| {
            apply_source_edits_with_application_globals(
                source,
                argument.generated_start,
                argument.generated_end,
                edits,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let mut inserted_application_globals = BTreeSet::new();
    for argument in &arguments {
        inserted_application_globals.extend(&argument.inserted_application_globals);
    }
    Ok(AppliedSourceArguments {
        values: arguments
            .into_iter()
            .map(|argument| argument.source)
            .collect(),
        inserted_application_globals,
    })
}

struct AppliedSourceArguments {
    values: Vec<String>,
    inserted_application_globals: BTreeSet<&'static str>,
}
