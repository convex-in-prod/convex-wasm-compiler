use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[path = "query_value_graph.rs"]
pub(super) mod query_value_graph;

use super::callable_control::{
    CallableControlEdgeKind, CallableControlInstructionKind, CallableControlPointKind,
    CallableControlSkeletonCandidate,
};
use super::callable_effects::{
    ArgumentFlow, CallEdge, CallPosition, EffectSpecialization, EffectTemplate, EffectTiming,
    StaticOperand, StaticOperandField,
};
use super::callable_plan_builder::propagate_callable_effects;
use super::callable_resolution::{
    ReachableStaticCallIndex, StaticCallableTarget, caller_parameter_for_reference,
};
use super::callable_value_flow::{
    AuthenticatedCallableEffectValueFlow, AuthenticatedEffectValueGraph,
    AuthenticatedEffectValueSource, CallableEffectValueFlowCandidate,
    authenticate_callable_effect_value_flows, build_authenticated_effect_value_graph,
    collect_callable_effect_value_flow,
};
use super::effect_plan::{
    CallableEffectPlan, CallableKey, SemanticEffectKey, SemanticEffectOperand,
    SemanticEffectProvenance, SemanticEffectTiming, SemanticIndexConstraint, SemanticOperand,
    SemanticOperandProjection, SemanticStaticEffectOperand, SourceAnchor,
    validate_callable_effect_plan,
};
use super::query_values::{
    AuthenticatedCallableQueryBuilderFlow, AuthenticatedCallableQueryValuePlan,
    CallableQueryBuilderFlowCandidate, CallableQueryValuePlanCandidate,
    authenticate_callable_query_builder_flows, authenticate_callable_query_value_plans,
    collect_callable_query_builder_flow, collect_callable_query_value_plans,
};
use super::{
    DatabaseOperationSource, LoadedModule, OperationCandidate, OperationIdentity, ReachableUnit,
    SourceRange, call_has_optional_callee, call_method_name, callee_identifier, contains_node_type,
    count_node_type, hash_bytes, identifier_name, leading_await_count, module_source, node_type,
    parse_db_operation_for_source, parse_scheduler_operation, source_range_string, source_slice,
    span, static_member_chain, static_member_segments, unwrap_runtime_expression,
    unwrap_transparent_expression, value_string,
};
use query_value_graph::{AuthenticatedQueryBuilderGraph, build_authenticated_query_builder_graph};

pub(super) type ResolvedBindingIndex = BTreeMap<(u32, u32), ResolvedBinding>;
pub(super) type ResolvedBindingReferenceIndex =
    BTreeMap<(u32, u32), Vec<super::ReferenceOccurrence>>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResolvedBinding {
    pub(super) name: String,
    pub(super) declaration_start: u32,
    pub(super) declaration_end: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum CallableValueFlowCandidate {
    Parameter {
        index: usize,
    },
    CapturedBinding {
        name: String,
        declaration_start: u32,
    },
    LiteralString {
        value: String,
    },
    Expression {
        range: SourceRange,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableLeafEffectCandidate {
    pub(super) operation: OperationCandidate,
    pub(super) capability: CallableValueFlowCandidate,
    pub(super) capability_reference: SourceRange,
    pub(super) capability_binding: ResolvedBinding,
    pub(super) table: Option<CallableValueFlowCandidate>,
    pub(super) static_arguments: Vec<CallableStaticArgumentCandidate>,
    pub(super) dynamic_arguments: Vec<CallableValueFlowCandidate>,
    pub(super) dynamic_argument_ranges: Vec<SourceRange>,
    pub(super) dynamic_argument_indices: Vec<Option<usize>>,
    pub(super) dynamic_parameter_projections: Vec<Option<CallableParameterProjectionCandidate>>,
    pub(super) implicit_undefined: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableParameterProjectionCandidate {
    pub(super) index: usize,
    pub(super) reference: SourceRange,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableStaticArgumentCandidate {
    pub(super) field: String,
    pub(super) argument_index: usize,
    pub(super) range: SourceRange,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableLeafCallCandidate {
    pub(super) callee: String,
    pub(super) callee_start: u32,
    pub(super) callee_end: u32,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) arguments: Vec<CallableValueFlowCandidate>,
    pub(super) argument_ranges: Vec<SourceRange>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum CallableLeafControlCandidate {
    Effect(CallableLeafEffectCandidate),
    Call(CallableLeafCallCandidate),
    QueryValue(CallableQueryValuePlanCandidate),
    QueryBuilderFlow(CallableQueryBuilderFlowCandidate),
    EffectValueFlow(CallableEffectValueFlowCandidate),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableLeafPlanCandidate {
    pub(super) callable_start: u32,
    pub(super) callable_end: u32,
    pub(super) parameter_names: Vec<String>,
    pub(super) parameter_starts: Vec<u32>,
    pub(super) control_block: Option<u32>,
    pub(super) current_batch_leaf: bool,
    pub(super) control: CallableLeafControlCandidate,
}

fn current_batch_leaf_expression(function: &Value) -> Option<(&Value, bool)> {
    let body = function.get("body")?;
    let (returned, implicit_undefined) = if node_type(body).ok()? == "BlockStatement" {
        let [statement] = body.get("body")?.as_array()?.as_slice() else {
            return None;
        };
        match node_type(statement).ok()? {
            "ReturnStatement" => (
                statement
                    .get("argument")
                    .filter(|argument| !argument.is_null())?,
                false,
            ),
            "ExpressionStatement" => {
                let expression = statement.get("expression")?;
                if leading_await_count(expression) != 1 {
                    return None;
                }
                (expression, true)
            }
            _ => return None,
        }
    } else {
        (body, false)
    };
    if leading_await_count(returned) > 1 {
        return None;
    }
    let expression = unwrap_transparent_expression(returned);
    (node_type(expression).ok()? == "CallExpression"
        && !call_has_optional_callee(expression)
        && !contains_node_type(expression, "AwaitExpression"))
    .then_some((expression, implicit_undefined))
}

fn literal_string(value: &Value) -> Option<String> {
    let value = unwrap_runtime_expression(value);
    (node_type(value).ok()? == "Literal")
        .then(|| value.get("value")?.as_str().map(str::to_string))
        .flatten()
}

pub(super) fn value_flow(
    value: &Value,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
) -> Result<CallableValueFlowCandidate> {
    let value = unwrap_runtime_expression(value);
    if let Some(value) = literal_string(value) {
        return Ok(CallableValueFlowCandidate::LiteralString { value });
    }
    let (start, end) = span(value)?;
    if node_type(value)? == "Identifier"
        && let Some(binding) = bindings.get(&(start, end))
    {
        if let Some(index) = parameter_starts
            .iter()
            .position(|parameter_start| *parameter_start == binding.declaration_start)
        {
            return Ok(CallableValueFlowCandidate::Parameter { index });
        }
        return Ok(CallableValueFlowCandidate::CapturedBinding {
            name: binding.name.clone(),
            declaration_start: binding.declaration_start,
        });
    }
    Ok(CallableValueFlowCandidate::Expression {
        range: SourceRange { start, end },
    })
}

fn parameter_projection(
    value: &Value,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
) -> Option<CallableParameterProjectionCandidate> {
    let mut current = unwrap_runtime_expression(value);
    loop {
        match node_type(current).ok()? {
            "Identifier" => {
                let (start, end) = span(current).ok()?;
                let binding = bindings.get(&(start, end))?;
                let index = parameter_starts
                    .iter()
                    .position(|parameter_start| *parameter_start == binding.declaration_start)?;
                return Some(CallableParameterProjectionCandidate {
                    index,
                    reference: SourceRange { start, end },
                });
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

fn callable_parameters(function: &Value) -> Option<(Vec<String>, Vec<u32>)> {
    let parameters = function.get("params")?.as_array()?;
    let mut names = Vec::with_capacity(parameters.len());
    let mut starts = Vec::with_capacity(parameters.len());
    for parameter in parameters {
        let parameter = unwrap_runtime_expression(parameter);
        names.push(identifier_name(parameter).ok()?);
        starts.push(span(parameter).ok()?.0);
    }
    Some((names, starts))
}

fn effect_capability_identifier<'a>(
    expression: &'a Value,
    operation: &OperationCandidate,
) -> Option<&'a Value> {
    let capability_name = operation.effect_path.as_deref()?.split('.').next()?;
    let effect_start = operation.effect_start?;
    let effect_end = operation.effect_end?;

    fn collect<'a>(
        value: &'a Value,
        name: &str,
        effect_start: u32,
        effect_end: u32,
        matches: &mut Vec<&'a Value>,
    ) {
        let value = unwrap_runtime_expression(value);
        if node_type(value).ok() == Some("Identifier")
            && identifier_name(value).ok().as_deref() == Some(name)
            && span(value)
                .ok()
                .is_some_and(|(start, end)| start >= effect_start && end <= effect_end)
        {
            matches.push(value);
            return;
        }
        match value {
            Value::Object(object) => {
                for child in object.values() {
                    collect(child, name, effect_start, effect_end, matches);
                }
            }
            Value::Array(values) => {
                for child in values {
                    collect(child, name, effect_start, effect_end, matches);
                }
            }
            _ => {}
        }
    }

    let mut matches = Vec::new();
    collect(
        expression,
        capability_name,
        effect_start,
        effect_end,
        &mut matches,
    );
    let [capability] = matches.as_slice() else {
        return None;
    };
    Some(*capability)
}

pub(super) fn parse_parameterized_table_database_operation(
    call: &Value,
) -> Option<OperationCandidate> {
    let call = unwrap_runtime_expression(call);
    if node_type(call).ok()? != "CallExpression" || call_has_optional_callee(call) {
        return None;
    }
    let callee = call.get("callee")?;
    let chain = static_member_chain(callee)?;
    let segments = static_member_segments(callee)?;
    if chain.computed || chain.optional || segments.len() != 3 || segments[1] != "db" {
        return None;
    }
    let kind = match segments[2].as_str() {
        "normalizeId" => "db.normalizeId",
        "get" => "db.get",
        "insert" => "db.insert",
        "patch" => "db.patch",
        "replace" => "db.replace",
        "delete" => "db.delete",
        _ => return None,
    };
    let arguments = call.get("arguments")?.as_array()?;
    let expected_arguments = match kind {
        "db.normalizeId" | "db.get" | "db.insert" | "db.delete" => 2,
        "db.patch" | "db.replace" => 3,
        _ => unreachable!("matched parameterized database operation disappeared"),
    };
    if arguments.len() != expected_arguments
        || arguments
            .iter()
            .any(|argument| count_node_type(argument, "AwaitExpression") > 0)
        || value_string(arguments.first()?).is_some()
    {
        return None;
    }
    let (start, end) = span(call).ok()?;
    let (effect_start, effect_end) = span(callee).ok()?;
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
        function_reference: None,
        function_reference_start: None,
        function_reference_end: None,
        effect_start: Some(effect_start),
        effect_end: Some(effect_end),
        effect_path: Some(segments.join(".")),
    })
}

fn callable_control_candidate(
    expression: &Value,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    query_values: &BTreeMap<(u32, u32), CallableQueryValuePlanCandidate>,
    implicit_undefined: bool,
) -> Result<Option<CallableLeafControlCandidate>> {
    let expression = unwrap_transparent_expression(expression);
    if node_type(expression).ok() != Some("CallExpression") || call_has_optional_callee(expression)
    {
        return Ok(None);
    }
    let identity = span(expression)?;
    if let Some(query_value) = query_values.get(&identity) {
        return Ok(Some(CallableLeafControlCandidate::QueryValue(
            query_value.clone(),
        )));
    }
    let direct_operation =
        parse_db_operation_for_source(expression, "", DatabaseOperationSource::Raw)
            .or_else(|| parse_scheduler_operation(expression));
    let parameterized_table_operation = direct_operation
        .is_none()
        .then(|| parse_parameterized_table_database_operation(expression))
        .flatten();
    let has_parameterized_table = parameterized_table_operation.is_some();
    let control = if let Some(operation) = direct_operation.or(parameterized_table_operation) {
        let Some(dynamic_arguments) = operation_dynamic_arguments(expression, &operation) else {
            return Ok(None);
        };
        if dynamic_arguments
            .iter()
            .any(|argument| count_node_type(argument, "AwaitExpression") > 0)
        {
            return Ok(None);
        }
        let Some(call_arguments) = expression.get("arguments").and_then(Value::as_array) else {
            return Ok(None);
        };
        let Some(capability_expression) = effect_capability_identifier(expression, &operation)
        else {
            return Ok(None);
        };
        let (capability_start, capability_end) = span(capability_expression)?;
        let Some(capability_binding) = bindings.get(&(capability_start, capability_end)).cloned()
        else {
            return Ok(None);
        };
        let table = if has_parameterized_table {
            expression
                .get("arguments")
                .and_then(Value::as_array)
                .and_then(|arguments| arguments.first())
                .map(|argument| value_flow(argument, &parameter_starts, bindings))
                .transpose()?
        } else {
            None
        };
        let dynamic_argument_ranges = dynamic_arguments
            .iter()
            .map(|argument| {
                span(unwrap_runtime_expression(argument))
                    .map(|(start, end)| SourceRange { start, end })
            })
            .collect::<Result<Vec<_>>>()?;
        let dynamic_argument_indices = dynamic_argument_ranges
            .iter()
            .map(|range| {
                if operation.kind == "db.query" {
                    return None;
                }
                let matching = call_arguments
                    .iter()
                    .enumerate()
                    .filter_map(|(index, argument)| {
                        let (start, end) = span(unwrap_runtime_expression(argument)).ok()?;
                        (start == range.start && end == range.end).then_some(index)
                    })
                    .collect::<Vec<_>>();
                match matching.as_slice() {
                    [index] => Some(*index),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        let mut static_arguments = Vec::new();
        if operation.kind.starts_with("db.") && operation.kind != "db.query" {
            let (start, end) = span(unwrap_runtime_expression(
                call_arguments
                    .first()
                    .context("database effect has no table argument")?,
            ))?;
            static_arguments.push(CallableStaticArgumentCandidate {
                field: "table".to_string(),
                argument_index: 0,
                range: SourceRange { start, end },
            });
        } else if operation.kind.starts_with("scheduler.") {
            let (start, end) =
                span(unwrap_runtime_expression(call_arguments.get(1).context(
                    "scheduler effect has no function-reference argument",
                )?))?;
            static_arguments.push(CallableStaticArgumentCandidate {
                field: "functionReference".to_string(),
                argument_index: 1,
                range: SourceRange { start, end },
            });
        }
        let dynamic_parameter_projections = dynamic_arguments
            .iter()
            .map(|argument| parameter_projection(argument, &parameter_starts, bindings))
            .collect::<Vec<_>>();
        let dynamic_arguments = dynamic_arguments
            .iter()
            .map(|argument| value_flow(argument, &parameter_starts, bindings))
            .collect::<Result<Vec<_>>>()?;
        CallableLeafControlCandidate::Effect(CallableLeafEffectCandidate {
            operation,
            capability: value_flow(capability_expression, parameter_starts, bindings)?,
            capability_reference: SourceRange {
                start: capability_start,
                end: capability_end,
            },
            capability_binding,
            table,
            static_arguments,
            dynamic_arguments,
            dynamic_argument_ranges,
            dynamic_argument_indices,
            dynamic_parameter_projections,
            implicit_undefined,
        })
    } else {
        let Some(callee) = callee_identifier(expression) else {
            return Ok(None);
        };
        let callee_expression = expression
            .get("callee")
            .map(unwrap_runtime_expression)
            .context("leaf call has no callee")?;
        let (callee_start, callee_end) = span(callee_expression)?;
        let Some(arguments) = expression.get("arguments").and_then(Value::as_array) else {
            return Ok(None);
        };
        if arguments.iter().any(|argument| {
            node_type(argument).ok() == Some("SpreadElement")
                || count_node_type(argument, "AwaitExpression") > 0
        }) {
            return Ok(None);
        }
        let argument_ranges = arguments
            .iter()
            .map(|argument| {
                span(unwrap_runtime_expression(argument))
                    .map(|(start, end)| SourceRange { start, end })
            })
            .collect::<Result<Vec<_>>>()?;
        let arguments = arguments
            .iter()
            .map(|argument| value_flow(argument, &parameter_starts, bindings))
            .collect::<Result<Vec<_>>>()?;
        let (start, end) = span(expression)?;
        CallableLeafControlCandidate::Call(CallableLeafCallCandidate {
            callee,
            callee_start,
            callee_end,
            start,
            end,
            arguments,
            argument_ranges,
        })
    };
    Ok(Some(control))
}

fn operation_dynamic_arguments<'a>(
    call: &'a Value,
    operation: &OperationCandidate,
) -> Option<Vec<&'a Value>> {
    let call = unwrap_runtime_expression(call);
    let arguments = call.get("arguments")?.as_array()?;
    match operation.kind.as_str() {
        "db.normalizeId" | "db.get" | "db.delete" | "db.insert" => Some(vec![arguments.get(1)?]),
        "db.patch" | "db.replace" => Some(vec![arguments.get(1)?, arguments.get(2)?]),
        "scheduler.runAfter" | "scheduler.runAt" => {
            Some(vec![arguments.first()?, arguments.get(2)?])
        }
        "db.query" => {
            fn expression_at_range(
                value: &Value,
                target_start: u32,
                target_end: u32,
            ) -> Option<&Value> {
                let value = unwrap_runtime_expression(value);
                if span(value).ok() == Some((target_start, target_end)) {
                    return Some(value);
                }
                match value {
                    Value::Object(object) => object
                        .values()
                        .filter_map(|child| expression_at_range(child, target_start, target_end))
                        .next(),
                    Value::Array(values) => values
                        .iter()
                        .filter_map(|child| expression_at_range(child, target_start, target_end))
                        .next(),
                    _ => None,
                }
            }

            let mut dynamic_arguments = operation
                .index_constraints
                .iter()
                .map(|constraint| {
                    expression_at_range(call, constraint.value_start, constraint.value_end)
                })
                .collect::<Option<Vec<_>>>()?;
            if let Some(limit_argument_index) = operation.limit_argument_index {
                if usize::try_from(limit_argument_index).ok() != Some(dynamic_arguments.len()) {
                    return None;
                }
                dynamic_arguments.push(arguments.first()?);
            }
            Some(dynamic_arguments)
        }
        _ => None,
    }
}

fn collect_callable_control_candidates(
    value: &Value,
    callable_start: u32,
    callable_end: u32,
    parameter_names: &[String],
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    query_values: &BTreeMap<(u32, u32), CallableQueryValuePlanCandidate>,
    current_batch_leaf: Option<(u32, u32, bool)>,
    root: bool,
    output: &mut Vec<CallableLeafPlanCandidate>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if !root
                && matches!(
                    object.get("type").and_then(Value::as_str),
                    Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
                )
            {
                return Ok(());
            }
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && let (start, end) = span(value)?
                && let Some(control) = callable_control_candidate(
                    value,
                    parameter_starts,
                    bindings,
                    query_values,
                    current_batch_leaf
                        .filter(|(leaf_start, leaf_end, _)| {
                            *leaf_start == start && *leaf_end == end
                        })
                        .is_some_and(|(_, _, implicit_undefined)| implicit_undefined),
                )?
            {
                let is_current_batch_leaf =
                    current_batch_leaf.is_some_and(|(leaf_start, leaf_end, _)| {
                        leaf_start == start && leaf_end == end
                    });
                let implicit_undefined_call =
                    current_batch_leaf.is_some_and(|(leaf_start, leaf_end, implicit_undefined)| {
                        leaf_start == start && leaf_end == end && implicit_undefined
                    }) && matches!(&control, CallableLeafControlCandidate::Call(_));
                output.push(CallableLeafPlanCandidate {
                    callable_start,
                    callable_end,
                    parameter_names: parameter_names.to_vec(),
                    parameter_starts: parameter_starts.to_vec(),
                    control_block: None,
                    current_batch_leaf: is_current_batch_leaf && !implicit_undefined_call,
                    control,
                });
            }
            for child in object.values() {
                collect_callable_control_candidates(
                    child,
                    callable_start,
                    callable_end,
                    parameter_names,
                    parameter_starts,
                    bindings,
                    query_values,
                    current_batch_leaf,
                    false,
                    output,
                )?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_callable_control_candidates(
                    child,
                    callable_start,
                    callable_end,
                    parameter_names,
                    parameter_starts,
                    bindings,
                    query_values,
                    current_batch_leaf,
                    false,
                    output,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_with_index_callback_sites(
    value: &Value,
    output: &mut BTreeMap<(u32, u32), SourceRange>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && !call_has_optional_callee(value)
                && call_method_name(value).as_deref() == Some("withIndex")
                && let Some(arguments) = value.get("arguments").and_then(Value::as_array)
                && let Some(callback) = arguments.get(1).map(unwrap_runtime_expression)
                && matches!(
                    node_type(callback).ok(),
                    Some("ArrowFunctionExpression" | "FunctionExpression")
                )
            {
                let callback_range = span(callback)?;
                let (start, end) = span(value)?;
                let previous = output.insert(callback_range, SourceRange { start, end });
                anyhow::ensure!(
                    previous.is_none(),
                    "withIndex callback belongs to more than one authenticated stage"
                );
            }
            for child in object.values() {
                collect_with_index_callback_sites(child, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_with_index_callback_sites(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_callable_leaf_plans_inner(
    value: &Value,
    bindings: &ResolvedBindingIndex,
    binding_references: &ResolvedBindingReferenceIndex,
    with_index_callbacks: &BTreeMap<(u32, u32), SourceRange>,
    output: &mut Vec<CallableLeafPlanCandidate>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression")
            ) && let Some((parameter_names, parameter_starts)) = callable_parameters(value)
            {
                let (callable_start, callable_end) = span(value)?;
                let current_batch_leaf = current_batch_leaf_expression(value).and_then(
                    |(expression, implicit_undefined)| {
                        span(expression)
                            .ok()
                            .map(|(start, end)| (start, end, implicit_undefined))
                    },
                );
                let query_values = collect_callable_query_value_plans(
                    value,
                    callable_start,
                    callable_end,
                    &parameter_starts,
                    bindings,
                    binding_references,
                )?;
                collect_callable_control_candidates(
                    value,
                    callable_start,
                    callable_end,
                    &parameter_names,
                    &parameter_starts,
                    bindings,
                    &query_values,
                    current_batch_leaf,
                    true,
                    output,
                )?;
                let query_builder_flow = collect_callable_query_builder_flow(
                    value,
                    callable_start,
                    callable_end,
                    &parameter_names,
                    &parameter_starts,
                    bindings,
                    binding_references,
                    with_index_callbacks
                        .get(&(callable_start, callable_end))
                        .cloned(),
                )?;
                if !query_builder_flow.paths.is_empty() || !query_builder_flow.rejections.is_empty()
                {
                    output.push(CallableLeafPlanCandidate {
                        callable_start,
                        callable_end,
                        parameter_names: parameter_names.clone(),
                        parameter_starts: parameter_starts.clone(),
                        control_block: None,
                        current_batch_leaf: false,
                        control: CallableLeafControlCandidate::QueryBuilderFlow(query_builder_flow),
                    });
                }
                let effect_value_flow = collect_callable_effect_value_flow(
                    value,
                    callable_start,
                    callable_end,
                    &parameter_names,
                    &parameter_starts,
                    bindings,
                    binding_references,
                )?;
                if !effect_value_flow.paths.is_empty() || !effect_value_flow.rejections.is_empty() {
                    output.push(CallableLeafPlanCandidate {
                        callable_start,
                        callable_end,
                        parameter_names,
                        parameter_starts,
                        control_block: None,
                        current_batch_leaf: false,
                        control: CallableLeafControlCandidate::EffectValueFlow(effect_value_flow),
                    });
                }
            }
            for child in object.values() {
                collect_callable_leaf_plans_inner(
                    child,
                    bindings,
                    binding_references,
                    with_index_callbacks,
                    output,
                )?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_callable_leaf_plans_inner(
                    child,
                    bindings,
                    binding_references,
                    with_index_callbacks,
                    output,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn collect_callable_leaf_plans(
    value: &Value,
    bindings: &ResolvedBindingIndex,
    binding_references: &ResolvedBindingReferenceIndex,
    output: &mut Vec<CallableLeafPlanCandidate>,
) -> Result<()> {
    let mut with_index_callbacks = BTreeMap::new();
    collect_with_index_callback_sites(value, &mut with_index_callbacks)?;
    collect_callable_leaf_plans_inner(
        value,
        bindings,
        binding_references,
        &with_index_callbacks,
        output,
    )
}

pub(super) fn bind_callable_control_blocks(
    skeletons: &[CallableControlSkeletonCandidate],
    candidates: &mut [CallableLeafPlanCandidate],
) -> Result<()> {
    let skeletons = skeletons
        .iter()
        .map(|skeleton| ((skeleton.callable_start, skeleton.callable_end), skeleton))
        .collect::<BTreeMap<_, _>>();
    for candidate in candidates {
        let skeleton = skeletons
            .get(&(candidate.callable_start, candidate.callable_end))
            .context("callable semantic point has no Oxc control skeleton")?;
        let (start, end) = match &candidate.control {
            CallableLeafControlCandidate::Effect(effect) => {
                (effect.operation.start, effect.operation.end)
            }
            CallableLeafControlCandidate::Call(call) => (call.start, call.end),
            CallableLeafControlCandidate::QueryValue(query) => {
                (query.source.start, query.source.end)
            }
            CallableLeafControlCandidate::QueryBuilderFlow(_)
            | CallableLeafControlCandidate::EffectValueFlow(_) => continue,
        };
        let matching = skeleton
            .points
            .iter()
            .filter(|point| {
                point.kind == CallableControlPointKind::Call
                    && point.start == start
                    && point.end == end
            })
            .collect::<Vec<_>>();
        let [point] = matching.as_slice() else {
            anyhow::bail!(
                "callable semantic point {start}..{end} maps to {} Oxc control points",
                matching.len()
            );
        };
        candidate.control_block = Some(point.block);
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct CallableEffectPlanIndex {
    by_callable: BTreeMap<CallableKey, Vec<CallableEffectPlan>>,
    by_site: BTreeMap<OperationIdentity, Vec<CallableEffectPlan>>,
    source_effects: BTreeMap<(CallableKey, OperationIdentity), CallableControlSourceEffect>,
    current_batch_leaves: BTreeSet<(CallableKey, OperationIdentity, OperationIdentity)>,
    control_provenance:
        BTreeMap<(CallableKey, OperationIdentity, OperationIdentity), PlanControlProvenance>,
    control_calls: BTreeMap<CallableKey, Vec<CallableControlCallPlan>>,
    control_plans: BTreeMap<CallableKey, CallableControlPlan>,
    activation_calls: AuthenticatedStaticActivationCallIndex,
    query_values: Vec<AuthenticatedCallableQueryValuePlan>,
    query_builder_flows: Vec<AuthenticatedCallableQueryBuilderFlow>,
    query_builder_graph: AuthenticatedQueryBuilderGraph,
    effect_value_flows: Vec<AuthenticatedCallableEffectValueFlow>,
    effect_value_graph: AuthenticatedEffectValueGraph,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlanControlProvenance {
    target_block: u32,
    consumer_block: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallableControlSourceEffect {
    pub(super) source: AuthenticatedEffectValueSource,
    pub(super) block: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallableControlSummary {
    pub(super) block_count: usize,
    pub(super) await_count: usize,
    pub(super) call_count: usize,
    pub(super) has_choice: bool,
    pub(super) has_cycle: bool,
    pub(super) has_finalization: bool,
    pub(super) has_explicit_exception_path: bool,
    pub(super) has_implicit_error_harness: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallableControlEffectPlan {
    pub(super) effect: CallableEffectPlan,
    pub(super) target_block: u32,
    pub(super) consumer_block: u32,
    pub(super) target_control: CallableControlSummary,
    current_batch_leaf: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallableControlCallPlan {
    pub(super) callsite: SourceAnchor,
    pub(super) target: CallableKey,
    pub(super) target_source: SourceAnchor,
    pub(super) block: u32,
    pub(super) position: CallPosition,
    pub(super) dispatch_exact: bool,
    pub(super) arguments_safe: bool,
    pub(super) arguments: Vec<CallableControlCallArgument>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallableControlCallArgument {
    pub(super) value: CallableValueFlowCandidate,
    pub(super) provenance: SourceAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallableControlPlan {
    pub(super) callable: CallableKey,
    pub(super) callable_source: SourceAnchor,
    pub(super) skeleton: CallableControlSkeletonCandidate,
    pub(super) control: CallableControlSummary,
    pub(super) source_effects: Vec<CallableControlSourceEffect>,
    pub(super) effects: Vec<CallableControlEffectPlan>,
    pub(super) calls: Vec<CallableControlCallPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AuthenticatedStaticActivationCaller {
    Callable(CallableKey),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AuthenticatedStaticActivationTarget {
    Callable(CallableKey),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedStaticActivationCall {
    pub(super) caller: AuthenticatedStaticActivationCaller,
    pub(super) target: AuthenticatedStaticActivationTarget,
    pub(super) callsite: SourceAnchor,
    pub(super) position: Option<CallPosition>,
    pub(super) dispatch_exact: bool,
}

#[derive(Default)]
pub(super) struct AuthenticatedStaticActivationCallIndex {
    calls: Vec<AuthenticatedStaticActivationCall>,
    calls_by_target: BTreeMap<CallableKey, Vec<usize>>,
}

impl AuthenticatedStaticActivationCallIndex {
    fn from_calls(mut calls: Vec<AuthenticatedStaticActivationCall>) -> Result<Self> {
        calls.sort_by_key(|call| {
            (
                call.callsite.module.clone(),
                call.callsite.start,
                call.callsite.end,
            )
        });
        for calls_at_same_site in calls.windows(2) {
            anyhow::ensure!(
                calls_at_same_site[0].callsite.module != calls_at_same_site[1].callsite.module
                    || calls_at_same_site[0].callsite.start != calls_at_same_site[1].callsite.start
                    || calls_at_same_site[0].callsite.end != calls_at_same_site[1].callsite.end,
                "static activation-call index duplicated an authenticated callsite"
            );
        }
        let mut calls_by_target = BTreeMap::<CallableKey, Vec<usize>>::new();
        for (index, call) in calls.iter().enumerate() {
            if let AuthenticatedStaticActivationTarget::Callable(target) = &call.target {
                calls_by_target
                    .entry(target.clone())
                    .or_default()
                    .push(index);
            }
        }
        Ok(Self {
            calls,
            calls_by_target,
        })
    }

    #[cfg(test)]
    pub(super) fn from_test_calls(calls: Vec<AuthenticatedStaticActivationCall>) -> Result<Self> {
        Self::from_calls(calls)
    }

    pub(super) fn calls(&self) -> impl Iterator<Item = &AuthenticatedStaticActivationCall> {
        self.calls.iter()
    }

    pub(super) fn calls_to(
        &self,
        target: &CallableKey,
    ) -> impl Iterator<Item = &AuthenticatedStaticActivationCall> {
        self.calls_by_target
            .get(target)
            .into_iter()
            .flatten()
            .map(|index| &self.calls[*index])
    }
}

impl CallableControlPlan {
    pub(super) fn current_batch_leaf(&self) -> Option<&CallableEffectPlan> {
        let [effect] = self.effects.as_slice() else {
            return None;
        };
        effect.current_batch_leaf.then_some(&effect.effect)
    }
}

fn control_summary(skeleton: &CallableControlSkeletonCandidate) -> CallableControlSummary {
    CallableControlSummary {
        block_count: skeleton.blocks.len(),
        await_count: skeleton
            .points
            .iter()
            .filter(|point| point.kind == CallableControlPointKind::Await)
            .count(),
        call_count: skeleton
            .points
            .iter()
            .filter(|point| point.kind == CallableControlPointKind::Call)
            .count(),
        has_choice: skeleton.blocks.iter().any(|block| {
            block
                .instructions
                .iter()
                .any(|instruction| instruction.kind == CallableControlInstructionKind::Condition)
                || block
                    .successors
                    .iter()
                    .filter(|edge| {
                        !matches!(
                            edge.kind,
                            CallableControlEdgeKind::ImplicitError
                                | CallableControlEdgeKind::ExplicitError
                                | CallableControlEdgeKind::Unreachable
                        )
                    })
                    .count()
                    > 1
        }),
        has_cycle: skeleton.blocks.iter().any(|block| {
            block
                .successors
                .iter()
                .any(|edge| edge.kind == CallableControlEdgeKind::Backedge)
        }),
        has_finalization: skeleton.blocks.iter().any(|block| {
            block.successors.iter().any(|edge| {
                matches!(
                    edge.kind,
                    CallableControlEdgeKind::Finalize | CallableControlEdgeKind::Join
                )
            })
        }),
        has_explicit_exception_path: skeleton.blocks.iter().any(|block| {
            block
                .instructions
                .iter()
                .any(|instruction| instruction.kind == CallableControlInstructionKind::Throw)
                || block
                    .successors
                    .iter()
                    .any(|edge| edge.kind == CallableControlEdgeKind::ExplicitError)
        }),
        has_implicit_error_harness: skeleton.blocks.iter().any(|block| {
            block
                .successors
                .iter()
                .any(|edge| edge.kind == CallableControlEdgeKind::ImplicitError)
        }),
    }
}

impl CallableEffectPlan {
    pub(super) fn consumer_site(&self) -> &SourceAnchor {
        self.provenance
            .caller_callsite
            .as_ref()
            .unwrap_or(&self.provenance.target_effect)
    }

    pub(super) fn consumer_site_identity(&self) -> OperationIdentity {
        let site = self.consumer_site();
        (site.module.clone(), site.start, site.end)
    }

    pub(super) fn target_identity(&self) -> OperationIdentity {
        let target = &self.provenance.target_effect;
        (target.module.clone(), target.start, target.end)
    }
}

impl CallableEffectPlanIndex {
    #[cfg(test)]
    pub(super) fn plan_for_callable(
        &self,
        module: &str,
        start: u32,
        end: u32,
    ) -> Option<&CallableEffectPlan> {
        let plans = self.by_callable.get(&callable_key(module, start, end))?;
        let [plan] = plans.as_slice() else {
            return None;
        };
        self.current_batch_leaves
            .contains(&(
                plan.callable.clone(),
                plan.target_identity(),
                plan.consumer_site_identity(),
            ))
            .then_some(plan)
    }

    pub(super) fn control_plan_for_callable(
        &self,
        module: &str,
        start: u32,
        end: u32,
    ) -> Option<&CallableControlPlan> {
        self.control_plans.get(&callable_key(module, start, end))
    }

    #[cfg(test)]
    pub(super) fn plan_at_site(
        &self,
        module: &str,
        start: u32,
        end: u32,
    ) -> Option<&CallableEffectPlan> {
        let plans = self.by_site.get(&(module.to_string(), start, end))?;
        let [plan] = plans.as_slice() else {
            return None;
        };
        Some(plan)
    }

    #[cfg(test)]
    pub(super) fn plans_at_site(
        &self,
        module: &str,
        start: u32,
        end: u32,
    ) -> &[CallableEffectPlan] {
        self.by_site
            .get(&(module.to_string(), start, end))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(super) fn plans(&self) -> impl Iterator<Item = &CallableEffectPlan> {
        self.by_callable.values().flatten()
    }

    pub(super) fn control_plans(&self) -> impl Iterator<Item = &CallableControlPlan> {
        self.control_plans.values()
    }

    pub(super) fn activation_calls(&self) -> &AuthenticatedStaticActivationCallIndex {
        &self.activation_calls
    }

    pub(super) fn query_value_plans(
        &self,
    ) -> impl Iterator<Item = &AuthenticatedCallableQueryValuePlan> {
        self.query_values.iter()
    }

    pub(super) fn query_builder_graph(&self) -> &AuthenticatedQueryBuilderGraph {
        &self.query_builder_graph
    }

    pub(super) fn effect_value_graph(&self) -> &AuthenticatedEffectValueGraph {
        &self.effect_value_graph
    }

    fn rebuild_consumer_sites(&mut self) {
        let mut by_site = BTreeMap::<OperationIdentity, Vec<CallableEffectPlan>>::new();
        for plan in self.by_callable.values().flatten() {
            let site = plan.consumer_site_identity();
            by_site.entry(site).or_default().push(plan.clone());
        }
        for plans in by_site.values_mut() {
            plans.sort_by_key(|plan| {
                (
                    plan.provenance.target_effect.module.clone(),
                    plan.provenance.target_effect.start,
                    plan.provenance.target_effect.end,
                    plan.effect_key.operation_kind.clone(),
                )
            });
            plans.dedup();
        }
        self.by_site = by_site;
    }

    fn insert(
        &mut self,
        plan: CallableEffectPlan,
        current_batch_leaf: bool,
        control: PlanControlProvenance,
    ) -> Result<()> {
        let identity = (
            plan.callable.clone(),
            plan.target_identity(),
            plan.consumer_site_identity(),
        );
        let plans = self.by_callable.entry(plan.callable.clone()).or_default();
        if let Some(previous) = plans.iter().find(|previous| {
            previous.target_identity() == plan.target_identity()
                && previous.consumer_site_identity() == plan.consumer_site_identity()
        }) {
            anyhow::ensure!(
                previous == &plan,
                "callable control plan has conflicting semantic projections for one effect site"
            );
            anyhow::ensure!(
                self.control_provenance.get(&identity) == Some(&control),
                "callable effect plan has conflicting Oxc control provenance"
            );
            if current_batch_leaf {
                self.current_batch_leaves.insert(identity);
            }
            return Ok(());
        }
        plans.push(plan);
        plans.sort_by_key(|plan| {
            (
                plan.provenance.target_effect.start,
                plan.provenance.target_effect.end,
                plan.consumer_site().start,
                plan.consumer_site().end,
            )
        });
        anyhow::ensure!(
            self.control_provenance
                .insert(identity.clone(), control)
                .is_none(),
            "callable effect plan duplicated its Oxc control provenance"
        );
        if current_batch_leaf {
            self.current_batch_leaves.insert(identity);
        }
        Ok(())
    }

    fn insert_source_effect(&mut self, source: CallableControlSourceEffect) -> Result<()> {
        source.source.validate()?;
        let identity = (
            source.source.target_callable.clone(),
            (
                source.source.target_effect.module.clone(),
                source.source.target_effect.start,
                source.source.target_effect.end,
            ),
        );
        if let Some(previous) = self.source_effects.insert(identity, source.clone()) {
            anyhow::ensure!(
                previous == source,
                "callable source effect has conflicting exact provenance"
            );
        }
        Ok(())
    }

    fn insert_call(&mut self, callable: CallableKey, call: CallableControlCallPlan) -> Result<()> {
        anyhow::ensure!(
            call.arguments.iter().all(|argument| {
                argument.provenance.module == call.callsite.module
                    && argument.provenance.source_sha256 == call.callsite.source_sha256
                    && argument.provenance.start >= call.callsite.start
                    && argument.provenance.end <= call.callsite.end
            }),
            "callable control call argument escaped its authenticated callsite"
        );
        let calls = self.control_calls.entry(callable).or_default();
        if let Some(previous) = calls
            .iter()
            .find(|previous| previous.callsite == call.callsite && previous.target == call.target)
        {
            anyhow::ensure!(
                previous == &call,
                "callable control plan has conflicting static-call provenance"
            );
            return Ok(());
        }
        calls.push(call);
        calls.sort_by_key(|call| {
            (
                call.callsite.start,
                call.callsite.end,
                call.target.module.clone(),
                call.target.unit_id.clone(),
            )
        });
        Ok(())
    }

    fn rebuild_control_plans(
        &mut self,
        modules: &BTreeMap<String, LoadedModule>,
        reachable: &BTreeMap<String, ReachableUnit>,
    ) -> Result<()> {
        let skeleton = |module: &str, start: u32, end: u32| {
            modules.get(module).and_then(|loaded| {
                loaded
                    .summary
                    .callable_control_skeletons
                    .iter()
                    .find(|candidate| {
                        candidate.callable_start == start && candidate.callable_end == end
                    })
            })
        };
        let mut control_plans = BTreeMap::<CallableKey, CallableControlPlan>::new();
        for unit in reachable.values() {
            let module = modules
                .get(&unit.module)
                .context("reachable callable-control module disappeared")?;
            for candidate in module
                .summary
                .callable_control_skeletons
                .iter()
                .filter(|candidate| {
                    candidate.callable_start >= unit.start && candidate.callable_end <= unit.end
                })
            {
                let callable = callable_key(
                    &unit.module,
                    candidate.callable_start,
                    candidate.callable_end,
                );
                let callable_source = source_anchor(
                    modules,
                    &unit.module,
                    candidate.callable_start,
                    candidate.callable_end,
                )?;
                let plan = CallableControlPlan {
                    callable: callable.clone(),
                    callable_source,
                    skeleton: candidate.clone(),
                    control: control_summary(candidate),
                    source_effects: Vec::new(),
                    effects: Vec::new(),
                    calls: Vec::new(),
                };
                if let Some(previous) = control_plans.insert(callable.clone(), plan.clone()) {
                    anyhow::ensure!(
                        previous == plan,
                        "reachable callable has conflicting Oxc control skeletons"
                    );
                    control_plans.insert(callable, previous);
                }
            }
        }
        for source_effect in self.source_effects.values() {
            let plan = control_plans
                .get_mut(&source_effect.source.target_callable)
                .context("callable source effect lost its generic control plan")?;
            anyhow::ensure!(
                source_effect.source.target_callable_source == plan.callable_source,
                "callable source effect conflicts with its generic control plan provenance"
            );
            anyhow::ensure!(
                plan.skeleton
                    .blocks
                    .iter()
                    .any(|block| block.id == source_effect.block),
                "callable source effect references an unknown Oxc control block"
            );
            plan.source_effects.push(source_effect.clone());
        }
        for plan in control_plans.values_mut() {
            plan.source_effects.sort_by_key(|effect| {
                (
                    effect.source.target_effect.start,
                    effect.source.target_effect.end,
                    effect.source.target_callee.start,
                    effect.source.target_callee.end,
                    effect.block,
                )
            });
            plan.source_effects.dedup();
        }
        for (callable, effects) in &self.by_callable {
            let plan = control_plans
                .get_mut(callable)
                .context("callable semantic effects lost their generic control plan")?;
            let callable_skeleton = skeleton(
                &plan.callable_source.module,
                plan.callable_source.start,
                plan.callable_source.end,
            )
            .context("callable semantic effects lost their Oxc control skeleton")?;
            let mut control_effects = Vec::with_capacity(effects.len());
            for effect in effects {
                let identity = (
                    effect.callable.clone(),
                    effect.target_identity(),
                    effect.consumer_site_identity(),
                );
                let provenance = self
                    .control_provenance
                    .get(&identity)
                    .context("callable semantic effect lost its Oxc block provenance")?;
                let target = &effect.provenance.target_callable_source;
                let target_skeleton = skeleton(&target.module, target.start, target.end)
                    .context("callable semantic effect target lost its Oxc control skeleton")?;
                anyhow::ensure!(
                    target_skeleton
                        .blocks
                        .iter()
                        .any(|block| block.id == provenance.target_block)
                        && callable_skeleton
                            .blocks
                            .iter()
                            .any(|block| block.id == provenance.consumer_block),
                    "callable semantic effect references an unknown Oxc control block"
                );
                control_effects.push(CallableControlEffectPlan {
                    effect: effect.clone(),
                    target_block: provenance.target_block,
                    consumer_block: provenance.consumer_block,
                    target_control: control_summary(target_skeleton),
                    current_batch_leaf: self.current_batch_leaves.contains(&identity),
                });
            }
            plan.effects = control_effects;
        }
        for (callable, calls) in &self.control_calls {
            let plan = control_plans
                .get_mut(callable)
                .context("static call lost its generic callable control plan")?;
            let callable_skeleton = skeleton(
                &plan.callable_source.module,
                plan.callable_source.start,
                plan.callable_source.end,
            )
            .context("static call lost its Oxc caller skeleton")?;
            for call in calls {
                anyhow::ensure!(
                    callable_skeleton
                        .blocks
                        .iter()
                        .any(|block| block.id == call.block),
                    "static call references an unknown caller Oxc block"
                );
                let target_skeleton = skeleton(
                    &call.target_source.module,
                    call.target_source.start,
                    call.target_source.end,
                )
                .context("static call lost its Oxc target skeleton")?;
                anyhow::ensure!(
                    target_skeleton.callable_start == call.target_source.start
                        && target_skeleton.callable_end == call.target_source.end,
                    "static call target skeleton changed identity"
                );
            }
            plan.calls = calls.clone();
        }
        self.control_plans = control_plans;
        Ok(())
    }

    fn rebuild_activation_calls(
        &mut self,
        modules: &BTreeMap<String, LoadedModule>,
        static_calls: &ReachableStaticCallIndex<'_>,
    ) -> Result<()> {
        let mut calls = Vec::new();
        for (static_target, resolved_calls) in static_calls.calls_by_target() {
            let target =
                static_activation_target_callable(modules, &self.control_plans, static_target)?
                    .map(AuthenticatedStaticActivationTarget::Callable)
                    .unwrap_or(AuthenticatedStaticActivationTarget::Unknown);
            let dispatch_exact = static_calls.dispatch_is_exact(static_target);
            for resolved in resolved_calls {
                let callsite = source_anchor(
                    modules,
                    &resolved.caller.module,
                    resolved.call.start,
                    resolved.call.end,
                )?;
                let caller = exact_activation_caller(&self.control_plans, &callsite)?
                    .map(|plan| {
                        AuthenticatedStaticActivationCaller::Callable(plan.callable.clone())
                    })
                    .unwrap_or(AuthenticatedStaticActivationCaller::Unknown);
                calls.push(AuthenticatedStaticActivationCall {
                    caller,
                    target: target.clone(),
                    callsite,
                    position: call_position(resolved.call),
                    dispatch_exact,
                });
            }
        }
        self.activation_calls = AuthenticatedStaticActivationCallIndex::from_calls(calls)?;
        Ok(())
    }
}

pub(super) fn callable_key(module: &str, start: u32, end: u32) -> CallableKey {
    CallableKey {
        module: module.to_string(),
        unit_id: format!("span:{start}:{end}"),
    }
}

pub(super) fn source_anchor(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    start: u32,
    end: u32,
) -> Result<SourceAnchor> {
    let loaded = modules
        .get(module)
        .with_context(|| format!("callable-plan module {module} disappeared"))?;
    let source = module_source(modules, module)?;
    let slice = source_slice(&source, start, end)?;
    Ok(SourceAnchor {
        module: module.to_string(),
        source_sha256: loaded.summary.source_hash.clone(),
        start,
        end,
        slice_sha256: hash_bytes(slice.as_bytes()),
    })
}

fn semantic_operation_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "db.normalizeId" => Some("databaseNormalizeId"),
        "db.get" => Some("databaseGet"),
        "db.query" => Some("databaseIndexQuery"),
        "db.insert" => Some("databaseInsert"),
        "db.patch" => Some("databasePatch"),
        "db.replace" => Some("databaseReplace"),
        "db.delete" => Some("databaseDelete"),
        "scheduler.runAfter" => Some("schedulerRunAfter"),
        "scheduler.runAt" => Some("schedulerRunAt"),
        _ => None,
    }
}

fn result_kind(operation: &OperationCandidate) -> Option<&'static str> {
    match operation.kind.as_str() {
        "db.query" if operation.terminal.as_deref() == Some("collect") => Some("hostArray"),
        "db.patch" | "db.replace" | "db.delete" => Some("undefined"),
        "db.normalizeId" | "db.get" | "db.query" | "db.insert" | "scheduler.runAfter"
        | "scheduler.runAt" => Some("hostValue"),
        _ => None,
    }
}

fn semantic_operand(
    flow: &CallableValueFlowCandidate,
    runtime_input_index: usize,
) -> SemanticOperand {
    match flow {
        CallableValueFlowCandidate::Parameter { index } => SemanticOperand::Parameter(*index),
        CallableValueFlowCandidate::LiteralString { value } => {
            SemanticOperand::LiteralString(value.clone())
        }
        CallableValueFlowCandidate::CapturedBinding { .. }
        | CallableValueFlowCandidate::Expression { .. } => {
            SemanticOperand::RuntimeInput(runtime_input_index)
        }
    }
}

fn semantic_effect_key(effect: &CallableLeafEffectCandidate) -> Option<SemanticEffectKey> {
    if matches!(
        effect.operation.kind.as_str(),
        "scheduler.runAfter" | "scheduler.runAt"
    ) && effect.operation.function_reference.is_none()
    {
        return None;
    }
    let mut static_operands = BTreeMap::new();
    if let Some(table) = &effect.operation.table {
        static_operands.insert("table".to_string(), table.clone());
    }
    if let Some(index) = &effect.operation.index {
        static_operands.insert("index".to_string(), index.clone());
    }
    if let Some(order) = &effect.operation.order {
        static_operands.insert("order".to_string(), order.clone());
    }
    if let Some(terminal) = &effect.operation.terminal {
        static_operands.insert("terminal".to_string(), terminal.clone());
    }
    if let Some(function_reference) = &effect.operation.function_reference {
        static_operands.insert("functionReference".to_string(), function_reference.clone());
    }
    Some(SemanticEffectKey {
        operation_kind: semantic_operation_kind(&effect.operation.kind)?.to_string(),
        result_kind: result_kind(&effect.operation)?.to_string(),
        timing: if effect.operation.kind == "db.normalizeId" {
            SemanticEffectTiming::Synchronous
        } else {
            SemanticEffectTiming::Suspending
        },
        static_operands,
        index_constraints: effect
            .operation
            .index_constraints
            .iter()
            .map(|constraint| SemanticIndexConstraint {
                field: constraint.field.clone(),
                operator: constraint.operator.clone(),
            })
            .collect(),
        limit: effect.operation.limit,
        limit_argument_index: effect.operation.limit_argument_index,
    })
}

#[derive(Clone)]
struct PreparedCallableEffectPlan {
    callable: CallableKey,
    callable_source: SourceAnchor,
    effect_key: SemanticEffectKey,
    unresolved_static_operands: BTreeMap<String, SemanticOperand>,
    static_operand_provenance: Vec<(String, usize, SourceAnchor)>,
    dynamic_operands: Vec<SemanticEffectOperand>,
    provenance: SemanticEffectProvenance,
    target_control_block: u32,
    current_batch_leaf: bool,
}

impl PreparedCallableEffectPlan {
    fn finalize(&self) -> Result<Option<CallableEffectPlan>> {
        let mut effect_key = self.effect_key.clone();
        for (name, operand) in &self.unresolved_static_operands {
            let SemanticOperand::LiteralString(value) = operand else {
                return Ok(None);
            };
            effect_key
                .static_operands
                .insert(name.clone(), value.clone());
        }
        let static_operands = self
            .static_operand_provenance
            .iter()
            .map(|(field, argument_index, target_provenance)| {
                Ok(SemanticStaticEffectOperand {
                    field: field.clone(),
                    value: effect_key
                        .static_operands
                        .get(field)
                        .with_context(|| {
                            format!("effect plan has no finalized static operand {field}")
                        })?
                        .clone(),
                    target_argument_index: Some(*argument_index),
                    target_provenance: target_provenance.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(validate_callable_effect_plan(CallableEffectPlan {
            callable: self.callable.clone(),
            callable_source: self.callable_source.clone(),
            effect_key,
            static_operands,
            dynamic_operands: self.dynamic_operands.clone(),
            provenance: self.provenance.clone(),
        })?))
    }

    fn effect_value_source(&self) -> Result<AuthenticatedEffectValueSource> {
        anyhow::ensure!(
            self.callable == self.provenance.target_callable
                && self.callable_source == self.provenance.target_callable_source
                && self.provenance.caller_callsite.is_none(),
            "callable source effect lost its direct source callable provenance"
        );
        Ok(AuthenticatedEffectValueSource {
            target_callable: self.provenance.target_callable.clone(),
            target_callable_source: self.provenance.target_callable_source.clone(),
            target_effect: self.provenance.target_effect.clone(),
            target_callee: self.provenance.target_callee.clone(),
            capability_reference: self.provenance.capability_reference.clone(),
            capability_binding: self.provenance.capability_binding.clone(),
            capability_name: self.provenance.capability_name.clone(),
        })
    }
}

fn prepared_effect_plan(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    candidate: &CallableLeafPlanCandidate,
    effect: &CallableLeafEffectCandidate,
) -> Result<Option<PreparedCallableEffectPlan>> {
    let Some(effect_key) = semantic_effect_key(effect) else {
        return Ok(None);
    };
    let current_batch_leaf = candidate.current_batch_leaf
        && (!effect.implicit_undefined || effect_key.result_kind == "undefined");
    let callable = callable_key(module, candidate.callable_start, candidate.callable_end);
    let callable_source = source_anchor(
        modules,
        module,
        candidate.callable_start,
        candidate.callable_end,
    )?;
    let target_effect = source_anchor(
        modules,
        module,
        effect.operation.start,
        effect.operation.end,
    )?;
    let target_callee = source_anchor(
        modules,
        module,
        effect
            .operation
            .effect_start
            .context("callable effect has no exact callee start")?,
        effect
            .operation
            .effect_end
            .context("callable effect has no exact callee end")?,
    )?;
    anyhow::ensure!(
        effect.dynamic_arguments.len() == effect.dynamic_argument_ranges.len()
            && effect.dynamic_arguments.len() == effect.dynamic_argument_indices.len()
            && effect.dynamic_arguments.len() == effect.dynamic_parameter_projections.len(),
        "callable effect dynamic argument provenance is incomplete"
    );
    let loaded = modules
        .get(module)
        .context("callable effect-plan module disappeared")?;
    let dynamic_operands = effect
        .dynamic_arguments
        .iter()
        .zip(&effect.dynamic_argument_ranges)
        .zip(&effect.dynamic_argument_indices)
        .zip(&effect.dynamic_parameter_projections)
        .enumerate()
        .map(|(index, (((flow, range), argument_index), projection))| {
            let provenance = source_anchor(modules, module, range.start, range.end)?;
            let value = if let Some(projection) = projection {
                let parameter_name = candidate
                    .parameter_names
                    .get(projection.index)
                    .context("effect operand projection has no callable parameter name")?;
                let parameter_start = candidate
                    .parameter_starts
                    .get(projection.index)
                    .context("effect operand projection has no callable parameter start")?;
                let matching = loaded
                    .summary
                    .resolved_binding_facts
                    .iter()
                    .filter(|fact| fact.name == *parameter_name && fact.start == *parameter_start)
                    .collect::<Vec<_>>();
                let [fact] = matching.as_slice() else {
                    anyhow::bail!("effect operand projection has no unique Oxc parameter binding");
                };
                anyhow::ensure!(
                    projection.reference.start >= range.start
                        && projection.reference.end <= range.end
                        && fact.references.iter().any(|reference| {
                            reference.name == *parameter_name
                                && reference.start == projection.reference.start
                                && reference.end == projection.reference.end
                                && reference.read
                                && !reference.write
                        }),
                    "effect operand projection conflicts with its exact Oxc parameter reference"
                );
                SemanticOperand::Parameter(projection.index)
            } else {
                semantic_operand(flow, index)
            };
            Ok(SemanticEffectOperand {
                value,
                target_argument_index: *argument_index,
                target_provenance: provenance.clone(),
                projection: SemanticOperandProjection::ExactCaller {
                    consumer_provenance: provenance,
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let static_operand_provenance = effect
        .static_arguments
        .iter()
        .map(|argument| {
            Ok((
                argument.field.clone(),
                argument.argument_index,
                source_anchor(modules, module, argument.range.start, argument.range.end)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut unresolved_static_operands = BTreeMap::new();
    if let Some(table) = &effect.table {
        unresolved_static_operands.insert("table".to_string(), semantic_operand(table, 0));
    }
    Ok(Some(PreparedCallableEffectPlan {
        callable: callable.clone(),
        callable_source: callable_source.clone(),
        effect_key,
        unresolved_static_operands,
        static_operand_provenance,
        dynamic_operands,
        provenance: SemanticEffectProvenance {
            target_callable: callable,
            target_callable_source: callable_source,
            target_effect,
            target_callee,
            capability_reference: source_anchor(
                modules,
                module,
                effect.capability_reference.start,
                effect.capability_reference.end,
            )?,
            capability_binding: source_anchor(
                modules,
                module,
                effect.capability_binding.declaration_start,
                effect.capability_binding.declaration_end,
            )?,
            capability_name: effect.capability_binding.name.clone(),
            caller_callsite: None,
        },
        target_control_block: candidate
            .control_block
            .context("callable effect has no Oxc control block")?,
        current_batch_leaf,
    }))
}

fn static_operand_field(name: &str) -> Option<StaticOperandField> {
    match name {
        "table" => Some(StaticOperandField::Table),
        "index" => Some(StaticOperandField::Index),
        "functionReference" => Some(StaticOperandField::FunctionReference),
        _ => None,
    }
}

fn specialize_prepared_plan(
    modules: &BTreeMap<String, LoadedModule>,
    specialization: &EffectSpecialization,
    candidate: &CallableLeafPlanCandidate,
    call: &CallableLeafCallCandidate,
    target: &PreparedCallableEffectPlan,
    effect_execution_mode: super::EffectExecutionMode,
) -> Result<Option<CallableEffectPlan>> {
    let mut effect_key = target.effect_key.clone();
    for (name, operand) in &target.unresolved_static_operands {
        let value = match operand {
            SemanticOperand::Parameter(index) => {
                let Some(field) = static_operand_field(name) else {
                    return Ok(None);
                };
                let Some(value) = specialization.static_operands.get(&field) else {
                    return Ok(None);
                };
                let Some(argument) = call.arguments.get(*index) else {
                    return Ok(None);
                };
                if let CallableValueFlowCandidate::LiteralString {
                    value: argument_value,
                } = argument
                    && argument_value != value
                {
                    return Ok(None);
                }
                value.clone()
            }
            SemanticOperand::LiteralString(value) => value.clone(),
            SemanticOperand::RuntimeInput(_) => return Ok(None),
        };
        effect_key.static_operands.insert(name.clone(), value);
    }
    let callable = callable_key(
        &specialization.caller_module,
        candidate.callable_start,
        candidate.callable_end,
    );
    let callable_source = source_anchor(
        modules,
        &specialization.caller_module,
        candidate.callable_start,
        candidate.callable_end,
    )?;
    let dynamic_operands = target
        .dynamic_operands
        .iter()
        .enumerate()
        .map(|(index, operand)| {
            let (value, projection) = match operand.value {
                SemanticOperand::Parameter(parameter_index) => {
                    let flow = call.arguments.get(parameter_index)?;
                    let range = call.argument_ranges.get(parameter_index)?;
                    (
                        semantic_operand(flow, index),
                        SemanticOperandProjection::ExactCaller {
                            consumer_provenance: source_anchor(
                                modules,
                                &specialization.caller_module,
                                range.start,
                                range.end,
                            )
                            .ok()?,
                        },
                    )
                }
                SemanticOperand::RuntimeInput(_) => {
                    if effect_execution_mode != super::EffectExecutionMode::GuestPromiseEventLoop {
                        return None;
                    }
                    (operand.value.clone(), SemanticOperandProjection::TargetOnly)
                }
                SemanticOperand::LiteralString(_) => {
                    return None;
                }
            };
            Some(SemanticEffectOperand {
                value,
                target_argument_index: operand.target_argument_index,
                target_provenance: operand.target_provenance.clone(),
                projection,
            })
        })
        .collect::<Option<Vec<_>>>();
    let Some(dynamic_operands) = dynamic_operands else {
        return Ok(None);
    };
    let static_operands = target
        .static_operand_provenance
        .iter()
        .map(|(field, argument_index, target_provenance)| {
            Ok(SemanticStaticEffectOperand {
                field: field.clone(),
                value: effect_key
                    .static_operands
                    .get(field)
                    .with_context(|| {
                        format!("specialized effect plan has no static operand {field}")
                    })?
                    .clone(),
                target_argument_index: Some(*argument_index),
                target_provenance: target_provenance.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(validate_callable_effect_plan(CallableEffectPlan {
        callable,
        callable_source,
        effect_key,
        static_operands,
        dynamic_operands,
        provenance: SemanticEffectProvenance {
            target_callable: target.provenance.target_callable.clone(),
            target_callable_source: target.provenance.target_callable_source.clone(),
            target_effect: target.provenance.target_effect.clone(),
            target_callee: target.provenance.target_callee.clone(),
            capability_reference: target.provenance.capability_reference.clone(),
            capability_binding: target.provenance.capability_binding.clone(),
            capability_name: target.provenance.capability_name.clone(),
            caller_callsite: Some(source_anchor(
                modules,
                &specialization.caller_module,
                call.start,
                call.end,
            )?),
        },
    })?))
}

fn callable_graph_id(module: &str, range: &SourceRange) -> String {
    format!("{module}#span:{}:{}", range.start, range.end)
}

fn target_callable_range(
    modules: &BTreeMap<String, LoadedModule>,
    target: &StaticCallableTarget,
) -> Option<SourceRange> {
    modules
        .get(&target.0)?
        .summary
        .units
        .get(&target.1)?
        .callable_range
        .clone()
}

fn static_activation_target_callable(
    modules: &BTreeMap<String, LoadedModule>,
    control_plans: &BTreeMap<CallableKey, CallableControlPlan>,
    target: &StaticCallableTarget,
) -> Result<Option<CallableKey>> {
    let unit = modules
        .get(&target.0)
        .context("static activation-call target module disappeared")?
        .summary
        .units
        .get(&target.1)
        .context("static activation-call target unit disappeared")?;
    let Some(range) = &unit.callable_range else {
        return Ok(None);
    };
    let callable = callable_key(&target.0, range.start, range.end);
    Ok(control_plans.contains_key(&callable).then_some(callable))
}

fn source_anchor_contains(container: &SourceAnchor, contained: &SourceAnchor) -> bool {
    container.module == contained.module
        && container.source_sha256 == contained.source_sha256
        && container.start <= contained.start
        && contained.end <= container.end
}

fn exact_activation_caller<'a>(
    control_plans: &'a BTreeMap<CallableKey, CallableControlPlan>,
    callsite: &SourceAnchor,
) -> Result<Option<&'a CallableControlPlan>> {
    let mut matching = Vec::new();
    for plan in control_plans.values() {
        if !source_anchor_contains(&plan.callable_source, callsite) {
            continue;
        }
        if plan.skeleton.points.iter().any(|point| {
            point.kind == CallableControlPointKind::Call
                && point.start == callsite.start
                && point.end == callsite.end
        }) {
            matching.push(plan);
        }
    }
    match matching.as_slice() {
        [] => Ok(None),
        [plan] => Ok(Some(*plan)),
        _ => anyhow::bail!("static activation-call has ambiguous exact Oxc caller control plans"),
    }
}

fn leaf_call_candidate<'a>(
    module: &'a LoadedModule,
    caller: &ReachableUnit,
    indexed: &super::CallCandidate,
) -> Option<(&'a CallableLeafPlanCandidate, &'a CallableLeafCallCandidate)> {
    let mut matches = module
        .summary
        .callable_leaf_plans
        .iter()
        .filter_map(|candidate| {
            if candidate.callable_start < caller.start || candidate.callable_end > caller.end {
                return None;
            }
            let CallableLeafControlCandidate::Call(call) = &candidate.control else {
                return None;
            };
            (call.start == indexed.start
                && call.end == indexed.end
                && call.callee == indexed.callee
                && call.callee_start == indexed.callee_start
                && call.callee_end == indexed.callee_end)
                .then_some((candidate, call))
        });
    match (matches.next(), matches.next()) {
        (Some(candidate), None) => Some(candidate),
        _ => None,
    }
}

fn call_position(call: &super::CallCandidate) -> Option<CallPosition> {
    match call.suspension.as_deref() {
        Some("await") => Some(CallPosition::SequentialAwait),
        Some("return") => Some(CallPosition::TailReturn),
        None => Some(CallPosition::Synchronous),
        Some(_) => None,
    }
}

pub(super) fn build_callable_effect_plan_index(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    static_calls: &ReachableStaticCallIndex<'_>,
    effect_execution_mode: super::EffectExecutionMode,
) -> Result<CallableEffectPlanIndex> {
    let mut index = CallableEffectPlanIndex::default();
    index.query_values = authenticate_callable_query_value_plans(modules, reachable)?;
    index.query_builder_flows = authenticate_callable_query_builder_flows(modules, reachable)?;
    let mut prepared = BTreeMap::new();
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("reachable callable-plan module disappeared")?;
        for candidate in module
            .summary
            .callable_leaf_plans
            .iter()
            .filter(|candidate| {
                candidate.callable_start >= unit.start && candidate.callable_end <= unit.end
            })
        {
            let CallableLeafControlCandidate::Effect(effect) = &candidate.control else {
                continue;
            };
            let Some(plan) = prepared_effect_plan(modules, &unit.module, candidate, effect)? else {
                continue;
            };
            let key = (
                plan.callable.clone(),
                plan.provenance.target_effect.start,
                plan.provenance.target_effect.end,
            );
            if let Some(previous) = prepared.insert(key.clone(), plan.clone()) {
                anyhow::ensure!(
                    previous.callable_source == plan.callable_source
                        && previous.effect_key == plan.effect_key
                        && previous.unresolved_static_operands == plan.unresolved_static_operands
                        && previous.dynamic_operands == plan.dynamic_operands
                        && previous.provenance == plan.provenance
                        && previous.target_control_block == plan.target_control_block,
                    "callable leaf plan has conflicting prepared semantic projections"
                );
            }
            index.insert_source_effect(CallableControlSourceEffect {
                source: plan.effect_value_source()?,
                block: plan.target_control_block,
            })?;
            let current_batch_leaf = plan.current_batch_leaf;
            if let Some(plan) = plan.finalize()? {
                index.insert(
                    plan,
                    current_batch_leaf,
                    PlanControlProvenance {
                        target_block: candidate
                            .control_block
                            .context("direct callable effect has no Oxc control block")?,
                        consumer_block: candidate
                            .control_block
                            .context("direct callable effect has no Oxc control block")?,
                    },
                )?;
            }
        }
    }

    let mut templates = Vec::new();
    let mut template_targets = BTreeMap::new();
    for (key, plan) in &prepared {
        let callable = &key.0;
        let mut static_operands = Vec::new();
        let mut supported = true;
        for (name, operand) in &plan.unresolved_static_operands {
            match operand {
                SemanticOperand::Parameter(parameter_index) => {
                    let Some(field) = static_operand_field(name) else {
                        supported = false;
                        break;
                    };
                    static_operands.push(StaticOperand {
                        field,
                        parameter_index: *parameter_index,
                    });
                }
                SemanticOperand::LiteralString(_) => {}
                SemanticOperand::RuntimeInput(_) => {
                    supported = false;
                    break;
                }
            }
        }
        if !supported {
            continue;
        }
        let id = format!(
            "{}#{}:{}:{}",
            callable.module,
            callable.unit_id,
            plan.provenance.target_effect.start,
            plan.provenance.target_effect.end
        );
        template_targets.insert(id.clone(), key.clone());
        templates.push(EffectTemplate {
            id,
            unit_id: callable_graph_id(
                &callable.module,
                &SourceRange {
                    start: plan.callable_source.start,
                    end: plan.callable_source.end,
                },
            ),
            static_operands,
            timing: match plan.effect_key.timing {
                SemanticEffectTiming::Synchronous => EffectTiming::Synchronous,
                SemanticEffectTiming::Suspending => EffectTiming::Suspending,
            },
            tail_return_safe: true,
        });
    }

    let mut calls = Vec::new();
    let mut leaf_calls = BTreeMap::new();
    let mut complete_targets = BTreeSet::new();
    for (target, resolved_calls) in static_calls.calls_by_target() {
        let Some(target_range) = target_callable_range(modules, target) else {
            continue;
        };
        let target_unit_id = callable_graph_id(&target.0, &target_range);
        if static_calls.dispatch_is_exact(target) {
            complete_targets.insert(target_unit_id.clone());
        }
        for resolved in resolved_calls {
            let caller_module = modules
                .get(&resolved.caller.module)
                .context("resolved callable-plan caller module disappeared")?;
            let source = module_source(modules, &resolved.caller.module)?;
            let leaf = leaf_call_candidate(caller_module, resolved.caller, resolved.call);
            let caller_range = if let Some((candidate, _)) = leaf {
                SourceRange {
                    start: candidate.callable_start,
                    end: candidate.callable_end,
                }
            } else {
                let caller_unit = caller_module
                    .summary
                    .units
                    .get(&resolved.caller.name)
                    .context("resolved callable-plan caller unit disappeared")?;
                let Some(range) = &caller_unit.callable_range else {
                    continue;
                };
                range.clone()
            };
            let caller_unit_id = callable_graph_id(&resolved.caller.module, &caller_range);
            let Some(position) = call_position(resolved.call) else {
                continue;
            };
            let mut arguments_safe = true;
            let arguments = if let Some((candidate, call)) = leaf {
                leaf_calls.insert(
                    (
                        resolved.caller.module.clone(),
                        resolved.call.start,
                        resolved.call.end,
                    ),
                    (candidate, call),
                );
                call.arguments
                    .iter()
                    .map(|argument| match argument {
                        CallableValueFlowCandidate::LiteralString { value } => {
                            ArgumentFlow::LiteralString(value.clone())
                        }
                        CallableValueFlowCandidate::Parameter { index } => {
                            ArgumentFlow::Parameter {
                                unit_id: caller_unit_id.clone(),
                                parameter_index: *index,
                            }
                        }
                        CallableValueFlowCandidate::CapturedBinding { .. }
                        | CallableValueFlowCandidate::Expression { .. } => ArgumentFlow::Unknown,
                    })
                    .collect()
            } else {
                resolved
                    .call
                    .arguments
                    .iter()
                    .enumerate()
                    .map(|(argument_index, argument)| {
                        if resolved
                            .call
                            .argument_await_counts
                            .get(argument_index)
                            .copied()
                            != Some(0)
                            || source_slice(&source, argument.start, argument.end)
                                .is_ok_and(|value| value.trim_start().starts_with("..."))
                        {
                            arguments_safe = false;
                            return Ok(ArgumentFlow::Unknown);
                        }
                        if let Some(value) =
                            source_range_string(&source, argument).filter(|value| !value.is_empty())
                        {
                            return Ok(ArgumentFlow::LiteralString(value));
                        }
                        if let Some(parameter) =
                            caller_parameter_for_reference(modules, resolved.caller, argument)?
                        {
                            return Ok(ArgumentFlow::Parameter {
                                unit_id: caller_unit_id.clone(),
                                parameter_index: parameter.index,
                            });
                        }
                        Ok(ArgumentFlow::Unknown)
                    })
                    .collect::<Result<Vec<_>>>()?
            };
            if let Some((candidate, call)) = leaf {
                anyhow::ensure!(
                    call.arguments.len() == call.argument_ranges.len(),
                    "callable control call has incomplete argument provenance"
                );
                let authenticated_arguments = call
                    .arguments
                    .iter()
                    .zip(&call.argument_ranges)
                    .map(|(value, range)| {
                        Ok(CallableControlCallArgument {
                            value: value.clone(),
                            provenance: source_anchor(
                                modules,
                                &resolved.caller.module,
                                range.start,
                                range.end,
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                index.insert_call(
                    callable_key(
                        &resolved.caller.module,
                        candidate.callable_start,
                        candidate.callable_end,
                    ),
                    CallableControlCallPlan {
                        callsite: source_anchor(
                            modules,
                            &resolved.caller.module,
                            call.start,
                            call.end,
                        )?,
                        target: callable_key(&target.0, target_range.start, target_range.end),
                        target_source: source_anchor(
                            modules,
                            &target.0,
                            target_range.start,
                            target_range.end,
                        )?,
                        block: candidate
                            .control_block
                            .context("static call has no Oxc control block")?,
                        position,
                        dispatch_exact: static_calls.dispatch_is_exact(target),
                        arguments_safe,
                        arguments: authenticated_arguments,
                    },
                )?;
            }
            calls.push(CallEdge {
                caller_module: resolved.caller.module.clone(),
                call_start: resolved.call.start,
                call_end: resolved.call.end,
                target_unit_id: target_unit_id.clone(),
                arguments,
                arguments_safe,
                position,
            });
        }
    }

    let mut specialized_plans = BTreeMap::<
        (String, u32, u32, String, u32, u32),
        Vec<(CallableEffectPlan, bool, PlanControlProvenance)>,
    >::new();
    let propagated_effects =
        propagate_callable_effects(&templates, &calls, &complete_targets, effect_execution_mode);
    for specialization in propagated_effects.iter() {
        let Some((candidate, call)) = leaf_calls.get(&(
            specialization.caller_module.clone(),
            specialization.call_start,
            specialization.call_end,
        )) else {
            continue;
        };
        let Some(target_key) = template_targets.get(&specialization.template_id) else {
            continue;
        };
        let Some(target) = prepared.get(target_key) else {
            continue;
        };
        let Some(plan) = specialize_prepared_plan(
            modules,
            specialization,
            candidate,
            call,
            target,
            effect_execution_mode,
        )?
        else {
            continue;
        };
        specialized_plans
            .entry((
                specialization.caller_module.clone(),
                call.start,
                call.end,
                plan.provenance.target_effect.module.clone(),
                plan.provenance.target_effect.start,
                plan.provenance.target_effect.end,
            ))
            .or_default()
            .push((
                plan,
                target.current_batch_leaf && candidate.current_batch_leaf,
                PlanControlProvenance {
                    target_block: target.target_control_block,
                    consumer_block: candidate
                        .control_block
                        .context("specialized callable call has no Oxc control block")?,
                },
            ));
    }
    for plans in specialized_plans.into_values() {
        let Some((plan, current_batch_leaf, control)) = plans.first() else {
            continue;
        };
        if !plans.iter().all(|candidate| {
            candidate.0 == *plan && candidate.1 == *current_batch_leaf && candidate.2 == *control
        }) {
            continue;
        }
        index.insert(plan.clone(), *current_batch_leaf, *control)?;
    }
    index.rebuild_consumer_sites();
    index.rebuild_control_plans(modules, reachable)?;
    index.rebuild_activation_calls(modules, static_calls)?;
    index.effect_value_flows =
        authenticate_callable_effect_value_flows(modules, reachable, &index.control_plans)?;
    index.query_builder_graph = build_authenticated_query_builder_graph(
        &index.query_builder_flows,
        index.control_plans.values(),
    );
    index.effect_value_graph = build_authenticated_effect_value_graph(
        &index.effect_value_flows,
        index.control_plans.values(),
    )?;
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(module: &str, start: u32, end: u32) -> SourceAnchor {
        SourceAnchor {
            module: module.to_string(),
            source_sha256: "a".repeat(64),
            start,
            end,
            slice_sha256: "b".repeat(64),
        }
    }

    fn plan(
        callable_start: u32,
        target_start: u32,
        callsite_start: Option<u32>,
        operation_kind: &str,
    ) -> CallableEffectPlan {
        let target_callable = callable_key("convex/helper.ts", 10, 60);
        let target_callable_source = anchor("convex/helper.ts", 10, 60);
        let (callable, callable_source) = if callsite_start.is_some() {
            let source = anchor("convex/example.ts", callable_start, callable_start + 20);
            (
                callable_key("convex/example.ts", source.start, source.end),
                source,
            )
        } else {
            (target_callable.clone(), target_callable_source.clone())
        };
        validate_callable_effect_plan(CallableEffectPlan {
            callable,
            callable_source,
            effect_key: SemanticEffectKey {
                operation_kind: operation_kind.to_string(),
                result_kind: "hostValue".to_string(),
                timing: SemanticEffectTiming::Suspending,
                static_operands: BTreeMap::from([("table".to_string(), "docs".to_string())]),
                index_constraints: Vec::new(),
                limit: None,
                limit_argument_index: None,
            },
            static_operands: vec![SemanticStaticEffectOperand {
                field: "table".to_string(),
                value: "docs".to_string(),
                target_argument_index: Some(0),
                target_provenance: anchor("convex/helper.ts", target_start + 1, target_start + 2),
            }],
            dynamic_operands: Vec::new(),
            provenance: SemanticEffectProvenance {
                target_callable,
                target_callable_source,
                target_effect: anchor("convex/helper.ts", target_start, target_start + 5),
                target_callee: anchor("convex/helper.ts", target_start, target_start + 5),
                capability_reference: anchor("convex/helper.ts", target_start, target_start + 1),
                capability_binding: anchor("convex/helper.ts", 10, 11),
                capability_name: "ctx".to_string(),
                caller_callsite: callsite_start
                    .map(|start| anchor("convex/example.ts", start, start + 5)),
            },
        })
        .expect("test callable effect plan must be valid")
    }

    #[test]
    fn direct_and_specialized_plans_use_one_consumer_site_rule() {
        let direct = plan(40, 15, None, "databaseGet");
        assert_eq!(
            direct.consumer_site_identity(),
            ("convex/helper.ts".to_string(), 15, 20)
        );
        assert_eq!(direct.consumer_site(), &direct.provenance.target_effect);

        let specialized = plan(70, 15, Some(80), "databaseGet");
        assert_eq!(
            specialized.consumer_site_identity(),
            ("convex/example.ts".to_string(), 80, 85)
        );
        assert_eq!(
            specialized.target_identity(),
            ("convex/helper.ts".to_string(), 15, 20)
        );
    }

    #[test]
    fn index_resolves_direct_and_specialized_plans_by_consumer_site() {
        let direct = plan(40, 15, None, "databaseGet");
        let specialized = plan(70, 35, Some(80), "databaseInsert");
        let mut index = CallableEffectPlanIndex::default();
        index
            .insert(
                direct.clone(),
                true,
                PlanControlProvenance {
                    target_block: 0,
                    consumer_block: 0,
                },
            )
            .unwrap();
        index
            .insert(
                specialized.clone(),
                true,
                PlanControlProvenance {
                    target_block: 0,
                    consumer_block: 0,
                },
            )
            .unwrap();
        index.rebuild_consumer_sites();

        assert_eq!(
            index.plan_at_site("convex/helper.ts", 15, 20),
            Some(&direct)
        );
        assert_eq!(
            index.plan_at_site("convex/example.ts", 80, 85),
            Some(&specialized)
        );
        assert_eq!(index.plans().count(), 2);
    }

    #[test]
    fn multiple_consumer_site_effects_remain_available_to_the_generic_plan() {
        let first = plan(90, 15, Some(100), "databaseGet");
        let second = plan(95, 35, Some(100), "databaseInsert");
        let mut index = CallableEffectPlanIndex::default();
        index
            .insert(
                first.clone(),
                true,
                PlanControlProvenance {
                    target_block: 0,
                    consumer_block: 0,
                },
            )
            .unwrap();
        index
            .insert(
                second.clone(),
                true,
                PlanControlProvenance {
                    target_block: 0,
                    consumer_block: 0,
                },
            )
            .unwrap();
        index.rebuild_consumer_sites();

        assert!(index.plan_at_site("convex/example.ts", 100, 105).is_none());
        assert_eq!(
            index
                .plans_at_site("convex/example.ts", 100, 105)
                .iter()
                .map(|plan| plan.effect_key.operation_kind.as_str())
                .collect::<Vec<_>>(),
            vec!["databaseGet", "databaseInsert"]
        );
        assert_eq!(
            index.plan_for_callable("convex/example.ts", 90, 110),
            Some(&first)
        );
        assert_eq!(
            index.plan_for_callable("convex/example.ts", 95, 115),
            Some(&second)
        );
        assert_eq!(index.plans().count(), 2);
    }
}
