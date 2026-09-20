use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::callable_plans::{
    CallableValueFlowCandidate, ResolvedBinding, ResolvedBindingIndex,
    ResolvedBindingReferenceIndex, callable_key, source_anchor, value_flow,
};
use super::callable_value_flow::{
    CallableValueBindingEdge, CallableValueBindingInitializer as BindingInitializer,
    CallableValueCallResultOrigin, CallableValueDomain, CallableValueParameterOrigin,
    MAX_CALLABLE_VALUE_PATH_VARIANTS,
    collect_callable_value_binding_initializers as collect_binding_initializers,
    resolve_callable_value_expression,
};
use super::effect_plan::{CallableKey, SourceAnchor};
use super::{
    LoadedModule, ReachableUnit, SourceRange, call_has_optional_callee, call_method_name,
    callee_identifier, count_node_type, hash_bytes, identifier_name, module_source, node_type,
    span, static_member_chain, unwrap_runtime_expression, value_string,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum CallableQueryCapabilityKind {
    ContextDatabase,
    Database,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQuerySourceCandidate {
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) callee: SourceRange,
    pub(super) capability_kind: CallableQueryCapabilityKind,
    pub(super) capability: CallableValueFlowCandidate,
    pub(super) capability_reference: SourceRange,
    pub(super) capability_binding: ResolvedBinding,
    pub(super) table: CallableValueFlowCandidate,
    pub(super) table_range: SourceRange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryIndexConstraintCandidate {
    pub(super) field: String,
    pub(super) operator: String,
    pub(super) value: CallableValueFlowCandidate,
    pub(super) value_range: SourceRange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum CallableQueryStageCandidate {
    WithIndex {
        start: u32,
        end: u32,
        receiver: SourceRange,
        index: String,
        index_range: SourceRange,
        constraints: Vec<CallableQueryIndexConstraintCandidate>,
    },
    Order {
        start: u32,
        end: u32,
        receiver: SourceRange,
        direction: CallableValueFlowCandidate,
        direction_range: SourceRange,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum CallableQueryConsumerKind {
    Collect,
    First,
    Unique,
    Take,
    Paginate,
    Stream,
}

impl CallableQueryConsumerKind {
    pub(super) fn terminal(self) -> &'static str {
        match self {
            Self::Collect => "collect",
            Self::First => "first",
            Self::Unique => "unique",
            Self::Take => "take",
            Self::Paginate => "paginate",
            Self::Stream => "stream",
        }
    }

    pub(super) fn result_kind(self) -> &'static str {
        match self {
            Self::Collect | Self::Take => "hostArray",
            Self::First | Self::Unique | Self::Paginate => "hostValue",
            Self::Stream => "queryStream",
        }
    }

    pub(super) fn descriptor_terminal(self) -> &'static str {
        match self {
            Self::Take => "collect",
            _ => self.terminal(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryBindingEdgeCandidate {
    pub(super) binding: ResolvedBinding,
    pub(super) initializer: SourceRange,
    pub(super) reference: SourceRange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryStreamBindingCandidate {
    pub(super) binding: ResolvedBinding,
    pub(super) references: Vec<super::ReferenceOccurrence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryConsumerCandidate {
    pub(super) kind: CallableQueryConsumerKind,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) receiver: SourceRange,
    pub(super) stages: Vec<CallableQueryStageCandidate>,
    pub(super) arguments: Vec<CallableValueFlowCandidate>,
    pub(super) argument_ranges: Vec<SourceRange>,
    pub(super) binding_edges: Vec<CallableQueryBindingEdgeCandidate>,
    pub(super) choice_ranges: Vec<SourceRange>,
    pub(super) static_limit: Option<u32>,
    pub(super) dynamic_limit: bool,
    pub(super) stream_binding: Option<CallableQueryStreamBindingCandidate>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum CallableQueryForwardCandidate {
    Return {
        start: u32,
        end: u32,
        value: SourceRange,
        stages: Vec<CallableQueryStageCandidate>,
        binding_edges: Vec<CallableQueryBindingEdgeCandidate>,
        choice_ranges: Vec<SourceRange>,
    },
    CallArgument {
        start: u32,
        end: u32,
        callee: String,
        callee_start: u32,
        callee_end: u32,
        argument_index: usize,
        value: SourceRange,
        stages: Vec<CallableQueryStageCandidate>,
        binding_edges: Vec<CallableQueryBindingEdgeCandidate>,
        choice_ranges: Vec<SourceRange>,
    },
}

impl CallableQueryForwardCandidate {
    fn binding_edges(&self) -> &[CallableQueryBindingEdgeCandidate] {
        match self {
            Self::Return { binding_edges, .. } | Self::CallArgument { binding_edges, .. } => {
                binding_edges
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryValueRejectionCandidate {
    pub(super) range: SourceRange,
    pub(super) reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryValuePlanCandidate {
    pub(super) callable_start: u32,
    pub(super) callable_end: u32,
    pub(super) source: CallableQuerySourceCandidate,
    pub(super) consumers: Vec<CallableQueryConsumerCandidate>,
    pub(super) forwards: Vec<CallableQueryForwardCandidate>,
    pub(super) locally_closed: bool,
    pub(super) closed: bool,
    pub(super) rejections: Vec<CallableQueryValueRejectionCandidate>,
}

/// The two opaque Convex query values whose flow is relevant to lowering. Ordinary JavaScript
/// values remain owned by Static Hermes; these kinds only describe the host-facing query protocol.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum CallableQueryBuilderKind {
    QueryBuilder,
    IndexRangeBuilder,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum CallableQueryBuilderOriginCandidate {
    QueryConstruction {
        source: CallableQuerySourceCandidate,
    },
    Parameter {
        index: usize,
        name: String,
        declaration: SourceRange,
        reference: SourceRange,
    },
    CallResult {
        callsite: SourceRange,
        callee: String,
        callee_range: SourceRange,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryBuilderFlowRejectionCandidate {
    pub(super) origin: CallableQueryBuilderOriginCandidate,
    pub(super) range: SourceRange,
    pub(super) reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum CallableQueryBuilderStepCandidate {
    Alias {
        edge: CallableQueryBindingEdgeCandidate,
    },
    QueryStage {
        stage: CallableQueryStageCandidate,
        range_callback: Option<SourceRange>,
    },
    IndexConstraint {
        site: SourceRange,
        receiver: SourceRange,
        constraint: CallableQueryIndexConstraintCandidate,
    },
    Choice {
        site: SourceRange,
        branch: usize,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum CallableQueryBuilderSinkCandidate {
    CallArgument {
        callsite: SourceRange,
        callee: String,
        callee_range: SourceRange,
        argument_index: usize,
        value: SourceRange,
    },
    CallResult {
        callsite: SourceRange,
    },
    Return {
        site: SourceRange,
        value: SourceRange,
    },
    Terminal {
        consumer: CallableQueryConsumerCandidate,
    },
    ForAwait {
        site: SourceRange,
        value: SourceRange,
        binding: CallableQueryStreamBindingCandidate,
    },
    WithIndexRangeReturn {
        site: SourceRange,
        value: SourceRange,
        with_index_site: SourceRange,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryBuilderPathCandidate {
    pub(super) value_kind: CallableQueryBuilderKind,
    pub(super) origin: CallableQueryBuilderOriginCandidate,
    pub(super) steps: Vec<CallableQueryBuilderStepCandidate>,
    pub(super) sink: CallableQueryBuilderSinkCandidate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableQueryBuilderFlowCandidate {
    pub(super) callable_start: u32,
    pub(super) callable_end: u32,
    pub(super) parameter_count: usize,
    pub(super) is_async: bool,
    pub(super) paths: Vec<CallableQueryBuilderPathCandidate>,
    pub(super) rejections: Vec<CallableQueryBuilderFlowRejectionCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryValueOperand {
    pub(super) value: CallableValueFlowCandidate,
    pub(super) provenance: SourceAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQuerySource {
    pub(super) construction: SourceAnchor,
    pub(super) callee: SourceAnchor,
    pub(super) capability_kind: CallableQueryCapabilityKind,
    pub(super) capability: CallableValueFlowCandidate,
    pub(super) capability_reference: SourceAnchor,
    pub(super) capability_binding: SourceAnchor,
    pub(super) capability_name: String,
    pub(super) table: AuthenticatedQueryValueOperand,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryIndexConstraint {
    pub(super) field: String,
    pub(super) operator: String,
    pub(super) value: AuthenticatedQueryValueOperand,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum AuthenticatedQueryStage {
    WithIndex {
        site: SourceAnchor,
        receiver: SourceAnchor,
        index: String,
        index_provenance: SourceAnchor,
        constraints: Vec<AuthenticatedQueryIndexConstraint>,
    },
    Order {
        site: SourceAnchor,
        receiver: SourceAnchor,
        direction: AuthenticatedQueryValueOperand,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryBindingEdge {
    pub(super) name: String,
    pub(super) binding: SourceAnchor,
    pub(super) initializer: SourceAnchor,
    pub(super) reference: SourceAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryStreamReference {
    pub(super) provenance: SourceAnchor,
    pub(super) read: bool,
    pub(super) write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryStreamBinding {
    pub(super) name: String,
    pub(super) binding: SourceAnchor,
    pub(super) references: Vec<AuthenticatedQueryStreamReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryConsumer {
    pub(super) kind: CallableQueryConsumerKind,
    pub(super) site: SourceAnchor,
    pub(super) receiver: SourceAnchor,
    pub(super) stages: Vec<AuthenticatedQueryStage>,
    pub(super) arguments: Vec<AuthenticatedQueryValueOperand>,
    pub(super) binding_edges: Vec<AuthenticatedQueryBindingEdge>,
    pub(super) choices: Vec<SourceAnchor>,
    pub(super) static_limit: Option<u32>,
    pub(super) dynamic_limit: bool,
    pub(super) stream_binding: Option<AuthenticatedQueryStreamBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum AuthenticatedQueryForward {
    Return {
        site: SourceAnchor,
        value: SourceAnchor,
        stages: Vec<AuthenticatedQueryStage>,
        binding_edges: Vec<AuthenticatedQueryBindingEdge>,
        choices: Vec<SourceAnchor>,
    },
    CallArgument {
        site: SourceAnchor,
        callee: String,
        callee_provenance: SourceAnchor,
        argument_index: usize,
        value: SourceAnchor,
        stages: Vec<AuthenticatedQueryStage>,
        binding_edges: Vec<AuthenticatedQueryBindingEdge>,
        choices: Vec<SourceAnchor>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryValueRejection {
    pub(super) provenance: SourceAnchor,
    pub(super) reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedCallableQueryValuePlan {
    pub(super) authorization_id: String,
    pub(super) callable: CallableKey,
    pub(super) callable_source: SourceAnchor,
    pub(super) source: AuthenticatedQuerySource,
    pub(super) consumers: Vec<AuthenticatedQueryConsumer>,
    pub(super) forwards: Vec<AuthenticatedQueryForward>,
    pub(super) locally_closed: bool,
    pub(super) closed: bool,
    pub(super) rejections: Vec<AuthenticatedQueryValueRejection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum AuthenticatedQueryBuilderOrigin {
    QueryConstruction {
        source: AuthenticatedQuerySource,
    },
    Parameter {
        index: usize,
        name: String,
        declaration: SourceAnchor,
        reference: SourceAnchor,
    },
    CallResult {
        callsite: SourceAnchor,
        callee: String,
        callee_provenance: SourceAnchor,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryBuilderFlowRejection {
    pub(super) origin: AuthenticatedQueryBuilderOrigin,
    pub(super) provenance: SourceAnchor,
    pub(super) reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum AuthenticatedQueryBuilderStep {
    Alias {
        edge: AuthenticatedQueryBindingEdge,
    },
    QueryStage {
        stage: AuthenticatedQueryStage,
        range_callback: Option<SourceAnchor>,
    },
    IndexConstraint {
        site: SourceAnchor,
        receiver: SourceAnchor,
        constraint: AuthenticatedQueryIndexConstraint,
    },
    Choice {
        site: SourceAnchor,
        branch: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub(super) enum AuthenticatedQueryBuilderSink {
    CallArgument {
        callsite: SourceAnchor,
        callee: String,
        callee_provenance: SourceAnchor,
        argument_index: usize,
        value: SourceAnchor,
    },
    CallResult {
        callsite: SourceAnchor,
    },
    Return {
        site: SourceAnchor,
        value: SourceAnchor,
    },
    Terminal {
        consumer: AuthenticatedQueryConsumer,
    },
    ForAwait {
        site: SourceAnchor,
        value: SourceAnchor,
        binding: AuthenticatedQueryStreamBinding,
    },
    WithIndexRangeReturn {
        site: SourceAnchor,
        value: SourceAnchor,
        with_index_site: SourceAnchor,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedQueryBuilderPath {
    pub(super) value_kind: CallableQueryBuilderKind,
    pub(super) origin: AuthenticatedQueryBuilderOrigin,
    pub(super) steps: Vec<AuthenticatedQueryBuilderStep>,
    pub(super) sink: AuthenticatedQueryBuilderSink,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatedCallableQueryBuilderFlow {
    pub(super) authorization_id: String,
    pub(super) callable: CallableKey,
    pub(super) callable_source: SourceAnchor,
    pub(super) parameter_count: usize,
    pub(super) is_async: bool,
    pub(super) paths: Vec<AuthenticatedQueryBuilderPath>,
    pub(super) rejections: Vec<AuthenticatedQueryBuilderFlowRejection>,
}

#[derive(Clone)]
struct ResolvedQueryPath {
    source: CallableQuerySourceCandidate,
    stages: Vec<CallableQueryStageCandidate>,
    binding_edges: Vec<CallableQueryBindingEdgeCandidate>,
    choice_ranges: Vec<SourceRange>,
}

fn source_range(value: &Value) -> Result<SourceRange> {
    let (start, end) = span(unwrap_runtime_expression(value))?;
    Ok(SourceRange { start, end })
}

fn query_source_candidate(
    call: &Value,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
) -> Result<Option<CallableQuerySourceCandidate>> {
    let call = unwrap_runtime_expression(call);
    if node_type(call).ok() != Some("CallExpression") || call_has_optional_callee(call) {
        return Ok(None);
    }
    let Some(callee) = call.get("callee") else {
        return Ok(None);
    };
    let Some(chain) = static_member_chain(callee) else {
        return Ok(None);
    };
    let capability_kind = match chain.fields.as_slice() {
        [database, query] if database == "db" && query == "query" => {
            CallableQueryCapabilityKind::ContextDatabase
        }
        [query] if query == "query" => CallableQueryCapabilityKind::Database,
        _ => return Ok(None),
    };
    if chain.computed || chain.optional {
        return Ok(None);
    }
    let Some(arguments) = call.get("arguments").and_then(Value::as_array) else {
        return Ok(None);
    };
    if arguments.len() != 1
        || node_type(&arguments[0]).ok() == Some("SpreadElement")
        || count_node_type(&arguments[0], "AwaitExpression") > 0
    {
        return Ok(None);
    }
    let capability_reference = SourceRange {
        start: chain.root_start,
        end: chain.root_end,
    };
    let Some(capability_binding) = bindings
        .get(&(capability_reference.start, capability_reference.end))
        .cloned()
    else {
        return Ok(None);
    };
    let (start, end) = span(call)?;
    let callee = source_range(callee)?;
    let table_range = source_range(&arguments[0])?;
    Ok(Some(CallableQuerySourceCandidate {
        start,
        end,
        callee,
        capability_kind,
        capability: value_flow(
            call.get("callee")
                .and_then(|callee| {
                    let mut current = unwrap_runtime_expression(callee);
                    while node_type(current).ok() == Some("MemberExpression") {
                        current = current.get("object").map(unwrap_runtime_expression)?;
                    }
                    Some(current)
                })
                .expect("static query chain lost its root"),
            parameter_starts,
            bindings,
        )?,
        capability_reference,
        capability_binding,
        table: value_flow(&arguments[0], parameter_starts, bindings)?,
        table_range,
    }))
}

fn query_receiver(call: &Value) -> Option<&Value> {
    let callee = call.get("callee").map(unwrap_runtime_expression)?;
    (node_type(callee).ok()? == "MemberExpression"
        && !callee
            .get("computed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        && !callee
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    .then(|| callee.get("object").map(unwrap_runtime_expression))
    .flatten()
}

fn query_stage_candidate(
    call: &Value,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
) -> Result<Option<CallableQueryStageCandidate>> {
    let call = unwrap_runtime_expression(call);
    if node_type(call).ok() != Some("CallExpression") || call_has_optional_callee(call) {
        return Ok(None);
    }
    let Some(method) = call_method_name(call) else {
        return Ok(None);
    };
    let Some(receiver) = query_receiver(call) else {
        return Ok(None);
    };
    let Some(arguments) = call.get("arguments").and_then(Value::as_array) else {
        return Ok(None);
    };
    let (start, end) = span(call)?;
    let receiver = source_range(receiver)?;
    match method.as_str() {
        "withIndex" => {
            if !matches!(arguments.len(), 1 | 2) {
                return Ok(None);
            }
            let Some(index) = value_string(&arguments[0]).filter(|index| !index.is_empty()) else {
                return Ok(None);
            };
            let constraints = if let Some(callback) = arguments.get(1) {
                let Some(constraints) = parse_query_index_constraints(callback, bindings) else {
                    return Ok(None);
                };
                constraints
                    .into_iter()
                    .map(|constraint| {
                        Ok(CallableQueryIndexConstraintCandidate {
                            field: constraint.field,
                            operator: constraint.operator,
                            value: value_flow(constraint.value, parameter_starts, bindings)?,
                            value_range: source_range(constraint.value)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
            Ok(Some(CallableQueryStageCandidate::WithIndex {
                start,
                end,
                receiver,
                index,
                index_range: source_range(&arguments[0])?,
                constraints,
            }))
        }
        "order" => {
            if arguments.len() != 1
                || node_type(&arguments[0]).ok() == Some("SpreadElement")
                || count_node_type(&arguments[0], "AwaitExpression") > 0
            {
                return Ok(None);
            }
            Ok(Some(CallableQueryStageCandidate::Order {
                start,
                end,
                receiver,
                direction: value_flow(&arguments[0], parameter_starts, bindings)?,
                direction_range: source_range(&arguments[0])?,
            }))
        }
        _ => Ok(None),
    }
}

struct ParsedQueryIndexConstraint<'a> {
    field: String,
    operator: String,
    value: &'a Value,
}

fn parse_query_index_constraints<'a>(
    callback: &'a Value,
    bindings: &ResolvedBindingIndex,
) -> Option<Vec<ParsedQueryIndexConstraint<'a>>> {
    let callback = unwrap_runtime_expression(callback);
    if !matches!(
        node_type(callback).ok()?,
        "ArrowFunctionExpression" | "FunctionExpression"
    ) {
        return None;
    }
    let [parameter] = callback.get("params")?.as_array()?.as_slice() else {
        return None;
    };
    let parameter = unwrap_runtime_expression(parameter);
    if node_type(parameter).ok()? != "Identifier" {
        return None;
    }
    let parameter_name = identifier_name(parameter).ok()?;
    let (parameter_start, _) = span(parameter).ok()?;
    let body = callback.get("body").map(unwrap_runtime_expression)?;
    let returned = if node_type(body).ok()? == "BlockStatement" {
        let statements = body.get("body")?.as_array()?;
        let returns = statements
            .iter()
            .filter(|statement| node_type(statement).ok() == Some("ReturnStatement"))
            .collect::<Vec<_>>();
        let [returned] = returns.as_slice() else {
            return None;
        };
        returned
            .get("argument")
            .filter(|argument| !argument.is_null())
            .map(unwrap_runtime_expression)?
    } else {
        body
    };
    let mut initializers = BTreeMap::new();
    collect_binding_initializers(callback, true, &mut initializers).ok()?;

    fn resolve<'a>(
        value: &'a Value,
        parameter_name: &str,
        parameter_start: u32,
        bindings: &ResolvedBindingIndex,
        initializers: &BTreeMap<u32, BindingInitializer<'a>>,
        resolving: &mut BTreeSet<u32>,
    ) -> Option<Vec<ParsedQueryIndexConstraint<'a>>> {
        let value = unwrap_runtime_expression(value);
        if node_type(value).ok()? == "Identifier" {
            let (start, end) = span(value).ok()?;
            let binding = bindings.get(&(start, end))?;
            if binding.name == parameter_name && binding.declaration_start == parameter_start {
                return Some(Vec::new());
            }
            let initializer = initializers.get(&binding.declaration_start)?;
            if !initializer.constant || !resolving.insert(binding.declaration_start) {
                return None;
            }
            let constraints = resolve(
                initializer.value,
                parameter_name,
                parameter_start,
                bindings,
                initializers,
                resolving,
            );
            resolving.remove(&binding.declaration_start);
            return constraints;
        }
        if node_type(value).ok()? != "CallExpression" || call_has_optional_callee(value) {
            return None;
        }
        let operator = call_method_name(value)?;
        if !matches!(operator.as_str(), "eq" | "gt" | "gte" | "lt" | "lte") {
            return None;
        }
        let [field, operand] = value.get("arguments")?.as_array()?.as_slice() else {
            return None;
        };
        let field = value_string(field).filter(|field| !field.is_empty())?;
        if count_node_type(operand, "AwaitExpression") > 0 {
            return None;
        }
        let mut constraints = resolve(
            query_receiver(value)?,
            parameter_name,
            parameter_start,
            bindings,
            initializers,
            resolving,
        )?;
        constraints.push(ParsedQueryIndexConstraint {
            field,
            operator,
            value: unwrap_runtime_expression(operand),
        });
        Some(constraints)
    }

    let constraints = resolve(
        returned,
        &parameter_name,
        parameter_start,
        bindings,
        &initializers,
        &mut BTreeSet::new(),
    )?;
    (!constraints.is_empty()).then_some(constraints)
}

fn resolve_query_expression(
    value: &Value,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    initializers: &BTreeMap<u32, BindingInitializer<'_>>,
    resolving: &mut BTreeSet<u32>,
) -> Result<Vec<ResolvedQueryPath>> {
    let value = unwrap_runtime_expression(value);
    if let Some(source) = query_source_candidate(value, parameter_starts, bindings)? {
        return Ok(vec![ResolvedQueryPath {
            source,
            stages: Vec::new(),
            binding_edges: Vec::new(),
            choice_ranges: Vec::new(),
        }]);
    }
    match node_type(value).ok() {
        Some("Identifier") => {
            let (start, end) = span(value)?;
            let Some(binding) = bindings.get(&(start, end)).cloned() else {
                return Ok(Vec::new());
            };
            let Some(initializer) = initializers.get(&binding.declaration_start).cloned() else {
                return Ok(Vec::new());
            };
            if !initializer.constant || !resolving.insert(binding.declaration_start) {
                return Ok(Vec::new());
            }
            let mut paths = resolve_query_expression(
                initializer.value,
                parameter_starts,
                bindings,
                initializers,
                resolving,
            )?;
            resolving.remove(&binding.declaration_start);
            for path in &mut paths {
                path.binding_edges.push(CallableQueryBindingEdgeCandidate {
                    binding: binding.clone(),
                    initializer: initializer.range.clone(),
                    reference: SourceRange { start, end },
                });
            }
            Ok(paths)
        }
        Some("CallExpression") => {
            let Some(stage) = query_stage_candidate(value, parameter_starts, bindings)? else {
                return Ok(Vec::new());
            };
            let Some(receiver) = query_receiver(value) else {
                return Ok(Vec::new());
            };
            let mut paths = resolve_query_expression(
                receiver,
                parameter_starts,
                bindings,
                initializers,
                resolving,
            )?;
            for path in &mut paths {
                path.stages.push(stage.clone());
            }
            Ok(paths)
        }
        Some("ConditionalExpression") => {
            let Some(consequent) = value.get("consequent") else {
                return Ok(Vec::new());
            };
            let Some(alternate) = value.get("alternate") else {
                return Ok(Vec::new());
            };
            let choice = source_range(value)?;
            let mut paths = resolve_query_expression(
                consequent,
                parameter_starts,
                bindings,
                initializers,
                resolving,
            )?;
            paths.extend(resolve_query_expression(
                alternate,
                parameter_starts,
                bindings,
                initializers,
                resolving,
            )?);
            for path in &mut paths {
                path.choice_ranges.push(choice.clone());
            }
            Ok(paths)
        }
        _ => Ok(Vec::new()),
    }
}

#[derive(Clone)]
struct ResolvedQueryBuilderPath {
    value_kind: CallableQueryBuilderKind,
    origin: CallableQueryBuilderOriginCandidate,
    steps: Vec<CallableQueryBuilderStepCandidate>,
}

fn query_builder_stage_candidate(
    value: &Value,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
) -> Result<Option<(CallableQueryStageCandidate, Option<SourceRange>)>> {
    if node_type(value).ok() != Some("CallExpression") || call_has_optional_callee(value) {
        return Ok(None);
    }
    let Some(method) = call_method_name(value) else {
        return Ok(None);
    };
    if method == "order" {
        return Ok(
            query_stage_candidate(value, parameter_starts, bindings)?.map(|stage| (stage, None))
        );
    }
    if method != "withIndex" {
        return Ok(None);
    }
    let Some(receiver) = query_receiver(value) else {
        return Ok(None);
    };
    let Some(arguments) = value.get("arguments").and_then(Value::as_array) else {
        return Ok(None);
    };
    if !matches!(arguments.len(), 1 | 2)
        || arguments.iter().any(|argument| {
            node_type(argument).ok() == Some("SpreadElement")
                || count_node_type(argument, "AwaitExpression") > 0
        })
    {
        return Ok(None);
    }
    let Some(index) = value_string(&arguments[0]).filter(|index| !index.is_empty()) else {
        return Ok(None);
    };
    let range_callback = arguments.get(1).and_then(|callback| {
        let callback = unwrap_runtime_expression(callback);
        matches!(
            node_type(callback).ok(),
            Some("ArrowFunctionExpression" | "FunctionExpression")
        )
        .then(|| source_range(callback).ok())
        .flatten()
    });
    if arguments.len() == 2 && range_callback.is_none() {
        return Ok(None);
    }
    let constraints = arguments
        .get(1)
        .and_then(|callback| parse_query_index_constraints(callback, bindings))
        .unwrap_or_default()
        .into_iter()
        .map(|constraint| {
            Ok(CallableQueryIndexConstraintCandidate {
                field: constraint.field,
                operator: constraint.operator,
                value: value_flow(constraint.value, parameter_starts, bindings)?,
                value_range: source_range(constraint.value)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let (start, end) = span(value)?;
    Ok(Some((
        CallableQueryStageCandidate::WithIndex {
            start,
            end,
            receiver: source_range(receiver)?,
            index,
            index_range: source_range(&arguments[0])?,
            constraints,
        },
        range_callback,
    )))
}

fn index_constraint_step_candidate(
    value: &Value,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
) -> Result<Option<CallableQueryBuilderStepCandidate>> {
    if node_type(value).ok() != Some("CallExpression") || call_has_optional_callee(value) {
        return Ok(None);
    }
    let Some(operator) = call_method_name(value) else {
        return Ok(None);
    };
    if !matches!(operator.as_str(), "eq" | "gt" | "gte" | "lt" | "lte") {
        return Ok(None);
    }
    let Some(receiver) = query_receiver(value) else {
        return Ok(None);
    };
    let Some(arguments) = value.get("arguments").and_then(Value::as_array) else {
        return Ok(None);
    };
    let [field, operand] = arguments.as_slice() else {
        return Ok(None);
    };
    if node_type(field).ok() == Some("SpreadElement")
        || node_type(operand).ok() == Some("SpreadElement")
        || count_node_type(operand, "AwaitExpression") > 0
    {
        return Ok(None);
    }
    let Some(field) = value_string(field).filter(|field| !field.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(CallableQueryBuilderStepCandidate::IndexConstraint {
        site: source_range(value)?,
        receiver: source_range(receiver)?,
        constraint: CallableQueryIndexConstraintCandidate {
            field,
            operator,
            value: value_flow(operand, parameter_starts, bindings)?,
            value_range: source_range(operand)?,
        },
    }))
}

struct QueryBuilderValueDomain<'a> {
    value_kind: CallableQueryBuilderKind,
    parameter_starts: &'a [u32],
    bindings: &'a ResolvedBindingIndex,
}

impl CallableValueDomain for QueryBuilderValueDomain<'_> {
    type Origin = CallableQueryBuilderOriginCandidate;
    type Step = CallableQueryBuilderStepCandidate;

    fn direct_origin(&self, value: &Value) -> Result<Option<Self::Origin>> {
        if self.value_kind != CallableQueryBuilderKind::QueryBuilder {
            return Ok(None);
        }
        Ok(
            query_source_candidate(value, self.parameter_starts, self.bindings)?
                .map(|source| CallableQueryBuilderOriginCandidate::QueryConstruction { source }),
        )
    }

    fn parameter_origin(&self, origin: CallableValueParameterOrigin) -> Self::Origin {
        CallableQueryBuilderOriginCandidate::Parameter {
            index: origin.index,
            name: origin.name,
            declaration: origin.declaration,
            reference: origin.reference,
        }
    }

    fn call_result_origin(&self, origin: CallableValueCallResultOrigin) -> Self::Origin {
        CallableQueryBuilderOriginCandidate::CallResult {
            callsite: origin.callsite,
            callee: origin.callee,
            callee_range: origin.callee_range,
        }
    }

    fn predecessor_steps<'a>(
        &self,
        value: &'a Value,
        _initializers: &BTreeMap<u32, BindingInitializer<'a>>,
    ) -> Result<Option<Vec<(Self::Step, &'a Value)>>> {
        if self.value_kind == CallableQueryBuilderKind::QueryBuilder
            && let Some((stage, range_callback)) =
                query_builder_stage_candidate(value, self.parameter_starts, self.bindings)?
            && let Some(receiver) = query_receiver(value)
        {
            return Ok(Some(vec![(
                CallableQueryBuilderStepCandidate::QueryStage {
                    stage,
                    range_callback,
                },
                receiver,
            )]));
        }
        if self.value_kind == CallableQueryBuilderKind::IndexRangeBuilder
            && let Some(step) =
                index_constraint_step_candidate(value, self.parameter_starts, self.bindings)?
            && let Some(receiver) = query_receiver(value)
        {
            return Ok(Some(vec![(step, receiver)]));
        }
        Ok(None)
    }

    fn alias_step(&self, edge: CallableValueBindingEdge) -> Self::Step {
        CallableQueryBuilderStepCandidate::Alias {
            edge: CallableQueryBindingEdgeCandidate {
                binding: edge.binding,
                initializer: edge.initializer,
                reference: edge.reference,
            },
        }
    }

    fn choice_step(&self, site: SourceRange, branch: usize, _child: SourceRange) -> Self::Step {
        CallableQueryBuilderStepCandidate::Choice { site, branch }
    }
}

fn resolve_query_builder_expression<'a>(
    value: &'a Value,
    value_kind: CallableQueryBuilderKind,
    parameter_names: &[String],
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    initializers: &BTreeMap<u32, BindingInitializer<'a>>,
) -> Result<Vec<ResolvedQueryBuilderPath>> {
    let domain = QueryBuilderValueDomain {
        value_kind,
        parameter_starts,
        bindings,
    };
    Ok(resolve_callable_value_expression(
        value,
        parameter_names,
        parameter_starts,
        bindings,
        initializers,
        &mut BTreeSet::new(),
        &domain,
    )?
    .into_iter()
    .map(|path| ResolvedQueryBuilderPath {
        value_kind,
        origin: path.origin,
        steps: path.steps,
    })
    .collect())
}

struct QueryBuilderFlowCollection<'a> {
    parameter_names: &'a [String],
    parameter_starts: &'a [u32],
    bindings: &'a ResolvedBindingIndex,
    initializers: &'a BTreeMap<u32, BindingInitializer<'a>>,
    binding_references: &'a ResolvedBindingReferenceIndex,
    with_index_site: Option<SourceRange>,
    paths: Vec<CallableQueryBuilderPathCandidate>,
}

impl QueryBuilderFlowCollection<'_> {
    fn resolved(
        &self,
        value: &Value,
        value_kind: CallableQueryBuilderKind,
    ) -> Result<Vec<ResolvedQueryBuilderPath>> {
        resolve_query_builder_expression(
            value,
            value_kind,
            self.parameter_names,
            self.parameter_starts,
            self.bindings,
            self.initializers,
        )
    }

    fn push_paths(
        &mut self,
        resolved: Vec<ResolvedQueryBuilderPath>,
        sink: impl Fn() -> CallableQueryBuilderSinkCandidate,
    ) {
        self.paths.extend(
            resolved
                .into_iter()
                .map(|path| CallableQueryBuilderPathCandidate {
                    value_kind: path.value_kind,
                    origin: path.origin,
                    steps: path.steps,
                    sink: sink(),
                }),
        );
    }

    fn collect(&mut self, value: &Value, root: bool) -> Result<()> {
        match value {
            Value::Object(object) => {
                if !root
                    && matches!(
                        object.get("type").and_then(Value::as_str),
                        Some(
                            "ArrowFunctionExpression"
                                | "FunctionDeclaration"
                                | "FunctionExpression"
                        )
                    )
                {
                    return Ok(());
                }
                if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                    && !call_has_optional_callee(value)
                    && let Some(kind) = consumer_kind(value)
                    && let Some(receiver) = query_receiver(value)
                    && let Some(arguments) = value.get("arguments").and_then(Value::as_array)
                {
                    let (start, end) = span(value)?;
                    let resolved =
                        self.resolved(receiver, CallableQueryBuilderKind::QueryBuilder)?;
                    for path in resolved {
                        let consumer = query_builder_terminal_candidate(
                            kind,
                            start,
                            end,
                            receiver,
                            arguments,
                            &path.steps,
                            self.parameter_starts,
                            self.bindings,
                        )?;
                        self.paths.push(CallableQueryBuilderPathCandidate {
                            value_kind: path.value_kind,
                            origin: path.origin,
                            steps: path.steps,
                            sink: CallableQueryBuilderSinkCandidate::Terminal { consumer },
                        });
                    }
                }
                if object.get("type").and_then(Value::as_str) == Some("ForOfStatement")
                    && object.get("await").and_then(Value::as_bool) == Some(true)
                    && let Some(iterable) = object.get("right").map(unwrap_runtime_expression)
                    && let Some(binding) = stream_binding_candidate(value, self.binding_references)
                {
                    let resolved =
                        self.resolved(iterable, CallableQueryBuilderKind::QueryBuilder)?;
                    let site = source_range(value)?;
                    let iterable = source_range(iterable)?;
                    self.push_paths(resolved, || CallableQueryBuilderSinkCandidate::ForAwait {
                        site: site.clone(),
                        value: iterable.clone(),
                        binding: binding.clone(),
                    });
                }
                if object.get("type").and_then(Value::as_str) == Some("ReturnStatement")
                    && let Some(returned) = object
                        .get("argument")
                        .filter(|argument| !argument.is_null())
                        .map(unwrap_runtime_expression)
                {
                    let site = source_range(value)?;
                    let returned_range = source_range(returned)?;
                    if let Some(with_index_site) = self.with_index_site.clone() {
                        let resolved =
                            self.resolved(returned, CallableQueryBuilderKind::IndexRangeBuilder)?;
                        self.push_paths(resolved, || {
                            CallableQueryBuilderSinkCandidate::WithIndexRangeReturn {
                                site: site.clone(),
                                value: returned_range.clone(),
                                with_index_site: with_index_site.clone(),
                            }
                        });
                    } else {
                        for value_kind in [
                            CallableQueryBuilderKind::QueryBuilder,
                            CallableQueryBuilderKind::IndexRangeBuilder,
                        ] {
                            let resolved = self.resolved(returned, value_kind)?;
                            self.push_paths(resolved, || {
                                CallableQueryBuilderSinkCandidate::Return {
                                    site: site.clone(),
                                    value: returned_range.clone(),
                                }
                            });
                        }
                    }
                }
                if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                    && let Some(callee) = callee_identifier(value)
                    && let Some(callee_value) = value.get("callee").map(unwrap_runtime_expression)
                    && let Some(arguments) = value.get("arguments").and_then(Value::as_array)
                    && !call_has_optional_callee(value)
                {
                    let callsite = source_range(value)?;
                    let callee_range = source_range(callee_value)?;
                    for (argument_index, argument) in arguments.iter().enumerate() {
                        if node_type(argument).ok() == Some("SpreadElement")
                            || count_node_type(argument, "AwaitExpression") > 0
                        {
                            continue;
                        }
                        let argument = unwrap_runtime_expression(argument);
                        let argument_range = source_range(argument)?;
                        for value_kind in [
                            CallableQueryBuilderKind::QueryBuilder,
                            CallableQueryBuilderKind::IndexRangeBuilder,
                        ] {
                            let resolved = self.resolved(argument, value_kind)?;
                            self.push_paths(resolved, || {
                                CallableQueryBuilderSinkCandidate::CallArgument {
                                    callsite: callsite.clone(),
                                    callee: callee.clone(),
                                    callee_range: callee_range.clone(),
                                    argument_index,
                                    value: argument_range.clone(),
                                }
                            });
                        }
                    }
                }
                for child in object.values() {
                    self.collect(child, false)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    self.collect(child, false)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn same_query_builder_origin_candidate(
    left: &CallableQueryBuilderOriginCandidate,
    right: &CallableQueryBuilderOriginCandidate,
) -> bool {
    match (left, right) {
        (
            CallableQueryBuilderOriginCandidate::QueryConstruction { source: left },
            CallableQueryBuilderOriginCandidate::QueryConstruction { source: right },
        ) => left.start == right.start && left.end == right.end,
        (
            CallableQueryBuilderOriginCandidate::Parameter {
                index: left_index,
                declaration: left_declaration,
                ..
            },
            CallableQueryBuilderOriginCandidate::Parameter {
                index: right_index,
                declaration: right_declaration,
                ..
            },
        ) => {
            left_index == right_index
                && left_declaration.start == right_declaration.start
                && left_declaration.end == right_declaration.end
        }
        (
            CallableQueryBuilderOriginCandidate::CallResult { callsite: left, .. },
            CallableQueryBuilderOriginCandidate::CallResult {
                callsite: right, ..
            },
        ) => left.start == right.start && left.end == right.end,
        _ => false,
    }
}

pub(super) fn same_authenticated_query_builder_origin(
    left: &AuthenticatedQueryBuilderOrigin,
    right: &AuthenticatedQueryBuilderOrigin,
) -> bool {
    match (left, right) {
        (
            AuthenticatedQueryBuilderOrigin::QueryConstruction { source: left },
            AuthenticatedQueryBuilderOrigin::QueryConstruction { source: right },
        ) => left.construction == right.construction,
        (
            AuthenticatedQueryBuilderOrigin::Parameter {
                index: left_index,
                declaration: left_declaration,
                ..
            },
            AuthenticatedQueryBuilderOrigin::Parameter {
                index: right_index,
                declaration: right_declaration,
                ..
            },
        ) => left_index == right_index && left_declaration == right_declaration,
        (
            AuthenticatedQueryBuilderOrigin::CallResult { callsite: left, .. },
            AuthenticatedQueryBuilderOrigin::CallResult {
                callsite: right, ..
            },
        ) => left == right,
        _ => false,
    }
}

fn path_reference_accounting(
    paths: &[CallableQueryBuilderPathCandidate],
    binding_references: &ResolvedBindingReferenceIndex,
) -> Vec<CallableQueryBuilderFlowRejectionCandidate> {
    let mut origins = Vec::<CallableQueryBuilderOriginCandidate>::new();
    for path in paths {
        if !origins
            .iter()
            .any(|origin| same_query_builder_origin_candidate(origin, &path.origin))
        {
            origins.push(path.origin.clone());
        }
    }

    let mut rejections = Vec::new();
    for origin in origins {
        let mut declarations = BTreeSet::new();
        let mut recognized = BTreeSet::new();
        for path in paths
            .iter()
            .filter(|path| same_query_builder_origin_candidate(&path.origin, &origin))
        {
            if let CallableQueryBuilderOriginCandidate::Parameter {
                declaration,
                reference,
                ..
            } = &path.origin
            {
                declarations.insert((declaration.start, declaration.end));
                recognized.insert((reference.start, reference.end));
            }
            for step in &path.steps {
                if let CallableQueryBuilderStepCandidate::Alias { edge } = step {
                    declarations
                        .insert((edge.binding.declaration_start, edge.binding.declaration_end));
                    recognized.insert((edge.reference.start, edge.reference.end));
                }
            }
        }
        for declaration in declarations {
            for reference in binding_references
                .get(&declaration)
                .into_iter()
                .flatten()
                .filter(|reference| {
                    reference.write || !recognized.contains(&(reference.start, reference.end))
                })
            {
                let rejection = CallableQueryBuilderFlowRejectionCandidate {
                    origin: origin.clone(),
                    range: SourceRange {
                        start: reference.start,
                        end: reference.end,
                    },
                    reason: if reference.write {
                        "query builder binding is written".to_string()
                    } else {
                        "query builder escapes its authenticated local flow".to_string()
                    },
                };
                if !rejections.contains(&rejection) {
                    rejections.push(rejection);
                }
            }
        }
    }
    rejections.sort_by_key(|rejection| (rejection.range.start, rejection.range.end));
    rejections
}

pub(super) fn collect_callable_query_builder_flow(
    callable: &Value,
    callable_start: u32,
    callable_end: u32,
    parameter_names: &[String],
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    binding_references: &ResolvedBindingReferenceIndex,
    with_index_site: Option<SourceRange>,
) -> Result<CallableQueryBuilderFlowCandidate> {
    let mut initializers = BTreeMap::new();
    collect_binding_initializers(callable, true, &mut initializers)?;
    let mut collection = QueryBuilderFlowCollection {
        parameter_names,
        parameter_starts,
        bindings,
        initializers: &initializers,
        binding_references,
        with_index_site: with_index_site.clone(),
        paths: Vec::new(),
    };
    collection.collect(callable, true)?;
    if let Some(with_index_site) = with_index_site
        && let Some(body) = callable.get("body").map(unwrap_runtime_expression)
        && node_type(body).ok() != Some("BlockStatement")
    {
        let resolved = collection.resolved(body, CallableQueryBuilderKind::IndexRangeBuilder)?;
        let site = SourceRange {
            start: callable_start,
            end: callable_end,
        };
        let value = source_range(body)?;
        collection.push_paths(resolved, || {
            CallableQueryBuilderSinkCandidate::WithIndexRangeReturn {
                site: site.clone(),
                value: value.clone(),
                with_index_site: with_index_site.clone(),
            }
        });
    }
    collection.paths.sort_by_key(|path| {
        let sink = match &path.sink {
            CallableQueryBuilderSinkCandidate::CallArgument { callsite, .. }
            | CallableQueryBuilderSinkCandidate::CallResult { callsite } => callsite,
            CallableQueryBuilderSinkCandidate::Return { site, .. }
            | CallableQueryBuilderSinkCandidate::ForAwait { site, .. }
            | CallableQueryBuilderSinkCandidate::WithIndexRangeReturn { site, .. } => site,
            CallableQueryBuilderSinkCandidate::Terminal { consumer } => {
                return (consumer.start, consumer.end, path.value_kind);
            }
        };
        (sink.start, sink.end, path.value_kind)
    });
    collection.paths.dedup();
    let rejections = path_reference_accounting(&collection.paths, binding_references);
    Ok(CallableQueryBuilderFlowCandidate {
        callable_start,
        callable_end,
        parameter_count: parameter_starts.len(),
        is_async: callable.get("async").and_then(Value::as_bool) == Some(true),
        paths: collection.paths,
        rejections,
    })
}

fn literal_take_limit(value: &Value) -> Option<u32> {
    let value = unwrap_runtime_expression(value);
    (node_type(value).ok()? == "Literal")
        .then(|| value.get("value")?.as_f64())
        .flatten()
        .filter(|value| value.fract() == 0.0 && (1.0..=100_000.0).contains(value))
        .map(|value| value as u32)
}

fn consumer_kind(call: &Value) -> Option<CallableQueryConsumerKind> {
    let arguments = call.get("arguments")?.as_array()?;
    match call_method_name(call)?.as_str() {
        "collect" if arguments.is_empty() => Some(CallableQueryConsumerKind::Collect),
        "first" if arguments.is_empty() => Some(CallableQueryConsumerKind::First),
        "unique" if arguments.is_empty() => Some(CallableQueryConsumerKind::Unique),
        "take"
            if arguments.len() == 1
                && (node_type(unwrap_runtime_expression(&arguments[0])).ok()
                    != Some("Literal")
                    || literal_take_limit(&arguments[0]).is_some()) =>
        {
            Some(CallableQueryConsumerKind::Take)
        }
        "paginate" if arguments.len() == 1 => Some(CallableQueryConsumerKind::Paginate),
        _ => None,
    }
}

fn consumer_candidate(
    kind: CallableQueryConsumerKind,
    start: u32,
    end: u32,
    receiver: &Value,
    arguments: &[Value],
    path: ResolvedQueryPath,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    stream_binding: Option<CallableQueryStreamBindingCandidate>,
) -> Result<CallableQueryConsumerCandidate> {
    let (static_limit, dynamic_limit) = if kind == CallableQueryConsumerKind::Take {
        let [argument] = arguments else {
            return Err(anyhow::anyhow!(
                "authenticated take consumer lost its limit"
            ));
        };
        let argument = unwrap_runtime_expression(argument);
        if node_type(argument).ok() == Some("Literal") {
            (literal_take_limit(argument), false)
        } else {
            (None, true)
        }
    } else {
        (None, false)
    };
    let argument_ranges = arguments
        .iter()
        .map(source_range)
        .collect::<Result<Vec<_>>>()?;
    let arguments = arguments
        .iter()
        .map(|argument| value_flow(argument, parameter_starts, bindings))
        .collect::<Result<Vec<_>>>()?;
    Ok(CallableQueryConsumerCandidate {
        kind,
        start,
        end,
        receiver: source_range(receiver)?,
        stages: path.stages,
        arguments,
        argument_ranges,
        binding_edges: path.binding_edges,
        choice_ranges: path.choice_ranges,
        static_limit,
        dynamic_limit,
        stream_binding,
    })
}

fn query_builder_terminal_candidate(
    kind: CallableQueryConsumerKind,
    start: u32,
    end: u32,
    receiver: &Value,
    arguments: &[Value],
    steps: &[CallableQueryBuilderStepCandidate],
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
) -> Result<CallableQueryConsumerCandidate> {
    let (static_limit, dynamic_limit) = if kind == CallableQueryConsumerKind::Take {
        let [argument] = arguments else {
            return Err(anyhow::anyhow!(
                "authenticated take consumer lost its limit"
            ));
        };
        let argument = unwrap_runtime_expression(argument);
        if node_type(argument).ok() == Some("Literal") {
            (literal_take_limit(argument), false)
        } else {
            (None, true)
        }
    } else {
        (None, false)
    };
    Ok(CallableQueryConsumerCandidate {
        kind,
        start,
        end,
        receiver: source_range(receiver)?,
        stages: steps
            .iter()
            .filter_map(|step| match step {
                CallableQueryBuilderStepCandidate::QueryStage { stage, .. } => Some(stage.clone()),
                _ => None,
            })
            .collect(),
        arguments: arguments
            .iter()
            .map(|argument| value_flow(argument, parameter_starts, bindings))
            .collect::<Result<Vec<_>>>()?,
        argument_ranges: arguments
            .iter()
            .map(source_range)
            .collect::<Result<Vec<_>>>()?,
        binding_edges: steps
            .iter()
            .filter_map(|step| match step {
                CallableQueryBuilderStepCandidate::Alias { edge } => Some(edge.clone()),
                _ => None,
            })
            .collect(),
        choice_ranges: steps
            .iter()
            .filter_map(|step| match step {
                CallableQueryBuilderStepCandidate::Choice { site, .. } => Some(site.clone()),
                _ => None,
            })
            .collect(),
        static_limit,
        dynamic_limit,
        stream_binding: None,
    })
}

fn stream_binding_candidate(
    statement: &Value,
    binding_references: &ResolvedBindingReferenceIndex,
) -> Option<CallableQueryStreamBindingCandidate> {
    let left = statement.get("left").map(unwrap_runtime_expression)?;
    if node_type(left).ok()? != "VariableDeclaration"
        || !matches!(left.get("kind")?.as_str()?, "const" | "let")
    {
        return None;
    }
    let [declaration] = left.get("declarations")?.as_array()?.as_slice() else {
        return None;
    };
    if declaration
        .get("init")
        .is_some_and(|initializer| !initializer.is_null())
    {
        return None;
    }
    let binding = declaration.get("id").map(unwrap_runtime_expression)?;
    if node_type(binding).ok()? != "Identifier" {
        return None;
    }
    let name = identifier_name(binding).ok()?;
    let (declaration_start, declaration_end) = span(binding).ok()?;
    Some(CallableQueryStreamBindingCandidate {
        binding: ResolvedBinding {
            name,
            declaration_start,
            declaration_end,
        },
        references: binding_references
            .get(&(declaration_start, declaration_end))
            .cloned()
            .unwrap_or_default(),
    })
}

struct QueryConsumerCollection<'a> {
    parameter_starts: &'a [u32],
    bindings: &'a ResolvedBindingIndex,
    initializers: &'a BTreeMap<u32, BindingInitializer<'a>>,
    binding_references: &'a ResolvedBindingReferenceIndex,
    consumers: BTreeMap<(u32, u32), Vec<CallableQueryConsumerCandidate>>,
    forwards: BTreeMap<(u32, u32), Vec<CallableQueryForwardCandidate>>,
}

impl QueryConsumerCollection<'_> {
    fn collect(&mut self, value: &Value, root: bool) -> Result<()> {
        match value {
            Value::Object(object) => {
                if !root
                    && matches!(
                        object.get("type").and_then(Value::as_str),
                        Some(
                            "ArrowFunctionExpression"
                                | "FunctionDeclaration"
                                | "FunctionExpression"
                        )
                    )
                {
                    return Ok(());
                }
                if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                    && !call_has_optional_callee(value)
                    && let Some(kind) = consumer_kind(value)
                    && let Some(receiver) = query_receiver(value)
                    && let Some(arguments) = value.get("arguments").and_then(Value::as_array)
                {
                    let (start, end) = span(value)?;
                    let paths = resolve_query_expression(
                        receiver,
                        self.parameter_starts,
                        self.bindings,
                        self.initializers,
                        &mut BTreeSet::new(),
                    )?;
                    for path in paths {
                        let source = (path.source.start, path.source.end);
                        let consumer = consumer_candidate(
                            kind,
                            start,
                            end,
                            receiver,
                            arguments,
                            path,
                            self.parameter_starts,
                            self.bindings,
                            None,
                        )?;
                        self.consumers.entry(source).or_default().push(consumer);
                    }
                }
                if object.get("type").and_then(Value::as_str) == Some("ForOfStatement")
                    && object.get("await").and_then(Value::as_bool) == Some(true)
                    && let Some(iterable) = object.get("right").map(unwrap_runtime_expression)
                    && let Some(stream_binding) =
                        stream_binding_candidate(value, self.binding_references)
                {
                    let (start, end) = span(value)?;
                    let paths = resolve_query_expression(
                        iterable,
                        self.parameter_starts,
                        self.bindings,
                        self.initializers,
                        &mut BTreeSet::new(),
                    )?;
                    for path in paths {
                        let source = (path.source.start, path.source.end);
                        let consumer = consumer_candidate(
                            CallableQueryConsumerKind::Stream,
                            start,
                            end,
                            iterable,
                            &[],
                            path,
                            self.parameter_starts,
                            self.bindings,
                            Some(stream_binding.clone()),
                        )?;
                        self.consumers.entry(source).or_default().push(consumer);
                    }
                }
                if object.get("type").and_then(Value::as_str) == Some("ReturnStatement")
                    && let Some(returned) = object
                        .get("argument")
                        .filter(|argument| !argument.is_null())
                        .map(unwrap_runtime_expression)
                {
                    let (start, end) = span(value)?;
                    let paths = resolve_query_expression(
                        returned,
                        self.parameter_starts,
                        self.bindings,
                        self.initializers,
                        &mut BTreeSet::new(),
                    )?;
                    for path in paths {
                        let source = (path.source.start, path.source.end);
                        self.forwards.entry(source).or_default().push(
                            CallableQueryForwardCandidate::Return {
                                start,
                                end,
                                value: source_range(returned)?,
                                stages: path.stages,
                                binding_edges: path.binding_edges,
                                choice_ranges: path.choice_ranges,
                            },
                        );
                    }
                }
                if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                    && let Some(callee) = callee_identifier(value)
                    && let Some(callee_expression) =
                        value.get("callee").map(unwrap_runtime_expression)
                    && let Some(arguments) = value.get("arguments").and_then(Value::as_array)
                {
                    let (start, end) = span(value)?;
                    let (callee_start, callee_end) = span(callee_expression)?;
                    for (argument_index, argument) in arguments.iter().enumerate() {
                        if node_type(argument).ok() == Some("SpreadElement") {
                            continue;
                        }
                        let argument = unwrap_runtime_expression(argument);
                        let paths = resolve_query_expression(
                            argument,
                            self.parameter_starts,
                            self.bindings,
                            self.initializers,
                            &mut BTreeSet::new(),
                        )?;
                        for path in paths {
                            let source = (path.source.start, path.source.end);
                            self.forwards.entry(source).or_default().push(
                                CallableQueryForwardCandidate::CallArgument {
                                    start,
                                    end,
                                    callee: callee.clone(),
                                    callee_start,
                                    callee_end,
                                    argument_index,
                                    value: source_range(argument)?,
                                    stages: path.stages,
                                    binding_edges: path.binding_edges,
                                    choice_ranges: path.choice_ranges,
                                },
                            );
                        }
                    }
                }
                for child in object.values() {
                    self.collect(child, false)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    self.collect(child, false)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn collect_query_sources(
    value: &Value,
    root: bool,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    output: &mut BTreeMap<(u32, u32), CallableQuerySourceCandidate>,
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
                && let Some(source) = query_source_candidate(value, parameter_starts, bindings)?
            {
                let key = (source.start, source.end);
                ensure!(
                    output.insert(key, source).is_none(),
                    "query-value source was collected twice"
                );
            }
            for child in object.values() {
                collect_query_sources(child, false, parameter_starts, bindings, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_query_sources(child, false, parameter_starts, bindings, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn collect_callable_query_value_plans(
    callable: &Value,
    callable_start: u32,
    callable_end: u32,
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    binding_references: &ResolvedBindingReferenceIndex,
) -> Result<BTreeMap<(u32, u32), CallableQueryValuePlanCandidate>> {
    let mut initializers = BTreeMap::new();
    collect_binding_initializers(callable, true, &mut initializers)?;
    let mut sources = BTreeMap::new();
    collect_query_sources(callable, true, parameter_starts, bindings, &mut sources)?;
    let mut collection = QueryConsumerCollection {
        parameter_starts,
        bindings,
        initializers: &initializers,
        binding_references,
        consumers: BTreeMap::new(),
        forwards: BTreeMap::new(),
    };
    collection.collect(callable, true)?;

    let mut output = BTreeMap::new();
    for (identity, source) in sources {
        let mut consumers = collection.consumers.remove(&identity).unwrap_or_default();
        consumers.sort_by_key(|consumer| (consumer.start, consumer.end, consumer.kind.terminal()));
        consumers.dedup();
        let mut forwards = collection.forwards.remove(&identity).unwrap_or_default();
        forwards.sort_by_key(|forward| match forward {
            CallableQueryForwardCandidate::Return { start, end, .. }
            | CallableQueryForwardCandidate::CallArgument { start, end, .. } => (*start, *end),
        });
        forwards.dedup();
        let binding_starts = consumers
            .iter()
            .flat_map(|consumer| &consumer.binding_edges)
            .chain(
                forwards
                    .iter()
                    .flat_map(CallableQueryForwardCandidate::binding_edges),
            )
            .map(|edge| edge.binding.declaration_start)
            .collect::<BTreeSet<_>>();
        let recognized_references = consumers
            .iter()
            .flat_map(|consumer| &consumer.binding_edges)
            .chain(
                forwards
                    .iter()
                    .flat_map(CallableQueryForwardCandidate::binding_edges),
            )
            .map(|edge| (edge.reference.start, edge.reference.end))
            .collect::<BTreeSet<_>>();
        let mut rejections = bindings
            .iter()
            .filter(|(_, binding)| binding_starts.contains(&binding.declaration_start))
            .filter(|(range, _)| !recognized_references.contains(range))
            .map(|(&(start, end), _)| CallableQueryValueRejectionCandidate {
                range: SourceRange { start, end },
                reason: "query value escapes its authenticated binding flow".to_string(),
            })
            .collect::<Vec<_>>();
        if consumers.is_empty() && forwards.is_empty() {
            rejections.push(CallableQueryValueRejectionCandidate {
                range: SourceRange {
                    start: source.start,
                    end: source.end,
                },
                reason: "query value has no authenticated terminal or stream consumer".to_string(),
            });
        }
        rejections.sort_by_key(|rejection| (rejection.range.start, rejection.range.end));
        rejections.dedup();
        let locally_closed = rejections.is_empty();
        let closed = locally_closed && !consumers.is_empty() && forwards.is_empty();
        let plan = CallableQueryValuePlanCandidate {
            callable_start,
            callable_end,
            source,
            consumers,
            forwards,
            locally_closed,
            closed,
            rejections,
        };
        ensure!(
            output.insert(identity, plan).is_none(),
            "query-value plan has duplicate source identities"
        );
    }
    Ok(output)
}

fn anchor_range(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    range: &SourceRange,
) -> Result<SourceAnchor> {
    source_anchor(modules, module, range.start, range.end)
}

fn anchor_contains(container: &SourceAnchor, value: &SourceAnchor) -> bool {
    container.module == value.module
        && container.source_sha256 == value.source_sha256
        && container.start <= value.start
        && value.end <= container.end
}

fn authenticate_binding_edge(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    edge: &CallableQueryBindingEdgeCandidate,
) -> Result<AuthenticatedQueryBindingEdge> {
    Ok(AuthenticatedQueryBindingEdge {
        name: edge.binding.name.clone(),
        binding: source_anchor(
            modules,
            module,
            edge.binding.declaration_start,
            edge.binding.declaration_end,
        )?,
        initializer: anchor_range(modules, module, &edge.initializer)?,
        reference: anchor_range(modules, module, &edge.reference)?,
    })
}

fn authenticate_stage(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    stage: &CallableQueryStageCandidate,
) -> Result<AuthenticatedQueryStage> {
    let authenticated = match stage {
        CallableQueryStageCandidate::WithIndex {
            start,
            end,
            receiver,
            index,
            index_range,
            constraints,
        } => AuthenticatedQueryStage::WithIndex {
            site: source_anchor(modules, module, *start, *end)?,
            receiver: anchor_range(modules, module, receiver)?,
            index: index.clone(),
            index_provenance: anchor_range(modules, module, index_range)?,
            constraints: constraints
                .iter()
                .map(|constraint| {
                    Ok(AuthenticatedQueryIndexConstraint {
                        field: constraint.field.clone(),
                        operator: constraint.operator.clone(),
                        value: AuthenticatedQueryValueOperand {
                            value: constraint.value.clone(),
                            provenance: anchor_range(modules, module, &constraint.value_range)?,
                        },
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        },
        CallableQueryStageCandidate::Order {
            start,
            end,
            receiver,
            direction,
            direction_range,
        } => AuthenticatedQueryStage::Order {
            site: source_anchor(modules, module, *start, *end)?,
            receiver: anchor_range(modules, module, receiver)?,
            direction: AuthenticatedQueryValueOperand {
                value: direction.clone(),
                provenance: anchor_range(modules, module, direction_range)?,
            },
        },
    };
    let (site, receiver, operands) = match &authenticated {
        AuthenticatedQueryStage::WithIndex {
            site,
            receiver,
            index_provenance,
            constraints,
            ..
        } => (
            site,
            receiver,
            std::iter::once(index_provenance)
                .chain(
                    constraints
                        .iter()
                        .map(|constraint| &constraint.value.provenance),
                )
                .collect::<Vec<_>>(),
        ),
        AuthenticatedQueryStage::Order {
            site,
            receiver,
            direction,
        } => (site, receiver, vec![&direction.provenance]),
    };
    ensure!(
        anchor_contains(site, receiver)
            && operands
                .into_iter()
                .all(|operand| anchor_contains(site, operand)),
        "authenticated query stage operands must remain inside the stage call"
    );
    Ok(authenticated)
}

fn authenticate_consumer(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    consumer: &CallableQueryConsumerCandidate,
) -> Result<AuthenticatedQueryConsumer> {
    ensure!(
        consumer.arguments.len() == consumer.argument_ranges.len(),
        "query consumer argument provenance is incomplete"
    );
    let site = source_anchor(modules, module, consumer.start, consumer.end)?;
    let receiver = anchor_range(modules, module, &consumer.receiver)?;
    let arguments = consumer
        .arguments
        .iter()
        .zip(&consumer.argument_ranges)
        .map(|(value, range)| {
            Ok(AuthenticatedQueryValueOperand {
                value: value.clone(),
                provenance: anchor_range(modules, module, range)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let stream_binding = consumer
        .stream_binding
        .as_ref()
        .map(|stream| {
            let binding = source_anchor(
                modules,
                module,
                stream.binding.declaration_start,
                stream.binding.declaration_end,
            )?;
            let references = stream
                .references
                .iter()
                .map(|reference| {
                    Ok(AuthenticatedQueryStreamReference {
                        provenance: source_anchor(modules, module, reference.start, reference.end)?,
                        read: reference.read,
                        write: reference.write,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                binding.slice_sha256 == hash_bytes(stream.binding.name.as_bytes())
                    && references.iter().all(|reference| {
                        reference.provenance.slice_sha256
                            == hash_bytes(stream.binding.name.as_bytes())
                            && anchor_contains(&site, &reference.provenance)
                    }),
                "query stream binding provenance is not exact"
            );
            Ok(AuthenticatedQueryStreamBinding {
                name: stream.binding.name.clone(),
                binding,
                references,
            })
        })
        .transpose()?;
    ensure!(
        anchor_contains(&site, &receiver)
            && arguments
                .iter()
                .all(|argument| anchor_contains(&site, &argument.provenance))
            && stream_binding
                .as_ref()
                .is_none_or(|stream| anchor_contains(&site, &stream.binding)),
        "authenticated query consumer operands must remain inside its source site"
    );
    ensure!(
        match consumer.kind {
            CallableQueryConsumerKind::Take => {
                consumer.arguments.len() == 1
                    && (consumer.static_limit.is_some() ^ consumer.dynamic_limit)
                    && consumer.stream_binding.is_none()
            }
            CallableQueryConsumerKind::Stream => {
                consumer.arguments.is_empty()
                    && consumer.static_limit.is_none()
                    && !consumer.dynamic_limit
                    && consumer.stream_binding.is_some()
            }
            _ => {
                consumer.static_limit.is_none()
                    && !consumer.dynamic_limit
                    && consumer.stream_binding.is_none()
            }
        },
        "query consumer terminal metadata is inconsistent"
    );
    Ok(AuthenticatedQueryConsumer {
        kind: consumer.kind,
        site,
        receiver,
        stages: consumer
            .stages
            .iter()
            .map(|stage| authenticate_stage(modules, module, stage))
            .collect::<Result<Vec<_>>>()?,
        arguments,
        binding_edges: consumer
            .binding_edges
            .iter()
            .map(|edge| authenticate_binding_edge(modules, module, edge))
            .collect::<Result<Vec<_>>>()?,
        choices: consumer
            .choice_ranges
            .iter()
            .map(|range| anchor_range(modules, module, range))
            .collect::<Result<Vec<_>>>()?,
        static_limit: consumer.static_limit,
        dynamic_limit: consumer.dynamic_limit,
        stream_binding,
    })
}

fn authenticate_forward(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    forward: &CallableQueryForwardCandidate,
) -> Result<AuthenticatedQueryForward> {
    let authenticate_edges = |edges: &[CallableQueryBindingEdgeCandidate]| {
        edges
            .iter()
            .map(|edge| authenticate_binding_edge(modules, module, edge))
            .collect::<Result<Vec<_>>>()
    };
    let authenticate_stages = |stages: &[CallableQueryStageCandidate]| {
        stages
            .iter()
            .map(|stage| authenticate_stage(modules, module, stage))
            .collect::<Result<Vec<_>>>()
    };
    let authenticate_choices = |choices: &[SourceRange]| {
        choices
            .iter()
            .map(|choice| anchor_range(modules, module, choice))
            .collect::<Result<Vec<_>>>()
    };
    Ok(match forward {
        CallableQueryForwardCandidate::Return {
            start,
            end,
            value,
            stages,
            binding_edges,
            choice_ranges,
        } => AuthenticatedQueryForward::Return {
            site: source_anchor(modules, module, *start, *end)?,
            value: anchor_range(modules, module, value)?,
            stages: authenticate_stages(stages)?,
            binding_edges: authenticate_edges(binding_edges)?,
            choices: authenticate_choices(choice_ranges)?,
        },
        CallableQueryForwardCandidate::CallArgument {
            start,
            end,
            callee,
            callee_start,
            callee_end,
            argument_index,
            value,
            stages,
            binding_edges,
            choice_ranges,
        } => AuthenticatedQueryForward::CallArgument {
            site: source_anchor(modules, module, *start, *end)?,
            callee: callee.clone(),
            callee_provenance: source_anchor(modules, module, *callee_start, *callee_end)?,
            argument_index: *argument_index,
            value: anchor_range(modules, module, value)?,
            stages: authenticate_stages(stages)?,
            binding_edges: authenticate_edges(binding_edges)?,
            choices: authenticate_choices(choice_ranges)?,
        },
    })
}

fn authenticate_query_source(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    callable_source: &SourceAnchor,
    candidate: &CallableQuerySourceCandidate,
) -> Result<AuthenticatedQuerySource> {
    let construction = source_anchor(modules, module, candidate.start, candidate.end)?;
    let callee = anchor_range(modules, module, &candidate.callee)?;
    let capability_reference = anchor_range(modules, module, &candidate.capability_reference)?;
    let capability_binding = source_anchor(
        modules,
        module,
        candidate.capability_binding.declaration_start,
        candidate.capability_binding.declaration_end,
    )?;
    let table = AuthenticatedQueryValueOperand {
        value: candidate.table.clone(),
        provenance: anchor_range(modules, module, &candidate.table_range)?,
    };
    ensure!(
        anchor_contains(callable_source, &construction)
            && anchor_contains(&construction, &callee)
            && anchor_contains(&callee, &capability_reference)
            && anchor_contains(&construction, &table.provenance),
        "query-value source provenance is not nested under its authenticated callable"
    );
    Ok(AuthenticatedQuerySource {
        construction,
        callee,
        capability_kind: candidate.capability_kind.clone(),
        capability: candidate.capability.clone(),
        capability_reference,
        capability_binding,
        capability_name: candidate.capability_binding.name.clone(),
        table,
    })
}

fn authenticate_query_value_plan(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    candidate: &CallableQueryValuePlanCandidate,
) -> Result<AuthenticatedCallableQueryValuePlan> {
    let callable = callable_key(module, candidate.callable_start, candidate.callable_end);
    let callable_source = source_anchor(
        modules,
        module,
        candidate.callable_start,
        candidate.callable_end,
    )?;
    let source = authenticate_query_source(modules, module, &callable_source, &candidate.source)?;
    ensure!(
        candidate.closed
            == (candidate.locally_closed
                && !candidate.consumers.is_empty()
                && candidate.forwards.is_empty())
            && candidate.locally_closed == candidate.rejections.is_empty(),
        "query-value closure flags disagree with their proof obligations"
    );
    let consumers = candidate
        .consumers
        .iter()
        .map(|consumer| authenticate_consumer(modules, module, consumer))
        .collect::<Result<Vec<_>>>()?;
    let forwards = candidate
        .forwards
        .iter()
        .map(|forward| authenticate_forward(modules, module, forward))
        .collect::<Result<Vec<_>>>()?;
    let rejections = candidate
        .rejections
        .iter()
        .map(|rejection| {
            Ok(AuthenticatedQueryValueRejection {
                provenance: anchor_range(modules, module, &rejection.range)?,
                reason: rejection.reason.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let authorization_material = serde_json::to_vec(&(
        "authenticated-query-value-plan",
        &callable,
        &callable_source,
        candidate,
    ))?;
    Ok(AuthenticatedCallableQueryValuePlan {
        authorization_id: format!("query_{}", &hash_bytes(&authorization_material)[..16]),
        callable,
        callable_source,
        source,
        consumers,
        forwards,
        locally_closed: candidate.locally_closed,
        closed: candidate.closed,
        rejections,
    })
}

fn authenticate_query_builder_origin(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    callable_source: &SourceAnchor,
    origin: &CallableQueryBuilderOriginCandidate,
) -> Result<AuthenticatedQueryBuilderOrigin> {
    let authenticated = match origin {
        CallableQueryBuilderOriginCandidate::QueryConstruction { source } => {
            AuthenticatedQueryBuilderOrigin::QueryConstruction {
                source: authenticate_query_source(modules, module, callable_source, source)?,
            }
        }
        CallableQueryBuilderOriginCandidate::Parameter {
            index,
            name,
            declaration,
            reference,
        } => AuthenticatedQueryBuilderOrigin::Parameter {
            index: *index,
            name: name.clone(),
            declaration: anchor_range(modules, module, declaration)?,
            reference: anchor_range(modules, module, reference)?,
        },
        CallableQueryBuilderOriginCandidate::CallResult {
            callsite,
            callee,
            callee_range,
        } => AuthenticatedQueryBuilderOrigin::CallResult {
            callsite: anchor_range(modules, module, callsite)?,
            callee: callee.clone(),
            callee_provenance: anchor_range(modules, module, callee_range)?,
        },
    };
    match &authenticated {
        AuthenticatedQueryBuilderOrigin::QueryConstruction { source } => ensure!(
            anchor_contains(callable_source, &source.construction),
            "query-builder construction escaped its authenticated callable"
        ),
        AuthenticatedQueryBuilderOrigin::Parameter {
            name,
            declaration,
            reference,
            ..
        } => ensure!(
            !name.is_empty()
                && declaration.slice_sha256 == hash_bytes(name.as_bytes())
                && reference.slice_sha256 == hash_bytes(name.as_bytes())
                && anchor_contains(callable_source, declaration)
                && anchor_contains(callable_source, reference),
            "query-builder parameter provenance is not exact"
        ),
        AuthenticatedQueryBuilderOrigin::CallResult {
            callsite,
            callee,
            callee_provenance,
        } => ensure!(
            !callee.is_empty()
                && callee_provenance.slice_sha256 == hash_bytes(callee.as_bytes())
                && anchor_contains(callable_source, callsite)
                && anchor_contains(callsite, callee_provenance),
            "query-builder call-result provenance is not exact"
        ),
    }
    Ok(authenticated)
}

fn authenticate_query_builder_step(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    step: &CallableQueryBuilderStepCandidate,
) -> Result<AuthenticatedQueryBuilderStep> {
    Ok(match step {
        CallableQueryBuilderStepCandidate::Alias { edge } => AuthenticatedQueryBuilderStep::Alias {
            edge: authenticate_binding_edge(modules, module, edge)?,
        },
        CallableQueryBuilderStepCandidate::QueryStage {
            stage,
            range_callback,
        } => {
            let stage = authenticate_stage(modules, module, stage)?;
            let range_callback = range_callback
                .as_ref()
                .map(|range| anchor_range(modules, module, range))
                .transpose()?;
            let stage_site = match &stage {
                AuthenticatedQueryStage::WithIndex { site, .. }
                | AuthenticatedQueryStage::Order { site, .. } => site,
            };
            ensure!(
                range_callback
                    .as_ref()
                    .is_none_or(|callback| anchor_contains(stage_site, callback)),
                "withIndex range callback escaped its authenticated stage"
            );
            AuthenticatedQueryBuilderStep::QueryStage {
                stage,
                range_callback,
            }
        }
        CallableQueryBuilderStepCandidate::IndexConstraint {
            site,
            receiver,
            constraint,
        } => {
            let site = anchor_range(modules, module, site)?;
            let receiver = anchor_range(modules, module, receiver)?;
            let constraint = AuthenticatedQueryIndexConstraint {
                field: constraint.field.clone(),
                operator: constraint.operator.clone(),
                value: AuthenticatedQueryValueOperand {
                    value: constraint.value.clone(),
                    provenance: anchor_range(modules, module, &constraint.value_range)?,
                },
            };
            ensure!(
                !constraint.field.is_empty()
                    && matches!(
                        constraint.operator.as_str(),
                        "eq" | "gt" | "gte" | "lt" | "lte"
                    )
                    && anchor_contains(&site, &receiver)
                    && anchor_contains(&site, &constraint.value.provenance),
                "index-range builder constraint provenance is not exact"
            );
            AuthenticatedQueryBuilderStep::IndexConstraint {
                site,
                receiver,
                constraint,
            }
        }
        CallableQueryBuilderStepCandidate::Choice { site, branch } => {
            ensure!(*branch < 2, "query-builder choice branch is not finite");
            AuthenticatedQueryBuilderStep::Choice {
                site: anchor_range(modules, module, site)?,
                branch: *branch,
            }
        }
    })
}

fn authenticate_query_stream_binding(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    site: &SourceAnchor,
    stream: &CallableQueryStreamBindingCandidate,
) -> Result<AuthenticatedQueryStreamBinding> {
    let binding = source_anchor(
        modules,
        module,
        stream.binding.declaration_start,
        stream.binding.declaration_end,
    )?;
    let references = stream
        .references
        .iter()
        .map(|reference| {
            Ok(AuthenticatedQueryStreamReference {
                provenance: source_anchor(modules, module, reference.start, reference.end)?,
                read: reference.read,
                write: reference.write,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        binding.slice_sha256 == hash_bytes(stream.binding.name.as_bytes())
            && anchor_contains(site, &binding)
            && references.iter().all(|reference| {
                reference.provenance.slice_sha256 == hash_bytes(stream.binding.name.as_bytes())
                    && anchor_contains(site, &reference.provenance)
                    && !reference.write
            }),
        "query-builder stream binding provenance is not exact"
    );
    Ok(AuthenticatedQueryStreamBinding {
        name: stream.binding.name.clone(),
        binding,
        references,
    })
}

fn authenticate_query_builder_sink(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    callable_source: &SourceAnchor,
    sink: &CallableQueryBuilderSinkCandidate,
) -> Result<AuthenticatedQueryBuilderSink> {
    let authenticated = match sink {
        CallableQueryBuilderSinkCandidate::CallArgument {
            callsite,
            callee,
            callee_range,
            argument_index,
            value,
        } => AuthenticatedQueryBuilderSink::CallArgument {
            callsite: anchor_range(modules, module, callsite)?,
            callee: callee.clone(),
            callee_provenance: anchor_range(modules, module, callee_range)?,
            argument_index: *argument_index,
            value: anchor_range(modules, module, value)?,
        },
        CallableQueryBuilderSinkCandidate::CallResult { callsite } => {
            AuthenticatedQueryBuilderSink::CallResult {
                callsite: anchor_range(modules, module, callsite)?,
            }
        }
        CallableQueryBuilderSinkCandidate::Return { site, value } => {
            AuthenticatedQueryBuilderSink::Return {
                site: anchor_range(modules, module, site)?,
                value: anchor_range(modules, module, value)?,
            }
        }
        CallableQueryBuilderSinkCandidate::Terminal { consumer } => {
            AuthenticatedQueryBuilderSink::Terminal {
                consumer: authenticate_consumer(modules, module, consumer)?,
            }
        }
        CallableQueryBuilderSinkCandidate::ForAwait {
            site,
            value,
            binding,
        } => {
            let site = anchor_range(modules, module, site)?;
            let value = anchor_range(modules, module, value)?;
            let binding = authenticate_query_stream_binding(modules, module, &site, binding)?;
            AuthenticatedQueryBuilderSink::ForAwait {
                site,
                value,
                binding,
            }
        }
        CallableQueryBuilderSinkCandidate::WithIndexRangeReturn {
            site,
            value,
            with_index_site,
        } => AuthenticatedQueryBuilderSink::WithIndexRangeReturn {
            site: anchor_range(modules, module, site)?,
            value: anchor_range(modules, module, value)?,
            with_index_site: anchor_range(modules, module, with_index_site)?,
        },
    };
    match &authenticated {
        AuthenticatedQueryBuilderSink::CallArgument {
            callsite,
            callee,
            callee_provenance,
            value,
            ..
        } => ensure!(
            !callee.is_empty()
                && callee_provenance.slice_sha256 == hash_bytes(callee.as_bytes())
                && anchor_contains(callable_source, callsite)
                && anchor_contains(callsite, callee_provenance)
                && anchor_contains(callsite, value),
            "query-builder call-argument provenance is not exact"
        ),
        AuthenticatedQueryBuilderSink::CallResult { callsite } => ensure!(
            anchor_contains(callable_source, callsite),
            "query-builder call-result sink escaped its callable"
        ),
        AuthenticatedQueryBuilderSink::Return { site, value } => ensure!(
            anchor_contains(callable_source, site) && anchor_contains(site, value),
            "query-builder return provenance is not exact"
        ),
        AuthenticatedQueryBuilderSink::Terminal { consumer } => ensure!(
            anchor_contains(callable_source, &consumer.site),
            "query-builder terminal escaped its callable"
        ),
        AuthenticatedQueryBuilderSink::ForAwait { site, value, .. } => ensure!(
            anchor_contains(callable_source, site) && anchor_contains(site, value),
            "query-builder for-await provenance is not exact"
        ),
        AuthenticatedQueryBuilderSink::WithIndexRangeReturn {
            site,
            value,
            with_index_site,
        } => ensure!(
            anchor_contains(callable_source, site)
                && anchor_contains(site, value)
                && anchor_contains(with_index_site, callable_source),
            "withIndex range-return provenance is not exact"
        ),
    }
    Ok(authenticated)
}

fn authenticate_query_builder_flow(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    candidate: &CallableQueryBuilderFlowCandidate,
) -> Result<AuthenticatedCallableQueryBuilderFlow> {
    let callable = callable_key(module, candidate.callable_start, candidate.callable_end);
    let callable_source = source_anchor(
        modules,
        module,
        candidate.callable_start,
        candidate.callable_end,
    )?;
    let paths = candidate
        .paths
        .iter()
        .map(|path| {
            let origin =
                authenticate_query_builder_origin(modules, module, &callable_source, &path.origin)?;
            let steps = path
                .steps
                .iter()
                .map(|step| authenticate_query_builder_step(modules, module, step))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                steps.iter().all(|step| match (path.value_kind, step) {
                    (
                        CallableQueryBuilderKind::QueryBuilder,
                        AuthenticatedQueryBuilderStep::IndexConstraint { .. },
                    )
                    | (
                        CallableQueryBuilderKind::IndexRangeBuilder,
                        AuthenticatedQueryBuilderStep::QueryStage { .. },
                    ) => false,
                    _ => true,
                }),
                "query-builder path changes its opaque value kind"
            );
            let sink =
                authenticate_query_builder_sink(modules, module, &callable_source, &path.sink)?;
            ensure!(
                matches!(
                    (path.value_kind, &sink),
                    (
                        CallableQueryBuilderKind::QueryBuilder,
                        AuthenticatedQueryBuilderSink::Terminal { .. }
                            | AuthenticatedQueryBuilderSink::ForAwait { .. }
                    ) | (
                        CallableQueryBuilderKind::IndexRangeBuilder,
                        AuthenticatedQueryBuilderSink::WithIndexRangeReturn { .. }
                    ) | (
                        _,
                        AuthenticatedQueryBuilderSink::CallArgument { .. }
                            | AuthenticatedQueryBuilderSink::CallResult { .. }
                            | AuthenticatedQueryBuilderSink::Return { .. }
                    )
                ),
                "query-builder path reaches a sink for a different value kind"
            );
            Ok(AuthenticatedQueryBuilderPath {
                value_kind: path.value_kind,
                origin,
                steps,
                sink,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        paths.iter().all(|path| match &path.origin {
            AuthenticatedQueryBuilderOrigin::Parameter { index, .. } => {
                *index < candidate.parameter_count
            }
            _ => true,
        }),
        "query-builder parameter port exceeds its callable signature"
    );
    ensure!(
        paths.len() <= MAX_CALLABLE_VALUE_PATH_VARIANTS * 16,
        "query-builder callable summary exceeded its bounded path budget"
    );
    let rejections = candidate
        .rejections
        .iter()
        .map(|rejection| {
            let origin = authenticate_query_builder_origin(
                modules,
                module,
                &callable_source,
                &rejection.origin,
            )?;
            ensure!(
                paths
                    .iter()
                    .any(|path| { same_authenticated_query_builder_origin(&path.origin, &origin) }),
                "query-builder rejection does not identify a collected root"
            );
            Ok(AuthenticatedQueryBuilderFlowRejection {
                origin,
                provenance: anchor_range(modules, module, &rejection.range)?,
                reason: rejection.reason.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let authorization_material = serde_json::to_vec(&(
        "authenticated-query-builder-flow",
        &callable,
        &callable_source,
        candidate,
    ))?;
    Ok(AuthenticatedCallableQueryBuilderFlow {
        authorization_id: format!("query_flow_{}", &hash_bytes(&authorization_material)[..16]),
        callable,
        callable_source,
        parameter_count: candidate.parameter_count,
        is_async: candidate.is_async,
        paths,
        rejections,
    })
}

pub(super) fn authenticate_callable_query_builder_flows(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
) -> Result<Vec<AuthenticatedCallableQueryBuilderFlow>> {
    let mut flows = BTreeMap::new();
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .ok_or_else(|| anyhow::anyhow!("reachable query-builder module disappeared"))?;
        let source = module_source(modules, &unit.module)?;
        ensure!(
            hash_bytes(source.as_bytes()) == module.summary.source_hash,
            "query-builder module source changed after its Oxc summary was authenticated"
        );
        for leaf in module
            .summary
            .callable_leaf_plans
            .iter()
            .filter(|candidate| {
                candidate.callable_start >= unit.start && candidate.callable_end <= unit.end
            })
        {
            let super::callable_plans::CallableLeafControlCandidate::QueryBuilderFlow(candidate) =
                &leaf.control
            else {
                continue;
            };
            let flow = authenticate_query_builder_flow(modules, &unit.module, candidate)?;
            if let Some(previous) = flows.insert(flow.callable.clone(), flow.clone()) {
                ensure!(
                    previous == flow,
                    "query-builder callable has conflicting authenticated flow summaries"
                );
                flows.insert(previous.callable.clone(), previous);
            }
        }
    }
    Ok(flows.into_values().collect())
}

pub(super) fn authenticate_callable_query_value_plans(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
) -> Result<Vec<AuthenticatedCallableQueryValuePlan>> {
    let mut plans = BTreeMap::new();
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .ok_or_else(|| anyhow::anyhow!("reachable query-value module disappeared"))?;
        let source = module_source(modules, &unit.module)?;
        ensure!(
            hash_bytes(source.as_bytes()) == module.summary.source_hash,
            "query-value module source changed after its Oxc summary was authenticated"
        );
        for candidate in module
            .summary
            .callable_leaf_plans
            .iter()
            .filter(|candidate| {
                candidate.callable_start >= unit.start && candidate.callable_end <= unit.end
            })
        {
            let super::callable_plans::CallableLeafControlCandidate::QueryValue(candidate) =
                &candidate.control
            else {
                continue;
            };
            let plan = authenticate_query_value_plan(modules, &unit.module, candidate)?;
            let identity = (
                unit.module.clone(),
                plan.source.construction.start,
                plan.source.construction.end,
            );
            if let Some(previous) = plans.insert(identity.clone(), plan.clone()) {
                ensure!(
                    previous == plan,
                    "query-value source has conflicting authenticated plan projections"
                );
                plans.insert(identity, previous);
            }
        }
    }
    Ok(plans.into_values().collect())
}

impl AuthenticatedCallableQueryValuePlan {
    pub(super) fn proxy_helper_name(&self) -> String {
        format!("__convexQueryValue_{}", self.authorization_id)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::{GetSpan, SourceType};

    use super::*;
    use crate::callable_plans::{
        CallableLeafControlCandidate, ResolvedBindingReferenceIndex, collect_callable_leaf_plans,
    };
    use crate::{LoadedModule, PhaseMeasurements, ReachableUnit, hash_bytes, summarize_module};

    fn plans(source: &str) -> Vec<CallableQueryValuePlanCandidate> {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::ts().with_module(true)).parse();
        assert!(parsed.diagnostics.is_empty(), "{:#?}", parsed.diagnostics);
        let semantic = SemanticBuilder::new_compiler()
            .with_build_nodes(true)
            .with_cfg(true)
            .build(&parsed.program);
        assert!(
            semantic.diagnostics.is_empty(),
            "{:#?}",
            semantic.diagnostics
        );
        let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false)).unwrap();
        let scoping = semantic.semantic.scoping();
        let nodes = semantic.semantic.nodes();
        let mut bindings = ResolvedBindingIndex::new();
        let mut binding_references = ResolvedBindingReferenceIndex::new();
        for symbol_id in scoping.symbol_ids() {
            let declaration = scoping.symbol_span(symbol_id);
            let binding = ResolvedBinding {
                name: scoping.symbol_name(symbol_id).to_string(),
                declaration_start: declaration.start,
                declaration_end: declaration.end,
            };
            for reference in scoping.get_resolved_references(symbol_id) {
                let flags = reference.flags();
                if !flags.is_value() || flags.is_value_as_type() {
                    continue;
                }
                let reference = nodes.get_node(reference.node_id()).kind().span();
                assert!(
                    bindings
                        .insert((reference.start, reference.end), binding.clone())
                        .is_none()
                );
                binding_references
                    .entry((declaration.start, declaration.end))
                    .or_default()
                    .push(crate::ReferenceOccurrence {
                        name: binding.name.clone(),
                        start: reference.start,
                        end: reference.end,
                        read: flags.is_read(),
                        write: flags.is_write(),
                    });
            }
        }
        let mut leaves = Vec::new();
        collect_callable_leaf_plans(&ast, &bindings, &binding_references, &mut leaves).unwrap();
        leaves
            .into_iter()
            .filter_map(|leaf| match leaf.control {
                CallableLeafControlCandidate::QueryValue(plan) => Some(plan),
                _ => None,
            })
            .collect()
    }

    fn builder_flows(source: &str) -> Vec<CallableQueryBuilderFlowCandidate> {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::ts().with_module(true)).parse();
        assert!(parsed.diagnostics.is_empty(), "{:#?}", parsed.diagnostics);
        let semantic = SemanticBuilder::new_compiler()
            .with_build_nodes(true)
            .with_cfg(true)
            .build(&parsed.program);
        assert!(
            semantic.diagnostics.is_empty(),
            "{:#?}",
            semantic.diagnostics
        );
        let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false)).unwrap();
        let scoping = semantic.semantic.scoping();
        let nodes = semantic.semantic.nodes();
        let mut bindings = ResolvedBindingIndex::new();
        let mut binding_references = ResolvedBindingReferenceIndex::new();
        for symbol_id in scoping.symbol_ids() {
            let declaration = scoping.symbol_span(symbol_id);
            let binding = ResolvedBinding {
                name: scoping.symbol_name(symbol_id).to_string(),
                declaration_start: declaration.start,
                declaration_end: declaration.end,
            };
            for reference in scoping.get_resolved_references(symbol_id) {
                let flags = reference.flags();
                if !flags.is_value() || flags.is_value_as_type() {
                    continue;
                }
                let reference = nodes.get_node(reference.node_id()).kind().span();
                assert!(
                    bindings
                        .insert((reference.start, reference.end), binding.clone())
                        .is_none()
                );
                binding_references
                    .entry((declaration.start, declaration.end))
                    .or_default()
                    .push(crate::ReferenceOccurrence {
                        name: binding.name.clone(),
                        start: reference.start,
                        end: reference.end,
                        read: flags.is_read(),
                        write: flags.is_write(),
                    });
            }
        }
        let mut leaves = Vec::new();
        collect_callable_leaf_plans(&ast, &bindings, &binding_references, &mut leaves).unwrap();
        leaves
            .into_iter()
            .filter_map(|leaf| match leaf.control {
                CallableLeafControlCandidate::QueryBuilderFlow(flow) => Some(flow),
                _ => None,
            })
            .collect()
    }

    fn literal_table(plan: &CallableQueryValuePlanCandidate) -> &str {
        let CallableValueFlowCandidate::LiteralString { value } = &plan.source.table else {
            panic!("test query source does not have a literal table")
        };
        value
    }

    fn authenticated(source: &str) -> Vec<AuthenticatedCallableQueryValuePlan> {
        let module_key = "convex/queryValueFixture.ts";
        let summary = summarize_module(
            module_key,
            Path::new(module_key),
            source,
            &hash_bytes(source.as_bytes()),
            "query-value-fixture-cache",
            "query-value-fixture-pipeline",
            "query-value-fixture-policy",
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let mut modules = BTreeMap::new();
        modules.insert(
            module_key.to_string(),
            LoadedModule::new(summary, source.to_string()),
        );
        let mut reachable = BTreeMap::new();
        reachable.insert(
            "fixture".to_string(),
            ReachableUnit {
                id: "fixture".to_string(),
                module: module_key.to_string(),
                name: "fixture".to_string(),
                start: 0,
                end: u32::try_from(source.len()).unwrap(),
                source: source.to_string(),
                kind: "function".to_string(),
                dependency_chain: Vec::new(),
                dependencies: BTreeMap::new(),
            },
        );
        authenticate_callable_query_value_plans(&modules, &reachable).unwrap()
    }

    #[test]
    fn query_value_plan_unifies_bindings_choices_terminals_and_streams() {
        let plans = plans(
            r#"
async function load(ctx, prefix, chooseAccounts, limit) {
  const base = ctx.db
    .query("documents")
    .withIndex("by_name", (range) => {
      const lowerBound = range.gte("name", prefix);
      return lowerBound.lt("name", `${prefix}\uffff`);
    });
  const alias = base;
  const selected = chooseAccounts
    ? ctx.db
        .query("accounts")
        .withIndex("by_name")
    : alias;
  const rows = await selected.order("desc").take(limit);
  for await (const row of alias) {
    if (row.name === prefix) break;
  }
  return rows;
}
"#,
        );
        assert_eq!(plans.len(), 2, "{plans:#?}");
        assert!(plans.iter().all(|plan| plan.closed), "{plans:#?}");

        let documents = plans
            .iter()
            .find(|plan| literal_table(plan) == "documents")
            .unwrap();
        assert_eq!(
            documents
                .consumers
                .iter()
                .map(|consumer| (consumer.kind.terminal(), consumer.kind.result_kind()))
                .collect::<Vec<_>>(),
            vec![("take", "hostArray"), ("stream", "queryStream")]
        );
        assert!(documents.consumers.iter().any(|consumer| {
            consumer.stages.iter().any(|stage| {
                matches!(
                    stage,
                    CallableQueryStageCandidate::WithIndex { constraints, .. }
                        if constraints.len() == 2
                            && constraints[0].operator == "gte"
                            && constraints[1].operator == "lt"
                )
            })
        }));
        assert!(
            documents
                .consumers
                .iter()
                .any(|consumer| !consumer.choice_ranges.is_empty())
        );

        let accounts = plans
            .iter()
            .find(|plan| literal_table(plan) == "accounts")
            .unwrap();
        assert_eq!(accounts.consumers.len(), 1);
        assert_eq!(accounts.consumers[0].kind, CallableQueryConsumerKind::Take);
        assert!(!accounts.consumers[0].choice_ranges.is_empty());
    }

    #[test]
    fn query_builder_flow_records_two_hop_argument_to_for_await_ports() {
        let flows = builder_flows(
            r#"
async function consume(query) {
  for await (const row of query) {
    void row;
  }
}

function forward(query) {
  return consume(query);
}

async function load(ctx) {
  const query = ctx.db.query("documents").withIndex("by_owner");
  return forward(query);
}
"#,
        );
        assert_eq!(flows.len(), 3, "{flows:#?}");
        let stream = flows
            .iter()
            .find(|flow| {
                flow.paths.iter().any(|path| {
                    matches!(
                        path.sink,
                        CallableQueryBuilderSinkCandidate::ForAwait { .. }
                    )
                })
            })
            .expect("consume flow must expose its for-await sink");
        assert!(stream.rejections.is_empty(), "{stream:#?}");
        assert!(stream.paths.iter().any(|path| {
            path.value_kind == CallableQueryBuilderKind::QueryBuilder
                && matches!(
                    path.origin,
                    CallableQueryBuilderOriginCandidate::Parameter { index: 0, .. }
                )
                && matches!(
                    path.sink,
                    CallableQueryBuilderSinkCandidate::ForAwait { .. }
                )
        }));
        assert_eq!(
            flows
                .iter()
                .flat_map(|flow| &flow.paths)
                .filter(|path| matches!(
                    (&path.value_kind, &path.sink),
                    (
                        CallableQueryBuilderKind::QueryBuilder,
                        CallableQueryBuilderSinkCandidate::CallArgument {
                            argument_index: 0,
                            ..
                        }
                    )
                ))
                .count(),
            2,
            "{flows:#?}"
        );
    }

    #[test]
    fn query_builder_flow_correlates_conditional_returned_index_ranges() {
        let flows = builder_flows(
            r#"
function constrain(range, lower, upper, bounded) {
  return bounded
    ? range.gte("owner", lower).lt("owner", upper)
    : range.eq("owner", lower);
}

async function load(ctx, lower, upper, bounded) {
  const query = ctx.db.query("documents").withIndex(
    "by_owner",
    (range) => constrain(range, lower, upper, bounded),
  );
  return await query.collect();
}
"#,
        );
        let range_helper = flows
            .iter()
            .find(|flow| {
                flow.paths.iter().any(|path| {
                    path.value_kind == CallableQueryBuilderKind::IndexRangeBuilder
                        && matches!(
                            path.origin,
                            CallableQueryBuilderOriginCandidate::Parameter { index: 0, .. }
                        )
                        && matches!(path.sink, CallableQueryBuilderSinkCandidate::Return { .. })
                })
            })
            .expect("range helper must expose its typed return paths");
        let variants = range_helper
            .paths
            .iter()
            .filter(|path| {
                path.value_kind == CallableQueryBuilderKind::IndexRangeBuilder
                    && matches!(path.sink, CallableQueryBuilderSinkCandidate::Return { .. })
            })
            .collect::<Vec<_>>();
        assert_eq!(variants.len(), 2, "{range_helper:#?}");
        assert!(variants.iter().all(|path| {
            path.steps
                .iter()
                .any(|step| matches!(step, CallableQueryBuilderStepCandidate::Choice { .. }))
        }));
        assert_eq!(
            variants
                .iter()
                .map(|path| {
                    path.steps
                        .iter()
                        .filter(|step| {
                            matches!(
                                step,
                                CallableQueryBuilderStepCandidate::IndexConstraint { .. }
                            )
                        })
                        .count()
                })
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 2])
        );
        assert!(
            flows.iter().any(|flow| {
                flow.paths.iter().any(|path| {
                    path.value_kind == CallableQueryBuilderKind::IndexRangeBuilder
                        && matches!(
                            path.origin,
                            CallableQueryBuilderOriginCandidate::CallResult { .. }
                        )
                        && matches!(
                            path.sink,
                            CallableQueryBuilderSinkCandidate::WithIndexRangeReturn { .. }
                        )
                })
            }),
            "{flows:#?}"
        );
    }

    #[test]
    fn query_value_plan_records_interprocedural_forwarding_without_closing_it_locally() {
        let plans = plans(
            r#"
async function load(ctx, owner) {
  const query = ctx.db
    .query("documents")
    .withIndex("by_owner", (range) => range.eq("owner", owner));
  consume(query);
  return await query.collect();
}
"#,
        );
        let [plan] = plans.as_slice() else {
            panic!("expected one query-value plan: {plans:#?}")
        };
        assert!(!plan.closed);
        assert!(plan.locally_closed);
        assert_eq!(plan.consumers.len(), 1);
        assert_eq!(plan.forwards.len(), 1, "{plan:#?}");
        assert!(plan.rejections.is_empty(), "{plan:#?}");
        assert!(matches!(
            &plan.forwards[0],
            CallableQueryForwardCandidate::CallArgument {
                callee,
                argument_index: 0,
                ..
            } if callee == "consume"
        ));
    }

    #[test]
    fn query_value_plan_fails_closed_on_storage_escape() {
        let plans = plans(
            r#"
async function load(ctx, owner, stored) {
  const query = ctx.db
    .query("documents")
    .withIndex("by_owner", (range) => range.eq("owner", owner));
  stored.push(query);
  return await query.collect();
}
"#,
        );
        let [plan] = plans.as_slice() else {
            panic!("expected one query-value plan: {plans:#?}")
        };
        assert!(!plan.closed);
        assert!(!plan.locally_closed);
        assert_eq!(plan.rejections.len(), 1, "{plan:#?}");
        assert_eq!(
            plan.rejections[0].reason,
            "query value escapes its authenticated binding flow"
        );
    }

    #[test]
    fn optional_computed_and_shadowed_query_sources_do_not_gain_authority() {
        let computed = plans(
            r#"
async function load() {
  return await ctx.db["query"]("documents").collect();
}
"#,
        );
        assert!(computed.is_empty(), "{computed:#?}");

        let optional = plans(
            r#"
async function load(ctx) {
  return await ctx?.db.query("documents").collect();
}
"#,
        );
        assert!(optional.is_empty(), "{optional:#?}");

        let shadowed = plans(
            r#"
async function load() {
  const ctx = { db: { query: () => ({ collect: async () => [] }) } };
  return await ctx.db.query("documents").collect();
}
"#,
        );
        let [plan] = shadowed.as_slice() else {
            panic!("shadowed query shape should remain a fact for capability intersection")
        };
        assert!(plan.closed);
        assert!(matches!(
            plan.source.capability,
            CallableValueFlowCandidate::CapturedBinding { .. }
        ));
    }

    #[test]
    fn database_capability_query_return_is_an_exact_open_callable_edge() {
        let plans = plans(
            r#"
function byOwner(db, owner) {
  const query = db
    .query("documents")
    .withIndex("by_owner", (range) => range.eq("owner", owner));
  return query;
}
"#,
        );
        let [plan] = plans.as_slice() else {
            panic!("expected one query-value plan: {plans:#?}")
        };
        assert_eq!(
            plan.source.capability_kind,
            CallableQueryCapabilityKind::Database
        );
        assert!(plan.locally_closed);
        assert!(!plan.closed);
        assert!(plan.consumers.is_empty());
        assert!(matches!(
            plan.forwards.as_slice(),
            [CallableQueryForwardCandidate::Return { .. }]
        ));
    }

    #[test]
    fn global_query_value_plan_authenticates_every_lowering_anchor() {
        let source = r#"
async function load(ctx, owner, limit) {
  const query = ctx.db
    .query("documents")
    .withIndex("by_owner", (range) => range.eq("owner", owner));
  return await query.order("desc").take(limit);
}
"#;
        let plans = authenticated(source);
        let [plan] = plans.as_slice() else {
            panic!("expected one authenticated query-value plan: {plans:#?}")
        };
        assert!(plan.closed, "{plan:#?}");
        assert!(plan.authorization_id.starts_with("query_"));
        assert_eq!(
            plan.source.construction.source_sha256,
            hash_bytes(source.as_bytes())
        );
        assert_eq!(
            plan.source.construction.slice_sha256,
            hash_bytes(
                source[plan.source.construction.start as usize
                    ..plan.source.construction.end as usize]
                    .as_bytes()
            )
        );
        assert_eq!(plan.consumers.len(), 1);
        assert_eq!(plan.consumers[0].kind, CallableQueryConsumerKind::Take);
        assert_eq!(plan.consumers[0].stages.len(), 2);
        assert!(
            plan.proxy_helper_name()
                .starts_with("__convexQueryValue_query_")
        );
    }

    #[test]
    fn global_query_value_plan_rejects_stale_source_provenance() {
        let module_key = "convex/queryValueCorruption.ts";
        let source = r#"async function load(ctx) {
  const query = ctx.db.query("documents");
  return await query.collect();
}
"#;
        let summary = summarize_module(
            module_key,
            Path::new(module_key),
            source,
            &hash_bytes(source.as_bytes()),
            "query-value-corruption-cache",
            "query-value-corruption-pipeline",
            "query-value-corruption-policy",
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        let tampered = source.replace("documents", "accounted");
        assert_eq!(source.len(), tampered.len());
        let mut modules = BTreeMap::new();
        modules.insert(module_key.to_string(), LoadedModule::new(summary, tampered));
        let mut reachable = BTreeMap::new();
        reachable.insert(
            "fixture".to_string(),
            ReachableUnit {
                id: "fixture".to_string(),
                module: module_key.to_string(),
                name: "fixture".to_string(),
                start: 0,
                end: u32::try_from(source.len()).unwrap(),
                source: source.to_string(),
                kind: "function".to_string(),
                dependency_chain: Vec::new(),
                dependencies: BTreeMap::new(),
            },
        );
        let error = authenticate_callable_query_value_plans(&modules, &reachable)
            .expect_err("stale query-value source must be rejected");
        assert!(
            error
                .to_string()
                .contains("source changed after its Oxc summary"),
            "{error:#}"
        );
    }
}
