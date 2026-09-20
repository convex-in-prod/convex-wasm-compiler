use std::collections::{BTreeMap, BTreeSet};

use super::{CallPosition, CallableControlCallPlan, CallableControlPlan};
use crate::effect_plan::{CallableKey, SourceAnchor};
use crate::query_values::{
    AuthenticatedCallableQueryBuilderFlow, AuthenticatedQueryBuilderOrigin,
    AuthenticatedQueryBuilderPath, AuthenticatedQueryBuilderSink, AuthenticatedQueryBuilderStep,
    CallableQueryBuilderKind, same_authenticated_query_builder_origin,
};

const MAX_TRANSITIVE_QUERY_BUILDER_ROUTES: usize = 1024;
const MAX_TRANSITIVE_QUERY_BUILDER_DEPTH: usize = 12;

type ConcreteOriginKey = (CallableKey, String, u32, u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedQueryBuilderRoute {
    pub(crate) value_kind: CallableQueryBuilderKind,
    pub(crate) origin_callable: CallableKey,
    pub(crate) origin_callable_source: SourceAnchor,
    /// Callable whose parameter list owns every remaining `Parameter` operand in this route.
    pub(crate) operand_callable: CallableKey,
    pub(crate) origin: AuthenticatedQueryBuilderOrigin,
    pub(crate) steps: Vec<AuthenticatedQueryBuilderStep>,
    pub(crate) sink_callable: CallableKey,
    pub(crate) sink_callable_source: SourceAnchor,
    pub(crate) sink: AuthenticatedQueryBuilderSink,
    pub(crate) callable_path: Vec<CallableKey>,
    pub(crate) callsites: Vec<SourceAnchor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QueryBuilderGraphRejection {
    pub(crate) callable: CallableKey,
    pub(crate) site: Option<SourceAnchor>,
    pub(crate) reason: String,
    pub(crate) disposition: QueryBuilderGraphRejectionDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryBuilderGraphRejectionDisposition {
    AuthorizationBlocking,
    UnmatchedSpeculativeVariant,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuthenticatedQueryBuilderGraph {
    routes: Vec<AuthenticatedQueryBuilderRoute>,
    rejections: Vec<QueryBuilderGraphRejection>,
    blocked_concrete_origins: BTreeSet<ConcreteOriginKey>,
}

impl AuthenticatedQueryBuilderGraph {
    pub(crate) fn routes(&self) -> impl Iterator<Item = &AuthenticatedQueryBuilderRoute> {
        self.routes.iter()
    }

    pub(crate) fn terminal_routes(&self) -> impl Iterator<Item = &AuthenticatedQueryBuilderRoute> {
        self.routes.iter().filter(|route| {
            let range_callback_open = route.steps.iter().any(|step| {
                matches!(
                    step,
                    AuthenticatedQueryBuilderStep::QueryStage {
                        range_callback: Some(_),
                        ..
                    }
                )
            });
            matches!(
                route.sink,
                AuthenticatedQueryBuilderSink::Terminal { .. }
                    | AuthenticatedQueryBuilderSink::ForAwait { .. }
                    | AuthenticatedQueryBuilderSink::WithIndexRangeReturn { .. }
            ) && !range_callback_open
                && concrete_origin_key(route)
                    .is_none_or(|origin| !self.blocked_concrete_origins.contains(&origin))
        })
    }

    /// Positive authority for materialization: the concrete source reaches this terminal and no
    /// other authenticated route from the same source remains open.
    pub(crate) fn closed_terminal_routes(
        &self,
    ) -> impl Iterator<Item = &AuthenticatedQueryBuilderRoute> {
        self.terminal_routes().filter(|route| {
            matches!(
                route.origin,
                AuthenticatedQueryBuilderOrigin::QueryConstruction { .. }
            )
        })
    }

    pub(crate) fn rejections(&self) -> &[QueryBuilderGraphRejection] {
        &self.rejections
    }

    pub(crate) fn blocking_rejections(&self) -> impl Iterator<Item = &QueryBuilderGraphRejection> {
        self.rejections.iter().filter(|rejection| {
            rejection.disposition == QueryBuilderGraphRejectionDisposition::AuthorizationBlocking
        })
    }
}

fn concrete_origin_key(route: &AuthenticatedQueryBuilderRoute) -> Option<ConcreteOriginKey> {
    concrete_origin_key_from_origin(&route.origin_callable, &route.origin)
}

fn concrete_origin_key_from_origin(
    callable: &CallableKey,
    origin: &AuthenticatedQueryBuilderOrigin,
) -> Option<ConcreteOriginKey> {
    let AuthenticatedQueryBuilderOrigin::QueryConstruction { source } = origin else {
        return None;
    };
    Some((
        callable.clone(),
        source.construction.module.clone(),
        source.construction.start,
        source.construction.end,
    ))
}

fn route_from_local(
    flow: &AuthenticatedCallableQueryBuilderFlow,
    path: &AuthenticatedQueryBuilderPath,
) -> AuthenticatedQueryBuilderRoute {
    AuthenticatedQueryBuilderRoute {
        value_kind: path.value_kind,
        origin_callable: flow.callable.clone(),
        origin_callable_source: flow.callable_source.clone(),
        operand_callable: flow.callable.clone(),
        origin: path.origin.clone(),
        steps: path.steps.clone(),
        sink_callable: flow.callable.clone(),
        sink_callable_source: flow.callable_source.clone(),
        sink: path.sink.clone(),
        callable_path: vec![flow.callable.clone()],
        callsites: Vec::new(),
    }
}

fn call_index<'a>(
    plans: impl IntoIterator<Item = &'a CallableControlPlan>,
) -> BTreeMap<(CallableKey, String, u32, u32), Vec<&'a CallableControlCallPlan>> {
    let mut calls = BTreeMap::new();
    for plan in plans {
        for call in &plan.calls {
            calls
                .entry((
                    plan.callable.clone(),
                    call.callsite.module.clone(),
                    call.callsite.start,
                    call.callsite.end,
                ))
                .or_insert_with(Vec::new)
                .push(call);
        }
    }
    calls
}

fn exact_call_at<'a>(
    calls: &'a BTreeMap<(CallableKey, String, u32, u32), Vec<&'a CallableControlCallPlan>>,
    caller: &CallableKey,
    callsite: &SourceAnchor,
) -> Option<&'a CallableControlCallPlan> {
    let matching = calls.get(&(
        caller.clone(),
        callsite.module.clone(),
        callsite.start,
        callsite.end,
    ))?;
    let [call] = matching.as_slice() else {
        return None;
    };
    (call.dispatch_exact && call.arguments_safe).then_some(*call)
}

fn cyclic_callables(
    flows: &BTreeMap<CallableKey, &AuthenticatedCallableQueryBuilderFlow>,
    calls: &BTreeMap<(CallableKey, String, u32, u32), Vec<&CallableControlCallPlan>>,
) -> BTreeSet<CallableKey> {
    let mut adjacency = BTreeMap::<CallableKey, BTreeSet<CallableKey>>::new();
    for ((caller, _, _, _), matching) in calls {
        let [call] = matching.as_slice() else {
            continue;
        };
        if call.dispatch_exact
            && call.arguments_safe
            && flows.contains_key(caller)
            && flows.contains_key(&call.target)
        {
            adjacency
                .entry(caller.clone())
                .or_default()
                .insert(call.target.clone());
        }
    }

    fn visit(
        callable: &CallableKey,
        adjacency: &BTreeMap<CallableKey, BTreeSet<CallableKey>>,
        states: &mut BTreeMap<CallableKey, u8>,
        stack: &mut Vec<CallableKey>,
        cyclic: &mut BTreeSet<CallableKey>,
    ) {
        states.insert(callable.clone(), 1);
        stack.push(callable.clone());
        for target in adjacency.get(callable).into_iter().flatten() {
            match states.get(target).copied().unwrap_or(0) {
                0 => visit(target, adjacency, states, stack, cyclic),
                1 => {
                    if let Some(index) = stack.iter().position(|entry| entry == target) {
                        cyclic.extend(stack[index..].iter().cloned());
                    }
                }
                _ => {}
            }
        }
        stack.pop();
        states.insert(callable.clone(), 2);
    }

    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    let mut cyclic = BTreeSet::new();
    for callable in flows.keys() {
        if states.get(callable).copied().unwrap_or(0) == 0 {
            visit(callable, &adjacency, &mut states, &mut stack, &mut cyclic);
        }
    }
    cyclic
}

fn compose_call_argument<'a>(
    first: &AuthenticatedQueryBuilderRoute,
    second: &AuthenticatedQueryBuilderRoute,
    flows: &BTreeMap<CallableKey, &AuthenticatedCallableQueryBuilderFlow>,
    calls: &'a BTreeMap<(CallableKey, String, u32, u32), Vec<&'a CallableControlCallPlan>>,
) -> Option<&'a CallableControlCallPlan> {
    let AuthenticatedQueryBuilderSink::CallArgument {
        callsite,
        argument_index,
        ..
    } = &first.sink
    else {
        return None;
    };
    let AuthenticatedQueryBuilderOrigin::Parameter { index, .. } = &second.origin else {
        return None;
    };
    if first.value_kind != second.value_kind || argument_index != index {
        return None;
    }
    let call = exact_call_at(calls, &first.sink_callable, callsite)?;
    let target = flows.get(&call.target)?;
    (call.target == second.origin_callable
        && second.operand_callable == call.target
        && *argument_index < target.parameter_count)
        .then_some(call)
}

fn compose_call_result<'a>(
    first: &AuthenticatedQueryBuilderRoute,
    second: &AuthenticatedQueryBuilderRoute,
    flows: &BTreeMap<CallableKey, &AuthenticatedCallableQueryBuilderFlow>,
    calls: &'a BTreeMap<(CallableKey, String, u32, u32), Vec<&'a CallableControlCallPlan>>,
) -> Option<&'a CallableControlCallPlan> {
    if !matches!(first.sink, AuthenticatedQueryBuilderSink::Return { .. }) {
        return None;
    }
    let AuthenticatedQueryBuilderOrigin::CallResult { callsite, .. } = &second.origin else {
        return None;
    };
    if first.value_kind != second.value_kind {
        return None;
    }
    let call = exact_call_at(calls, &second.origin_callable, callsite)?;
    let target = flows.get(&call.target)?;
    (call.target == first.sink_callable
        && !target.is_async
        && call.position != CallPosition::SequentialAwait)
        .then_some(call)
}

fn specialize_operand(
    operand: &mut crate::query_values::AuthenticatedQueryValueOperand,
    call: &CallableControlCallPlan,
) -> Option<()> {
    let crate::callable_plans::CallableValueFlowCandidate::Parameter { index } = &operand.value
    else {
        return Some(());
    };
    let argument = call.arguments.get(*index)?;
    operand.value = argument.value.clone();
    operand.provenance = argument.provenance.clone();
    Some(())
}

fn specialize_value(
    value: &mut crate::callable_plans::CallableValueFlowCandidate,
    provenance: &mut SourceAnchor,
    call: &CallableControlCallPlan,
) -> Option<()> {
    let crate::callable_plans::CallableValueFlowCandidate::Parameter { index } = value else {
        return Some(());
    };
    let argument = call.arguments.get(*index)?;
    *value = argument.value.clone();
    *provenance = argument.provenance.clone();
    Some(())
}

fn specialize_stage(
    stage: &mut crate::query_values::AuthenticatedQueryStage,
    call: &CallableControlCallPlan,
) -> Option<()> {
    match stage {
        crate::query_values::AuthenticatedQueryStage::WithIndex { constraints, .. } => {
            for constraint in constraints {
                specialize_operand(&mut constraint.value, call)?;
            }
        }
        crate::query_values::AuthenticatedQueryStage::Order { direction, .. } => {
            specialize_operand(direction, call)?;
        }
    }
    Some(())
}

fn specialize_origin(
    origin: &AuthenticatedQueryBuilderOrigin,
    call: &CallableControlCallPlan,
) -> Option<AuthenticatedQueryBuilderOrigin> {
    let mut specialized = origin.clone();
    if let AuthenticatedQueryBuilderOrigin::QueryConstruction { source } = &mut specialized {
        specialize_value(
            &mut source.capability,
            &mut source.capability_reference,
            call,
        )?;
        specialize_operand(&mut source.table, call)?;
    }
    Some(specialized)
}

fn specialize_sink(
    sink: &AuthenticatedQueryBuilderSink,
    call: &CallableControlCallPlan,
) -> Option<AuthenticatedQueryBuilderSink> {
    let mut specialized = sink.clone();
    if let AuthenticatedQueryBuilderSink::Terminal { consumer } = &mut specialized {
        for stage in &mut consumer.stages {
            specialize_stage(stage, call)?;
        }
        for argument in &mut consumer.arguments {
            specialize_operand(argument, call)?;
        }
    }
    Some(specialized)
}

fn specialize_steps(
    steps: &[AuthenticatedQueryBuilderStep],
    call: &CallableControlCallPlan,
) -> Option<Vec<AuthenticatedQueryBuilderStep>> {
    let mut specialized = steps.to_vec();
    for step in &mut specialized {
        match step {
            AuthenticatedQueryBuilderStep::QueryStage { stage, .. } => {
                specialize_stage(stage, call)?;
            }
            AuthenticatedQueryBuilderStep::IndexConstraint { constraint, .. } => {
                specialize_operand(&mut constraint.value, call)?;
            }
            AuthenticatedQueryBuilderStep::Alias { .. }
            | AuthenticatedQueryBuilderStep::Choice { .. } => {}
        }
    }
    Some(specialized)
}

fn compose_routes(
    first: &AuthenticatedQueryBuilderRoute,
    second: &AuthenticatedQueryBuilderRoute,
    call: &CallableControlCallPlan,
    specialize_first: bool,
    call_result: bool,
) -> Option<AuthenticatedQueryBuilderRoute> {
    if first.callable_path.len() + second.callable_path.len() > MAX_TRANSITIVE_QUERY_BUILDER_DEPTH {
        return None;
    }
    let mut callable_path = first.callable_path.clone();
    callable_path.extend(second.callable_path.iter().cloned());
    let mut callsites = first.callsites.clone();
    callsites.push(call.callsite.clone());
    callsites.extend(second.callsites.iter().cloned());
    let mut steps = if specialize_first {
        specialize_steps(&first.steps, call)?
    } else {
        first.steps.clone()
    };
    steps.extend(if specialize_first {
        second.steps.clone()
    } else {
        specialize_steps(&second.steps, call)?
    });
    Some(AuthenticatedQueryBuilderRoute {
        value_kind: first.value_kind,
        origin_callable: first.origin_callable.clone(),
        origin_callable_source: first.origin_callable_source.clone(),
        operand_callable: if call_result {
            second.operand_callable.clone()
        } else {
            first.operand_callable.clone()
        },
        origin: if specialize_first {
            specialize_origin(&first.origin, call)?
        } else {
            first.origin.clone()
        },
        steps,
        sink_callable: second.sink_callable.clone(),
        sink_callable_source: second.sink_callable_source.clone(),
        sink: if call_result {
            second.sink.clone()
        } else {
            specialize_sink(&second.sink, call)?
        },
        callable_path,
        callsites,
    })
}

fn close_with_index_range(
    query: &AuthenticatedQueryBuilderRoute,
    range: &AuthenticatedQueryBuilderRoute,
) -> Option<AuthenticatedQueryBuilderRoute> {
    if query.value_kind != CallableQueryBuilderKind::QueryBuilder
        || range.value_kind != CallableQueryBuilderKind::IndexRangeBuilder
    {
        return None;
    }
    let AuthenticatedQueryBuilderSink::WithIndexRangeReturn {
        with_index_site, ..
    } = &range.sink
    else {
        return None;
    };
    let matching_steps = query
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| match step {
            AuthenticatedQueryBuilderStep::QueryStage {
                stage: crate::query_values::AuthenticatedQueryStage::WithIndex { site, .. },
                range_callback: Some(callback),
            } if site == with_index_site
                && callback == &range.origin_callable_source
                && callback == &range.sink_callable_source =>
            {
                Some(index)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [step_index] = matching_steps.as_slice() else {
        return None;
    };
    let mut closed = query.clone();
    let AuthenticatedQueryBuilderStep::QueryStage {
        stage: crate::query_values::AuthenticatedQueryStage::WithIndex { constraints, .. },
        range_callback,
    } = &mut closed.steps[*step_index]
    else {
        return None;
    };
    let existing_constraints = constraints.clone();
    let mut resolved_constraints = range
        .steps
        .iter()
        .filter_map(|step| match step {
            AuthenticatedQueryBuilderStep::IndexConstraint { constraint, .. } => {
                Some(constraint.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if resolved_constraints.is_empty() {
        return None;
    }
    if !existing_constraints.is_empty() {
        if existing_constraints.len() != resolved_constraints.len()
            || !existing_constraints.iter().zip(&resolved_constraints).all(
                |(existing, resolved)| {
                    existing.field == resolved.field
                        && existing.operator == resolved.operator
                        && existing.value.provenance == resolved.value.provenance
                },
            )
        {
            return None;
        }
        // The legacy local parser expresses outer parameters in the query owner's frame, while
        // the callback summary sees the same symbol as a capture. Exact operand provenance proves
        // they are the same value; retain the query-owner representation for materialization.
        resolved_constraints = existing_constraints;
    }
    *constraints = resolved_constraints.clone();
    *range_callback = None;
    if let AuthenticatedQueryBuilderSink::Terminal { consumer } = &mut closed.sink {
        let matching = consumer
            .stages
            .iter()
            .enumerate()
            .filter_map(|(index, stage)| match stage {
                crate::query_values::AuthenticatedQueryStage::WithIndex { site, .. }
                    if site == with_index_site =>
                {
                    Some(index)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [consumer_index] = matching.as_slice() else {
            return None;
        };
        let crate::query_values::AuthenticatedQueryStage::WithIndex {
            constraints: consumer_constraints,
            ..
        } = &mut consumer.stages[*consumer_index]
        else {
            return None;
        };
        *consumer_constraints = resolved_constraints;
    }
    closed
        .callable_path
        .extend(range.callable_path.iter().cloned());
    closed.callsites.extend(range.callsites.iter().cloned());
    Some(closed)
}

fn connector_site(route: &AuthenticatedQueryBuilderRoute) -> Option<SourceAnchor> {
    match &route.sink {
        AuthenticatedQueryBuilderSink::CallArgument { callsite, .. } => Some(callsite.clone()),
        AuthenticatedQueryBuilderSink::Return { site, .. } => Some(site.clone()),
        _ => None,
    }
}

pub(super) fn build_authenticated_query_builder_graph<'a>(
    flows: &'a [AuthenticatedCallableQueryBuilderFlow],
    control_plans: impl IntoIterator<Item = &'a CallableControlPlan>,
) -> AuthenticatedQueryBuilderGraph {
    let flows_by_callable = flows
        .iter()
        .map(|flow| (flow.callable.clone(), flow))
        .collect::<BTreeMap<_, _>>();
    let calls = call_index(control_plans);
    let cyclic = cyclic_callables(&flows_by_callable, &calls);
    let mut rejections = Vec::new();
    let mut blocked_concrete_origins = BTreeSet::new();
    for flow in flows {
        for rejection in &flow.rejections {
            let concrete_origin =
                concrete_origin_key_from_origin(&flow.callable, &rejection.origin);
            if let Some(origin) = &concrete_origin {
                blocked_concrete_origins.insert(origin.clone());
            }
            rejections.push(QueryBuilderGraphRejection {
                callable: flow.callable.clone(),
                site: Some(rejection.provenance.clone()),
                reason: rejection.reason.clone(),
                disposition: if concrete_origin.is_some() {
                    QueryBuilderGraphRejectionDisposition::AuthorizationBlocking
                } else {
                    QueryBuilderGraphRejectionDisposition::UnmatchedSpeculativeVariant
                },
            });
        }
        if cyclic.contains(&flow.callable) {
            rejections.push(QueryBuilderGraphRejection {
                callable: flow.callable.clone(),
                site: Some(flow.callable_source.clone()),
                reason: "query-builder flow crosses a recursive callable component".to_string(),
                disposition: QueryBuilderGraphRejectionDisposition::AuthorizationBlocking,
            });
        }
    }

    let mut routes = flows
        .iter()
        .filter(|flow| !cyclic.contains(&flow.callable))
        .flat_map(|flow| {
            flow.paths
                .iter()
                .filter(|path| {
                    !flow.rejections.iter().any(|rejection| {
                        same_authenticated_query_builder_origin(&path.origin, &rejection.origin)
                    })
                })
                .map(|path| route_from_local(flow, path))
        })
        .collect::<Vec<_>>();
    routes.dedup();

    let mut cursor = 0;
    while cursor < routes.len() && routes.len() < MAX_TRANSITIVE_QUERY_BUILDER_ROUTES {
        let first = routes[cursor].clone();
        let snapshot = routes.clone();
        for second in &snapshot {
            let composed = if let Some(call) =
                compose_call_argument(&first, second, &flows_by_callable, &calls)
            {
                compose_routes(&first, second, call, false, false)
            } else if let Some(call) =
                compose_call_result(&first, second, &flows_by_callable, &calls)
            {
                compose_routes(
                    &first,
                    second,
                    call,
                    first.operand_callable == call.target,
                    true,
                )
            } else {
                None
            };
            let Some(composed) = composed else {
                continue;
            };
            if !routes.contains(&composed) {
                routes.push(composed);
                if routes.len() == MAX_TRANSITIVE_QUERY_BUILDER_ROUTES {
                    break;
                }
            }
        }
        cursor += 1;
    }

    let mut query_cursor = 0;
    while query_cursor < routes.len() && routes.len() < MAX_TRANSITIVE_QUERY_BUILDER_ROUTES {
        let query = routes[query_cursor].clone();
        let snapshot = routes.clone();
        for range in &snapshot {
            let Some(closed) = close_with_index_range(&query, range) else {
                continue;
            };
            if !routes.contains(&closed) {
                routes.push(closed);
                if routes.len() == MAX_TRANSITIVE_QUERY_BUILDER_ROUTES {
                    break;
                }
            }
        }
        query_cursor += 1;
    }

    if routes.len() == MAX_TRANSITIVE_QUERY_BUILDER_ROUTES {
        for flow in flows {
            rejections.push(QueryBuilderGraphRejection {
                callable: flow.callable.clone(),
                site: Some(flow.callable_source.clone()),
                reason: "query-builder graph exceeded its bounded route budget".to_string(),
                disposition: QueryBuilderGraphRejectionDisposition::AuthorizationBlocking,
            });
        }
        routes.clear();
    } else {
        for route in &routes {
            if let Some(site) = connector_site(route) {
                let has_continuation = routes.iter().any(|candidate| {
                    compose_call_argument(route, candidate, &flows_by_callable, &calls).is_some()
                        || compose_call_result(route, candidate, &flows_by_callable, &calls)
                            .is_some()
                });
                if !has_continuation {
                    let concrete_origin = concrete_origin_key(route);
                    if let Some(origin) = &concrete_origin {
                        blocked_concrete_origins.insert(origin.clone());
                    }
                    rejections.push(QueryBuilderGraphRejection {
                        callable: route.sink_callable.clone(),
                        site: Some(site),
                        reason: "query-builder connector has no one exact typed continuation"
                            .to_string(),
                        disposition: if concrete_origin.is_some() {
                            QueryBuilderGraphRejectionDisposition::AuthorizationBlocking
                        } else {
                            QueryBuilderGraphRejectionDisposition::UnmatchedSpeculativeVariant
                        },
                    });
                }
            }
        }
    }

    routes.sort_by_key(|route| {
        (
            route.origin_callable.module.clone(),
            route.origin_callable.unit_id.clone(),
            route.sink_callable.module.clone(),
            route.sink_callable.unit_id.clone(),
            route.callable_path.len(),
            route.callsites.len(),
        )
    });
    rejections.sort_by_key(|rejection| {
        (
            rejection.callable.module.clone(),
            rejection.callable.unit_id.clone(),
            rejection.site.as_ref().map(|site| site.start).unwrap_or(0),
            rejection.reason.clone(),
        )
    });
    rejections.dedup();
    AuthenticatedQueryBuilderGraph {
        routes,
        rejections,
        blocked_concrete_origins,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::callable_control::{
        CallableControlBlockCandidate, CallableControlSkeletonCandidate, CallableIntraBlockOrder,
    };
    use crate::callable_plans::{
        CallableControlCallArgument, CallableControlSummary, CallableValueFlowCandidate,
    };
    use crate::query_values::{
        AuthenticatedQueryBuilderFlowRejection, AuthenticatedQueryConsumer,
        AuthenticatedQueryIndexConstraint, AuthenticatedQuerySource, AuthenticatedQueryStage,
        AuthenticatedQueryStreamBinding, AuthenticatedQueryValueOperand,
        CallableQueryCapabilityKind, CallableQueryConsumerKind,
    };
    use crate::{LoadedModule, PhaseMeasurements, ReachableUnit, hash_bytes, summarize_module};

    fn key(name: &str) -> CallableKey {
        CallableKey {
            module: format!("convex/{name}.ts"),
            unit_id: format!("{name}:0:100"),
        }
    }

    fn anchor(module: &str, start: u32, end: u32) -> SourceAnchor {
        SourceAnchor {
            module: format!("convex/{module}.ts"),
            source_sha256: "a".repeat(64),
            start,
            end,
            slice_sha256: format!("{start:032x}{end:032x}"),
        }
    }

    fn query_source(module: &str) -> AuthenticatedQuerySource {
        AuthenticatedQuerySource {
            construction: anchor(module, 5, 20),
            callee: anchor(module, 5, 15),
            capability_kind: CallableQueryCapabilityKind::ContextDatabase,
            capability: CallableValueFlowCandidate::Parameter { index: 0 },
            capability_reference: anchor(module, 5, 8),
            capability_binding: anchor(module, 1, 4),
            capability_name: "ctx".to_string(),
            table: AuthenticatedQueryValueOperand {
                value: CallableValueFlowCandidate::LiteralString {
                    value: "documents".to_string(),
                },
                provenance: anchor(module, 16, 19),
            },
        }
    }

    fn parameter(module: &str, index: usize, reference: u32) -> AuthenticatedQueryBuilderOrigin {
        AuthenticatedQueryBuilderOrigin::Parameter {
            index,
            name: "builder".to_string(),
            declaration: anchor(module, 1, 8),
            reference: anchor(module, reference, reference + 7),
        }
    }

    fn call_argument(
        module: &str,
        start: u32,
        argument_index: usize,
    ) -> AuthenticatedQueryBuilderSink {
        AuthenticatedQueryBuilderSink::CallArgument {
            callsite: anchor(module, start, start + 10),
            callee: "helper".to_string(),
            callee_provenance: anchor(module, start, start + 6),
            argument_index,
            value: anchor(module, start + 7, start + 9),
        }
    }

    fn return_sink(module: &str, start: u32) -> AuthenticatedQueryBuilderSink {
        AuthenticatedQueryBuilderSink::Return {
            site: anchor(module, start, start + 10),
            value: anchor(module, start + 7, start + 9),
        }
    }

    fn flow(
        callable: CallableKey,
        parameter_count: usize,
        paths: Vec<AuthenticatedQueryBuilderPath>,
    ) -> AuthenticatedCallableQueryBuilderFlow {
        let module = callable
            .module
            .strip_prefix("convex/")
            .and_then(|module| module.strip_suffix(".ts"))
            .unwrap()
            .to_string();
        AuthenticatedCallableQueryBuilderFlow {
            authorization_id: format!("flow_{}", callable.unit_id),
            callable,
            callable_source: anchor(&module, 0, 100),
            parameter_count,
            is_async: false,
            paths,
            rejections: Vec::new(),
        }
    }

    fn control_summary() -> CallableControlSummary {
        CallableControlSummary {
            block_count: 1,
            await_count: 0,
            call_count: 1,
            has_choice: false,
            has_cycle: false,
            has_finalization: false,
            has_explicit_exception_path: false,
            has_implicit_error_harness: false,
        }
    }

    fn control_skeleton() -> CallableControlSkeletonCandidate {
        CallableControlSkeletonCandidate {
            callable_start: 0,
            callable_end: 100,
            entry_block: 0,
            blocks: vec![CallableControlBlockCandidate {
                id: 0,
                unreachable: false,
                instructions: Vec::new(),
                successors: Vec::new(),
            }],
            points: Vec::new(),
            intra_block_order: CallableIntraBlockOrder::Unresolved,
        }
    }

    fn control_plan(
        caller: CallableKey,
        module: &str,
        start: u32,
        target: CallableKey,
    ) -> CallableControlPlan {
        CallableControlPlan {
            callable: caller,
            callable_source: anchor(module, 0, 100),
            skeleton: control_skeleton(),
            control: control_summary(),
            source_effects: Vec::new(),
            effects: Vec::new(),
            calls: vec![CallableControlCallPlan {
                callsite: anchor(module, start, start + 10),
                target: target.clone(),
                target_source: anchor(
                    target
                        .module
                        .strip_prefix("convex/")
                        .and_then(|module| module.strip_suffix(".ts"))
                        .unwrap(),
                    0,
                    100,
                ),
                block: 0,
                position: CallPosition::Synchronous,
                dispatch_exact: true,
                arguments_safe: true,
                arguments: (0..4)
                    .map(|index| CallableControlCallArgument {
                        value: if index == 0 {
                            CallableValueFlowCandidate::Expression {
                                range: crate::SourceRange {
                                    start: start + 7,
                                    end: start + 9,
                                },
                            }
                        } else {
                            CallableValueFlowCandidate::LiteralString {
                                value: format!("argument-{index}"),
                            }
                        },
                        provenance: anchor(module, start + 7, start + 9),
                    })
                    .collect(),
            }],
        }
    }

    fn authenticated_flows(source: &str) -> Vec<AuthenticatedCallableQueryBuilderFlow> {
        let module_key = "convex/queryGraphFixture.ts";
        let summary = summarize_module(
            module_key,
            Path::new(module_key),
            source,
            &hash_bytes(source.as_bytes()),
            "query-graph-fixture-cache",
            "query-graph-fixture-pipeline",
            "query-graph-fixture-policy",
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
        crate::query_values::authenticate_callable_query_builder_flows(&modules, &reachable)
            .unwrap()
    }

    #[test]
    fn exact_two_hop_argument_flow_reaches_for_await() {
        let load = key("load");
        let forward = key("forward");
        let consume = key("consume");
        let flows = vec![
            flow(
                load.clone(),
                1,
                vec![AuthenticatedQueryBuilderPath {
                    value_kind: CallableQueryBuilderKind::QueryBuilder,
                    origin: AuthenticatedQueryBuilderOrigin::QueryConstruction {
                        source: query_source("load"),
                    },
                    steps: Vec::new(),
                    sink: call_argument("load", 30, 0),
                }],
            ),
            flow(
                forward.clone(),
                1,
                vec![AuthenticatedQueryBuilderPath {
                    value_kind: CallableQueryBuilderKind::QueryBuilder,
                    origin: parameter("forward", 0, 20),
                    steps: Vec::new(),
                    sink: call_argument("forward", 40, 0),
                }],
            ),
            flow(
                consume.clone(),
                1,
                vec![AuthenticatedQueryBuilderPath {
                    value_kind: CallableQueryBuilderKind::QueryBuilder,
                    origin: parameter("consume", 0, 20),
                    steps: Vec::new(),
                    sink: AuthenticatedQueryBuilderSink::ForAwait {
                        site: anchor("consume", 40, 80),
                        value: anchor("consume", 55, 62),
                        binding: AuthenticatedQueryStreamBinding {
                            name: "row".to_string(),
                            binding: anchor("consume", 45, 48),
                            references: Vec::new(),
                        },
                    },
                }],
            ),
        ];
        let controls = vec![
            control_plan(load.clone(), "load", 30, forward.clone()),
            control_plan(forward.clone(), "forward", 40, consume.clone()),
            CallableControlPlan {
                callable: consume.clone(),
                callable_source: anchor("consume", 0, 100),
                skeleton: control_skeleton(),
                control: control_summary(),
                source_effects: Vec::new(),
                effects: Vec::new(),
                calls: Vec::new(),
            },
        ];
        let graph = build_authenticated_query_builder_graph(&flows, &controls);
        let routes = graph
            .terminal_routes()
            .filter(|route| {
                matches!(
                    route.origin,
                    AuthenticatedQueryBuilderOrigin::QueryConstruction { .. }
                ) && matches!(route.sink, AuthenticatedQueryBuilderSink::ForAwait { .. })
            })
            .collect::<Vec<_>>();
        let [route] = routes.as_slice() else {
            panic!("expected one exact construction-to-stream route: {routes:#?}")
        };
        assert_eq!(route.callable_path, vec![load, forward, consume]);
        assert_eq!(route.callsites.len(), 2);
        let AuthenticatedQueryBuilderOrigin::QueryConstruction { source } = &route.origin else {
            unreachable!()
        };
        assert_eq!(
            source.table.value,
            CallableValueFlowCandidate::LiteralString {
                value: "documents".to_string()
            }
        );
    }

    #[test]
    fn authenticated_inline_range_callback_preserves_existing_query_admission() {
        let flows = authenticated_flows(
            r#"
async function load(ctx, owner) {
  const query = ctx.db.query("documents").withIndex(
    "by_owner",
    (range) => range.eq("owner", owner),
  );
  return await query.collect();
}
"#,
        );
        let controls = flows
            .iter()
            .map(|flow| CallableControlPlan {
                callable: flow.callable.clone(),
                callable_source: flow.callable_source.clone(),
                skeleton: control_skeleton(),
                control: control_summary(),
                source_effects: Vec::new(),
                effects: Vec::new(),
                calls: Vec::new(),
            })
            .collect::<Vec<_>>();
        let graph = build_authenticated_query_builder_graph(&flows, &controls);
        let closed = graph.closed_terminal_routes().collect::<Vec<_>>();
        assert_eq!(closed.len(), 1, "flows={flows:#?}\ngraph={graph:#?}");
        let AuthenticatedQueryBuilderOrigin::QueryConstruction { source } = &closed[0].origin
        else {
            unreachable!()
        };
        assert_eq!(
            source.table.value,
            CallableValueFlowCandidate::LiteralString {
                value: "documents".to_string(),
            }
        );
        assert!(closed[0].steps.iter().any(|step| {
            matches!(
                step,
                AuthenticatedQueryBuilderStep::QueryStage {
                    stage: AuthenticatedQueryStage::WithIndex { constraints, .. },
                    range_callback: None,
                } if constraints.len() == 1
                    && constraints[0].field == "owner"
                    && constraints[0].operator == "eq"
            )
        }));
    }

    #[test]
    fn authenticated_handler_stream_closes_its_inline_range_callback() {
        let flows = authenticated_flows(
            r#"
function enabledName(row) {
  return row.enabled ? row.name : null;
}
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => {
    const planned = ctx.db
      .query("documents")
      .withIndex("by_owner", (range) => range.eq("owner", args.owner));
    for await (const row of planned) {
      const name = enabledName(row);
      if (name !== null) return name;
    }
    return null;
  },
});
"#,
        );
        let controls = flows
            .iter()
            .map(|flow| CallableControlPlan {
                callable: flow.callable.clone(),
                callable_source: flow.callable_source.clone(),
                skeleton: control_skeleton(),
                control: control_summary(),
                source_effects: Vec::new(),
                effects: Vec::new(),
                calls: Vec::new(),
            })
            .collect::<Vec<_>>();
        let graph = build_authenticated_query_builder_graph(&flows, &controls);
        let closed = graph.closed_terminal_routes().collect::<Vec<_>>();
        assert_eq!(closed.len(), 1, "flows={flows:#?}\ngraph={graph:#?}");
        assert!(matches!(
            closed[0].sink,
            AuthenticatedQueryBuilderSink::ForAwait { .. }
        ));
    }

    #[test]
    fn concrete_query_alias_escape_blocks_its_terminal() {
        let flows = authenticated_flows(
            r#"
async function load(ctx, stored) {
  const query = ctx.db.query("documents");
  stored.push(query);
  return await query.collect();
}
"#,
        );
        let controls = flows
            .iter()
            .map(|flow| CallableControlPlan {
                callable: flow.callable.clone(),
                callable_source: flow.callable_source.clone(),
                skeleton: control_skeleton(),
                control: control_summary(),
                source_effects: Vec::new(),
                effects: Vec::new(),
                calls: Vec::new(),
            })
            .collect::<Vec<_>>();
        let graph = build_authenticated_query_builder_graph(&flows, &controls);
        assert_eq!(graph.closed_terminal_routes().count(), 0, "{graph:#?}");
        assert!(graph.blocking_rejections().any(|rejection| {
            rejection
                .reason
                .contains("escapes its authenticated local flow")
        }));
    }

    #[test]
    fn escaped_helper_parameter_blocks_its_concrete_caller() {
        let load = key("escaped_parameter_load");
        let consume = key("escaped_parameter_consume");
        let rejected_parameter = parameter("escaped_parameter_consume", 0, 20);
        let load_flow = flow(
            load.clone(),
            1,
            vec![AuthenticatedQueryBuilderPath {
                value_kind: CallableQueryBuilderKind::QueryBuilder,
                origin: AuthenticatedQueryBuilderOrigin::QueryConstruction {
                    source: query_source("escaped_parameter_load"),
                },
                steps: Vec::new(),
                sink: call_argument("escaped_parameter_load", 30, 0),
            }],
        );
        let mut consume_flow = flow(
            consume.clone(),
            1,
            vec![AuthenticatedQueryBuilderPath {
                value_kind: CallableQueryBuilderKind::QueryBuilder,
                origin: rejected_parameter.clone(),
                steps: Vec::new(),
                sink: AuthenticatedQueryBuilderSink::Terminal {
                    consumer: AuthenticatedQueryConsumer {
                        kind: CallableQueryConsumerKind::Collect,
                        site: anchor("escaped_parameter_consume", 30, 40),
                        receiver: anchor("escaped_parameter_consume", 30, 37),
                        stages: Vec::new(),
                        arguments: Vec::new(),
                        binding_edges: Vec::new(),
                        choices: Vec::new(),
                        static_limit: None,
                        dynamic_limit: false,
                        stream_binding: None,
                    },
                },
            }],
        );
        consume_flow
            .rejections
            .push(AuthenticatedQueryBuilderFlowRejection {
                origin: rejected_parameter,
                provenance: anchor("escaped_parameter_consume", 50, 57),
                reason: "query builder escapes its authenticated local flow".to_string(),
            });
        let controls = vec![
            control_plan(load.clone(), "escaped_parameter_load", 30, consume.clone()),
            CallableControlPlan {
                callable: consume,
                callable_source: anchor("escaped_parameter_consume", 0, 100),
                skeleton: control_skeleton(),
                control: control_summary(),
                source_effects: Vec::new(),
                effects: Vec::new(),
                calls: Vec::new(),
            },
        ];
        let graph = build_authenticated_query_builder_graph(&[load_flow, consume_flow], &controls);
        assert_eq!(graph.closed_terminal_routes().count(), 0, "{graph:#?}");
        assert!(graph.rejections().iter().any(|rejection| {
            rejection.disposition
                == QueryBuilderGraphRejectionDisposition::UnmatchedSpeculativeVariant
        }));
        assert!(
            graph
                .blocking_rejections()
                .any(|rejection| { rejection.reason.contains("no one exact typed continuation") })
        );
    }

    fn range_constraint(module: &str, start: u32, operator: &str) -> AuthenticatedQueryBuilderStep {
        AuthenticatedQueryBuilderStep::IndexConstraint {
            site: anchor(module, start, start + 12),
            receiver: anchor(module, start, start + 5),
            constraint: AuthenticatedQueryIndexConstraint {
                field: "owner".to_string(),
                operator: operator.to_string(),
                value: AuthenticatedQueryValueOperand {
                    value: CallableValueFlowCandidate::Parameter { index: 1 },
                    provenance: anchor(module, start + 10, start + 11),
                },
            },
        }
    }

    #[test]
    fn conditional_range_return_correlates_through_call_result() {
        let load = key("range_load");
        let callback = key("callback");
        let constrain = key("constrain");
        let helper_paths = [("gte", 0usize), ("eq", 1usize)]
            .into_iter()
            .map(|(operator, branch)| AuthenticatedQueryBuilderPath {
                value_kind: CallableQueryBuilderKind::IndexRangeBuilder,
                origin: parameter("constrain", 0, 20 + branch as u32 * 10),
                steps: vec![
                    range_constraint("constrain", 30 + branch as u32 * 15, operator),
                    AuthenticatedQueryBuilderStep::Choice {
                        site: anchor("constrain", 25, 70),
                        branch,
                    },
                ],
                sink: return_sink("constrain", 75),
            })
            .collect();
        let with_index_site = anchor("range_load", 20, 90);
        let with_index_stage = AuthenticatedQueryStage::WithIndex {
            site: with_index_site.clone(),
            receiver: anchor("range_load", 20, 40),
            index: "by_owner".to_string(),
            index_provenance: anchor("range_load", 42, 52),
            constraints: Vec::new(),
        };
        let flows = vec![
            flow(
                load.clone(),
                1,
                vec![AuthenticatedQueryBuilderPath {
                    value_kind: CallableQueryBuilderKind::QueryBuilder,
                    origin: AuthenticatedQueryBuilderOrigin::QueryConstruction {
                        source: query_source("range_load"),
                    },
                    steps: vec![AuthenticatedQueryBuilderStep::QueryStage {
                        stage: with_index_stage.clone(),
                        range_callback: Some(anchor("callback", 0, 100)),
                    }],
                    sink: AuthenticatedQueryBuilderSink::Terminal {
                        consumer: AuthenticatedQueryConsumer {
                            kind: CallableQueryConsumerKind::Collect,
                            site: anchor("range_load", 91, 99),
                            receiver: anchor("range_load", 91, 95),
                            stages: vec![with_index_stage],
                            arguments: Vec::new(),
                            binding_edges: Vec::new(),
                            choices: Vec::new(),
                            static_limit: None,
                            dynamic_limit: false,
                            stream_binding: None,
                        },
                    },
                }],
            ),
            flow(
                callback.clone(),
                1,
                vec![
                    AuthenticatedQueryBuilderPath {
                        value_kind: CallableQueryBuilderKind::IndexRangeBuilder,
                        origin: parameter("callback", 0, 20),
                        steps: Vec::new(),
                        sink: call_argument("callback", 30, 0),
                    },
                    AuthenticatedQueryBuilderPath {
                        value_kind: CallableQueryBuilderKind::IndexRangeBuilder,
                        origin: AuthenticatedQueryBuilderOrigin::CallResult {
                            callsite: anchor("callback", 30, 40),
                            callee: "constrain".to_string(),
                            callee_provenance: anchor("callback", 30, 36),
                        },
                        steps: Vec::new(),
                        sink: AuthenticatedQueryBuilderSink::WithIndexRangeReturn {
                            site: anchor("callback", 0, 100),
                            value: anchor("callback", 30, 40),
                            with_index_site: with_index_site.clone(),
                        },
                    },
                ],
            ),
            flow(constrain.clone(), 4, helper_paths),
        ];
        let controls = vec![
            control_plan(callback.clone(), "callback", 30, constrain.clone()),
            CallableControlPlan {
                callable: constrain,
                callable_source: anchor("constrain", 0, 100),
                skeleton: control_skeleton(),
                control: control_summary(),
                source_effects: Vec::new(),
                effects: Vec::new(),
                calls: Vec::new(),
            },
        ];
        let graph = build_authenticated_query_builder_graph(&flows, &controls);
        let routes = graph
            .terminal_routes()
            .filter(|route| {
                route.origin_callable == callback
                    && matches!(
                        route.origin,
                        AuthenticatedQueryBuilderOrigin::Parameter { index: 0, .. }
                    )
                    && matches!(
                        route.sink,
                        AuthenticatedQueryBuilderSink::WithIndexRangeReturn { .. }
                    )
            })
            .collect::<Vec<_>>();
        assert_eq!(routes.len(), 2, "{routes:#?}");
        assert_eq!(
            routes
                .iter()
                .map(|route| route
                    .steps
                    .iter()
                    .find_map(|step| match step {
                        AuthenticatedQueryBuilderStep::Choice { branch, .. } => Some(*branch),
                        _ => None,
                    })
                    .unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1])
        );
        assert!(routes.iter().all(|route| {
            route.steps.iter().any(|step| match step {
                AuthenticatedQueryBuilderStep::IndexConstraint { constraint, .. } => {
                    constraint.value.value
                        == CallableValueFlowCandidate::LiteralString {
                            value: "argument-1".to_string(),
                        }
                        && constraint.value.provenance == anchor("callback", 37, 39)
                }
                _ => false,
            })
        }));

        let query_routes = graph
            .terminal_routes()
            .filter(|route| {
                route.origin_callable == load
                    && matches!(
                        route.origin,
                        AuthenticatedQueryBuilderOrigin::QueryConstruction { .. }
                    )
                    && matches!(route.sink, AuthenticatedQueryBuilderSink::Terminal { .. })
            })
            .collect::<Vec<_>>();
        assert_eq!(query_routes.len(), 2, "{query_routes:#?}");
        assert_eq!(
            query_routes
                .iter()
                .map(|route| {
                    route
                        .steps
                        .iter()
                        .find_map(|step| match step {
                            AuthenticatedQueryBuilderStep::QueryStage {
                                stage: AuthenticatedQueryStage::WithIndex { constraints, .. },
                                range_callback: None,
                            } => Some(constraints[0].operator.clone()),
                            _ => None,
                        })
                        .unwrap()
                })
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["eq".to_string(), "gte".to_string()])
        );

        let open_query = graph
            .routes()
            .find(|route| {
                route.origin_callable == load
                    && route.steps.iter().any(|step| {
                        matches!(
                            step,
                            AuthenticatedQueryBuilderStep::QueryStage {
                                range_callback: Some(_),
                                ..
                            }
                        )
                    })
            })
            .unwrap()
            .clone();
        let range_for = |operator: &str| {
            routes
                .iter()
                .copied()
                .find(|route| {
                    route.steps.iter().any(|step| {
                        matches!(
                            step,
                            AuthenticatedQueryBuilderStep::IndexConstraint { constraint, .. }
                                if constraint.operator == operator
                        )
                    })
                })
                .unwrap()
        };
        let eq_constraint = range_for("eq")
            .steps
            .iter()
            .find_map(|step| match step {
                AuthenticatedQueryBuilderStep::IndexConstraint { constraint, .. } => {
                    Some(constraint.clone())
                }
                _ => None,
            })
            .unwrap();
        let mut legacy_query = open_query;
        for step in &mut legacy_query.steps {
            if let AuthenticatedQueryBuilderStep::QueryStage {
                stage: AuthenticatedQueryStage::WithIndex { constraints, .. },
                ..
            } = step
            {
                *constraints = vec![eq_constraint.clone()];
            }
        }
        let AuthenticatedQueryBuilderSink::Terminal { consumer } = &mut legacy_query.sink else {
            unreachable!()
        };
        let AuthenticatedQueryStage::WithIndex { constraints, .. } = &mut consumer.stages[0] else {
            unreachable!()
        };
        *constraints = vec![eq_constraint];
        assert!(close_with_index_range(&legacy_query, range_for("eq")).is_some());
        assert!(close_with_index_range(&legacy_query, range_for("gte")).is_none());
    }

    #[test]
    fn inexact_dispatch_does_not_create_a_transitive_route() {
        let load = key("inexact_load");
        let consume = key("inexact_consume");
        let flows = vec![
            flow(
                load.clone(),
                1,
                vec![AuthenticatedQueryBuilderPath {
                    value_kind: CallableQueryBuilderKind::QueryBuilder,
                    origin: AuthenticatedQueryBuilderOrigin::QueryConstruction {
                        source: query_source("inexact_load"),
                    },
                    steps: Vec::new(),
                    sink: call_argument("inexact_load", 30, 0),
                }],
            ),
            flow(
                consume.clone(),
                1,
                vec![AuthenticatedQueryBuilderPath {
                    value_kind: CallableQueryBuilderKind::QueryBuilder,
                    origin: parameter("inexact_consume", 0, 20),
                    steps: Vec::new(),
                    sink: AuthenticatedQueryBuilderSink::ForAwait {
                        site: anchor("inexact_consume", 40, 80),
                        value: anchor("inexact_consume", 55, 62),
                        binding: AuthenticatedQueryStreamBinding {
                            name: "row".to_string(),
                            binding: anchor("inexact_consume", 45, 48),
                            references: Vec::new(),
                        },
                    },
                }],
            ),
        ];
        let mut control = control_plan(load, "inexact_load", 30, consume);
        control.calls[0].dispatch_exact = false;
        let graph = build_authenticated_query_builder_graph(&flows, [&control]);
        assert!(!graph.terminal_routes().any(|route| matches!(
            route.origin,
            AuthenticatedQueryBuilderOrigin::QueryConstruction { .. }
        )));
        assert!(
            graph
                .rejections()
                .iter()
                .any(|rejection| rejection.reason.contains("no one exact typed continuation"))
        );
        assert!(graph.blocking_rejections().next().is_some());
        assert!(graph.rejections().iter().all(|rejection| {
            rejection.disposition == QueryBuilderGraphRejectionDisposition::AuthorizationBlocking
        }));
    }

    #[test]
    fn unmatched_concrete_source_connector_blocks_its_other_terminal() {
        let load = key("mixed_load");
        let source = query_source("mixed_load");
        let flows = vec![flow(
            load.clone(),
            1,
            vec![
                AuthenticatedQueryBuilderPath {
                    value_kind: CallableQueryBuilderKind::QueryBuilder,
                    origin: AuthenticatedQueryBuilderOrigin::QueryConstruction {
                        source: source.clone(),
                    },
                    steps: Vec::new(),
                    sink: AuthenticatedQueryBuilderSink::Terminal {
                        consumer: AuthenticatedQueryConsumer {
                            kind: CallableQueryConsumerKind::Collect,
                            site: anchor("mixed_load", 21, 29),
                            receiver: anchor("mixed_load", 21, 25),
                            stages: Vec::new(),
                            arguments: Vec::new(),
                            binding_edges: Vec::new(),
                            choices: Vec::new(),
                            static_limit: None,
                            dynamic_limit: false,
                            stream_binding: None,
                        },
                    },
                },
                AuthenticatedQueryBuilderPath {
                    value_kind: CallableQueryBuilderKind::QueryBuilder,
                    origin: AuthenticatedQueryBuilderOrigin::QueryConstruction { source },
                    steps: Vec::new(),
                    sink: call_argument("mixed_load", 30, 0),
                },
            ],
        )];
        let control = CallableControlPlan {
            callable: load,
            callable_source: anchor("mixed_load", 0, 100),
            skeleton: control_skeleton(),
            control: control_summary(),
            source_effects: Vec::new(),
            effects: Vec::new(),
            calls: Vec::new(),
        };
        let graph = build_authenticated_query_builder_graph(&flows, [&control]);
        assert_eq!(graph.closed_terminal_routes().count(), 0);
        assert_eq!(graph.blocking_rejections().count(), 1);
        assert!(graph.rejections().iter().all(|rejection| {
            rejection.disposition == QueryBuilderGraphRejectionDisposition::AuthorizationBlocking
        }));
    }
}
