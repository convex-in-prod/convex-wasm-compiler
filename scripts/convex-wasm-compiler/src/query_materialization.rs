use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};

use super::callable_plans::query_value_graph::AuthenticatedQueryBuilderRoute;
use super::callable_plans::{CallableEffectPlanIndex, CallableValueFlowCandidate};
use super::capability_flow::{CapabilityFlowProof, CapabilityOwner};
use super::effect_plan::SourceAnchor;
use super::query_values::{
    AuthenticatedCallableQueryValuePlan, AuthenticatedQueryBuilderOrigin,
    AuthenticatedQueryBuilderSink, AuthenticatedQueryBuilderStep, AuthenticatedQueryConsumer,
    AuthenticatedQueryIndexConstraint, AuthenticatedQueryStage, CallableQueryBuilderKind,
    CallableQueryCapabilityKind, CallableQueryConsumerKind,
};
use super::{
    AdmittedIndexConstraint, AdmittedOperation, OperationIdentity, ReachableUnit, hash_bytes,
    line_column, module_source, source_slice,
};

pub(super) type RepresentedQueryConstruction = (String, String, (u32, u32));

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizedQueryConstraint {
    field: String,
    operator: String,
    value: SourceAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizedQueryConsumerDescriptor {
    owner_unit_id: String,
    consumer: SourceAnchor,
    kind: CallableQueryConsumerKind,
    table: String,
    index: String,
    constraints: Vec<AuthorizedQueryConstraint>,
    order: String,
    limit: Option<u32>,
    limit_argument: Option<SourceAnchor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizedQueryValuePlan {
    authorization_id: String,
    construction: SourceAnchor,
    source_owner_unit_id: String,
    consumers: Vec<AuthorizedQueryConsumerDescriptor>,
}

#[derive(Default)]
pub(super) struct AuthorizedQueryValueIndex {
    plans: Vec<AuthorizedQueryValuePlan>,
}

impl AuthorizedQueryValueIndex {
    pub(super) fn construction_identities(&self) -> BTreeSet<OperationIdentity> {
        self.plans
            .iter()
            .map(|plan| {
                (
                    plan.construction.module.clone(),
                    plan.construction.start,
                    plan.construction.end,
                )
            })
            .collect()
    }

    pub(super) fn represented_constructions(&self) -> BTreeSet<RepresentedQueryConstruction> {
        self.plans
            .iter()
            .map(|plan| {
                (
                    plan.construction.module.clone(),
                    plan.source_owner_unit_id.clone(),
                    (plan.construction.start, plan.construction.end),
                )
            })
            .collect()
    }

    pub(super) fn result_consumer_identities(&self) -> BTreeSet<OperationIdentity> {
        self.plans
            .iter()
            .flat_map(|plan| &plan.consumers)
            .map(|consumer| {
                (
                    consumer.consumer.module.clone(),
                    consumer.consumer.start,
                    consumer.consumer.end,
                )
            })
            .collect()
    }

    pub(super) fn result_consumers(
        &self,
    ) -> impl Iterator<Item = AuthorizedQueryResultConsumer<'_>> {
        self.plans.iter().flat_map(|plan| {
            plan.consumers
                .iter()
                .map(move |consumer| AuthorizedQueryResultConsumer {
                    authorization_id: &plan.authorization_id,
                    owner_unit_id: &consumer.owner_unit_id,
                    consumer: &consumer.consumer,
                    kind: consumer.kind,
                    table: &consumer.table,
                })
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct AuthorizedQueryResultConsumer<'a> {
    pub(super) authorization_id: &'a str,
    pub(super) owner_unit_id: &'a str,
    pub(super) consumer: &'a SourceAnchor,
    pub(super) kind: CallableQueryConsumerKind,
    pub(super) table: &'a str,
}

fn anchor_contains(container: &SourceAnchor, value: &SourceAnchor) -> bool {
    container.module == value.module
        && container.source_sha256 == value.source_sha256
        && container.start <= value.start
        && value.end <= container.end
}

fn authenticated_source_identity(
    modules: &BTreeMap<String, super::LoadedModule>,
    anchor: &SourceAnchor,
) -> Result<bool> {
    let source = module_source(modules, &anchor.module)?;
    Ok(hash_bytes(source.as_bytes()) == anchor.source_sha256
        && hash_bytes(source_slice(&source, anchor.start, anchor.end)?.as_bytes())
            == anchor.slice_sha256)
}

fn literal_string(value: &CallableValueFlowCandidate) -> Option<&str> {
    match value {
        CallableValueFlowCandidate::LiteralString { value } if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn constraints_match_host_contract(constraints: &[AuthenticatedQueryIndexConstraint]) -> bool {
    if constraints.is_empty() {
        return false;
    }
    let mut fields = BTreeSet::new();
    let mut saw_range = false;
    for (index, constraint) in constraints.iter().enumerate() {
        if constraint.field.is_empty() || !fields.insert(constraint.field.clone()) {
            return false;
        }
        match constraint.operator.as_str() {
            "eq" if !saw_range => {}
            "gt" | "gte" | "lt" | "lte" if !saw_range && index + 1 == constraints.len() => {
                saw_range = true;
            }
            _ => return false,
        }
    }
    true
}

fn consumer_descriptor(
    plan: &AuthenticatedCallableQueryValuePlan,
    consumer: &AuthenticatedQueryConsumer,
    owner_unit_id: String,
) -> Option<AuthorizedQueryConsumerDescriptor> {
    let (limit, limit_argument) = match consumer.kind {
        CallableQueryConsumerKind::Take => {
            let [argument] = consumer.arguments.as_slice() else {
                return None;
            };
            match (consumer.static_limit, consumer.dynamic_limit) {
                (Some(limit), false) => (Some(limit), None),
                (None, true) => (None, Some(argument.provenance.clone())),
                _ => return None,
            }
        }
        CallableQueryConsumerKind::Collect
        | CallableQueryConsumerKind::First
        | CallableQueryConsumerKind::Unique
        | CallableQueryConsumerKind::Stream
            if consumer.arguments.is_empty()
                && consumer.static_limit.is_none()
                && !consumer.dynamic_limit =>
        {
            (None, None)
        }
        CallableQueryConsumerKind::Paginate
            if consumer.arguments.len() == 1
                && consumer.static_limit.is_none()
                && !consumer.dynamic_limit =>
        {
            (None, None)
        }
        _ => return None,
    };
    let table = literal_string(&plan.source.table.value)?.to_string();
    let mut with_index = None;
    let mut order = "ascending".to_string();
    let mut saw_order = false;
    for stage in &consumer.stages {
        match stage {
            AuthenticatedQueryStage::WithIndex {
                index, constraints, ..
            } if with_index.is_none()
                && !saw_order
                && !index.is_empty()
                && constraints_match_host_contract(constraints) =>
            {
                with_index = Some((index.clone(), constraints));
            }
            AuthenticatedQueryStage::Order { direction, .. }
                if with_index.is_some() && !saw_order =>
            {
                order = match literal_string(&direction.value)? {
                    "asc" => "ascending".to_string(),
                    "desc" => "descending".to_string(),
                    _ => return None,
                };
                saw_order = true;
            }
            _ => return None,
        }
    }
    let (index, constraints) = with_index?;
    Some(AuthorizedQueryConsumerDescriptor {
        owner_unit_id,
        consumer: consumer.site.clone(),
        kind: consumer.kind,
        table,
        index,
        constraints: constraints
            .iter()
            .map(|constraint| AuthorizedQueryConstraint {
                field: constraint.field.clone(),
                operator: constraint.operator.clone(),
                value: constraint.value.provenance.clone(),
            })
            .collect(),
        order,
        limit,
        limit_argument,
    })
}

fn query_consumer_from_route(
    route: &AuthenticatedQueryBuilderRoute,
) -> Option<AuthenticatedQueryConsumer> {
    if route.value_kind != CallableQueryBuilderKind::QueryBuilder {
        return None;
    }
    let stages = route
        .steps
        .iter()
        .filter_map(|step| match step {
            AuthenticatedQueryBuilderStep::QueryStage {
                stage,
                range_callback: None,
            } => Some(stage.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let binding_edges = route
        .steps
        .iter()
        .filter_map(|step| match step {
            AuthenticatedQueryBuilderStep::Alias { edge } => Some(edge.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut choices = Vec::new();
    for choice in route.steps.iter().filter_map(|step| match step {
        AuthenticatedQueryBuilderStep::Choice { site, .. } => Some(site),
        _ => None,
    }) {
        if !choices.contains(choice) {
            choices.push(choice.clone());
        }
    }
    match &route.sink {
        AuthenticatedQueryBuilderSink::Terminal { consumer } => {
            let mut consumer = consumer.clone();
            consumer.stages = stages;
            consumer.binding_edges = binding_edges;
            consumer.choices = choices;
            Some(consumer)
        }
        AuthenticatedQueryBuilderSink::ForAwait {
            site,
            value,
            binding,
        } => Some(AuthenticatedQueryConsumer {
            kind: CallableQueryConsumerKind::Stream,
            site: site.clone(),
            receiver: value.clone(),
            stages,
            arguments: Vec::new(),
            binding_edges,
            choices,
            static_limit: None,
            dynamic_limit: false,
            stream_binding: Some(binding.clone()),
        }),
        AuthenticatedQueryBuilderSink::CallArgument { .. }
        | AuthenticatedQueryBuilderSink::CallResult { .. }
        | AuthenticatedQueryBuilderSink::Return { .. }
        | AuthenticatedQueryBuilderSink::WithIndexRangeReturn { .. } => None,
    }
}

fn closed_query_variants<'a>(
    callable_plans: &'a CallableEffectPlanIndex,
) -> Result<
    Vec<(
        &'a AuthenticatedCallableQueryValuePlan,
        Vec<AuthenticatedQueryConsumer>,
    )>,
> {
    let mut source_plans = BTreeMap::new();
    for plan in callable_plans.query_value_plans() {
        let key = (
            plan.source.construction.module.clone(),
            plan.source.construction.start,
            plan.source.construction.end,
        );
        let previous = source_plans.insert(key, plan);
        ensure!(
            previous.is_none(),
            "query construction has more than one authenticated source plan"
        );
    }

    let mut closed = BTreeMap::<
        (String, u32, u32),
        (
            &AuthenticatedCallableQueryValuePlan,
            Vec<AuthenticatedQueryConsumer>,
        ),
    >::new();
    for route in callable_plans
        .query_builder_graph()
        .closed_terminal_routes()
    {
        let AuthenticatedQueryBuilderOrigin::QueryConstruction { source } = &route.origin else {
            continue;
        };
        let key = (
            source.construction.module.clone(),
            source.construction.start,
            source.construction.end,
        );
        let plan = source_plans
            .get(&key)
            .context("closed query-builder route lost its authenticated source plan")?;
        ensure!(
            route.origin_callable == plan.callable
                && route.origin_callable_source == plan.callable_source
                && source == &plan.source,
            "closed query-builder route disagrees with its authenticated source plan"
        );
        let Some(consumer) = query_consumer_from_route(route) else {
            continue;
        };
        let (retained_plan, consumers) = closed.entry(key).or_insert_with(|| (*plan, Vec::new()));
        ensure!(
            retained_plan.authorization_id == plan.authorization_id,
            "closed query variants disagree about source authorization"
        );
        if !consumers.contains(&consumer) {
            consumers.push(consumer);
        }
    }
    Ok(closed.into_values().collect())
}

fn consumer_owner_unit_id(
    reachable: &BTreeMap<String, ReachableUnit>,
    consumer: &SourceAnchor,
) -> Option<String> {
    let mut owners = reachable
        .values()
        .filter(|unit| {
            unit.module == consumer.module
                && consumer.start >= unit.start
                && consumer.end <= unit.end
        })
        .collect::<Vec<_>>();
    owners.sort_by_key(|unit| {
        (
            unit.end - unit.start,
            unit.start,
            unit.end,
            unit.id.as_str(),
        )
    });
    let owner = owners.first()?;
    if owners.get(1).is_some_and(|next| {
        next.start == owner.start && next.end == owner.end && next.id != owner.id
    }) {
        return None;
    }
    Some(owner.id.clone())
}

fn value_flow_matches_owner(
    plan: &AuthenticatedCallableQueryValuePlan,
    owner: &CapabilityOwner,
    target: &ReachableUnit,
) -> bool {
    match &plan.source.capability {
        CallableValueFlowCandidate::Parameter { index } => {
            owner.parameter_index == Some(*index)
                || (owner.parameter_index.is_none() && target.kind == "handler")
        }
        CallableValueFlowCandidate::CapturedBinding {
            name,
            declaration_start,
        } => name == &owner.name && *declaration_start == owner.binding_start,
        CallableValueFlowCandidate::LiteralString { .. }
        | CallableValueFlowCandidate::Expression { .. } => false,
    }
}

fn provider_kind_matches(
    plan: &AuthenticatedCallableQueryValuePlan,
    owner: &CapabilityOwner,
) -> bool {
    match plan.source.capability_kind {
        CallableQueryCapabilityKind::ContextDatabase => owner.argument_projection.is_empty(),
        // Provider kind is currently retained only by an exact `db` projection owner. A direct
        // helper parameter that receives `ctx.db` loses that lineage in capability flow, so it
        // remains fail-closed until the proof carries provider kinds across parameter edges.
        CallableQueryCapabilityKind::Database => {
            owner.argument_projection.last().map(String::as_str) == Some("db")
        }
    }
}

fn owner_authorizes_plan(
    plan: &AuthenticatedCallableQueryValuePlan,
    owner: &CapabilityOwner,
    reachable: &BTreeMap<String, ReachableUnit>,
) -> Result<bool> {
    let binding = &plan.source.capability_binding;
    if owner.module != binding.module
        || owner.binding_start != binding.start
        || owner.name != plan.source.capability_name
        || binding.slice_sha256 != hash_bytes(owner.name.as_bytes())
        || plan.source.capability_reference.slice_sha256 != hash_bytes(owner.name.as_bytes())
        || !provider_kind_matches(plan, owner)
    {
        return Ok(false);
    }
    let target = reachable
        .get(&owner.unit_id)
        .context("owned query provider target unit disappeared")?;
    if target.module != owner.module
        || binding.start < target.start
        || binding.end > target.end
        || plan.callable_source.module != target.module
        || plan.callable_source.start < target.start
        || plan.callable_source.end > target.end
        || !anchor_contains(&plan.callable_source, &plan.source.construction)
        || !value_flow_matches_owner(plan, owner, target)
        || !owner.references.iter().any(|reference| {
            reference.name == owner.name
                && reference.start == plan.source.capability_reference.start
                && reference.end == plan.source.capability_reference.end
                && reference.read
                && !reference.write
        })
    {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn authorize_query_value_plans(
    _modules: &BTreeMap<String, super::LoadedModule>,
    proof: &CapabilityFlowProof,
    reachable: &BTreeMap<String, ReachableUnit>,
    callable_plans: &CallableEffectPlanIndex,
) -> Result<AuthorizedQueryValueIndex> {
    let mut authorized = Vec::new();
    for (plan, plan_consumers) in closed_query_variants(callable_plans)? {
        let mut consumers = Vec::new();
        let mut complete = true;
        for consumer in &plan_consumers {
            let Some(owner_unit_id) = consumer_owner_unit_id(reachable, &consumer.site) else {
                complete = false;
                break;
            };
            let Some(descriptor) = consumer_descriptor(plan, consumer, owner_unit_id) else {
                complete = false;
                break;
            };
            consumers.push(descriptor);
        }
        if !complete || consumers.is_empty() || consumers.len() != plan_consumers.len() {
            continue;
        }
        let mut owners = Vec::new();
        for owner in proof.owned_capabilities() {
            if owner_authorizes_plan(plan, owner, reachable)? {
                owners.push(owner);
            }
        }
        let [owner] = owners.as_slice() else {
            continue;
        };
        authorized.push(AuthorizedQueryValuePlan {
            authorization_id: plan.authorization_id.clone(),
            construction: plan.source.construction.clone(),
            source_owner_unit_id: owner.unit_id.clone(),
            consumers,
        });
    }
    authorized.sort_by_key(|plan| {
        (
            plan.construction.module.clone(),
            plan.construction.start,
            plan.construction.end,
            plan.authorization_id.clone(),
        )
    });
    Ok(AuthorizedQueryValueIndex { plans: authorized })
}

fn operation_matches_consumer(
    operation: &AdmittedOperation,
    consumer: &AuthorizedQueryConsumerDescriptor,
) -> bool {
    operation.kind == "databaseIndexQuery"
        && operation.file == consumer.consumer.module
        && operation.start == consumer.consumer.start
        && operation.end == consumer.consumer.end
        && operation.table.as_deref() == Some(consumer.table.as_str())
        && operation.index.as_deref() == Some(consumer.index.as_str())
        && operation.order.as_deref() == Some(consumer.order.as_str())
        && operation.terminal.as_deref() == Some(consumer.kind.descriptor_terminal())
        && operation.limit == consumer.limit
        && operation.limit_argument_index
            == consumer
                .limit_argument
                .as_ref()
                .and_then(|_| u32::try_from(consumer.constraints.len()).ok())
        && operation.index_constraints.len() == consumer.constraints.len()
        && operation
            .index_constraints
            .iter()
            .zip(&consumer.constraints)
            .all(|(operation, consumer)| {
                operation.field == consumer.field && operation.operator == consumer.operator
            })
}

pub(super) fn materialize_authorized_query_values(
    modules: &BTreeMap<String, super::LoadedModule>,
    index: &AuthorizedQueryValueIndex,
    authorized_constructions: &BTreeSet<OperationIdentity>,
    operations: &mut Vec<AdmittedOperation>,
) -> Result<()> {
    ensure!(
        index.construction_identities() == *authorized_constructions,
        "authorized query-value identities disagree with their authenticated plans"
    );
    for plan in &index.plans {
        for consumer in &plan.consumers {
            ensure!(
                authenticated_source_identity(modules, &consumer.consumer)?,
                "authorized query consumer changed source identity"
            );
            if operations
                .iter()
                .any(|operation| operation_matches_consumer(operation, consumer))
            {
                continue;
            }
            let constraints = consumer
                .constraints
                .iter()
                .map(|constraint| {
                    ensure!(
                        authenticated_source_identity(modules, &constraint.value)?,
                        "authorized query constraint changed source identity"
                    );
                    let source = module_source(modules, &constraint.value.module)?;
                    Ok(AdmittedIndexConstraint {
                        field: constraint.field.clone(),
                        operator: constraint.operator.clone(),
                        value_source: source_slice(
                            &source,
                            constraint.value.start,
                            constraint.value.end,
                        )?
                        .to_string(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let semantic_key = serde_json::to_vec(&(
                "authorized-query-result",
                &consumer.table,
                &consumer.index,
                consumer
                    .constraints
                    .iter()
                    .map(|constraint| (&constraint.field, &constraint.operator))
                    .collect::<Vec<_>>(),
                &consumer.order,
                consumer.kind.terminal(),
                consumer.limit,
                consumer.limit_argument.is_some(),
            ))?;
            let source = module_source(modules, &consumer.consumer.module)?;
            let (line, column) = line_column(&source, consumer.consumer.start);
            operations.push(AdmittedOperation {
                id: u32::try_from(operations.len() + 1)?,
                stable_key: format!("op_{}", &hash_bytes(&semantic_key)[..16]),
                kind: "databaseIndexQuery".to_string(),
                table: Some(consumer.table.clone()),
                index: Some(consumer.index.clone()),
                index_constraints: constraints,
                order: Some(consumer.order.clone()),
                terminal: Some(consumer.kind.descriptor_terminal().to_string()),
                limit: consumer.limit,
                limit_argument_index: consumer
                    .limit_argument
                    .as_ref()
                    .map(|_| u32::try_from(consumer.constraints.len()))
                    .transpose()?,
                algorithm: None,
                function_reference: None,
                contract_version: None,
                selector: None,
                file: consumer.consumer.module.clone(),
                start: consumer.consumer.start,
                end: consumer.consumer.end,
                line,
                column,
                source: source_slice(&source, consumer.consumer.start, consumer.consumer.end)?
                    .to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReferenceOccurrence;
    use crate::callable_plans::CallableValueFlowCandidate;
    use crate::effect_plan::CallableKey;
    use crate::query_values::{
        AuthenticatedQuerySource, AuthenticatedQueryStreamBinding,
        AuthenticatedQueryStreamReference, AuthenticatedQueryValueOperand,
    };

    const MODULE: &str = "convex/queryMaterialization.ts";
    const SOURCE_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn anchor(start: u32, end: u32, slice: &str) -> SourceAnchor {
        SourceAnchor {
            module: MODULE.to_string(),
            source_sha256: SOURCE_SHA256.to_string(),
            start,
            end,
            slice_sha256: hash_bytes(slice.as_bytes()),
        }
    }

    fn constraint(field: &str, operator: &str, start: u32) -> AuthenticatedQueryIndexConstraint {
        AuthenticatedQueryIndexConstraint {
            field: field.to_string(),
            operator: operator.to_string(),
            value: AuthenticatedQueryValueOperand {
                value: CallableValueFlowCandidate::Expression {
                    range: crate::SourceRange {
                        start,
                        end: start + 5,
                    },
                },
                provenance: anchor(start, start + 5, "value"),
            },
        }
    }

    fn consumer(
        kind: CallableQueryConsumerKind,
        constraints: Vec<AuthenticatedQueryIndexConstraint>,
    ) -> AuthenticatedQueryConsumer {
        let (arguments, static_limit, dynamic_limit, stream_binding) = match kind {
            CallableQueryConsumerKind::Take => (
                vec![AuthenticatedQueryValueOperand {
                    value: CallableValueFlowCandidate::Parameter { index: 1 },
                    provenance: anchor(145, 150, "limit"),
                }],
                None,
                true,
                None,
            ),
            CallableQueryConsumerKind::Stream => (
                Vec::new(),
                None,
                false,
                Some(AuthenticatedQueryStreamBinding {
                    name: "row".to_string(),
                    binding: anchor(120, 123, "row"),
                    references: vec![AuthenticatedQueryStreamReference {
                        provenance: anchor(130, 133, "row"),
                        read: true,
                        write: false,
                    }],
                }),
            ),
            CallableQueryConsumerKind::Paginate => (
                vec![AuthenticatedQueryValueOperand {
                    value: CallableValueFlowCandidate::Parameter { index: 1 },
                    provenance: anchor(145, 162, "paginationOptions"),
                }],
                None,
                false,
                None,
            ),
            _ => (Vec::new(), None, false, None),
        };
        AuthenticatedQueryConsumer {
            kind,
            site: anchor(100, 170, "consumer"),
            receiver: anchor(100, 110, "query"),
            stages: vec![AuthenticatedQueryStage::WithIndex {
                site: anchor(20, 90, "withIndex"),
                receiver: anchor(20, 40, "query"),
                index: "by_owner".to_string(),
                index_provenance: anchor(45, 55, "by_owner"),
                constraints,
            }],
            arguments,
            binding_edges: Vec::new(),
            choices: Vec::new(),
            static_limit,
            dynamic_limit,
            stream_binding,
        }
    }

    fn plan(consumers: Vec<AuthenticatedQueryConsumer>) -> AuthenticatedCallableQueryValuePlan {
        AuthenticatedCallableQueryValuePlan {
            authorization_id: "query_test".to_string(),
            callable: CallableKey {
                module: MODULE.to_string(),
                unit_id: format!("{MODULE}:0:200"),
            },
            callable_source: anchor(0, 200, "callable"),
            source: AuthenticatedQuerySource {
                construction: anchor(10, 40, "ctx.db.query"),
                callee: anchor(10, 30, "ctx.db.query"),
                capability_kind: CallableQueryCapabilityKind::ContextDatabase,
                capability: CallableValueFlowCandidate::Parameter { index: 0 },
                capability_reference: anchor(10, 13, "ctx"),
                capability_binding: anchor(1, 4, "ctx"),
                capability_name: "ctx".to_string(),
                table: AuthenticatedQueryValueOperand {
                    value: CallableValueFlowCandidate::LiteralString {
                        value: "documents".to_string(),
                    },
                    provenance: anchor(31, 38, "documents"),
                },
            },
            consumers,
            forwards: Vec::new(),
            locally_closed: true,
            closed: true,
            rejections: Vec::new(),
        }
    }

    #[test]
    fn executable_wave_accepts_authenticated_paginate_and_other_query_terminals() {
        let constraints = vec![constraint("owner", "eq", 60)];
        for kind in [
            CallableQueryConsumerKind::Collect,
            CallableQueryConsumerKind::First,
            CallableQueryConsumerKind::Unique,
            CallableQueryConsumerKind::Take,
            CallableQueryConsumerKind::Paginate,
            CallableQueryConsumerKind::Stream,
        ] {
            let plan = plan(vec![consumer(kind, constraints.clone())]);
            let descriptor = consumer_descriptor(&plan, &plan.consumers[0], "handler".to_string())
                .expect("authenticated terminal should materialize provisionally");
            assert_eq!(descriptor.kind, kind);
        }
    }

    #[test]
    fn host_constraint_boundary_accepts_range_only_and_rejects_multi_range_or_duplicates() {
        assert!(!constraints_match_host_contract(&[]));
        assert!(constraints_match_host_contract(&[constraint(
            "updated", "gte", 50
        )]));
        assert!(constraints_match_host_contract(&[
            constraint("owner", "eq", 50),
            constraint("updated", "lt", 60),
        ]));
        assert!(!constraints_match_host_contract(&[
            constraint("updated", "gte", 50),
            constraint("updated_max", "lt", 60),
        ]));
        assert!(!constraints_match_host_contract(&[
            constraint("owner", "eq", 50),
            constraint("owner", "eq", 60),
        ]));
    }

    #[test]
    fn provider_authority_requires_the_exact_owned_binding_read_and_provider_kind() {
        let plan = plan(vec![consumer(
            CallableQueryConsumerKind::Stream,
            Vec::new(),
        )]);
        let target = ReachableUnit {
            id: "handler".to_string(),
            module: MODULE.to_string(),
            name: "selected".to_string(),
            start: 0,
            end: 200,
            source: String::new(),
            kind: "handler".to_string(),
            dependency_chain: Vec::new(),
            dependencies: BTreeMap::new(),
        };
        let reachable = BTreeMap::from([(target.id.clone(), target)]);
        let owner = CapabilityOwner {
            module: MODULE.to_string(),
            unit_id: "handler".to_string(),
            binding_start: 1,
            parameter_index: None,
            argument_projection: Vec::new(),
            name: "ctx".to_string(),
            references: vec![ReferenceOccurrence {
                name: "ctx".to_string(),
                start: 10,
                end: 13,
                read: true,
                write: false,
            }],
            dependency_chain: Vec::new(),
        };
        assert!(owner_authorizes_plan(&plan, &owner, &reachable).unwrap());

        let mut shadowed = owner.clone();
        shadowed.binding_start = 2;
        assert!(!owner_authorizes_plan(&plan, &shadowed, &reachable).unwrap());

        let mut write = owner.clone();
        write.references[0].write = true;
        assert!(!owner_authorizes_plan(&plan, &write, &reachable).unwrap());

        let mut database_plan = plan.clone();
        database_plan.source.capability_kind = CallableQueryCapabilityKind::Database;
        assert!(!owner_authorizes_plan(&database_plan, &owner, &reachable).unwrap());
    }

    #[test]
    fn result_consumers_preserve_terminal_and_exact_table_provenance() {
        let stream = consumer_descriptor(
            &plan(vec![consumer(
                CallableQueryConsumerKind::Stream,
                vec![constraint("owner", "eq", 60)],
            )]),
            &consumer(
                CallableQueryConsumerKind::Stream,
                vec![constraint("owner", "eq", 60)],
            ),
            "helper".to_string(),
        )
        .unwrap();
        let index = AuthorizedQueryValueIndex {
            plans: vec![AuthorizedQueryValuePlan {
                authorization_id: "query_test".to_string(),
                construction: anchor(10, 40, "ctx.db.query"),
                source_owner_unit_id: "handler".to_string(),
                consumers: vec![stream],
            }],
        };
        let consumers = index.result_consumers().collect::<Vec<_>>();
        assert_eq!(consumers.len(), 1);
        assert_eq!(consumers[0].kind, CallableQueryConsumerKind::Stream);
        assert_eq!(consumers[0].owner_unit_id, "helper");
        assert_eq!(consumers[0].table, "documents");
        assert_eq!(consumers[0].consumer.start, 100);
    }
}
