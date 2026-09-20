use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};

use super::adapter_semantics::{AppliedRegistrationAdapter, DependencyAdapterCallIndex};
use super::callable_effects::{
    ArgumentFlow, CallEdge as CallableCallEdge, CallPosition, EffectTemplate, EffectTiming,
    StaticOperand as CallableStaticOperand, StaticOperandField,
    specialize_effects_with_complete_targets,
};
use super::callable_plans::{
    CallableEffectPlanIndex, CallableLeafControlCandidate, CallableValueFlowCandidate, callable_key,
};
use super::callable_resolution::{
    ReachableStaticCallIndex, caller_parameter_for_reference, resolve_static_source_target,
};
use super::callable_value_flow::AuthenticatedEffectValueGraph;
use super::capability_predicates::CapabilityPredicateTestCandidate;
use super::effect_plan::CallableKey;
use super::{
    CallCandidate, Diagnostic, GraphInput, LoadedModule, OperationCandidate, OperationIdentity,
    ReachableUnit, ReferenceOccurrence, RegistrationSummary, SourceRange, diagnostic_at,
    module_source, source_range_string, source_slice,
};

type CapabilityBindingKey = (String, u32, Vec<String>);
type CapabilityReferenceKey = (String, String, u32, u32);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CapabilityRequirement {
    Reference(CapabilityReferenceKey),
    ParameterProjection(CapabilityBindingKey),
}

#[derive(Clone)]
pub(super) struct CapabilityOwner {
    pub(super) module: String,
    pub(super) unit_id: String,
    pub(super) binding_start: u32,
    pub(super) parameter_index: Option<usize>,
    pub(super) argument_projection: Vec<String>,
    pub(super) name: String,
    pub(super) references: Vec<ReferenceOccurrence>,
    pub(super) dependency_chain: Vec<String>,
}

#[derive(Clone)]
pub(super) struct LegacyInterproceduralEffectSpecialization {
    pub(super) caller_module: String,
    pub(super) call_start: u32,
    pub(super) call_end: u32,
    pub(super) target_module: String,
    pub(super) target_unit_id: String,
    pub(super) operation: OperationCandidate,
    pub(super) call_position: CallPosition,
}

pub(super) struct OwnedCapabilityAnalysis {
    pub(super) admitted_operations: BTreeSet<OperationIdentity>,
    pub(super) authorized_callable_effects: BTreeSet<OperationIdentity>,
    pub(super) authorized_query_values: BTreeSet<OperationIdentity>,
    pub(super) legacy_interprocedural_effects: Vec<LegacyInterproceduralEffectSpecialization>,
}

#[derive(Default)]
struct OwnedCapabilityReferences {
    by_unit: BTreeMap<String, BTreeMap<String, BTreeSet<(u32, u32)>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CapabilityPredicateEvaluation {
    ProvedTrue,
    Unknown,
}

#[derive(Default)]
pub(super) struct CapabilityFlowProof {
    registration_kind: String,
    candidate_parameters: BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned: BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned_references: OwnedCapabilityReferences,
    guest_runtime_awaited_callables: BTreeSet<CallableKey>,
}

impl CapabilityFlowProof {
    pub(super) fn owned_capabilities(&self) -> impl Iterator<Item = &CapabilityOwner> {
        self.owned.values()
    }

    pub(super) fn exact_owned_reference(
        &self,
        caller: &ReachableUnit,
        reference: &SourceRange,
    ) -> bool {
        self.owned_references.contains(caller, reference)
    }

    pub(super) fn evaluate_predicate_test(
        &self,
        graph: &GraphInput,
        modules: &BTreeMap<String, LoadedModule>,
        caller: &ReachableUnit,
        test: &CapabilityPredicateTestCandidate,
    ) -> Result<CapabilityPredicateEvaluation> {
        if !matches!(
            self.registration_kind.as_str(),
            "query" | "internalQuery" | "mutation" | "internalMutation"
        ) {
            return Ok(CapabilityPredicateEvaluation::Unknown);
        }
        match test {
            CapabilityPredicateTestCandidate::DirectMember { member, object, .. } => {
                if member == "db" && self.exact_owned_reference(caller, object) {
                    Ok(CapabilityPredicateEvaluation::ProvedTrue)
                } else {
                    Ok(CapabilityPredicateEvaluation::Unknown)
                }
            }
            CapabilityPredicateTestCandidate::DirectCall {
                callee,
                callee_span,
                argument,
            } => {
                if !self.exact_owned_reference(caller, argument) {
                    return Ok(CapabilityPredicateEvaluation::Unknown);
                }
                let caller_module = modules
                    .get(&caller.module)
                    .context("capability predicate caller module disappeared")?;
                let matching_calls = caller_module
                    .summary
                    .calls
                    .iter()
                    .filter(|call| {
                        call.start >= caller.start
                            && call.end <= caller.end
                            && call.callee == *callee
                            && call.callee_start == callee_span.start
                            && call.callee_end == callee_span.end
                            && call.arguments.as_slice() == std::slice::from_ref(argument)
                            && call.argument_await_counts.as_slice() == [0]
                    })
                    .count();
                if matching_calls != 1 {
                    return Ok(CapabilityPredicateEvaluation::Unknown);
                }
                let Some((target_module, target_name)) =
                    resolve_static_source_target(graph, modules, &caller.module, callee)?
                else {
                    return Ok(CapabilityPredicateEvaluation::Unknown);
                };
                let target = modules
                    .get(&target_module)
                    .and_then(|module| module.summary.units.get(&target_name));
                let Some(target) = target else {
                    return Ok(CapabilityPredicateEvaluation::Unknown);
                };
                let Some(template) = &target.capability_predicate else {
                    return Ok(CapabilityPredicateEvaluation::Unknown);
                };
                let Some(parameter) = target
                    .parameters
                    .iter()
                    .find(|parameter| parameter.index == template.parameter_index)
                else {
                    return Ok(CapabilityPredicateEvaluation::Unknown);
                };
                if template.member == "db"
                    && self
                        .owned
                        .contains_key(&(target_module, parameter.start, Vec::new()))
                {
                    Ok(CapabilityPredicateEvaluation::ProvedTrue)
                } else {
                    Ok(CapabilityPredicateEvaluation::Unknown)
                }
            }
        }
    }
}

impl OwnedCapabilityReferences {
    fn insert(&mut self, owner: &CapabilityOwner) -> Vec<CapabilityReferenceKey> {
        let references = self
            .by_unit
            .entry(owner.module.clone())
            .or_default()
            .entry(owner.unit_id.clone())
            .or_default();
        let mut inserted = Vec::new();
        for reference in owner
            .references
            .iter()
            .filter(|reference| reference.read && !reference.write)
        {
            if references.insert((reference.start, reference.end)) {
                inserted.push((
                    owner.module.clone(),
                    owner.unit_id.clone(),
                    reference.start,
                    reference.end,
                ));
            }
        }
        inserted
    }

    fn contains(&self, caller: &ReachableUnit, argument: &SourceRange) -> bool {
        self.contains_span(&caller.module, &caller.id, argument.start, argument.end)
    }

    fn contains_span(&self, module: &str, unit_id: &str, start: u32, end: u32) -> bool {
        self.by_unit
            .get(module)
            .and_then(|units| units.get(unit_id))
            .is_some_and(|references| references.contains(&(start, end)))
    }
}

fn assign_callable_static_operand(
    operation: &mut OperationCandidate,
    field: &StaticOperandField,
    value: String,
) -> Result<()> {
    match field {
        StaticOperandField::Table => operation.table = Some(value),
        StaticOperandField::Index => operation.index = Some(value),
        StaticOperandField::FunctionReference => operation.function_reference = Some(value),
    }
    Ok(())
}

fn guest_direct_effect_requires_callable_plan(kind: &str) -> bool {
    matches!(
        kind,
        "db.get"
            | "db.query"
            | "db.insert"
            | "db.patch"
            | "db.replace"
            | "db.delete"
            | "scheduler.runAfter"
            | "scheduler.runAt"
    )
}

fn legacy_interprocedural_effect_specializations(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    index: &ReachableStaticCallIndex<'_>,
    owned: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
) -> Result<Vec<LegacyInterproceduralEffectSpecialization>> {
    let mut templates = Vec::new();
    let mut operations = BTreeMap::new();
    for owner in owned.values() {
        if !owner.argument_projection.is_empty() {
            continue;
        }
        let Some(capability_parameter_index) = owner.parameter_index else {
            continue;
        };
        let target = reachable
            .get(&owner.unit_id)
            .context("interprocedural effect target disappeared")?;
        let module = modules
            .get(&owner.module)
            .context("interprocedural effect source module disappeared")?;
        let unit = module
            .summary
            .units
            .get(&target.name)
            .context("interprocedural effect source unit disappeared")?;
        for effect in unit
            .effect_sites
            .iter()
            .filter(|effect| effect.capability_parameter_index == capability_parameter_index)
        {
            if module.summary.callable_leaf_plans.iter().any(|plan| {
                plan.callable_start >= target.start
                    && plan.callable_end <= target.end
                    && plan.current_batch_leaf
                    && matches!(
                        &plan.control,
                        CallableLeafControlCandidate::Effect(leaf)
                            if leaf.operation.start == effect.operation.start
                                && leaf.operation.end == effect.operation.end
                                && matches!(
                                    leaf.capability,
                                    CallableValueFlowCandidate::Parameter { index }
                                        if index == capability_parameter_index
                                )
                    )
            }) {
                // Leaf callable plans own this class. The older callable-effect site remains the
                // continuation-bearing fallback and must not provide duplicate positive authority.
                continue;
            }
            let id = format!(
                "{}:{}:{}",
                target.id, effect.operation.start, effect.operation.end
            );
            ensure!(
                operations
                    .insert(id.clone(), (target, effect.operation.clone()))
                    .is_none(),
                "callable effect template ID is duplicated"
            );
            templates.push(EffectTemplate {
                id,
                unit_id: target.id.clone(),
                timing: if effect.operation.kind == "db.normalizeId" {
                    EffectTiming::Synchronous
                } else {
                    EffectTiming::Suspending
                },
                tail_return_safe: false,
                static_operands: effect
                    .static_operands
                    .iter()
                    .map(|operand| {
                        let field = match operand.field.as_str() {
                            "table" => StaticOperandField::Table,
                            "index" => StaticOperandField::Index,
                            "functionReference" => StaticOperandField::FunctionReference,
                            other => {
                                bail!("callable effect has unsupported static operand {other}")
                            }
                        };
                        Ok(CallableStaticOperand {
                            field,
                            parameter_index: operand.parameter_index,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            });
        }
    }
    let mut calls = Vec::new();
    let mut complete_targets = BTreeSet::new();
    for (target_key, indexed_calls) in index.calls_by_target() {
        let Some(target_unit) = reachable
            .values()
            .find(|unit| unit.module == target_key.0 && unit.name == target_key.1)
        else {
            // The complete static index also contains authenticated adapter/source helpers that
            // are represented by their own contracts rather than flattened reachable units.
            continue;
        };
        if index.dispatch_is_exact(target_key) {
            complete_targets.insert(target_unit.id.clone());
        }
        for indexed in indexed_calls {
            let caller = indexed.caller;
            let call = indexed.call;
            let source = module_source(modules, &caller.module)?;
            let mut arguments = Vec::with_capacity(call.arguments.len());
            let mut arguments_safe = true;
            for (argument_index, argument) in call.arguments.iter().enumerate() {
                let flow = if call.argument_await_counts.get(argument_index).copied() != Some(0)
                    || source_slice(&source, argument.start, argument.end)
                        .is_ok_and(|value| value.trim_start().starts_with("..."))
                {
                    arguments_safe = false;
                    ArgumentFlow::Unknown
                } else if let Some(value) =
                    source_range_string(&source, argument).filter(|value| !value.is_empty())
                {
                    ArgumentFlow::LiteralString(value)
                } else if let Some(parameter) =
                    caller_parameter_for_reference(modules, caller, argument)?
                {
                    ArgumentFlow::Parameter {
                        unit_id: caller.id.clone(),
                        parameter_index: parameter.index,
                    }
                } else {
                    ArgumentFlow::Unknown
                };
                arguments.push(flow);
            }
            calls.push(CallableCallEdge {
                caller_module: caller.module.clone(),
                call_start: call.start,
                call_end: call.end,
                target_unit_id: target_unit.id.clone(),
                arguments,
                arguments_safe,
                position: match call.suspension.as_deref() {
                    Some("await") => CallPosition::SequentialAwait,
                    Some("return") => CallPosition::TailReturn,
                    None => CallPosition::Synchronous,
                    Some(other) => bail!("callable effect has unsupported call position {other}"),
                },
            });
        }
    }
    let mut output = Vec::new();
    for specialization in
        specialize_effects_with_complete_targets(&templates, &calls, Some(&complete_targets))
    {
        let (target, candidate) = operations
            .get(&specialization.template_id)
            .context("specialized callable effect template disappeared")?;
        let mut operation = candidate.clone();
        for (field, value) in specialization.static_operands {
            assign_callable_static_operand(&mut operation, &field, value)?;
        }
        output.push(LegacyInterproceduralEffectSpecialization {
            caller_module: specialization.caller_module,
            call_start: specialization.call_start,
            call_end: specialization.call_end,
            target_module: target.module.clone(),
            target_unit_id: target.id.clone(),
            operation,
            call_position: specialization.position,
        });
    }
    Ok(output)
}

fn forwarded_parameter_projection_key(
    modules: &BTreeMap<String, LoadedModule>,
    caller: &ReachableUnit,
    call: &CallCandidate,
    owner: &CapabilityOwner,
) -> Result<Option<CapabilityBindingKey>> {
    if owner.argument_projection.is_empty() || exact_capability_argument(call, owner).is_some() {
        return Ok(None);
    }
    let Some(argument_index) = owner.parameter_index else {
        return Ok(None);
    };
    if call.argument_await_counts.get(argument_index).copied() != Some(0) {
        return Ok(None);
    }
    let Some(argument) = call.arguments.get(argument_index) else {
        return Ok(None);
    };
    let Some(parameter) = caller_parameter_for_reference(modules, caller, argument)? else {
        return Ok(None);
    };
    Ok(Some((
        caller.module.clone(),
        parameter.start,
        owner.argument_projection.clone(),
    )))
}

fn populate_forwarded_projection_candidates(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    static_calls: &ReachableStaticCallIndex<'_>,
    candidate_parameters: &mut BTreeMap<CapabilityBindingKey, CapabilityOwner>,
) -> Result<()> {
    loop {
        let projected = candidate_parameters
            .values()
            .filter(|owner| !owner.argument_projection.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        let mut inserted = false;
        for owner in projected {
            let target = capability_parameter_target(reachable, &owner)?;
            if !static_calls.dispatch_is_exact(&target) {
                continue;
            }
            for indexed in static_calls.calls_to(&target) {
                let caller = indexed.caller;
                if caller.kind == "handler" {
                    continue;
                }
                let Some(key) =
                    forwarded_parameter_projection_key(modules, caller, indexed.call, &owner)?
                else {
                    continue;
                };
                if candidate_parameters.contains_key(&key) {
                    continue;
                }
                let module = modules
                    .get(&caller.module)
                    .context("forwarded capability projection caller module disappeared")?;
                let source_unit = module
                    .summary
                    .units
                    .get(&caller.name)
                    .context("forwarded capability projection caller unit disappeared")?;
                let parameter = source_unit
                    .parameters
                    .iter()
                    .find(|parameter| parameter.start == key.1)
                    .context("forwarded capability projection caller parameter disappeared")?;
                let projection = parameter.capability_projections.iter().find(|projection| {
                    projection.binding_start == parameter.start && projection.path == key.2
                });
                candidate_parameters.insert(
                    key,
                    CapabilityOwner {
                        module: caller.module.clone(),
                        unit_id: caller.id.clone(),
                        binding_start: parameter.start,
                        parameter_index: Some(parameter.index),
                        argument_projection: owner.argument_projection.clone(),
                        name: projection.map_or_else(
                            || {
                                format!(
                                    "{}.{}",
                                    parameter.name,
                                    owner.argument_projection.join(".")
                                )
                            },
                            |projection| projection.name.clone(),
                        ),
                        references: projection
                            .map(|projection| projection.references.clone())
                            .unwrap_or_default(),
                        dependency_chain: caller.dependency_chain.clone(),
                    },
                );
                inserted = true;
            }
        }
        if !inserted {
            return Ok(());
        }
    }
}

fn capability_requirement_is_satisfied(
    requirement: &CapabilityRequirement,
    owned: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned_references: &OwnedCapabilityReferences,
) -> bool {
    match requirement {
        CapabilityRequirement::Reference((module, unit_id, start, end)) => {
            owned_references.contains_span(module, unit_id, *start, *end)
        }
        CapabilityRequirement::ParameterProjection(key) => owned.contains_key(key),
    }
}

pub(super) fn build_capability_flow_proof(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    static_calls: &ReachableStaticCallIndex<'_>,
    registration: &RegistrationSummary,
    registration_adapter: Option<&AppliedRegistrationAdapter>,
) -> Result<CapabilityFlowProof> {
    let Some(context_name) = &registration.context_parameter else {
        return Ok(CapabilityFlowProof {
            registration_kind: registration.kind.clone(),
            ..CapabilityFlowProof::default()
        });
    };
    let context_start = registration
        .context_parameter_start
        .context("registration context parameter has no source start")?;
    let root = reachable
        .values()
        .find(|unit| unit.kind == "handler")
        .context("reachable registration handler disappeared")?;
    let root_owner = CapabilityOwner {
        module: root.module.clone(),
        unit_id: root.id.clone(),
        binding_start: context_start,
        parameter_index: None,
        argument_projection: Vec::new(),
        name: context_name.clone(),
        references: registration.context_references.clone(),
        dependency_chain: root.dependency_chain.clone(),
    };
    let mut candidate_parameters = BTreeMap::<CapabilityBindingKey, CapabilityOwner>::new();
    for unit in reachable.values().filter(|unit| unit.kind != "handler") {
        let module = modules
            .get(&unit.module)
            .context("reachable capability candidate module disappeared")?;
        let source_unit = module
            .summary
            .units
            .get(&unit.name)
            .context("reachable capability candidate unit disappeared")?;
        if source_unit.registration.is_some() {
            continue;
        }
        for parameter in &source_unit.parameters {
            candidate_parameters.insert(
                (unit.module.clone(), parameter.start, Vec::new()),
                CapabilityOwner {
                    module: unit.module.clone(),
                    unit_id: unit.id.clone(),
                    binding_start: parameter.start,
                    parameter_index: Some(parameter.index),
                    argument_projection: Vec::new(),
                    name: parameter.name.clone(),
                    references: parameter.references.clone(),
                    dependency_chain: unit.dependency_chain.clone(),
                },
            );
            for projection in &parameter.capability_projections {
                candidate_parameters.insert(
                    (
                        unit.module.clone(),
                        projection.binding_start,
                        projection.path.clone(),
                    ),
                    CapabilityOwner {
                        module: unit.module.clone(),
                        unit_id: unit.id.clone(),
                        binding_start: projection.binding_start,
                        parameter_index: Some(parameter.index),
                        argument_projection: projection.path.clone(),
                        name: projection.name.clone(),
                        references: projection.references.clone(),
                        dependency_chain: unit.dependency_chain.clone(),
                    },
                );
            }
        }
    }
    populate_forwarded_projection_candidates(
        modules,
        reachable,
        static_calls,
        &mut candidate_parameters,
    )?;
    let mut owned_references = OwnedCapabilityReferences::default();
    let _ = owned_references.insert(&root_owner);
    let mut owned = BTreeMap::from([(
        (
            root_owner.module.clone(),
            root_owner.binding_start,
            Vec::new(),
        ),
        root_owner,
    )]);
    let mut guest_runtime_awaited_callables = BTreeSet::new();
    if let Some(adapter) = registration_adapter {
        let key = (
            adapter.helper_module.clone(),
            adapter.helper_parameter_start,
            Vec::new(),
        );
        let owner = candidate_parameters.get(&key).with_context(|| {
            format!(
                "registration adapter {} helper context parameter is not reachable",
                adapter.descriptor.id
            )
        })?;
        let _ = owned_references.insert(owner);
        ensure!(
            owned.insert(key, owner.clone()).is_none(),
            "registration adapter helper context parameter duplicates the root owner"
        );
        let helper_target = (
            adapter.helper_module.clone(),
            adapter.helper_unit_name.clone(),
        );
        let helper_has_only_exact_static_references = static_calls
            .inexact_references_to(&helper_target)
            .is_empty()
            && static_calls
                .references_to(&helper_target)
                .iter()
                .all(|reference| !reference.reference.write && reference.direct_call);
        if helper_has_only_exact_static_references {
            let helper = reachable.get(&owner.unit_id).with_context(|| {
                format!(
                    "registration adapter {} helper reachable unit disappeared",
                    adapter.descriptor.id
                )
            })?;
            let helper_unit = modules
                .get(&adapter.helper_module)
                .and_then(|module| module.summary.units.get(&adapter.helper_unit_name))
                .with_context(|| {
                    format!(
                        "registration adapter {} helper callable unit disappeared",
                        adapter.descriptor.id
                    )
                })?;
            let callable = helper_unit.callable_range.as_ref().with_context(|| {
                format!(
                    "registration adapter {} helper has no callable range",
                    adapter.descriptor.id
                )
            })?;
            ensure!(
                callable.start >= helper.start && callable.end <= helper.end,
                "registration adapter helper callable range escaped its reachable unit"
            );
            guest_runtime_awaited_callables.insert(callable_key(
                &adapter.helper_module,
                callable.start,
                callable.end,
            ));
        }
    }
    let mut remaining_requirements = BTreeMap::<CapabilityBindingKey, usize>::new();
    let mut requirements_by_parameter =
        BTreeMap::<CapabilityBindingKey, BTreeSet<CapabilityRequirement>>::new();
    let mut waiting_by_requirement =
        BTreeMap::<CapabilityRequirement, Vec<CapabilityBindingKey>>::new();
    let mut ready = BTreeSet::new();
    for (key, owner) in &candidate_parameters {
        if owned.contains_key(key) {
            continue;
        }
        let Some(requirements) = capability_parameter_requirements(
            modules,
            reachable,
            static_calls,
            &candidate_parameters,
            owner,
        )?
        else {
            continue;
        };
        requirements_by_parameter.insert(key.clone(), requirements.clone());
        let pending = requirements
            .iter()
            .filter(|requirement| {
                !capability_requirement_is_satisfied(requirement, &owned, &owned_references)
            })
            .cloned()
            .collect::<Vec<_>>();
        if pending.is_empty() {
            ready.insert(key.clone());
            continue;
        }
        remaining_requirements.insert(key.clone(), pending.len());
        for requirement in pending {
            waiting_by_requirement
                .entry(requirement)
                .or_default()
                .push(key.clone());
        }
    }
    loop {
        while let Some(key) = ready.pop_first() {
            if owned.contains_key(&key) {
                continue;
            }
            promote_capability_parameters(
                std::slice::from_ref(&key),
                &candidate_parameters,
                &mut owned,
                &mut owned_references,
                &mut remaining_requirements,
                &mut waiting_by_requirement,
                &mut ready,
            )?;
        }
        if !promote_rooted_closed_capability_regions(
            modules,
            reachable,
            static_calls,
            &candidate_parameters,
            &requirements_by_parameter,
            &mut owned,
            &mut owned_references,
            &mut remaining_requirements,
            &mut waiting_by_requirement,
            &mut ready,
        )? {
            break;
        }
    }
    Ok(CapabilityFlowProof {
        registration_kind: registration.kind.clone(),
        candidate_parameters,
        owned,
        owned_references,
        guest_runtime_awaited_callables,
    })
}

#[expect(clippy::too_many_arguments)]
fn promote_capability_parameters(
    keys: &[CapabilityBindingKey],
    candidate_parameters: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned: &mut BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned_references: &mut OwnedCapabilityReferences,
    remaining_requirements: &mut BTreeMap<CapabilityBindingKey, usize>,
    waiting_by_requirement: &mut BTreeMap<CapabilityRequirement, Vec<CapabilityBindingKey>>,
    ready: &mut BTreeSet<CapabilityBindingKey>,
) -> Result<()> {
    let owners = keys
        .iter()
        .filter(|key| !owned.contains_key(*key))
        .map(|key| {
            candidate_parameters
                .get(key)
                .cloned()
                .with_context(|| format!("capability candidate {key:?} disappeared"))
                .map(|owner| (key.clone(), owner))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut inserted_requirements = Vec::new();
    for (key, owner) in &owners {
        inserted_requirements.push(CapabilityRequirement::ParameterProjection(key.clone()));
        inserted_requirements.extend(
            owned_references
                .insert(owner)
                .into_iter()
                .map(CapabilityRequirement::Reference),
        );
    }
    for (key, owner) in owners {
        ensure!(
            owned.insert(key, owner).is_none(),
            "promoted capability candidate was already owned"
        );
    }
    for requirement in inserted_requirements {
        let Some(waiting) = waiting_by_requirement.remove(&requirement) else {
            continue;
        };
        for waiting_key in waiting {
            let remaining = remaining_requirements
                .get_mut(&waiting_key)
                .context("waiting capability requirement disappeared")?;
            ensure!(*remaining > 0, "capability requirement count underflow");
            *remaining -= 1;
            if *remaining == 0 {
                ready.insert(waiting_key);
            }
        }
    }
    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn promote_rooted_closed_capability_regions(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    static_calls: &ReachableStaticCallIndex<'_>,
    candidate_parameters: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    requirements_by_parameter: &BTreeMap<CapabilityBindingKey, BTreeSet<CapabilityRequirement>>,
    owned: &mut BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned_references: &mut OwnedCapabilityReferences,
    remaining_requirements: &mut BTreeMap<CapabilityBindingKey, usize>,
    waiting_by_requirement: &mut BTreeMap<CapabilityRequirement, Vec<CapabilityBindingKey>>,
    ready: &mut BTreeSet<CapabilityBindingKey>,
) -> Result<bool> {
    let unresolved = remaining_requirements
        .iter()
        .filter(|(key, remaining)| **remaining > 0 && !owned.contains_key(*key))
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    if unresolved.is_empty() {
        return Ok(false);
    }

    let mut parameter_by_reference =
        BTreeMap::<CapabilityReferenceKey, CapabilityBindingKey>::new();
    for (key, owner) in candidate_parameters {
        for reference in owner
            .references
            .iter()
            .filter(|reference| reference.read && !reference.write)
        {
            let reference_key = (
                owner.module.clone(),
                owner.unit_id.clone(),
                reference.start,
                reference.end,
            );
            if let Some(existing) = parameter_by_reference.insert(reference_key, key.clone()) {
                ensure!(
                    existing == *key,
                    "capability reference belongs to multiple candidate parameters"
                );
            }
        }
    }

    let mut roots = Vec::new();
    for key in &unresolved {
        let Some(owner) = candidate_parameters.get(key) else {
            continue;
        };
        if capability_parameter_has_owned_caller(
            modules,
            reachable,
            static_calls,
            candidate_parameters,
            owned,
            owned_references,
            owner,
        )? {
            roots.push(key.clone());
        }
    }
    for root in roots {
        let mut region = BTreeSet::new();
        let mut pending = vec![root];
        let mut closed = true;
        while let Some(key) = pending.pop() {
            if !region.insert(key.clone()) {
                continue;
            }
            let requirements = requirements_by_parameter
                .get(&key)
                .context("unresolved capability candidate requirements disappeared")?;
            for requirement in requirements.iter().filter(|requirement| {
                !capability_requirement_is_satisfied(requirement, owned, owned_references)
            }) {
                let provider = match requirement {
                    CapabilityRequirement::Reference(reference) => {
                        parameter_by_reference.get(reference)
                    }
                    CapabilityRequirement::ParameterProjection(provider) => candidate_parameters
                        .get_key_value(provider)
                        .map(|(key, _)| key),
                };
                let Some(provider) = provider else {
                    closed = false;
                    break;
                };
                if !unresolved.contains(provider) {
                    closed = false;
                    break;
                }
                pending.push(provider.clone());
            }
            if !closed {
                break;
            }
        }
        if !closed {
            continue;
        }
        let keys = region.into_iter().collect::<Vec<_>>();
        promote_capability_parameters(
            &keys,
            candidate_parameters,
            owned,
            owned_references,
            remaining_requirements,
            waiting_by_requirement,
            ready,
        )?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) fn analyze_owned_capabilities(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    static_calls: &ReachableStaticCallIndex<'_>,
    proof: &CapabilityFlowProof,
    callable_effect_plans: &CallableEffectPlanIndex,
    effect_values: &AuthenticatedEffectValueGraph,
    authorized_query_values: &BTreeSet<OperationIdentity>,
    represented_query_constructions: &BTreeSet<(String, String, (u32, u32))>,
    dependency_adapter_calls: &DependencyAdapterCallIndex<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<OwnedCapabilityAnalysis> {
    let mut admitted = authorized_query_values.clone();
    admitted.extend(
        dependency_adapter_calls
            .calls
            .iter()
            .filter(|call| call.descriptor.semantic.kind == "functionHandleCreate")
            .map(|call| {
                (
                    call.importer_module.clone(),
                    call.operation.start,
                    call.operation.end,
                )
            }),
    );
    if proof.owned.is_empty() {
        return Ok(OwnedCapabilityAnalysis {
            admitted_operations: admitted,
            authorized_callable_effects: BTreeSet::new(),
            authorized_query_values: authorized_query_values.clone(),
            legacy_interprocedural_effects: Vec::new(),
        });
    }
    let mut legacy_interprocedural_effects = Vec::new();
    let mut specialized_effects = represented_query_constructions.clone();
    let mut authorized_callable_effects = BTreeSet::new();
    for plan in callable_effect_plans.plans() {
        let binding = &plan.provenance.capability_binding;
        let Some(owner) = proof.owned.values().find(|owner| {
            owner.module == binding.module
                && owner.binding_start == binding.start
                && owner.name == plan.provenance.capability_name
        }) else {
            continue;
        };
        let target = reachable
            .get(&owner.unit_id)
            .context("authorized callable effect target disappeared")?;
        let reference = &plan.provenance.capability_reference;
        if owner.name != plan.provenance.capability_name
            || binding.start < target.start
            || binding.end > target.end
            || plan.provenance.target_effect.start < target.start
            || plan.provenance.target_effect.end > target.end
            || !owner.references.iter().any(|owned_reference| {
                owned_reference.start == reference.start
                    && owned_reference.end == reference.end
                    && owned_reference.read
                    && !owned_reference.write
            })
        {
            continue;
        }
        if graph.effect_execution_mode == super::EffectExecutionMode::GuestPromiseEventLoop
            && !effect_values.closes_guest_effect_site(
                plan,
                callable_effect_plans.activation_calls(),
                &proof.guest_runtime_awaited_callables,
            )
        {
            continue;
        }
        let identity = plan.target_identity();
        authorized_callable_effects.insert(identity.clone());
        admitted.insert(identity.clone());
        specialized_effects.insert((
            owner.module.clone(),
            owner.unit_id.clone(),
            (identity.1, identity.2),
        ));
    }
    let specializations =
        if graph.effect_execution_mode == super::EffectExecutionMode::BlockingFiber {
            legacy_interprocedural_effect_specializations(
                modules,
                reachable,
                static_calls,
                &proof.owned,
            )?
        } else {
            Vec::new()
        };
    for specialization in &specializations {
        let operation = &specialization.operation;
        specialized_effects.insert((
            specialization.target_module.clone(),
            specialization.target_unit_id.clone(),
            (operation.start, operation.end),
        ));
        admitted.insert((
            specialization.target_module.clone(),
            operation.start,
            operation.end,
        ));
    }
    legacy_interprocedural_effects.extend(specializations);
    let mut attempted_parameters = BTreeSet::new();
    for (key, owner) in &proof.candidate_parameters {
        if capability_parameter_has_owned_caller(
            modules,
            reachable,
            static_calls,
            &proof.candidate_parameters,
            &proof.owned,
            &proof.owned_references,
            owner,
        )? {
            attempted_parameters.insert(key.clone());
        }
    }
    for owner in proof.owned.values() {
        let unit = reachable
            .get(&owner.unit_id)
            .context("owned capability source unit disappeared")?;
        let module = modules
            .get(&owner.module)
            .context("owned capability source module disappeared")?;
        let dependency_calls = dependency_adapter_calls.calls_for(&owner.module, &owner.unit_id);
        for reference in &owner.references {
            let reference_database_path = format!("{}.db", reference.name);
            if specialized_effects
                .iter()
                .any(|(module, unit_id, (start, end))| {
                    module == &owner.module
                        && unit_id == &owner.unit_id
                        && reference.start >= *start
                        && reference.end <= *end
                })
            {
                continue;
            }
            let mut represented_dependency_operations =
                dependency_calls.iter().copied().filter(|call| {
                    call.effect_start <= reference.start
                        && call.effect_end >= reference.end
                        && (call.effect_path == reference.name
                            || call.effect_path == reference_database_path)
                });
            let represented_dependency_operation = represented_dependency_operations.next();
            if reference.read
                && !reference.write
                && represented_dependency_operation.is_some()
                && represented_dependency_operations.next().is_none()
            {
                let call = represented_dependency_operation.expect("checked represented call");
                admitted.insert((
                    call.importer_module.clone(),
                    call.operation.start,
                    call.operation.end,
                ));
                continue;
            }
            let represented_operations = module
                .summary
                .operations
                .iter()
                .filter(|operation| {
                    operation.start >= unit.start
                        && operation.end <= unit.end
                        && operation
                            .effect_start
                            .is_some_and(|start| start <= reference.start)
                        && operation.effect_end.is_some_and(|end| end >= reference.end)
                        && operation.effect_path.as_deref().is_some_and(|path| {
                            owned_operation_effect_path(
                                &reference.name,
                                operation.kind.as_str(),
                                path,
                            )
                        })
                        && module.summary.effects.iter().any(|effect| {
                            operation.effect_start == Some(effect.start)
                                && operation.effect_end == Some(effect.end)
                                && operation.effect_path.as_deref() == Some(effect.path.as_str())
                        })
                })
                .collect::<Vec<_>>();
            if reference.read
                && !reference.write
                && represented_operations.len() == 1
                && !(graph.effect_execution_mode
                    == super::EffectExecutionMode::GuestPromiseEventLoop
                    && guest_direct_effect_requires_callable_plan(&represented_operations[0].kind))
            {
                let operation = represented_operations[0];
                admitted.insert((owner.module.clone(), operation.start, operation.end));
                continue;
            }

            let forwarded_calls = if reference.read && !reference.write {
                module
                    .summary
                    .calls
                    .iter()
                    .filter(|call| call.start >= unit.start && call.end <= unit.end)
                    .flat_map(|call| {
                        let direct = call
                            .arguments
                            .iter()
                            .enumerate()
                            .filter(move |(_, argument)| {
                                argument.start == reference.start && argument.end == reference.end
                            })
                            .map(move |(index, _)| (call, index, Vec::new()));
                        let projected = call.argument_projections.iter().enumerate().flat_map(
                            move |(index, projections)| {
                                projections.iter().filter_map(move |projection| {
                                    (projection.await_count == 0
                                        && projection.value.start == reference.start
                                        && projection.value.end == reference.end)
                                        .then(|| (call, index, projection.path.clone()))
                                })
                            },
                        );
                        direct.chain(projected)
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            if forwarded_calls.len() == 1
                && resolve_forwarded_capability_keys(
                    modules,
                    reachable,
                    static_calls,
                    unit,
                    forwarded_calls[0].0,
                    forwarded_calls[0].1,
                    &forwarded_calls[0].2,
                    &proof.candidate_parameters,
                )?
                .iter()
                .any(|target| attempted_parameters.contains(target))
            {
                continue;
            }

            let effect = module
                .summary
                .effects
                .iter()
                .filter(|effect| {
                    effect.start <= reference.start
                        && effect.end >= reference.end
                        && (effect.path == reference.name
                            || effect
                                .path
                                .strip_prefix(&reference.name)
                                .is_some_and(|suffix| suffix.starts_with('.')))
                })
                .max_by_key(|effect| effect.end - effect.start);
            let (start, path) = effect.map_or_else(
                || (reference.start, reference.name.clone()),
                |effect| (effect.start, effect.path.clone()),
            );
            if let Some(rejected) = module.summary.operations.iter().find(|operation| {
                operation.start >= unit.start
                    && operation.end <= unit.end
                    && operation
                        .effect_start
                        .is_some_and(|effect_start| effect_start <= reference.start)
                    && operation
                        .effect_end
                        .is_some_and(|effect_end| effect_end >= reference.end)
                    && rejected_context_operation_diagnostic(&operation.kind).is_some()
            }) {
                let (code, message) = rejected_context_operation_diagnostic(&rejected.kind)
                    .expect("rejected context operation diagnostic disappeared");
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    code,
                    message.to_string(),
                    &owner.module,
                    rejected.start,
                    Some(path),
                    owner.dependency_chain.clone(),
                )?);
                continue;
            }
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "unsupported-convex-effect",
                format!(
                    "reachable Convex capability access {path} is not represented by an admitted operation or an exact static source call"
                ),
                &owner.module,
                start,
                Some(path),
                owner.dependency_chain.clone(),
            )?);
        }
    }
    diagnose_rejected_capability_parameters(
        graph,
        modules,
        reachable,
        static_calls,
        &proof.candidate_parameters,
        &proof.owned,
        &proof.owned_references,
        &attempted_parameters,
        diagnostics,
    )?;
    for call in dependency_adapter_calls.calls {
        if admitted.contains(&(
            call.importer_module.clone(),
            call.operation.start,
            call.operation.end,
        )) {
            continue;
        }
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-dependency-adapter-capability",
            format!(
                "adapter {} database argument is not an exact owned Convex database capability",
                call.descriptor.id
            ),
            &call.importer_module,
            call.effect_start,
            Some(call.descriptor.semantic.kind.clone()),
            call.dependency_chain.clone(),
        )?);
    }
    Ok(OwnedCapabilityAnalysis {
        admitted_operations: admitted,
        authorized_callable_effects,
        authorized_query_values: authorized_query_values.clone(),
        legacy_interprocedural_effects,
    })
}

fn owned_operation_effect_path(owner: &str, kind: &str, path: &str) -> bool {
    let suffix = match kind {
        "auth.getUserIdentity" => ".auth.getUserIdentity",
        "db.normalizeId" => ".db.normalizeId",
        "db.get" => ".db.get",
        "db.query" => ".db.query",
        "db.insert" => ".db.insert",
        "db.patch" => ".db.patch",
        "db.replace" => ".db.replace",
        "db.delete" => ".db.delete",
        "scheduler.runAfter" => ".scheduler.runAfter",
        "scheduler.runAt" => ".scheduler.runAt",
        "intrinsic.sha256" => return false,
        _ => return false,
    };
    path == format!("{owner}{suffix}")
}

fn rejected_context_operation_diagnostic(kind: &str) -> Option<(&'static str, &'static str)> {
    match kind {
        "rejected.auth.getUserIdentity.computed" => Some((
            "unsupported-authentication-get-user-identity-shape",
            "authentication identity admission requires a non-computed getUserIdentity member call",
        )),
        "rejected.auth.getUserIdentity.optional" => Some((
            "unsupported-authentication-get-user-identity-shape",
            "authentication identity admission does not allow optional member access or calls",
        )),
        "rejected.auth.getUserIdentity.arity" => Some((
            "unsupported-authentication-get-user-identity-shape",
            "authentication identity admission requires exactly zero arguments",
        )),
        "rejected.db.normalizeId.computed" => Some((
            "unsupported-database-normalize-id-shape",
            "database ID normalization admission requires a non-computed normalizeId member call",
        )),
        "rejected.db.normalizeId.optional" => Some((
            "unsupported-database-normalize-id-shape",
            "database ID normalization admission does not allow optional member access or calls",
        )),
        "rejected.db.normalizeId.arity" => Some((
            "unsupported-database-normalize-id-shape",
            "database ID normalization admission requires exactly two arguments",
        )),
        "rejected.db.normalizeId.dynamicTable" => Some((
            "unsupported-database-normalize-id-shape",
            "database ID normalization admission requires a nonempty static string table name",
        )),
        _ => None,
    }
}

fn resolve_forwarded_capability_keys(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    static_calls: &ReachableStaticCallIndex<'_>,
    caller: &ReachableUnit,
    call: &CallCandidate,
    argument_index: usize,
    argument_projection: &[String],
    candidate_parameters: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
) -> Result<Vec<CapabilityBindingKey>> {
    let Some((target_module, target_name)) = static_calls.target_for_call(caller, call) else {
        return Ok(Vec::new());
    };
    let target_module_summary = modules
        .get(target_module)
        .context("capability target module disappeared")?;
    let Some(target_unit) = target_module_summary.summary.units.get(target_name) else {
        return Ok(Vec::new());
    };
    if target_unit.registration.is_some() {
        return Ok(Vec::new());
    }
    let Some(reachable_target) = reachable
        .values()
        .find(|unit| unit.module == *target_module && unit.name == *target_name)
    else {
        return Ok(Vec::new());
    };
    Ok(candidate_parameters
        .iter()
        .filter(|(_, owner)| {
            owner.module == *target_module
                && owner.unit_id == reachable_target.id
                && owner.parameter_index == Some(argument_index)
                && owner.argument_projection == argument_projection
        })
        .map(|(key, _)| key.clone())
        .collect())
}

fn exact_owned_capability_argument(
    modules: &BTreeMap<String, LoadedModule>,
    caller: &ReachableUnit,
    call: &CallCandidate,
    owner: &CapabilityOwner,
    candidate_parameters: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned_references: &OwnedCapabilityReferences,
) -> Result<bool> {
    Ok(
        exact_capability_requirement(modules, caller, call, owner, candidate_parameters)?
            .is_some_and(|requirement| {
                capability_requirement_is_satisfied(&requirement, owned, owned_references)
            }),
    )
}

fn exact_capability_argument<'a>(
    call: &'a CallCandidate,
    owner: &CapabilityOwner,
) -> Option<&'a SourceRange> {
    let argument_index = owner.parameter_index?;
    if owner.argument_projection.is_empty() {
        return (call.argument_await_counts.get(argument_index).copied() == Some(0))
            .then(|| call.arguments.get(argument_index))
            .flatten();
    }
    call.argument_projections
        .get(argument_index)?
        .iter()
        .find(|projection| {
            projection.path == owner.argument_projection && projection.await_count == 0
        })
        .map(|projection| &projection.value)
}

fn exact_capability_requirement(
    modules: &BTreeMap<String, LoadedModule>,
    caller: &ReachableUnit,
    call: &CallCandidate,
    owner: &CapabilityOwner,
    candidate_parameters: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
) -> Result<Option<CapabilityRequirement>> {
    if let Some(argument) = exact_capability_argument(call, owner) {
        return Ok(Some(CapabilityRequirement::Reference((
            caller.module.clone(),
            caller.id.clone(),
            argument.start,
            argument.end,
        ))));
    }
    let Some(key) = forwarded_parameter_projection_key(modules, caller, call, owner)? else {
        return Ok(None);
    };
    Ok(candidate_parameters
        .contains_key(&key)
        .then_some(CapabilityRequirement::ParameterProjection(key)))
}

fn capability_parameter_target(
    reachable: &BTreeMap<String, ReachableUnit>,
    owner: &CapabilityOwner,
) -> Result<(String, String)> {
    let target = reachable
        .get(&owner.unit_id)
        .context("capability parameter target unit disappeared")?;
    Ok((target.module.clone(), target.name.clone()))
}

fn capability_parameter_dispatch_is_exact(
    reachable: &BTreeMap<String, ReachableUnit>,
    index: &ReachableStaticCallIndex<'_>,
    owner: &CapabilityOwner,
) -> Result<bool> {
    let target = capability_parameter_target(reachable, owner)?;
    Ok(index.dispatch_is_exact(&target))
}

fn capability_parameter_requirements(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    index: &ReachableStaticCallIndex<'_>,
    candidate_parameters: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owner: &CapabilityOwner,
) -> Result<Option<BTreeSet<CapabilityRequirement>>> {
    owner
        .parameter_index
        .context("capability candidate parameter has no argument index")?;
    if !capability_parameter_dispatch_is_exact(reachable, index, owner)? {
        return Ok(None);
    }
    let target = capability_parameter_target(reachable, owner)?;
    let calls = index.calls_to(&target);
    if calls.is_empty() {
        return Ok(None);
    }
    let mut requirements = BTreeSet::new();
    for indexed in calls {
        let caller = indexed.caller;
        let call = indexed.call;
        let Some(requirement) =
            exact_capability_requirement(modules, caller, call, owner, candidate_parameters)?
        else {
            return Ok(None);
        };
        requirements.insert(requirement);
    }
    Ok(Some(requirements))
}

fn capability_parameter_has_owned_caller(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    index: &ReachableStaticCallIndex<'_>,
    candidate_parameters: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned_references: &OwnedCapabilityReferences,
    owner: &CapabilityOwner,
) -> Result<bool> {
    if owner.parameter_index.is_none() {
        return Ok(false);
    }
    let Ok(target) = capability_parameter_target(reachable, owner) else {
        return Ok(false);
    };
    for indexed in index.calls_to(&target) {
        if exact_owned_capability_argument(
            modules,
            indexed.caller,
            indexed.call,
            owner,
            candidate_parameters,
            owned,
            owned_references,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[expect(clippy::too_many_arguments)]
fn diagnose_rejected_capability_parameters(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    index: &ReachableStaticCallIndex<'_>,
    candidate_parameters: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned: &BTreeMap<CapabilityBindingKey, CapabilityOwner>,
    owned_references: &OwnedCapabilityReferences,
    attempted_parameters: &BTreeSet<CapabilityBindingKey>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<()> {
    for (key, owner) in candidate_parameters {
        if owned.contains_key(key) || !attempted_parameters.contains(key) {
            continue;
        }
        owner
            .parameter_index
            .context("rejected capability parameter has no argument index")?;
        let target = reachable
            .get(&owner.unit_id)
            .context("rejected capability target unit disappeared")?;
        let target_key = (target.module.clone(), target.name.clone());
        for indexed in index.calls_to(&target_key) {
            let caller = indexed.caller;
            let call = indexed.call;
            if exact_owned_capability_argument(
                modules,
                caller,
                call,
                owner,
                candidate_parameters,
                owned,
                owned_references,
            )? {
                continue;
            }
            let start = exact_capability_argument(call, owner)
                .or_else(|| {
                    owner
                        .parameter_index
                        .and_then(|index| call.arguments.get(index))
                })
                .map_or(call.start, |argument| argument.start);
            diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "mixed-capability-callsite",
                    format!(
                        "reachable call to capability-owned helper {} argument {} is not an exact owned capability forwarding edge",
                        target.name,
                        owner.parameter_index.expect("checked capability parameter index")
                    ),
                    &caller.module,
                    start,
                    Some(call.callee.clone()),
                    caller.dependency_chain.clone(),
                )?);
        }
        for indexed in index.references_to(&target_key) {
            let caller = indexed.caller;
            let reference = indexed.reference;
            if reference.write {
                diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "capability-helper-binding-write",
                        format!(
                            "reachable write to capability-owned helper {} can change static call dispatch",
                            target.name
                        ),
                        &caller.module,
                        reference.start,
                        Some(reference.name.clone()),
                        caller.dependency_chain.clone(),
                    )?);
                continue;
            }
            if indexed.direct_call {
                continue;
            }
            diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "indirect-capability-callsite",
                    format!(
                        "reachable capability-owned helper {} is referenced outside a direct static call",
                        target.name
                    ),
                    &caller.module,
                    reference.start,
                    Some(reference.name.clone()),
                    caller.dependency_chain.clone(),
            )?);
        }
        for indexed in index.inexact_references_to(&target_key) {
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "indirect-capability-callsite",
                format!(
                    "reachable capability-owned helper {} is referenced outside a reachable direct static call",
                    target.name
                ),
                &indexed.module,
                indexed.reference.start,
                Some(indexed.reference.name.clone()),
                owner.dependency_chain.clone(),
            )?);
        }
    }
    Ok(())
}
