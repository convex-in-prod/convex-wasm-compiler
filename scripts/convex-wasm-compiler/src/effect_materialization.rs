use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};

use super::callable_effects::CallPosition;
use super::callable_value_flow::AuthenticatedEffectValueGraph;
use super::capability_flow::LegacyInterproceduralEffectSpecialization;
use super::effect_plan::{
    AuthorizedEffectLeaf, CallableEffectPlan, PlanSourceSpan, SemanticEffectOperand,
    SemanticEffectTiming, SourceAnchor,
};
use super::effect_site_rewrites::{
    AuthorizedDirectDynamicOperand, AuthorizedDirectEffectSite, AuthorizedDirectEffectVariant,
    supports_direct_effect_site,
};
use super::{
    AdmittedIndexConstraint, AdmittedOperation, LoadedModule, OperationIdentity, hash_bytes,
    line_column, module_source, source_slice,
};

#[derive(Default)]
pub(super) struct AuthorizedEffectSiteIndex {
    by_site: BTreeMap<OperationIdentity, CallableEffectPlan>,
    by_target: BTreeMap<OperationIdentity, Vec<CallableEffectPlan>>,
}

impl AuthorizedEffectSiteIndex {
    pub(super) fn new<'a>(
        graph: &AuthenticatedEffectValueGraph,
        target_plans: impl IntoIterator<Item = &'a CallableEffectPlan>,
        authorized_targets: &BTreeSet<OperationIdentity>,
    ) -> Result<Self> {
        Self::with_current_batch_leaves(graph, std::iter::empty(), target_plans, authorized_targets)
    }

    pub(super) fn with_current_batch_leaves<'a, 'b>(
        graph: &AuthenticatedEffectValueGraph,
        current_batch_leaves: impl IntoIterator<Item = &'a CallableEffectPlan>,
        target_plans: impl IntoIterator<Item = &'b CallableEffectPlan>,
        authorized_targets: &BTreeSet<OperationIdentity>,
    ) -> Result<Self> {
        let mut index = Self::default();
        let mut conflicting_sites = BTreeSet::new();
        let mut site_plans = Vec::new();
        for materializable in graph.materializable_consumer_plans() {
            ensure!(
                materializable
                    .source
                    .matches_effect_plan(&materializable.plan)
                    && materializable.consumer == *materializable.plan.consumer_site(),
                "graph materialization attestation does not match its consumer plan"
            );
            site_plans.push(materializable.plan.clone());
        }
        site_plans.extend(current_batch_leaves.into_iter().cloned());
        for plan in &site_plans {
            if !authorized_targets.contains(&plan.target_identity()) {
                continue;
            }
            let site = plan.consumer_site_identity();
            if !conflicting_sites.contains(&site) {
                match index.by_site.get(&site) {
                    Some(previous) if previous != plan => {
                        index.by_site.remove(&site);
                        conflicting_sites.insert(site);
                    }
                    Some(_) => {}
                    None => {
                        index.by_site.insert(site, plan.clone());
                    }
                }
            }
        }
        site_plans.extend(target_plans.into_iter().cloned());
        for plan in site_plans {
            let target = plan.target_identity();
            if !authorized_targets.contains(&target) {
                continue;
            }
            let variants = index.by_target.entry(target).or_default();
            if !variants.contains(&plan) {
                variants.push(plan.clone());
            }
        }
        for variants in index.by_target.values_mut() {
            variants.sort_by_key(|plan| {
                (
                    plan.effect_key.operation_kind.clone(),
                    plan.effect_key.static_operands.clone(),
                    plan.consumer_site_identity(),
                )
            });
        }
        Ok(index)
    }

    pub(super) fn plan_at_site(
        &self,
        module: &str,
        start: u32,
        end: u32,
    ) -> Option<&CallableEffectPlan> {
        self.by_site.get(&(module.to_string(), start, end))
    }

    fn target_plans(&self) -> impl Iterator<Item = &[CallableEffectPlan]> {
        self.by_target.values().map(Vec::as_slice)
    }

    pub(super) fn materialized_target_identities(&self) -> BTreeSet<OperationIdentity> {
        self.by_target.keys().cloned().collect()
    }

    pub(super) fn authorizes_target_operation(&self, operation: &AdmittedOperation) -> bool {
        self.by_target
            .get(&(operation.file.clone(), operation.start, operation.end))
            .is_some_and(|plans| {
                plans.iter().any(|plan| {
                    materialized_operation_matches(operation, plan, &operation.index_constraints)
                })
            })
    }
}

#[derive(Clone, Copy)]
enum OperandProjection {
    Target,
    Consumer,
}

fn operand_anchor(
    operand: &super::effect_plan::SemanticEffectOperand,
    projection: OperandProjection,
) -> Result<&SourceAnchor> {
    match projection {
        OperandProjection::Target => Ok(&operand.target_provenance),
        OperandProjection::Consumer => operand
            .consumer_provenance()
            .context("target-only effect operand has no consumer materialization anchor"),
    }
}

fn materialized_operation_matches(
    operation: &AdmittedOperation,
    plan: &CallableEffectPlan,
    index_constraints: &[AdmittedIndexConstraint],
) -> bool {
    operation.kind == plan.effect_key.operation_kind
        && operation.table == plan.effect_key.static_operands.get("table").cloned()
        && operation.index == plan.effect_key.static_operands.get("index").cloned()
        && operation.index_constraints.len() == index_constraints.len()
        && operation
            .index_constraints
            .iter()
            .zip(index_constraints)
            .all(|(left, right)| {
                left.field == right.field
                    && left.operator == right.operator
                    && left.value_source == right.value_source
            })
        && operation.order == plan.effect_key.static_operands.get("order").cloned()
        && operation.terminal == plan.effect_key.static_operands.get("terminal").cloned()
        && operation.limit == plan.effect_key.limit
        && operation.limit_argument_index == plan.effect_key.limit_argument_index
        && operation.function_reference
            == plan
                .effect_key
                .static_operands
                .get("functionReference")
                .cloned()
}

fn validate_materializable_descriptor(plan: &CallableEffectPlan) -> Result<()> {
    let operands = plan.dynamic_operands.len();
    match plan.effect_key.operation_kind.as_str() {
        "databaseNormalizeId" | "databaseGet" | "databaseInsert" | "databaseDelete" => {
            ensure!(
                operands == 1,
                "single-argument database effect plan has the wrong operand count"
            );
            ensure!(
                plan.effect_key.static_operands.contains_key("table"),
                "database effect plan has no static table"
            );
        }
        "databasePatch" | "databaseReplace" => {
            ensure!(
                operands == 2,
                "two-argument database effect plan has the wrong operand count"
            );
            ensure!(
                plan.effect_key.static_operands.contains_key("table"),
                "database effect plan has no static table"
            );
        }
        "databaseIndexQuery" => {
            ensure!(
                plan.effect_key.static_operands.contains_key("table")
                    && plan.effect_key.static_operands.contains_key("index")
                    && plan.effect_key.static_operands.contains_key("order")
                    && plan.effect_key.static_operands.contains_key("terminal"),
                "index-query effect plan has an incomplete static descriptor"
            );
            let expected_operands = plan.effect_key.index_constraints.len()
                + usize::from(plan.effect_key.limit_argument_index.is_some());
            ensure!(
                operands == expected_operands,
                "index-query constraints and dynamic terminal operands do not match the descriptor"
            );
        }
        "schedulerRunAfter" | "schedulerRunAt" => {
            ensure!(
                operands == 2,
                "scheduler effect plan has the wrong operand count"
            );
            ensure!(
                plan.effect_key
                    .static_operands
                    .contains_key("functionReference"),
                "scheduler effect plan has no static function reference"
            );
        }
        kind => anyhow::bail!("unsupported callable effect-plan operation kind {kind}"),
    }
    match plan.effect_key.operation_kind.as_str() {
        "databaseNormalizeId" => ensure!(
            plan.effect_key.timing == SemanticEffectTiming::Synchronous,
            "database normalize-ID plan must be synchronous"
        ),
        _ => ensure!(
            plan.effect_key.timing == SemanticEffectTiming::Suspending,
            "host effect plan must be suspending"
        ),
    }
    Ok(())
}

fn materialize_operation(
    modules: &BTreeMap<String, LoadedModule>,
    operations: &mut Vec<AdmittedOperation>,
    plan: &CallableEffectPlan,
    site: &SourceAnchor,
    projection: OperandProjection,
) -> Result<AuthorizedEffectLeaf> {
    validate_materializable_descriptor(plan)?;
    let source = module_source(modules, &site.module)?;
    let index_constraints = plan
        .effect_key
        .index_constraints
        .iter()
        .zip(&plan.dynamic_operands)
        .map(|(constraint, operand)| {
            let anchor = operand_anchor(operand, projection)?;
            ensure!(
                anchor.module == site.module
                    && anchor.source_sha256 == site.source_sha256
                    && anchor.start >= site.start
                    && anchor.end <= site.end,
                "effect-plan operand is outside its materialization site"
            );
            Ok(AdmittedIndexConstraint {
                field: constraint.field.clone(),
                operator: constraint.operator.clone(),
                value_source: source_slice(&source, anchor.start, anchor.end)?.to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let matching = operations
        .iter()
        .enumerate()
        .filter(|(_, operation)| {
            operation.file == site.module
                && operation.start == site.start
                && operation.end == site.end
                && materialized_operation_matches(operation, plan, &index_constraints)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() <= 1,
        "effect-plan materialization matched duplicate operation descriptors"
    );
    let operation_index = if let Some(index) = matching.first().copied() {
        index
    } else {
        let semantic_key = if plan.effect_key.operation_kind == "databaseIndexQuery" {
            serde_json::to_vec(&("authorized-index-query", &plan.effect_key))?
        } else {
            serde_json::to_vec(&("authorized-effect-site", &plan.effect_key, site))?
        };
        let (line, column) = line_column(&source, site.start);
        operations.push(AdmittedOperation {
            id: u32::try_from(operations.len() + 1)?,
            stable_key: format!("op_{}", &hash_bytes(&semantic_key)[..16]),
            kind: plan.effect_key.operation_kind.clone(),
            table: plan.effect_key.static_operands.get("table").cloned(),
            index: plan.effect_key.static_operands.get("index").cloned(),
            index_constraints,
            order: plan.effect_key.static_operands.get("order").cloned(),
            terminal: plan.effect_key.static_operands.get("terminal").cloned(),
            limit: plan.effect_key.limit,
            limit_argument_index: plan.effect_key.limit_argument_index,
            algorithm: None,
            function_reference: plan
                .effect_key
                .static_operands
                .get("functionReference")
                .cloned(),
            contract_version: None,
            selector: None,
            file: site.module.clone(),
            start: site.start,
            end: site.end,
            line,
            column,
            source: source_slice(&source, site.start, site.end)?.to_string(),
        });
        operations.len() - 1
    };
    let operation = &operations[operation_index];
    let arguments = plan
        .dynamic_operands
        .iter()
        .map(|operand| {
            let anchor = operand_anchor(operand, projection)?;
            ensure!(
                anchor.module == site.module
                    && anchor.source_sha256 == site.source_sha256
                    && anchor.start >= site.start
                    && anchor.end <= site.end,
                "effect-plan operand is outside its materialization site"
            );
            Ok(PlanSourceSpan {
                start: anchor.start,
                end: anchor.end,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let authorization_material = serde_json::to_vec(&(
        "authorized-effect-leaf",
        &plan.provenance,
        site,
        operation.id,
        &operation.stable_key,
    ))?;
    Ok(AuthorizedEffectLeaf {
        authorization_id: format!("effect_{}", &hash_bytes(&authorization_material)[..16]),
        operation_id: operation.id,
        operation_stable_key: operation.stable_key.clone(),
        operation_span: PlanSourceSpan {
            start: site.start,
            end: site.end,
        },
        arguments,
    })
}

pub(super) fn materialize_authorized_effect_targets(
    modules: &BTreeMap<String, LoadedModule>,
    sites: &AuthorizedEffectSiteIndex,
    excluded_targets: &BTreeSet<OperationIdentity>,
    operations: &mut Vec<AdmittedOperation>,
) -> Result<Vec<AuthorizedDirectEffectSite>> {
    let mut direct_sites = Vec::new();
    for plans in sites.target_plans() {
        let first = plans
            .first()
            .context("authorized effect target has no semantic plan")?;
        if excluded_targets.contains(&first.target_identity()) {
            continue;
        }
        let direct = supports_direct_effect_site(&first.effect_key);
        let mut variants = Vec::<AuthorizedDirectEffectVariant>::new();
        for plan in plans {
            ensure!(
                plan.provenance.target_effect == first.provenance.target_effect
                    && plan.provenance.target_callee == first.provenance.target_callee,
                "authorized effect target variants disagree about source provenance"
            );
            ensure!(
                supports_direct_effect_site(&plan.effect_key) == direct,
                "authorized effect target mixes direct and non-direct rewrite semantics"
            );
            let effect = materialize_operation(
                modules,
                operations,
                plan,
                &plan.provenance.target_effect,
                OperandProjection::Target,
            )?;
            if !direct {
                continue;
            }
            if let Some(previous) = variants
                .iter()
                .find(|variant| variant.effect_key == plan.effect_key)
            {
                ensure!(
                    previous.effect.operation_id == effect.operation_id
                        && previous.effect.operation_stable_key == effect.operation_stable_key
                        && previous.effect.operation_span == effect.operation_span
                        && previous.effect.arguments == effect.arguments
                        && previous.static_operands == plan.static_operands
                        && previous
                            .dynamic_operands
                            .iter()
                            .zip(&plan.dynamic_operands)
                            .all(|(previous, current)| {
                                previous.target_argument_index == current.target_argument_index
                                    && previous.target_provenance == current.target_provenance
                            })
                        && previous.dynamic_operands.len() == plan.dynamic_operands.len(),
                    "equivalent direct effect-site variants materialized different descriptors"
                );
                continue;
            }
            ensure!(
                variants.iter().all(|variant| {
                    variant.effect_key.static_operands != plan.effect_key.static_operands
                }),
                "one direct effect-site static tuple maps to conflicting descriptors"
            );
            variants.push(AuthorizedDirectEffectVariant {
                effect_key: plan.effect_key.clone(),
                static_operands: plan.static_operands.clone(),
                dynamic_operands: plan
                    .dynamic_operands
                    .iter()
                    .map(|operand| AuthorizedDirectDynamicOperand {
                        target_argument_index: operand.target_argument_index,
                        target_provenance: operand.target_provenance.clone(),
                    })
                    .collect(),
                effect,
            });
        }
        if !direct {
            continue;
        }
        variants.sort_by_key(|variant| variant.effect_key.static_operands.clone());
        let authorization_material = serde_json::to_vec(&(
            "authorized-direct-effect-site",
            &first.provenance.target_effect,
            &first.provenance.target_callee,
            variants
                .iter()
                .map(|variant| {
                    (
                        &variant.effect_key,
                        &variant.static_operands,
                        &variant.dynamic_operands,
                        variant.effect.operation_id,
                        &variant.effect.operation_stable_key,
                    )
                })
                .collect::<Vec<_>>(),
        ))?;
        direct_sites.push(AuthorizedDirectEffectSite {
            authorization_id: format!("site_{}", &hash_bytes(&authorization_material)[..16]),
            target_effect: first.provenance.target_effect.clone(),
            target_callee: first.provenance.target_callee.clone(),
            variants,
        });
    }
    Ok(direct_sites)
}

pub(super) fn materialize_authorized_batch_site(
    modules: &BTreeMap<String, LoadedModule>,
    sites: &AuthorizedEffectSiteIndex,
    operations: &mut Vec<AdmittedOperation>,
    module: &str,
    start: u32,
    end: u32,
) -> Result<Option<AuthorizedEffectLeaf>> {
    let Some(plan) = sites.plan_at_site(module, start, end) else {
        return Ok(None);
    };
    if plan
        .dynamic_operands
        .iter()
        .any(SemanticEffectOperand::is_target_only)
    {
        return Ok(None);
    }
    Ok(Some(materialize_operation(
        modules,
        operations,
        plan,
        plan.consumer_site(),
        OperandProjection::Consumer,
    )?))
}

pub(super) fn append_legacy_interprocedural_effect_operations(
    modules: &BTreeMap<String, LoadedModule>,
    specializations: &[LegacyInterproceduralEffectSpecialization],
    semantic_plan_targets: &BTreeSet<OperationIdentity>,
    operations: &mut Vec<AdmittedOperation>,
) -> Result<()> {
    let mut by_semantics = BTreeMap::new();
    for specialization in specializations
        .iter()
        .filter(|specialization| specialization.call_position == CallPosition::SequentialAwait)
        .filter(|specialization| {
            !semantic_plan_targets.contains(&(
                specialization.target_module.clone(),
                specialization.operation.start,
                specialization.operation.end,
            ))
        })
    {
        let operation = &specialization.operation;
        let key = (
            specialization.target_module.clone(),
            specialization.target_unit_id.clone(),
            operation.start,
            operation.end,
            operation.kind.clone(),
            operation.table.clone(),
            operation.index.clone(),
            operation
                .index_constraints
                .iter()
                .map(|constraint| (constraint.field.clone(), constraint.operator.clone()))
                .collect::<Vec<_>>(),
            operation.order.clone(),
            operation.terminal.clone(),
            (operation.limit, operation.limit_argument_index),
            operation.function_reference.clone(),
        );
        by_semantics.entry(key).or_insert(specialization);
    }
    for (_, specialization) in by_semantics {
        let operation = &specialization.operation;
        let admitted_kind = match operation.kind.as_str() {
            "auth.getUserIdentity" => "authenticationGetUserIdentity",
            "db.normalizeId" => "databaseNormalizeId",
            "db.query" => "databaseIndexQuery",
            "db.get" => "databaseGet",
            "db.insert" => "databaseInsert",
            "db.patch" => "databasePatch",
            "db.replace" => "databaseReplace",
            "db.delete" => "databaseDelete",
            "scheduler.runAfter" => "schedulerRunAfter",
            "scheduler.runAt" => "schedulerRunAt",
            other => other,
        };
        if operations.iter().any(|existing| {
            existing.file == specialization.target_module
                && existing.start == operation.start
                && existing.end == operation.end
                && existing.kind == admitted_kind
                && existing.table == operation.table
                && existing.index == operation.index
                && existing.order == operation.order
                && existing.terminal == operation.terminal
                && existing.limit == operation.limit
                && existing.limit_argument_index == operation.limit_argument_index
                && existing.function_reference == operation.function_reference
        }) {
            continue;
        }
        let source = module_source(modules, &specialization.target_module)?;
        let semantic_key = serde_json::to_vec(&(
            "legacy-interprocedural-effect",
            &specialization.target_module,
            &specialization.target_unit_id,
            operation.start,
            operation.end,
            &operation.kind,
            &operation.table,
            &operation.index,
            operation
                .index_constraints
                .iter()
                .map(|constraint| (&constraint.field, &constraint.operator))
                .collect::<Vec<_>>(),
            &operation.order,
            &operation.terminal,
            operation.limit,
            operation.limit_argument_index,
            &operation.function_reference,
        ))?;
        let (line, column) = line_column(&source, operation.start);
        operations.push(AdmittedOperation {
            id: u32::try_from(operations.len() + 1)?,
            stable_key: format!("op_{}", &hash_bytes(&semantic_key)[..16]),
            kind: admitted_kind.to_string(),
            table: operation.table.clone(),
            index: operation.index.clone(),
            index_constraints: operation
                .index_constraints
                .iter()
                .map(|constraint| AdmittedIndexConstraint {
                    field: constraint.field.clone(),
                    operator: constraint.operator.clone(),
                    value_source: constraint.value_source.clone(),
                })
                .collect(),
            order: operation.order.clone(),
            terminal: operation.terminal.clone(),
            limit: operation.limit,
            limit_argument_index: operation.limit_argument_index,
            algorithm: operation.algorithm.clone(),
            function_reference: operation.function_reference.clone(),
            contract_version: None,
            selector: None,
            file: specialization.target_module.clone(),
            start: operation.start,
            end: operation.end,
            line,
            column,
            source: source_slice(&source, operation.start, operation.end)?.to_string(),
        });
    }
    Ok(())
}
