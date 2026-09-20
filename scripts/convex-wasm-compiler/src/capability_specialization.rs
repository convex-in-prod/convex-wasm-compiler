use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result, ensure};

use super::capability_flow::{CapabilityFlowProof, CapabilityPredicateEvaluation};
use super::capability_predicates::{
    CapabilitySourceEdit, apply_source_edits, edits_for_proved_true,
};
use super::{
    GraphInput, LoadedModule, PhaseMeasurements, ReachableUnit, compiler_pipeline_sha256,
    context_reuse, hash_bytes, module_summary_cache_key, summarize_module,
};

pub(super) fn specialize_proved_capability_branches(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    proof: &CapabilityFlowProof,
    phases: &mut PhaseMeasurements,
) -> Result<Option<BTreeMap<String, LoadedModule>>> {
    let mut edits_by_module = BTreeMap::<String, Vec<_>>::new();
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("reachable capability predicate module disappeared")?;
        for branch in module
            .summary
            .capability_branches
            .iter()
            .filter(|branch| branch.start >= unit.start && branch.end <= unit.end)
        {
            if proof.evaluate_predicate_test(graph, modules, unit, &branch.predicate)?
                != CapabilityPredicateEvaluation::ProvedTrue
            {
                continue;
            }
            let Ok(edits) = edits_for_proved_true(branch) else {
                continue;
            };
            edits_by_module
                .entry(unit.module.clone())
                .or_default()
                .extend(edits);
        }
    }
    if edits_by_module.is_empty() {
        return Ok(None);
    }

    for edits in edits_by_module.values_mut() {
        edits.sort_by_key(|edit| (edit.start, std::cmp::Reverse(edit.end), edit.replacement));
        let mut canonical = Vec::<CapabilitySourceEdit>::with_capacity(edits.len());
        for edit in edits.drain(..) {
            if let Some(previous) = canonical.last() {
                if previous.start == edit.start && previous.end == edit.end {
                    ensure!(
                        previous.replacement == edit.replacement,
                        "capability source edits conflict on one exact range"
                    );
                    continue;
                }
                if previous.end > edit.start {
                    ensure!(
                        previous.start <= edit.start && previous.end >= edit.end,
                        "capability source edits overlap without containment"
                    );
                    continue;
                }
            }
            canonical.push(edit);
        }
        *edits = canonical;
    }

    let mut specialized = modules.clone();
    for (module_key, edits) in edits_by_module {
        let module = modules
            .get(&module_key)
            .context("capability specialization module disappeared")?;
        let source = apply_source_edits(module.source.as_str(), &edits)?;
        let source_hash = hash_bytes(source.as_bytes());
        let pipeline_sha256 = compiler_pipeline_sha256();
        let policy_fingerprint = context_reuse::context_policy_fingerprint();
        let cache_key = module_summary_cache_key(
            &module_key,
            &source_hash,
            pipeline_sha256,
            policy_fingerprint,
        );
        let summary = summarize_module(
            &module_key,
            Path::new(&module_key),
            &source,
            &source_hash,
            &cache_key,
            pipeline_sha256,
            policy_fingerprint,
            phases,
        )?;
        specialized.insert(module_key, LoadedModule::new(summary, source));
    }
    Ok(Some(specialized))
}
