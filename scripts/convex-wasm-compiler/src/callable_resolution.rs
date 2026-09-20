use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};

use super::{
    CallCandidate, GraphInput, LoadedModule, ParameterSummary, ReachableUnit, ReferenceOccurrence,
    SourceRange, UnitSummary, resolve_graph_import,
};

pub(super) type StaticCallableTarget = (String, String);
pub(super) type StaticSourceTarget = Option<StaticCallableTarget>;
pub(super) type StaticSourceTargetCache = BTreeMap<(String, String), StaticSourceTarget>;

pub(super) struct ResolvedStaticCall<'a> {
    pub(super) caller: &'a ReachableUnit,
    pub(super) call: &'a CallCandidate,
}

pub(super) struct ResolvedStaticReference<'a> {
    pub(super) caller: &'a ReachableUnit,
    pub(super) reference: &'a ReferenceOccurrence,
    pub(super) direct_call: bool,
}

pub(super) struct InexactStaticReference<'a> {
    pub(super) module: String,
    pub(super) reference: &'a ReferenceOccurrence,
}

pub(super) struct ReachableStaticCallIndex<'a> {
    calls_by_target: BTreeMap<StaticCallableTarget, Vec<ResolvedStaticCall<'a>>>,
    references_by_target: BTreeMap<StaticCallableTarget, Vec<ResolvedStaticReference<'a>>>,
    targets_by_callsite: BTreeMap<(String, u32, u32), StaticCallableTarget>,
    inexact_references_by_target: BTreeMap<StaticCallableTarget, Vec<InexactStaticReference<'a>>>,
}

impl<'a> ReachableStaticCallIndex<'a> {
    pub(super) fn calls_to(&self, target: &StaticCallableTarget) -> &[ResolvedStaticCall<'a>] {
        self.calls_by_target
            .get(target)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(super) fn references_to(
        &self,
        target: &StaticCallableTarget,
    ) -> &[ResolvedStaticReference<'a>] {
        self.references_by_target
            .get(target)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(super) fn calls_by_target(
        &self,
    ) -> impl Iterator<Item = (&StaticCallableTarget, &[ResolvedStaticCall<'a>])> {
        self.calls_by_target
            .iter()
            .map(|(target, calls)| (target, calls.as_slice()))
    }

    pub(super) fn dispatch_is_exact(&self, target: &StaticCallableTarget) -> bool {
        let references = self.references_to(target);
        !self.inexact_references_by_target.contains_key(target)
            && !references.is_empty()
            && references
                .iter()
                .all(|indexed| !indexed.reference.write && indexed.direct_call)
    }

    pub(super) fn inexact_references_to(
        &self,
        target: &StaticCallableTarget,
    ) -> &[InexactStaticReference<'a>] {
        self.inexact_references_by_target
            .get(target)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(super) fn target_for_call(
        &self,
        caller: &ReachableUnit,
        call: &CallCandidate,
    ) -> Option<&StaticCallableTarget> {
        self.targets_by_callsite
            .get(&(caller.id.clone(), call.start, call.end))
    }
}

pub(super) fn caller_parameter_for_reference<'a>(
    modules: &'a BTreeMap<String, LoadedModule>,
    caller: &ReachableUnit,
    argument: &SourceRange,
) -> Result<Option<&'a ParameterSummary>> {
    let module = modules
        .get(&caller.module)
        .context("callable graph caller module disappeared")?;
    let unit = module
        .summary
        .units
        .get(&caller.name)
        .context("callable graph caller unit disappeared")?;
    Ok(unit.parameters.iter().find(|parameter| {
        parameter.references.iter().any(|reference| {
            reference.read
                && !reference.write
                && reference.start == argument.start
                && reference.end == argument.end
        })
    }))
}

pub(super) fn resolve_static_source_target(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    caller_module: &str,
    callee: &str,
) -> Result<StaticSourceTarget> {
    resolve_static_source_target_inner(graph, modules, caller_module, callee, &mut BTreeSet::new())
}

fn resolve_static_source_target_inner(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    caller_module: &str,
    callee: &str,
    seen: &mut BTreeSet<(String, String)>,
) -> Result<StaticSourceTarget> {
    if !seen.insert((caller_module.to_string(), callee.to_string())) {
        return Ok(None);
    }
    let caller = modules
        .get(caller_module)
        .context("callable-resolution caller module disappeared")?;
    if let Some(unit) = caller.summary.units.get(callee) {
        if let Some(alias) = &unit.static_callable_alias {
            return resolve_static_source_target_inner(
                graph,
                modules,
                caller_module,
                &alias.target,
                seen,
            );
        }
        return Ok(Some((caller_module.to_string(), unit.name.clone())));
    }
    let Some(binding) = caller.summary.imports.get(callee) else {
        return Ok(None);
    };
    if binding.type_only {
        return Ok(None);
    }
    let resolved = resolve_graph_import(graph, caller_module, &binding.specifier)?;
    let Some(target_module) = modules.get(&resolved) else {
        return Ok(None);
    };
    let Some(target_name) = target_module.summary.exports.get(&binding.imported) else {
        return Ok(None);
    };
    resolve_static_source_target_inner(graph, modules, &resolved, target_name, seen)
}

pub(super) fn cached_static_source_target(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    cache: &mut StaticSourceTargetCache,
    caller_module: &str,
    callee: &str,
) -> Result<StaticSourceTarget> {
    let key = (caller_module.to_string(), callee.to_string());
    if let Some(target) = cache.get(&key) {
        return Ok(target.clone());
    }
    let target = resolve_static_source_target(graph, modules, caller_module, callee)?;
    cache.insert(key, target.clone());
    Ok(target)
}

pub(super) fn index_reachable_static_calls<'a>(
    graph: &GraphInput,
    modules: &'a BTreeMap<String, LoadedModule>,
    reachable: &'a BTreeMap<String, ReachableUnit>,
) -> Result<ReachableStaticCallIndex<'a>> {
    let mut owners_by_module = BTreeMap::<String, Vec<(&ReachableUnit, SourceRange)>>::new();
    for caller in reachable.values() {
        let module = modules
            .get(&caller.module)
            .context("reachable callable-resolution caller module disappeared")?;
        let callable_range = if caller.kind == "handler" {
            Some(SourceRange {
                start: caller.start,
                end: caller.end,
            })
        } else {
            module
                .summary
                .units
                .get(&caller.name)
                .context("reachable callable-resolution source unit disappeared")?
                .callable_range
                .clone()
        };
        let Some(callable_range) = callable_range else {
            continue;
        };
        ensure!(
            callable_range.start >= caller.start
                && callable_range.end <= caller.end
                && callable_range.start < callable_range.end,
            "reachable callable {} has an invalid authenticated callable range",
            caller.id
        );
        owners_by_module
            .entry(caller.module.clone())
            .or_default()
            .push((caller, callable_range));
    }
    for owners in owners_by_module.values() {
        validate_callable_owner_ranges(owners)?;
    }

    let unreachable_callable_ranges_by_module = modules
        .iter()
        .map(|(module_key, module)| {
            let reachable_ranges = owners_by_module
                .get(module_key)
                .into_iter()
                .flatten()
                .map(|(_, range)| (range.start, range.end))
                .collect::<BTreeSet<_>>();
            let unreachable_ranges = module
                .summary
                .units
                .values()
                .filter_map(unit_callable_range)
                .filter(|range| !reachable_ranges.contains(&(range.start, range.end)))
                .collect::<Vec<_>>();
            (module_key.clone(), unreachable_ranges)
        })
        .collect::<BTreeMap<_, _>>();

    let mut unique_calls = BTreeMap::<(String, u32, u32), (&ReachableUnit, &CallCandidate)>::new();
    let mut unique_references =
        BTreeMap::<(String, u32, u32), (&ReachableUnit, &ReferenceOccurrence)>::new();
    let mut unowned_references = Vec::new();
    let mut direct_calls = BTreeSet::<(String, u32, String)>::new();

    for (module_key, owners) in &owners_by_module {
        let module = modules
            .get(module_key)
            .context("callable-resolution owner module disappeared")?;
        for call in &module.summary.calls {
            let Some(caller) = innermost_callable_owner(owners, call.start, call.end)? else {
                continue;
            };
            direct_calls.insert((caller.id.clone(), call.callee_start, call.callee.clone()));
            ensure!(
                unique_calls
                    .insert(
                        (caller.module.clone(), call.start, call.end),
                        (caller, call)
                    )
                    .is_none(),
                "callable-resolution call fact is duplicated"
            );
        }
        for reference in &module.summary.references {
            let Some(caller) = innermost_callable_owner(owners, reference.start, reference.end)?
            else {
                if unreachable_callable_ranges_by_module
                    .get(module_key)
                    .into_iter()
                    .flatten()
                    .any(|range| reference.start >= range.start && reference.end <= range.end)
                {
                    continue;
                }
                unowned_references.push((module_key.clone(), reference));
                continue;
            };
            ensure!(
                unique_references
                    .insert(
                        (caller.module.clone(), reference.start, reference.end),
                        (caller, reference),
                    )
                    .is_none(),
                "callable-resolution reference fact is duplicated"
            );
        }
    }

    let mut static_targets = StaticSourceTargetCache::new();
    let mut calls_by_target = BTreeMap::<StaticCallableTarget, Vec<ResolvedStaticCall>>::new();
    let mut targets_by_callsite = BTreeMap::new();
    for ((_, start, end), (caller, call)) in unique_calls {
        let Some(target) = cached_static_source_target(
            graph,
            modules,
            &mut static_targets,
            &caller.module,
            &call.callee,
        )?
        else {
            continue;
        };
        ensure!(
            targets_by_callsite
                .insert((caller.id.clone(), start, end), target.clone())
                .is_none(),
            "callable-resolution callsite target is duplicated"
        );
        calls_by_target
            .entry(target)
            .or_default()
            .push(ResolvedStaticCall { caller, call });
    }

    let mut references_by_target =
        BTreeMap::<StaticCallableTarget, Vec<ResolvedStaticReference>>::new();
    for (_, (caller, reference)) in unique_references {
        let exact_alias_initializer = modules
            .get(&caller.module)
            .and_then(|module| module.summary.units.get(&caller.name))
            .and_then(|unit| unit.static_callable_alias.as_ref())
            .is_some_and(|alias| {
                alias.target == reference.name
                    && alias.reference.start == reference.start
                    && alias.reference.end == reference.end
                    && reference.read
                    && !reference.write
            });
        if exact_alias_initializer {
            continue;
        }
        let Some(target) = cached_static_source_target(
            graph,
            modules,
            &mut static_targets,
            &caller.module,
            &reference.name,
        )?
        else {
            continue;
        };
        references_by_target
            .entry(target)
            .or_default()
            .push(ResolvedStaticReference {
                caller,
                reference,
                direct_call: direct_calls.contains(&(
                    caller.id.clone(),
                    reference.start,
                    reference.name.clone(),
                )),
            });
    }

    let mut inexact_references_by_target =
        BTreeMap::<StaticCallableTarget, Vec<InexactStaticReference<'a>>>::new();
    for (module_key, reference) in unowned_references {
        let exact_alias_initializer = modules.get(&module_key).is_some_and(|module| {
            module.summary.units.values().any(|unit| {
                unit.static_callable_alias.as_ref().is_some_and(|alias| {
                    alias.target == reference.name
                        && alias.reference.start == reference.start
                        && alias.reference.end == reference.end
                        && reference.read
                        && !reference.write
                })
            })
        });
        if exact_alias_initializer {
            continue;
        }
        if let Some(target) = cached_static_source_target(
            graph,
            modules,
            &mut static_targets,
            &module_key,
            &reference.name,
        )? {
            inexact_references_by_target
                .entry(target)
                .or_default()
                .push(InexactStaticReference {
                    module: module_key,
                    reference,
                });
        }
    }

    Ok(ReachableStaticCallIndex {
        calls_by_target,
        references_by_target,
        targets_by_callsite,
        inexact_references_by_target,
    })
}

fn unit_callable_range(unit: &UnitSummary) -> Option<SourceRange> {
    unit.callable_range.clone().or_else(|| {
        unit.registration.as_ref().map(|registration| SourceRange {
            start: registration.handler_start,
            end: registration.handler_end,
        })
    })
}

fn validate_callable_owner_ranges(owners: &[(&ReachableUnit, SourceRange)]) -> Result<()> {
    for (index, (left_owner, left)) in owners.iter().enumerate() {
        for (right_owner, right) in &owners[index + 1..] {
            let disjoint = left.end <= right.start || right.end <= left.start;
            let left_contains = left.start <= right.start && left.end >= right.end;
            let right_contains = right.start <= left.start && right.end >= left.end;
            if !disjoint && !left_contains && !right_contains {
                bail!(
                    "reachable callable ranges partially overlap for {} and {}",
                    left_owner.id,
                    right_owner.id
                );
            }
            ensure!(
                left.start != right.start || left.end != right.end,
                "reachable callable range has multiple owners: {} and {}",
                left_owner.id,
                right_owner.id
            );
        }
    }
    Ok(())
}

fn innermost_callable_owner<'a>(
    owners: &[(&'a ReachableUnit, SourceRange)],
    start: u32,
    end: u32,
) -> Result<Option<&'a ReachableUnit>> {
    let mut selected = None::<(&ReachableUnit, u32)>;
    for (owner, range) in owners {
        if start < range.start || end > range.end {
            continue;
        }
        let width = range.end - range.start;
        match selected {
            Some((_, selected_width)) if selected_width < width => {}
            Some((selected_owner, selected_width)) if selected_width == width => bail!(
                "callable fact has ambiguous owners {} and {}",
                selected_owner.id,
                owner.id
            ),
            _ => selected = Some((owner, width)),
        }
    }
    Ok(selected.map(|(owner, _)| owner))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reachable_unit(id: &str, start: u32, end: u32) -> ReachableUnit {
        ReachableUnit {
            id: id.to_string(),
            module: "module.ts".to_string(),
            name: id.to_string(),
            start,
            end,
            source: String::new(),
            kind: "function".to_string(),
            dependency_chain: Vec::new(),
            dependencies: BTreeMap::new(),
        }
    }

    #[test]
    fn nested_callable_fact_belongs_to_innermost_owner() {
        let outer = reachable_unit("outer", 10, 100);
        let inner = reachable_unit("inner", 30, 60);
        let owners = vec![
            (
                &outer,
                SourceRange {
                    start: 10,
                    end: 100,
                },
            ),
            (&inner, SourceRange { start: 30, end: 60 }),
        ];

        validate_callable_owner_ranges(&owners).unwrap();
        assert_eq!(
            innermost_callable_owner(&owners, 40, 50)
                .unwrap()
                .map(|owner| owner.id.as_str()),
            Some("inner")
        );
        assert_eq!(
            innermost_callable_owner(&owners, 20, 25)
                .unwrap()
                .map(|owner| owner.id.as_str()),
            Some("outer")
        );
    }
}
