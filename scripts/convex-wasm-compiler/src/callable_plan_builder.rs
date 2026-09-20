use std::collections::{BTreeMap, BTreeSet};

use super::callable_effects::{
    CallEdge, EffectPropagationPolicy, EffectSpecialization, EffectTemplate,
    specialize_effects_with_policy,
};
use super::{EffectExecutionMode, OperationIdentity};

/// Effect specializations grouped by their authenticated consumer callsite.
///
/// The vector is intentional: one static helper call may represent several target effects. Legacy
/// batch projections may require one effect, but the generic callable plan must not discard the
/// rest merely because they share a callsite.
pub(super) struct PropagatedCallableEffects {
    by_consumer: BTreeMap<OperationIdentity, Vec<EffectSpecialization>>,
}

impl PropagatedCallableEffects {
    pub(super) fn iter(&self) -> impl Iterator<Item = &EffectSpecialization> {
        self.by_consumer.values().flatten()
    }
}

/// Propagates semantic effects through exact static calls without reconstructing JavaScript
/// control. Oxc-authenticated callsites and static operands remain compiler facts; Static Hermes
/// owns Promise consumption, branches, and continuations in guest mode.
pub(super) fn propagate_callable_effects(
    templates: &[EffectTemplate],
    calls: &[CallEdge],
    complete_targets: &BTreeSet<String>,
    effect_execution_mode: EffectExecutionMode,
) -> PropagatedCallableEffects {
    let policy = match effect_execution_mode {
        EffectExecutionMode::BlockingFiber => EffectPropagationPolicy::BlockingFiberCompatibility,
        EffectExecutionMode::GuestPromiseEventLoop => {
            EffectPropagationPolicy::StaticHermesGuestPromise
        }
    };
    let mut by_consumer = BTreeMap::<OperationIdentity, Vec<EffectSpecialization>>::new();
    for specialization in
        specialize_effects_with_policy(templates, calls, Some(complete_targets), policy)
    {
        by_consumer
            .entry((
                specialization.caller_module.clone(),
                specialization.call_start,
                specialization.call_end,
            ))
            .or_default()
            .push(specialization);
    }
    for effects in by_consumer.values_mut() {
        effects.sort_by(|left, right| {
            (&left.template_id, &left.static_operands, left.position).cmp(&(
                &right.template_id,
                &right.static_operands,
                right.position,
            ))
        });
        effects.dedup();
    }
    PropagatedCallableEffects { by_consumer }
}
