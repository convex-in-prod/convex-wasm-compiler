use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum StaticOperandField {
    Table,
    Index,
    FunctionReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StaticOperand {
    pub(crate) field: StaticOperandField,
    pub(crate) parameter_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectTemplate {
    pub(crate) id: String,
    pub(crate) unit_id: String,
    pub(crate) static_operands: Vec<StaticOperand>,
    pub(crate) timing: EffectTiming,
    pub(crate) tail_return_safe: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectTiming {
    Synchronous,
    Suspending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ArgumentFlow {
    LiteralString(String),
    Parameter {
        unit_id: String,
        parameter_index: usize,
    },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CallEdge {
    pub(crate) caller_module: String,
    pub(crate) call_start: u32,
    pub(crate) call_end: u32,
    pub(crate) target_unit_id: String,
    pub(crate) arguments: Vec<ArgumentFlow>,
    pub(crate) arguments_safe: bool,
    pub(crate) position: CallPosition,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CallPosition {
    Synchronous,
    SequentialAwait,
    TailReturn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectPropagationPolicy {
    BlockingFiberCompatibility,
    StaticHermesGuestPromise,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectSpecialization {
    pub(crate) template_id: String,
    pub(crate) caller_module: String,
    pub(crate) call_start: u32,
    pub(crate) call_end: u32,
    pub(crate) static_operands: BTreeMap<StaticOperandField, String>,
    pub(crate) position: CallPosition,
}

type ParameterKey = (String, usize);
type StaticValues = Option<BTreeSet<String>>;

fn resolve_argument(
    argument: &ArgumentFlow,
    incoming: &BTreeMap<&str, Vec<&CallEdge>>,
    complete_targets: Option<&BTreeSet<String>>,
    cache: &mut BTreeMap<ParameterKey, StaticValues>,
    visiting: &mut BTreeSet<ParameterKey>,
) -> StaticValues {
    match argument {
        ArgumentFlow::LiteralString(value) => Some(BTreeSet::from([value.clone()])),
        ArgumentFlow::Parameter {
            unit_id,
            parameter_index,
        } => resolve_parameter(
            unit_id,
            *parameter_index,
            incoming,
            complete_targets,
            cache,
            visiting,
        ),
        ArgumentFlow::Unknown => None,
    }
}

fn resolve_parameter(
    unit_id: &str,
    parameter_index: usize,
    incoming: &BTreeMap<&str, Vec<&CallEdge>>,
    complete_targets: Option<&BTreeSet<String>>,
    cache: &mut BTreeMap<ParameterKey, StaticValues>,
    visiting: &mut BTreeSet<ParameterKey>,
) -> StaticValues {
    let key = (unit_id.to_string(), parameter_index);
    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }
    if !visiting.insert(key.clone()) {
        return None;
    }
    if complete_targets.is_some_and(|targets| !targets.contains(unit_id)) {
        visiting.remove(&key);
        cache.insert(key, None);
        return None;
    }
    let mut values = BTreeSet::new();
    let mut complete = true;
    let calls = incoming.get(unit_id).map(Vec::as_slice).unwrap_or_default();
    if calls.is_empty() {
        complete = false;
    }
    for call in calls {
        let Some(argument) = call.arguments.get(parameter_index) else {
            complete = false;
            break;
        };
        let Some(argument_values) =
            resolve_argument(argument, incoming, complete_targets, cache, visiting)
        else {
            complete = false;
            break;
        };
        values.extend(argument_values);
    }
    visiting.remove(&key);
    let result = (complete && !values.is_empty()).then_some(values);
    cache.insert(key, result.clone());
    result
}

#[cfg(test)]
pub(crate) fn specialize_effects(
    templates: &[EffectTemplate],
    calls: &[CallEdge],
) -> Vec<EffectSpecialization> {
    specialize_effects_with_complete_targets(templates, calls, None)
}

pub(crate) fn specialize_effects_with_complete_targets(
    templates: &[EffectTemplate],
    calls: &[CallEdge],
    complete_targets: Option<&BTreeSet<String>>,
) -> Vec<EffectSpecialization> {
    specialize_effects_with_policy(
        templates,
        calls,
        complete_targets,
        EffectPropagationPolicy::BlockingFiberCompatibility,
    )
}

pub(crate) fn specialize_effects_with_policy(
    templates: &[EffectTemplate],
    calls: &[CallEdge],
    complete_targets: Option<&BTreeSet<String>>,
    policy: EffectPropagationPolicy,
) -> Vec<EffectSpecialization> {
    let mut incoming = BTreeMap::<&str, Vec<&CallEdge>>::new();
    for call in calls {
        incoming
            .entry(call.target_unit_id.as_str())
            .or_default()
            .push(call);
    }
    let mut cache = BTreeMap::new();
    let mut output = Vec::new();
    for template in templates {
        if complete_targets.is_some_and(|targets| !targets.contains(&template.unit_id)) {
            continue;
        }
        let calls = incoming
            .get(template.unit_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        for call in calls {
            if !call.arguments_safe {
                continue;
            }
            let compatible_position = match policy {
                EffectPropagationPolicy::BlockingFiberCompatibility => {
                    template.timing != EffectTiming::Suspending
                        || call.position == CallPosition::SequentialAwait
                        || (template.tail_return_safe && call.position == CallPosition::TailReturn)
                }
                // Static Hermes owns the Promise value, its eventual await, branches, and
                // continuations. The compiler only propagates the authenticated effect fact.
                EffectPropagationPolicy::StaticHermesGuestPromise => true,
            };
            if !compatible_position {
                continue;
            }
            let mut assignments = vec![BTreeMap::new()];
            for operand in &template.static_operands {
                let Some(argument) = call.arguments.get(operand.parameter_index) else {
                    assignments.clear();
                    break;
                };
                let Some(values) = resolve_argument(
                    argument,
                    &incoming,
                    complete_targets,
                    &mut cache,
                    &mut BTreeSet::new(),
                ) else {
                    assignments.clear();
                    break;
                };
                let mut expanded = Vec::new();
                for assignment in assignments {
                    for value in &values {
                        let mut specialized = assignment.clone();
                        specialized.insert(operand.field.clone(), value.clone());
                        expanded.push(specialized);
                    }
                }
                assignments = expanded;
            }
            output.extend(
                assignments
                    .into_iter()
                    .map(|static_operands| EffectSpecialization {
                        template_id: template.id.clone(),
                        caller_module: call.caller_module.clone(),
                        call_start: call.call_start,
                        call_end: call.call_end,
                        static_operands,
                        position: call.position,
                    }),
            );
        }
    }
    output.sort_by(|left, right| {
        (
            &left.template_id,
            &left.caller_module,
            left.call_start,
            left.call_end,
            &left.static_operands,
        )
            .cmp(&(
                &right.template_id,
                &right.caller_module,
                right.call_start,
                right.call_end,
                &right.static_operands,
            ))
    });
    output.dedup();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_operand(parameter_index: usize) -> StaticOperand {
        StaticOperand {
            field: StaticOperandField::Table,
            parameter_index,
        }
    }

    #[test]
    fn specializes_static_operand_through_two_forwarding_levels() {
        let templates = vec![EffectTemplate {
            id: "load:get".to_string(),
            unit_id: "load".to_string(),
            static_operands: vec![table_operand(1)],
            timing: EffectTiming::Suspending,
            tail_return_safe: false,
        }];
        let calls = vec![
            CallEdge {
                caller_module: "entry.ts".to_string(),
                call_start: 10,
                call_end: 20,
                target_unit_id: "outer".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::LiteralString("documents".to_string()),
                ],
                arguments_safe: true,
                position: CallPosition::TailReturn,
            },
            CallEdge {
                caller_module: "helper.ts".to_string(),
                call_start: 30,
                call_end: 40,
                target_unit_id: "inner".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::Parameter {
                        unit_id: "outer".to_string(),
                        parameter_index: 1,
                    },
                ],
                arguments_safe: true,
                position: CallPosition::TailReturn,
            },
            CallEdge {
                caller_module: "nested.ts".to_string(),
                call_start: 50,
                call_end: 60,
                target_unit_id: "load".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::Parameter {
                        unit_id: "inner".to_string(),
                        parameter_index: 1,
                    },
                ],
                arguments_safe: true,
                position: CallPosition::SequentialAwait,
            },
        ];
        let specializations = specialize_effects(&templates, &calls);
        assert_eq!(specializations.len(), 1);
        assert_eq!(specializations[0].caller_module, "nested.ts");
        assert_eq!(specializations[0].call_start, 50);
        assert_eq!(specializations[0].call_end, 60);
        assert_eq!(
            specializations[0]
                .static_operands
                .get(&StaticOperandField::Table),
            Some(&"documents".to_string())
        );
    }

    #[test]
    fn specializes_multiple_sequential_effect_templates_from_one_helper() {
        let templates = vec![
            EffectTemplate {
                id: "update:0:get".to_string(),
                unit_id: "update".to_string(),
                static_operands: vec![table_operand(1)],
                timing: EffectTiming::Suspending,
                tail_return_safe: false,
            },
            EffectTemplate {
                id: "update:1:patch".to_string(),
                unit_id: "update".to_string(),
                static_operands: vec![table_operand(1)],
                timing: EffectTiming::Suspending,
                tail_return_safe: false,
            },
        ];
        let calls = vec![CallEdge {
            caller_module: "entry.ts".to_string(),
            call_start: 1,
            call_end: 2,
            target_unit_id: "update".to_string(),
            arguments: vec![
                ArgumentFlow::Unknown,
                ArgumentFlow::LiteralString("documents".to_string()),
            ],
            arguments_safe: true,
            position: CallPosition::SequentialAwait,
        }];
        let specializations = specialize_effects(&templates, &calls);
        assert_eq!(
            specializations,
            vec![
                EffectSpecialization {
                    template_id: "update:0:get".to_string(),
                    caller_module: "entry.ts".to_string(),
                    call_start: 1,
                    call_end: 2,
                    position: CallPosition::SequentialAwait,
                    static_operands: BTreeMap::from([(
                        StaticOperandField::Table,
                        "documents".to_string(),
                    )]),
                },
                EffectSpecialization {
                    template_id: "update:1:patch".to_string(),
                    caller_module: "entry.ts".to_string(),
                    call_start: 1,
                    call_end: 2,
                    position: CallPosition::SequentialAwait,
                    static_operands: BTreeMap::from([(
                        StaticOperandField::Table,
                        "documents".to_string(),
                    )]),
                },
            ]
        );
    }

    #[test]
    fn ambiguous_or_dynamic_static_operand_fails_closed() {
        let templates = vec![EffectTemplate {
            id: "load:get".to_string(),
            unit_id: "load".to_string(),
            static_operands: vec![table_operand(1)],
            timing: EffectTiming::Suspending,
            tail_return_safe: false,
        }];
        let dynamic = vec![CallEdge {
            caller_module: "entry.ts".to_string(),
            call_start: 1,
            call_end: 2,
            target_unit_id: "load".to_string(),
            arguments: vec![ArgumentFlow::Unknown, ArgumentFlow::Unknown],
            arguments_safe: true,
            position: CallPosition::SequentialAwait,
        }];
        assert!(specialize_effects(&templates, &dynamic).is_empty());

        let incomplete_forwarding = vec![
            CallEdge {
                caller_module: "static_entry.ts".to_string(),
                call_start: 10,
                call_end: 20,
                target_unit_id: "forward".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::LiteralString("documents".to_string()),
                ],
                arguments_safe: true,
                position: CallPosition::TailReturn,
            },
            CallEdge {
                caller_module: "dynamic_entry.ts".to_string(),
                call_start: 30,
                call_end: 40,
                target_unit_id: "forward".to_string(),
                arguments: vec![ArgumentFlow::Unknown, ArgumentFlow::Unknown],
                arguments_safe: true,
                position: CallPosition::TailReturn,
            },
            CallEdge {
                caller_module: "helper.ts".to_string(),
                call_start: 50,
                call_end: 60,
                target_unit_id: "load".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::Parameter {
                        unit_id: "forward".to_string(),
                        parameter_index: 1,
                    },
                ],
                arguments_safe: true,
                position: CallPosition::SequentialAwait,
            },
        ];
        assert!(specialize_effects(&templates, &incomplete_forwarding).is_empty());
    }

    #[test]
    fn recursive_static_operand_flow_fails_closed() {
        let templates = vec![EffectTemplate {
            id: "load:get".to_string(),
            unit_id: "load".to_string(),
            static_operands: vec![table_operand(1)],
            timing: EffectTiming::Suspending,
            tail_return_safe: false,
        }];
        let calls = vec![
            CallEdge {
                caller_module: "first.ts".to_string(),
                call_start: 1,
                call_end: 2,
                target_unit_id: "second".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::Parameter {
                        unit_id: "first".to_string(),
                        parameter_index: 1,
                    },
                ],
                arguments_safe: true,
                position: CallPosition::TailReturn,
            },
            CallEdge {
                caller_module: "second.ts".to_string(),
                call_start: 3,
                call_end: 4,
                target_unit_id: "first".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::Parameter {
                        unit_id: "second".to_string(),
                        parameter_index: 1,
                    },
                ],
                arguments_safe: true,
                position: CallPosition::TailReturn,
            },
            CallEdge {
                caller_module: "first.ts".to_string(),
                call_start: 5,
                call_end: 6,
                target_unit_id: "load".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::Parameter {
                        unit_id: "first".to_string(),
                        parameter_index: 1,
                    },
                ],
                arguments_safe: true,
                position: CallPosition::SequentialAwait,
            },
        ];
        assert!(specialize_effects(&templates, &calls).is_empty());
    }

    #[test]
    fn specializes_suspending_effect_only_for_sequential_await() {
        let templates = vec![EffectTemplate {
            id: "load:get".to_string(),
            unit_id: "load".to_string(),
            static_operands: vec![table_operand(1)],
            timing: EffectTiming::Suspending,
            tail_return_safe: false,
        }];
        let calls = [
            (1, CallPosition::Synchronous),
            (3, CallPosition::SequentialAwait),
            (5, CallPosition::TailReturn),
        ]
        .into_iter()
        .map(|(call_start, position)| CallEdge {
            caller_module: "entry.ts".to_string(),
            call_start,
            call_end: call_start + 1,
            target_unit_id: "load".to_string(),
            arguments: vec![
                ArgumentFlow::Unknown,
                ArgumentFlow::LiteralString("documents".to_string()),
            ],
            arguments_safe: true,
            position,
        })
        .collect::<Vec<_>>();

        let specializations = specialize_effects(&templates, &calls);

        assert_eq!(specializations.len(), 1);
        assert_eq!(specializations[0].call_start, 3);
    }

    #[test]
    fn static_hermes_policy_propagates_suspending_effects_across_consumer_positions() {
        let templates = vec![EffectTemplate {
            id: "load:get".to_string(),
            unit_id: "load".to_string(),
            static_operands: vec![table_operand(1)],
            timing: EffectTiming::Suspending,
            tail_return_safe: false,
        }];
        let calls = [
            (1, CallPosition::Synchronous),
            (3, CallPosition::SequentialAwait),
            (5, CallPosition::TailReturn),
        ]
        .into_iter()
        .map(|(call_start, position)| CallEdge {
            caller_module: "entry.ts".to_string(),
            call_start,
            call_end: call_start + 1,
            target_unit_id: "load".to_string(),
            arguments: vec![
                ArgumentFlow::Unknown,
                ArgumentFlow::LiteralString("documents".to_string()),
            ],
            arguments_safe: true,
            position,
        })
        .collect::<Vec<_>>();

        let specializations = specialize_effects_with_policy(
            &templates,
            &calls,
            None,
            EffectPropagationPolicy::StaticHermesGuestPromise,
        );

        assert_eq!(
            specializations
                .iter()
                .map(|specialization| specialization.call_start)
                .collect::<Vec<_>>(),
            vec![1, 3, 5]
        );
    }

    #[test]
    fn unsafe_argument_evaluation_fails_closed() {
        let templates = vec![EffectTemplate {
            id: "load:get".to_string(),
            unit_id: "load".to_string(),
            static_operands: vec![table_operand(1)],
            timing: EffectTiming::Suspending,
            tail_return_safe: false,
        }];
        let calls = vec![CallEdge {
            caller_module: "entry.ts".to_string(),
            call_start: 1,
            call_end: 2,
            target_unit_id: "load".to_string(),
            arguments: vec![
                ArgumentFlow::Unknown,
                ArgumentFlow::LiteralString("documents".to_string()),
                ArgumentFlow::Unknown,
            ],
            arguments_safe: false,
            position: CallPosition::SequentialAwait,
        }];

        assert!(specialize_effects(&templates, &calls).is_empty());
    }

    #[test]
    fn incomplete_forwarding_dispatch_fails_closed() {
        let templates = vec![EffectTemplate {
            id: "load:get".to_string(),
            unit_id: "load".to_string(),
            static_operands: vec![table_operand(1)],
            timing: EffectTiming::Suspending,
            tail_return_safe: true,
        }];
        let calls = vec![
            CallEdge {
                caller_module: "entry.ts".to_string(),
                call_start: 1,
                call_end: 2,
                target_unit_id: "forward".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::LiteralString("documents".to_string()),
                ],
                arguments_safe: true,
                position: CallPosition::TailReturn,
            },
            CallEdge {
                caller_module: "helper.ts".to_string(),
                call_start: 3,
                call_end: 4,
                target_unit_id: "load".to_string(),
                arguments: vec![
                    ArgumentFlow::Unknown,
                    ArgumentFlow::Parameter {
                        unit_id: "forward".to_string(),
                        parameter_index: 1,
                    },
                ],
                arguments_safe: true,
                position: CallPosition::TailReturn,
            },
        ];

        assert!(
            specialize_effects_with_complete_targets(
                &templates,
                &calls,
                Some(&BTreeSet::from(["load".to_string()])),
            )
            .is_empty()
        );
        assert_eq!(
            specialize_effects_with_complete_targets(
                &templates,
                &calls,
                Some(&BTreeSet::from(
                    ["load".to_string(), "forward".to_string(),]
                )),
            )
            .len(),
            1
        );
    }

    #[test]
    fn incomplete_template_dispatch_rejects_a_direct_literal_call() {
        let templates = vec![EffectTemplate {
            id: "load:get".to_string(),
            unit_id: "load".to_string(),
            static_operands: vec![table_operand(1)],
            timing: EffectTiming::Suspending,
            tail_return_safe: true,
        }];
        let calls = vec![CallEdge {
            caller_module: "entry.ts".to_string(),
            call_start: 1,
            call_end: 2,
            target_unit_id: "load".to_string(),
            arguments: vec![
                ArgumentFlow::Unknown,
                ArgumentFlow::LiteralString("documents".to_string()),
            ],
            arguments_safe: true,
            position: CallPosition::TailReturn,
        }];

        assert!(
            specialize_effects_with_complete_targets(&templates, &calls, Some(&BTreeSet::new()),)
                .is_empty()
        );
    }
}
