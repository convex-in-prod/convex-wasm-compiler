use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::callable_control::{
    CallableControlEdgeKind, CallableControlInstructionKind, CallableControlPointKind,
    CallableControlSkeletonCandidate, CallableIntraBlockOrder,
};
use super::callable_effects::CallPosition;
use super::callable_plans::{
    AuthenticatedStaticActivationCallIndex, AuthenticatedStaticActivationCaller,
    AuthenticatedStaticActivationTarget, ResolvedBinding, ResolvedBindingIndex,
    ResolvedBindingReferenceIndex,
};
use super::{
    SourceRange, call_has_optional_callee, callee_identifier, count_node_type,
    is_static_member_call, node_type, span, unwrap_runtime_expression,
};

pub(super) const MAX_CALLABLE_VALUE_PATH_VARIANTS: usize = 32;

#[derive(Clone)]
pub(super) struct CallableValueBindingInitializer<'a> {
    pub(super) range: SourceRange,
    pub(super) value: &'a Value,
    pub(super) constant: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableValueBindingEdge {
    pub(super) binding: ResolvedBinding,
    pub(super) initializer: SourceRange,
    pub(super) reference: SourceRange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableValueParameterOrigin {
    pub(super) index: usize,
    pub(super) name: String,
    pub(super) declaration: SourceRange,
    pub(super) reference: SourceRange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableValueCallResultOrigin {
    pub(super) callsite: SourceRange,
    pub(super) callee: String,
    pub(super) callee_range: SourceRange,
}

#[derive(Clone)]
pub(super) struct ResolvedCallableValuePath<Origin, Step> {
    pub(super) origin: Origin,
    pub(super) steps: Vec<Step>,
}

pub(super) trait CallableValueDomain {
    type Origin: Clone;
    type Step: Clone;

    fn direct_origin(&self, value: &Value) -> Result<Option<Self::Origin>>;

    fn parameter_origin(&self, origin: CallableValueParameterOrigin) -> Self::Origin;

    fn call_result_origin(&self, origin: CallableValueCallResultOrigin) -> Self::Origin;

    /// Returns authenticated predecessor expressions and the domain edge from each predecessor to
    /// `value`. Ordinary aliases, exact calls, and finite choices are handled by the shared walker.
    fn predecessor_steps<'a>(
        &self,
        value: &'a Value,
        initializers: &BTreeMap<u32, CallableValueBindingInitializer<'a>>,
    ) -> Result<Option<Vec<(Self::Step, &'a Value)>>>;

    fn alias_step(&self, edge: CallableValueBindingEdge) -> Self::Step;

    fn choice_step(&self, site: SourceRange, branch: usize, child: SourceRange) -> Self::Step;
}

fn source_range(value: &Value) -> Result<SourceRange> {
    let (start, end) = span(unwrap_runtime_expression(value))?;
    Ok(SourceRange { start, end })
}

pub(super) fn collect_callable_value_binding_initializers<'a>(
    value: &'a Value,
    root: bool,
    output: &mut BTreeMap<u32, CallableValueBindingInitializer<'a>>,
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
            if object.get("type").and_then(Value::as_str) == Some("VariableDeclaration") {
                let constant = object.get("kind").and_then(Value::as_str) == Some("const");
                if let Some(declarations) = object.get("declarations").and_then(Value::as_array) {
                    for declaration in declarations {
                        let Some(identifier) = declaration.get("id") else {
                            continue;
                        };
                        if node_type(identifier).ok() != Some("Identifier") {
                            continue;
                        }
                        let Some(initializer) = declaration
                            .get("init")
                            .filter(|initializer| !initializer.is_null())
                        else {
                            continue;
                        };
                        let (binding_start, _) = span(identifier)?;
                        ensure!(
                            output
                                .insert(
                                    binding_start,
                                    CallableValueBindingInitializer {
                                        range: source_range(unwrap_runtime_expression(
                                            initializer
                                        ))?,
                                        value: initializer,
                                        constant,
                                    },
                                )
                                .is_none(),
                            "callable value binding has duplicate initializers"
                        );
                    }
                }
            }
            for child in object.values() {
                collect_callable_value_binding_initializers(child, false, output)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_callable_value_binding_initializers(child, false, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parameter_origin(
    value: &Value,
    parameter_names: &[String],
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
) -> Result<Option<CallableValueParameterOrigin>> {
    if node_type(value).ok() != Some("Identifier") {
        return Ok(None);
    }
    let (start, end) = span(value)?;
    let Some(binding) = bindings.get(&(start, end)) else {
        return Ok(None);
    };
    let Some(index) = parameter_starts
        .iter()
        .position(|parameter_start| *parameter_start == binding.declaration_start)
    else {
        return Ok(None);
    };
    let Some(name) = parameter_names.get(index) else {
        return Ok(None);
    };
    Ok(Some(CallableValueParameterOrigin {
        index,
        name: name.clone(),
        declaration: SourceRange {
            start: binding.declaration_start,
            end: binding.declaration_end,
        },
        reference: SourceRange { start, end },
    }))
}

fn exact_call_result_origin(value: &Value) -> Result<Option<CallableValueCallResultOrigin>> {
    if node_type(value).ok() != Some("CallExpression") || call_has_optional_callee(value) {
        return Ok(None);
    }
    let Some(callee) = callee_identifier(value) else {
        return Ok(None);
    };
    let Some(callee_value) = value.get("callee").map(unwrap_runtime_expression) else {
        return Ok(None);
    };
    let Some(arguments) = value.get("arguments").and_then(Value::as_array) else {
        return Ok(None);
    };
    if arguments.iter().any(|argument| {
        node_type(argument).ok() == Some("SpreadElement")
            || count_node_type(argument, "AwaitExpression") > 0
    }) {
        return Ok(None);
    }
    Ok(Some(CallableValueCallResultOrigin {
        callsite: source_range(value)?,
        callee,
        callee_range: source_range(callee_value)?,
    }))
}

pub(super) fn resolve_callable_value_expression<'a, Domain: CallableValueDomain>(
    value: &'a Value,
    parameter_names: &[String],
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    initializers: &BTreeMap<u32, CallableValueBindingInitializer<'a>>,
    resolving: &mut BTreeSet<u32>,
    domain: &Domain,
) -> Result<Vec<ResolvedCallableValuePath<Domain::Origin, Domain::Step>>> {
    let value = unwrap_runtime_expression(value);
    if let Some(origin) = domain.direct_origin(value)? {
        return Ok(vec![ResolvedCallableValuePath {
            origin,
            steps: Vec::new(),
        }]);
    }
    match node_type(value).ok() {
        Some("Identifier") => {
            let (start, end) = span(value)?;
            let Some(binding) = bindings.get(&(start, end)).cloned() else {
                return Ok(Vec::new());
            };
            if let Some(origin) =
                parameter_origin(value, parameter_names, parameter_starts, bindings)?
            {
                return Ok(vec![ResolvedCallableValuePath {
                    origin: domain.parameter_origin(origin),
                    steps: Vec::new(),
                }]);
            }
            let Some(initializer) = initializers.get(&binding.declaration_start).cloned() else {
                return Ok(Vec::new());
            };
            if !initializer.constant || !resolving.insert(binding.declaration_start) {
                return Ok(Vec::new());
            }
            let mut paths = resolve_callable_value_expression(
                initializer.value,
                parameter_names,
                parameter_starts,
                bindings,
                initializers,
                resolving,
                domain,
            )?;
            resolving.remove(&binding.declaration_start);
            for path in &mut paths {
                path.steps.push(domain.alias_step(CallableValueBindingEdge {
                    binding: binding.clone(),
                    initializer: initializer.range.clone(),
                    reference: SourceRange { start, end },
                }));
            }
            Ok(paths)
        }
        Some("CallExpression") => {
            if let Some(predecessors) = domain.predecessor_steps(value, initializers)? {
                let mut paths = Vec::new();
                for (step, predecessor) in predecessors {
                    let mut predecessor_paths = resolve_callable_value_expression(
                        predecessor,
                        parameter_names,
                        parameter_starts,
                        bindings,
                        initializers,
                        resolving,
                        domain,
                    )?;
                    for path in &mut predecessor_paths {
                        path.steps.push(step.clone());
                    }
                    paths.extend(predecessor_paths);
                    if paths.len() > MAX_CALLABLE_VALUE_PATH_VARIANTS {
                        return Ok(Vec::new());
                    }
                }
                return Ok(paths);
            }
            Ok(exact_call_result_origin(value)?
                .map(|origin| {
                    vec![ResolvedCallableValuePath {
                        origin: domain.call_result_origin(origin),
                        steps: Vec::new(),
                    }]
                })
                .unwrap_or_default())
        }
        Some("ConditionalExpression") => {
            let Some(consequent) = value.get("consequent") else {
                return Ok(Vec::new());
            };
            let Some(alternate) = value.get("alternate") else {
                return Ok(Vec::new());
            };
            let choice = source_range(value)?;
            let mut paths = resolve_callable_value_expression(
                consequent,
                parameter_names,
                parameter_starts,
                bindings,
                initializers,
                resolving,
                domain,
            )?;
            let consequent_range = source_range(unwrap_runtime_expression(consequent))?;
            for path in &mut paths {
                path.steps
                    .push(domain.choice_step(choice.clone(), 0, consequent_range.clone()));
            }
            let mut alternate_paths = resolve_callable_value_expression(
                alternate,
                parameter_names,
                parameter_starts,
                bindings,
                initializers,
                resolving,
                domain,
            )?;
            let alternate_range = source_range(unwrap_runtime_expression(alternate))?;
            for path in &mut alternate_paths {
                path.steps
                    .push(domain.choice_step(choice.clone(), 1, alternate_range.clone()));
            }
            paths.extend(alternate_paths);
            if paths.len() > MAX_CALLABLE_VALUE_PATH_VARIANTS {
                return Ok(Vec::new());
            }
            Ok(paths)
        }
        _ => Ok(Vec::new()),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub(super) enum CallableEffectValueOriginCandidate {
    Parameter {
        #[serde(flatten)]
        origin: CallableValueParameterOrigin,
    },
    CallResult {
        #[serde(flatten)]
        origin: CallableValueCallResultOrigin,
    },
    EffectSite {
        site: SourceRange,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub(super) enum CallableEffectValueStepCandidate {
    Alias {
        edge: CallableValueBindingEdge,
    },
    Choice {
        site: SourceRange,
        branch: usize,
        child: SourceRange,
    },
    PromiseAll {
        site: SourceRange,
        promise: SourceRange,
        argument: SourceRange,
        array_alias: Option<CallableValueBindingEdge>,
        child_index: usize,
        child_count: usize,
        child: SourceRange,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub(super) enum CallableEffectValueSinkCandidate {
    Await {
        site: SourceRange,
        value: SourceRange,
    },
    Return {
        site: SourceRange,
        value: SourceRange,
    },
    CallArgument {
        callsite: SourceRange,
        callee: String,
        callee_range: SourceRange,
        argument_index: usize,
        value: SourceRange,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableEffectValuePathCandidate {
    pub(super) origin: CallableEffectValueOriginCandidate,
    pub(super) steps: Vec<CallableEffectValueStepCandidate>,
    pub(super) sink: CallableEffectValueSinkCandidate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableEffectValueFlowRejectionCandidate {
    pub(super) origin: CallableEffectValueOriginCandidate,
    pub(super) range: SourceRange,
    pub(super) reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableEffectValueFlowCandidate {
    pub(super) callable_start: u32,
    pub(super) callable_end: u32,
    pub(super) parameter_count: usize,
    pub(super) paths: Vec<CallableEffectValuePathCandidate>,
    pub(super) rejections: Vec<CallableEffectValueFlowRejectionCandidate>,
}

struct EffectPromiseValueDomain<'a> {
    bindings: &'a ResolvedBindingIndex,
}

impl CallableValueDomain for EffectPromiseValueDomain<'_> {
    type Origin = CallableEffectValueOriginCandidate;
    type Step = CallableEffectValueStepCandidate;

    fn direct_origin(&self, value: &Value) -> Result<Option<Self::Origin>> {
        if node_type(value).ok() != Some("CallExpression")
            || call_has_optional_callee(value)
            || callee_identifier(value).is_some()
            || is_static_member_call(value, "Promise", "all")
        {
            return Ok(None);
        }
        Ok(Some(CallableEffectValueOriginCandidate::EffectSite {
            site: source_range(value)?,
        }))
    }

    fn parameter_origin(&self, origin: CallableValueParameterOrigin) -> Self::Origin {
        CallableEffectValueOriginCandidate::Parameter { origin }
    }

    fn call_result_origin(&self, origin: CallableValueCallResultOrigin) -> Self::Origin {
        CallableEffectValueOriginCandidate::CallResult { origin }
    }

    fn predecessor_steps<'a>(
        &self,
        value: &'a Value,
        initializers: &BTreeMap<u32, CallableValueBindingInitializer<'a>>,
    ) -> Result<Option<Vec<(Self::Step, &'a Value)>>> {
        if !is_static_member_call(value, "Promise", "all") {
            return Ok(None);
        }
        let Some(arguments) = value.get("arguments").and_then(Value::as_array) else {
            return Ok(Some(Vec::new()));
        };
        let [argument] = arguments.as_slice() else {
            return Ok(Some(Vec::new()));
        };
        let argument = unwrap_runtime_expression(argument);
        let argument_range = source_range(argument)?;
        let (array, array_alias) = match node_type(argument).ok() {
            Some("ArrayExpression") => (argument, None),
            Some("Identifier") => {
                let (start, end) = span(argument)?;
                let Some(binding) = self.bindings.get(&(start, end)).cloned() else {
                    return Ok(Some(Vec::new()));
                };
                let Some(initializer) = initializers.get(&binding.declaration_start) else {
                    return Ok(Some(Vec::new()));
                };
                let array = unwrap_runtime_expression(initializer.value);
                if !initializer.constant || node_type(array).ok() != Some("ArrayExpression") {
                    return Ok(Some(Vec::new()));
                }
                (
                    array,
                    Some(CallableValueBindingEdge {
                        binding,
                        initializer: initializer.range.clone(),
                        reference: SourceRange { start, end },
                    }),
                )
            }
            _ => return Ok(Some(Vec::new())),
        };
        let Some(elements) = array.get("elements").and_then(Value::as_array) else {
            return Ok(Some(Vec::new()));
        };
        let Some(promise) = value
            .get("callee")
            .map(unwrap_runtime_expression)
            .and_then(|callee| callee.get("object"))
            .map(unwrap_runtime_expression)
        else {
            return Ok(Some(Vec::new()));
        };
        let promise = source_range(promise)?;
        if self.bindings.contains_key(&(promise.start, promise.end)) {
            // A locally resolved Promise is an ordinary call. It creates no semantic aggregate
            // edge, so its effect children cannot acquire Promise authority from source spelling.
            return Ok(Some(Vec::new()));
        }
        let site = source_range(value)?;
        let mut predecessors = Vec::with_capacity(elements.len());
        for (child_index, element) in elements.iter().enumerate() {
            if element.is_null() || node_type(element).ok() == Some("SpreadElement") {
                return Ok(Some(Vec::new()));
            }
            predecessors.push((
                CallableEffectValueStepCandidate::PromiseAll {
                    site: site.clone(),
                    promise: promise.clone(),
                    argument: argument_range.clone(),
                    array_alias: array_alias.clone(),
                    child_index,
                    child_count: elements.len(),
                    child: source_range(unwrap_runtime_expression(element))?,
                },
                unwrap_runtime_expression(element),
            ));
        }
        Ok(Some(predecessors))
    }

    fn alias_step(&self, edge: CallableValueBindingEdge) -> Self::Step {
        CallableEffectValueStepCandidate::Alias { edge }
    }

    fn choice_step(&self, site: SourceRange, branch: usize, child: SourceRange) -> Self::Step {
        CallableEffectValueStepCandidate::Choice {
            site,
            branch,
            child,
        }
    }
}

struct EffectValueFlowCollection<'a> {
    parameter_names: &'a [String],
    parameter_starts: &'a [u32],
    bindings: &'a ResolvedBindingIndex,
    initializers: &'a BTreeMap<u32, CallableValueBindingInitializer<'a>>,
    paths: Vec<CallableEffectValuePathCandidate>,
}

impl EffectValueFlowCollection<'_> {
    fn resolved(
        &self,
        value: &Value,
    ) -> Result<
        Vec<
            ResolvedCallableValuePath<
                CallableEffectValueOriginCandidate,
                CallableEffectValueStepCandidate,
            >,
        >,
    > {
        resolve_callable_value_expression(
            value,
            self.parameter_names,
            self.parameter_starts,
            self.bindings,
            self.initializers,
            &mut BTreeSet::new(),
            &EffectPromiseValueDomain {
                bindings: self.bindings,
            },
        )
    }

    fn push_paths(
        &mut self,
        resolved: Vec<
            ResolvedCallableValuePath<
                CallableEffectValueOriginCandidate,
                CallableEffectValueStepCandidate,
            >,
        >,
        sink: impl Fn() -> CallableEffectValueSinkCandidate,
    ) {
        self.paths.extend(
            resolved
                .into_iter()
                .map(|path| CallableEffectValuePathCandidate {
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
                match object.get("type").and_then(Value::as_str) {
                    Some("AwaitExpression") => {
                        if let Some(argument) = object.get("argument") {
                            let resolved = self.resolved(argument)?;
                            let site = source_range(value)?;
                            let awaited = source_range(unwrap_runtime_expression(argument))?;
                            self.push_paths(resolved, || CallableEffectValueSinkCandidate::Await {
                                site: site.clone(),
                                value: awaited.clone(),
                            });
                        }
                    }
                    Some("ReturnStatement") => {
                        if let Some(returned) = object
                            .get("argument")
                            .filter(|argument| !argument.is_null())
                            .map(unwrap_runtime_expression)
                        {
                            let resolved = self.resolved(returned)?;
                            let site = source_range(value)?;
                            let returned = source_range(returned)?;
                            self.push_paths(resolved, || {
                                CallableEffectValueSinkCandidate::Return {
                                    site: site.clone(),
                                    value: returned.clone(),
                                }
                            });
                        }
                    }
                    Some("CallExpression") if !call_has_optional_callee(value) => {
                        if let (Some(callee), Some(callee_value), Some(arguments)) = (
                            callee_identifier(value),
                            value.get("callee").map(unwrap_runtime_expression),
                            value.get("arguments").and_then(Value::as_array),
                        ) {
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
                                let resolved = self.resolved(argument)?;
                                self.push_paths(resolved, || {
                                    CallableEffectValueSinkCandidate::CallArgument {
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
                    _ => {}
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

fn same_effect_value_origin(
    left: &CallableEffectValueOriginCandidate,
    right: &CallableEffectValueOriginCandidate,
) -> bool {
    match (left, right) {
        (
            CallableEffectValueOriginCandidate::Parameter { origin: left },
            CallableEffectValueOriginCandidate::Parameter { origin: right },
        ) => left.index == right.index && left.declaration == right.declaration,
        (
            CallableEffectValueOriginCandidate::CallResult { origin: left },
            CallableEffectValueOriginCandidate::CallResult { origin: right },
        ) => left.callsite == right.callsite,
        (
            CallableEffectValueOriginCandidate::EffectSite { site: left },
            CallableEffectValueOriginCandidate::EffectSite { site: right },
        ) => left == right,
        _ => false,
    }
}

fn effect_value_reference_accounting(
    paths: &[CallableEffectValuePathCandidate],
    binding_references: &ResolvedBindingReferenceIndex,
) -> Vec<CallableEffectValueFlowRejectionCandidate> {
    let mut origins = Vec::<CallableEffectValueOriginCandidate>::new();
    for path in paths {
        if !origins
            .iter()
            .any(|origin| same_effect_value_origin(origin, &path.origin))
        {
            origins.push(path.origin.clone());
        }
    }
    let mut rejections = Vec::new();
    for origin in origins {
        let mut declarations = BTreeSet::new();
        let mut recognized = BTreeSet::new();
        let mut exclusive_alias_references = BTreeMap::<(u32, u32), BTreeSet<(u32, u32)>>::new();
        for path in paths
            .iter()
            .filter(|path| same_effect_value_origin(&path.origin, &origin))
        {
            if let CallableEffectValueOriginCandidate::Parameter { origin, .. } = &path.origin {
                declarations.insert((origin.declaration.start, origin.declaration.end));
                recognized.insert((origin.reference.start, origin.reference.end));
            }
            for step in &path.steps {
                match step {
                    CallableEffectValueStepCandidate::Alias { edge } => {
                        declarations
                            .insert((edge.binding.declaration_start, edge.binding.declaration_end));
                        recognized.insert((edge.reference.start, edge.reference.end));
                    }
                    CallableEffectValueStepCandidate::PromiseAll {
                        array_alias: Some(edge),
                        ..
                    } => {
                        let declaration =
                            (edge.binding.declaration_start, edge.binding.declaration_end);
                        declarations.insert(declaration);
                        recognized.insert((edge.reference.start, edge.reference.end));
                        exclusive_alias_references
                            .entry(declaration)
                            .or_default()
                            .insert((edge.reference.start, edge.reference.end));
                    }
                    CallableEffectValueStepCandidate::Choice { .. }
                    | CallableEffectValueStepCandidate::PromiseAll {
                        array_alias: None, ..
                    } => {}
                }
            }
        }
        for declaration in declarations {
            for reference in binding_references
                .get(&declaration)
                .into_iter()
                .flatten()
                .filter(|reference| {
                    reference.write
                        || !recognized.contains(&(reference.start, reference.end))
                        || exclusive_alias_references
                            .get(&declaration)
                            .is_some_and(|references| {
                                references.len() != 1
                                    || !references.contains(&(reference.start, reference.end))
                            })
                })
            {
                let rejection = CallableEffectValueFlowRejectionCandidate {
                    origin: origin.clone(),
                    range: SourceRange {
                        start: reference.start,
                        end: reference.end,
                    },
                    reason: if reference.write {
                        "effect value binding is written".to_string()
                    } else {
                        "effect value escapes its authenticated callable flow".to_string()
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

pub(super) fn collect_callable_effect_value_flow(
    callable: &Value,
    callable_start: u32,
    callable_end: u32,
    parameter_names: &[String],
    parameter_starts: &[u32],
    bindings: &ResolvedBindingIndex,
    binding_references: &ResolvedBindingReferenceIndex,
) -> Result<CallableEffectValueFlowCandidate> {
    let mut initializers = BTreeMap::new();
    collect_callable_value_binding_initializers(callable, true, &mut initializers)?;
    let mut collection = EffectValueFlowCollection {
        parameter_names,
        parameter_starts,
        bindings,
        initializers: &initializers,
        paths: Vec::new(),
    };
    collection.collect(callable, true)?;
    collection.paths.sort_by_key(|path| {
        let origin = match &path.origin {
            CallableEffectValueOriginCandidate::Parameter { origin } => {
                (0, origin.declaration.start, origin.reference.start)
            }
            CallableEffectValueOriginCandidate::CallResult { origin } => {
                (1, origin.callsite.start, origin.callsite.end)
            }
            CallableEffectValueOriginCandidate::EffectSite { site } => (2, site.start, site.end),
        };
        let sink = match &path.sink {
            CallableEffectValueSinkCandidate::Await { site, .. }
            | CallableEffectValueSinkCandidate::Return { site, .. } => (site.start, site.end),
            CallableEffectValueSinkCandidate::CallArgument { callsite, .. } => {
                (callsite.start, callsite.end)
            }
        };
        (origin, sink)
    });
    collection.paths.dedup();
    let rejections = effect_value_reference_accounting(&collection.paths, binding_references);
    Ok(CallableEffectValueFlowCandidate {
        callable_start,
        callable_end,
        parameter_count: parameter_names.len(),
        paths: collection.paths,
        rejections,
    })
}

use super::callable_plans::{
    CallableControlCallPlan, CallableControlPlan, CallableValueFlowCandidate, callable_key,
    source_anchor,
};
use super::effect_plan::{
    CallableEffectPlan, CallableKey, SemanticEffectOperand, SemanticOperand,
    SemanticOperandProjection, SourceAnchor, validate_callable_effect_plan,
};
use super::{LoadedModule, OperationIdentity, ReachableUnit};

const MAX_EFFECT_VALUE_ROUTES: usize = 1024;
const MAX_EFFECT_VALUE_DEPTH: usize = 12;

/// Exact source provenance for a callable effect value. This intentionally excludes its
/// specialized descriptor and operands: the generic value graph must be able to authenticate the
/// JavaScript value before a caller provides static operands for lowering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedEffectValueSource {
    pub(super) target_callable: CallableKey,
    pub(super) target_callable_source: SourceAnchor,
    pub(super) target_effect: SourceAnchor,
    pub(super) target_callee: SourceAnchor,
    pub(super) capability_reference: SourceAnchor,
    pub(super) capability_binding: SourceAnchor,
    pub(super) capability_name: String,
}

impl AuthenticatedEffectValueSource {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            !self.target_callable.module.is_empty()
                && !self.target_callable.unit_id.is_empty()
                && self.target_callable.module == self.target_callable_source.module
                && !self.capability_name.is_empty(),
            "effect-value source has invalid callable or capability identity"
        );
        ensure!(
            source_anchor_contains(&self.target_callable_source, &self.target_effect)
                && source_anchor_contains(&self.target_effect, &self.target_callee)
                && source_anchor_contains(&self.target_callee, &self.capability_reference)
                && self.capability_binding.module == self.target_callable_source.module
                && self.capability_binding.source_sha256
                    == self.target_callable_source.source_sha256,
            "effect-value source has invalid exact provenance containment"
        );
        Ok(())
    }

    pub(super) fn matches_effect_plan(&self, plan: &CallableEffectPlan) -> bool {
        self.target_callable == plan.provenance.target_callable
            && self.target_callable_source == plan.provenance.target_callable_source
            && self.target_effect == plan.provenance.target_effect
            && self.target_callee == plan.provenance.target_callee
            && self.capability_reference == plan.provenance.capability_reference
            && self.capability_binding == plan.provenance.capability_binding
            && self.capability_name == plan.provenance.capability_name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AuthenticatedEffectValueOrigin {
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
    EffectSite {
        source: AuthenticatedEffectValueSource,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AuthenticatedEffectValueStep {
    Alias {
        binding: SourceAnchor,
        initializer: SourceAnchor,
        reference: SourceAnchor,
    },
    Choice {
        site: SourceAnchor,
        branch: usize,
        child: SourceAnchor,
    },
    PromiseAll {
        site: SourceAnchor,
        promise: SourceAnchor,
        argument: SourceAnchor,
        array_alias: Option<AuthenticatedPromiseAllArrayAlias>,
        child_index: usize,
        child_count: usize,
        child: SourceAnchor,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedPromiseAllArrayAlias {
    binding: SourceAnchor,
    initializer: SourceAnchor,
    reference: SourceAnchor,
    await_site: Option<SourceAnchor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AuthenticatedEffectValueSink {
    Await {
        site: SourceAnchor,
        value: SourceAnchor,
    },
    Return {
        site: SourceAnchor,
        value: SourceAnchor,
    },
    CallArgument {
        callsite: SourceAnchor,
        callee: String,
        callee_provenance: SourceAnchor,
        argument_index: usize,
        value: SourceAnchor,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedEffectValuePath {
    origin: AuthenticatedEffectValueOrigin,
    steps: Vec<AuthenticatedEffectValueStep>,
    sink: AuthenticatedEffectValueSink,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedEffectValuePathPrefix {
    origin: AuthenticatedEffectValueOrigin,
    steps: Vec<AuthenticatedEffectValueStep>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedEffectValueFlowRejection {
    origin: AuthenticatedEffectValueOrigin,
    provenance: SourceAnchor,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedCallableEffectValueFlow {
    callable: CallableKey,
    callable_source: SourceAnchor,
    parameter_count: usize,
    handler: bool,
    paths: Vec<AuthenticatedEffectValuePath>,
    rejections: Vec<AuthenticatedEffectValueFlowRejection>,
}

fn anchor_in_callable(callable: &SourceAnchor, anchor: &SourceAnchor) -> bool {
    callable.module == anchor.module
        && callable.source_sha256 == anchor.source_sha256
        && anchor.start >= callable.start
        && anchor.end <= callable.end
        && anchor.start < anchor.end
}

fn effect_value_binding_fact_at<'a>(
    modules: &'a BTreeMap<String, LoadedModule>,
    module: &str,
    declaration: &SourceRange,
) -> Option<&'a super::ResolvedBindingFact> {
    let matching = modules
        .get(module)?
        .summary
        .resolved_binding_facts
        .iter()
        .filter(|fact| fact.start == declaration.start && fact.end == declaration.end)
        .collect::<Vec<_>>();
    let [fact] = matching.as_slice() else {
        return None;
    };
    Some(*fact)
}

fn exact_effect_value_binding_fact<'a>(
    modules: &'a BTreeMap<String, LoadedModule>,
    module: &str,
    name: &str,
    declaration: &SourceRange,
    reference: &SourceRange,
) -> Option<&'a super::ResolvedBindingFact> {
    let fact = effect_value_binding_fact_at(modules, module, declaration)?;
    (fact.name == name
        && fact.references.iter().any(|candidate| {
            candidate.name == name
                && candidate.start == reference.start
                && candidate.end == reference.end
                && candidate.read
                && !candidate.write
        }))
    .then_some(fact)
}

fn exact_callable_parameter_fact<'a>(
    modules: &'a BTreeMap<String, LoadedModule>,
    module: &str,
    callable: &SourceAnchor,
) -> Result<&'a super::CallableParameterFact> {
    let matching = modules
        .get(module)
        .expect("authenticated effect-value module disappeared")
        .summary
        .callable_parameter_facts
        .iter()
        .filter(|fact| fact.callable_start == callable.start && fact.callable_end == callable.end)
        .collect::<Vec<_>>();
    let [fact] = matching.as_slice() else {
        anyhow::bail!("effect-value callable has no unique independent parameter fact");
    };
    Ok(*fact)
}

fn authenticate_effect_value_origin(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    callable: &SourceAnchor,
    parameters: &[super::CallableParameterEntryFact],
    control_plan: Option<&CallableControlPlan>,
    candidate: &CallableEffectValueOriginCandidate,
) -> Result<Option<AuthenticatedEffectValueOrigin>> {
    let origin = match candidate {
        CallableEffectValueOriginCandidate::Parameter { origin } => {
            let expected = parameters.get(origin.index);
            ensure!(
                expected.is_some_and(|expected| {
                    expected.index == origin.index
                        && expected.name == origin.name
                        && expected.start == origin.declaration.start
                }) && exact_effect_value_binding_fact(
                    modules,
                    module,
                    &origin.name,
                    &origin.declaration,
                    &origin.reference,
                )
                .is_some(),
                "effect-value parameter origin conflicts with exact Oxc parameter binding"
            );
            let declaration = source_anchor(
                modules,
                module,
                origin.declaration.start,
                origin.declaration.end,
            )?;
            let reference = source_anchor(
                modules,
                module,
                origin.reference.start,
                origin.reference.end,
            )?;
            ensure!(
                anchor_in_callable(callable, &declaration)
                    && anchor_in_callable(callable, &reference),
                "effect-value parameter provenance escaped its callable"
            );
            AuthenticatedEffectValueOrigin::Parameter {
                index: origin.index,
                name: origin.name.clone(),
                declaration,
                reference,
            }
        }
        CallableEffectValueOriginCandidate::CallResult { origin } => {
            let loaded = modules
                .get(module)
                .expect("authenticated effect-value module disappeared");
            let matching_calls = loaded
                .summary
                .calls
                .iter()
                .filter(|call| {
                    call.start == origin.callsite.start && call.end == origin.callsite.end
                })
                .collect::<Vec<_>>();
            let summary_call = match matching_calls.as_slice() {
                [] => return Ok(None),
                [summary_call] => *summary_call,
                _ => anyhow::bail!("effect-value call result has ambiguous independent call facts"),
            };
            ensure!(
                summary_call.callee == origin.callee
                    && summary_call.callee_start == origin.callee_range.start
                    && summary_call.callee_end == origin.callee_range.end,
                "effect-value call result conflicts with its independent call fact"
            );
            let callsite =
                source_anchor(modules, module, origin.callsite.start, origin.callsite.end)?;
            let callee_provenance = source_anchor(
                modules,
                module,
                origin.callee_range.start,
                origin.callee_range.end,
            )?;
            ensure!(
                anchor_in_callable(callable, &callsite)
                    && anchor_in_callable(callable, &callee_provenance)
                    && callee_provenance.start >= callsite.start
                    && callee_provenance.end <= callsite.end,
                "effect-value call-result provenance escaped its exact callsite"
            );
            AuthenticatedEffectValueOrigin::CallResult {
                callsite,
                callee: origin.callee.clone(),
                callee_provenance,
            }
        }
        CallableEffectValueOriginCandidate::EffectSite { site } => {
            let Some(control_plan) = control_plan else {
                return Ok(None);
            };
            let site = source_anchor(modules, module, site.start, site.end)?;
            ensure!(
                anchor_in_callable(callable, &site),
                "effect-value effect-site provenance escaped its callable"
            );
            let matching = control_plan
                .source_effects
                .iter()
                .filter(|effect| {
                    effect.source.target_callable == control_plan.callable
                        && effect.source.target_callable_source == control_plan.callable_source
                        && effect.source.target_effect == site
                })
                .collect::<Vec<_>>();
            let [effect] = matching.as_slice() else {
                return Ok(None);
            };
            AuthenticatedEffectValueOrigin::EffectSite {
                source: effect.source.clone(),
            }
        }
    };
    Ok(Some(origin))
}

fn authenticate_effect_value_step(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    callable: &SourceAnchor,
    candidate: &CallableEffectValueStepCandidate,
) -> Result<AuthenticatedEffectValueStep> {
    let anchor = |range: &SourceRange| {
        source_anchor(modules, module, range.start, range.end).and_then(|anchor| {
            ensure!(
                anchor_in_callable(callable, &anchor),
                "effect-value step provenance escaped its callable"
            );
            Ok(anchor)
        })
    };
    Ok(match candidate {
        CallableEffectValueStepCandidate::Alias { edge } => {
            let declaration = SourceRange {
                start: edge.binding.declaration_start,
                end: edge.binding.declaration_end,
            };
            let fact = exact_effect_value_binding_fact(
                modules,
                module,
                &edge.binding.name,
                &declaration,
                &edge.reference,
            );
            ensure!(
                fact.is_some_and(|fact| {
                    fact.constant
                        && fact.initializer_start == Some(edge.initializer.start)
                        && fact.initializer_end == Some(edge.initializer.end)
                }),
                "effect-value alias conflicts with exact Oxc binding flow"
            );
            AuthenticatedEffectValueStep::Alias {
                binding: anchor(&declaration)?,
                initializer: anchor(&edge.initializer)?,
                reference: anchor(&edge.reference)?,
            }
        }
        CallableEffectValueStepCandidate::Choice {
            site,
            branch,
            child,
        } => {
            let loaded = modules
                .get(module)
                .expect("authenticated effect-value module disappeared");
            let matching = loaded
                .summary
                .conditional_expression_facts
                .iter()
                .filter(|fact| fact.start == site.start && fact.end == site.end)
                .collect::<Vec<_>>();
            let [fact] = matching.as_slice() else {
                anyhow::bail!("effect-value choice has no unique conditional expression fact");
            };
            let expected_child = match branch {
                0 => (fact.consequent_start, fact.consequent_end),
                1 => (fact.alternate_start, fact.alternate_end),
                _ => anyhow::bail!("effect-value choice branch is outside its conditional"),
            };
            ensure!(
                expected_child == (child.start, child.end),
                "effect-value choice conflicts with exact conditional branch provenance"
            );
            AuthenticatedEffectValueStep::Choice {
                site: anchor(site)?,
                branch: *branch,
                child: anchor(child)?,
            }
        }
        CallableEffectValueStepCandidate::PromiseAll {
            site,
            promise,
            argument,
            array_alias,
            child_index,
            child_count,
            child,
        } => {
            let site = anchor(site)?;
            let promise = anchor(promise)?;
            let argument = anchor(argument)?;
            let child = anchor(child)?;
            ensure!(
                promise.start >= site.start
                    && promise.end <= site.end
                    && argument.start >= site.start
                    && argument.end <= site.end
                    && *child_count > 0,
                "Promise.all effect-value edge escaped its callsite"
            );
            let loaded = modules
                .get(module)
                .expect("authenticated effect-value module disappeared");
            let matching_sites = loaded
                .summary
                .promise_all_sites
                .iter()
                .filter(|candidate| candidate.start == site.start && candidate.end == site.end)
                .collect::<Vec<_>>();
            let [promise_all_site] = matching_sites.as_slice() else {
                anyhow::bail!("effect-value Promise.all edge has no unique callsite fact");
            };
            ensure!(
                promise_all_site.promise_start == promise.start
                    && promise_all_site.promise_end == promise.end
                    && promise_all_site.argument_start == Some(argument.start)
                    && promise_all_site.argument_end == Some(argument.end)
                    && loaded.summary.globals.iter().any(|global| {
                        global.name == "Promise"
                            && global.read
                            && !global.write
                            && global.start == promise.start
                            && global.end == promise.end
                    }),
                "effect-value Promise.all edge lacks unshadowed global provenance"
            );
            let array_alias = match array_alias {
                None => {
                    ensure!(
                        child.start >= argument.start
                            && child.end <= argument.end
                            && promise_all_site.elements.len() == *child_count
                            && promise_all_site
                                .elements
                                .get(*child_index)
                                .is_some_and(|element| {
                                    element.start == child.start && element.end == child.end
                                }),
                        "Promise.all child conflicts with exact element provenance"
                    );
                    None
                }
                Some(edge) => {
                    let declaration = SourceRange {
                        start: edge.binding.declaration_start,
                        end: edge.binding.declaration_end,
                    };
                    let fact = exact_effect_value_binding_fact(
                        modules,
                        module,
                        &edge.binding.name,
                        &declaration,
                        &edge.reference,
                    );
                    ensure!(
                        fact.is_some_and(|fact| {
                            fact.constant
                                && fact.initializer_start == Some(edge.initializer.start)
                                && fact.initializer_end == Some(edge.initializer.end)
                                && fact.array_elements.as_ref().is_some_and(|elements| {
                                    elements.len() == *child_count
                                        && elements.get(*child_index).is_some_and(|element| {
                                            element.start == child.start && element.end == child.end
                                        })
                                })
                        }),
                        "Promise.all array alias conflicts with exact Oxc binding flow"
                    );
                    let binding = anchor(&declaration)?;
                    let initializer = anchor(&edge.initializer)?;
                    let reference = anchor(&edge.reference)?;
                    ensure!(
                        reference == argument
                            && initializer.end <= argument.start
                            && child.start >= initializer.start
                            && child.end <= initializer.end,
                        "Promise.all array alias escaped its exact binding provenance"
                    );
                    let matching_handoffs = loaded
                        .summary
                        .promise_all_alias_handoffs
                        .iter()
                        .filter(|handoff| {
                            handoff.binding_start == binding.start
                                && handoff.binding_end == binding.end
                                && handoff.promise_all_start == site.start
                                && handoff.promise_all_end == site.end
                                && handoff.argument_start == argument.start
                                && handoff.argument_end == argument.end
                        })
                        .collect::<Vec<_>>();
                    let await_site = match matching_handoffs.as_slice() {
                        [] => None,
                        [handoff] => {
                            let await_site = source_anchor(
                                modules,
                                module,
                                handoff.await_start,
                                handoff.await_end,
                            )?;
                            ensure!(
                                site.start >= await_site.start && site.end <= await_site.end,
                                "Promise.all array alias handoff escaped its awaited aggregate"
                            );
                            Some(await_site)
                        }
                        _ => anyhow::bail!(
                            "Promise.all array alias has conflicting immediate awaited handoff facts"
                        ),
                    };
                    Some(AuthenticatedPromiseAllArrayAlias {
                        binding,
                        initializer,
                        reference,
                        await_site,
                    })
                }
            };
            AuthenticatedEffectValueStep::PromiseAll {
                site,
                promise,
                argument,
                array_alias,
                child_index: *child_index,
                child_count: *child_count,
                child,
            }
        }
    })
}

enum EffectValueSinkAuthentication {
    Authenticated(AuthenticatedEffectValueSink),
    UnrepresentedCallArgument {
        callsite: SourceAnchor,
        value: SourceAnchor,
    },
}

fn authenticate_effect_value_sink(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    callable: &SourceAnchor,
    candidate: &CallableEffectValueSinkCandidate,
) -> Result<EffectValueSinkAuthentication> {
    let loaded = modules
        .get(module)
        .expect("authenticated effect-value module disappeared");
    let mut skeletons = loaded
        .summary
        .callable_control_skeletons
        .iter()
        .filter(|skeleton| {
            skeleton.callable_start == callable.start && skeleton.callable_end == callable.end
        });
    let skeleton = match (skeletons.next(), skeletons.next()) {
        (Some(skeleton), None) => skeleton,
        _ => anyhow::bail!("effect-value sink has no exact Oxc callable control skeleton"),
    };
    let anchor = |range: &SourceRange| {
        source_anchor(modules, module, range.start, range.end).and_then(|anchor| {
            ensure!(
                anchor_in_callable(callable, &anchor),
                "effect-value sink provenance escaped its callable"
            );
            Ok(anchor)
        })
    };
    Ok(EffectValueSinkAuthentication::Authenticated(
        match candidate {
            CallableEffectValueSinkCandidate::Await { site, value } => {
                ensure!(
                    skeleton.points.iter().any(|point| {
                        point.kind == CallableControlPointKind::Await
                            && point.start == site.start
                            && point.end == site.end
                            && point.value_start == Some(value.start)
                            && point.value_end == Some(value.end)
                    }),
                    "effect-value await sink conflicts with its exact Oxc operand provenance"
                );
                let site = anchor(site)?;
                let value = anchor(value)?;
                ensure!(
                    value.start >= site.start && value.end <= site.end,
                    "effect-value await value escaped its exact sink site"
                );
                AuthenticatedEffectValueSink::Await { site, value }
            }
            CallableEffectValueSinkCandidate::Return { site, value } => {
                ensure!(
                    skeleton.blocks.iter().any(|block| {
                        block.instructions.iter().any(|instruction| {
                            instruction.kind == CallableControlInstructionKind::Return
                                && instruction.start == Some(site.start)
                                && instruction.end == Some(site.end)
                                && instruction.value_start == Some(value.start)
                                && instruction.value_end == Some(value.end)
                        })
                    }),
                    "effect-value return sink conflicts with its exact Oxc operand provenance"
                );
                let site = anchor(site)?;
                let value = anchor(value)?;
                ensure!(
                    value.start >= site.start && value.end <= site.end,
                    "effect-value return value escaped its exact sink site"
                );
                AuthenticatedEffectValueSink::Return { site, value }
            }
            CallableEffectValueSinkCandidate::CallArgument {
                callsite,
                callee,
                callee_range,
                argument_index,
                value,
            } => {
                ensure!(
                    skeleton.points.iter().any(|point| {
                        point.kind == CallableControlPointKind::Call
                            && point.start == callsite.start
                            && point.end == callsite.end
                    }),
                    "effect-value call-argument sink lacks Oxc control provenance"
                );
                let callsite = anchor(callsite)?;
                let callee_provenance = anchor(callee_range)?;
                let value = anchor(value)?;
                let matching_calls = loaded
                    .summary
                    .calls
                    .iter()
                    .filter(|call| call.start == callsite.start && call.end == callsite.end)
                    .collect::<Vec<_>>();
                let summary_call = match matching_calls.as_slice() {
                    [] => {
                        return Ok(EffectValueSinkAuthentication::UnrepresentedCallArgument {
                            callsite,
                            value,
                        });
                    }
                    [summary_call] => *summary_call,
                    _ => {
                        anyhow::bail!(
                            "effect-value call argument has ambiguous independent call facts"
                        )
                    }
                };
                ensure!(
                    callee_provenance.start >= callsite.start
                        && callee_provenance.end <= callsite.end
                        && value.start >= callsite.start
                        && value.end <= callsite.end,
                    "effect-value call-argument provenance escaped its callsite"
                );
                ensure!(
                    summary_call.callee == *callee
                        && summary_call.callee_start == callee_provenance.start
                        && summary_call.callee_end == callee_provenance.end
                        && summary_call
                            .arguments
                            .get(*argument_index)
                            .is_some_and(|argument| {
                                argument.start == value.start && argument.end == value.end
                            }),
                    "effect-value call argument conflicts with its independent call fact"
                );
                AuthenticatedEffectValueSink::CallArgument {
                    callsite,
                    callee: callee.clone(),
                    callee_provenance,
                    argument_index: *argument_index,
                    value,
                }
            }
        },
    ))
}

fn authenticate_effect_value_path_continuity_to(
    origin: &AuthenticatedEffectValueOrigin,
    steps: &[AuthenticatedEffectValueStep],
    sink_value: &SourceAnchor,
) -> Result<()> {
    let mut cursor = match origin {
        AuthenticatedEffectValueOrigin::Parameter { reference, .. } => reference,
        AuthenticatedEffectValueOrigin::CallResult { callsite, .. } => callsite,
        AuthenticatedEffectValueOrigin::EffectSite { source } => &source.target_effect,
    };
    for step in steps {
        let (input, output) = match step {
            AuthenticatedEffectValueStep::Alias {
                initializer,
                reference,
                ..
            } => (initializer, reference),
            AuthenticatedEffectValueStep::Choice { site, child, .. }
            | AuthenticatedEffectValueStep::PromiseAll { site, child, .. } => (child, site),
        };
        ensure!(
            cursor == input,
            "effect-value path conflicts with ordered expression provenance"
        );
        cursor = output;
    }
    ensure!(
        cursor == sink_value,
        "effect-value path conflicts with ordered expression provenance"
    );
    Ok(())
}

fn authenticate_effect_value_path_continuity(path: &AuthenticatedEffectValuePath) -> Result<()> {
    let sink_value = match &path.sink {
        AuthenticatedEffectValueSink::Await { value, .. }
        | AuthenticatedEffectValueSink::Return { value, .. }
        | AuthenticatedEffectValueSink::CallArgument { value, .. } => value,
    };
    authenticate_effect_value_path_continuity_to(&path.origin, &path.steps, sink_value)
}

fn expected_effect_value_rejections(
    modules: &BTreeMap<String, LoadedModule>,
    module: &str,
    callable: &SourceAnchor,
    paths: &[AuthenticatedEffectValuePathPrefix],
) -> Result<Vec<AuthenticatedEffectValueFlowRejection>> {
    let mut origins = Vec::new();
    for path in paths {
        if !origins
            .iter()
            .any(|origin| same_authenticated_effect_value_origin(origin, &path.origin))
        {
            origins.push(path.origin.clone());
        }
    }
    let mut expected = Vec::new();
    for origin in origins {
        let mut declarations = BTreeSet::new();
        let mut recognized = BTreeSet::new();
        let mut exclusive_alias_references = BTreeMap::<(u32, u32), BTreeSet<(u32, u32)>>::new();
        for path in paths
            .iter()
            .filter(|path| same_authenticated_effect_value_origin(&origin, &path.origin))
        {
            if let AuthenticatedEffectValueOrigin::Parameter {
                declaration,
                reference,
                ..
            } = &path.origin
            {
                declarations.insert((declaration.start, declaration.end));
                recognized.insert((reference.start, reference.end));
            }
            for step in &path.steps {
                match step {
                    AuthenticatedEffectValueStep::Alias {
                        binding, reference, ..
                    } => {
                        declarations.insert((binding.start, binding.end));
                        recognized.insert((reference.start, reference.end));
                    }
                    AuthenticatedEffectValueStep::PromiseAll {
                        array_alias: Some(alias),
                        ..
                    } => {
                        let declaration = (alias.binding.start, alias.binding.end);
                        declarations.insert(declaration);
                        recognized.insert((alias.reference.start, alias.reference.end));
                        exclusive_alias_references
                            .entry(declaration)
                            .or_default()
                            .insert((alias.reference.start, alias.reference.end));
                    }
                    AuthenticatedEffectValueStep::Choice { .. }
                    | AuthenticatedEffectValueStep::PromiseAll {
                        array_alias: None, ..
                    } => {}
                }
            }
        }
        for (start, end) in declarations {
            let declaration = SourceRange { start, end };
            let fact = effect_value_binding_fact_at(modules, module, &declaration)
                .context("effect-value declaration has no unique resolved binding fact")?;
            for reference in fact.references.iter().filter(|reference| {
                reference.write
                    || !recognized.contains(&(reference.start, reference.end))
                    || exclusive_alias_references
                        .get(&(start, end))
                        .is_some_and(|references| {
                            references.len() != 1
                                || !references.contains(&(reference.start, reference.end))
                        })
            }) {
                let provenance = source_anchor(modules, module, reference.start, reference.end)?;
                ensure!(
                    anchor_in_callable(callable, &provenance),
                    "effect-value binding reference escaped its callable provenance"
                );
                let rejection = AuthenticatedEffectValueFlowRejection {
                    origin: origin.clone(),
                    provenance,
                    reason: if reference.write {
                        "effect value binding is written".to_string()
                    } else {
                        "effect value escapes its authenticated callable flow".to_string()
                    },
                };
                if !expected.contains(&rejection) {
                    expected.push(rejection);
                }
            }
        }
    }
    expected.sort_by_key(|rejection| {
        (
            rejection.provenance.start,
            rejection.provenance.end,
            rejection.reason.clone(),
        )
    });
    Ok(expected)
}

fn authenticate_callable_effect_value_flows_inner(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    control_plans: Option<&BTreeMap<CallableKey, CallableControlPlan>>,
) -> Result<Vec<AuthenticatedCallableEffectValueFlow>> {
    let mut flows = Vec::<AuthenticatedCallableEffectValueFlow>::new();
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .expect("reachable effect-value module disappeared");
        for leaf_plan in module
            .summary
            .callable_leaf_plans
            .iter()
            .filter(|leaf_plan| {
                leaf_plan.callable_start >= unit.start && leaf_plan.callable_end <= unit.end
            })
        {
            let super::callable_plans::CallableLeafControlCandidate::EffectValueFlow(candidate) =
                &leaf_plan.control
            else {
                continue;
            };
            ensure!(
                candidate.callable_start == leaf_plan.callable_start
                    && candidate.callable_end == leaf_plan.callable_end
                    && candidate.parameter_count == leaf_plan.parameter_names.len()
                    && candidate.parameter_count == leaf_plan.parameter_starts.len(),
                "effect-value flow conflicts with its callable leaf plan"
            );
            let callable = callable_key(
                &unit.module,
                leaf_plan.callable_start,
                leaf_plan.callable_end,
            );
            let callable_source = source_anchor(
                modules,
                &unit.module,
                leaf_plan.callable_start,
                leaf_plan.callable_end,
            )?;
            let control_plan = control_plans.and_then(|plans| plans.get(&callable));
            if let Some(control_plan) = control_plan {
                ensure!(
                    control_plan.callable_source == callable_source,
                    "effect-value flow conflicts with its callable control plan provenance"
                );
            }
            let parameter_fact =
                exact_callable_parameter_fact(modules, &unit.module, &callable_source)?;
            ensure!(
                leaf_plan.parameter_names.len() == parameter_fact.parameters.len()
                    && leaf_plan.parameter_starts.len() == parameter_fact.parameters.len()
                    && leaf_plan
                        .parameter_names
                        .iter()
                        .zip(&leaf_plan.parameter_starts)
                        .zip(&parameter_fact.parameters)
                        .all(|((name, start), parameter)| {
                            name == &parameter.name && *start == parameter.start
                        }),
                "callable leaf plan conflicts with independent ordered parameter facts"
            );
            let handler = module.summary.units.values().any(|unit| {
                unit.registration.as_ref().is_some_and(|registration| {
                    registration.handler_start == leaf_plan.callable_start
                        && registration.handler_end == leaf_plan.callable_end
                })
            });
            let mut paths = Vec::new();
            let mut reference_accounting_paths = Vec::new();
            let mut unrepresented_call_rejections = Vec::new();
            for path in &candidate.paths {
                let Some(origin) = authenticate_effect_value_origin(
                    modules,
                    &unit.module,
                    &callable_source,
                    &parameter_fact.parameters,
                    control_plan,
                    &path.origin,
                )?
                else {
                    continue;
                };
                let steps = path
                    .steps
                    .iter()
                    .map(|step| {
                        authenticate_effect_value_step(
                            modules,
                            &unit.module,
                            &callable_source,
                            step,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                let prefix = AuthenticatedEffectValuePathPrefix {
                    origin: origin.clone(),
                    steps: steps.clone(),
                };
                match authenticate_effect_value_sink(
                    modules,
                    &unit.module,
                    &callable_source,
                    &path.sink,
                )? {
                    EffectValueSinkAuthentication::Authenticated(sink) => {
                        let path = AuthenticatedEffectValuePath {
                            origin,
                            steps,
                            sink,
                        };
                        authenticate_effect_value_path_continuity(&path)?;
                        paths.push(path);
                    }
                    EffectValueSinkAuthentication::UnrepresentedCallArgument {
                        callsite,
                        value,
                    } => {
                        authenticate_effect_value_path_continuity_to(
                            &prefix.origin,
                            &prefix.steps,
                            &value,
                        )?;
                        unrepresented_call_rejections.push(AuthenticatedEffectValueFlowRejection {
                            origin,
                            provenance: callsite,
                            reason: "effect value reaches an unrepresented call".to_string(),
                        });
                    }
                }
                reference_accounting_paths.push(prefix);
            }
            let mut rejections = candidate
                .rejections
                .iter()
                .map(|rejection| {
                    let Some(origin) = authenticate_effect_value_origin(
                        modules,
                        &unit.module,
                        &callable_source,
                        &parameter_fact.parameters,
                        control_plan,
                        &rejection.origin,
                    )?
                    else {
                        return Ok(None);
                    };
                    Ok(Some(AuthenticatedEffectValueFlowRejection {
                        origin,
                        provenance: source_anchor(
                            modules,
                            &unit.module,
                            rejection.range.start,
                            rejection.range.end,
                        )?,
                        reason: rejection.reason.clone(),
                    }))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            let expected_rejections = expected_effect_value_rejections(
                modules,
                &unit.module,
                &callable_source,
                &reference_accounting_paths,
            )?;
            ensure!(
                rejections.len() == expected_rejections.len()
                    && rejections
                        .iter()
                        .all(|rejection| expected_rejections.contains(rejection))
                    && expected_rejections
                        .iter()
                        .all(|rejection| rejections.contains(rejection)),
                "effect-value rejections conflict with exact resolved-binding reference accounting"
            );
            rejections.extend(unrepresented_call_rejections);
            rejections.sort_by_key(|rejection| {
                (
                    rejection.provenance.start,
                    rejection.provenance.end,
                    rejection.reason.clone(),
                )
            });
            rejections.dedup();
            let flow = AuthenticatedCallableEffectValueFlow {
                callable,
                callable_source,
                parameter_count: candidate.parameter_count,
                handler,
                paths,
                rejections,
            };
            if let Some(previous) = flows.iter().find(|previous| {
                previous.callable == flow.callable
                    && previous.callable_source == flow.callable_source
            }) {
                ensure!(
                    previous == &flow,
                    "callable has conflicting authenticated effect-value flows"
                );
            } else {
                flows.push(flow);
            }
        }
    }
    flows.sort_by_key(|flow| {
        (
            flow.callable.module.clone(),
            flow.callable_source.start,
            flow.callable_source.end,
        )
    });
    Ok(flows)
}

pub(super) fn authenticate_callable_effect_value_flows(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    control_plans: &BTreeMap<CallableKey, CallableControlPlan>,
) -> Result<Vec<AuthenticatedCallableEffectValueFlow>> {
    authenticate_callable_effect_value_flows_inner(modules, reachable, Some(control_plans))
}

#[cfg(test)]
pub(super) fn authenticate_callable_effect_value_flows_without_effect_plans(
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
) -> Result<Vec<AuthenticatedCallableEffectValueFlow>> {
    authenticate_callable_effect_value_flows_inner(modules, reachable, None)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedEffectValueRoute {
    origin_callable: CallableKey,
    origin: AuthenticatedEffectValueOrigin,
    sink_callable: CallableKey,
    sink: AuthenticatedEffectValueSink,
    steps: Vec<AuthenticatedEffectValueStep>,
    callable_path: Vec<CallableKey>,
    callsites: Vec<SourceAnchor>,
    base_path_ids: Vec<usize>,
    blocked: bool,
    handler_sink: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedEffectValueCallEdge {
    caller: CallableKey,
    callsite: SourceAnchor,
    target: CallableKey,
    control: CallableControlCallPlan,
    composable: bool,
    recursive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedEffectValueSourceBlock {
    target_callable: CallableKey,
    target_callable_source: SourceAnchor,
    target_effect: SourceAnchor,
    target_callee: SourceAnchor,
    block: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedMaterializedEffectValueSource {
    source: AuthenticatedEffectValueSource,
    plan: CallableEffectPlan,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct AuthenticatedEffectValueGraph {
    routes: Vec<AuthenticatedEffectValueRoute>,
    call_edges: Vec<AuthenticatedEffectValueCallEdge>,
    recursive_callables: BTreeSet<CallableKey>,
    handler_callables: BTreeSet<CallableKey>,
    control_skeletons: BTreeMap<CallableKey, CallableControlSkeletonCandidate>,
    control_sources: BTreeMap<CallableKey, SourceAnchor>,
    source_blocks: Vec<AuthenticatedEffectValueSourceBlock>,
    materialized_source_effects: Vec<AuthenticatedMaterializedEffectValueSource>,
    materializable_consumer_plans: Vec<AuthenticatedMaterializableConsumerPlan>,
    incomplete: bool,
}

/// A plan that the authenticated graph, rather than a downstream materializer, has proved can be
/// used at its exact consumer. `source` and `route` bind the plan to the original capability and
/// every exact call that carried its value to that consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedMaterializableConsumerPlan {
    pub(super) source: AuthenticatedEffectValueSource,
    pub(super) plan: CallableEffectPlan,
    pub(super) consumer: SourceAnchor,
    route: AuthenticatedMaterializationRoute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthenticatedMaterializationRoute {
    DirectSource,
    ExactCalls(Vec<CallableControlCallPlan>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AuthenticatedFixedPromiseAllChildOrigin {
    EffectSite { plan: CallableEffectPlan },
    CallResult { callsite: SourceAnchor },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedFixedPromiseAllChild {
    pub(super) child_index: usize,
    pub(super) child: SourceAnchor,
    pub(super) origin: AuthenticatedFixedPromiseAllChildOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedFixedPromiseAllPlan {
    pub(super) site: SourceAnchor,
    pub(super) promise: SourceAnchor,
    pub(super) argument: SourceAnchor,
    pub(super) children: Vec<AuthenticatedFixedPromiseAllChild>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedGuestPromiseAllChild {
    callsite: SourceAnchor,
    target: CallableKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedGuestPromiseAllRoot {
    caller: CallableKey,
    children: Vec<AuthenticatedGuestPromiseAllChild>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedGuestPromiseAllRootCandidate {
    caller: CallableKey,
    site: SourceAnchor,
    promise: SourceAnchor,
    argument: SourceAnchor,
    array_alias: Option<AuthenticatedPromiseAllArrayAlias>,
    child_count: usize,
    children: Vec<(usize, SourceAnchor, SourceAnchor)>,
}

fn source_anchor_contains(container: &SourceAnchor, contained: &SourceAnchor) -> bool {
    container.module == contained.module
        && container.source_sha256 == contained.source_sha256
        && container.start <= contained.start
        && contained.end <= container.end
}

fn unique_control_block(blocks: impl Iterator<Item = u32>) -> Option<u32> {
    let mut blocks = blocks.collect::<BTreeSet<_>>().into_iter();
    let block = blocks.next()?;
    blocks.next().is_none().then_some(block)
}

fn direct_guest_effect_sink(route: &AuthenticatedEffectValueRoute) -> bool {
    let AuthenticatedEffectValueOrigin::EffectSite { source } = &route.origin else {
        return false;
    };
    let effect = &source.target_effect;
    let (sink, value) = match &route.sink {
        AuthenticatedEffectValueSink::Await { site, value }
        | AuthenticatedEffectValueSink::Return { site, value } => (site, value),
        AuthenticatedEffectValueSink::CallArgument { .. } => return false,
    };
    if !source_anchor_contains(sink, value) || !source_anchor_contains(sink, effect) {
        return false;
    }
    if route.steps.is_empty() {
        return value == effect;
    }
    let mut cursor = effect;
    for step in &route.steps {
        let AuthenticatedEffectValueStep::Choice { site, child, .. } = step else {
            return false;
        };
        if child != cursor {
            return false;
        }
        cursor = site;
    }
    cursor == value
}

fn guest_effect_value_sink_block(
    skeleton: &CallableControlSkeletonCandidate,
    sink: &AuthenticatedEffectValueSink,
) -> Option<u32> {
    match sink {
        AuthenticatedEffectValueSink::Await { site, value } => {
            unique_control_block(skeleton.points.iter().filter_map(|point| {
                (point.kind == CallableControlPointKind::Await
                    && point.start == site.start
                    && point.end == site.end
                    && point.value_start == Some(value.start)
                    && point.value_end == Some(value.end))
                .then_some(point.block)
            }))
        }
        AuthenticatedEffectValueSink::Return { site, value } => {
            unique_control_block(skeleton.blocks.iter().filter_map(|block| {
                block
                    .instructions
                    .iter()
                    .any(|instruction| {
                        instruction.kind == CallableControlInstructionKind::Return
                            && instruction.start == Some(site.start)
                            && instruction.end == Some(site.end)
                            && instruction.value_start == Some(value.start)
                            && instruction.value_end == Some(value.end)
                    })
                    .then_some(block.id)
            }))
        }
        AuthenticatedEffectValueSink::CallArgument { callsite, .. } => {
            unique_control_block(skeleton.points.iter().filter_map(|point| {
                (point.kind == CallableControlPointKind::Call
                    && point.start == callsite.start
                    && point.end == callsite.end)
                    .then_some(point.block)
            }))
        }
    }
}

fn guest_cfg_continuations_reach_sink(
    skeleton: &CallableControlSkeletonCandidate,
    source_block: u32,
    sink_block: u32,
) -> bool {
    fn reaches_sink(
        skeleton: &CallableControlSkeletonCandidate,
        current: u32,
        sink: u32,
        visiting: &mut BTreeSet<u32>,
    ) -> bool {
        if current == sink {
            return true;
        }
        if !visiting.insert(current) {
            // A cycle can keep the root alive without reaching the authenticated sink. The guest
            // lowering has no ordering proof that would make that continuation safe.
            return false;
        }
        let result = skeleton
            .blocks
            .iter()
            .find(|block| block.id == current)
            .is_some_and(|block| {
                if block.unreachable {
                    return false;
                }
                let successors = block
                    .successors
                    .iter()
                    .filter(|edge| edge.kind != CallableControlEdgeKind::Unreachable)
                    .collect::<Vec<_>>();
                !successors.is_empty()
                    && successors
                        .into_iter()
                        .all(|edge| reaches_sink(skeleton, edge.target, sink, visiting))
            });
        visiting.remove(&current);
        result
    }

    source_block != sink_block
        && reaches_sink(skeleton, source_block, sink_block, &mut BTreeSet::new())
}

fn guest_control_has_finalization(skeleton: &CallableControlSkeletonCandidate) -> bool {
    skeleton.blocks.iter().any(|block| {
        block
            .successors
            .iter()
            .any(|edge| edge.kind == CallableControlEdgeKind::Finalize)
    })
}

impl AuthenticatedEffectValueGraph {
    pub(super) fn materializable_consumer_plans(
        &self,
    ) -> &[AuthenticatedMaterializableConsumerPlan] {
        &self.materializable_consumer_plans
    }

    pub(super) fn represented_effect_targets(&self) -> BTreeSet<OperationIdentity> {
        self.source_blocks
            .iter()
            .map(|source| {
                (
                    source.target_effect.module.clone(),
                    source.target_effect.start,
                    source.target_effect.end,
                )
            })
            .collect()
    }

    fn materialized_plan_for_source(
        &self,
        source: &AuthenticatedEffectValueSource,
    ) -> Option<&CallableEffectPlan> {
        let matching = self
            .materialized_source_effects
            .iter()
            .filter(|candidate| candidate.source == *source)
            .collect::<Vec<_>>();
        let [candidate] = matching.as_slice() else {
            return None;
        };
        Some(&candidate.plan)
    }

    fn route_is_safe(&self, route: &AuthenticatedEffectValueRoute) -> bool {
        !route.blocked
            && !route
                .callable_path
                .iter()
                .any(|callable| self.recursive_callables.contains(callable))
    }

    fn exact_call_route(
        &self,
        route: &AuthenticatedEffectValueRoute,
    ) -> Option<Vec<CallableControlCallPlan>> {
        let mut caller = route.origin_callable.clone();
        let mut calls = Vec::with_capacity(route.callsites.len());
        for callsite in &route.callsites {
            let matching = self
                .call_edges
                .iter()
                .filter(|edge| {
                    edge.composable
                        && !edge.recursive
                        && edge.caller == caller
                        && edge.callsite == *callsite
                        && edge.callsite == edge.control.callsite
                        && edge.target == edge.control.target
                        && edge.control.dispatch_exact
                        && edge.control.arguments_safe
                        && self
                            .control_sources
                            .get(&edge.caller)
                            .is_some_and(|source| {
                                source_anchor_contains(source, &edge.control.callsite)
                            })
                        && self.control_sources.get(&edge.target)
                            == Some(&edge.control.target_source)
                })
                .collect::<Vec<_>>();
            let [edge] = matching.as_slice() else {
                return None;
            };
            caller = edge.target.clone();
            calls.push(edge.control.clone());
        }
        (caller == route.sink_callable).then_some(calls)
    }

    fn matching_source_routes<'a>(
        &'a self,
        plan: &CallableEffectPlan,
    ) -> Vec<(
        &'a AuthenticatedEffectValueRoute,
        AuthenticatedEffectValueSource,
    )> {
        self.routes
            .iter()
            .filter(|route| self.route_is_safe(route))
            .filter_map(|route| match &route.origin {
                AuthenticatedEffectValueOrigin::EffectSite { source }
                    if source.matches_effect_plan(plan) =>
                {
                    Some((route, source.clone()))
                }
                AuthenticatedEffectValueOrigin::Parameter { .. }
                | AuthenticatedEffectValueOrigin::CallResult { .. }
                | AuthenticatedEffectValueOrigin::EffectSite { .. } => None,
            })
            .collect()
    }

    fn routes_from_effect_source<'a>(
        &'a self,
        source: &AuthenticatedEffectValueSource,
    ) -> Vec<&'a AuthenticatedEffectValueRoute> {
        self.routes
            .iter()
            .filter(|route| {
                matches!(
                    &route.origin,
                    AuthenticatedEffectValueOrigin::EffectSite { source: origin } if origin == source
                )
            })
            .collect()
    }

    fn materialized_source_for_specialized_plan(
        &self,
        plan: &CallableEffectPlan,
    ) -> Option<&AuthenticatedMaterializedEffectValueSource> {
        let matching = self
            .materialized_source_effects
            .iter()
            .filter(|candidate| {
                candidate.source.matches_effect_plan(plan)
                    && candidate.plan.callable == plan.provenance.target_callable
                    && candidate.plan.callable_source == plan.provenance.target_callable_source
                    && candidate.plan.provenance.caller_callsite.is_none()
            })
            .collect::<Vec<_>>();
        let [source] = matching.as_slice() else {
            return None;
        };
        Some(*source)
    }

    fn graph_owns_specialized_consumer(
        &self,
        plan: &CallableEffectPlan,
    ) -> Result<Option<AuthenticatedMaterializableConsumerPlan>> {
        let Some(caller_callsite) = plan.provenance.caller_callsite.as_ref() else {
            return Ok(None);
        };
        if plan.callable == plan.provenance.target_callable
            || self.control_sources.get(&plan.callable) != Some(&plan.callable_source)
            || self.control_sources.get(&plan.provenance.target_callable)
                != Some(&plan.provenance.target_callable_source)
            || !source_anchor_contains(&plan.callable_source, caller_callsite)
        {
            return Ok(None);
        }
        let matching_edges = self
            .call_edges
            .iter()
            .filter(|edge| {
                edge.composable
                    && !edge.recursive
                    && edge.caller == plan.callable
                    && edge.target == plan.provenance.target_callable
                    && edge.callsite == *caller_callsite
                    && edge.control.callsite == *caller_callsite
                    && edge.control.target == plan.provenance.target_callable
                    && edge.control.target_source == plan.provenance.target_callable_source
                    && edge.control.dispatch_exact
                    && edge.control.arguments_safe
            })
            .collect::<Vec<_>>();
        let [edge] = matching_edges.as_slice() else {
            return Ok(None);
        };
        let Some(source) = self.materialized_source_for_specialized_plan(plan) else {
            return Ok(None);
        };
        let mut matching = self
            .matching_source_routes(&source.plan)
            .into_iter()
            .filter_map(|(route, route_source)| {
                if route_source != source.source {
                    return None;
                }
                let calls = self.exact_call_route(route)?;
                calls
                    .iter()
                    .any(|call| call == &edge.control)
                    .then_some(calls)
            });
        let direct_calls = matching.next().and_then(|first| {
            matching
                .all(|candidate| candidate == first)
                .then_some(first)
        });
        let calls = direct_calls.or_else(|| {
            self.source_awaits_direct_effect_to_return(source)
                .then(|| vec![edge.control.clone()])
        });
        let Some(calls) = calls else {
            return Ok(None);
        };
        let Some(projected) = self.project_exact_synchronous_consumer(source, edge, calls)? else {
            return Ok(None);
        };
        Ok((projected.plan == *plan).then_some(projected))
    }

    fn source_awaits_direct_effect_to_return(
        &self,
        source: &AuthenticatedMaterializedEffectValueSource,
    ) -> bool {
        let Some(skeleton) = self.control_skeletons.get(&source.source.target_callable) else {
            return false;
        };
        let matching = self.routes_from_effect_source(&source.source);
        !matching.is_empty()
            && matching.iter().all(|route| {
                route.callsites.is_empty()
                    && self.route_is_safe(route)
                    && matches!(
                        &route.sink,
                        AuthenticatedEffectValueSink::Await { site, .. }
                            if skeleton.blocks.iter().any(|block| {
                                block.instructions.iter().any(|instruction| {
                                    instruction.kind == CallableControlInstructionKind::Return
                                        && instruction.value_start == Some(site.start)
                                        && instruction.value_end == Some(site.end)
                                })
                            })
                    )
            })
            && self.closes_routes(&matching, &BTreeSet::new())
    }

    fn fixed_promise_all_child_witness(
        route: &AuthenticatedEffectValueRoute,
        callsite: &SourceAnchor,
    ) -> Option<AuthenticatedEffectValueStep> {
        let matching = route
            .steps
            .iter()
            .filter(|step| {
                matches!(
                    step,
                    AuthenticatedEffectValueStep::PromiseAll {
                        array_alias: None,
                        child,
                        ..
                    } if child == callsite
                )
            })
            .collect::<Vec<_>>();
        let [witness] = matching.as_slice() else {
            return None;
        };
        Some((*witness).clone())
    }

    fn call_result_closes_fixed_promise_all(
        &self,
        caller: &CallableKey,
        callsite: &SourceAnchor,
    ) -> bool {
        let matching = self
            .routes
            .iter()
            .filter(|route| {
                route.origin_callable == *caller
                    && matches!(
                        &route.origin,
                        AuthenticatedEffectValueOrigin::CallResult {
                            callsite: origin,
                            ..
                        } if origin == callsite
                    )
            })
            .collect::<Vec<_>>();
        let Some(witness) = matching
            .first()
            .and_then(|route| Self::fixed_promise_all_child_witness(route, callsite))
        else {
            return false;
        };
        matching.iter().all(|route| {
            route.callsites.is_empty()
                && self.route_is_safe(route)
                && matches!(route.sink, AuthenticatedEffectValueSink::Await { .. })
                && Self::fixed_promise_all_child_witness(route, callsite) == Some(witness.clone())
        }) && self.closes_routes(&matching, &BTreeSet::new())
    }

    fn project_exact_synchronous_consumer(
        &self,
        source: &AuthenticatedMaterializedEffectValueSource,
        edge: &AuthenticatedEffectValueCallEdge,
        calls: Vec<CallableControlCallPlan>,
    ) -> Result<Option<AuthenticatedMaterializableConsumerPlan>> {
        let plan = &source.plan;
        if plan.callable != source.source.target_callable
            || plan.callable_source != source.source.target_callable_source
            || plan.provenance.caller_callsite.is_some()
            || edge.control.position != CallPosition::Synchronous
            || edge.caller == edge.target
            || edge.target != source.source.target_callable
            || self
                .materialized_source_effects
                .iter()
                .filter(|candidate| {
                    candidate.source.target_callable == source.source.target_callable
                        && candidate.plan.provenance.caller_callsite.is_none()
                })
                .count()
                != 1
        {
            return Ok(None);
        }
        let [call] = calls.as_slice() else {
            // A callable effect plan records one consumer callsite. Do not pretend a one-hop
            // projection authenticates a transitive operand substitution.
            return Ok(None);
        };
        if edge.control != *call
            || edge.callsite != call.callsite
            || edge.target != call.target
            || !edge.composable
            || edge.recursive
        {
            return Ok(None);
        }
        let caller_source = self
            .control_sources
            .get(&edge.caller)
            .context("authenticated effect-value call lost its caller source")?;
        let mut dynamic_operands = Vec::with_capacity(plan.dynamic_operands.len());
        for operand in &plan.dynamic_operands {
            let SemanticOperandProjection::ExactCaller { .. } = &operand.projection else {
                return Ok(None);
            };
            let SemanticOperand::Parameter(parameter_index) = &operand.value else {
                return Ok(None);
            };
            let Some(argument) = call.arguments.get(*parameter_index) else {
                return Ok(None);
            };
            let value = match &argument.value {
                CallableValueFlowCandidate::Parameter { index } => {
                    SemanticOperand::Parameter(*index)
                }
                CallableValueFlowCandidate::LiteralString { value } => {
                    SemanticOperand::LiteralString(value.clone())
                }
                CallableValueFlowCandidate::CapturedBinding { .. }
                | CallableValueFlowCandidate::Expression { .. } => {
                    SemanticOperand::RuntimeInput(*parameter_index)
                }
            };
            dynamic_operands.push(SemanticEffectOperand {
                value,
                target_argument_index: operand.target_argument_index,
                target_provenance: operand.target_provenance.clone(),
                projection: SemanticOperandProjection::ExactCaller {
                    consumer_provenance: argument.provenance.clone(),
                },
            });
        }
        let mut provenance = plan.provenance.clone();
        provenance.caller_callsite = Some(call.callsite.clone());
        let plan = validate_callable_effect_plan(CallableEffectPlan {
            callable: edge.caller.clone(),
            callable_source: caller_source.clone(),
            effect_key: plan.effect_key.clone(),
            static_operands: plan.static_operands.clone(),
            dynamic_operands,
            provenance,
        })?;
        Ok(Some(AuthenticatedMaterializableConsumerPlan {
            source: source.source.clone(),
            consumer: call.callsite.clone(),
            plan,
            route: AuthenticatedMaterializationRoute::ExactCalls(calls),
        }))
    }

    fn project_fixed_promise_all_consumer(
        &self,
        source: &AuthenticatedMaterializedEffectValueSource,
        route: &AuthenticatedEffectValueRoute,
    ) -> Result<Option<AuthenticatedMaterializableConsumerPlan>> {
        let plan = &source.plan;
        if !self.route_is_safe(route)
            || !Self::route_matches_effect_site(route, plan)
            || plan.callable != source.source.target_callable
            || plan.callable_source != source.source.target_callable_source
            || plan.provenance.caller_callsite.is_some()
        {
            return Ok(None);
        }
        let Some(calls) = self.exact_call_route(route) else {
            return Ok(None);
        };
        let [call] = calls.as_slice() else {
            // A callable effect plan records one consumer callsite. Do not pretend a one-hop
            // projection authenticates a transitive operand substitution.
            return Ok(None);
        };
        let matching_edges = self
            .call_edges
            .iter()
            .filter(|edge| {
                edge.control == *call
                    && edge.composable
                    && !edge.recursive
                    && edge.caller == route.sink_callable
                    && edge.target == source.source.target_callable
            })
            .collect::<Vec<_>>();
        let [edge] = matching_edges.as_slice() else {
            return Ok(None);
        };
        if call.position != CallPosition::Synchronous
            || route.origin_callable != call.target
            || route.sink_callable != edge.caller
            || !route.steps.iter().any(|step| {
                matches!(
                    step,
                    AuthenticatedEffectValueStep::PromiseAll {
                        array_alias: None,
                        child,
                        ..
                    } if child == &call.callsite
                )
            })
        {
            return Ok(None);
        }
        self.project_exact_synchronous_consumer(source, edge, calls)
    }

    fn project_awaited_return_fixed_promise_all_consumers(
        &self,
        source: &AuthenticatedMaterializedEffectValueSource,
    ) -> Result<Vec<AuthenticatedMaterializableConsumerPlan>> {
        if !self.source_awaits_direct_effect_to_return(source) {
            return Ok(Vec::new());
        }
        let mut projections = Vec::new();
        for edge in self.call_edges.iter().filter(|edge| {
            edge.composable
                && !edge.recursive
                && edge.target == source.source.target_callable
                && edge.callsite == edge.control.callsite
                && edge.target == edge.control.target
                && edge.control.target_source == source.source.target_callable_source
                && edge.control.position == CallPosition::Synchronous
                && edge.control.dispatch_exact
                && edge.control.arguments_safe
                && self
                    .control_sources
                    .get(&edge.caller)
                    .is_some_and(|caller_source| {
                        source_anchor_contains(caller_source, &edge.callsite)
                    })
                && self.call_result_closes_fixed_promise_all(&edge.caller, &edge.callsite)
        }) {
            if let Some(projected) =
                self.project_exact_synchronous_consumer(source, edge, vec![edge.control.clone()])?
            {
                projections.push(projected);
            }
        }
        Ok(projections)
    }

    fn rebuild_materializable_consumer_plans(
        &mut self,
        control_plans: &[&CallableControlPlan],
    ) -> Result<()> {
        self.materializable_consumer_plans.clear();
        if self.incomplete {
            return Ok(());
        }
        let mut materializable = Vec::new();
        for source in &self.materialized_source_effects {
            if self
                .matching_source_routes(&source.plan)
                .iter()
                .any(|(_, candidate)| candidate == &source.source)
            {
                materializable.push(AuthenticatedMaterializableConsumerPlan {
                    source: source.source.clone(),
                    consumer: source.plan.consumer_site().clone(),
                    plan: source.plan.clone(),
                    route: AuthenticatedMaterializationRoute::DirectSource,
                });
            }
        }
        for control_plan in control_plans {
            for effect in &control_plan.effects {
                let plan = &effect.effect;
                let Some(projected) = self.graph_owns_specialized_consumer(plan)? else {
                    continue;
                };
                materializable.push(projected);
            }
        }
        for source in &self.materialized_source_effects {
            for route in &self.routes {
                let Some(projected) = self.project_fixed_promise_all_consumer(source, route)?
                else {
                    continue;
                };
                materializable.push(projected);
            }
            materializable.extend(self.project_awaited_return_fixed_promise_all_consumers(source)?);
        }
        let mut deduplicated = Vec::new();
        for candidate in materializable {
            if let Some(previous) =
                deduplicated
                    .iter()
                    .find(|previous: &&AuthenticatedMaterializableConsumerPlan| {
                        previous.source == candidate.source
                            && previous.plan == candidate.plan
                            && previous.consumer == candidate.consumer
                    })
            {
                ensure!(
                    previous.route == candidate.route,
                    "effect-value graph has conflicting exact route witnesses for one materializable plan"
                );
                continue;
            }
            deduplicated.push(candidate);
        }
        deduplicated.sort_by_key(|candidate| {
            (
                candidate.plan.consumer_site_identity(),
                candidate.plan.target_identity(),
                candidate.plan.effect_key.operation_kind.clone(),
            )
        });
        self.materializable_consumer_plans = deduplicated;
        Ok(())
    }

    fn descendant_through_call(
        route: &AuthenticatedEffectValueRoute,
        candidate: &AuthenticatedEffectValueRoute,
        callsite: &SourceAnchor,
    ) -> bool {
        candidate.base_path_ids.len() > route.base_path_ids.len()
            && candidate.base_path_ids.starts_with(&route.base_path_ids)
            && candidate.callsites.get(route.callsites.len()) == Some(callsite)
    }

    fn route_matches_effect_site(
        route: &AuthenticatedEffectValueRoute,
        target: &CallableEffectPlan,
    ) -> bool {
        matches!(
            &route.origin,
            AuthenticatedEffectValueOrigin::EffectSite { source }
                if source.matches_effect_plan(target)
        )
    }

    fn has_exact_guest_consumer(
        &self,
        target: &CallableEffectPlan,
        activation_calls: &AuthenticatedStaticActivationCallIndex,
    ) -> bool {
        let caller_callsite = &target.provenance.caller_callsite;
        if target.callable == target.provenance.target_callable {
            return caller_callsite.is_none()
                && target.callable_source == target.provenance.target_callable_source;
        }
        let Some(caller_callsite) = caller_callsite else {
            return false;
        };
        if self.control_sources.get(&target.callable) != Some(&target.callable_source)
            || self.control_sources.get(&target.provenance.target_callable)
                != Some(&target.provenance.target_callable_source)
        {
            return false;
        }
        let matching_value_edges = self
            .call_edges
            .iter()
            .filter(|edge| {
                edge.composable
                    && edge.caller == target.callable
                    && edge.callsite == *caller_callsite
                    && edge.target == target.provenance.target_callable
            })
            .count();
        if matching_value_edges != 1 {
            return false;
        }
        activation_calls
            .calls()
            .filter(|call| {
                call.dispatch_exact
                    && call.callsite == *caller_callsite
                    && matches!(
                        &call.caller,
                        AuthenticatedStaticActivationCaller::Callable(caller)
                            if caller == &target.callable
                    )
                    && matches!(
                        &call.target,
                        AuthenticatedStaticActivationTarget::Callable(callee)
                            if callee == &target.provenance.target_callable
                    )
            })
            .count()
            == 1
    }

    fn base_effect_site_route(route: &AuthenticatedEffectValueRoute) -> bool {
        route.base_path_ids.len() == 1
            && route.callable_path.len() == 1
            && route.origin_callable == route.sink_callable
            && route.callsites.is_empty()
    }

    fn guest_effect_source_block(&self, route: &AuthenticatedEffectValueRoute) -> Option<u32> {
        let AuthenticatedEffectValueOrigin::EffectSite {
            source: source_effect,
        } = &route.origin
        else {
            return None;
        };
        unique_control_block(
            self.source_blocks
                .iter()
                .filter(|source| {
                    source.target_callable == source_effect.target_callable
                        && source.target_callable_source == source_effect.target_callable_source
                        && source.target_effect == source_effect.target_effect
                        && source.target_callee == source_effect.target_callee
                })
                .map(|source| source.block),
        )
    }

    fn guest_base_route_closes(&self, route: &AuthenticatedEffectValueRoute) -> bool {
        if route.blocked
            || route
                .steps
                .iter()
                .any(|step| matches!(step, AuthenticatedEffectValueStep::PromiseAll { .. }))
        {
            return false;
        }
        if matches!(&route.sink, AuthenticatedEffectValueSink::Return { .. }) {
            let Some(skeleton) = self.control_skeletons.get(&route.origin_callable) else {
                return false;
            };
            if guest_control_has_finalization(skeleton) {
                return false;
            }
        }
        if direct_guest_effect_sink(route) {
            return match &route.sink {
                AuthenticatedEffectValueSink::Await { .. } => true,
                AuthenticatedEffectValueSink::Return { .. } => true,
                AuthenticatedEffectValueSink::CallArgument { .. } => false,
            };
        }
        let Some(skeleton) = self.control_skeletons.get(&route.origin_callable) else {
            return false;
        };
        let Some(source_block) = self.guest_effect_source_block(route) else {
            return false;
        };
        let Some(sink_block) = guest_effect_value_sink_block(skeleton, &route.sink) else {
            return false;
        };
        if source_block == sink_block
            && skeleton.intra_block_order == CallableIntraBlockOrder::Unresolved
        {
            // Oxc identifies the block but deliberately does not authenticate expression order
            // inside it. Only the direct syntactic containment check above can close that case.
            return false;
        }
        guest_cfg_continuations_reach_sink(skeleton, source_block, sink_block)
    }

    fn guest_promise_all_roots(
        &self,
        activation_calls: &AuthenticatedStaticActivationCallIndex,
    ) -> Vec<AuthenticatedGuestPromiseAllRoot> {
        let mut candidates = Vec::<AuthenticatedGuestPromiseAllRootCandidate>::new();
        for route in &self.routes {
            let [
                AuthenticatedEffectValueStep::PromiseAll {
                    site,
                    promise,
                    argument,
                    array_alias,
                    child_index,
                    child_count,
                    child,
                },
            ] = route.steps.as_slice()
            else {
                continue;
            };
            let AuthenticatedEffectValueOrigin::CallResult { callsite, .. } = &route.origin else {
                continue;
            };
            if route.blocked
                || route.base_path_ids.len() != 1
                || route.callable_path.len() != 1
                || route.origin_callable != route.sink_callable
                || route.callsites.len() != 0
                || route
                    .callable_path
                    .iter()
                    .any(|callable| self.recursive_callables.contains(callable))
                || child != callsite
            {
                continue;
            }
            let AuthenticatedEffectValueSink::Await { site: sink, value } = &route.sink else {
                continue;
            };
            if value != site {
                continue;
            }
            if let Some(alias) = array_alias {
                let Some(await_site) = alias.await_site.as_ref() else {
                    // The binding is exact, but without an adjacent awaited handoff its started
                    // children have no authenticated aggregate owner.
                    continue;
                };
                if sink != await_site {
                    continue;
                }
            }
            let candidate = candidates.iter_mut().find(|candidate| {
                candidate.caller == route.origin_callable
                    && candidate.site == *site
                    && candidate.promise == *promise
                    && candidate.argument == *argument
                    && candidate.array_alias == *array_alias
                    && candidate.child_count == *child_count
            });
            let child = (*child_index, child.clone(), callsite.clone());
            if let Some(candidate) = candidate {
                candidate.children.push(child);
            } else {
                candidates.push(AuthenticatedGuestPromiseAllRootCandidate {
                    caller: route.origin_callable.clone(),
                    site: site.clone(),
                    promise: promise.clone(),
                    argument: argument.clone(),
                    array_alias: array_alias.clone(),
                    child_count: *child_count,
                    children: vec![child],
                });
            }
        }

        let mut roots = Vec::new();
        for candidate in candidates {
            if candidate.child_count == 0 || candidate.children.len() != candidate.child_count {
                continue;
            }
            let mut children = Vec::with_capacity(candidate.child_count);
            let mut child_sources = Vec::with_capacity(candidate.child_count);
            let mut complete = true;
            for child_index in 0..candidate.child_count {
                let mut matching = candidate
                    .children
                    .iter()
                    .filter(|(index, _, _)| *index == child_index);
                let Some((_, child, callsite)) = matching.next() else {
                    complete = false;
                    break;
                };
                if matching.next().is_some() {
                    complete = false;
                    break;
                }
                let child = child.clone();
                let callsite = callsite.clone();
                if child_sources.iter().any(|existing| existing == &child)
                    || children
                        .iter()
                        .any(|existing: &AuthenticatedGuestPromiseAllChild| {
                            existing.callsite == callsite
                        })
                {
                    complete = false;
                    break;
                }
                let matching_edges = self
                    .call_edges
                    .iter()
                    .filter(|edge| edge.caller == candidate.caller && edge.callsite == callsite)
                    .collect::<Vec<_>>();
                let [edge] = matching_edges.as_slice() else {
                    complete = false;
                    break;
                };
                if !edge.composable || edge.recursive {
                    complete = false;
                    break;
                }
                let matching_activations = activation_calls
                    .calls()
                    .filter(|call| {
                        call.dispatch_exact
                            && call.callsite == callsite
                            && call.position == Some(CallPosition::Synchronous)
                            && matches!(
                                &call.caller,
                                AuthenticatedStaticActivationCaller::Callable(caller)
                                    if caller == &candidate.caller
                            )
                            && matches!(
                                &call.target,
                                AuthenticatedStaticActivationTarget::Callable(target)
                                    if target == &edge.target
                            )
                    })
                    .collect::<Vec<_>>();
                if !matches!(matching_activations.as_slice(), [_]) {
                    complete = false;
                    break;
                }
                child_sources.push(child);
                children.push(AuthenticatedGuestPromiseAllChild {
                    callsite,
                    target: edge.target.clone(),
                });
            }
            if complete {
                roots.push(AuthenticatedGuestPromiseAllRoot {
                    caller: candidate.caller,
                    children,
                });
            }
        }
        roots
    }

    fn guest_callable_rooted(
        &self,
        callable: &CallableKey,
        activation_calls: &AuthenticatedStaticActivationCallIndex,
        runtime_awaited_callables: &BTreeSet<CallableKey>,
        aggregate_roots: &[AuthenticatedGuestPromiseAllRoot],
        cache: &mut BTreeMap<CallableKey, bool>,
        visiting: &mut BTreeSet<CallableKey>,
    ) -> bool {
        if let Some(rooted) = cache.get(callable) {
            return *rooted;
        }
        if !self.control_skeletons.contains_key(callable) || !visiting.insert(callable.clone()) {
            return false;
        }
        let inbound = activation_calls.calls_to(callable).collect::<Vec<_>>();
        let inbound_rooted = inbound.iter().all(|call| {
            call.dispatch_exact
                && matches!(
                    &call.target,
                    AuthenticatedStaticActivationTarget::Callable(target) if target == callable
                )
                && match call.position {
                    Some(CallPosition::SequentialAwait) => true,
                    Some(CallPosition::TailReturn) => match &call.caller {
                        AuthenticatedStaticActivationCaller::Callable(caller) => self
                            .control_skeletons
                            .get(caller)
                            .is_some_and(|skeleton| !guest_control_has_finalization(skeleton)),
                        AuthenticatedStaticActivationCaller::Unknown => false,
                    },
                    Some(CallPosition::Synchronous) => matches!(
                        &call.caller,
                        AuthenticatedStaticActivationCaller::Callable(caller)
                            if aggregate_roots.iter().any(|root| {
                                root.caller == *caller
                                    && root.children.iter().any(|child| {
                                        child.callsite == call.callsite && child.target == *callable
                                    })
                            })
                    ),
                    _ => false,
                }
                && match &call.caller {
                    AuthenticatedStaticActivationCaller::Callable(caller) => self
                        .guest_callable_rooted(
                            caller,
                            activation_calls,
                            runtime_awaited_callables,
                            aggregate_roots,
                            cache,
                            visiting,
                        ),
                    AuthenticatedStaticActivationCaller::Unknown => false,
                }
        });
        let rooted = inbound_rooted
            && (self.handler_callables.contains(callable)
                || runtime_awaited_callables.contains(callable)
                || !inbound.is_empty());
        visiting.remove(callable);
        cache.insert(callable.clone(), rooted);
        rooted
    }

    fn guest_routes_are_rooted(
        &self,
        matching: &[&AuthenticatedEffectValueRoute],
        activation_calls: &AuthenticatedStaticActivationCallIndex,
        runtime_awaited_callables: &BTreeSet<CallableKey>,
        aggregate_roots: &[AuthenticatedGuestPromiseAllRoot],
    ) -> bool {
        let mut cache = BTreeMap::new();
        matching.iter().all(|route| {
            route.callable_path.iter().all(|callable| {
                self.guest_callable_rooted(
                    callable,
                    activation_calls,
                    runtime_awaited_callables,
                    aggregate_roots,
                    &mut cache,
                    &mut BTreeSet::new(),
                )
            })
        })
    }

    fn route_is_fully_expanded(
        &self,
        route: &AuthenticatedEffectValueRoute,
        matching: &[&AuthenticatedEffectValueRoute],
    ) -> bool {
        match &route.sink {
            AuthenticatedEffectValueSink::CallArgument { callsite, .. } => self
                .call_edges
                .iter()
                .find(|edge| edge.callsite == *callsite)
                .is_some_and(|edge| {
                    edge.composable
                        && matching.iter().any(|candidate| {
                            Self::descendant_through_call(route, candidate, callsite)
                        })
                }),
            AuthenticatedEffectValueSink::Return { .. } if !route.handler_sink => {
                let inbound = self
                    .call_edges
                    .iter()
                    .filter(|edge| edge.target == route.sink_callable)
                    .collect::<Vec<_>>();
                !inbound.is_empty()
                    && inbound.iter().all(|edge| {
                        edge.composable
                            && matching.iter().any(|candidate| {
                                Self::descendant_through_call(route, candidate, &edge.callsite)
                            })
                    })
            }
            AuthenticatedEffectValueSink::Await { .. }
            | AuthenticatedEffectValueSink::Return { .. } => false,
        }
    }

    fn closes_routes(
        &self,
        matching: &[&AuthenticatedEffectValueRoute],
        batch_closures: &BTreeSet<(String, u32, u32)>,
    ) -> bool {
        let frontier = matching
            .iter()
            .copied()
            .filter(|route| !self.route_is_fully_expanded(route, matching))
            .collect::<Vec<_>>();
        !frontier.is_empty()
            && frontier.iter().all(|route| {
                !route.blocked
                    && !route
                        .callable_path
                        .iter()
                        .any(|callable| self.recursive_callables.contains(callable))
                    && (matches!(route.sink, AuthenticatedEffectValueSink::Await { .. })
                        || route.handler_sink
                            && matches!(route.sink, AuthenticatedEffectValueSink::Return { .. })
                        || route.callsites.last().is_some_and(|callsite| {
                            batch_closures.contains(&(
                                callsite.module.clone(),
                                callsite.start,
                                callsite.end,
                            ))
                        }))
            })
    }

    pub(super) fn closes_call_result(
        &self,
        module: &str,
        start: u32,
        end: u32,
        batch_closures: &BTreeSet<(String, u32, u32)>,
    ) -> bool {
        if batch_closures.contains(&(module.to_string(), start, end)) {
            return true;
        }
        if self.incomplete {
            return false;
        }
        let matching = self
            .routes
            .iter()
            .filter(|route| match &route.origin {
                AuthenticatedEffectValueOrigin::CallResult { callsite, .. } => {
                    callsite.module == module && callsite.start == start && callsite.end == end
                }
                AuthenticatedEffectValueOrigin::Parameter { .. }
                | AuthenticatedEffectValueOrigin::EffectSite { .. } => false,
            })
            .collect::<Vec<_>>();
        self.closes_routes(&matching, batch_closures)
    }

    /// Shared closure remains limited to source sites that already have a materialized direct
    /// plan. Guest admission performs its separate exact source-to-specialized-plan join below.
    #[cfg(test)]
    pub(super) fn closes_effect_site(&self, target: &CallableEffectPlan) -> bool {
        if self.incomplete {
            return false;
        }
        let matching = self
            .routes
            .iter()
            .filter(|route| {
                matches!(
                    &route.origin,
                    AuthenticatedEffectValueOrigin::EffectSite { source }
                        if source.matches_effect_plan(target)
                            && self.materialized_plan_for_source(source).is_some()
                )
            })
            .collect::<Vec<_>>();
        self.closes_routes(&matching, &BTreeSet::new())
    }

    /// Guest Promise lowering starts the host operation before JavaScript has established ordinary
    /// Promise ownership. Accept it only when both the local control flow and every activation
    /// path prove that an authenticated root will settle after consuming the value.
    pub(super) fn closes_guest_effect_site(
        &self,
        target: &CallableEffectPlan,
        activation_calls: &AuthenticatedStaticActivationCallIndex,
        runtime_awaited_callables: &BTreeSet<CallableKey>,
    ) -> bool {
        if self.incomplete {
            return false;
        }
        if !self.has_exact_guest_consumer(target, activation_calls) {
            return false;
        }
        let matching = self
            .routes
            .iter()
            .filter(|route| Self::route_matches_effect_site(route, target))
            .collect::<Vec<_>>();
        let base_routes = matching
            .iter()
            .copied()
            .filter(|route| Self::base_effect_site_route(route))
            .collect::<Vec<_>>();
        let aggregate_roots = self.guest_promise_all_roots(activation_calls);
        let routes_close = !base_routes.is_empty()
            && base_routes
                .iter()
                .all(|route| self.guest_base_route_closes(route))
            && self.closes_routes(&matching, &BTreeSet::new())
            && self.guest_routes_are_rooted(
                &matching,
                activation_calls,
                runtime_awaited_callables,
                &aggregate_roots,
            );
        if routes_close {
            return true;
        }
        false
    }

    pub(super) fn fixed_promise_all_plan(
        &self,
        module: &str,
        site_start: u32,
        site_end: u32,
    ) -> Option<AuthenticatedFixedPromiseAllPlan> {
        if self.incomplete {
            return None;
        }
        let mut site_provenance = None::<(SourceAnchor, SourceAnchor, SourceAnchor)>;
        let mut children =
            BTreeMap::<usize, (SourceAnchor, Vec<AuthenticatedFixedPromiseAllChildOrigin>)>::new();
        for route in &self.routes {
            for step in &route.steps {
                let AuthenticatedEffectValueStep::PromiseAll {
                    site,
                    promise,
                    argument,
                    array_alias,
                    child_index,
                    child,
                    ..
                } = step
                else {
                    continue;
                };
                if array_alias.is_some() {
                    continue;
                }
                if site.module != module || site.start != site_start || site.end != site_end {
                    continue;
                }
                let origin = match &route.origin {
                    AuthenticatedEffectValueOrigin::EffectSite { source }
                        if source.target_effect == *child =>
                    {
                        let plan = self.materialized_plan_for_source(source)?;
                        AuthenticatedFixedPromiseAllChildOrigin::EffectSite { plan: plan.clone() }
                    }
                    AuthenticatedEffectValueOrigin::CallResult { callsite, .. }
                        if callsite == child =>
                    {
                        let matching_edges = self
                            .call_edges
                            .iter()
                            .filter(|edge| edge.callsite == *callsite)
                            .collect::<Vec<_>>();
                        if !matching_edges.is_empty()
                            && !matches!(
                                matching_edges.as_slice(),
                                [edge] if edge.composable && !edge.recursive
                            )
                        {
                            return None;
                        }
                        AuthenticatedFixedPromiseAllChildOrigin::CallResult {
                            callsite: callsite.clone(),
                        }
                    }
                    AuthenticatedEffectValueOrigin::Parameter { .. }
                    | AuthenticatedEffectValueOrigin::EffectSite { .. }
                    | AuthenticatedEffectValueOrigin::CallResult { .. } => continue,
                };
                if route.blocked
                    || route
                        .callable_path
                        .iter()
                        .any(|callable| self.recursive_callables.contains(callable))
                    || !matches!(route.sink, AuthenticatedEffectValueSink::Await { .. })
                {
                    return None;
                }
                let current_site = (site.clone(), promise.clone(), argument.clone());
                match &site_provenance {
                    Some(previous) if previous != &current_site => return None,
                    Some(_) => {}
                    None => site_provenance = Some(current_site),
                }
                let entry = children
                    .entry(*child_index)
                    .or_insert_with(|| (child.clone(), Vec::new()));
                if entry.0 != *child {
                    return None;
                }
                if !entry.1.contains(&origin) {
                    entry.1.push(origin);
                }
            }
        }
        let (site, promise, argument) = site_provenance?;
        let mut ordered = Vec::with_capacity(children.len());
        for (expected_index, (child_index, (child, origins))) in children.into_iter().enumerate() {
            let [origin] = origins.as_slice() else {
                return None;
            };
            if child_index != expected_index {
                return None;
            }
            ordered.push(AuthenticatedFixedPromiseAllChild {
                child_index,
                child,
                origin: origin.clone(),
            });
        }
        (!ordered.is_empty()).then_some(AuthenticatedFixedPromiseAllPlan {
            site,
            promise,
            argument,
            children: ordered,
        })
    }
}

fn same_authenticated_effect_value_origin(
    left: &AuthenticatedEffectValueOrigin,
    right: &AuthenticatedEffectValueOrigin,
) -> bool {
    match (left, right) {
        (
            AuthenticatedEffectValueOrigin::Parameter {
                index: left_index,
                declaration: left_declaration,
                ..
            },
            AuthenticatedEffectValueOrigin::Parameter {
                index: right_index,
                declaration: right_declaration,
                ..
            },
        ) => left_index == right_index && left_declaration == right_declaration,
        (
            AuthenticatedEffectValueOrigin::CallResult { callsite: left, .. },
            AuthenticatedEffectValueOrigin::CallResult {
                callsite: right, ..
            },
        ) => left == right,
        (
            AuthenticatedEffectValueOrigin::EffectSite { source: left },
            AuthenticatedEffectValueOrigin::EffectSite { source: right },
        ) => left == right,
        _ => false,
    }
}

fn effect_value_call_index<'a>(
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

fn exact_effect_value_call_at<'a>(
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

fn mark_recursive_effect_value_edges(
    call_edges: &mut [AuthenticatedEffectValueCallEdge],
) -> BTreeSet<CallableKey> {
    fn reaches(
        current: &CallableKey,
        target: &CallableKey,
        adjacency: &BTreeMap<CallableKey, BTreeSet<CallableKey>>,
        visited: &mut BTreeSet<CallableKey>,
    ) -> bool {
        adjacency.get(current).is_some_and(|targets| {
            targets.iter().any(|next| {
                next == target
                    || visited.insert(next.clone()) && reaches(next, target, adjacency, visited)
            })
        })
    }

    let mut adjacency = BTreeMap::<CallableKey, BTreeSet<CallableKey>>::new();
    for edge in call_edges.iter() {
        adjacency
            .entry(edge.caller.clone())
            .or_default()
            .insert(edge.target.clone());
    }
    let mut recursive_callables = BTreeSet::new();
    for edge in call_edges.iter_mut() {
        edge.recursive = edge.caller == edge.target
            || reaches(&edge.target, &edge.caller, &adjacency, &mut BTreeSet::new());
        if edge.recursive {
            recursive_callables.insert(edge.caller.clone());
            recursive_callables.insert(edge.target.clone());
        }
    }
    recursive_callables
}

fn compose_effect_value_routes(
    first: &AuthenticatedEffectValueRoute,
    second: &AuthenticatedEffectValueRoute,
    call: &CallableControlCallPlan,
) -> (Option<AuthenticatedEffectValueRoute>, bool) {
    let mut callable_path = first.callable_path.clone();
    callable_path.extend(second.callable_path.iter().cloned());
    if callable_path.len() > MAX_EFFECT_VALUE_DEPTH {
        return (None, true);
    }
    let mut callsites = first.callsites.clone();
    callsites.push(call.callsite.clone());
    callsites.extend(second.callsites.iter().cloned());
    let mut steps = first.steps.clone();
    steps.extend(second.steps.iter().cloned());
    let mut base_path_ids = first.base_path_ids.clone();
    base_path_ids.extend(second.base_path_ids.iter().copied());
    (
        Some(AuthenticatedEffectValueRoute {
            origin_callable: first.origin_callable.clone(),
            origin: first.origin.clone(),
            sink_callable: second.sink_callable.clone(),
            sink: second.sink.clone(),
            steps,
            callable_path,
            callsites,
            base_path_ids,
            blocked: first.blocked || second.blocked,
            handler_sink: second.handler_sink,
        }),
        false,
    )
}

pub(super) fn build_authenticated_effect_value_graph<'a>(
    flows: &[AuthenticatedCallableEffectValueFlow],
    control_plans: impl IntoIterator<Item = &'a CallableControlPlan>,
) -> Result<AuthenticatedEffectValueGraph> {
    let control_plans = control_plans.into_iter().collect::<Vec<_>>();
    let mut incomplete = false;
    let mut control_skeletons = BTreeMap::new();
    let mut control_sources = BTreeMap::new();
    let mut source_blocks = Vec::new();
    let mut materialized_source_effects = Vec::new();
    for plan in &control_plans {
        let skeleton = &plan.skeleton;
        if skeleton.callable_start != plan.callable_source.start
            || skeleton.callable_end != plan.callable_source.end
            || !skeleton
                .blocks
                .iter()
                .any(|block| block.id == skeleton.entry_block)
        {
            incomplete = true;
            continue;
        }
        match control_skeletons.get(&plan.callable) {
            Some(previous) if previous != skeleton => {
                incomplete = true;
                continue;
            }
            Some(_) => {}
            None => {
                control_skeletons.insert(plan.callable.clone(), skeleton.clone());
            }
        }
        match control_sources.get(&plan.callable) {
            Some(previous) if previous != &plan.callable_source => {
                incomplete = true;
                continue;
            }
            Some(_) => {}
            None => {
                control_sources.insert(plan.callable.clone(), plan.callable_source.clone());
            }
        }
        for source_effect in &plan.source_effects {
            source_blocks.push(AuthenticatedEffectValueSourceBlock {
                target_callable: source_effect.source.target_callable.clone(),
                target_callable_source: source_effect.source.target_callable_source.clone(),
                target_effect: source_effect.source.target_effect.clone(),
                target_callee: source_effect.source.target_callee.clone(),
                block: source_effect.block,
            });
            let matching = plan
                .effects
                .iter()
                .filter(|effect| {
                    effect.effect.callable == plan.callable
                        && effect.effect.callable_source == plan.callable_source
                        && effect.effect.provenance.caller_callsite.is_none()
                        && source_effect.source.matches_effect_plan(&effect.effect)
                })
                .collect::<Vec<_>>();
            match matching.as_slice() {
                [] => {}
                [effect] => {
                    materialized_source_effects.push(AuthenticatedMaterializedEffectValueSource {
                        source: source_effect.source.clone(),
                        plan: effect.effect.clone(),
                    });
                }
                _ => incomplete = true,
            }
        }
        for effect in plan.effects.iter().filter(|effect| {
            effect.effect.callable == plan.callable
                && effect.effect.callable_source == plan.callable_source
                && effect.effect.provenance.caller_callsite.is_none()
        }) {
            if !matches!(
                plan.source_effects
                    .iter()
                    .filter(|source| source.source.matches_effect_plan(&effect.effect))
                    .collect::<Vec<_>>()
                    .as_slice(),
                [_]
            ) {
                incomplete = true;
            }
        }
    }
    source_blocks.sort_by(|left, right| {
        (
            &left.target_callable,
            &left.target_callable_source.module,
            &left.target_callable_source.source_sha256,
            left.target_effect.start,
            left.target_effect.end,
            left.target_callee.start,
            left.target_callee.end,
            left.block,
        )
            .cmp(&(
                &right.target_callable,
                &right.target_callable_source.module,
                &right.target_callable_source.source_sha256,
                right.target_effect.start,
                right.target_effect.end,
                right.target_callee.start,
                right.target_callee.end,
                right.block,
            ))
    });
    source_blocks.dedup();
    materialized_source_effects.sort_by_key(|effect| {
        (
            effect.source.target_callable.clone(),
            effect.source.target_effect.module.clone(),
            effect.source.target_effect.start,
            effect.source.target_effect.end,
        )
    });
    materialized_source_effects.dedup();
    for source in &source_blocks {
        if !control_skeletons
            .get(&source.target_callable)
            .is_some_and(|skeleton| skeleton.blocks.iter().any(|block| block.id == source.block))
        {
            incomplete = true;
        }
    }
    let handler_callables = flows
        .iter()
        .filter(|flow| flow.handler)
        .map(|flow| flow.callable.clone())
        .collect::<BTreeSet<_>>();
    let flows_by_callable = flows
        .iter()
        .map(|flow| (flow.callable.clone(), flow))
        .collect::<BTreeMap<_, _>>();
    let calls = effect_value_call_index(control_plans.iter().copied());
    let mut call_edges = calls
        .iter()
        .flat_map(|((caller, _, _, _), matching)| {
            matching
                .iter()
                .map(move |call| AuthenticatedEffectValueCallEdge {
                    caller: caller.clone(),
                    callsite: call.callsite.clone(),
                    target: call.target.clone(),
                    control: (*call).clone(),
                    composable: matching.len() == 1 && call.dispatch_exact && call.arguments_safe,
                    recursive: false,
                })
        })
        .collect::<Vec<_>>();
    call_edges.sort_by_key(|edge| {
        (
            edge.callsite.module.clone(),
            edge.callsite.start,
            edge.callsite.end,
            edge.caller.clone(),
            edge.target.clone(),
        )
    });
    let recursive_callables = mark_recursive_effect_value_edges(&mut call_edges);
    let mut routes = Vec::new();
    for flow in flows {
        for path in &flow.paths {
            let blocked = flow.rejections.iter().any(|rejection| {
                same_authenticated_effect_value_origin(&rejection.origin, &path.origin)
            });
            routes.push(AuthenticatedEffectValueRoute {
                origin_callable: flow.callable.clone(),
                origin: path.origin.clone(),
                sink_callable: flow.callable.clone(),
                sink: path.sink.clone(),
                steps: path.steps.clone(),
                callable_path: vec![flow.callable.clone()],
                callsites: Vec::new(),
                base_path_ids: Vec::new(),
                blocked,
                handler_sink: flow.handler,
            });
        }
    }
    routes.sort_by_key(|route| {
        (
            route.origin_callable.clone(),
            route.sink_callable.clone(),
            route.callable_path.len(),
        )
    });
    routes.dedup();
    for (base_path_id, route) in routes.iter_mut().enumerate() {
        route.base_path_ids.push(base_path_id);
    }
    if routes.len() > MAX_EFFECT_VALUE_ROUTES {
        routes.truncate(MAX_EFFECT_VALUE_ROUTES);
        return Ok(AuthenticatedEffectValueGraph {
            routes,
            call_edges,
            recursive_callables,
            handler_callables,
            control_skeletons,
            control_sources,
            source_blocks,
            materialized_source_effects,
            materializable_consumer_plans: Vec::new(),
            incomplete: true,
        });
    }
    let mut changed = true;
    while changed {
        changed = false;
        let snapshot = routes.clone();
        'outer: for first in &snapshot {
            for second in &snapshot {
                let (call, caller) = match (&first.sink, &second.origin) {
                    (
                        AuthenticatedEffectValueSink::CallArgument {
                            callsite,
                            argument_index,
                            ..
                        },
                        AuthenticatedEffectValueOrigin::Parameter { index, .. },
                    ) if argument_index == index => {
                        let Some(call) =
                            exact_effect_value_call_at(&calls, &first.sink_callable, callsite)
                        else {
                            continue;
                        };
                        if call.target != second.origin_callable
                            || flows_by_callable
                                .get(&call.target)
                                .is_none_or(|target| *argument_index >= target.parameter_count)
                        {
                            continue;
                        }
                        (call, &first.sink_callable)
                    }
                    (
                        AuthenticatedEffectValueSink::Return { .. },
                        AuthenticatedEffectValueOrigin::CallResult { callsite, .. },
                    ) => {
                        let Some(call) =
                            exact_effect_value_call_at(&calls, &second.origin_callable, callsite)
                        else {
                            continue;
                        };
                        if call.target != first.sink_callable {
                            continue;
                        }
                        (call, &second.origin_callable)
                    }
                    _ => continue,
                };
                if call_edges.iter().any(|edge| {
                    edge.recursive
                        && edge.caller == *caller
                        && edge.callsite == call.callsite
                        && edge.target == call.target
                }) {
                    continue;
                }
                let (composed, depth_exceeded) = compose_effect_value_routes(first, second, call);
                incomplete |= depth_exceeded;
                let Some(composed) = composed else {
                    continue;
                };
                if !routes.contains(&composed) {
                    if routes.len() >= MAX_EFFECT_VALUE_ROUTES {
                        incomplete = true;
                        break 'outer;
                    }
                    routes.push(composed);
                    changed = true;
                }
            }
        }
        if incomplete {
            break;
        }
    }
    let mut graph = AuthenticatedEffectValueGraph {
        routes,
        call_edges,
        recursive_callables,
        handler_callables,
        control_skeletons,
        control_sources,
        source_blocks,
        materialized_source_effects,
        materializable_consumer_plans: Vec::new(),
        incomplete,
    };
    graph.rebuild_materializable_consumer_plans(&control_plans)?;
    Ok(graph)
}

#[cfg(test)]
mod tests {
    use super::super::callable_control::{
        CallableControlBlockCandidate, CallableControlPointCandidate,
    };
    use super::super::callable_effects::CallPosition;
    use super::super::callable_plans::{
        AuthenticatedStaticActivationCall, AuthenticatedStaticActivationCaller,
        AuthenticatedStaticActivationTarget, CallableControlCallPlan, CallableControlSourceEffect,
        CallableControlSummary,
    };
    use super::super::effect_plan::validate_callable_effect_plan;
    use super::super::effect_plan::{
        SemanticEffectKey, SemanticEffectProvenance, SemanticEffectTiming,
    };
    use super::*;

    fn anchor(start: u32, end: u32) -> SourceAnchor {
        SourceAnchor {
            module: "fixture.js".to_string(),
            source_sha256: "source".to_string(),
            start,
            end,
            slice_sha256: format!("{start}-{end}"),
        }
    }

    fn authenticated_anchor(start: u32, end: u32) -> SourceAnchor {
        SourceAnchor {
            module: "fixture.js".to_string(),
            source_sha256: "a".repeat(64),
            start,
            end,
            slice_sha256: "b".repeat(64),
        }
    }

    #[test]
    fn route_cap_cannot_hide_an_uncomposed_unsafe_sibling() {
        let callable = CallableKey {
            module: "fixture.js".to_string(),
            unit_id: "fixture.js#handler".to_string(),
        };
        let origin = AuthenticatedEffectValueOrigin::CallResult {
            callsite: anchor(1, 2),
            callee: "adapter".to_string(),
            callee_provenance: anchor(1, 2),
        };
        let mut paths = (0..MAX_EFFECT_VALUE_ROUTES)
            .map(|index| AuthenticatedEffectValuePath {
                origin: origin.clone(),
                steps: Vec::new(),
                sink: AuthenticatedEffectValueSink::Await {
                    site: anchor(10 + index as u32 * 2, 11 + index as u32 * 2),
                    value: anchor(10 + index as u32 * 2, 11 + index as u32 * 2),
                },
            })
            .collect::<Vec<_>>();
        paths.push(AuthenticatedEffectValuePath {
            origin,
            steps: Vec::new(),
            sink: AuthenticatedEffectValueSink::CallArgument {
                callsite: anchor(10_000, 10_010),
                callee: "unknown".to_string(),
                callee_provenance: anchor(10_000, 10_001),
                argument_index: 0,
                value: anchor(10_002, 10_003),
            },
        });
        let graph = build_authenticated_effect_value_graph(
            &[AuthenticatedCallableEffectValueFlow {
                callable: callable.clone(),
                callable_source: anchor(0, 20_000),
                parameter_count: 0,
                handler: true,
                paths,
                rejections: Vec::new(),
            }],
            std::iter::empty::<&CallableControlPlan>(),
        )
        .expect("route-cap test graph must build");

        assert!(graph.incomplete);
        assert!(!graph.closes_call_result("fixture.js", 1, 2, &BTreeSet::new()));
    }

    #[test]
    fn guest_graph_closes_an_unmaterialized_source_only_for_exact_specialized_provenance() {
        let fixture_anchor = authenticated_anchor;
        let source_callable = CallableKey {
            module: "fixture.js".to_string(),
            unit_id: "span:0:100".to_string(),
        };
        let consumer_callable = CallableKey {
            module: "fixture.js".to_string(),
            unit_id: "span:100:200".to_string(),
        };
        let consumer_source = fixture_anchor(100, 200);
        let consumer_callsite = fixture_anchor(120, 140);
        let source = AuthenticatedEffectValueSource {
            target_callable: source_callable.clone(),
            target_callable_source: fixture_anchor(0, 100),
            target_effect: fixture_anchor(20, 30),
            target_callee: fixture_anchor(20, 26),
            capability_reference: fixture_anchor(20, 22),
            capability_binding: fixture_anchor(1, 4),
            capability_name: "ctx".to_string(),
        };
        let specialized = CallableEffectPlan {
            callable: consumer_callable.clone(),
            callable_source: consumer_source.clone(),
            effect_key: SemanticEffectKey {
                operation_kind: "databaseGet".to_string(),
                result_kind: "hostValue".to_string(),
                timing: SemanticEffectTiming::Suspending,
                static_operands: BTreeMap::from([("table".to_string(), "documents".to_string())]),
                index_constraints: Vec::new(),
                limit: None,
                limit_argument_index: None,
            },
            static_operands: Vec::new(),
            dynamic_operands: Vec::new(),
            provenance: SemanticEffectProvenance {
                target_callable: source.target_callable.clone(),
                target_callable_source: source.target_callable_source.clone(),
                target_effect: source.target_effect.clone(),
                target_callee: source.target_callee.clone(),
                capability_reference: source.capability_reference.clone(),
                capability_binding: source.capability_binding.clone(),
                capability_name: source.capability_name.clone(),
                caller_callsite: Some(consumer_callsite.clone()),
            },
        };
        let control = CallableControlPlan {
            callable: source_callable.clone(),
            callable_source: source.target_callable_source.clone(),
            skeleton: CallableControlSkeletonCandidate {
                callable_start: 0,
                callable_end: 100,
                entry_block: 0,
                blocks: vec![CallableControlBlockCandidate {
                    id: 0,
                    unreachable: false,
                    instructions: Vec::new(),
                    successors: Vec::new(),
                }],
                points: vec![CallableControlPointCandidate {
                    kind: CallableControlPointKind::Await,
                    start: 10,
                    end: 35,
                    block: 0,
                    value_start: Some(20),
                    value_end: Some(30),
                }],
                intra_block_order: CallableIntraBlockOrder::Unresolved,
            },
            control: CallableControlSummary {
                block_count: 1,
                await_count: 1,
                call_count: 0,
                has_choice: false,
                has_cycle: false,
                has_finalization: false,
                has_explicit_exception_path: false,
                has_implicit_error_harness: false,
            },
            source_effects: vec![CallableControlSourceEffect {
                source: source.clone(),
                block: 0,
            }],
            // This empty vector is the operand-unfinalized state. The specialized descriptor is
            // deliberately not installed in the source callable's semantic plan set.
            effects: Vec::new(),
            calls: Vec::new(),
        };
        let caller_control = CallableControlPlan {
            callable: consumer_callable.clone(),
            callable_source: consumer_source.clone(),
            skeleton: CallableControlSkeletonCandidate {
                callable_start: 100,
                callable_end: 200,
                entry_block: 0,
                blocks: vec![CallableControlBlockCandidate {
                    id: 0,
                    unreachable: false,
                    instructions: Vec::new(),
                    successors: Vec::new(),
                }],
                points: vec![CallableControlPointCandidate {
                    kind: CallableControlPointKind::Call,
                    start: 120,
                    end: 140,
                    block: 0,
                    value_start: None,
                    value_end: None,
                }],
                intra_block_order: CallableIntraBlockOrder::Unresolved,
            },
            control: CallableControlSummary {
                block_count: 1,
                await_count: 0,
                call_count: 1,
                has_choice: false,
                has_cycle: false,
                has_finalization: false,
                has_explicit_exception_path: false,
                has_implicit_error_harness: false,
            },
            source_effects: Vec::new(),
            effects: Vec::new(),
            calls: vec![CallableControlCallPlan {
                callsite: consumer_callsite.clone(),
                target: source_callable.clone(),
                target_source: source.target_callable_source.clone(),
                block: 0,
                position: CallPosition::SequentialAwait,
                dispatch_exact: true,
                arguments_safe: true,
                arguments: Vec::new(),
            }],
        };
        let activation_calls = AuthenticatedStaticActivationCallIndex::from_test_calls(vec![
            AuthenticatedStaticActivationCall {
                caller: AuthenticatedStaticActivationCaller::Callable(consumer_callable.clone()),
                target: AuthenticatedStaticActivationTarget::Callable(source_callable.clone()),
                callsite: consumer_callsite,
                position: Some(CallPosition::SequentialAwait),
                dispatch_exact: true,
            },
        ])
        .expect("test activation call must be unambiguous");
        let graph = build_authenticated_effect_value_graph(
            &[
                AuthenticatedCallableEffectValueFlow {
                    callable: source_callable,
                    callable_source: source.target_callable_source.clone(),
                    parameter_count: 0,
                    handler: true,
                    paths: vec![AuthenticatedEffectValuePath {
                        origin: AuthenticatedEffectValueOrigin::EffectSite {
                            source: source.clone(),
                        },
                        steps: Vec::new(),
                        sink: AuthenticatedEffectValueSink::Await {
                            site: fixture_anchor(10, 35),
                            value: source.target_effect.clone(),
                        },
                    }],
                    rejections: Vec::new(),
                },
                AuthenticatedCallableEffectValueFlow {
                    callable: consumer_callable,
                    callable_source: consumer_source,
                    parameter_count: 0,
                    handler: true,
                    paths: Vec::new(),
                    rejections: Vec::new(),
                },
            ],
            [&control, &caller_control],
        )
        .expect("specialized-provenance test graph must build");

        assert!(!graph.incomplete);
        assert!(graph.routes.iter().any(|route| {
            matches!(
                &route.origin,
                AuthenticatedEffectValueOrigin::EffectSite { source: origin } if origin == &source
            )
        }));
        assert!(!graph.closes_effect_site(&specialized));
        assert!(validate_callable_effect_plan(specialized.clone()).is_ok());
        assert!(
            !graph.closes_guest_effect_site(
                &specialized,
                &AuthenticatedStaticActivationCallIndex::default(),
                &BTreeSet::new(),
            ),
            "guest specialization requires its exact activation record"
        );
        let mut graph_without_value_edge = graph.clone();
        graph_without_value_edge.call_edges.clear();
        assert!(
            !graph_without_value_edge.closes_guest_effect_site(
                &specialized,
                &activation_calls,
                &BTreeSet::new(),
            ),
            "guest specialization requires its exact composable value-flow edge"
        );
        assert!(graph.closes_guest_effect_site(&specialized, &activation_calls, &BTreeSet::new(),));

        let mut mismatched_target_callable = specialized.clone();
        mismatched_target_callable
            .provenance
            .target_callable
            .unit_id = "span:200:300".to_string();
        let mut mismatched_target_source = specialized.clone();
        mismatched_target_source.provenance.target_callable_source = fixture_anchor(200, 300);
        let mut mismatched_target_effect = specialized.clone();
        mismatched_target_effect.provenance.target_effect = fixture_anchor(40, 50);
        let mut mismatched_target_callee = specialized.clone();
        mismatched_target_callee.provenance.target_callee = fixture_anchor(40, 46);
        let mut mismatched_capability_reference = specialized.clone();
        mismatched_capability_reference
            .provenance
            .capability_reference = fixture_anchor(50, 52);
        let mut mismatched_capability_binding = specialized.clone();
        mismatched_capability_binding.provenance.capability_binding = fixture_anchor(52, 55);
        let mut mismatched_capability_name = specialized.clone();
        mismatched_capability_name.provenance.capability_name = "different".to_string();
        for (name, mismatched) in [
            ("target callable", mismatched_target_callable),
            ("target callable source", mismatched_target_source),
            ("target effect", mismatched_target_effect),
            ("target callee", mismatched_target_callee),
            ("capability reference", mismatched_capability_reference),
            ("capability binding", mismatched_capability_binding),
            ("capability name", mismatched_capability_name),
        ] {
            assert!(!source.matches_effect_plan(&mismatched), "{name}");
            assert!(
                !graph.closes_guest_effect_site(&mismatched, &activation_calls, &BTreeSet::new(),),
                "{name}"
            );
        }

        let mut mismatched_consumer_callable = specialized.clone();
        mismatched_consumer_callable.callable.unit_id = "span:101:199".to_string();
        let mut mismatched_consumer_source = specialized.clone();
        mismatched_consumer_source.callable_source.slice_sha256 = "c".repeat(64);
        let mut mismatched_caller_callsite = specialized;
        mismatched_caller_callsite
            .provenance
            .caller_callsite
            .as_mut()
            .expect("specialized fixture lost its caller callsite")
            .slice_sha256 = "c".repeat(64);
        for (name, mismatched) in [
            ("consumer callable", mismatched_consumer_callable),
            ("consumer callable source", mismatched_consumer_source),
            ("consumer callsite", mismatched_caller_callsite),
        ] {
            assert!(
                validate_callable_effect_plan(mismatched.clone()).is_ok(),
                "{name} corruption must remain locally valid"
            );
            assert!(
                source.matches_effect_plan(&mismatched),
                "{name} must preserve the source relation"
            );
            assert!(
                !graph.closes_guest_effect_site(&mismatched, &activation_calls, &BTreeSet::new(),),
                "{name}"
            );
        }
    }
}
