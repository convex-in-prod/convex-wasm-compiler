use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableKey {
    pub(super) module: String,
    pub(super) unit_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SourceAnchor {
    pub(super) module: String,
    pub(super) source_sha256: String,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) slice_sha256: String,
}

impl SourceAnchor {
    fn contains(&self, other: &Self) -> bool {
        self.module == other.module
            && self.source_sha256 == other.source_sha256
            && self.start <= other.start
            && other.end <= self.end
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum SemanticEffectTiming {
    Synchronous,
    Suspending,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SemanticIndexConstraint {
    pub(super) field: String,
    pub(super) operator: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SemanticEffectKey {
    pub(super) operation_kind: String,
    pub(super) result_kind: String,
    pub(super) timing: SemanticEffectTiming,
    pub(super) static_operands: std::collections::BTreeMap<String, String>,
    pub(super) index_constraints: Vec<SemanticIndexConstraint>,
    pub(super) limit: Option<u32>,
    #[serde(default)]
    pub(super) limit_argument_index: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum SemanticOperand {
    Parameter(usize),
    RuntimeInput(usize),
    LiteralString(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub(super) enum SemanticOperandProjection {
    ExactCaller { consumer_provenance: SourceAnchor },
    TargetOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SemanticEffectOperand {
    pub(super) value: SemanticOperand,
    pub(super) target_argument_index: Option<usize>,
    pub(super) target_provenance: SourceAnchor,
    pub(super) projection: SemanticOperandProjection,
}

impl SemanticEffectOperand {
    pub(super) fn consumer_provenance(&self) -> Option<&SourceAnchor> {
        match &self.projection {
            SemanticOperandProjection::ExactCaller {
                consumer_provenance,
            } => Some(consumer_provenance),
            SemanticOperandProjection::TargetOnly => None,
        }
    }

    pub(super) fn is_target_only(&self) -> bool {
        matches!(&self.projection, SemanticOperandProjection::TargetOnly)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SemanticStaticEffectOperand {
    pub(super) field: String,
    pub(super) value: String,
    pub(super) target_argument_index: Option<usize>,
    pub(super) target_provenance: SourceAnchor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SemanticEffectProvenance {
    pub(super) target_callable: CallableKey,
    pub(super) target_callable_source: SourceAnchor,
    pub(super) target_effect: SourceAnchor,
    pub(super) target_callee: SourceAnchor,
    pub(super) capability_reference: SourceAnchor,
    pub(super) capability_binding: SourceAnchor,
    pub(super) capability_name: String,
    pub(super) caller_callsite: Option<SourceAnchor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableEffectPlan {
    pub(super) callable: CallableKey,
    pub(super) callable_source: SourceAnchor,
    pub(super) effect_key: SemanticEffectKey,
    pub(super) static_operands: Vec<SemanticStaticEffectOperand>,
    pub(super) dynamic_operands: Vec<SemanticEffectOperand>,
    pub(super) provenance: SemanticEffectProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NormalizedCallableEffectPlan {
    pub(super) effect_key: SemanticEffectKey,
    pub(super) dynamic_operands: Vec<SemanticOperand>,
}

impl CallableEffectPlan {
    pub(super) fn normalized_projection(&self) -> NormalizedCallableEffectPlan {
        NormalizedCallableEffectPlan {
            effect_key: self.effect_key.clone(),
            dynamic_operands: self
                .dynamic_operands
                .iter()
                .map(|operand| operand.value.clone())
                .collect(),
        }
    }

    pub(super) fn semantically_equivalent(&self, other: &Self) -> bool {
        self.normalized_projection() == other.normalized_projection()
    }

    pub(super) fn same_target_effect(&self, other: &Self) -> bool {
        self.effect_key == other.effect_key
            && self.static_operands == other.static_operands
            && self.provenance.target_callable == other.provenance.target_callable
            && self.provenance.target_callable_source == other.provenance.target_callable_source
            && self.provenance.target_effect == other.provenance.target_effect
            && self.provenance.target_callee == other.provenance.target_callee
            && self.provenance.capability_reference == other.provenance.capability_reference
            && self.provenance.capability_binding == other.provenance.capability_binding
            && self.provenance.capability_name == other.provenance.capability_name
            && self.dynamic_operands.len() == other.dynamic_operands.len()
            && self
                .dynamic_operands
                .iter()
                .zip(&other.dynamic_operands)
                .all(|(left, right)| {
                    left.target_argument_index == right.target_argument_index
                        && left.target_provenance == right.target_provenance
                        && left.is_target_only() == right.is_target_only()
                })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CallableEffectPlanRejectionKind {
    InvalidCallable,
    InvalidProvenance,
    InvalidSemantics,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallableEffectPlanRejection {
    pub(super) kind: CallableEffectPlanRejectionKind,
    pub(super) message: String,
}

impl std::fmt::Display for CallableEffectPlanRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for CallableEffectPlanRejection {}

fn callable_effect_rejection(
    kind: CallableEffectPlanRejectionKind,
    message: impl Into<String>,
) -> CallableEffectPlanRejection {
    CallableEffectPlanRejection {
        kind,
        message: message.into(),
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_callable_key(
    callable: &CallableKey,
    description: &str,
) -> Result<(), CallableEffectPlanRejection> {
    if callable.module.is_empty() || callable.unit_id.is_empty() {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidCallable,
            format!("{description} requires nonempty module and unit identities"),
        ));
    }
    Ok(())
}

fn validate_source_anchor(
    anchor: &SourceAnchor,
    description: &str,
) -> Result<(), CallableEffectPlanRejection> {
    if anchor.module.is_empty() {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            format!("{description} requires a nonempty module identity"),
        ));
    }
    if anchor.start >= anchor.end {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            format!("{description} must identify a nonempty source range"),
        ));
    }
    if !is_lowercase_sha256(&anchor.source_sha256) || !is_lowercase_sha256(&anchor.slice_sha256) {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            format!("{description} requires lowercase SHA-256 source and slice identities"),
        ));
    }
    Ok(())
}

pub(super) fn validate_callable_effect_plan(
    plan: CallableEffectPlan,
) -> Result<CallableEffectPlan, CallableEffectPlanRejection> {
    validate_callable_key(&plan.callable, "effect-plan callable")?;
    validate_callable_key(
        &plan.provenance.target_callable,
        "effect-plan target callable",
    )?;
    validate_source_anchor(&plan.callable_source, "effect-plan callable source")?;
    validate_source_anchor(
        &plan.provenance.target_callable_source,
        "effect-plan target callable source",
    )?;
    validate_source_anchor(&plan.provenance.target_effect, "effect-plan target effect")?;
    validate_source_anchor(&plan.provenance.target_callee, "effect-plan target callee")?;
    validate_source_anchor(
        &plan.provenance.capability_reference,
        "effect-plan capability reference",
    )?;
    validate_source_anchor(
        &plan.provenance.capability_binding,
        "effect-plan capability binding",
    )?;
    if let Some(caller_callsite) = &plan.provenance.caller_callsite {
        validate_source_anchor(caller_callsite, "effect-plan caller callsite")?;
    }
    for operand in &plan.dynamic_operands {
        validate_source_anchor(&operand.target_provenance, "effect-plan target operand")?;
        if let Some(consumer_provenance) = operand.consumer_provenance() {
            validate_source_anchor(consumer_provenance, "effect-plan consumer operand")?;
        }
    }
    for operand in &plan.static_operands {
        validate_source_anchor(
            &operand.target_provenance,
            "effect-plan static target operand",
        )?;
    }

    if plan.callable_source.module != plan.callable.module {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            "effect-plan callable source module must match its callable identity",
        ));
    }
    if plan.provenance.target_callable_source.module != plan.provenance.target_callable.module {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            "effect-plan target callable source module must match its callable identity",
        ));
    }
    if !plan
        .provenance
        .target_callable_source
        .contains(&plan.provenance.target_effect)
    {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            "effect-plan target effect must be contained by its callable source",
        ));
    }
    if !plan
        .provenance
        .target_effect
        .contains(&plan.provenance.target_callee)
    {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            "effect-plan target callee must be contained by its target effect",
        ));
    }
    if !plan
        .provenance
        .target_callee
        .contains(&plan.provenance.capability_reference)
    {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            "effect-plan capability reference must be contained by its target callee",
        ));
    }
    if plan.provenance.capability_binding.module != plan.provenance.target_callable_source.module
        || plan.provenance.capability_binding.source_sha256
            != plan.provenance.target_callable_source.source_sha256
        || plan.provenance.capability_name.is_empty()
    {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            "effect-plan capability binding must identify a named Oxc binding in the target module",
        ));
    }

    let caller_callsite = if plan.callable == plan.provenance.target_callable {
        if plan.callable_source != plan.provenance.target_callable_source {
            return Err(callable_effect_rejection(
                CallableEffectPlanRejectionKind::InvalidProvenance,
                "direct effect plans require identical callable source anchors",
            ));
        }
        if plan.provenance.caller_callsite.is_some() {
            return Err(callable_effect_rejection(
                CallableEffectPlanRejectionKind::InvalidProvenance,
                "direct effect plans must not include a caller callsite",
            ));
        }
        None
    } else {
        let caller_callsite = plan.provenance.caller_callsite.as_ref().ok_or_else(|| {
            callable_effect_rejection(
                CallableEffectPlanRejectionKind::InvalidProvenance,
                "specialized effect plans require a caller callsite",
            )
        })?;
        if !plan.callable_source.contains(caller_callsite) {
            return Err(callable_effect_rejection(
                CallableEffectPlanRejectionKind::InvalidProvenance,
                "effect-plan caller callsite must be contained by the caller source",
            ));
        }
        Some(caller_callsite)
    };

    if plan.dynamic_operands.iter().any(|operand| {
        !plan
            .provenance
            .target_effect
            .contains(&operand.target_provenance)
    }) {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            "effect-plan target operand provenance must be contained by its target effect",
        ));
    }
    for operand in &plan.dynamic_operands {
        match &operand.projection {
            SemanticOperandProjection::ExactCaller {
                consumer_provenance,
            } => {
                if !caller_callsite
                    .unwrap_or(&plan.provenance.target_effect)
                    .contains(consumer_provenance)
                {
                    return Err(callable_effect_rejection(
                        CallableEffectPlanRejectionKind::InvalidProvenance,
                        "effect-plan caller-projected operand must be contained by its consumer site",
                    ));
                }
            }
            SemanticOperandProjection::TargetOnly => {
                if caller_callsite.is_none()
                    || !matches!(operand.value, SemanticOperand::RuntimeInput(_))
                {
                    return Err(callable_effect_rejection(
                        CallableEffectPlanRejectionKind::InvalidProvenance,
                        "effect-plan target-only operand must be a specialized runtime input",
                    ));
                }
            }
        }
    }
    let mut static_fields = std::collections::BTreeSet::new();
    if plan.static_operands.iter().any(|operand| {
        operand.field.is_empty()
            || operand.value.is_empty()
            || !static_fields.insert(operand.field.clone())
            || plan.effect_key.static_operands.get(&operand.field) != Some(&operand.value)
            || !plan
                .provenance
                .target_effect
                .contains(&operand.target_provenance)
    }) {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidProvenance,
            "effect-plan static operand provenance must exactly match its semantic descriptor",
        ));
    }

    if plan.effect_key.operation_kind.is_empty() || plan.effect_key.result_kind.is_empty() {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidSemantics,
            "effect-plan operation and result kinds must be nonempty",
        ));
    }
    if plan
        .effect_key
        .static_operands
        .iter()
        .any(|(name, value)| name.is_empty() || value.is_empty())
    {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidSemantics,
            "effect-plan static operand names and values must be nonempty",
        ));
    }
    if plan
        .effect_key
        .index_constraints
        .iter()
        .any(|constraint| constraint.field.is_empty() || constraint.operator.is_empty())
    {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidSemantics,
            "effect-plan index constraint fields and operators must be nonempty",
        ));
    }
    if let Some(limit_argument_index) = plan.effect_key.limit_argument_index
        && (plan.effect_key.operation_kind != "databaseIndexQuery"
            || plan.effect_key.limit.is_some()
            || plan
                .effect_key
                .static_operands
                .get("terminal")
                .map(String::as_str)
                != Some("collect")
            || usize::try_from(limit_argument_index).ok()
                != Some(plan.effect_key.index_constraints.len()))
    {
        return Err(callable_effect_rejection(
            CallableEffectPlanRejectionKind::InvalidSemantics,
            "dynamic query limit must follow all index constraints in a collect descriptor",
        ));
    }

    Ok(plan)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PlanSourceSpan {
    pub(super) start: u32,
    pub(super) end: u32,
}

impl PlanSourceSpan {
    fn is_valid(self) -> bool {
        self.start < self.end
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorizedEffectLeaf {
    pub(super) authorization_id: String,
    pub(super) operation_id: u32,
    pub(super) operation_stable_key: String,
    pub(super) operation_span: PlanSourceSpan,
    pub(super) arguments: Vec<PlanSourceSpan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PureContinuation {
    pub(super) authorization_id: String,
    pub(super) body_span: PlanSourceSpan,
    pub(super) suspension_span: PlanSourceSpan,
    pub(super) result_binding: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum BatchKind {
    Fixed,
    Mapped {
        iterator_span: PlanSourceSpan,
        element_binding: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ChoiceArm {
    pub(super) label: String,
    pub(super) plan: EffectPlanNode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(super) enum EffectPlanNode {
    ZeroEffect {
        result_span: Option<PlanSourceSpan>,
    },
    AuthorizedEffect(AuthorizedEffectLeaf),
    Continue {
        input: Box<EffectPlanNode>,
        continuation: PureContinuation,
    },
    Choice {
        discriminant_span: PlanSourceSpan,
        arms: Vec<ChoiceArm>,
    },
    Batch {
        kind: BatchKind,
        children: Vec<EffectPlanNode>,
    },
    Sequence {
        steps: Vec<EffectPlanNode>,
    },
    IndependentlyResumable {
        reason: String,
        suspension_count: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EffectPlanRejectionKind {
    InvalidStructure,
    IndependentlyResumable,
    UnsupportedLowering,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EffectPlanRejection {
    pub(super) kind: EffectPlanRejectionKind,
    pub(super) path: Vec<usize>,
    pub(super) message: String,
}

impl std::fmt::Display for EffectPlanRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for EffectPlanRejection {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StartableEffectPlan {
    root: EffectPlanNode,
    pub(super) maximum_sequential_suspensions: usize,
    pub(super) authorized_leaf_count: usize,
}

impl StartableEffectPlan {
    pub(super) fn root(&self) -> &EffectPlanNode {
        &self.root
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CurrentDirectBatchLeaf {
    pub(super) effect: AuthorizedEffectLeaf,
    pub(super) continuation: Option<PureContinuation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CurrentDirectBatchLayout {
    Fixed(Vec<CurrentDirectBatchLeaf>),
    Mapped {
        iterator_span: PlanSourceSpan,
        element_binding: String,
        child: CurrentDirectBatchLeaf,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PlanAnalysis {
    maximum_sequential_suspensions: usize,
    authorized_leaf_count: usize,
}

fn rejection(
    kind: EffectPlanRejectionKind,
    path: &[usize],
    message: impl Into<String>,
) -> EffectPlanRejection {
    EffectPlanRejection {
        kind,
        path: path.to_vec(),
        message: message.into(),
    }
}

fn validate_leaf(leaf: &AuthorizedEffectLeaf, path: &[usize]) -> Result<(), EffectPlanRejection> {
    if leaf.authorization_id.is_empty() || leaf.operation_stable_key.is_empty() {
        return Err(rejection(
            EffectPlanRejectionKind::InvalidStructure,
            path,
            "effect-plan leaves require authenticated authorization and operation identities",
        ));
    }
    if leaf.operation_id == 0 {
        return Err(rejection(
            EffectPlanRejectionKind::InvalidStructure,
            path,
            "effect-plan operation IDs must be nonzero",
        ));
    }
    if !leaf.operation_span.is_valid() || leaf.arguments.iter().any(|span| !span.is_valid()) {
        return Err(rejection(
            EffectPlanRejectionKind::InvalidStructure,
            path,
            "effect-plan operation and argument spans must be nonempty",
        ));
    }
    Ok(())
}

fn validate_continuation(
    continuation: &PureContinuation,
    path: &[usize],
) -> Result<(), EffectPlanRejection> {
    if continuation.authorization_id.is_empty() || continuation.result_binding.is_empty() {
        return Err(rejection(
            EffectPlanRejectionKind::InvalidStructure,
            path,
            "effect-plan continuations require authenticated identities and result bindings",
        ));
    }
    if !continuation.body_span.is_valid()
        || !continuation.suspension_span.is_valid()
        || continuation.suspension_span.start < continuation.body_span.start
        || continuation.suspension_span.end > continuation.body_span.end
    {
        return Err(rejection(
            EffectPlanRejectionKind::InvalidStructure,
            path,
            "effect-plan continuation suspension must be contained by its body",
        ));
    }
    Ok(())
}

fn analyze_node(
    node: &EffectPlanNode,
    path: &mut Vec<usize>,
) -> Result<PlanAnalysis, EffectPlanRejection> {
    match node {
        EffectPlanNode::ZeroEffect { result_span } => {
            if result_span.is_some_and(|span| !span.is_valid()) {
                return Err(rejection(
                    EffectPlanRejectionKind::InvalidStructure,
                    path,
                    "zero-effect result spans must be nonempty",
                ));
            }
            Ok(PlanAnalysis::default())
        }
        EffectPlanNode::AuthorizedEffect(leaf) => {
            validate_leaf(leaf, path)?;
            Ok(PlanAnalysis {
                maximum_sequential_suspensions: 1,
                authorized_leaf_count: 1,
            })
        }
        EffectPlanNode::Continue {
            input,
            continuation,
        } => {
            validate_continuation(continuation, path)?;
            analyze_node(input, path)
        }
        EffectPlanNode::Choice {
            discriminant_span,
            arms,
        } => {
            if !discriminant_span.is_valid() || arms.is_empty() {
                return Err(rejection(
                    EffectPlanRejectionKind::InvalidStructure,
                    path,
                    "effect-plan choices require a discriminant and at least one arm",
                ));
            }
            let mut labels = std::collections::BTreeSet::new();
            let mut analysis = PlanAnalysis::default();
            for (index, arm) in arms.iter().enumerate() {
                if arm.label.is_empty() || !labels.insert(arm.label.as_str()) {
                    return Err(rejection(
                        EffectPlanRejectionKind::InvalidStructure,
                        path,
                        "effect-plan choice labels must be nonempty and unique",
                    ));
                }
                path.push(index);
                let arm_analysis = analyze_node(&arm.plan, path)?;
                path.pop();
                analysis.maximum_sequential_suspensions = analysis
                    .maximum_sequential_suspensions
                    .max(arm_analysis.maximum_sequential_suspensions);
                analysis.authorized_leaf_count += arm_analysis.authorized_leaf_count;
            }
            Ok(analysis)
        }
        EffectPlanNode::Batch { kind, children } => {
            if let BatchKind::Mapped {
                iterator_span,
                element_binding,
            } = kind
                && (!iterator_span.is_valid() || element_binding.is_empty() || children.len() != 1)
            {
                return Err(rejection(
                    EffectPlanRejectionKind::InvalidStructure,
                    path,
                    "mapped effect plans require one child template, iterator, and element binding",
                ));
            }
            let mut analysis = PlanAnalysis::default();
            for (index, child) in children.iter().enumerate() {
                path.push(index);
                let child_analysis = analyze_node(child, path)?;
                if child_analysis.maximum_sequential_suspensions > 1 {
                    let rejection = rejection(
                        EffectPlanRejectionKind::IndependentlyResumable,
                        path,
                        "effect-plan batch child has independently resumable sequential suspensions",
                    );
                    path.pop();
                    return Err(rejection);
                }
                path.pop();
                analysis.maximum_sequential_suspensions = analysis
                    .maximum_sequential_suspensions
                    .max(child_analysis.maximum_sequential_suspensions);
                analysis.authorized_leaf_count += child_analysis.authorized_leaf_count;
            }
            Ok(analysis)
        }
        EffectPlanNode::Sequence { steps } => {
            if steps.is_empty() {
                return Err(rejection(
                    EffectPlanRejectionKind::InvalidStructure,
                    path,
                    "effect-plan sequences require at least one step",
                ));
            }
            let mut analysis = PlanAnalysis::default();
            for (index, step) in steps.iter().enumerate() {
                path.push(index);
                let step_analysis = analyze_node(step, path)?;
                path.pop();
                analysis.maximum_sequential_suspensions +=
                    step_analysis.maximum_sequential_suspensions;
                analysis.authorized_leaf_count += step_analysis.authorized_leaf_count;
            }
            Ok(analysis)
        }
        EffectPlanNode::IndependentlyResumable {
            reason,
            suspension_count,
        } => Err(rejection(
            EffectPlanRejectionKind::IndependentlyResumable,
            path,
            format!(
                "effect-plan child is independently resumable across {suspension_count} suspensions: {reason}"
            ),
        )),
    }
}

pub(super) fn validate_effect_plan(
    root: EffectPlanNode,
) -> Result<StartableEffectPlan, EffectPlanRejection> {
    let analysis = analyze_node(&root, &mut Vec::new())?;
    Ok(StartableEffectPlan {
        root,
        maximum_sequential_suspensions: analysis.maximum_sequential_suspensions,
        authorized_leaf_count: analysis.authorized_leaf_count,
    })
}

fn current_direct_batch_leaf(
    node: &EffectPlanNode,
    path: &[usize],
) -> Result<CurrentDirectBatchLeaf, EffectPlanRejection> {
    match node {
        EffectPlanNode::AuthorizedEffect(effect) => Ok(CurrentDirectBatchLeaf {
            effect: effect.clone(),
            continuation: None,
        }),
        EffectPlanNode::Continue {
            input,
            continuation,
        } => match input.as_ref() {
            EffectPlanNode::AuthorizedEffect(effect) => Ok(CurrentDirectBatchLeaf {
                effect: effect.clone(),
                continuation: Some(continuation.clone()),
            }),
            _ => Err(rejection(
                EffectPlanRejectionKind::UnsupportedLowering,
                path,
                "current direct-batch lowering requires a continuation to consume one effect",
            )),
        },
        _ => Err(rejection(
            EffectPlanRejectionKind::UnsupportedLowering,
            path,
            "current direct-batch lowering does not yet support zero-effect, branch, nested-batch, or sequential child plans",
        )),
    }
}

pub(super) fn current_direct_batch_layout(
    plan: &StartableEffectPlan,
) -> Result<CurrentDirectBatchLayout, EffectPlanRejection> {
    let EffectPlanNode::Batch { kind, children } = plan.root() else {
        return Err(rejection(
            EffectPlanRejectionKind::UnsupportedLowering,
            &[],
            "current direct-batch lowering requires a batch root",
        ));
    };
    match kind {
        BatchKind::Fixed => children
            .iter()
            .enumerate()
            .map(|(index, child)| current_direct_batch_leaf(child, &[index]))
            .collect::<Result<Vec<_>, _>>()
            .map(CurrentDirectBatchLayout::Fixed),
        BatchKind::Mapped {
            iterator_span,
            element_binding,
        } => Ok(CurrentDirectBatchLayout::Mapped {
            iterator_span: *iterator_span,
            element_binding: element_binding.clone(),
            child: current_direct_batch_leaf(&children[0], &[0])?,
        }),
    }
}

pub(super) fn current_direct_batch_authorization_layout(
    batch: &super::direct_batches::DirectAsyncBatchAuthorization,
) -> Result<CurrentDirectBatchLayout, EffectPlanRejection> {
    use super::direct_batches::DirectAsyncBatchAuthorizationShape;

    match &batch.shape {
        DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            helper_continuation_prebound,
            helper_continuation,
            ..
        } => {
            if *helper_continuation_prebound != helper_continuation.is_some() {
                return Err(rejection(
                    EffectPlanRejectionKind::InvalidStructure,
                    &[],
                    "mapped batch continuation prebinding metadata disagrees with its authorization",
                ));
            }
        }
        DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } => {
            for (index, child) in children.iter().enumerate() {
                if child.helper_continuation_prebound != child.helper_continuation.is_some() {
                    return Err(rejection(
                        EffectPlanRejectionKind::InvalidStructure,
                        &[index],
                        "fixed batch continuation prebinding metadata disagrees with its authorization",
                    ));
                }
            }
        }
    }

    let continuation_node =
        |effect: EffectPlanNode,
         continuation: &super::direct_batches::DirectBatchHelperContinuationAuthorization| {
            EffectPlanNode::Continue {
                input: Box::new(effect),
                continuation: PureContinuation {
                    authorization_id: format!(
                        "{}:{}",
                        continuation.source_sha256, continuation.source_body_start
                    ),
                    body_span: PlanSourceSpan {
                        start: continuation.source_body_start,
                        end: continuation.source_body_end,
                    },
                    suspension_span: PlanSourceSpan {
                        start: continuation.source_suspension_start,
                        end: continuation.source_suspension_end,
                    },
                    result_binding: continuation.source_result_binding.clone(),
                },
            }
        };
    let effect_node =
        |authorization_id: String,
         operation_id: u32,
         operation_stable_key: &str,
         operation_start: u32,
         operation_end: u32,
         arguments: &[super::direct_batches::DirectAsyncBatchArgumentAuthorization]| {
            EffectPlanNode::AuthorizedEffect(AuthorizedEffectLeaf {
                authorization_id,
                operation_id,
                operation_stable_key: operation_stable_key.to_string(),
                operation_span: PlanSourceSpan {
                    start: operation_start,
                    end: operation_end,
                },
                arguments: arguments
                    .iter()
                    .map(|argument| PlanSourceSpan {
                        start: argument.source_start,
                        end: argument.source_end,
                    })
                    .collect(),
            })
        };
    let root = match &batch.shape {
        DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            operation_start,
            operation_end,
            operation_id,
            operation_stable_key,
            dynamic_arguments,
            source_iterator_start,
            source_iterator_end,
            callback_parameter,
            helper_continuation,
            ..
        } => {
            let effect = effect_node(
                format!("{}:0", batch.id),
                *operation_id,
                operation_stable_key,
                *operation_start,
                *operation_end,
                dynamic_arguments,
            );
            EffectPlanNode::Batch {
                kind: BatchKind::Mapped {
                    iterator_span: PlanSourceSpan {
                        start: *source_iterator_start,
                        end: *source_iterator_end,
                    },
                    element_binding: callback_parameter.clone(),
                },
                children: vec![
                    helper_continuation
                        .as_ref()
                        .map_or(effect.clone(), |continuation| {
                            continuation_node(effect, continuation)
                        }),
                ],
            }
        }
        DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } => {
            EffectPlanNode::Batch {
                kind: BatchKind::Fixed,
                children: children
                    .iter()
                    .enumerate()
                    .map(|(index, child)| {
                        let effect = effect_node(
                            format!("{}:{index}", batch.id),
                            child.operation_id,
                            &child.operation_stable_key,
                            child.operation_start,
                            child.operation_end,
                            &child.dynamic_arguments,
                        );
                        child
                            .helper_continuation
                            .as_ref()
                            .map_or(effect.clone(), |continuation| {
                                continuation_node(effect, continuation)
                            })
                    })
                    .collect(),
            }
        }
    };
    let plan = validate_effect_plan(root)?;
    current_direct_batch_layout(&plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: u32, end: u32) -> PlanSourceSpan {
        PlanSourceSpan { start, end }
    }

    fn effect(id: u32, start: u32) -> EffectPlanNode {
        EffectPlanNode::AuthorizedEffect(AuthorizedEffectLeaf {
            authorization_id: format!("effect-{id}"),
            operation_id: id,
            operation_stable_key: format!("operation-{id}"),
            operation_span: span(start, start + 2),
            arguments: vec![span(start + 2, start + 3)],
        })
    }

    fn continuation(input: EffectPlanNode, start: u32) -> EffectPlanNode {
        EffectPlanNode::Continue {
            input: Box::new(input),
            continuation: PureContinuation {
                authorization_id: format!("continuation-{start}"),
                body_span: span(start, start + 10),
                suspension_span: span(start + 2, start + 5),
                result_binding: "value".to_string(),
            },
        }
    }

    fn callable(module: &str, unit_id: &str) -> CallableKey {
        CallableKey {
            module: module.to_string(),
            unit_id: unit_id.to_string(),
        }
    }

    fn anchor(
        module: &str,
        source_hash_character: char,
        slice_hash_character: char,
        start: u32,
        end: u32,
    ) -> SourceAnchor {
        SourceAnchor {
            module: module.to_string(),
            source_sha256: source_hash_character.to_string().repeat(64),
            start,
            end,
            slice_sha256: slice_hash_character.to_string().repeat(64),
        }
    }

    fn semantic_effect_key(table: &str) -> SemanticEffectKey {
        SemanticEffectKey {
            operation_kind: "database.get".to_string(),
            result_kind: "document_or_null".to_string(),
            timing: SemanticEffectTiming::Suspending,
            static_operands: std::collections::BTreeMap::from([(
                "table".to_string(),
                table.to_string(),
            )]),
            index_constraints: Vec::new(),
            limit: None,
            limit_argument_index: None,
        }
    }

    fn direct_callable_effect_plan() -> CallableEffectPlan {
        let callable = callable("messages.js", "getMessage");
        let callable_source = anchor("messages.js", 'a', 'b', 0, 200);
        let target_effect = anchor("messages.js", 'a', 'c', 40, 70);
        CallableEffectPlan {
            callable: callable.clone(),
            callable_source: callable_source.clone(),
            effect_key: semantic_effect_key("messages"),
            static_operands: vec![SemanticStaticEffectOperand {
                field: "table".to_string(),
                value: "messages".to_string(),
                target_argument_index: Some(0),
                target_provenance: anchor("messages.js", 'a', '2', 51, 60),
            }],
            dynamic_operands: vec![SemanticEffectOperand {
                value: SemanticOperand::Parameter(0),
                target_argument_index: Some(1),
                target_provenance: anchor("messages.js", 'a', 'd', 61, 65),
                projection: SemanticOperandProjection::ExactCaller {
                    consumer_provenance: anchor("messages.js", 'a', 'd', 61, 65),
                },
            }],
            provenance: SemanticEffectProvenance {
                target_callable: callable,
                target_callable_source: callable_source,
                target_callee: anchor("messages.js", 'a', 'e', 40, 50),
                capability_reference: anchor("messages.js", 'a', 'f', 40, 43),
                capability_binding: anchor("messages.js", 'a', '1', 10, 13),
                capability_name: "ctx".to_string(),
                target_effect,
                caller_callsite: None,
            },
        }
    }

    fn specialized_callable_effect_plan() -> CallableEffectPlan {
        let caller = callable("queries.js", "getVisibleMessage");
        let caller_source = anchor("queries.js", '1', '2', 0, 160);
        let caller_callsite = anchor("queries.js", '1', '3', 80, 100);
        CallableEffectPlan {
            callable: caller,
            callable_source: caller_source,
            effect_key: semantic_effect_key("messages"),
            static_operands: vec![SemanticStaticEffectOperand {
                field: "table".to_string(),
                value: "messages".to_string(),
                target_argument_index: Some(0),
                target_provenance: anchor("helpers.js", '5', 'a', 131, 136),
            }],
            dynamic_operands: vec![SemanticEffectOperand {
                value: SemanticOperand::Parameter(0),
                target_argument_index: Some(1),
                target_provenance: anchor("helpers.js", '5', '8', 140, 146),
                projection: SemanticOperandProjection::ExactCaller {
                    consumer_provenance: anchor("queries.js", '1', '4', 86, 92),
                },
            }],
            provenance: SemanticEffectProvenance {
                target_callable: callable("helpers.js", "getMessageById"),
                target_callable_source: anchor("helpers.js", '5', '6', 20, 240),
                target_effect: anchor("helpers.js", '5', '7', 120, 150),
                target_callee: anchor("helpers.js", '5', '7', 120, 130),
                capability_reference: anchor("helpers.js", '5', '9', 120, 123),
                capability_binding: anchor("helpers.js", '5', 'a', 25, 28),
                capability_name: "ctx".to_string(),
                caller_callsite: Some(caller_callsite),
            },
        }
    }

    #[test]
    fn direct_callable_effect_plan_validates() {
        let plan = validate_callable_effect_plan(direct_callable_effect_plan())
            .expect("authenticated direct effect should validate");

        assert_eq!(plan.callable.module, "messages.js");
        assert_eq!(plan.provenance.target_effect.start, 40);
        assert!(plan.provenance.caller_callsite.is_none());
    }

    #[test]
    fn imported_specialization_has_the_same_normalized_projection() {
        let direct = validate_callable_effect_plan(direct_callable_effect_plan())
            .expect("direct effect should validate");
        let specialized = validate_callable_effect_plan(specialized_callable_effect_plan())
            .expect("imported specialization should validate");

        assert_ne!(direct.callable, specialized.callable);
        assert_ne!(
            direct.provenance.target_effect,
            specialized.provenance.target_effect
        );
        assert_eq!(
            direct.normalized_projection(),
            specialized.normalized_projection()
        );
        assert!(direct.semantically_equivalent(&specialized));
    }

    #[test]
    fn specialized_plan_retains_caller_and_target_anchors() {
        let source_plan = specialized_callable_effect_plan();
        let expected_callsite = source_plan
            .provenance
            .caller_callsite
            .clone()
            .expect("specialized fixture must have a callsite");
        let expected_target_effect = source_plan.provenance.target_effect.clone();

        let validated = validate_callable_effect_plan(source_plan)
            .expect("imported specialization should validate");

        assert_eq!(
            validated.provenance.caller_callsite.as_ref(),
            Some(&expected_callsite)
        );
        assert_eq!(validated.provenance.target_effect, expected_target_effect);
        assert_ne!(expected_callsite.module, expected_target_effect.module);
    }

    #[test]
    fn target_only_runtime_operand_requires_a_specialized_target_plan() {
        let mut specialized = specialized_callable_effect_plan();
        let operand = specialized
            .dynamic_operands
            .first_mut()
            .expect("specialized fixture has no dynamic operand");
        operand.value = SemanticOperand::RuntimeInput(0);
        operand.projection = SemanticOperandProjection::TargetOnly;
        let validated = validate_callable_effect_plan(specialized)
            .expect("target-only runtime operand should retain its target-only provenance");
        assert!(validated.dynamic_operands[0].is_target_only());
        assert!(
            validated.dynamic_operands[0]
                .consumer_provenance()
                .is_none()
        );

        let mut direct = direct_callable_effect_plan();
        let operand = direct
            .dynamic_operands
            .first_mut()
            .expect("direct fixture has no dynamic operand");
        operand.value = SemanticOperand::RuntimeInput(0);
        operand.projection = SemanticOperandProjection::TargetOnly;
        let rejection = validate_callable_effect_plan(direct)
            .expect_err("direct target-only operand must not bypass caller specialization");
        assert_eq!(
            rejection.kind,
            CallableEffectPlanRejectionKind::InvalidProvenance
        );
        assert!(rejection.message.contains("target-only"));
    }

    #[test]
    fn operand_projection_domains_cannot_be_exchanged() {
        let mut target_only = specialized_callable_effect_plan();
        let operand = target_only
            .dynamic_operands
            .first_mut()
            .expect("specialized fixture has no dynamic operand");
        operand.value = SemanticOperand::RuntimeInput(0);
        operand.projection = SemanticOperandProjection::TargetOnly;

        let mut caller_projected = target_only.clone();
        let target_provenance = caller_projected.dynamic_operands[0]
            .target_provenance
            .clone();
        caller_projected.dynamic_operands[0].projection = SemanticOperandProjection::ExactCaller {
            consumer_provenance: target_provenance,
        };
        let rejection = validate_callable_effect_plan(caller_projected)
            .expect_err("target provenance must not be reused as a caller projection");
        assert_eq!(
            rejection.kind,
            CallableEffectPlanRejectionKind::InvalidProvenance
        );
        assert!(rejection.message.contains("caller-projected"));

        target_only.dynamic_operands[0].value = SemanticOperand::Parameter(0);
        let rejection = validate_callable_effect_plan(target_only)
            .expect_err("target-only operands must remain runtime inputs");
        assert_eq!(
            rejection.kind,
            CallableEffectPlanRejectionKind::InvalidProvenance
        );
        assert!(rejection.message.contains("target-only"));
    }

    #[test]
    fn specialized_plan_requires_a_caller_callsite() {
        let mut plan = specialized_callable_effect_plan();
        plan.provenance.caller_callsite = None;

        let rejection = validate_callable_effect_plan(plan)
            .expect_err("specialized effect without a callsite must be rejected");

        assert_eq!(
            rejection.kind,
            CallableEffectPlanRejectionKind::InvalidProvenance
        );
        assert!(rejection.message.contains("require a caller callsite"));
    }

    #[test]
    fn target_effect_must_be_inside_its_callable_source() {
        let mut plan = direct_callable_effect_plan();
        plan.provenance.target_effect = anchor("messages.js", 'a', '8', 180, 220);

        let rejection = validate_callable_effect_plan(plan)
            .expect_err("out-of-bounds target effect must be rejected");

        assert_eq!(
            rejection.kind,
            CallableEffectPlanRejectionKind::InvalidProvenance
        );
        assert!(rejection.message.contains("contained"));
    }

    #[test]
    fn target_callee_and_capability_binding_provenance_fail_closed() {
        let mut callee = direct_callable_effect_plan();
        callee.provenance.target_callee = anchor("messages.js", 'a', '8', 70, 80);
        let rejection = validate_callable_effect_plan(callee)
            .expect_err("callee outside the target effect must be rejected");
        assert_eq!(
            rejection.kind,
            CallableEffectPlanRejectionKind::InvalidProvenance
        );
        assert!(rejection.message.contains("target callee"));

        let mut binding = direct_callable_effect_plan();
        binding.provenance.capability_binding.module = "other.js".to_string();
        let rejection = validate_callable_effect_plan(binding)
            .expect_err("capability binding in another module must be rejected");
        assert_eq!(
            rejection.kind,
            CallableEffectPlanRejectionKind::InvalidProvenance
        );
        assert!(rejection.message.contains("Oxc binding"));
    }

    #[test]
    fn source_anchors_require_lowercase_sha256_identities() {
        let mut plan = direct_callable_effect_plan();
        plan.provenance.target_effect.source_sha256 = "A".repeat(64);

        let rejection = validate_callable_effect_plan(plan)
            .expect_err("uppercase source identity must be rejected");

        assert_eq!(
            rejection.kind,
            CallableEffectPlanRejectionKind::InvalidProvenance
        );
        assert!(rejection.message.contains("lowercase SHA-256"));
    }

    #[test]
    fn different_semantic_operation_or_table_is_not_equivalent() {
        let plan = direct_callable_effect_plan();
        let mut different_table = plan.clone();
        different_table
            .effect_key
            .static_operands
            .insert("table".to_string(), "users".to_string());
        let mut different_operation = plan.clone();
        different_operation.effect_key.operation_kind = "database.insert".to_string();

        assert!(!plan.semantically_equivalent(&different_table));
        assert!(!plan.semantically_equivalent(&different_operation));
    }

    #[test]
    fn one_effect_with_synchronous_continuation_is_startable() {
        let plan = validate_effect_plan(EffectPlanNode::Batch {
            kind: BatchKind::Mapped {
                iterator_span: span(1, 4),
                element_binding: "id".to_string(),
            },
            children: vec![continuation(effect(7, 20), 10)],
        })
        .expect("one-effect continuation should be startable");

        assert_eq!(plan.maximum_sequential_suspensions, 1);
        assert_eq!(plan.authorized_leaf_count, 1);
        let CurrentDirectBatchLayout::Mapped { child, .. } =
            current_direct_batch_layout(&plan).expect("simple mapped plan should lower")
        else {
            panic!("mapped plan changed layout");
        };
        assert_eq!(child.effect.operation_id, 7);
        assert!(child.continuation.is_some());
    }

    #[test]
    fn nested_batches_branches_and_zero_effect_paths_are_represented() {
        let plan = validate_effect_plan(EffectPlanNode::Batch {
            kind: BatchKind::Fixed,
            children: vec![EffectPlanNode::Batch {
                kind: BatchKind::Fixed,
                children: vec![EffectPlanNode::Choice {
                    discriminant_span: span(1, 2),
                    arms: vec![
                        ChoiceArm {
                            label: "present".to_string(),
                            plan: effect(1, 10),
                        },
                        ChoiceArm {
                            label: "absent".to_string(),
                            plan: EffectPlanNode::ZeroEffect {
                                result_span: Some(span(20, 24)),
                            },
                        },
                    ],
                }],
            }],
        })
        .expect("nested one-stage paths should be startable");

        assert_eq!(plan.maximum_sequential_suspensions, 1);
        assert_eq!(plan.authorized_leaf_count, 1);
        let rejection = current_direct_batch_layout(&plan)
            .expect_err("unimplemented nested lowering must fail closed");
        assert_eq!(rejection.kind, EffectPlanRejectionKind::UnsupportedLowering);
    }

    #[test]
    fn top_level_sequence_is_valid_but_two_stage_batch_child_is_resumable() {
        let sequence = EffectPlanNode::Sequence {
            steps: vec![effect(1, 10), continuation(effect(2, 30), 20)],
        };
        let top_level = validate_effect_plan(sequence.clone())
            .expect("top-level sequential effects should remain representable");
        assert_eq!(top_level.maximum_sequential_suspensions, 2);

        let rejection = validate_effect_plan(EffectPlanNode::Batch {
            kind: BatchKind::Fixed,
            children: vec![sequence],
        })
        .expect_err("two-stage batch child must remain a V8 boundary");
        assert_eq!(
            rejection.kind,
            EffectPlanRejectionKind::IndependentlyResumable
        );
        assert_eq!(rejection.path, vec![0]);
    }

    #[test]
    fn explicit_independent_resumption_is_rejected() {
        let rejection = validate_effect_plan(EffectPlanNode::Batch {
            kind: BatchKind::Fixed,
            children: vec![EffectPlanNode::IndependentlyResumable {
                reason: "second effect argument depends on the first result".to_string(),
                suspension_count: 2,
            }],
        })
        .expect_err("explicit independent resumption must remain a V8 boundary");

        assert_eq!(
            rejection.kind,
            EffectPlanRejectionKind::IndependentlyResumable
        );
        assert!(rejection.message.contains("depends on the first result"));
    }
}
