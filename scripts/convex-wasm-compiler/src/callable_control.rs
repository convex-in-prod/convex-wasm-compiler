use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Context, Result};
use oxc_ast::{AstKind, ast::Expression};
use oxc_cfg::{
    ControlFlowGraph, EdgeType, ErrorEdgeKind, InstructionKind, IterationInstructionKind,
    ReturnInstructionKind, graph::visit::EdgeRef,
};
use oxc_semantic::AstNodes;
use oxc_span::{GetSpan, Span};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum CallableControlInstructionKind {
    Statement,
    Condition,
    Return,
    ReturnUndefined,
    Throw,
    Break,
    Continue,
    IterateIn,
    IterateOf,
    ImplicitReturn,
    Unreachable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableControlInstructionCandidate {
    pub(super) kind: CallableControlInstructionKind,
    pub(super) start: Option<u32>,
    pub(super) end: Option<u32>,
    #[serde(default)]
    pub(super) value_start: Option<u32>,
    #[serde(default)]
    pub(super) value_end: Option<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum CallableControlEdgeKind {
    Normal,
    Jump,
    Backedge,
    Finalize,
    ImplicitError,
    ExplicitError,
    Join,
    Unreachable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableControlEdgeCandidate {
    pub(super) target: u32,
    pub(super) kind: CallableControlEdgeKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableControlBlockCandidate {
    pub(super) id: u32,
    pub(super) unreachable: bool,
    pub(super) instructions: Vec<CallableControlInstructionCandidate>,
    pub(super) successors: Vec<CallableControlEdgeCandidate>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum CallableControlPointKind {
    Await,
    Call,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableControlPointCandidate {
    pub(super) kind: CallableControlPointKind,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) block: u32,
    #[serde(default)]
    pub(super) value_start: Option<u32>,
    #[serde(default)]
    pub(super) value_end: Option<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum CallableIntraBlockOrder {
    Unresolved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CallableControlSkeletonCandidate {
    pub(super) callable_start: u32,
    pub(super) callable_end: u32,
    pub(super) entry_block: u32,
    pub(super) blocks: Vec<CallableControlBlockCandidate>,
    pub(super) points: Vec<CallableControlPointCandidate>,
    pub(super) intra_block_order: CallableIntraBlockOrder,
}

fn instruction_kind(kind: InstructionKind) -> CallableControlInstructionKind {
    match kind {
        InstructionKind::Statement => CallableControlInstructionKind::Statement,
        InstructionKind::Condition => CallableControlInstructionKind::Condition,
        InstructionKind::Return(ReturnInstructionKind::NotImplicitUndefined) => {
            CallableControlInstructionKind::Return
        }
        InstructionKind::Return(ReturnInstructionKind::ImplicitUndefined) => {
            CallableControlInstructionKind::ReturnUndefined
        }
        InstructionKind::Throw => CallableControlInstructionKind::Throw,
        InstructionKind::Break(_) => CallableControlInstructionKind::Break,
        InstructionKind::Continue(_) => CallableControlInstructionKind::Continue,
        InstructionKind::Iteration(IterationInstructionKind::In) => {
            CallableControlInstructionKind::IterateIn
        }
        InstructionKind::Iteration(IterationInstructionKind::Of) => {
            CallableControlInstructionKind::IterateOf
        }
        InstructionKind::ImplicitReturn => CallableControlInstructionKind::ImplicitReturn,
        InstructionKind::Unreachable => CallableControlInstructionKind::Unreachable,
    }
}

fn runtime_expression_span(mut expression: &Expression<'_>) -> Span {
    loop {
        expression = match expression {
            Expression::ParenthesizedExpression(wrapper) => &wrapper.expression,
            Expression::TSAsExpression(wrapper) => &wrapper.expression,
            Expression::TSSatisfiesExpression(wrapper) => &wrapper.expression,
            Expression::TSTypeAssertion(wrapper) => &wrapper.expression,
            Expression::TSNonNullExpression(wrapper) => &wrapper.expression,
            Expression::TSInstantiationExpression(wrapper) => &wrapper.expression,
            _ => return expression.span(),
        };
    }
}

fn edge_kind(kind: &EdgeType) -> Option<CallableControlEdgeKind> {
    match kind {
        EdgeType::Normal => Some(CallableControlEdgeKind::Normal),
        EdgeType::Jump => Some(CallableControlEdgeKind::Jump),
        EdgeType::Backedge => Some(CallableControlEdgeKind::Backedge),
        EdgeType::Finalize => Some(CallableControlEdgeKind::Finalize),
        EdgeType::Error(ErrorEdgeKind::Implicit) => Some(CallableControlEdgeKind::ImplicitError),
        EdgeType::Error(ErrorEdgeKind::Explicit) => Some(CallableControlEdgeKind::ExplicitError),
        EdgeType::Join => Some(CallableControlEdgeKind::Join),
        EdgeType::Unreachable => Some(CallableControlEdgeKind::Unreachable),
        EdgeType::NewFunction => None,
    }
}

fn reachable_function_blocks(
    cfg: &ControlFlowGraph,
    entry: oxc_cfg::BlockNodeId,
) -> BTreeSet<oxc_cfg::BlockNodeId> {
    let mut reachable = BTreeSet::new();
    let mut pending = VecDeque::from([entry]);
    while let Some(block) = pending.pop_front() {
        if !reachable.insert(block) {
            continue;
        }
        for edge in cfg.graph.edges(block) {
            if edge_kind(edge.weight()).is_some() {
                pending.push_back(edge.target());
            }
        }
    }
    reachable
}

fn callable_block(
    nodes: &AstNodes<'_>,
    cfg: &ControlFlowGraph,
    block: oxc_cfg::BlockNodeId,
    function_blocks: &BTreeSet<oxc_cfg::BlockNodeId>,
    local_ids: &BTreeMap<oxc_cfg::BlockNodeId, u32>,
) -> Result<CallableControlBlockCandidate> {
    let basic_block = cfg.basic_block(block);
    let mut instructions = Vec::with_capacity(basic_block.instructions().len());
    for instruction in basic_block.instructions() {
        let ast_kind = instruction
            .node_id
            .map(|node_id| nodes.get_node(node_id).kind());
        let source = ast_kind.as_ref().map(|kind| kind.span());
        let value = ast_kind.as_ref().and_then(|kind| match kind {
            AstKind::ReturnStatement(statement) => {
                statement.argument.as_ref().map(runtime_expression_span)
            }
            _ => None,
        });
        instructions.push(CallableControlInstructionCandidate {
            kind: instruction_kind(instruction.kind),
            start: source.map(|span| span.start),
            end: source.map(|span| span.end),
            value_start: value.map(|span| span.start),
            value_end: value.map(|span| span.end),
        });
    }
    let mut successors = cfg
        .graph
        .edges(block)
        .filter_map(|edge| {
            let kind = edge_kind(edge.weight())?;
            function_blocks
                .contains(&edge.target())
                .then_some((edge.target(), kind))
        })
        .map(|(target, kind)| {
            Ok(CallableControlEdgeCandidate {
                target: *local_ids
                    .get(&target)
                    .context("Oxc callable successor lost its local block identity")?,
                kind,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    successors.sort_by_key(|edge| (edge.target, edge.kind as u8));
    Ok(CallableControlBlockCandidate {
        id: *local_ids
            .get(&block)
            .context("Oxc callable block lost its local identity")?,
        unreachable: basic_block.is_unreachable(),
        instructions,
        successors,
    })
}

pub(super) fn collect_callable_control_skeletons(
    nodes: &AstNodes<'_>,
    cfg: &ControlFlowGraph,
) -> Result<Vec<CallableControlSkeletonCandidate>> {
    let mut points_by_block = BTreeMap::new();
    for point in nodes {
        let (kind, value) = match point.kind() {
            AstKind::AwaitExpression(expression) => (
                CallableControlPointKind::Await,
                Some(runtime_expression_span(&expression.argument)),
            ),
            AstKind::CallExpression(_) => (CallableControlPointKind::Call, None),
            _ => continue,
        };
        let source = point.kind().span();
        points_by_block
            .entry(nodes.cfg_id(point.id()))
            .or_insert_with(Vec::new)
            .push((kind, source.start, source.end, value));
    }
    for points in points_by_block.values_mut() {
        points.sort_by_key(|(kind, start, end, _)| (*start, *end, *kind as u8));
    }

    let mut callables = BTreeMap::new();
    for node in nodes {
        if !matches!(
            node.kind(),
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            continue;
        }
        let source = node.kind().span();
        let entry = nodes.cfg_id(node.id());
        let function_blocks = reachable_function_blocks(cfg, entry);
        let local_ids = function_blocks
            .iter()
            .enumerate()
            .map(|(local, block)| Ok((*block, u32::try_from(local)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut blocks = function_blocks
            .iter()
            .map(|block| callable_block(nodes, cfg, *block, &function_blocks, &local_ids))
            .collect::<Result<Vec<_>>>()?;
        blocks.sort_by_key(|block| block.id);
        let mut points = function_blocks
            .iter()
            .flat_map(|block| {
                points_by_block
                    .get(block)
                    .into_iter()
                    .flatten()
                    .map(move |(kind, start, end, value)| (*block, *kind, *start, *end, *value))
            })
            .map(|(block, kind, start, end, value)| {
                Ok(CallableControlPointCandidate {
                    kind,
                    start,
                    end,
                    block: *local_ids
                        .get(&block)
                        .context("Oxc callable control point lost its local block identity")?,
                    value_start: value.map(|span| span.start),
                    value_end: value.map(|span| span.end),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        points.sort_by_key(|point| (point.block, point.start, point.end, point.kind as u8));
        let candidate = CallableControlSkeletonCandidate {
            callable_start: source.start,
            callable_end: source.end,
            entry_block: *local_ids
                .get(&entry)
                .context("Oxc callable entry lost its local block identity")?,
            blocks,
            points,
            // Oxc identifies the containing basic block but does not prove JavaScript evaluation
            // order among multiple suspension or call points within that block.
            intra_block_order: CallableIntraBlockOrder::Unresolved,
        };
        anyhow::ensure!(
            callables
                .insert((source.start, source.end), candidate)
                .is_none(),
            "Oxc callable source span maps to multiple control-flow entries"
        );
    }
    let output = callables.into_values().collect::<Vec<_>>();
    for candidate in &output {
        anyhow::ensure!(
            candidate
                .blocks
                .iter()
                .any(|block| block.id == candidate.entry_block),
            "Oxc callable control skeleton lost its entry block"
        );
        for block in &candidate.blocks {
            for edge in &block.successors {
                anyhow::ensure!(
                    candidate
                        .blocks
                        .iter()
                        .any(|target| target.id == edge.target),
                    "Oxc callable control skeleton has an external successor"
                );
            }
        }
        for point in &candidate.points {
            anyhow::ensure!(
                candidate.blocks.iter().any(|block| block.id == point.block),
                "Oxc callable control point is outside its callable graph"
            );
        }
    }
    Ok(output)
}

pub(super) fn require_cfg<'a>(cfg: Option<&'a ControlFlowGraph>) -> Result<&'a ControlFlowGraph> {
    cfg.context("Oxc semantic analysis did not produce the requested control-flow graph")
}
