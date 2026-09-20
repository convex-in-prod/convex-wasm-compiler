use anyhow::{Result, ensure};
use oxc_semantic::{AstNodes, Scoping};
use oxc_span::GetSpan;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ParameterSummary, SourceRange, count_node_type, identifier_name, literal_string, node_type,
    span, unwrap_runtime_expression,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CapabilityPredicateTemplateCandidate {
    pub(super) parameter_index: usize,
    pub(super) member: String,
    pub(super) expression: SourceRange,
    pub(super) object: SourceRange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub(super) enum CapabilityPredicateTestCandidate {
    #[serde(rename_all = "camelCase")]
    DirectMember {
        member: String,
        object_name: String,
        object: SourceRange,
    },
    #[serde(rename_all = "camelCase")]
    DirectCall {
        callee: String,
        callee_span: SourceRange,
        argument: SourceRange,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum StructuredCompletion {
    Normal,
    Return,
    Throw,
    Unknown,
}

impl StructuredCompletion {
    pub(super) fn is_abrupt(self) -> bool {
        matches!(self, Self::Return | Self::Throw)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum CapabilityBranchKind {
    IfStatement,
    ConditionalExpression,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CapabilityBranchCandidate {
    pub(super) kind: CapabilityBranchKind,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) test: SourceRange,
    pub(super) predicate: CapabilityPredicateTestCandidate,
    pub(super) consequent: SourceRange,
    pub(super) consequent_completion: StructuredCompletion,
    pub(super) alternate: Option<SourceRange>,
    pub(super) alternate_erasable: bool,
    pub(super) trailing: Option<SourceRange>,
    pub(super) trailing_erasable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CapabilitySourceEdit {
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) replacement: &'static str,
}

fn exact_in_predicate(value: &Value) -> Option<(String, String, SourceRange, SourceRange)> {
    let value = unwrap_runtime_expression(value);
    if node_type(value).ok()? != "BinaryExpression"
        || value.get("operator").and_then(Value::as_str) != Some("in")
    {
        return None;
    }
    let member = literal_string(value.get("left")?).ok()?;
    let object = unwrap_runtime_expression(value.get("right")?);
    let object_name = identifier_name(object).ok()?;
    let (object_start, object_end) = span(object).ok()?;
    let (start, end) = span(value).ok()?;
    Some((
        member,
        object_name,
        SourceRange {
            start: object_start,
            end: object_end,
        },
        SourceRange { start, end },
    ))
}

pub(super) fn predicate_template(
    function: &Value,
    parameters: &[ParameterSummary],
) -> Option<CapabilityPredicateTemplateCandidate> {
    let function = unwrap_runtime_expression(function);
    if !matches!(
        node_type(function).ok()?,
        "ArrowFunctionExpression" | "FunctionDeclaration" | "FunctionExpression"
    ) || function.get("async").and_then(Value::as_bool) == Some(true)
        || function.get("generator").and_then(Value::as_bool) == Some(true)
        || parameters.len() != 1
    {
        return None;
    }
    let parameter_nodes = function.get("params")?.as_array()?;
    if parameter_nodes.len() != 1
        || identifier_name(&parameter_nodes[0]).ok()? != parameters[0].name
    {
        return None;
    }
    let body = function.get("body")?;
    if node_type(body).ok()? != "BlockStatement"
        || body
            .get("directives")
            .and_then(Value::as_array)
            .is_some_and(|directives| !directives.is_empty())
    {
        return None;
    }
    let statements = body.get("body")?.as_array()?;
    if statements.len() != 1 || node_type(&statements[0]).ok()? != "ReturnStatement" {
        return None;
    }
    let argument = statements[0]
        .get("argument")
        .filter(|argument| !argument.is_null())?;
    let (member, object_name, object, expression) = exact_in_predicate(argument)?;
    if object_name != parameters[0].name {
        return None;
    }
    Some(CapabilityPredicateTemplateCandidate {
        parameter_index: parameters[0].index,
        member,
        expression,
        object,
    })
}

fn predicate_test(value: &Value) -> Option<CapabilityPredicateTestCandidate> {
    let value = unwrap_runtime_expression(value);
    if let Some((member, object_name, object, _)) = exact_in_predicate(value) {
        return Some(CapabilityPredicateTestCandidate::DirectMember {
            member,
            object_name,
            object,
        });
    }
    if node_type(value).ok()? != "CallExpression"
        || value.get("optional").and_then(Value::as_bool) == Some(true)
        || count_node_type(value, "AwaitExpression") != 0
    {
        return None;
    }
    let callee = unwrap_runtime_expression(value.get("callee")?);
    let callee_name = identifier_name(callee).ok()?;
    let arguments = value.get("arguments")?.as_array()?;
    if arguments.len() != 1 || node_type(&arguments[0]).ok()? == "SpreadElement" {
        return None;
    }
    let argument = unwrap_runtime_expression(&arguments[0]);
    let (callee_start, callee_end) = span(callee).ok()?;
    let (argument_start, argument_end) = span(argument).ok()?;
    Some(CapabilityPredicateTestCandidate::DirectCall {
        callee: callee_name,
        callee_span: SourceRange {
            start: callee_start,
            end: callee_end,
        },
        argument: SourceRange {
            start: argument_start,
            end: argument_end,
        },
    })
}

fn completion(statement: &Value) -> StructuredCompletion {
    let Ok(kind) = node_type(statement) else {
        return StructuredCompletion::Unknown;
    };
    match kind {
        "ReturnStatement" => StructuredCompletion::Return,
        "ThrowStatement" => StructuredCompletion::Throw,
        "EmptyStatement" | "ExpressionStatement" | "VariableDeclaration" => {
            StructuredCompletion::Normal
        }
        "BlockStatement" => {
            let Some(statements) = statement.get("body").and_then(Value::as_array) else {
                return StructuredCompletion::Unknown;
            };
            let mut result = StructuredCompletion::Normal;
            for statement in statements {
                match completion(statement) {
                    StructuredCompletion::Normal => {}
                    abrupt @ (StructuredCompletion::Return | StructuredCompletion::Throw) => {
                        result = abrupt;
                        break;
                    }
                    StructuredCompletion::Unknown => result = StructuredCompletion::Unknown,
                }
            }
            result
        }
        _ => StructuredCompletion::Unknown,
    }
}

fn source_range(value: &Value) -> Option<SourceRange> {
    let (start, end) = span(value).ok()?;
    Some(SourceRange { start, end })
}

fn branch_candidate(
    value: &Value,
    trailing: Option<SourceRange>,
) -> Option<CapabilityBranchCandidate> {
    let kind = node_type(value).ok()?;
    match kind {
        "IfStatement" => {
            let test = value.get("test")?;
            let predicate = predicate_test(test)?;
            let consequent = value.get("consequent")?;
            let alternate = value
                .get("alternate")
                .filter(|alternate| !alternate.is_null());
            let (start, end) = span(value).ok()?;
            Some(CapabilityBranchCandidate {
                kind: CapabilityBranchKind::IfStatement,
                start,
                end,
                test: source_range(test)?,
                predicate,
                consequent: source_range(consequent)?,
                consequent_completion: completion(consequent),
                alternate: alternate.and_then(source_range),
                alternate_erasable: alternate.is_none(),
                trailing,
                trailing_erasable: false,
            })
        }
        "ConditionalExpression" => {
            let test = value.get("test")?;
            let predicate = predicate_test(test)?;
            let consequent = value.get("consequent")?;
            let alternate = value.get("alternate")?;
            let (start, end) = span(value).ok()?;
            Some(CapabilityBranchCandidate {
                kind: CapabilityBranchKind::ConditionalExpression,
                start,
                end,
                test: source_range(test)?,
                predicate,
                consequent: source_range(consequent)?,
                consequent_completion: StructuredCompletion::Normal,
                alternate: source_range(alternate),
                // Replacing an unselected expression cannot change outer binding resolution.
                alternate_erasable: true,
                trailing: None,
                trailing_erasable: true,
            })
        }
        _ => None,
    }
}

fn collect_branches(value: &Value, output: &mut Vec<CapabilityBranchCandidate>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_branches(value, output);
            }
        }
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("BlockStatement")
                && let Some(statements) = object.get("body").and_then(Value::as_array)
            {
                let trailing_end = statements
                    .last()
                    .and_then(source_range)
                    .map(|range| range.end);
                for (index, statement) in statements.iter().enumerate() {
                    let trailing = if index + 1 < statements.len() {
                        source_range(&statements[index + 1]).and_then(|first| {
                            trailing_end.map(|end| SourceRange {
                                start: first.start,
                                end,
                            })
                        })
                    } else {
                        None
                    };
                    if let Some(candidate) = branch_candidate(statement, trailing) {
                        output.push(candidate);
                    }
                    collect_branches(statement, output);
                }
                return;
            }
            if let Some(candidate) = branch_candidate(value, None) {
                output.push(candidate);
            }
            for child in object.values() {
                collect_branches(child, output);
            }
        }
        _ => {}
    }
}

pub(super) fn capability_branches(ast: &Value) -> Vec<CapabilityBranchCandidate> {
    let mut output = Vec::new();
    collect_branches(ast, &mut output);
    output.sort_by_key(|branch| (branch.start, branch.end));
    output.dedup_by_key(|branch| (branch.start, branch.end));
    output
}

struct BindingClosureIndex {
    starts: Vec<u32>,
    leaf_count: usize,
    minimum_coverage_start: Vec<u32>,
    maximum_coverage_end: Vec<u32>,
    maximum_binding_end: Vec<u32>,
}

impl BindingClosureIndex {
    fn new(scoping: &Scoping, nodes: &AstNodes<'_>) -> Self {
        let mut bindings = scoping
            .symbol_ids()
            .map(|symbol_id| {
                let binding = scoping.symbol_span(symbol_id);
                let mut coverage_start = binding.start;
                let mut coverage_end = binding.end;
                for reference in scoping.get_resolved_references(symbol_id) {
                    let reference = nodes.get_node(reference.node_id()).kind().span();
                    coverage_start = coverage_start.min(reference.start);
                    coverage_end = coverage_end.max(reference.end);
                }
                (binding.start, binding.end, coverage_start, coverage_end)
            })
            .collect::<Vec<_>>();
        bindings.sort_by_key(|binding| binding.0);
        let leaf_count = bindings.len().next_power_of_two().max(1);
        let mut minimum_coverage_start = vec![u32::MAX; leaf_count * 2];
        let mut maximum_coverage_end = vec![0; leaf_count * 2];
        let mut maximum_binding_end = vec![0; leaf_count * 2];
        let starts = bindings
            .iter()
            .enumerate()
            .map(|(index, &(start, end, coverage_start, coverage_end))| {
                let leaf = leaf_count + index;
                minimum_coverage_start[leaf] = coverage_start;
                maximum_coverage_end[leaf] = coverage_end;
                maximum_binding_end[leaf] = end;
                start
            })
            .collect();
        for index in (1..leaf_count).rev() {
            minimum_coverage_start[index] =
                minimum_coverage_start[index * 2].min(minimum_coverage_start[index * 2 + 1]);
            maximum_coverage_end[index] =
                maximum_coverage_end[index * 2].max(maximum_coverage_end[index * 2 + 1]);
            maximum_binding_end[index] =
                maximum_binding_end[index * 2].max(maximum_binding_end[index * 2 + 1]);
        }
        Self {
            starts,
            leaf_count,
            minimum_coverage_start,
            maximum_coverage_end,
            maximum_binding_end,
        }
    }

    fn range_is_closed(&self, range: &SourceRange) -> bool {
        let mut left = self.starts.partition_point(|start| *start < range.start) + self.leaf_count;
        let mut right = self.starts.partition_point(|start| *start < range.end) + self.leaf_count;
        let mut minimum_coverage_start = u32::MAX;
        let mut maximum_coverage_end = 0;
        let mut maximum_binding_end = 0;
        while left < right {
            if left % 2 == 1 {
                minimum_coverage_start =
                    minimum_coverage_start.min(self.minimum_coverage_start[left]);
                maximum_coverage_end = maximum_coverage_end.max(self.maximum_coverage_end[left]);
                maximum_binding_end = maximum_binding_end.max(self.maximum_binding_end[left]);
                left += 1;
            }
            if right % 2 == 1 {
                right -= 1;
                minimum_coverage_start =
                    minimum_coverage_start.min(self.minimum_coverage_start[right]);
                maximum_coverage_end = maximum_coverage_end.max(self.maximum_coverage_end[right]);
                maximum_binding_end = maximum_binding_end.max(self.maximum_binding_end[right]);
            }
            left /= 2;
            right /= 2;
        }
        minimum_coverage_start >= range.start
            && maximum_coverage_end <= range.end
            && maximum_binding_end <= range.end
    }
}

pub(super) fn prove_branch_erasability(
    branches: &mut [CapabilityBranchCandidate],
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
) {
    let bindings = BindingClosureIndex::new(scoping, nodes);
    for branch in branches {
        if branch.kind != CapabilityBranchKind::IfStatement {
            continue;
        }
        if let Some(alternate) = &branch.alternate {
            branch.alternate_erasable = bindings.range_is_closed(alternate);
        }
        if let Some(trailing) = &branch.trailing {
            branch.trailing_erasable = bindings.range_is_closed(trailing);
        }
    }
}

pub(super) fn edits_for_proved_true(
    branch: &CapabilityBranchCandidate,
) -> Result<Vec<CapabilitySourceEdit>> {
    let mut edits = vec![CapabilitySourceEdit {
        start: branch.test.start,
        end: branch.test.end,
        replacement: "true",
    }];
    match branch.kind {
        CapabilityBranchKind::IfStatement => {
            if branch.alternate.is_some() {
                ensure!(
                    branch.alternate_erasable,
                    "proved capability branch alternate is not safely erasable"
                );
                edits.push(CapabilitySourceEdit {
                    start: branch.consequent.end,
                    end: branch.end,
                    replacement: "",
                });
            } else if branch.consequent_completion.is_abrupt()
                && let Some(trailing) = &branch.trailing
            {
                ensure!(
                    branch.trailing_erasable,
                    "proved capability branch tail is not safely erasable"
                );
                edits.push(CapabilitySourceEdit {
                    start: trailing.start,
                    end: trailing.end,
                    replacement: "",
                });
            }
        }
        CapabilityBranchKind::ConditionalExpression => {
            let alternate = branch
                .alternate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("conditional capability branch has no alternate"))?;
            ensure!(
                branch.alternate_erasable,
                "proved capability conditional alternate is not safely erasable"
            );
            edits.push(CapabilitySourceEdit {
                start: alternate.start,
                end: alternate.end,
                replacement: "0",
            });
        }
    }
    edits.sort_by_key(|edit| (edit.start, edit.end));
    for pair in edits.windows(2) {
        ensure!(
            pair[0].end <= pair[1].start,
            "capability source edits overlap"
        );
    }
    Ok(edits)
}

fn apply_token(bytes: &mut [u8], replacement: &str) -> Result<()> {
    let first_line_bytes = bytes
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .unwrap_or(bytes.len());
    ensure!(
        replacement.len() <= first_line_bytes,
        "capability source edit replacement does not fit before the first newline"
    );
    for byte in bytes.iter_mut() {
        if !matches!(*byte, b'\r' | b'\n') {
            *byte = b' ';
        }
    }
    bytes[..replacement.len()].copy_from_slice(replacement.as_bytes());
    Ok(())
}

pub(super) fn apply_source_edits(source: &str, edits: &[CapabilitySourceEdit]) -> Result<String> {
    let mut ordered = edits.to_vec();
    ordered.sort_by_key(|edit| (edit.start, edit.end));
    for edit in &ordered {
        ensure!(edit.start < edit.end, "capability source edit is empty");
        ensure!(
            usize::try_from(edit.end)? <= source.len(),
            "capability source edit is out of range"
        );
        ensure!(
            source.is_char_boundary(usize::try_from(edit.start)?)
                && source.is_char_boundary(usize::try_from(edit.end)?),
            "capability source edit splits a UTF-8 code point"
        );
    }
    for pair in ordered.windows(2) {
        ensure!(
            pair[0].end <= pair[1].start,
            "capability source edits overlap"
        );
    }
    let mut output = source.as_bytes().to_vec();
    for edit in ordered {
        let start = usize::try_from(edit.start)?;
        let end = usize::try_from(edit.end)?;
        apply_token(&mut output[start..end], edit.replacement)?;
    }
    String::from_utf8(output).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;
    use serde_json::Value;

    use super::*;

    fn ast(source: &str) -> Value {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::ts()).parse();
        assert!(parsed.diagnostics.is_empty(), "{:#?}", parsed.diagnostics);
        serde_json::from_str(&parsed.program.to_estree_json(true, false)).unwrap()
    }

    fn branches(source: &str) -> Vec<CapabilityBranchCandidate> {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::ts()).parse();
        assert!(parsed.diagnostics.is_empty(), "{:#?}", parsed.diagnostics);
        let semantic = SemanticBuilder::new_compiler()
            .with_build_nodes(true)
            .build(&parsed.program);
        assert!(
            semantic.diagnostics.is_empty(),
            "{:#?}",
            semantic.diagnostics
        );
        let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false)).unwrap();
        let mut branches = capability_branches(&ast);
        prove_branch_erasability(
            &mut branches,
            semantic.semantic.scoping(),
            semantic.semantic.nodes(),
        );
        branches
    }

    fn function<'a>(ast: &'a Value, name: &str) -> &'a Value {
        ast.get("body")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .find(|statement| {
                statement
                    .get("id")
                    .and_then(|id| id.get("name"))
                    .and_then(Value::as_str)
                    == Some(name)
            })
            .unwrap()
    }

    #[test]
    fn recognizes_only_pure_exact_in_predicates() {
        let source = r#"
function hasDb(ctx: unknown): ctx is object { return "db" in (ctx as object); }
function extra(ctx: object) { sideEffect(); return "db" in ctx; }
async function asyncPredicate(ctx: object) { return "db" in ctx; }
"#;
        let parsed = ast(source);
        let has_db = function(&parsed, "hasDb");
        let (start, end) = span(&has_db.get("params").unwrap()[0]).unwrap();
        let parameters = vec![ParameterSummary {
            index: 0,
            name: "ctx".to_string(),
            start,
            end,
            references: Vec::new(),
            capability_projections: Vec::new(),
        }];
        assert_eq!(
            predicate_template(has_db, &parameters).map(|candidate| candidate.member),
            Some("db".to_string())
        );
        assert!(predicate_template(function(&parsed, "extra"), &parameters).is_none());
        assert!(predicate_template(function(&parsed, "asyncPredicate"), &parameters).is_none());
    }

    #[test]
    fn plans_if_conditional_and_returning_guard_edits() {
        let source = r#"
function selected(ctx, id) {
  if (hasDb(ctx)) { return ctx.db.get("docs", id); }
  return ctx.runQuery(api.docs.get, { id });
}
function direct(ctx) {
  return "db" in ctx ? ctx.db : ctx.runQuery(api.other, {});
}
"#;
        let branches = branches(source);
        assert_eq!(branches.len(), 2);
        assert_eq!(
            branches[0].consequent_completion,
            StructuredCompletion::Return
        );
        assert!(branches[0].trailing.is_some());
        let mut edits = edits_for_proved_true(&branches[0]).unwrap();
        edits.extend(edits_for_proved_true(&branches[1]).unwrap());
        let specialized = apply_source_edits(source, &edits).unwrap();
        assert_eq!(specialized.len(), source.len());
        assert_eq!(
            specialized
                .match_indices('\n')
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
            source
                .match_indices('\n')
                .map(|(index, _)| index)
                .collect::<Vec<_>>()
        );
        assert!(!specialized.contains("hasDb(ctx)"));
        assert!(!specialized.contains("runQuery"));
        assert!(specialized.contains("if (true"));
        assert!(specialized.contains("? ctx.db : 0"));
        let reparsed = ast(&specialized);
        assert_eq!(
            reparsed
                .get("body")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn rejects_unsafe_or_malformed_edits() {
        let source = "function selected(ctx) {\nvoid fallback;\nif (hasDb(ctx)) return ok;\nconst fallback = bad();\n}\n";
        let branches = branches(source);
        assert_eq!(branches.len(), 1);
        assert!(!branches[0].trailing_erasable);
        assert!(edits_for_proved_true(&branches[0]).is_err());
        assert!(
            apply_source_edits(
                source,
                &[
                    CapabilitySourceEdit {
                        start: 0,
                        end: 2,
                        replacement: "true",
                    },
                    CapabilitySourceEdit {
                        start: 1,
                        end: 3,
                        replacement: ";",
                    },
                ],
            )
            .is_err()
        );
        assert!(
            apply_source_edits(
                source,
                &[CapabilitySourceEdit {
                    start: u32::try_from(source.len()).unwrap(),
                    end: u32::try_from(source.len() + 1).unwrap(),
                    replacement: ";",
                }],
            )
            .is_err()
        );
    }

    #[test]
    fn neutral_edits_fit_minimal_statement_and_expression_spans() -> Result<()> {
        let source = r#"
function statement(ctx) { if (hasDb(ctx)) return 1; else ; }
function expression(ctx) { return hasDb(ctx) ? 1 : 0; }
"#;
        let branches = branches(source);
        assert_eq!(branches.len(), 2);
        let edits = branches
            .iter()
            .map(edits_for_proved_true)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let specialized = apply_source_edits(source, &edits)?;
        assert_eq!(specialized.len(), source.len());
        let _ = ast(&specialized);
        Ok(())
    }

    #[test]
    fn sequential_guards_have_linear_summary_size() {
        let mut source = "function selected(ctx) {\n".to_string();
        for index in 0..4096 {
            source.push_str(&format!("if (hasDb(ctx)) return {index};\n"));
        }
        source.push_str("return 0;\n}\n");
        let branches = branches(&source);
        assert_eq!(branches.len(), 4096);
        assert!(branches.iter().all(|branch| branch.trailing.is_some()));
        assert!(serde_json::to_vec(&branches).unwrap().len() < source.len() * 16);
    }

    #[test]
    fn runtime_typescript_declarations_are_not_erasable_tails() {
        let source = r#"
function selected(ctx) {
  void RuntimeValue;
  if (hasDb(ctx)) return 1;
  enum RuntimeValue { A }
}
"#;
        let branches = branches(source);
        assert_eq!(branches.len(), 1);
        assert!(!branches[0].trailing_erasable);
        assert!(edits_for_proved_true(&branches[0]).is_err());
    }
}
