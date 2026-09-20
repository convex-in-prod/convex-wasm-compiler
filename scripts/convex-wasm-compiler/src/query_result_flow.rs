use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, Scoping, SemanticBuilder};
use oxc_span::{GetSpan, SourceType};
use serde_json::Value;

use super::effect_plan::SourceAnchor;
use super::query_materialization::AuthorizedQueryValueIndex;
use super::query_values::CallableQueryConsumerKind;
use super::{
    ReachableUnit, ReferenceOccurrence, identifier_name, node_type, span,
    unwrap_runtime_expression, unwrap_transparent_expression,
};

type BindingKey = (u32, u32);
type SourceSpan = (u32, u32);
type GlobalReference = (String, u32, u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedQueryResultSeed {
    pub(super) authorization_id: String,
    pub(super) generated_unit_binding: String,
    pub(super) consumer: SourceAnchor,
    pub(super) kind: CallableQueryConsumerKind,
    pub(super) table: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct ProvedQueryDocumentProperty {
    pub(super) table: String,
    pub(super) property: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ProvedQueryResultFlow {
    array_expressions: BTreeSet<SourceSpan>,
    host_array_expressions: BTreeSet<SourceSpan>,
    document_properties: BTreeSet<ProvedQueryDocumentProperty>,
}

impl ProvedQueryResultFlow {
    pub(super) fn array_expressions(&self) -> &BTreeSet<SourceSpan> {
        &self.array_expressions
    }

    pub(super) fn host_array_expressions(&self) -> &BTreeSet<SourceSpan> {
        &self.host_array_expressions
    }

    pub(super) fn document_properties(&self) -> impl Iterator<Item = &ProvedQueryDocumentProperty> {
        self.document_properties.iter()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct QueryResultFlowRejection {
    pub(super) consumer: SourceAnchor,
    pub(super) reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum QueryResultFlowOutcome {
    Proved(ProvedQueryResultFlow),
    Rejected(QueryResultFlowRejection),
}

pub(super) fn authenticated_query_result_seeds(
    index: &AuthorizedQueryValueIndex,
    reachable: &BTreeMap<String, ReachableUnit>,
) -> Result<Vec<AuthenticatedQueryResultSeed>> {
    index
        .result_consumers()
        .map(|consumer| {
            let unit = reachable
                .get(consumer.owner_unit_id)
                .context("authorized query-result owner unit disappeared")?;
            ensure!(
                unit.module == consumer.consumer.module
                    && consumer.consumer.start >= unit.start
                    && consumer.consumer.end <= unit.end,
                "authorized query-result consumer escaped its owner unit"
            );
            Ok(AuthenticatedQueryResultSeed {
                authorization_id: consumer.authorization_id.to_string(),
                generated_unit_binding: if unit.kind == "handler" {
                    "__convexWasmHandler".to_string()
                } else {
                    unit.name.clone()
                },
                consumer: consumer.consumer.clone(),
                kind: consumer.kind,
                table: consumer.table.to_string(),
            })
        })
        .collect()
}

#[derive(Clone, Debug)]
struct BindingFact {
    name: String,
    references: Vec<ReferenceOccurrence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResultProvenance {
    Document(BTreeSet<String>),
    Array(Option<Box<ResultProvenance>>),
    Tuple(Vec<Option<ResultProvenance>>),
    Object(BTreeMap<String, ResultProvenance>),
}

impl ResultProvenance {
    fn ordinary_array() -> Self {
        Self::Array(None)
    }

    fn array_from(element: Self) -> Self {
        Self::Array(Some(Box::new(element)))
    }

    fn is_array(&self) -> bool {
        matches!(self, Self::Array(_) | Self::Tuple(_))
    }

    fn elements(&self) -> Option<Self> {
        match self {
            Self::Array(element) => element.as_deref().cloned(),
            Self::Tuple(elements) => {
                let mut merged: Option<Self> = None;
                for element in elements.iter().flatten() {
                    merged = Some(match merged {
                        Some(current) => current.merge(element)?,
                        None => element.clone(),
                    });
                }
                merged
            }
            _ => None,
        }
    }

    fn flattened(&self) -> Option<Self> {
        let element = self.elements()?;
        if element.is_array() {
            Some(Self::Array(element.elements().map(Box::new)))
        } else {
            Some(Self::ordinary_array())
        }
    }

    fn property(&self, property: &str) -> Option<Self> {
        match self {
            Self::Object(properties) => properties.get(property).cloned(),
            Self::Tuple(elements) => property
                .parse::<usize>()
                .ok()
                .and_then(|index| elements.get(index))
                .cloned()
                .flatten(),
            _ => None,
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            Self::Document(_) => "document",
            Self::Array(_) | Self::Tuple(_) => "array",
            Self::Object(_) => "object container",
        }
    }

    fn merge(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Document(left), Self::Document(right)) => {
                let mut tables = left.clone();
                tables.extend(right.iter().cloned());
                Some(Self::Document(tables))
            }
            (Self::Array(left), Self::Array(right)) => Some(Self::Array(merge_optional_boxed(
                left.as_deref(),
                right.as_deref(),
            )?)),
            (Self::Tuple(left), Self::Tuple(right)) if left.len() == right.len() => {
                Some(Self::Tuple(
                    left.iter()
                        .zip(right)
                        .map(|(left, right)| merge_optional(left.as_ref(), right.as_ref()))
                        .collect::<Option<Vec<_>>>()?,
                ))
            }
            (left, right) if left.is_array() && right.is_array() => Some(Self::Array(
                merge_optional_boxed(left.elements().as_ref(), right.elements().as_ref())?,
            )),
            (Self::Object(left), Self::Object(right)) => {
                let mut properties = left.clone();
                for (property, provenance) in right {
                    match properties.get_mut(property) {
                        Some(existing) => *existing = existing.merge(provenance)?,
                        None => {
                            properties.insert(property.clone(), provenance.clone());
                        }
                    }
                }
                Some(Self::Object(properties))
            }
            _ => None,
        }
    }
}

fn merge_optional(
    left: Option<&ResultProvenance>,
    right: Option<&ResultProvenance>,
) -> Option<Option<ResultProvenance>> {
    Some(match (left, right) {
        (Some(left), Some(right)) => Some(left.merge(right)?),
        (Some(value), None) | (None, Some(value)) => Some(value.clone()),
        (None, None) => None,
    })
}

fn merge_optional_boxed(
    left: Option<&ResultProvenance>,
    right: Option<&ResultProvenance>,
) -> Option<Option<Box<ResultProvenance>>> {
    merge_optional(left, right).map(|value| value.map(Box::new))
}

#[derive(Clone)]
struct BoundSeed {
    kind: CallableQueryConsumerKind,
    site: SourceSpan,
    tables: BTreeSet<String>,
}

#[derive(Clone, Copy)]
struct FunctionNode<'a> {
    binding: Option<BindingKey>,
    source: &'a Value,
}

fn semantic_binding_facts(
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
) -> Result<(
    BTreeMap<BindingKey, BindingFact>,
    BTreeMap<SourceSpan, BindingKey>,
)> {
    let mut bindings = BTreeMap::new();
    let mut references = BTreeMap::new();
    for symbol_id in scoping.symbol_ids() {
        let declaration = scoping.symbol_span(symbol_id);
        let key = (declaration.start, declaration.end);
        let name = scoping.symbol_name(symbol_id).to_string();
        let mut binding_references = Vec::new();
        for reference in scoping.get_resolved_references(symbol_id) {
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let reference_span = nodes.get_node(reference.node_id()).kind().span();
            let occurrence = ReferenceOccurrence {
                name: name.clone(),
                start: reference_span.start,
                end: reference_span.end,
                read: flags.is_read(),
                write: flags.is_write(),
            };
            ensure!(
                references
                    .insert((occurrence.start, occurrence.end), key)
                    .is_none(),
                "query-result reference resolved to multiple Oxc symbols"
            );
            binding_references.push(occurrence);
        }
        binding_references.sort_by_key(|reference| (reference.start, reference.end));
        ensure!(
            bindings
                .insert(
                    key,
                    BindingFact {
                        name,
                        references: binding_references,
                    },
                )
                .is_none(),
            "query-result declaration resolved to multiple Oxc symbols"
        );
    }
    Ok((bindings, references))
}

fn semantic_global_references(
    scoping: &Scoping,
    nodes: &AstNodes<'_>,
) -> BTreeSet<GlobalReference> {
    let mut references = BTreeSet::new();
    for (name, reference_ids) in scoping.root_unresolved_references() {
        for reference_id in reference_ids {
            let reference = scoping.get_reference(*reference_id);
            let flags = reference.flags();
            if !flags.is_value() || flags.is_value_as_type() {
                continue;
            }
            let span = nodes.get_node(reference.node_id()).kind().span();
            references.insert((name.to_string(), span.start, span.end));
        }
    }
    references
}

fn top_level_function_spans(ast: &Value) -> Result<BTreeMap<String, SourceSpan>> {
    ensure!(
        node_type(ast)? == "Program",
        "query-result proof root is not a Program"
    );
    let mut functions = BTreeMap::new();
    for statement in ast
        .get("body")
        .and_then(Value::as_array)
        .context("query-result Program has no body")?
    {
        if node_type(statement).ok() == Some("FunctionDeclaration")
            && let Some(identifier) = statement.get("id")
        {
            let name = identifier_name(identifier)?;
            ensure!(
                functions.insert(name.clone(), span(statement)?).is_none(),
                "generated query-result function {name} is duplicated"
            );
            continue;
        }
        if node_type(statement).ok() != Some("VariableDeclaration") {
            continue;
        }
        for declaration in statement
            .get("declarations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(identifier), Some(initializer)) =
                (declaration.get("id"), declaration.get("init"))
            else {
                continue;
            };
            let initializer = unwrap_transparent_expression(initializer);
            if !matches!(
                node_type(initializer).ok(),
                Some("ArrowFunctionExpression" | "FunctionExpression")
            ) {
                continue;
            }
            let name = identifier_name(identifier)?;
            ensure!(
                functions.insert(name.clone(), span(initializer)?).is_none(),
                "generated query-result function {name} is duplicated"
            );
        }
    }
    Ok(functions)
}

fn collect_candidate_sites(
    value: &Value,
    kind: CallableQueryConsumerKind,
    output: &mut Vec<SourceSpan>,
) {
    match value {
        Value::Object(object) => {
            let matches = if kind == CallableQueryConsumerKind::Stream {
                object.get("type").and_then(Value::as_str) == Some("ForOfStatement")
                    && object.get("await").and_then(Value::as_bool) == Some(true)
            } else {
                object.get("type").and_then(Value::as_str) == Some("CallExpression")
                    && super::call_method_name(value).as_deref() == Some(kind.terminal())
            };
            if matches && let Ok(site) = span(value) {
                output.push(site);
            }
            for child in object.values() {
                collect_candidate_sites(child, kind, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_candidate_sites(child, kind, output);
            }
        }
        _ => {}
    }
}

fn bind_seeds(
    ast: &Value,
    seeds: &[AuthenticatedQueryResultSeed],
) -> Result<Result<Vec<BoundSeed>, QueryResultFlowRejection>> {
    let functions = top_level_function_spans(ast)?;
    let mut groups =
        BTreeMap::<(String, CallableQueryConsumerKind), Vec<&AuthenticatedQueryResultSeed>>::new();
    for seed in seeds {
        groups
            .entry((seed.generated_unit_binding.clone(), seed.kind))
            .or_default()
            .push(seed);
    }
    let mut bound = Vec::new();
    for ((unit_name, kind), grouped_seeds) in groups {
        let mut consumer_seeds =
            BTreeMap::<(String, String, u32, u32, String), (SourceAnchor, BTreeSet<String>)>::new();
        for seed in grouped_seeds {
            let key = (
                seed.consumer.module.clone(),
                seed.consumer.source_sha256.clone(),
                seed.consumer.start,
                seed.consumer.end,
                seed.consumer.slice_sha256.clone(),
            );
            let (_, tables) = consumer_seeds
                .entry(key)
                .or_insert_with(|| (seed.consumer.clone(), BTreeSet::new()));
            tables.insert(seed.table.clone());
        }
        let grouped_seeds = consumer_seeds.into_values().collect::<Vec<_>>();
        let Some(&(function_start, function_end)) = functions.get(&unit_name) else {
            return Ok(Err(QueryResultFlowRejection {
                consumer: grouped_seeds[0].0.clone(),
                reason: "authenticated query-result owner did not bind to one generated function"
                    .to_string(),
            }));
        };
        let Some(function) = find_node(ast, (function_start, function_end), None) else {
            return Ok(Err(QueryResultFlowRejection {
                consumer: grouped_seeds[0].0.clone(),
                reason: "generated query-result owner function disappeared".to_string(),
            }));
        };
        let mut sites = Vec::new();
        collect_candidate_sites(function, kind, &mut sites);
        sites.sort_unstable();
        if sites.len() != grouped_seeds.len() {
            return Ok(Err(QueryResultFlowRejection {
                consumer: grouped_seeds[0].0.clone(),
                reason: format!(
                    "authenticated {} result sites bound to {} generated sites instead of {}",
                    kind.terminal(),
                    sites.len(),
                    grouped_seeds.len()
                ),
            }));
        }
        bound.extend(
            grouped_seeds
                .into_iter()
                .zip(sites)
                .map(|((_consumer, tables), site)| BoundSeed { kind, site, tables }),
        );
    }
    bound.sort_by_key(|seed| seed.site);
    Ok(Ok(bound))
}

fn find_node<'a>(
    value: &'a Value,
    expected: SourceSpan,
    expected_kind: Option<&str>,
) -> Option<&'a Value> {
    match value {
        Value::Object(object) => {
            if span(value).ok() == Some(expected)
                && expected_kind.is_none_or(|kind| node_type(value).ok() == Some(kind))
            {
                return Some(value);
            }
            object
                .values()
                .find_map(|child| find_node(child, expected, expected_kind))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|child| find_node(child, expected, expected_kind)),
        _ => None,
    }
}

fn collect_functions<'a>(value: &'a Value, output: &mut Vec<FunctionNode<'a>>) {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("FunctionDeclaration" | "FunctionExpression" | "ArrowFunctionExpression")
            ) {
                let binding = object
                    .get("id")
                    .filter(|identifier| !identifier.is_null())
                    .and_then(|identifier| span(identifier).ok());
                output.push(FunctionNode {
                    binding,
                    source: value,
                });
            }
            if object.get("type").and_then(Value::as_str) == Some("VariableDeclarator")
                && let (Some(identifier), Some(initializer)) =
                    (object.get("id"), object.get("init"))
                && let initializer = unwrap_transparent_expression(initializer)
                && matches!(
                    node_type(initializer).ok(),
                    Some("FunctionExpression" | "ArrowFunctionExpression")
                )
                && let Ok(binding) = span(identifier)
            {
                output.push(FunctionNode {
                    binding: Some(binding),
                    source: initializer,
                });
            }
            for child in object.values() {
                collect_functions(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_functions(child, output);
            }
        }
        _ => {}
    }
}

fn function_parameters(function: &Value) -> Vec<BindingKey> {
    function
        .get("params")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|parameter| {
            let parameter = unwrap_runtime_expression(parameter);
            (node_type(parameter).ok() == Some("Identifier"))
                .then(|| span(parameter).ok())
                .flatten()
        })
        .collect()
}

fn collect_function_returns<'a>(value: &'a Value, root: bool, output: &mut Vec<Option<&'a Value>>) {
    match value {
        Value::Object(object) => {
            let kind = object.get("type").and_then(Value::as_str);
            if !root
                && matches!(
                    kind,
                    Some("FunctionDeclaration" | "FunctionExpression" | "ArrowFunctionExpression")
                )
            {
                return;
            }
            if kind == Some("ReturnStatement") {
                output.push(
                    object
                        .get("argument")
                        .filter(|argument| !argument.is_null()),
                );
                return;
            }
            if root
                && kind == Some("ArrowFunctionExpression")
                && let Some(body) = object.get("body")
                && node_type(body).ok() != Some("BlockStatement")
            {
                output.push(Some(body));
                return;
            }
            for child in object.values() {
                collect_function_returns(child, false, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_function_returns(child, root, output);
            }
        }
        _ => {}
    }
}

fn transparent_expression(value: &Value) -> &Value {
    let mut value = value;
    loop {
        let next = match node_type(value).ok() {
            Some("AwaitExpression") => value.get("argument"),
            _ => {
                let unwrapped = unwrap_runtime_expression(value);
                (!std::ptr::eq(unwrapped, value)).then_some(unwrapped)
            }
        };
        let Some(next) = next else {
            return value;
        };
        value = next;
    }
}

fn member_parts(value: &Value) -> Option<(&Value, String, bool, bool)> {
    let value = unwrap_runtime_expression(value);
    if node_type(value).ok()? != "MemberExpression" {
        return None;
    }
    let computed = value.get("computed").and_then(Value::as_bool) == Some(true);
    let optional = value.get("optional").and_then(Value::as_bool) == Some(true);
    let receiver = value.get("object").map(transparent_expression)?;
    let property = if computed {
        let property = value.get("property").map(transparent_expression)?;
        match node_type(property).ok()? {
            "Literal" => property.get("value").and_then(|value| match value {
                Value::String(value) => Some(value.clone()),
                Value::Number(value) => Some(value.to_string()),
                _ => None,
            })?,
            _ => return None,
        }
    } else {
        value
            .get("property")
            .and_then(|property| identifier_name(property).ok())?
    };
    Some((receiver, property, computed, optional))
}

struct FlowState<'a> {
    seed_expressions: BTreeMap<SourceSpan, ResultProvenance>,
    bindings: &'a BTreeMap<BindingKey, BindingFact>,
    reference_bindings: &'a BTreeMap<SourceSpan, BindingKey>,
    global_references: &'a BTreeSet<GlobalReference>,
    binding_provenance: BTreeMap<BindingKey, ResultProvenance>,
    assignment_results: BTreeMap<SourceSpan, ResultProvenance>,
    function_returns: BTreeMap<BindingKey, ResultProvenance>,
    local_map_bindings: BTreeSet<BindingKey>,
    local_map_values: BTreeMap<BindingKey, ResultProvenance>,
    consumed_references: BTreeSet<SourceSpan>,
    consumed_write_references: BTreeSet<SourceSpan>,
    consumed_seed_expressions: BTreeSet<SourceSpan>,
    array_expressions: BTreeSet<SourceSpan>,
    document_properties: BTreeSet<ProvedQueryDocumentProperty>,
    rejection: Option<String>,
}

impl FlowState<'_> {
    fn is_global_reference(&self, value: &Value, name: &str) -> bool {
        identifier_name(value).ok().as_deref() == Some(name)
            && span(value).ok().is_some_and(|(start, end)| {
                self.global_references
                    .contains(&(name.to_string(), start, end))
            })
    }

    fn reference_provenance(&self, value: &Value) -> Option<ResultProvenance> {
        let value = transparent_expression(value);
        let reference = span(value).ok()?;
        let binding = self.reference_bindings.get(&reference)?;
        self.binding_provenance.get(binding).cloned()
    }

    fn expression_provenance(&self, value: &Value) -> Option<ResultProvenance> {
        let raw_span = span(value).ok();
        if let Some(provenance) = raw_span.and_then(|site| self.seed_expressions.get(&site)) {
            return Some(provenance.clone());
        }
        if let Some(provenance) = raw_span.and_then(|site| self.assignment_results.get(&site)) {
            return Some(provenance.clone());
        }
        let value = transparent_expression(value);
        let value_span = span(value).ok();
        if let Some(provenance) = value_span.and_then(|site| self.seed_expressions.get(&site)) {
            return Some(provenance.clone());
        }
        if let Some(provenance) = value_span.and_then(|site| self.assignment_results.get(&site)) {
            return Some(provenance.clone());
        }
        match node_type(value).ok()? {
            "Identifier" => self.reference_provenance(value),
            "ConditionalExpression" => {
                let consequent = value.get("consequent")?;
                let alternate = value.get("alternate")?;
                merge_optional(
                    self.expression_provenance(consequent).as_ref(),
                    self.expression_provenance(alternate).as_ref(),
                )?
            }
            "ArrayExpression" => {
                let mut exact = Vec::new();
                let mut spread_element: Option<ResultProvenance> = None;
                for element in value.get("elements")?.as_array()? {
                    if element.is_null() {
                        exact.push(None);
                        continue;
                    }
                    if node_type(element).ok() == Some("SpreadElement") {
                        let spread = self.expression_provenance(element.get("argument")?)?;
                        let element = spread.elements();
                        spread_element = match (spread_element, element) {
                            (Some(current), Some(element)) => Some(current.merge(&element)?),
                            (None, element) => element,
                            (current, None) => current,
                        };
                        continue;
                    }
                    exact.push(self.expression_provenance(element));
                }
                if spread_element.is_some() {
                    let mut element = spread_element;
                    for value in exact.iter().flatten() {
                        element = Some(match element {
                            Some(current) => current.merge(value)?,
                            None => value.clone(),
                        });
                    }
                    element.map(ResultProvenance::array_from)
                } else if exact.iter().any(Option::is_some) {
                    Some(ResultProvenance::Tuple(exact))
                } else {
                    None
                }
            }
            "ObjectExpression" => {
                let mut properties = BTreeMap::<String, ResultProvenance>::new();
                for property in value.get("properties")?.as_array()? {
                    if node_type(property).ok() == Some("SpreadElement") {
                        let Some(ResultProvenance::Object(spread)) =
                            self.expression_provenance(property.get("argument")?)
                        else {
                            continue;
                        };
                        for (key, value) in spread {
                            match properties.get_mut(&key) {
                                Some(existing) => *existing = existing.merge(&value)?,
                                None => {
                                    properties.insert(key, value);
                                }
                            }
                        }
                        continue;
                    }
                    if node_type(property).ok() != Some("Property")
                        || property.get("computed").and_then(Value::as_bool) == Some(true)
                        || property.get("kind").and_then(Value::as_str) != Some("init")
                    {
                        continue;
                    }
                    let key = property.get("key").and_then(|key| {
                        identifier_name(key).ok().or_else(|| {
                            key.get("value").and_then(Value::as_str).map(str::to_string)
                        })
                    })?;
                    if let Some(provenance) = property
                        .get("value")
                        .and_then(|value| self.expression_provenance(value))
                    {
                        properties.insert(key, provenance);
                    }
                }
                (!properties.is_empty()).then_some(ResultProvenance::Object(properties))
            }
            "MemberExpression" => {
                let receiver = value.get("object").map(transparent_expression)?;
                let provenance = self.expression_provenance(receiver)?;
                let computed = value.get("computed").and_then(Value::as_bool) == Some(true);
                if provenance.is_array() && computed {
                    return provenance.elements();
                }
                let (_, property, _, _) = member_parts(value)?;
                provenance.property(&property)
            }
            "CallExpression" => {
                let callee = value.get("callee").map(transparent_expression)?;
                if node_type(callee).ok() == Some("Identifier") {
                    let target = self.reference_bindings.get(&span(callee).ok()?)?;
                    return self.function_returns.get(target).cloned();
                }
                let (receiver, method, computed, optional) = member_parts(callee)?;
                if computed || optional {
                    return None;
                }
                let arguments = value.get("arguments").and_then(Value::as_array)?;
                if method == "get"
                    && arguments.len() == 1
                    && node_type(receiver).ok() == Some("Identifier")
                    && let Some(binding) = self.reference_bindings.get(&span(receiver).ok()?)
                    && self.local_map_bindings.contains(binding)
                {
                    return self.local_map_values.get(binding).cloned();
                }
                if method == "all"
                    && self.is_global_reference(receiver, "Promise")
                    && arguments.len() == 1
                {
                    return self.expression_provenance(&arguments[0]);
                }
                let receiver_provenance = self.expression_provenance(receiver);
                match method.as_str() {
                    "filter" | "slice" | "sort" | "toSorted" | "reverse" | "toReversed" => {
                        receiver_provenance.filter(ResultProvenance::is_array)
                    }
                    "map" => {
                        let callback = arguments.first()?;
                        match self.callback_return_provenance(callback) {
                            Some(provenance) => Some(ResultProvenance::array_from(provenance)),
                            None if receiver_provenance.is_some() => {
                                Some(ResultProvenance::ordinary_array())
                            }
                            None => None,
                        }
                    }
                    "flatMap" => {
                        let callback = arguments.first()?;
                        let returned = self.callback_return_provenance(callback);
                        match returned {
                            Some(returned) if returned.is_array() => {
                                Some(ResultProvenance::Array(returned.elements().map(Box::new)))
                            }
                            Some(returned) => Some(ResultProvenance::array_from(returned)),
                            None if receiver_provenance.is_some() => {
                                Some(ResultProvenance::ordinary_array())
                            }
                            None => None,
                        }
                    }
                    "flat" => receiver_provenance?.flattened(),
                    "find" | "at" => receiver_provenance?.elements(),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn callback_return_provenance(&self, callback: &Value) -> Option<ResultProvenance> {
        let callback = transparent_expression(callback);
        if node_type(callback).ok() == Some("Identifier") {
            let binding = self.reference_bindings.get(&span(callback).ok()?)?;
            return self.function_returns.get(binding).cloned();
        }
        if !matches!(
            node_type(callback).ok(),
            Some("ArrowFunctionExpression" | "FunctionExpression")
        ) {
            return None;
        }
        let mut returns = Vec::new();
        collect_function_returns(callback, true, &mut returns);
        merge_return_provenance(&returns, self)
    }
}

fn neutral_return(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let value = transparent_expression(value);
    node_type(value).ok() == Some("Literal") && value.get("value").is_none_or(Value::is_null)
}

fn merge_return_provenance(
    returns: &[Option<&Value>],
    state: &FlowState<'_>,
) -> Option<ResultProvenance> {
    let mut merged: Option<ResultProvenance> = None;
    for returned in returns {
        if neutral_return(*returned) {
            continue;
        }
        let provenance = state.expression_provenance(returned.as_ref()?)?;
        merged = Some(match merged {
            Some(current) => current.merge(&provenance)?,
            None => provenance,
        });
    }
    merged
}

fn assign_binding(
    state: &mut FlowState<'_>,
    binding: BindingKey,
    provenance: ResultProvenance,
) -> bool {
    let Some(fact) = state.bindings.get(&binding) else {
        state.rejection.get_or_insert_with(|| {
            format!(
                "query-result binding at {}..{} disappeared from Oxc semantics",
                binding.0, binding.1
            )
        });
        return false;
    };
    if fact.references.iter().any(|reference| {
        reference.write
            && !state
                .consumed_write_references
                .contains(&(reference.start, reference.end))
    }) {
        state.rejection.get_or_insert_with(|| {
            format!(
                "query-result binding {} at {}..{} is written",
                fact.name, binding.0, binding.1
            )
        });
        return false;
    }
    match state.binding_provenance.get_mut(&binding) {
        Some(existing) => {
            let Some(merged) = existing.merge(&provenance) else {
                state.rejection.get_or_insert_with(|| {
                    format!(
                        "query-result binding {} at {}..{} has conflicting document and array provenance",
                        fact.name, binding.0, binding.1
                    )
                });
                return false;
            };
            if *existing == merged {
                false
            } else {
                *existing = merged;
                true
            }
        }
        None => {
            state.binding_provenance.insert(binding, provenance);
            true
        }
    }
}

fn collect_declarator_bindings<'a>(value: &'a Value, output: &mut Vec<(BindingKey, &'a Value)>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("VariableDeclarator")
                && let (Some(identifier), Some(initializer)) =
                    (object.get("id"), object.get("init"))
                && node_type(identifier).ok() == Some("Identifier")
                && let Ok(binding) = span(identifier)
            {
                output.push((binding, initializer));
            }
            for child in object.values() {
                collect_declarator_bindings(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_declarator_bindings(child, output);
            }
        }
        _ => {}
    }
}

fn collect_declarators<'a>(value: &'a Value, output: &mut Vec<(&'a Value, &'a Value)>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("VariableDeclarator")
                && let (Some(pattern), Some(initializer)) = (object.get("id"), object.get("init"))
                && !initializer.is_null()
            {
                output.push((pattern, initializer));
            }
            for child in object.values() {
                collect_declarators(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_declarators(child, output);
            }
        }
        _ => {}
    }
}

fn assign_pattern_provenance(
    state: &mut FlowState<'_>,
    pattern: &Value,
    provenance: &ResultProvenance,
) -> bool {
    let pattern = unwrap_runtime_expression(pattern);
    match node_type(pattern).ok() {
        Some("Identifier") => span(pattern)
            .ok()
            .is_some_and(|binding| assign_binding(state, binding, provenance.clone())),
        Some("AssignmentPattern") => pattern
            .get("left")
            .is_some_and(|left| assign_pattern_provenance(state, left, provenance)),
        Some("ArrayPattern") => {
            let Some(elements) = pattern.get("elements").and_then(Value::as_array) else {
                return false;
            };
            let (exact, homogeneous) = match provenance {
                ResultProvenance::Tuple(values) => (Some(values.as_slice()), None),
                _ => (None, provenance.elements()),
            };
            let mut changed = false;
            for (index, element) in elements.iter().enumerate() {
                if element.is_null() || node_type(element).ok() == Some("RestElement") {
                    continue;
                }
                let element_provenance = match exact {
                    Some(values) => values.get(index).and_then(Option::as_ref),
                    None => homogeneous.as_ref(),
                };
                if let Some(element_provenance) = element_provenance {
                    changed |= assign_pattern_provenance(state, element, element_provenance);
                }
            }
            changed
        }
        Some("ObjectPattern") => {
            let Some(properties) = pattern.get("properties").and_then(Value::as_array) else {
                return false;
            };
            let mut changed = false;
            for property in properties {
                if node_type(property).ok() != Some("Property")
                    || property.get("computed").and_then(Value::as_bool) == Some(true)
                {
                    continue;
                }
                let Some(key) = property.get("key").and_then(|key| {
                    identifier_name(key)
                        .ok()
                        .or_else(|| key.get("value").and_then(Value::as_str).map(str::to_string))
                }) else {
                    continue;
                };
                let Some(value) = property.get("value") else {
                    continue;
                };
                if let Some(property_provenance) = provenance.property(&key) {
                    changed |= assign_pattern_provenance(state, value, &property_provenance);
                }
            }
            changed
        }
        _ => false,
    }
}

fn collect_nullable_assignment_proposals<'a>(
    value: &'a Value,
    neutral_bindings: &BTreeSet<BindingKey>,
    state: &FlowState<'_>,
    output: &mut Vec<(
        BindingKey,
        SourceSpan,
        SourceSpan,
        ResultProvenance,
        &'a Value,
    )>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("AssignmentExpression")
                && object.get("operator").and_then(Value::as_str) == Some("=")
                && let (Some(left), Some(right)) = (object.get("left"), object.get("right"))
                && node_type(left).ok() == Some("Identifier")
                && let Ok(reference) = span(left)
                && let Some(binding) = state.reference_bindings.get(&reference)
                && neutral_bindings.contains(binding)
                && let Some(provenance) = state.expression_provenance(right)
                && let Ok(assignment) = span(value)
            {
                output.push((*binding, reference, assignment, provenance, right));
            }
            for child in object.values() {
                collect_nullable_assignment_proposals(child, neutral_bindings, state, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_nullable_assignment_proposals(child, neutral_bindings, state, output);
            }
        }
        _ => {}
    }
}

fn resolved_callback<'a>(
    callback: &'a Value,
    functions: &'a [FunctionNode<'a>],
    reference_bindings: &BTreeMap<SourceSpan, BindingKey>,
) -> Option<FunctionNode<'a>> {
    let callback = transparent_expression(callback);
    if matches!(
        node_type(callback).ok(),
        Some("ArrowFunctionExpression" | "FunctionExpression")
    ) {
        return Some(FunctionNode {
            binding: None,
            source: callback,
        });
    }
    let target = reference_bindings.get(&span(callback).ok()?)?;
    functions
        .iter()
        .find(|function| function.binding == Some(*target))
        .copied()
}

fn collect_empty_local_map_bindings(
    value: &Value,
    global_references: &BTreeSet<GlobalReference>,
    output: &mut BTreeSet<BindingKey>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("VariableDeclarator")
                && let (Some(identifier), Some(initializer)) =
                    (object.get("id"), object.get("init"))
                && node_type(identifier).ok() == Some("Identifier")
                && let initializer = transparent_expression(initializer)
                && node_type(initializer).ok() == Some("NewExpression")
                && initializer
                    .get("arguments")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
                && let Some(callee) = initializer.get("callee").map(transparent_expression)
                && identifier_name(callee).ok().as_deref() == Some("Map")
                && span(callee).ok().is_some_and(|(start, end)| {
                    global_references.contains(&("Map".to_string(), start, end))
                })
                && let Ok(binding) = span(identifier)
            {
                output.insert(binding);
            }
            for child in object.values() {
                collect_empty_local_map_bindings(child, global_references, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_empty_local_map_bindings(child, global_references, output);
            }
        }
        _ => {}
    }
}

fn local_map_method_call<'a>(
    value: &'a Value,
    local_map_bindings: &BTreeSet<BindingKey>,
    reference_bindings: &BTreeMap<SourceSpan, BindingKey>,
) -> Option<(BindingKey, SourceSpan, String, &'a [Value])> {
    let value = transparent_expression(value);
    if node_type(value).ok()? != "CallExpression" {
        return None;
    }
    let callee = value.get("callee").map(transparent_expression)?;
    let (receiver, method, computed, optional) = member_parts(callee)?;
    if computed || optional || node_type(receiver).ok()? != "Identifier" {
        return None;
    }
    let receiver_span = span(receiver).ok()?;
    let binding = *reference_bindings.get(&receiver_span)?;
    if !local_map_bindings.contains(&binding) {
        return None;
    }
    let arguments = value.get("arguments")?.as_array()?.as_slice();
    Some((binding, receiver_span, method, arguments))
}

#[derive(Clone)]
struct LocalMapSetProposal<'a> {
    value: &'a Value,
    provenance: Option<ResultProvenance>,
}

fn collect_local_map_calls<'a>(
    value: &'a Value,
    state: &FlowState<'_>,
    proposals: &mut BTreeMap<BindingKey, Vec<LocalMapSetProposal<'a>>>,
    supported_references: &mut BTreeSet<SourceSpan>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && let Some((_, receiver, method, arguments)) = local_map_method_call(
                    value,
                    &state.local_map_bindings,
                    state.reference_bindings,
                )
                && method == "get"
                && arguments.len() == 1
            {
                supported_references.insert(receiver);
            }
            if object.get("type").and_then(Value::as_str) == Some("ExpressionStatement")
                && let Some(expression) = object.get("expression")
                && let Some((binding, receiver, method, arguments)) = local_map_method_call(
                    expression,
                    &state.local_map_bindings,
                    state.reference_bindings,
                )
                && method == "set"
                && arguments.len() == 2
            {
                supported_references.insert(receiver);
                let value = &arguments[1];
                proposals
                    .entry(binding)
                    .or_default()
                    .push(LocalMapSetProposal {
                        value,
                        provenance: state.expression_provenance(value),
                    });
            }
            for child in object.values() {
                collect_local_map_calls(child, state, proposals, supported_references);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_local_map_calls(child, state, proposals, supported_references);
            }
        }
        _ => {}
    }
}

fn merged_local_map_value(
    proposals: &[LocalMapSetProposal<'_>],
) -> Result<Option<ResultProvenance>, String> {
    if proposals.is_empty()
        || proposals
            .iter()
            .any(|proposal| proposal.provenance.is_none())
    {
        return Ok(None);
    }
    let mut provenances = proposals
        .iter()
        .filter_map(|proposal| proposal.provenance.as_ref());
    let Some(mut merged) = provenances.next().cloned() else {
        return Ok(None);
    };
    for provenance in provenances {
        merged = merged.merge(provenance).ok_or_else(|| {
            "local Map receives conflicting query-result value shapes".to_string()
        })?;
    }
    Ok(Some(merged))
}

fn collect_call_parameter_proposals(
    value: &Value,
    functions: &[FunctionNode<'_>],
    state: &FlowState<'_>,
    proposals: &mut BTreeMap<BindingKey, Vec<Option<ResultProvenance>>>,
    supported_function_references: &mut BTreeSet<SourceSpan>,
    expected_function_references: &mut BTreeMap<BindingKey, usize>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && let Some(callee) = object.get("callee").map(transparent_expression)
                && let Some(arguments) = object.get("arguments").and_then(Value::as_array)
            {
                if node_type(callee).ok() == Some("Identifier")
                    && let Ok(callee_span) = span(callee)
                    && let Some(target) = state.reference_bindings.get(&callee_span)
                    && let Some(function) = functions
                        .iter()
                        .find(|function| function.binding == Some(*target))
                {
                    supported_function_references.insert(callee_span);
                    *expected_function_references.entry(*target).or_default() += 1;
                    for (index, parameter) in
                        function_parameters(function.source).into_iter().enumerate()
                    {
                        proposals.entry(parameter).or_default().push(
                            arguments
                                .get(index)
                                .and_then(|argument| state.expression_provenance(argument)),
                        );
                    }
                } else if let Some((receiver, method, computed, optional)) = member_parts(callee)
                    && !computed
                    && !optional
                    && matches!(
                        method.as_str(),
                        "filter"
                            | "map"
                            | "flatMap"
                            | "forEach"
                            | "some"
                            | "every"
                            | "find"
                            | "findIndex"
                            | "sort"
                            | "toSorted"
                    )
                    && let Some(array) = state.expression_provenance(receiver)
                    && let Some(element) = array.elements()
                    && let Some(callback) = arguments.first()
                    && let Some(function) =
                        resolved_callback(callback, functions, state.reference_bindings)
                    && let parameters = function_parameters(function.source)
                {
                    let proved_parameter_count = if matches!(method.as_str(), "sort" | "toSorted") {
                        2
                    } else {
                        1
                    };
                    for parameter in parameters.into_iter().take(proved_parameter_count) {
                        proposals
                            .entry(parameter)
                            .or_default()
                            .push(Some(element.clone()));
                    }
                    if let Some(binding) = function.binding
                        && let Ok(callback_span) = span(transparent_expression(callback))
                    {
                        supported_function_references.insert(callback_span);
                        *expected_function_references.entry(binding).or_default() += 1;
                    }
                }
            }
            for child in object.values() {
                collect_call_parameter_proposals(
                    child,
                    functions,
                    state,
                    proposals,
                    supported_function_references,
                    expected_function_references,
                );
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_call_parameter_proposals(
                    child,
                    functions,
                    state,
                    proposals,
                    supported_function_references,
                    expected_function_references,
                );
            }
        }
        _ => {}
    }
}

fn collect_for_of_proposals(
    value: &Value,
    state: &FlowState<'_>,
    output: &mut Vec<(BindingKey, ResultProvenance, SourceSpan)>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("ForOfStatement")
                && object.get("await").and_then(Value::as_bool) != Some(true)
                && let Some(iterable) = object.get("right")
                && let Some(array) = state.expression_provenance(iterable)
                && let Some(element) = array.elements()
                && let Some(left) = object.get("left")
                && node_type(left).ok() == Some("VariableDeclaration")
                && let Some(declaration) = left
                    .get("declarations")
                    .and_then(Value::as_array)
                    .and_then(|declarations| declarations.first())
                && let Some(identifier) = declaration.get("id")
                && node_type(identifier).ok() == Some("Identifier")
                && let (Ok(binding), Ok(iterable_span)) = (span(identifier), span(iterable))
            {
                output.push((binding, element, iterable_span));
            }
            for child in object.values() {
                collect_for_of_proposals(child, state, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_for_of_proposals(child, state, output);
            }
        }
        _ => {}
    }
}

fn reference_spans(
    value: &Value,
    reference_bindings: &BTreeMap<SourceSpan, BindingKey>,
    output: &mut BTreeSet<SourceSpan>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("Identifier")
                && let Ok(reference) = span(value)
                && reference_bindings.contains_key(&reference)
            {
                output.insert(reference);
            }
            for child in object.values() {
                reference_spans(child, reference_bindings, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                reference_spans(child, reference_bindings, output);
            }
        }
        _ => {}
    }
}

fn seed_spans(
    value: &Value,
    seed_expressions: &BTreeMap<SourceSpan, ResultProvenance>,
    output: &mut BTreeSet<SourceSpan>,
) {
    if let Ok(site) = span(value)
        && seed_expressions.contains_key(&site)
    {
        output.insert(site);
    }
    match value {
        Value::Object(object) => {
            for child in object.values() {
                seed_spans(child, seed_expressions, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                seed_spans(child, seed_expressions, output);
            }
        }
        _ => {}
    }
}

fn mark_expression_flow(value: &Value, state: &mut FlowState<'_>) {
    let mut references = BTreeSet::new();
    reference_spans(value, state.reference_bindings, &mut references);
    let mut seeds = BTreeSet::new();
    seed_spans(value, &state.seed_expressions, &mut seeds);
    state.consumed_references.extend(references);
    state.consumed_seed_expressions.extend(seeds);
}

fn collect_member_uses(value: &Value, write: bool, state: &mut FlowState<'_>) {
    match value {
        Value::Object(object) => {
            let kind = object.get("type").and_then(Value::as_str);
            if kind == Some("ObjectExpression")
                && let Some(properties) = object.get("properties").and_then(Value::as_array)
            {
                for property in properties {
                    if node_type(property).ok() == Some("SpreadElement")
                        && let Some(argument) = property.get("argument")
                        && state
                            .expression_provenance(argument)
                            .is_some_and(|provenance| {
                                matches!(provenance, ResultProvenance::Document(_))
                            })
                    {
                        mark_expression_flow(argument, state);
                    }
                }
            }
            if kind == Some("MemberExpression")
                && let Some(receiver) = object.get("object").map(transparent_expression)
                && let Some(provenance) = state.expression_provenance(receiver)
            {
                let computed = object.get("computed").and_then(Value::as_bool) == Some(true);
                let property = member_parts(value).map(|(_, property, _, _)| property);
                match (&provenance, write, computed, property) {
                    (_, true, _, _) => {
                        state.rejection.get_or_insert_with(|| {
                            "query-result member writes are unsupported".to_string()
                        });
                    }
                    (ResultProvenance::Document(_), false, true, None) => {
                        state.rejection.get_or_insert_with(|| {
                            "dynamic computed query-result document access is unsupported"
                                .to_string()
                        });
                    }
                    (ResultProvenance::Document(tables), false, _, Some(property)) => {
                        mark_expression_flow(receiver, state);
                        for table in tables {
                            state
                                .document_properties
                                .insert(ProvedQueryDocumentProperty {
                                    table: table.clone(),
                                    property: property.clone(),
                                });
                        }
                    }
                    (ResultProvenance::Array(_) | ResultProvenance::Tuple(_), false, true, _) => {
                        // An indexed array read preserves the authenticated element provenance;
                        // the dynamic index cannot change which table produced an element.
                        mark_expression_flow(receiver, state);
                    }
                    (
                        ResultProvenance::Array(_) | ResultProvenance::Tuple(_),
                        false,
                        false,
                        Some(property),
                    ) if matches!(
                        property.as_str(),
                        "length"
                            | "filter"
                            | "map"
                            | "flatMap"
                            | "flat"
                            | "slice"
                            | "sort"
                            | "toSorted"
                            | "reverse"
                            | "toReversed"
                            | "at"
                            | "forEach"
                            | "some"
                            | "every"
                            | "find"
                            | "findIndex"
                    ) =>
                    {
                        mark_expression_flow(receiver, state);
                    }
                    (
                        ResultProvenance::Array(_) | ResultProvenance::Tuple(_),
                        false,
                        _,
                        property,
                    ) => {
                        state.rejection.get_or_insert_with(|| {
                            format!(
                                "unsupported query-result array member access{}",
                                property
                                    .as_deref()
                                    .map(|property| format!(" .{property}"))
                                    .unwrap_or_default()
                            )
                        });
                    }
                    (ResultProvenance::Object(_), false, true, None) => {
                        state.rejection.get_or_insert_with(|| {
                            "dynamic query-result object-container access is unsupported"
                                .to_string()
                        });
                    }
                    (ResultProvenance::Object(_), false, _, Some(_)) => {
                        mark_expression_flow(receiver, state);
                    }
                    _ => {}
                }
            }
            if kind == Some("CallExpression")
                && let Some(callee) = object.get("callee").map(transparent_expression)
                && let Some((receiver, _, _, _)) = member_parts(callee)
                && state
                    .expression_provenance(receiver)
                    .is_some_and(|provenance| matches!(provenance, ResultProvenance::Document(_)))
            {
                state.rejection.get_or_insert_with(|| {
                    "dynamic query-result document method calls are unsupported".to_string()
                });
            }
            for (key, child) in object {
                let child_write = match (kind, key.as_str()) {
                    (Some("AssignmentExpression"), "left")
                    | (Some("AssignmentPattern"), "left")
                    | (Some("UpdateExpression"), "argument") => true,
                    (Some("UnaryExpression"), "argument")
                        if object.get("operator").and_then(Value::as_str) == Some("delete") =>
                    {
                        true
                    }
                    (Some("MemberExpression"), "object" | "property") if write => true,
                    _ => false,
                };
                collect_member_uses(child, child_write, state);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_member_uses(child, write, state);
            }
        }
        _ => {}
    }
}

fn mark_direct_scalar_uses(value: &Value, state: &mut FlowState<'_>) {
    match value {
        Value::Object(object) => {
            let kind = object.get("type").and_then(Value::as_str);
            let mut consume_expression = |candidate: Option<&Value>| {
                let Some(candidate) = candidate.map(transparent_expression) else {
                    return;
                };
                if state.expression_provenance(candidate).is_some() {
                    mark_expression_flow(candidate, state);
                }
            };
            match kind {
                Some("IfStatement" | "ConditionalExpression" | "WhileStatement") => {
                    consume_expression(object.get("test"));
                }
                Some("UnaryExpression")
                    if matches!(
                        object.get("operator").and_then(Value::as_str),
                        Some("!" | "typeof" | "void")
                    ) =>
                {
                    consume_expression(object.get("argument"));
                }
                Some("LogicalExpression") => {
                    consume_expression(object.get("left"));
                    consume_expression(object.get("right"));
                }
                Some("BinaryExpression")
                    if matches!(
                        object.get("operator").and_then(Value::as_str),
                        Some("==" | "!=" | "===" | "!==")
                    ) =>
                {
                    let left = object.get("left");
                    let right = object.get("right");
                    let nullish = |candidate: Option<&Value>| {
                        candidate.is_some_and(|candidate| {
                            let candidate = transparent_expression(candidate);
                            (node_type(candidate).ok() == Some("Literal")
                                && candidate.get("value").is_none_or(Value::is_null))
                                || identifier_name(candidate).ok().as_deref() == Some("undefined")
                                || (node_type(candidate).ok() == Some("UnaryExpression")
                                    && candidate.get("operator").and_then(Value::as_str)
                                        == Some("void")
                                    && candidate
                                        .get("argument")
                                        .map(transparent_expression)
                                        .is_some_and(|argument| {
                                            node_type(argument).ok() == Some("Literal")
                                                && argument.get("value").and_then(Value::as_u64)
                                                    == Some(0)
                                        }))
                        })
                    };
                    if nullish(right) {
                        consume_expression(left);
                    }
                    if nullish(left) {
                        consume_expression(right);
                    }
                }
                _ => {}
            }
            for child in object.values() {
                mark_direct_scalar_uses(child, state);
            }
        }
        Value::Array(values) => {
            for child in values {
                mark_direct_scalar_uses(child, state);
            }
        }
        _ => {}
    }
}

fn mark_terminal_result_uses(value: &Value, state: &mut FlowState<'_>) {
    match value {
        Value::Object(object) => {
            match object.get("type").and_then(Value::as_str) {
                Some("ExpressionStatement") => {
                    if let Some(expression) = object.get("expression")
                        && state.expression_provenance(expression).is_some()
                    {
                        mark_expression_flow(expression, state);
                    }
                }
                Some("ReturnStatement") => {
                    if let Some(argument) = object.get("argument").filter(|value| !value.is_null())
                        && state.expression_provenance(argument).is_some()
                    {
                        mark_expression_flow(argument, state);
                    }
                }
                _ => {}
            }
            for child in object.values() {
                mark_terminal_result_uses(child, state);
            }
        }
        Value::Array(values) => {
            for child in values {
                mark_terminal_result_uses(child, state);
            }
        }
        _ => {}
    }
}

fn collect_proved_array_expressions(
    value: &Value,
    state: &FlowState<'_>,
    output: &mut BTreeSet<SourceSpan>,
) {
    if state
        .expression_provenance(value)
        .is_some_and(|provenance| provenance.is_array())
        && let Ok(site) = span(value)
    {
        output.insert(site);
    }
    match value {
        Value::Object(object) => {
            for child in object.values() {
                collect_proved_array_expressions(child, state, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_proved_array_expressions(child, state, output);
            }
        }
        _ => {}
    }
}

fn mark_flow_edge_references(
    ast: &Value,
    functions: &[FunctionNode<'_>],
    state: &mut FlowState<'_>,
) {
    let mut declarators = Vec::new();
    collect_declarators(ast, &mut declarators);
    for (_, initializer) in declarators {
        if state.expression_provenance(initializer).is_some() {
            mark_expression_flow(initializer, state);
        }
    }
    for function in functions {
        if let Some(binding) = function.binding
            && state.function_returns.contains_key(&binding)
        {
            let mut returns = Vec::new();
            collect_function_returns(function.source, true, &mut returns);
            for returned in returns.into_iter().flatten() {
                if state.expression_provenance(returned).is_some() {
                    mark_expression_flow(returned, state);
                }
            }
        }
    }
    mark_call_argument_references(ast, functions, state);
    mark_for_of_references(ast, state);
}

fn mark_call_argument_references(
    value: &Value,
    functions: &[FunctionNode<'_>],
    state: &mut FlowState<'_>,
) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("CallExpression")
                && let Some(callee) = object.get("callee").map(transparent_expression)
                && node_type(callee).ok() == Some("Identifier")
                && let Ok(callee_span) = span(callee)
                && let Some(target) = state.reference_bindings.get(&callee_span)
                && let Some(function) = functions
                    .iter()
                    .find(|function| function.binding == Some(*target))
                && let Some(arguments) = object.get("arguments").and_then(Value::as_array)
            {
                for (parameter, argument) in function_parameters(function.source)
                    .into_iter()
                    .zip(arguments)
                {
                    if state.binding_provenance.contains_key(&parameter)
                        && state.expression_provenance(argument).is_some()
                    {
                        mark_expression_flow(argument, state);
                    }
                }
            }
            for child in object.values() {
                mark_call_argument_references(child, functions, state);
            }
        }
        Value::Array(values) => {
            for child in values {
                mark_call_argument_references(child, functions, state);
            }
        }
        _ => {}
    }
}

fn mark_for_of_references(value: &Value, state: &mut FlowState<'_>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("ForOfStatement")
                && object.get("await").and_then(Value::as_bool) != Some(true)
                && let Some(iterable) = object.get("right")
                && state
                    .expression_provenance(iterable)
                    .is_some_and(|provenance| provenance.is_array())
            {
                mark_expression_flow(iterable, state);
            }
            for child in object.values() {
                mark_for_of_references(child, state);
            }
        }
        Value::Array(values) => {
            for child in values {
                mark_for_of_references(child, state);
            }
        }
        _ => {}
    }
}

fn prove_bound_flow(
    ast: &Value,
    bindings: &BTreeMap<BindingKey, BindingFact>,
    reference_bindings: &BTreeMap<SourceSpan, BindingKey>,
    global_references: &BTreeSet<GlobalReference>,
    seeds: &[BoundSeed],
) -> Result<Result<ProvedQueryResultFlow, String>> {
    let mut local_map_bindings = BTreeSet::new();
    collect_empty_local_map_bindings(ast, global_references, &mut local_map_bindings);
    let mut state = FlowState {
        seed_expressions: BTreeMap::new(),
        bindings,
        reference_bindings,
        global_references,
        binding_provenance: BTreeMap::new(),
        assignment_results: BTreeMap::new(),
        function_returns: BTreeMap::new(),
        local_map_bindings,
        local_map_values: BTreeMap::new(),
        consumed_references: BTreeSet::new(),
        consumed_write_references: BTreeSet::new(),
        consumed_seed_expressions: BTreeSet::new(),
        array_expressions: BTreeSet::new(),
        document_properties: BTreeSet::new(),
        rejection: None,
    };
    for seed in seeds {
        let document_provenance = ResultProvenance::Document(seed.tables.clone());
        match seed.kind {
            CallableQueryConsumerKind::Collect | CallableQueryConsumerKind::Take => {
                state
                    .seed_expressions
                    .insert(seed.site, ResultProvenance::array_from(document_provenance));
                state.array_expressions.insert(seed.site);
            }
            CallableQueryConsumerKind::First | CallableQueryConsumerKind::Unique => {
                state
                    .seed_expressions
                    .insert(seed.site, document_provenance);
            }
            CallableQueryConsumerKind::Stream => {
                let Some(statement) = find_node(ast, seed.site, Some("ForOfStatement")) else {
                    return Ok(Err("authenticated stream statement disappeared".to_string()));
                };
                let Some(left) = statement.get("left") else {
                    return Ok(Err("authenticated stream has no loop binding".to_string()));
                };
                let Some(identifier) = left
                    .get("declarations")
                    .and_then(Value::as_array)
                    .and_then(|declarations| declarations.first())
                    .and_then(|declaration| declaration.get("id"))
                else {
                    return Ok(Err(
                        "authenticated stream requires one lexical identifier binding".to_string(),
                    ));
                };
                if node_type(identifier).ok() != Some("Identifier") {
                    return Ok(Err(
                        "authenticated stream destructuring binding is unsupported".to_string(),
                    ));
                }
                assign_binding(&mut state, span(identifier)?, document_provenance);
            }
            CallableQueryConsumerKind::Paginate => {
                state.seed_expressions.insert(
                    seed.site,
                    ResultProvenance::Object(BTreeMap::from([(
                        "page".to_string(),
                        ResultProvenance::array_from(document_provenance),
                    )])),
                );
            }
        }
    }

    let mut functions = Vec::new();
    collect_functions(ast, &mut functions);
    functions.sort_by_key(|function| span(function.source).unwrap_or_default());
    functions.dedup_by_key(|function| span(function.source).unwrap_or_default());
    let mut direct_declarators = Vec::new();
    collect_declarator_bindings(ast, &mut direct_declarators);
    let neutral_bindings = direct_declarators
        .iter()
        .filter(|(_, initializer)| neutral_return(Some(initializer)))
        .map(|(binding, _)| *binding)
        .collect::<BTreeSet<_>>();
    let mut declarators = Vec::new();
    collect_declarators(ast, &mut declarators);

    loop {
        let before_bindings = state.binding_provenance.clone();
        let before_assignment_results = state.assignment_results.clone();
        let before_returns = state.function_returns.clone();
        let before_map_values = state.local_map_values.clone();

        for (pattern, initializer) in &declarators {
            if let Some(provenance) = state.expression_provenance(initializer) {
                assign_pattern_provenance(&mut state, pattern, &provenance);
            }
        }

        let mut assignments = Vec::new();
        collect_nullable_assignment_proposals(ast, &neutral_bindings, &state, &mut assignments);
        for (binding, write_reference, assignment, provenance, right) in assignments {
            let Some(fact) = bindings.get(&binding) else {
                state.rejection.get_or_insert_with(|| {
                    "nullable query-result assignment binding disappeared".to_string()
                });
                continue;
            };
            let writes = fact
                .references
                .iter()
                .filter(|reference| reference.write)
                .collect::<Vec<_>>();
            if writes.len() != 1
                || (writes[0].start, writes[0].end) != write_reference
                || writes[0].read
            {
                state.rejection.get_or_insert_with(|| {
                    format!(
                        "query-result nullable binding {} must have one exact assignment",
                        fact.name
                    )
                });
                continue;
            }
            state.consumed_write_references.insert(write_reference);
            assign_binding(&mut state, binding, provenance.clone());
            // Plain assignment evaluates to its right-hand value. Record that result only after
            // the single-write nullable-binding contract is proved, so an unsupported assignment
            // target cannot hide a query-result escape through its surrounding expression.
            state.assignment_results.insert(assignment, provenance);
            mark_expression_flow(right, &mut state);
        }

        let mut proposals = BTreeMap::<BindingKey, Vec<Option<ResultProvenance>>>::new();
        let mut supported_function_references = BTreeSet::new();
        let mut expected_function_references = BTreeMap::new();
        collect_call_parameter_proposals(
            ast,
            &functions,
            &state,
            &mut proposals,
            &mut supported_function_references,
            &mut expected_function_references,
        );
        for (parameter, provenances) in proposals {
            if provenances.iter().all(Option::is_none) {
                continue;
            }
            let Some(function) = functions
                .iter()
                .find(|function| function_parameters(function.source).contains(&parameter))
            else {
                continue;
            };
            if let Some(binding) = function.binding {
                let Some(fact) = bindings.get(&binding) else {
                    continue;
                };
                if fact.references.iter().any(|reference| {
                    reference.write
                        || !supported_function_references
                            .contains(&(reference.start, reference.end))
                }) || expected_function_references
                    .get(&binding)
                    .copied()
                    .unwrap_or_default()
                    != fact.references.len()
                {
                    continue;
                }
            }
            let mut provenances = provenances.into_iter().flatten();
            let Some(mut merged) = provenances.next() else {
                continue;
            };
            for provenance in provenances {
                let Some(next) = merged.merge(&provenance) else {
                    state.rejection.get_or_insert_with(|| {
                        format!(
                            "query-result helper parameter at {}..{} receives conflicting document and array provenance",
                            parameter.0, parameter.1
                        )
                    });
                    break;
                };
                merged = next;
            }
            if state.rejection.is_some() {
                continue;
            }
            assign_binding(&mut state, parameter, merged);
        }

        let mut for_of = Vec::new();
        collect_for_of_proposals(ast, &state, &mut for_of);
        for (binding, provenance, _) in for_of {
            assign_binding(&mut state, binding, provenance);
        }

        for function in &functions {
            let Some(binding) = function.binding else {
                continue;
            };
            let mut returns = Vec::new();
            collect_function_returns(function.source, true, &mut returns);
            if let Some(provenance) = merge_return_provenance(&returns, &state) {
                state.function_returns.insert(binding, provenance);
            }
        }

        let mut map_proposals = BTreeMap::new();
        let mut supported_map_references = BTreeSet::new();
        collect_local_map_calls(
            ast,
            &state,
            &mut map_proposals,
            &mut supported_map_references,
        );
        for (binding, proposals) in map_proposals {
            match merged_local_map_value(&proposals) {
                Ok(Some(provenance)) => {
                    state.local_map_values.insert(binding, provenance);
                }
                Ok(None) => {}
                Err(reason) => {
                    state.rejection.get_or_insert(reason);
                }
            }
        }

        if state.binding_provenance == before_bindings
            && state.assignment_results == before_assignment_results
            && state.function_returns == before_returns
            && state.local_map_values == before_map_values
        {
            break;
        }
    }

    let mut final_map_proposals = BTreeMap::new();
    let mut supported_map_references = BTreeSet::new();
    collect_local_map_calls(
        ast,
        &state,
        &mut final_map_proposals,
        &mut supported_map_references,
    );
    let proved_local_maps = state
        .local_map_values
        .iter()
        .map(|(binding, provenance)| (*binding, provenance.clone()))
        .collect::<Vec<_>>();
    for (binding, provenance) in proved_local_maps {
        let Some(fact) = bindings.get(&binding) else {
            state.rejection.get_or_insert_with(|| {
                "proved local Map query-result container disappeared".to_string()
            });
            continue;
        };
        if fact.references.iter().any(|reference| {
            reference.write
                || !reference.read
                || !supported_map_references.contains(&(reference.start, reference.end))
        }) {
            state.rejection.get_or_insert_with(|| {
                format!(
                    "local Map query-result container {} escapes exact get/set use",
                    fact.name
                )
            });
            continue;
        }
        let proposals = final_map_proposals
            .get(&binding)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        match merged_local_map_value(proposals) {
            Ok(Some(final_provenance)) if final_provenance == provenance => {
                for proposal in proposals {
                    mark_expression_flow(proposal.value, &mut state);
                }
            }
            Ok(Some(_)) => {
                state.rejection.get_or_insert_with(|| {
                    format!(
                        "local Map query-result container {} changed value provenance",
                        fact.name
                    )
                });
            }
            Ok(None) => {
                state.rejection.get_or_insert_with(|| {
                    format!(
                        "local Map query-result container {} mixes proved and unproved values",
                        fact.name
                    )
                });
            }
            Err(reason) => {
                state.rejection.get_or_insert(reason);
            }
        }
    }

    collect_member_uses(ast, false, &mut state);
    mark_direct_scalar_uses(ast, &mut state);
    mark_flow_edge_references(ast, &functions, &mut state);
    mark_terminal_result_uses(ast, &mut state);

    if let Some(reason) = state.rejection {
        return Ok(Err(reason));
    }

    for site in state.seed_expressions.keys() {
        if !state.consumed_seed_expressions.contains(site) {
            return Ok(Err(format!(
                "query-result terminal at {}..{} has an unrepresented direct escape or use",
                site.0, site.1
            )));
        }
    }

    for (binding, provenance) in &state.binding_provenance {
        let Some(fact) = bindings.get(binding) else {
            return Ok(Err("proved query-result binding disappeared".to_string()));
        };
        for reference in &fact.references {
            let site = (reference.start, reference.end);
            let represented = if reference.write {
                state.consumed_write_references.contains(&site)
            } else {
                reference.read && state.consumed_references.contains(&site)
            };
            if !represented {
                return Ok(Err(format!(
                    "{} query-result {} reference at {}..{} has an unrepresented escape, write, computed access, or dynamic flow",
                    provenance.kind_name(),
                    fact.name,
                    reference.start,
                    reference.end
                )));
            }
        }
    }

    // Query terminals are decoded by runtime helpers that already mark their host arrays.
    // Derived array operations retain authenticated provenance but create new arrays that the
    // opaque codec cannot recognize until generated-source lowering marks them separately.
    let host_array_expressions = state.array_expressions.clone();
    let mut proved_array_expressions = BTreeSet::new();
    collect_proved_array_expressions(ast, &state, &mut proved_array_expressions);
    state.array_expressions.extend(proved_array_expressions);

    Ok(Ok(ProvedQueryResultFlow {
        array_expressions: state.array_expressions,
        host_array_expressions,
        document_properties: state.document_properties,
    }))
}

pub(super) fn prove_generated_query_result_flow(
    source: &str,
    seeds: &[AuthenticatedQueryResultSeed],
) -> Result<QueryResultFlowOutcome> {
    if seeds.is_empty() {
        return Ok(QueryResultFlowOutcome::Proved(
            ProvedQueryResultFlow::default(),
        ));
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "generated query-result source has {} parser diagnostics",
        parsed.diagnostics.len()
    );
    let semantic = SemanticBuilder::new_compiler()
        .with_build_nodes(true)
        .build(&parsed.program);
    ensure!(
        semantic.diagnostics.is_empty(),
        "generated query-result source has {} semantic diagnostics",
        semantic.diagnostics.len()
    );
    let ast: Value = serde_json::from_str(&parsed.program.to_estree_json(true, false))
        .context("Oxc emitted invalid query-result ESTree JSON")?;
    let global_references =
        semantic_global_references(semantic.semantic.scoping(), semantic.semantic.nodes());
    let (bindings, reference_bindings) =
        semantic_binding_facts(semantic.semantic.scoping(), semantic.semantic.nodes())?;
    let bound = match bind_seeds(&ast, seeds)? {
        Ok(bound) => bound,
        Err(rejection) => return Ok(QueryResultFlowOutcome::Rejected(rejection)),
    };
    match prove_bound_flow(
        &ast,
        &bindings,
        &reference_bindings,
        &global_references,
        &bound,
    )? {
        Ok(proof) => Ok(QueryResultFlowOutcome::Proved(proof)),
        Err(reason) => Ok(QueryResultFlowOutcome::Rejected(QueryResultFlowRejection {
            consumer: seeds[0].consumer.clone(),
            reason,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(start: u32) -> SourceAnchor {
        SourceAnchor {
            module: "convex/resultFlow.ts".to_string(),
            source_sha256: "1".repeat(64),
            start,
            end: start + 1,
            slice_sha256: "2".repeat(64),
        }
    }

    fn seed(
        authorization_id: &str,
        owner: &str,
        kind: CallableQueryConsumerKind,
        start: u32,
    ) -> AuthenticatedQueryResultSeed {
        seed_for_table(authorization_id, owner, kind, start, "documents")
    }

    fn seed_for_table(
        authorization_id: &str,
        owner: &str,
        kind: CallableQueryConsumerKind,
        start: u32,
        table: &str,
    ) -> AuthenticatedQueryResultSeed {
        AuthenticatedQueryResultSeed {
            authorization_id: authorization_id.to_string(),
            generated_unit_binding: owner.to_string(),
            consumer: anchor(start),
            kind,
            table: table.to_string(),
        }
    }

    fn proved(outcome: QueryResultFlowOutcome) -> ProvedQueryResultFlow {
        match outcome {
            QueryResultFlowOutcome::Proved(proof) => proof,
            QueryResultFlowOutcome::Rejected(rejection) => {
                panic!("query-result flow rejected: {}", rejection.reason)
            }
        }
    }

    fn rejected(outcome: QueryResultFlowOutcome) -> QueryResultFlowRejection {
        match outcome {
            QueryResultFlowOutcome::Proved(_) => panic!("query-result flow unexpectedly proved"),
            QueryResultFlowOutcome::Rejected(rejection) => rejection,
        }
    }

    #[test]
    fn direct_terminal_property_is_proved_but_computed_access_is_rejected() {
        let direct = proved(
            prove_generated_query_result_flow(
                "async function load() { return (await planned.first()).name; }",
                &[seed("first", "load", CallableQueryConsumerKind::First, 1)],
            )
            .unwrap(),
        );
        assert_eq!(
            direct.document_properties().collect::<Vec<_>>(),
            vec![&ProvedQueryDocumentProperty {
                table: "documents".to_string(),
                property: "name".to_string(),
            }]
        );

        let rejection = rejected(
            prove_generated_query_result_flow(
                "async function load(key) { return (await planned.first())[key]; }",
                &[seed("first", "load", CallableQueryConsumerKind::First, 1)],
            )
            .unwrap(),
        );
        assert!(
            rejection.reason.contains("computed"),
            "{}",
            rejection.reason
        );
    }

    #[test]
    fn paginate_proves_page_documents_and_keeps_cursor_metadata_ordinary() {
        let proof = proved(
            prove_generated_query_result_flow(
                r#"
async function load() {
  const result = await planned.paginate(options);
  return {
    ...result,
    isDone: result.isDone,
    page: result.page.map((document) => document.name),
  };
}
"#,
                &[seed(
                    "paginate",
                    "load",
                    CallableQueryConsumerKind::Paginate,
                    1,
                )],
            )
            .unwrap(),
        );
        assert_eq!(
            proof.document_properties().collect::<Vec<_>>(),
            vec![&ProvedQueryDocumentProperty {
                table: "documents".to_string(),
                property: "name".to_string(),
            }]
        );

        let rejection = rejected(
            prove_generated_query_result_flow(
                "async function load(key) { const result = await planned.paginate(options); return result[key]; }",
                &[seed(
                    "paginate",
                    "load",
                    CallableQueryConsumerKind::Paginate,
                    1,
                )],
            )
            .unwrap(),
        );
        assert!(
            rejection
                .reason
                .contains("dynamic query-result object-container access"),
            "{}",
            rejection.reason
        );
    }

    #[test]
    fn converging_query_stream_authorizations_share_one_consumer_seed() {
        let proof = proved(
            prove_generated_query_result_flow(
                r#"
async function load() {
  for await (const document of candidates) {
    if (document.active) return document.name;
  }
}
"#,
                &[
                    seed_for_table(
                        "first",
                        "load",
                        CallableQueryConsumerKind::Stream,
                        1,
                        "documents",
                    ),
                    seed_for_table(
                        "second",
                        "load",
                        CallableQueryConsumerKind::Stream,
                        1,
                        "archivedDocuments",
                    ),
                ],
            )
            .unwrap(),
        );
        assert_eq!(
            proof.document_properties().collect::<Vec<_>>(),
            vec![
                &ProvedQueryDocumentProperty {
                    table: "archivedDocuments".to_string(),
                    property: "active".to_string(),
                },
                &ProvedQueryDocumentProperty {
                    table: "archivedDocuments".to_string(),
                    property: "name".to_string(),
                },
                &ProvedQueryDocumentProperty {
                    table: "documents".to_string(),
                    property: "active".to_string(),
                },
                &ProvedQueryDocumentProperty {
                    table: "documents".to_string(),
                    property: "name".to_string(),
                },
            ]
        );
    }

    #[test]
    fn helper_parameter_rejects_conflicting_query_shapes() {
        let rejection = rejected(
            prove_generated_query_result_flow(
                r#"
function project(value) { return value.name; }
async function load() {
  const document = await firstPlan.first();
  const documents = await collectPlan.collect();
  project(document);
  return project(documents);
}
"#,
                &[
                    seed("first", "load", CallableQueryConsumerKind::First, 1),
                    seed("collect", "load", CallableQueryConsumerKind::Collect, 2),
                ],
            )
            .unwrap(),
        );
        assert!(
            rejection.reason.contains("conflicting"),
            "{}",
            rejection.reason
        );
    }

    #[test]
    fn helper_parameter_specializes_proved_calls_without_rejecting_ordinary_calls() {
        let proof = proved(
            prove_generated_query_result_flow(
                r#"
function project(value) { return value.name; }
async function load() {
  const document = await firstPlan.first();
  project(document);
  return project({ name: "ordinary" });
}
"#,
                &[seed("first", "load", CallableQueryConsumerKind::First, 1)],
            )
            .unwrap(),
        );
        assert!(
            proof
                .document_properties()
                .any(|property| property.property == "name")
        );
    }

    #[test]
    fn promise_all_tuple_and_mapped_pages_preserve_exact_result_provenance() {
        let tuple = proved(
            prove_generated_query_result_flow(
                r#"
async function load() {
  const [document, documents] = await Promise.all([
    firstPlan.first(),
    collectPlan.collect(),
  ]);
  return { name: document.name, count: documents.length };
}
"#,
                &[
                    seed("first", "load", CallableQueryConsumerKind::First, 1),
                    seed("collect", "load", CallableQueryConsumerKind::Collect, 2),
                ],
            )
            .unwrap(),
        );
        assert!(
            tuple
                .document_properties()
                .any(|property| property.property == "name")
        );

        let mapped = proved(
            prove_generated_query_result_flow(
                r#"
async function load(kinds) {
  const pages = await Promise.all(
    kinds.map(async (kind) => await queryPlan.take(2)),
  );
  return pages.flat().map((document) => document.name);
}
"#,
                &[seed("take", "load", CallableQueryConsumerKind::Take, 1)],
            )
            .unwrap(),
        );
        assert!(
            mapped
                .document_properties()
                .any(|property| property.property == "name")
        );
    }

    #[test]
    fn promise_all_keeps_ordinary_slots_and_unrelated_maps_outside_query_provenance() {
        let proof = proved(
            prove_generated_query_result_flow(
                r#"
async function ordinaryTeamId() { return "team"; }
async function load(values) {
  const marketKeys = values.map((value) => value.key);
  if (new Set(marketKeys).size !== marketKeys.length) throw new Error("duplicate");
  const [document, teamId] = await Promise.all([
    firstPlan.first(),
    ordinaryTeamId(),
  ]);
  return { matches: document.teamId === teamId, name: document?.name };
}
"#,
                &[seed("first", "load", CallableQueryConsumerKind::First, 1)],
            )
            .unwrap(),
        );
        let properties = proof
            .document_properties()
            .map(|property| property.property.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(properties, BTreeSet::from(["name", "teamId"]));
    }

    #[test]
    fn lowered_optional_guards_and_document_spreads_consume_exact_document_flow() {
        let proof = proved(
            prove_generated_query_result_flow(
                r#"
function project(document) { return { ...document, projected: true }; }
async function load() {
  const document = await firstPlan.first();
  const name = document === null || document === void 0 ? void 0 : document.name;
  return { name, projected: project(document) };
}
"#,
                &[seed("first", "load", CallableQueryConsumerKind::First, 1)],
            )
            .unwrap(),
        );
        assert!(
            proof
                .document_properties()
                .any(|property| property.property == "name")
        );
    }

    #[test]
    fn exact_local_map_forwards_one_homogeneous_query_result_value_shape() {
        proved(
            prove_generated_query_result_flow(
                r#"
async function listByCredential() { return await credentialPlan.collect(); }
async function listByNickname() { return await nicknamePlan.collect(); }
async function load(keys) {
  const readsByKey = new Map();
  const results = await Promise.all(keys.map((key) => {
    const existingRead = readsByKey.get(key);
    if (existingRead !== undefined) return existingRead;
    const read = key.startsWith("credential:")
      ? listByCredential()
      : listByNickname();
    readsByKey.set(key, read);
    return read;
  }));
  return { results };
}
"#,
                &[
                    seed(
                        "credential",
                        "listByCredential",
                        CallableQueryConsumerKind::Collect,
                        1,
                    ),
                    seed(
                        "nickname",
                        "listByNickname",
                        CallableQueryConsumerKind::Collect,
                        2,
                    ),
                ],
            )
            .unwrap(),
        );
    }

    #[test]
    fn local_map_query_result_container_rejects_escapes_and_mixed_values() {
        for source in [
            r#"
async function load(key) {
  const cache = new Map();
  const rows = await queryPlan.collect();
  cache.set(key, rows);
  return cache;
}
"#,
            r#"
async function load(key) {
  const cache = new Map();
  const rows = await queryPlan.collect();
  cache.set(key, rows);
  cache.set("ordinary", []);
  return cache.get(key);
}
"#,
        ] {
            let rejection = rejected(
                prove_generated_query_result_flow(
                    source,
                    &[seed(
                        "collect",
                        "load",
                        CallableQueryConsumerKind::Collect,
                        1,
                    )],
                )
                .unwrap(),
            );
            assert!(
                rejection.reason.contains("Map") || rejection.reason.contains("unrepresented"),
                "{}",
                rejection.reason
            );
        }
    }

    #[test]
    fn helper_collection_return_can_flow_into_a_static_result_object() {
        proved(
            prove_generated_query_result_flow(
                r#"
async function list() { return await queryPlan.collect(); }
async function load() { return { reviews: await list() }; }
"#,
                &[seed(
                    "collect",
                    "list",
                    CallableQueryConsumerKind::Collect,
                    1,
                )],
            )
            .unwrap(),
        );
    }

    #[test]
    fn static_object_forwarding_array_indexing_sort_and_optional_reads_are_proved() {
        let proof = proved(
            prove_generated_query_result_flow(
                r#"
function project(input) { return input.document?.name; }
function first(rows) { return rows[0]; }
async function load() {
  const document = await firstPlan.first();
  const rows = await collectPlan.collect();
  rows.sort((left, right) => left.rank - right.rank);
  const selected = first(rows);
  return { projected: project({ document }), selected: selected.name };
}
"#,
                &[
                    seed("first", "load", CallableQueryConsumerKind::First, 1),
                    seed("collect", "load", CallableQueryConsumerKind::Collect, 2),
                ],
            )
            .unwrap(),
        );
        let properties = proof
            .document_properties()
            .map(|property| property.property.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(properties, BTreeSet::from(["name", "rank"]));
    }

    #[test]
    fn nullable_binding_rejects_more_than_one_query_result_assignment() {
        let rejection = rejected(
            prove_generated_query_result_flow(
                r#"
async function load() {
  let saved = null;
  saved = await firstPlan.first();
  saved = (await collectPlan.collect()).find((row) => row.enabled);
  return saved === null ? null : saved.name;
}
"#,
                &[
                    seed("first", "load", CallableQueryConsumerKind::First, 1),
                    seed("collect", "load", CallableQueryConsumerKind::Collect, 2),
                ],
            )
            .unwrap(),
        );
        assert!(
            rejection.reason.contains("one exact assignment"),
            "{}",
            rejection.reason
        );
    }

    #[test]
    fn proved_nullable_assignment_propagates_its_expression_result() {
        let proof = proved(
            prove_generated_query_result_flow(
                r#"
async function load() {
  let saved = null;
  const alias = (saved = await firstPlan.first());
  return alias.name;
}
"#,
                &[seed("first", "load", CallableQueryConsumerKind::First, 1)],
            )
            .unwrap(),
        );
        assert_eq!(
            proof.document_properties().collect::<Vec<_>>(),
            vec![&ProvedQueryDocumentProperty {
                table: "documents".to_string(),
                property: "name".to_string(),
            }]
        );
    }
}
