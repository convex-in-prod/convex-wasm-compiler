pub(super) const EFFECT_VALUE_GRAPH_SHAPE_COUNT: usize = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DependencyAdapterImport {
    None,
    Entry,
    Helper,
}

pub(super) struct EffectValueGraphCase {
    pub source: String,
    pub imported_helper_source: Option<String>,
    pub dependency_adapter_import: DependencyAdapterImport,
    pub guest_mode: bool,
    pub must_admit: bool,
    pub must_fallback: bool,
    pub expected_operation_kinds: Option<Vec<&'static str>>,
    pub semantic_feature: String,
}

struct ByteCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn choose(&mut self, alternatives: usize) -> usize {
        assert!(alternatives > 0);
        let value = self
            .data
            .get(self.offset)
            .copied()
            .unwrap_or_else(|| (self.offset as u8).wrapping_mul(67).wrapping_add(29));
        self.offset += 1;
        value as usize % alternatives
    }
}

#[allow(clippy::too_many_arguments)]
fn semantic_feature(
    family: &str,
    origin: &str,
    topology: &str,
    sink_use: &str,
    call_fact: &str,
    scc: &str,
    depth: &str,
    width_boundary: &str,
    mode: &str,
    expected: &str,
    authority_consumer: &str,
    placement: &str,
    sibling_consumers: &str,
) -> String {
    serde_json::json!({
        "authorityConsumer": authority_consumer,
        "callFactState": call_fact,
        "executionMode": mode,
        "expectedRouting": expected,
        "family": family,
        "helperDepth": depth,
        "origin": origin,
        "placement": placement,
        "scc": scc,
        "siblingConsumers": sibling_consumers,
        "sinkUse": sink_use,
        "stepTopology": topology,
        "widthBoundary": width_boundary,
    })
    .to_string()
}

fn adapter_call(context: &str, owner: &str) -> String {
    format!("getOneFrom({context}.db, \"items\", \"by_owner\", {owner})")
}

fn conditional_adapter_expression(context: &str, arguments: &str, variants: usize) -> String {
    assert!(variants > 0);
    let mut expression = adapter_call(context, &format!("{arguments}.owners[{}]", variants - 1));
    for index in (0..variants - 1).rev() {
        expression = format!(
            "{arguments}.choice === {index} ? {} : ({expression})",
            adapter_call(context, &format!("{arguments}.owners[{index}]")),
        );
    }
    expression
}

fn forward_chain(
    context: &str,
    arguments: &str,
    pending: &str,
    depth: usize,
    metamorph: bool,
) -> (String, String) {
    assert!(depth > 0);
    let prefix = if metamorph { "pass" } else { "forward" };
    let parameter = if metamorph { "operationValue" } else { "value" };
    let mut declarations =
        format!("function {prefix}0({parameter}) {{\n  return {parameter};\n}}\n");
    for index in 1..depth {
        declarations.push_str(&format!(
            "function {prefix}{index}({parameter}) {{\n  return {prefix}{}({parameter});\n}}\n",
            index - 1,
        ));
    }
    let body = format!(
        "const {pending} = {};\n    return await {prefix}{}({pending});",
        adapter_call(context, &format!("{arguments}.owner")),
        depth - 1,
    );
    (declarations, body)
}

pub(super) fn render_effect_value_graph_case(
    index: usize,
    metamorph: bool,
) -> EffectValueGraphCase {
    let context = if metamorph { "requestContext" } else { "ctx" };
    let arguments = if metamorph { "requestArgs" } else { "args" };
    let pending = if metamorph {
        "operationPromise"
    } else {
        "pending"
    };
    let prefix = if metamorph {
        "type GraphPromise = Promise<unknown>;\n/* callable effect/value graph metamorph */\n"
    } else {
        ""
    };
    let shape = index % EFFECT_VALUE_GRAPH_SHAPE_COUNT;
    let (declarations, body, must_admit, expected_operation_kinds) = match shape {
        0 => {
            let expression = conditional_adapter_expression(context, arguments, 4);
            (
                String::new(),
                format!("const {pending} = {expression};\n    return await {pending};"),
                true,
                None,
            )
        }
        1 => (
            String::new(),
            format!(
                "return await Promise.all([{}, {}]);",
                adapter_call(context, &format!("{arguments}.owner")),
                adapter_call(context, &format!("{arguments}.otherOwner")),
            ),
            true,
            Some(vec!["databaseIndexQuery", "databaseIndexQuery"]),
        ),
        2 => {
            let first = if metamorph { "outerPass" } else { "outer" };
            let second = if metamorph { "innerPass" } else { "inner" };
            let value = if metamorph { "operationValue" } else { "value" };
            (
                format!(
                    "function {second}({value}) {{\n  return {value};\n}}\nfunction {first}({value}) {{\n  return {second}({value});\n}}\n"
                ),
                format!(
                    "const {pending} = {};\n    return await {first}({pending});",
                    adapter_call(context, &format!("{arguments}.owner")),
                ),
                true,
                Some(vec!["databaseIndexQuery"]),
            )
        }
        3 => {
            let close = if metamorph { "closeOperation" } else { "close" };
            let bounce = if metamorph {
                "returnOperation"
            } else {
                "bounce"
            };
            let helper_context = if metamorph {
                "forwardedContext"
            } else {
                "helperContext"
            };
            let owner = if metamorph { "ownerValue" } else { "owner" };
            let value = if metamorph { "operationValue" } else { "value" };
            (
                format!(
                    "function {bounce}({value}) {{\n  const alias = {value};\n  return alias;\n}}\nasync function {close}({helper_context}, {owner}) {{\n  const origin = {};\n  const returned = {bounce}(origin);\n  return await returned;\n}}\n",
                    adapter_call(helper_context, owner),
                ),
                format!("return await {close}({context}, {arguments}.owner);"),
                true,
                Some(vec!["databaseIndexQuery"]),
            )
        }
        4 | 5 => {
            let load = if metamorph { "loadOperation" } else { "load" };
            let consume_first = if metamorph {
                "consumeLeft"
            } else {
                "consumeFirst"
            };
            let consume_second = if metamorph {
                "consumeRight"
            } else {
                "consumeSecond"
            };
            let drop_value = if metamorph {
                "dropOperation"
            } else {
                "dropValue"
            };
            let helper_context = if metamorph {
                "forwardedContext"
            } else {
                "helperContext"
            };
            let owner = if metamorph { "ownerValue" } else { "owner" };
            let declarations = format!(
                "function {load}({helper_context}, {owner}) {{\n  return {};\n}}\nasync function {consume_first}({helper_context}, {owner}) {{\n  return await {load}({helper_context}, {owner});\n}}\nasync function {consume_second}({helper_context}, {owner}) {{\n  return await {load}({helper_context}, {owner});\n}}\nfunction {drop_value}({helper_context}, {owner}) {{\n  void {load}({helper_context}, {owner});\n}}\n",
                adapter_call(helper_context, owner),
            );
            let body = if shape == 4 {
                format!(
                    "if ({arguments}.first) return await {consume_first}({context}, {arguments}.owner);\n    return await {consume_second}({context}, {arguments}.otherOwner);"
                )
            } else {
                format!(
                    "{drop_value}({context}, {arguments}.otherOwner);\n    return await {consume_first}({context}, {arguments}.owner);"
                )
            };
            (declarations, body, shape == 4, None)
        }
        6 => {
            let first = if metamorph { "awaitLeft" } else { "awaitFirst" };
            let second = if metamorph {
                "awaitRight"
            } else {
                "awaitSecond"
            };
            let value = if metamorph { "operationValue" } else { "value" };
            (
                format!(
                    "async function {first}({value}) {{ return await {value}; }}\nasync function {second}({value}) {{ return await {value}; }}\n"
                ),
                format!(
                    "const consume = {arguments}.first ? {first} : {second};\n    return await consume({});",
                    adapter_call(context, &format!("{arguments}.owner")),
                ),
                false,
                None,
            )
        }
        7 => {
            let consume = if metamorph {
                "consumeOperation"
            } else {
                "consume"
            };
            let value = if metamorph { "operationValue" } else { "value" };
            (
                format!("async function {consume}({value}) {{ return await {value}; }}\n"),
                format!(
                    "void {consume};\n    return await {consume}({});",
                    adapter_call(context, &format!("{arguments}.owner")),
                ),
                false,
                None,
            )
        }
        8 => {
            let first = if metamorph {
                "recursiveLeft"
            } else {
                "recursiveFirst"
            };
            let second = if metamorph {
                "recursiveRight"
            } else {
                "recursiveSecond"
            };
            let value = if metamorph { "operationValue" } else { "value" };
            (
                format!(
                    "function {first}({value}, depth) {{\n  return depth === 0 ? {value} : {second}({value}, depth - 1);\n}}\nfunction {second}({value}, depth) {{\n  return depth === 0 ? {value} : {first}({value}, depth - 1);\n}}\n"
                ),
                format!(
                    "return await {first}({}, 2);",
                    adapter_call(context, &format!("{arguments}.owner")),
                ),
                false,
                None,
            )
        }
        9 => {
            let recurse = if metamorph {
                "countDown"
            } else {
                "pureRecursive"
            };
            let consume = if metamorph {
                "consumeOperation"
            } else {
                "consume"
            };
            let value = if metamorph { "operationValue" } else { "value" };
            (
                format!(
                    "function {recurse}(depth) {{\n  return depth === 0 ? 0 : {recurse}(depth - 1);\n}}\nfunction {consume}({value}, _depth) {{\n  return {value};\n}}\n"
                ),
                format!(
                    "return await {consume}({}, {recurse}(2));",
                    adapter_call(context, &format!("{arguments}.owner")),
                ),
                true,
                Some(vec!["databaseIndexQuery"]),
            )
        }
        10 | 11 => {
            let depth = if shape == 10 { 3 } else { 8 };
            let (declarations, body) = forward_chain(context, arguments, pending, depth, metamorph);
            (declarations, body, shape == 10, None)
        }
        12 => {
            let expression = conditional_adapter_expression(context, arguments, 33);
            (
                String::new(),
                format!("const {pending} = {expression};\n    return await {pending};"),
                false,
                None,
            )
        }
        13 => {
            let value = if metamorph { "q" } else { "p" };
            let mut body = format!(
                "const {value} = {};\n",
                adapter_call(context, &format!("{arguments}.owner")),
            );
            for _ in 0..1_025 {
                body.push_str("await ");
                body.push_str(value);
                body.push_str(";\n");
            }
            body.push_str("return null;");
            (String::new(), body, false, None)
        }
        _ => {
            let consume = if metamorph {
                "observeOperation"
            } else {
                "observeValue"
            };
            (
                String::new(),
                format!(
                    "const {pending} = {};\n    {consume}({pending});\n    return await {pending};",
                    adapter_call(context, &format!("{arguments}.owner")),
                ),
                false,
                Some(vec!["databaseIndexQuery"]),
            )
        }
    };
    let source = format!(
        "{prefix}import {{ query }} from \"./_generated/server\";\nimport {{ getOneFrom }} from \"invariant-validation-dependency-adapter\";\n{declarations}export const selected = query({{\n  args: {{}},\n  handler: async ({context}, {arguments}) => {{\n    {body}\n  }},\n}});\n"
    );
    EffectValueGraphCase {
        source,
        imported_helper_source: None,
        dependency_adapter_import: DependencyAdapterImport::Entry,
        guest_mode: false,
        must_admit,
        must_fallback: !must_admit,
        expected_operation_kinds,
        semantic_feature: semantic_feature(
            "retained-fixed-graph",
            "dependency-adapter-call-result",
            &format!("fixed-shape-{shape}"),
            if shape == 1 {
                "fixed-promise-all"
            } else if must_admit {
                "authenticated-close"
            } else {
                "blocked-or-incomplete"
            },
            if matches!(shape, 6 | 7 | 14) {
                "dynamic-or-unrepresented"
            } else {
                "exact"
            },
            if shape == 8 {
                "value-carrying"
            } else if shape == 9 {
                "unrelated-safe"
            } else {
                "none"
            },
            match shape {
                10 => "3",
                11 => "8",
                _ => "not-applicable",
            },
            match shape {
                12 => "variant-cap-plus-1:33",
                13 => "route-cap-plus-1:1025",
                _ => "not-applicable",
            },
            "blocking-fiber",
            if must_admit { "admit" } else { "fallback" },
            if shape == 1 {
                "authenticated-fixed-promise-all"
            } else {
                "dependency-adapter"
            },
            "entry-local",
            match shape {
                4 => "complete",
                5 => "incomplete",
                _ => "none",
            },
        ),
    }
}

fn generated_entry_source(prefix: &str, imports: &str, declarations: &str, body: &str) -> String {
    format!(
        "{prefix}import {{ query }} from \"./_generated/server\";\n{imports}{declarations}export const selected = query({{\n  args: {{}},\n  handler: async (ctx, args) => {{\n    {body}\n  }},\n}});\n"
    )
}

fn generated_adapter_call(context: &str, owner: &str) -> String {
    format!("getOneFrom({context}.db, \"items\", \"by_owner\", {owner})")
}

fn generated_forwarders(depth: usize, metamorph: bool) -> (String, String) {
    assert!(depth > 0);
    let prefix = if metamorph { "relay" } else { "pass" };
    let parameter = if metamorph { "operationValue" } else { "value" };
    let mut declarations = String::new();
    for index in 0..depth {
        let returned = if index == 0 {
            parameter.to_string()
        } else {
            format!("{prefix}{}({parameter})", index - 1)
        };
        declarations.push_str(&format!(
            "function {prefix}{index}({parameter}) {{\n  return {returned};\n}}\n"
        ));
    }
    (declarations, format!("{prefix}{}", depth - 1))
}

fn render_parameterized_flow(cursor: &mut ByteCursor<'_>, metamorph: bool) -> EffectValueGraphCase {
    let imported = cursor.choose(2) == 1;
    let depth = cursor.choose(3) + 1;
    let topology_index = cursor.choose(4);
    let use_index = cursor.choose(4);
    let load = if metamorph {
        "loadOperationValue"
    } else {
        "loadOperation"
    };
    let pending = if metamorph {
        "operationPromise"
    } else {
        "pending"
    };
    let (forwarders, last_forwarder) = generated_forwarders(depth, metamorph);
    let load_declaration = format!(
        "{}function {load}(helperContext, owner) {{\n  return {last_forwarder}({});\n}}\n",
        if imported { "export " } else { "" },
        generated_adapter_call("helperContext", "owner"),
    );
    let helper_declarations = format!("{forwarders}{load_declaration}");
    let (imports, declarations, helper_source, dependency_adapter_import) = if imported {
        (
            format!("import {{ {load} }} from \"./invariant_validation_graph_helper.js\";\n"),
            String::new(),
            Some(format!(
                "import {{ getOneFrom }} from \"invariant-validation-dependency-adapter\";\n{helper_declarations}"
            )),
            DependencyAdapterImport::Helper,
        )
    } else {
        (
            "import { getOneFrom } from \"invariant-validation-dependency-adapter\";\n".to_string(),
            helper_declarations,
            None,
            DependencyAdapterImport::Entry,
        )
    };
    let origin = format!("{load}(ctx, args.owner)");
    let body = match use_index {
        0 => match topology_index {
            0 => format!("const {pending} = {origin};\n    return await {pending};"),
            1 => {
                let alias = if metamorph {
                    "forwardedPromise"
                } else {
                    "alias"
                };
                format!(
                    "const {pending} = {origin};\n    const {alias} = {pending};\n    return await {alias};"
                )
            }
            2 => format!(
                "const {pending} = {origin};\n    return await (args.first ? {pending} : {pending});"
            ),
            _ => format!("const {pending} = {origin};\n    return await Promise.all([{pending}]);"),
        },
        1 => format!("return await {load}?.(ctx, args.owner);"),
        2 => {
            let left = if metamorph {
                "awaitLeftValue"
            } else {
                "awaitLeft"
            };
            let right = if metamorph {
                "awaitRightValue"
            } else {
                "awaitRight"
            };
            format!(
                "async function {left}(value) {{ return await value; }}\n    async function {right}(value) {{ return await value; }}\n    const {pending} = {origin};\n    const selectedConsumer = args.first ? {left} : {right};\n    return await selectedConsumer({pending});"
            )
        }
        _ => format!(
            "const {pending} = {origin};\n    observeUnrepresented({pending});\n    return await {pending};"
        ),
    };
    let must_admit = use_index == 0 && depth <= 3;
    let topology = if use_index == 0 {
        [
            "return",
            "return-alias",
            "return-choice",
            "return-promise-child",
        ][topology_index]
    } else {
        "not-applicable"
    };
    let call_fact = [
        "exact",
        "missing-optional-call-result",
        "dynamic-ambiguous",
        "unrepresented",
    ][use_index];
    EffectValueGraphCase {
        source: generated_entry_source(
            if metamorph {
                "type GeneratedGraphPromise = Promise<unknown>;\n/* parameterized graph metamorph */\n"
            } else {
                ""
            },
            &imports,
            &declarations,
            &body,
        ),
        imported_helper_source: helper_source,
        dependency_adapter_import,
        guest_mode: false,
        must_admit,
        must_fallback: !must_admit,
        expected_operation_kinds: must_admit.then(|| vec!["databaseIndexQuery"]),
        semantic_feature: semantic_feature(
            "parameterized-flow",
            "dependency-adapter-call-result",
            topology,
            [
                "await",
                "missing-optional-call-result",
                "dynamic-call-argument",
                "unrepresented-call-and-await",
            ][use_index],
            call_fact,
            "none",
            &depth.to_string(),
            "not-applicable",
            "blocking-fiber",
            if must_admit { "admit" } else { "fallback" },
            if use_index == 0 && topology_index == 3 {
                "authenticated-fixed-promise-all"
            } else {
                "dependency-adapter"
            },
            if imported { "imported" } else { "local" },
            "none",
        ),
    }
}

fn render_parameterized_siblings(
    cursor: &mut ByteCursor<'_>,
    metamorph: bool,
) -> EffectValueGraphCase {
    let imported = cursor.choose(2) == 1;
    let consumer_count = cursor.choose(3) + 2;
    let incomplete = cursor.choose(2) == 1;
    let depth = cursor.choose(3) + 1;
    let load = if metamorph { "loadValue" } else { "load" };
    let drop_value = if metamorph {
        "dropOperationValue"
    } else {
        "dropOperation"
    };
    let (forwarders, last_forwarder) = generated_forwarders(depth, metamorph);
    let export = if imported { "export " } else { "" };
    let mut helper_declarations = format!(
        "{forwarders}function {load}(helperContext, owner) {{\n  return {last_forwarder}({});\n}}\n",
        generated_adapter_call("helperContext", "owner"),
    );
    let mut consumer_names = Vec::new();
    for index in 0..consumer_count {
        let name = if metamorph {
            format!("consumeBranchValue{index}")
        } else {
            format!("consumeBranch{index}")
        };
        helper_declarations.push_str(&format!(
            "{export}async function {name}(helperContext, owner) {{\n  return await {load}(helperContext, owner);\n}}\n"
        ));
        consumer_names.push(name);
    }
    if incomplete {
        helper_declarations.push_str(&format!(
            "{export}function {drop_value}(helperContext, owner) {{\n  void {load}(helperContext, owner);\n}}\n"
        ));
    }
    let (imports, declarations, helper_source, dependency_adapter_import) = if imported {
        let mut imported_names = consumer_names.clone();
        if incomplete {
            imported_names.push(drop_value.to_string());
        }
        (
            format!(
                "import {{ {} }} from \"./invariant_validation_graph_helper.js\";\n",
                imported_names.join(", ")
            ),
            String::new(),
            Some(format!(
                "import {{ getOneFrom }} from \"invariant-validation-dependency-adapter\";\n{helper_declarations}"
            )),
            DependencyAdapterImport::Helper,
        )
    } else {
        (
            "import { getOneFrom } from \"invariant-validation-dependency-adapter\";\n".to_string(),
            helper_declarations,
            None,
            DependencyAdapterImport::Entry,
        )
    };
    let mut branch = format!(
        "return await {}(ctx, args.owners[{}]);",
        consumer_names[consumer_count - 1],
        consumer_count - 1
    );
    for index in (0..consumer_count - 1).rev() {
        branch = format!(
            "if (args.choice === {index}) return await {}(ctx, args.owners[{index}]);\n    {branch}",
            consumer_names[index],
        );
    }
    let body = if incomplete {
        format!("{drop_value}(ctx, args.owner);\n    {branch}")
    } else {
        branch
    };
    let must_admit = !incomplete;
    EffectValueGraphCase {
        source: generated_entry_source(
            if metamorph {
                "/* complete-inbound graph metamorph */\n"
            } else {
                ""
            },
            &imports,
            &declarations,
            &body,
        ),
        imported_helper_source: helper_source,
        dependency_adapter_import,
        guest_mode: false,
        must_admit,
        must_fallback: !must_admit,
        expected_operation_kinds: None,
        semantic_feature: semantic_feature(
            "parameterized-inbound-callers",
            "dependency-adapter-call-result",
            "helper-return-to-branch-consumers",
            if incomplete {
                "await-plus-dropped-sibling"
            } else {
                "awaited-branches"
            },
            if incomplete {
                "incomplete-inbound"
            } else {
                "complete-inbound"
            },
            "none",
            &depth.to_string(),
            &format!("consumer-count:{consumer_count}"),
            "blocking-fiber",
            if must_admit { "admit" } else { "fallback" },
            "dependency-adapter",
            if imported { "imported" } else { "local" },
            if incomplete { "incomplete" } else { "complete" },
        ),
    }
}

fn render_parameterized_scc(cursor: &mut ByteCursor<'_>, metamorph: bool) -> EffectValueGraphCase {
    let value_carrying = cursor.choose(2) == 1;
    let runtime_depth = cursor.choose(3) + 1;
    let value = if metamorph { "operationValue" } else { "value" };
    let (declarations, body) = if value_carrying {
        let left = if metamorph {
            "recursiveLeftValue"
        } else {
            "recursiveLeft"
        };
        let right = if metamorph {
            "recursiveRightValue"
        } else {
            "recursiveRight"
        };
        (
            format!(
                "function {left}({value}, depth) {{\n  return depth === 0 ? {value} : {right}({value}, depth - 1);\n}}\nfunction {right}({value}, depth) {{\n  return depth === 0 ? {value} : {left}({value}, depth - 1);\n}}\n"
            ),
            format!(
                "return await {left}({}, {runtime_depth});",
                generated_adapter_call("ctx", "args.owner")
            ),
        )
    } else {
        let recurse = if metamorph {
            "countPureDepth"
        } else {
            "pureRecursive"
        };
        let consume = if metamorph {
            "consumeOperationValue"
        } else {
            "consumeOperation"
        };
        (
            format!(
                "function {recurse}(depth) {{\n  return depth === 0 ? 0 : {recurse}(depth - 1);\n}}\nfunction {consume}({value}, _depth) {{\n  return {value};\n}}\n"
            ),
            format!(
                "return await {consume}({}, {recurse}({runtime_depth}));",
                generated_adapter_call("ctx", "args.owner")
            ),
        )
    };
    let must_admit = !value_carrying;
    EffectValueGraphCase {
        source: generated_entry_source(
            if metamorph {
                "/* recursive-graph metamorph */\n"
            } else {
                ""
            },
            "import { getOneFrom } from \"invariant-validation-dependency-adapter\";\n",
            &declarations,
            &body,
        ),
        imported_helper_source: None,
        dependency_adapter_import: DependencyAdapterImport::Entry,
        guest_mode: false,
        must_admit,
        must_fallback: !must_admit,
        expected_operation_kinds: must_admit.then(|| vec!["databaseIndexQuery"]),
        semantic_feature: semantic_feature(
            "parameterized-scc",
            "dependency-adapter-call-result",
            if value_carrying {
                "recursive-value-forwarding"
            } else {
                "unrelated-recursive-argument"
            },
            "await",
            "exact",
            if value_carrying {
                "value-carrying"
            } else {
                "unrelated-safe"
            },
            &runtime_depth.to_string(),
            "not-applicable",
            "blocking-fiber",
            if must_admit { "admit" } else { "fallback" },
            "dependency-adapter",
            "local",
            "none",
        ),
    }
}

fn render_parameterized_variant_boundary(
    cursor: &mut ByteCursor<'_>,
    metamorph: bool,
) -> EffectValueGraphCase {
    let boundary_index = cursor.choose(3);
    let variants = [31, 32, 33][boundary_index];
    let context = if metamorph { "requestContext" } else { "ctx" };
    let arguments = if metamorph { "requestArgs" } else { "args" };
    let pending = if metamorph {
        "operationPromise"
    } else {
        "pending"
    };
    let expression = conditional_adapter_expression(context, arguments, variants);
    let body = format!("const {pending} = {expression};\n    return await {pending};");
    let must_admit = variants <= 32;
    EffectValueGraphCase {
        source: format!(
            "{}import {{ query }} from \"./_generated/server\";\nimport {{ getOneFrom }} from \"invariant-validation-dependency-adapter\";\nexport const selected = query({{\n  args: {{}},\n  handler: async ({context}, {arguments}) => {{\n    {body}\n  }},\n}});\n",
            if metamorph {
                "/* variant-boundary graph metamorph */\n"
            } else {
                ""
            }
        ),
        imported_helper_source: None,
        dependency_adapter_import: DependencyAdapterImport::Entry,
        guest_mode: false,
        must_admit,
        must_fallback: !must_admit,
        expected_operation_kinds: None,
        semantic_feature: semantic_feature(
            "parameterized-variant-boundary",
            "dependency-adapter-call-result",
            "conditional-choice",
            "await",
            "exact",
            "none",
            "0",
            [
                "variant-cap-minus-1:31",
                "variant-cap:32",
                "variant-cap-plus-1:33",
            ][boundary_index],
            "blocking-fiber",
            if must_admit { "admit" } else { "fallback" },
            "dependency-adapter",
            "local",
            "none",
        ),
    }
}

fn render_parameterized_route_boundary(
    cursor: &mut ByteCursor<'_>,
    metamorph: bool,
) -> EffectValueGraphCase {
    let boundary_index = cursor.choose(3);
    let route_count = [1_023, 1_024, 1_025][boundary_index];
    let pending = if metamorph { "q" } else { "p" };
    let mut body = format!(
        "const {pending} = {};\n",
        generated_adapter_call("ctx", "args.owner")
    );
    for _ in 0..route_count {
        body.push_str("await ");
        body.push_str(pending);
        body.push_str(";\n");
    }
    body.push_str("return null;");
    let must_admit = route_count <= 1_024;
    EffectValueGraphCase {
        source: generated_entry_source(
            if metamorph {
                "/* route-boundary graph metamorph */\n"
            } else {
                ""
            },
            "import { getOneFrom } from \"invariant-validation-dependency-adapter\";\n",
            "",
            &body,
        ),
        imported_helper_source: None,
        dependency_adapter_import: DependencyAdapterImport::Entry,
        guest_mode: false,
        must_admit,
        must_fallback: !must_admit,
        expected_operation_kinds: must_admit.then(|| vec!["databaseIndexQuery"]),
        semantic_feature: semantic_feature(
            "parameterized-route-boundary",
            "dependency-adapter-call-result",
            "repeated-await-routes",
            "await",
            "exact",
            "none",
            "0",
            [
                "route-cap-minus-1:1023",
                "route-cap:1024",
                "route-cap-plus-1:1025",
            ][boundary_index],
            "blocking-fiber",
            if must_admit { "admit" } else { "fallback" },
            "dependency-adapter",
            "local",
            "none",
        ),
    }
}

fn render_parameterized_guest(
    cursor: &mut ByteCursor<'_>,
    metamorph: bool,
) -> EffectValueGraphCase {
    let imported = cursor.choose(2) == 1;
    let depth = cursor.choose(4) + 1;
    let topology_index = cursor.choose(3);
    let closure_index = cursor.choose(3);
    let load = if metamorph {
        "loadGuestOperation"
    } else {
        "loadGuest"
    };
    let pending = if metamorph {
        "operationPromise"
    } else {
        "pending"
    };
    let (forwarders, last_forwarder) = generated_forwarders(depth, metamorph);
    let (
        load_declaration,
        must_admit,
        expected_operation_kinds,
        closure_topology,
        sink_use,
        call_fact,
    ) = match closure_index {
        0 => (
            format!(
                "{}async function {load}(helperContext, id) {{\n  return await helperContext.db.get(\"items\", id);\n}}\n",
                if imported { "export " } else { "" },
            ),
            true,
            Some(vec!["databaseGet"]),
            "helper-return",
            "await",
            "exact",
        ),
        1 => (
            format!(
                "{}function {load}(helperContext, id) {{\n  helperContext.db.get(\"items\", id);\n  return null;\n}}\n",
                if imported { "export " } else { "" },
            ),
            false,
            None,
            "detached-effect",
            "unclosed",
            "exact",
        ),
        _ => (
            format!(
                "{}async function {load}(helperContext, id) {{\n  const pending = helperContext.db.get(\"items\", id);\n  JSON.stringify(pending);\n  return await pending;\n}}\n",
                if imported { "export " } else { "" },
            ),
            false,
            None,
            "helper-return-json-escape",
            "await-after-escape",
            "unrepresented",
        ),
    };
    let helper_declarations = format!("{forwarders}{load_declaration}");
    let (imports, declarations, helper_source) = if imported {
        (
            format!("import {{ {load} }} from \"./invariant_validation_graph_helper.js\";\n"),
            forwarders,
            Some(load_declaration),
        )
    } else {
        (String::new(), helper_declarations, None)
    };
    let origin = format!("{last_forwarder}({load}(ctx, args.id))");
    let outer_topology = [
        "helper-return",
        "helper-return-alias",
        "helper-return-choice",
    ][topology_index];
    let step_topology = format!("{outer_topology}-{closure_topology}");
    let body = match topology_index {
        0 => format!("return await {origin};"),
        1 => format!("const {pending} = {origin};\n    return await {pending};"),
        _ => format!(
            "const {pending} = {origin};\n    return await (args.first ? {pending} : {pending});"
        ),
    };
    // Guest effect sites only admit a direct await. Same-block aliases need intra-block ordering
    // proof that the guest closure analysis intentionally does not provide.
    let must_admit = must_admit && topology_index == 0;
    let expected_operation_kinds = must_admit.then(|| expected_operation_kinds).flatten();
    EffectValueGraphCase {
        source: generated_entry_source(
            if metamorph {
                "/* guest-effect graph metamorph */\n"
            } else {
                ""
            },
            &imports,
            &declarations,
            &body,
        ),
        imported_helper_source: helper_source,
        dependency_adapter_import: DependencyAdapterImport::None,
        guest_mode: true,
        must_admit,
        must_fallback: !must_admit,
        expected_operation_kinds,
        semantic_feature: semantic_feature(
            "parameterized-guest-effect-closure",
            "plan-owned-effect-site",
            &step_topology,
            sink_use,
            call_fact,
            "none",
            &depth.to_string(),
            "not-applicable",
            "guest-promise-event-loop",
            if must_admit { "admit" } else { "fallback" },
            "authenticated-effect-value-closure",
            if imported { "imported" } else { "local" },
            "none",
        ),
    }
}

pub(super) fn render_parameterized_effect_value_graph_case(
    data: &[u8],
    metamorph: bool,
) -> EffectValueGraphCase {
    let mut cursor = ByteCursor::new(data);
    match cursor.choose(16) {
        0 | 7 | 8 | 13 | 15 => render_parameterized_flow(&mut cursor, metamorph),
        1 | 9 => render_parameterized_siblings(&mut cursor, metamorph),
        2 | 10 => render_parameterized_scc(&mut cursor, metamorph),
        3 | 11 => render_parameterized_variant_boundary(&mut cursor, metamorph),
        4 => render_parameterized_route_boundary(&mut cursor, metamorph),
        5 | 6 | 12 | 14 => render_parameterized_guest(&mut cursor, metamorph),
        _ => render_parameterized_guest(&mut cursor, metamorph),
    }
}
