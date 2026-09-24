use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::adapter_material::{
    DependencyAdapterDescriptorEntry, RegistrationAdapterDescriptorEntry,
    RegistrationAdapterSourceOperation,
};
use super::callable_value_flow::AuthenticatedEffectValueGraph;
use super::source_graph::is_resolved_convex_server_module;
use super::{
    Diagnostic, GraphInput, ImportBinding, IndexConstraintCandidate, LoadedModule,
    OperationCandidate, OperationIdentity, ReferenceOccurrence, RegistrationSummary, SourceRange,
    canonical_index_query_shape, checked_module_path, diagnostic_at, generated_server_udf_kind,
    hash_bytes, is_resolved_generated_server_module, module_source, resolve_graph_import,
    source_range_string, source_slice,
};

#[derive(Clone)]
pub(super) struct AppliedRegistrationAdapter {
    pub(super) descriptor: RegistrationAdapterDescriptorEntry,
    pub(super) wrapper_module: String,
    pub(super) wrapper_specifier: String,
    pub(super) wrapper_unit_name: String,
    pub(super) wrapper_unit_source_sha256: String,
    pub(super) helper_module: String,
    pub(super) helper_unit_name: String,
    pub(super) helper_unit_source_sha256: String,
    pub(super) helper_parameter_start: u32,
}

#[derive(Clone)]
pub(super) struct AppliedSourceOperation {
    pub(super) descriptor: RegistrationAdapterSourceOperation,
    pub(super) importer_module: String,
    pub(super) importer_unit_id: String,
    pub(super) call_start: u32,
    pub(super) call_end: u32,
    pub(super) callee_end: u32,
    pub(super) helper_unit_source_sha256: String,
    pub(super) operation_id: u32,
}

#[derive(Clone)]
pub(super) struct AppliedDependencyAdapterCall {
    pub(super) descriptor: DependencyAdapterDescriptorEntry,
    pub(super) importer_module: String,
    pub(super) importer_unit_id: String,
    pub(super) dependency_chain: Vec<String>,
    pub(super) callee_start: u32,
    pub(super) callee_end: u32,
    pub(super) call_start: u32,
    pub(super) call_end: u32,
    pub(super) effect_start: u32,
    pub(super) effect_end: u32,
    pub(super) effect_path: String,
    pub(super) operation: OperationCandidate,
    pub(super) dynamic_arguments: Vec<SourceRange>,
    pub(super) represented_global_spans: Vec<SourceRange>,
    pub(super) generated_function_name: String,
}

pub(super) struct DependencyAdapterCallIndex<'a> {
    pub(super) calls: &'a [AppliedDependencyAdapterCall],
    calls_by_importer_unit:
        BTreeMap<&'a str, BTreeMap<&'a str, Vec<&'a AppliedDependencyAdapterCall>>>,
    calls_by_span: BTreeMap<&'a str, BTreeMap<(u32, u32), &'a AppliedDependencyAdapterCall>>,
    represented_global_spans: BTreeMap<&'a str, BTreeMap<&'a str, BTreeSet<(u32, u32)>>>,
}

impl<'a> DependencyAdapterCallIndex<'a> {
    pub(super) fn new(calls: &'a [AppliedDependencyAdapterCall]) -> Self {
        let mut calls_by_importer_unit = BTreeMap::new();
        let mut calls_by_span = BTreeMap::new();
        let mut represented_global_spans = BTreeMap::new();
        for call in calls {
            calls_by_importer_unit
                .entry(call.importer_module.as_str())
                .or_insert_with(BTreeMap::new)
                .entry(call.importer_unit_id.as_str())
                .or_insert_with(Vec::new)
                .push(call);
            assert!(
                calls_by_span
                    .entry(call.importer_module.as_str())
                    .or_insert_with(BTreeMap::new)
                    .insert((call.call_start, call.call_end), call)
                    .is_none(),
                "validated dependency adapter call span is duplicated"
            );
            for span in &call.represented_global_spans {
                represented_global_spans
                    .entry(call.importer_module.as_str())
                    .or_insert_with(BTreeMap::new)
                    .entry(call.importer_unit_id.as_str())
                    .or_insert_with(BTreeSet::new)
                    .insert((span.start, span.end));
            }
        }
        Self {
            calls,
            calls_by_importer_unit,
            calls_by_span,
            represented_global_spans,
        }
    }

    pub(super) fn calls_for(
        &self,
        module: &str,
        unit_id: &str,
    ) -> &[&'a AppliedDependencyAdapterCall] {
        self.calls_by_importer_unit
            .get(module)
            .and_then(|units| units.get(unit_id))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(super) fn call_at(
        &self,
        module: &str,
        start: u32,
        end: u32,
    ) -> Option<&'a AppliedDependencyAdapterCall> {
        self.calls_by_span
            .get(module)
            .and_then(|spans| spans.get(&(start, end)))
            .copied()
    }

    pub(super) fn represents_global(
        &self,
        module: &str,
        unit_id: &str,
        start: u32,
        end: u32,
    ) -> bool {
        self.represented_global_spans
            .get(module)
            .and_then(|units| units.get(unit_id))
            .is_some_and(|spans| spans.contains(&(start, end)))
    }
}

pub(super) fn diagnose_dependency_adapter_effect_value_flow(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    calls: &[AppliedDependencyAdapterCall],
    effect_values: &AuthenticatedEffectValueGraph,
    batch_closures: &BTreeSet<OperationIdentity>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<()> {
    for call in calls {
        if effect_values.closes_call_result(
            &call.importer_module,
            call.call_start,
            call.call_end,
            batch_closures,
        ) {
            continue;
        }
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-dependency-adapter-suspension",
            format!(
                "adapter {} result does not reach an authenticated await or handler return through exact callable value flow",
                call.descriptor.id
            ),
            &call.importer_module,
            call.call_start,
            Some(call.descriptor.semantic.kind.clone()),
            call.dependency_chain.clone(),
        )?);
    }
    Ok(())
}

pub(super) struct DependencyAdapterAuthenticationFailure {
    code: &'static str,
    message: String,
    module: Option<String>,
    start: Option<u32>,
    construct: String,
}

pub(super) type DependencyAdapterAuthenticationCache =
    BTreeMap<String, Option<DependencyAdapterAuthenticationFailure>>;

pub(super) fn apply_registration_adapter(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    registration: &mut RegistrationSummary,
    dependency_chain: &[String],
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Option<AppliedRegistrationAdapter>> {
    let ordinary_registration_spelling = matches!(
        registration.kind.as_str(),
        "internalQuery" | "query" | "internalMutation" | "mutation"
    );
    let entry = modules
        .get(&graph.entry_path)
        .context("registration adapter entry module disappeared")?;
    let Some(binding) = entry.summary.imports.get(&registration.builder_local) else {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-registration-builder",
            format!(
                "registration builder {} is not {}",
                registration.builder_local,
                if ordinary_registration_spelling {
                    "an imported generated Convex server binding"
                } else {
                    "an imported binding with an authenticated adapter"
                }
            ),
            &graph.entry_path,
            registration.builder_start,
            Some("CallExpression".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    };
    if binding.type_only {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-registration-builder",
            "registration builder is imported as a type-only binding".to_string(),
            &graph.entry_path,
            registration.builder_start,
            Some("ImportDeclaration".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    }
    let exact_binding_reference = entry.summary.references.iter().any(|reference| {
        reference.name == registration.builder_local
            && reference.start == registration.builder_start
            && reference.end == registration.builder_end
            && reference.read
            && !reference.write
    });
    if !exact_binding_reference {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            if ordinary_registration_spelling {
                "unsupported-registration-builder"
            } else {
                "registration-adapter-binding-mismatch"
            },
            "registration builder call does not resolve to the exact imported binding".to_string(),
            &graph.entry_path,
            registration.builder_start,
            Some("Identifier".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    }
    let resolved = resolve_graph_import(graph, &graph.entry_path, &binding.specifier)?;
    if is_resolved_generated_server_module(&resolved, &graph.functions_root)
        && let Some(udf_kind) = generated_server_udf_kind(&binding.imported)
    {
        // The imported generated-server name is the authority. Local aliases have no registration
        // meaning until this exact binding and read reference prove their canonical kind.
        registration.kind.clone_from(&binding.imported);
        if matches!(udf_kind, "query" | "mutation") {
            return Ok(None);
        }
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-registration-builder",
            format!(
                "generated Convex server registration builder {} has unsupported kind {udf_kind}",
                binding.imported
            ),
            &graph.entry_path,
            registration.builder_start,
            Some("ImportDeclaration".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    }
    let matches = graph
        .registration_adapter
        .descriptor
        .adapters
        .iter()
        .filter(|adapter| {
            adapter.wrapper.module_path == resolved
                && adapter.wrapper.export_name == binding.imported
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unmatched-registration-adapter",
            format!(
                "registration import {} from {} resolves to {}#{} but has {} authenticated adapters",
                binding.local,
                binding.specifier,
                resolved,
                binding.imported,
                matches.len()
            ),
            &graph.entry_path,
            registration.builder_start,
            Some("ImportDeclaration".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    }
    let descriptor = matches[0].clone();
    // Preserve the authenticated Convex kind when later adapter validation rejects the source.
    // That export must produce a normal diagnostic fallback instead of reaching the ordinary
    // registration-kind assertion with the application's wrapper binding name.
    registration.kind.clone_from(&descriptor.registration_kind);
    let helper_module_path = descriptor.authentication.helper.module_path.clone();
    let Some(wrapper_module) = modules.get(&resolved) else {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "registration-adapter-wrapper-missing",
            format!(
                "adapter {} wrapper module is absent from the authenticated graph",
                descriptor.id
            ),
            &graph.entry_path,
            registration.builder_start,
            Some("ImportDeclaration".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    };
    let wrapper_unit = wrapper_module
        .summary
        .exports
        .get(&descriptor.wrapper.export_name)
        .and_then(|local| wrapper_module.summary.units.get(local));
    let Some(wrapper_unit) = wrapper_unit else {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "registration-adapter-wrapper-missing",
            format!(
                "adapter {} wrapper export {} has no runtime unit",
                descriptor.id, descriptor.wrapper.export_name
            ),
            &resolved,
            binding.start,
            Some("ExportNamedDeclaration".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    };
    let wrapper_unit_source_sha256 = hash_bytes(wrapper_unit.source.as_bytes());
    if wrapper_unit_source_sha256 != descriptor.wrapper.source_sha256 {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "registration-adapter-wrapper-source-mismatch",
            format!(
                "adapter {} wrapper source digest is {}, expected {}",
                descriptor.id, wrapper_unit_source_sha256, descriptor.wrapper.source_sha256
            ),
            &resolved,
            wrapper_unit.start,
            Some(wrapper_unit.kind.clone()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    }
    let Some(helper_module) = modules.get(&descriptor.authentication.helper.module_path) else {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "registration-adapter-helper-missing",
            format!(
                "adapter {} authentication helper module is absent from the authenticated graph",
                descriptor.id
            ),
            &resolved,
            wrapper_unit.start,
            Some(wrapper_unit.kind.clone()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    };
    let helper_unit = helper_module
        .summary
        .exports
        .get(&descriptor.authentication.helper.export_name)
        .and_then(|local| helper_module.summary.units.get(local));
    let Some(helper_unit) = helper_unit else {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "registration-adapter-helper-missing",
            format!(
                "adapter {} authentication helper export {} has no runtime unit",
                descriptor.id, descriptor.authentication.helper.export_name
            ),
            &descriptor.authentication.helper.module_path,
            0,
            Some("ExportNamedDeclaration".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    };
    let helper_unit_source_sha256 = hash_bytes(helper_unit.source.as_bytes());
    if helper_unit_source_sha256 != descriptor.authentication.helper.source_sha256 {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "registration-adapter-helper-source-mismatch",
            format!(
                "adapter {} authentication helper source digest is {}, expected {}",
                descriptor.id,
                helper_unit_source_sha256,
                descriptor.authentication.helper.source_sha256
            ),
            &descriptor.authentication.helper.module_path,
            helper_unit.start,
            Some(helper_unit.kind.clone()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    }
    let Some(helper_context_parameter) = helper_unit.parameters.first() else {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "registration-adapter-helper-shape-mismatch",
            format!(
                "adapter {} authentication helper has no context parameter",
                descriptor.id
            ),
            &descriptor.authentication.helper.module_path,
            helper_unit.start,
            Some(helper_unit.kind.clone()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    };
    if registration.handler_type != "ArrowFunctionExpression" {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "registration-adapter-handler-shape-mismatch",
            format!(
                "adapter {} requires an inline arrow callback to preserve callback receiver semantics",
                descriptor.id
            ),
            &graph.entry_path,
            registration.handler_start,
            Some(registration.handler_type.clone()),
            dependency_chain.to_vec(),
        )?);
        return Ok(None);
    }
    Ok(Some(AppliedRegistrationAdapter {
        descriptor,
        wrapper_module: resolved,
        wrapper_specifier: binding.specifier.clone(),
        wrapper_unit_name: wrapper_unit.name.clone(),
        wrapper_unit_source_sha256,
        helper_module: helper_module_path,
        helper_unit_name: helper_unit.name.clone(),
        helper_unit_source_sha256,
        helper_parameter_start: helper_context_parameter.start,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn adapt_source_operation(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    importer_module: &str,
    importer_unit_id: &str,
    unit_start: u32,
    unit_end: u32,
    binding: &ImportBinding,
    resolved: &str,
    reference: &ReferenceOccurrence,
    dependency_chain: &[String],
    applied: &mut Vec<AppliedSourceOperation>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<bool> {
    let matching = graph
        .registration_adapter
        .descriptor
        .source_operations
        .iter()
        .filter(|operation| {
            operation.helper.module_path == resolved
                && operation.helper.export_name == binding.imported
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Ok(false);
    }
    ensure!(
        matching.len() == 1,
        "validated registration source operation helper identity became ambiguous"
    );
    let descriptor = matching[0];
    let fail = |code: &'static str, message: String, diagnostics: &mut Vec<Diagnostic>| {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            code,
            message,
            importer_module,
            reference.start,
            Some("CallExpression".to_string()),
            dependency_chain.to_vec(),
        )?);
        Ok::<bool, anyhow::Error>(true)
    };
    if binding.local != binding.imported {
        return fail(
            "source-operation-import-alias",
            format!(
                "authenticated source helper {}#{} must be imported without an alias",
                resolved, binding.imported
            ),
            diagnostics,
        );
    }
    let helper_module = modules.get(resolved).with_context(|| {
        format!("authenticated source helper module {resolved} is absent from the source graph")
    })?;
    let Some(helper_unit) = helper_module
        .summary
        .exports
        .get(&binding.imported)
        .and_then(|local| helper_module.summary.units.get(local))
    else {
        return fail(
            "source-operation-helper-missing",
            format!(
                "authenticated source helper {}#{} has no runtime unit",
                resolved, binding.imported
            ),
            diagnostics,
        );
    };
    let helper_unit_source_sha256 = hash_bytes(helper_unit.source.as_bytes());
    if helper_unit_source_sha256 != descriptor.helper.source_sha256 {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "source-operation-helper-source-mismatch",
            format!(
                "authenticated source helper {}#{} source digest is {}, expected {}",
                resolved,
                binding.imported,
                helper_unit_source_sha256,
                descriptor.helper.source_sha256
            ),
            resolved,
            helper_unit.start,
            Some(helper_unit.kind.clone()),
            dependency_chain.to_vec(),
        )?);
        return Ok(true);
    }
    let importer = modules
        .get(importer_module)
        .context("source operation importer disappeared")?;
    let invocations = importer
        .summary
        .direct_identifier_invocations
        .iter()
        .filter(|invocation| {
            invocation.callee == binding.local
                && invocation.callee_start == reference.start
                && invocation.callee_end == reference.end
                && invocation.start >= unit_start
                && invocation.end <= unit_end
        })
        .collect::<Vec<_>>();
    let [invocation] = invocations.as_slice() else {
        return fail(
            "source-operation-nondirect-use",
            format!(
                "authenticated source helper {} must be used as one exact direct call statement",
                binding.imported
            ),
            diagnostics,
        );
    };
    if invocation.constructor || invocation.argument_count != 1 || invocation.has_spread_argument {
        return fail(
            "source-operation-call-shape",
            format!(
                "authenticated source helper {} requires one direct non-spread argument",
                binding.imported
            ),
            diagnostics,
        );
    }
    if importer
        .source
        .as_bytes()
        .get(invocation.callee_end as usize)
        != Some(&b'(')
        || importer
            .source
            .as_bytes()
            .get(invocation.end.saturating_sub(1) as usize)
            != Some(&b')')
    {
        return fail(
            "source-operation-call-shape",
            format!(
                "authenticated source helper {} requires exact direct-call syntax",
                binding.imported
            ),
            diagnostics,
        );
    }
    let exact_statement = importer.summary.constructs.iter().any(|construct| {
        construct.kind == "ExpressionStatement"
            && construct.start == invocation.start
            && construct.end >= invocation.end
            && construct.end <= unit_end
            && source_slice(&importer.source, invocation.end, construct.end)
                .is_ok_and(|suffix| matches!(suffix.trim(), "" | ";"))
    });
    if !exact_statement {
        return fail(
            "source-operation-statement-shape",
            format!(
                "authenticated source helper {} call must be a direct expression statement",
                binding.imported
            ),
            diagnostics,
        );
    }
    applied.push(AppliedSourceOperation {
        descriptor: descriptor.clone(),
        importer_module: importer_module.to_string(),
        importer_unit_id: importer_unit_id.to_string(),
        call_start: invocation.start,
        call_end: invocation.end,
        callee_end: invocation.callee_end,
        helper_unit_source_sha256,
        operation_id: 0,
    });
    Ok(true)
}

pub(super) fn dependency_adapter_material_drift(
    graph: &GraphInput,
    descriptor: &DependencyAdapterDescriptorEntry,
) -> Option<String> {
    let expected = &descriptor.material;
    let current_file = |path: &str| {
        graph
            .dependency_adapter
            .current
            .files
            .iter()
            .find(|file| file.path == path)
    };
    let Some(module) = current_file(&descriptor.export_identity.module_path) else {
        return Some(format!(
            "resolved module {} has no authenticated current file material",
            descriptor.export_identity.module_path
        ));
    };
    if module.sha256 != expected.module_source_sha256 {
        return Some(format!(
            "resolved module source digest is {}, expected {}",
            module.sha256, expected.module_source_sha256
        ));
    }
    let Some(package) = current_file(&expected.package_json.path) else {
        return Some(format!(
            "package manifest {} has no authenticated current file material",
            expected.package_json.path
        ));
    };
    if package.sha256 != expected.package_json.sha256 {
        return Some(format!(
            "package manifest {} digest is {}, expected {}",
            expected.package_json.path, package.sha256, expected.package_json.sha256
        ));
    }
    for source in &expected.semantic_sources {
        let Some(current) = current_file(&source.path) else {
            return Some(format!(
                "semantic source {} has no authenticated current file material",
                source.path
            ));
        };
        if current.sha256 != source.source_sha256 {
            return Some(format!(
                "semantic source {} digest is {}, expected {}",
                source.path, current.sha256, source.source_sha256
            ));
        }
    }
    let package_version = checked_module_path(&graph.repo_root, &expected.package_json.path)
        .ok()
        .and_then(|path| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    if package_version.as_deref() != Some(expected.package_json.version.as_str()) {
        return Some(format!(
            "package manifest {} version is {:?}, expected {}",
            expected.package_json.path, package_version, expected.package_json.version
        ));
    }
    for expected_lock in [&expected.package_lock, &expected.installed_lock] {
        let Some(current) = graph.dependency_adapter.current.locks.iter().find(|lock| {
            lock.path == expected_lock.path && lock.package_key == expected_lock.package_key
        }) else {
            return Some(format!(
                "lock {} has no authenticated packages[{}] material",
                expected_lock.path, expected_lock.package_key
            ));
        };
        if current.entry_sha256 != expected_lock.entry_sha256 {
            return Some(format!(
                "lock {} packages[{}] digest is {}, expected {}",
                expected_lock.path,
                expected_lock.package_key,
                current.entry_sha256,
                expected_lock.entry_sha256
            ));
        }
    }
    None
}

pub(super) fn dependency_adapter_iterable_is_owned(
    graph: &GraphInput,
    module_key: &str,
    module: &LoadedModule,
    registration: &RegistrationSummary,
    unit_start: u32,
    unit_end: u32,
    range: &SourceRange,
    call_start: u32,
    visited: &mut BTreeSet<(u32, u32)>,
    represented_globals: &mut BTreeSet<(u32, u32)>,
) -> bool {
    if !visited.insert((range.start, range.end)) {
        return false;
    }
    if let Some(iterable) = module
        .summary
        .static_iterables
        .iter()
        .find(|iterable| iterable.start == range.start && iterable.end == range.end)
    {
        if iterable.kind == "array" {
            return true;
        }
        if iterable.kind == "set"
            && iterable
                .global_start
                .zip(iterable.global_end)
                .is_some_and(|(start, end)| {
                    module.summary.globals.iter().any(|global| {
                        global.name == "Set"
                            && global.read
                            && !global.write
                            && global.start == start
                            && global.end == end
                    })
                })
        {
            let source_is_owned = match iterable.source_start.zip(iterable.source_end) {
                None => true,
                Some((start, end)) => dependency_adapter_iterable_is_owned(
                    graph,
                    module_key,
                    module,
                    registration,
                    unit_start,
                    unit_end,
                    &SourceRange { start, end },
                    call_start,
                    visited,
                    represented_globals,
                ),
            };
            if source_is_owned {
                represented_globals.insert((
                    iterable
                        .global_start
                        .expect("authenticated Set global start"),
                    iterable.global_end.expect("authenticated Set global end"),
                ));
            }
            return source_is_owned;
        }
    }
    if module_key == graph.entry_path
        && unit_start == registration.handler_start
        && unit_end == registration.handler_end
        && let Some(access) = module.summary.static_member_accesses.iter().find(|access| {
            access.start == range.start
                && access.end == range.end
                && registration.argument_parameter.as_ref() == Some(&access.root)
                && registration
                    .array_argument_fields
                    .contains(&access.first_field)
        })
    {
        return registration.argument_references.iter().any(|reference| {
            reference.read
                && !reference.write
                && reference.start == access.root_start
                && reference.end == access.root_end
        });
    }
    let owned_set = module.summary.local_set_bindings.iter().find(|binding| {
        binding.enclosing_function_start == Some(unit_start)
            && binding.enclosing_function_end == Some(unit_end)
            && binding.binding_start < call_start
            && module.summary.globals.iter().any(|global| {
                global.name == "Set"
                    && global.read
                    && !global.write
                    && global.start == binding.set_global_start
                    && global.end == binding.set_global_end
            })
            && binding.references.iter().any(|reference| {
                reference.read
                    && !reference.write
                    && reference.start == range.start
                    && reference.end == range.end
            })
            && binding.references.iter().all(|reference| {
                reference.read
                    && !reference.write
                    && ((reference.start == range.start && reference.end == range.end)
                        || module.summary.static_member_calls.iter().any(|call| {
                            call.root == binding.name
                                && call.first_field == "add"
                                && call.root_start == reference.start
                                && call.root_end == reference.end
                                && call.end < call_start
                        })
                        || module.summary.static_member_accesses.iter().any(|access| {
                            access.root == binding.name
                                && access.first_field == "size"
                                && access.root_start == reference.start
                                && access.root_end == reference.end
                        }))
            })
    });
    if let Some(binding) = owned_set {
        represented_globals.insert((binding.set_global_start, binding.set_global_end));
        true
    } else {
        false
    }
}

fn authenticate_dependency_adapter(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    descriptor: &DependencyAdapterDescriptorEntry,
    resolved: &str,
) -> Result<Option<DependencyAdapterAuthenticationFailure>> {
    let target_module = modules
        .get(resolved)
        .context("dependency adapter resolved module was not preloaded")?;
    let target_unit = target_module
        .summary
        .exports
        .get(&descriptor.export_identity.export_name)
        .and_then(|local| target_module.summary.units.get(local));
    let Some(target_unit) = target_unit else {
        return Ok(Some(DependencyAdapterAuthenticationFailure {
            code: "dependency-adapter-export-missing",
            message: format!(
                "adapter {} resolved export {}#{} has no runtime unit",
                descriptor.id, resolved, descriptor.export_identity.export_name
            ),
            module: None,
            start: None,
            construct: "ImportDeclaration".to_string(),
        }));
    };
    let actual_unit_sha256 = hash_bytes(target_unit.source.as_bytes());
    if actual_unit_sha256 != descriptor.export_identity.unit_source_sha256 {
        return Ok(Some(DependencyAdapterAuthenticationFailure {
            code: "dependency-adapter-export-source-mismatch",
            message: format!(
                "adapter {} export unit digest is {}, expected {}",
                descriptor.id, actual_unit_sha256, descriptor.export_identity.unit_source_sha256
            ),
            module: Some(resolved.to_string()),
            start: Some(target_unit.start),
            construct: target_unit.kind.clone(),
        }));
    }
    for source in &descriptor.material.semantic_sources {
        let Some(semantic_module) = modules.get(&source.path) else {
            return Ok(Some(DependencyAdapterAuthenticationFailure {
                code: "dependency-adapter-semantic-source-missing",
                message: format!(
                    "adapter {} semantic source {} was not preloaded from the authenticated graph",
                    descriptor.id, source.path
                ),
                module: Some(resolved.to_string()),
                start: Some(target_unit.start),
                construct: target_unit.kind.clone(),
            }));
        };
        if semantic_module.summary.source_hash != source.source_sha256 {
            return Ok(Some(DependencyAdapterAuthenticationFailure {
                code: "dependency-adapter-semantic-source-mismatch",
                message: format!(
                    "adapter {} semantic source {} digest is {}, expected {}",
                    descriptor.id,
                    source.path,
                    semantic_module.summary.source_hash,
                    source.source_sha256
                ),
                module: Some(source.path.clone()),
                start: Some(0),
                construct: "Program".to_string(),
            }));
        }
        for expected_unit in &source.units {
            let Some(unit) = semantic_module.summary.units.get(&expected_unit.unit_name) else {
                return Ok(Some(DependencyAdapterAuthenticationFailure {
                    code: "dependency-adapter-semantic-unit-missing",
                    message: format!(
                        "adapter {} semantic source {} has no unit {}",
                        descriptor.id, source.path, expected_unit.unit_name
                    ),
                    module: Some(source.path.clone()),
                    start: Some(0),
                    construct: expected_unit.unit_name.clone(),
                }));
            };
            let actual = hash_bytes(unit.source.as_bytes());
            if actual != expected_unit.unit_source_sha256 {
                return Ok(Some(DependencyAdapterAuthenticationFailure {
                    code: "dependency-adapter-semantic-unit-mismatch",
                    message: format!(
                        "adapter {} semantic unit {}#{} digest is {}, expected {}",
                        descriptor.id,
                        source.path,
                        expected_unit.unit_name,
                        actual,
                        expected_unit.unit_source_sha256
                    ),
                    module: Some(source.path.clone()),
                    start: Some(unit.start),
                    construct: unit.kind.clone(),
                }));
            }
        }
    }
    if let Some(drift) = dependency_adapter_material_drift(graph, descriptor) {
        return Ok(Some(DependencyAdapterAuthenticationFailure {
            code: "dependency-adapter-material-mismatch",
            message: format!("adapter {} material drift: {drift}", descriptor.id),
            module: Some(resolved.to_string()),
            start: Some(target_unit.start),
            construct: target_unit.kind.clone(),
        }));
    }
    Ok(None)
}

#[expect(clippy::too_many_arguments)]
pub(super) fn adapt_dependency_call(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    module_key: &str,
    unit_id: &str,
    unit_start: u32,
    unit_end: u32,
    binding: &ImportBinding,
    resolved: &str,
    reference: &ReferenceOccurrence,
    registration: &RegistrationSummary,
    dependency_chain: &[String],
    authentication_cache: &mut DependencyAdapterAuthenticationCache,
    applied: &mut Vec<AppliedDependencyAdapterCall>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<bool> {
    let matches = graph
        .dependency_adapter
        .descriptor
        .adapters
        .iter()
        .filter(|adapter| {
            (adapter.export_identity.module_path == resolved
                && adapter.export_identity.export_name == binding.imported)
                || (is_resolved_convex_server_module(resolved)
                    && adapter.substitution.as_ref().is_some_and(|substitution| {
                        substitution.module_specifier == binding.specifier
                            && substitution.export_name == binding.imported
                    }))
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Ok(false);
    }
    ensure!(
        matches.len() == 1,
        "validated dependency adapter descriptor has duplicate resolved export identities"
    );
    let descriptor = matches[0].clone();
    let mut adapter_chain = dependency_chain.to_vec();
    adapter_chain.push(format!(
        "{}#{}",
        descriptor.export_identity.module_path, descriptor.export_identity.export_name
    ));
    if !authentication_cache.contains_key(&descriptor.id) {
        // A substitution is selected from the public SDK barrel, but its authority remains the
        // authenticated implementation unit recorded by the descriptor.
        let authentication = authenticate_dependency_adapter(
            graph,
            modules,
            &descriptor,
            &descriptor.export_identity.module_path,
        )?;
        authentication_cache.insert(descriptor.id.clone(), authentication);
    }
    if let Some(failure) = authentication_cache
        .get(&descriptor.id)
        .context("dependency adapter authentication cache entry disappeared")?
    {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            failure.code,
            failure.message.clone(),
            failure.module.as_deref().unwrap_or(module_key),
            failure.start.unwrap_or(binding.start),
            Some(failure.construct.clone()),
            adapter_chain,
        )?);
        return Ok(true);
    }
    let caller = modules
        .get(module_key)
        .context("dependency adapter caller module disappeared")?;
    let calls = caller
        .summary
        .calls
        .iter()
        .filter(|call| {
            call.start >= unit_start
                && call.end <= unit_end
                && call.callee == binding.local
                && call.callee_start == reference.start
                && call.callee_end == reference.end
        })
        .collect::<Vec<_>>();
    if !reference.read || reference.write || calls.len() != 1 {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-dependency-adapter-binding",
            format!(
                "adapter {} requires one immutable direct imported-binding call; aliases, optional calls, computed calls, and escaped bindings are unsupported",
                descriptor.id
            ),
            module_key,
            reference.start,
            Some(binding.local.clone()),
            adapter_chain,
        )?);
        return Ok(true);
    }
    let call = calls[0];
    let source = module_source(modules, module_key)?;
    let arguments = &call.arguments;
    if descriptor.semantic.kind == "functionHandleCreate" {
        if arguments.len() != 1 {
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "unsupported-dependency-adapter-call-shape",
                format!(
                    "adapter {} requires exactly one function-reference argument",
                    descriptor.id
                ),
                module_key,
                call.start,
                Some(descriptor.semantic.kind.clone()),
                adapter_chain,
            )?);
            return Ok(true);
        }
        let argument = arguments[0].clone();
        applied.push(AppliedDependencyAdapterCall {
            descriptor: descriptor.clone(),
            importer_module: module_key.to_string(),
            importer_unit_id: unit_id.to_string(),
            dependency_chain: adapter_chain,
            callee_start: call.callee_start,
            callee_end: call.callee_end,
            call_start: call.start,
            call_end: call.end,
            effect_start: call.callee_start,
            effect_end: call.callee_end,
            effect_path: binding.local.clone(),
            operation: OperationCandidate {
                kind: "functionHandleCreate".to_string(),
                start: call.start,
                end: call.end,
                table: None,
                index: None,
                index_constraints: Vec::new(),
                order: None,
                terminal: None,
                limit: None,
                limit_argument_index: None,
                algorithm: None,
                function_reference: None,
                function_reference_start: None,
                function_reference_end: None,
                effect_start: Some(call.callee_start),
                effect_end: Some(call.callee_end),
                effect_path: Some(binding.local.clone()),
            },
            dynamic_arguments: vec![argument],
            represented_global_spans: Vec::new(),
            generated_function_name: "__convexDependencyAdapter_functionHandleCreate".to_string(),
        });
        return Ok(true);
    }
    let mut represented_globals = BTreeSet::new();
    let (table, index, eq_field, terminal, dynamic_argument_index) = match descriptor
        .semantic
        .kind
        .as_str()
    {
        "databaseIndexCollect" | "databaseIndexUnique" | "databaseIndexUniqueOrThrow" => {
            if !matches!(arguments.len(), 4 | 5) {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-dependency-adapter-call-shape",
                    format!(
                        "adapter {} requires four arguments plus at most one static field argument",
                        descriptor.id
                    ),
                    module_key,
                    call.start,
                    Some(descriptor.semantic.kind.clone()),
                    adapter_chain,
                )?);
                return Ok(true);
            }
            let table =
                source_range_string(&source, &arguments[1]).filter(|table| !table.is_empty());
            let index =
                source_range_string(&source, &arguments[2]).filter(|index| !index.is_empty());
            let (Some(table), Some(index)) = (table, index) else {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-dependency-adapter-call-shape",
                    format!(
                        "adapter {} requires nonempty static string table and index arguments",
                        descriptor.id
                    ),
                    module_key,
                    call.start,
                    Some(descriptor.semantic.kind.clone()),
                    adapter_chain,
                )?);
                return Ok(true);
            };
            let field = if let Some(field) = arguments.get(4) {
                let Some(field) = source_range_string(&source, field) else {
                    diagnostics.push(diagnostic_at(
                        graph,
                        modules,
                        "unsupported-dependency-adapter-call-shape",
                        format!(
                            "adapter {} requires a static string field argument",
                            descriptor.id
                        ),
                        module_key,
                        call.start,
                        Some(descriptor.semantic.kind.clone()),
                        adapter_chain,
                    )?);
                    return Ok(true);
                };
                if field.is_empty() {
                    index
                        .strip_prefix("by_")
                        .unwrap_or(index.as_str())
                        .to_string()
                } else {
                    field
                }
            } else {
                index
                    .strip_prefix("by_")
                    .unwrap_or(index.as_str())
                    .to_string()
            };
            let terminal = if descriptor.semantic.kind == "databaseIndexCollect" {
                "collect"
            } else {
                "unique"
            };
            (
                Some(table),
                Some(index),
                Some(field),
                Some(terminal.to_string()),
                3,
            )
        }
        "databaseGetBatch" | "databaseGetBatchOrThrow" => {
            if arguments.len() != 3 {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-dependency-adapter-call-shape",
                    format!(
                        "adapter {} supports only the static-table three-argument overload",
                        descriptor.id
                    ),
                    module_key,
                    call.start,
                    Some(descriptor.semantic.kind.clone()),
                    adapter_chain,
                )?);
                return Ok(true);
            }
            let Some(table) =
                source_range_string(&source, &arguments[1]).filter(|table| !table.is_empty())
            else {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-dependency-adapter-call-shape",
                    format!(
                        "adapter {} requires a nonempty static string table argument",
                        descriptor.id
                    ),
                    module_key,
                    call.start,
                    Some(descriptor.semantic.kind.clone()),
                    adapter_chain,
                )?);
                return Ok(true);
            };
            if !dependency_adapter_iterable_is_owned(
                graph,
                module_key,
                caller,
                registration,
                unit_start,
                unit_end,
                &arguments[2],
                call.start,
                &mut BTreeSet::new(),
                &mut represented_globals,
            ) {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unsupported-dependency-adapter-iterable",
                    format!(
                        "adapter {} requires an owned array or Set; promised, custom, escaped, and unproved iterables are unsupported",
                        descriptor.id
                    ),
                    module_key,
                    arguments[2].start,
                    Some(descriptor.semantic.kind.clone()),
                    adapter_chain,
                )?);
                return Ok(true);
            }
            (Some(table), None, None, None, 2)
        }
        _ => unreachable!("validated dependency adapter semantic kind"),
    };
    let effect = &arguments[0];
    let effect_source = source_slice(&source, effect.start, effect.end)?;
    let effect_path = effect_source.trim().to_string();
    if effect_path.is_empty() {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-dependency-adapter-call-shape",
            format!(
                "adapter {} database capability argument is empty",
                descriptor.id
            ),
            module_key,
            call.start,
            Some(descriptor.semantic.kind.clone()),
            adapter_chain,
        )?);
        return Ok(true);
    }
    let dynamic_value_source = source_slice(
        &source,
        arguments[dynamic_argument_index].start,
        arguments[dynamic_argument_index].end,
    )?
    .to_string();
    let index_query_shape = if descriptor.semantic.kind.starts_with("databaseIndex") {
        Some(
            canonical_index_query_shape(
                None,
                terminal
                    .as_deref()
                    .expect("validated index dependency adapter has no terminal"),
                None,
                false,
            )
            .expect("validated index dependency adapter has a noncanonical query shape"),
        )
    } else {
        None
    };
    let operation = OperationCandidate {
        kind: if descriptor.semantic.kind.starts_with("databaseIndex") {
            "db.query".to_string()
        } else {
            "db.get".to_string()
        },
        start: call.start,
        end: call.end,
        table,
        index,
        index_constraints: eq_field
            .map(|field| {
                vec![IndexConstraintCandidate {
                    field,
                    operator: "eq".to_string(),
                    value_source: dynamic_value_source,
                    value_start: arguments[dynamic_argument_index].start,
                    value_end: arguments[dynamic_argument_index].end,
                }]
            })
            .unwrap_or_default(),
        order: index_query_shape.as_ref().map(|shape| shape.order.clone()),
        terminal: index_query_shape
            .as_ref()
            .map(|shape| shape.terminal.clone()),
        limit: index_query_shape.and_then(|shape| shape.limit),
        limit_argument_index: None,
        algorithm: None,
        function_reference: None,
        function_reference_start: None,
        function_reference_end: None,
        effect_start: Some(effect.start),
        effect_end: Some(effect.end),
        effect_path: Some(effect_path.clone()),
    };
    applied.push(AppliedDependencyAdapterCall {
        descriptor: descriptor.clone(),
        importer_module: module_key.to_string(),
        importer_unit_id: unit_id.to_string(),
        dependency_chain: adapter_chain,
        callee_start: call.callee_start,
        callee_end: call.callee_end,
        call_start: call.start,
        call_end: call.end,
        effect_start: effect.start,
        effect_end: effect.end,
        effect_path,
        operation,
        dynamic_arguments: vec![arguments[dynamic_argument_index].clone()],
        represented_global_spans: represented_globals
            .into_iter()
            .map(|(start, end)| SourceRange { start, end })
            .collect(),
        generated_function_name: format!("__convexDependencyAdapter_{}", descriptor.semantic.kind),
    });
    Ok(true)
}
