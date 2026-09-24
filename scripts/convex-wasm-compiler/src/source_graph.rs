use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use super::{
    ABI_VERSION, AppliedDependencyAdapterCall, AppliedRegistrationAdapter, AppliedSourceOperation,
    COMPILER_SCHEMA, Diagnostic, EffectExecutionMode, GraphInput, ImportBinding, LoadedModule,
    OXC_VERSION, ReachableUnit, ReferenceOccurrence, ResolvedImport, ValueMode,
    canonical_function_reference, diagnostic_at, is_generated_api_module_path,
};

#[derive(Clone)]
pub(super) struct StaticFunctionReferenceAuthorization {
    pub(super) unit_id: String,
    pub(super) module: String,
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) visibility: String,
    pub(super) function_reference: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct AuthenticatedGeneratedApiMaterial {
    module: String,
    source_sha256: String,
    any_api_resolved: String,
}

pub(super) fn source_fingerprint(
    graph: &GraphInput,
    reachable: &BTreeMap<String, ReachableUnit>,
    imports: &[ResolvedImport],
    generated_api_materials: &BTreeMap<String, AuthenticatedGeneratedApiMaterial>,
    dependency_adapter_calls: &[AppliedDependencyAdapterCall],
    registration_adapter: Option<&AppliedRegistrationAdapter>,
    source_operations: &[AppliedSourceOperation],
    value_mode: ValueMode,
    effect_execution_mode: EffectExecutionMode,
) -> String {
    let mut hash = Sha256::new();
    for value in [
        COMPILER_SCHEMA,
        ABI_VERSION,
        OXC_VERSION,
        &graph.toolchain.esbuild,
        &graph.toolchain.convex,
        &graph.entry_path,
        &graph.export_name,
        value_mode.identity(),
        effect_execution_mode.identity(),
    ] {
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    for unit in reachable.values() {
        hash.update(unit.id.as_bytes());
        hash.update([0]);
        hash.update(unit.source.as_bytes());
        hash.update([0]);
    }
    for import in imports {
        hash.update(import.importer.as_bytes());
        hash.update([0]);
        hash.update(import.specifier.as_bytes());
        hash.update([0]);
        hash.update(import.imported_name.as_bytes());
        hash.update([0]);
        hash.update(import.resolved.as_bytes());
        hash.update([0]);
    }
    for material in generated_api_materials.values() {
        hash.update(material.module.as_bytes());
        hash.update([0]);
        hash.update(material.source_sha256.as_bytes());
        hash.update([0]);
        hash.update(material.any_api_resolved.as_bytes());
        hash.update([0]);
    }
    hash_dependency_adapter_identity(&mut hash, dependency_adapter_calls);
    if let Some(adapter) = registration_adapter {
        hash_registration_adapter_identity(&mut hash, adapter);
    }
    hash_source_operation_identity(&mut hash, source_operations);
    hex::encode(hash.finalize())
}

pub(super) fn source_graph_fingerprint(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    imports: &[ResolvedImport],
    generated_api_materials: &BTreeMap<String, AuthenticatedGeneratedApiMaterial>,
    dependency_adapter_calls: &[AppliedDependencyAdapterCall],
    registration_adapter: Option<&AppliedRegistrationAdapter>,
    source_operations: &[AppliedSourceOperation],
    value_mode: ValueMode,
    effect_execution_mode: EffectExecutionMode,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"convex-wasm-reachable-source-graph\0");
    hash.update(graph.toolchain.esbuild.as_bytes());
    hash.update([0]);
    hash.update(graph.toolchain.convex.as_bytes());
    hash.update([0]);
    hash.update(value_mode.identity().as_bytes());
    hash.update([0]);
    hash.update(effect_execution_mode.identity().as_bytes());
    hash.update([0]);
    for module_key in reachable
        .values()
        .map(|unit| unit.module.as_str())
        .collect::<BTreeSet<_>>()
    {
        let module = modules
            .get(module_key)
            .expect("reachable source graph module must be loaded");
        hash.update(module_key.as_bytes());
        hash.update([0]);
        hash.update(module.summary.source_hash.as_bytes());
        hash.update([0]);
    }
    for import in imports {
        hash.update(import.importer.as_bytes());
        hash.update([0]);
        hash.update(import.specifier.as_bytes());
        hash.update([0]);
        hash.update(import.resolved.as_bytes());
        hash.update([0]);
    }
    for material in generated_api_materials.values() {
        hash.update(material.module.as_bytes());
        hash.update([0]);
        hash.update(material.source_sha256.as_bytes());
        hash.update([0]);
        hash.update(material.any_api_resolved.as_bytes());
        hash.update([0]);
    }
    hash_dependency_adapter_identity(&mut hash, dependency_adapter_calls);
    if let Some(adapter) = registration_adapter {
        hash_registration_adapter_identity(&mut hash, adapter);
    }
    hash_source_operation_identity(&mut hash, source_operations);
    hex::encode(hash.finalize())
}

fn hash_dependency_adapter_identity(hash: &mut Sha256, calls: &[AppliedDependencyAdapterCall]) {
    let mut descriptors = BTreeMap::new();
    for call in calls {
        if let Some(existing) = descriptors.insert(call.descriptor.id.as_str(), &call.descriptor) {
            assert_eq!(
                existing, &call.descriptor,
                "validated dependency adapter ID has conflicting descriptors"
            );
        }
    }
    for descriptor in descriptors.into_values() {
        hash.update(b"convex-wasm-applied-dependency-adapter\0");
        hash.update(
            serde_json::to_vec(descriptor)
                .expect("dependency adapter descriptor serialization must succeed"),
        );
        hash.update([0]);
    }
}

fn hash_source_operation_identity(hash: &mut Sha256, operations: &[AppliedSourceOperation]) {
    let mut descriptors = BTreeMap::new();
    for operation in operations {
        let identity = (
            &operation.descriptor,
            operation.helper_unit_source_sha256.as_str(),
        );
        if let Some(existing) = descriptors.insert(operation.descriptor.id.as_str(), identity) {
            assert_eq!(
                existing, identity,
                "validated source operation ID has conflicting applied material"
            );
        }
    }
    for (descriptor, helper_unit_source_sha256) in descriptors.into_values() {
        hash.update(b"convex-wasm-applied-source-operation\0");
        hash.update(
            serde_json::to_vec(descriptor)
                .expect("source operation descriptor serialization must succeed"),
        );
        hash.update([0]);
        hash.update(helper_unit_source_sha256.as_bytes());
        hash.update([0]);
    }
}

fn hash_registration_adapter_identity(hash: &mut Sha256, adapter: &AppliedRegistrationAdapter) {
    hash.update(b"convex-wasm-applied-registration-adapter\0");
    for value in [
        adapter.descriptor.id.as_str(),
        adapter.descriptor.registration_kind.as_str(),
        adapter.wrapper_module.as_str(),
        adapter.descriptor.wrapper.export_name.as_str(),
        adapter.wrapper_unit_name.as_str(),
        adapter.wrapper_unit_source_sha256.as_str(),
        adapter.helper_module.as_str(),
        adapter
            .descriptor
            .authentication
            .helper
            .export_name
            .as_str(),
        adapter.helper_unit_name.as_str(),
        adapter.helper_unit_source_sha256.as_str(),
        adapter.descriptor.authentication.result_kind.as_str(),
    ] {
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    for parameter in &adapter.descriptor.authentication.result_parameters {
        hash.update(parameter.callback_parameter_index.to_le_bytes());
        hash.update([0]);
        if let Some(property) = &parameter.property {
            hash.update(property.as_bytes());
        }
        hash.update([0]);
    }
}

pub(super) fn resolve_graph_import(
    graph: &GraphInput,
    importer: &str,
    specifier: &str,
) -> Result<String> {
    let input = graph
        .metafile
        .inputs
        .get(importer)
        .with_context(|| format!("esbuild metafile has no input {importer}"))?;
    let matches = input
        .imports
        .iter()
        .filter(|import| import.original.as_deref() == Some(specifier))
        .collect::<Vec<_>>();
    let resolutions = matches
        .iter()
        .map(|import| (&import.path, &import.kind, import.external))
        .collect::<BTreeSet<_>>();
    ensure!(
        resolutions.len() == 1,
        "esbuild graph must resolve {specifier} from {importer} consistently, found {} entries with {} distinct resolutions",
        matches.len(),
        resolutions.len()
    );
    let resolved = matches[0];
    ensure!(
        resolved.kind == "import-statement",
        "unsupported esbuild import kind {} for {specifier}",
        resolved.kind
    );
    ensure!(
        !resolved.external,
        "runtime import {specifier} from {importer} is external"
    );
    Ok(resolved.path.clone())
}

pub(super) fn is_admitted_import(resolved: &str, imported: &str) -> bool {
    let _ = imported;
    is_admitted_module_path(resolved)
}

pub(super) fn is_admitted_module_path(resolved: &str) -> bool {
    resolved.starts_with("convex/") || resolved.starts_with("shared/")
}

pub(super) fn is_dependency_adapter_module_path(graph: &GraphInput, resolved: &str) -> bool {
    graph
        .dependency_adapter
        .descriptor
        .adapters
        .iter()
        .any(|adapter| {
            adapter.export_identity.module_path == resolved
                || (adapter.substitution.is_some()
                    && graph
                        .dependency_adapter
                        .current
                        .files
                        .iter()
                        .any(|file| file.path == adapter.export_identity.module_path)
                    && is_resolved_convex_server_module(resolved))
                || adapter
                    .material
                    .semantic_sources
                    .iter()
                    .any(|source| source.path == resolved)
        })
}

pub(super) fn is_resolved_convex_server_module(resolved: &str) -> bool {
    resolved
        .strip_prefix("node_modules/convex/")
        .is_some_and(|path| {
            matches!(
                path,
                "server.js" | "dist/esm/server/index.js" | "dist/cjs/server/index.js"
            )
        })
}

pub(crate) fn is_normalized_functions_root(root: &str) -> bool {
    !root.is_empty()
        && !root.starts_with('/')
        && !root.contains('\\')
        && !root.contains('\0')
        && root
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

pub(crate) fn is_resolved_generated_server_module(resolved: &str, functions_root: &str) -> bool {
    resolved.strip_suffix("/_generated/server.js") == Some(functions_root)
}

pub(crate) fn generated_server_udf_kind(imported: &str) -> Option<&'static str> {
    match imported {
        "internalQuery" | "query" => Some("query"),
        "internalMutation" | "mutation" => Some("mutation"),
        "action" | "internalAction" => Some("action"),
        "httpAction" => Some("httpAction"),
        _ => None,
    }
}

fn authenticate_generated_api_module(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    resolved: &str,
) -> std::result::Result<AuthenticatedGeneratedApiMaterial, String> {
    let module = modules.get(resolved).ok_or_else(|| {
        "resolved generated api module is absent from the authenticated esbuild graph closure"
            .to_string()
    })?;
    let convention = module
        .summary
        .generated_api_convention
        .as_ref()
        .ok_or_else(|| {
            "generated api source does not import anyApi from convex/server and export both api and internal as that exact binding"
                .to_string()
        })?;
    let any_api_resolved = resolve_graph_import(graph, resolved, &convention.any_api_specifier)
        .map_err(|error| format!("generated api anyApi import is not resolved exactly: {error}"))?;
    if !is_resolved_convex_server_module(&any_api_resolved) {
        return Err(format!(
            "generated api anyApi import resolves outside the pinned convex/server module: {any_api_resolved}"
        ));
    }
    Ok(AuthenticatedGeneratedApiMaterial {
        module: resolved.to_string(),
        source_sha256: module.summary.source_hash.clone(),
        any_api_resolved,
    })
}

#[expect(clippy::too_many_arguments)]
pub(super) fn adapt_generated_function_reference(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    module_key: &str,
    binding: &ImportBinding,
    resolved: &str,
    reference: &ReferenceOccurrence,
    unit_id: &str,
    dependency_chain: &[String],
    resolved_imports: &mut Vec<ResolvedImport>,
    generated_api_materials: &mut BTreeMap<String, AuthenticatedGeneratedApiMaterial>,
    authorizations: &mut Vec<StaticFunctionReferenceAuthorization>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<bool> {
    if !is_generated_api_module_path(resolved)
        || !matches!(binding.imported.as_str(), "api" | "internal")
    {
        return Ok(false);
    }

    let material = match authenticate_generated_api_module(graph, modules, resolved) {
        Ok(material) => material,
        Err(message) => {
            let (file, start) =
                modules
                    .get(resolved)
                    .map_or((module_key, binding.start), |module| {
                        (
                            resolved,
                            module
                                .summary
                                .generated_api_convention
                                .as_ref()
                                .map_or(0, |convention| convention.any_api_import_start),
                        )
                    });
            diagnostics.push(diagnostic_at(
                graph,
                modules,
                "generated-api-source-mismatch",
                message,
                file,
                start,
                Some("GeneratedApiConvention".to_string()),
                dependency_chain.to_vec(),
            )?);
            return Ok(true);
        }
    };

    if let Some(existing) = generated_api_materials.get(resolved) {
        ensure!(
            existing == &material,
            "authenticated generated api material changed during one export analysis"
        );
    } else {
        resolved_imports.push(ResolvedImport {
            importer: resolved.to_string(),
            specifier: "convex/server".to_string(),
            imported_name: "anyApi".to_string(),
            resolved: material.any_api_resolved.clone(),
            dependency_chain: dependency_chain.to_vec(),
        });
        generated_api_materials.insert(resolved.to_string(), material);
    }

    let module = modules
        .get(module_key)
        .context("generated api importer disappeared")?;
    if !reference.read || reference.write {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "generated-function-reference-escape",
            "generated api bindings are immutable compile-time function-reference roots"
                .to_string(),
            module_key,
            reference.start,
            Some(binding.local.clone()),
            dependency_chain.to_vec(),
        )?);
        return Ok(true);
    }
    let member_chain = module
        .summary
        .static_member_chains
        .iter()
        .filter(|chain| {
            chain.root == reference.name
                && chain.root_start == reference.start
                && chain.root_end == reference.end
        })
        .max_by_key(|chain| chain.end - chain.start);
    let Some(member_chain) = member_chain else {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "generated-function-reference-escape",
            format!(
                "generated {} export {} is referenced outside one complete static function reference",
                binding.imported, binding.local
            ),
            module_key,
            reference.start,
            Some(binding.local.clone()),
            dependency_chain.to_vec(),
        )?);
        return Ok(true);
    };
    if member_chain.computed || member_chain.optional {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "unsupported-generated-function-reference",
            "generated function references require non-optional, non-computed identifier members"
                .to_string(),
            module_key,
            member_chain.start,
            Some("MemberExpression".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(true);
    }
    if member_chain.fields.len() < 2 {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "generated-function-reference-escape",
            "generated api namespaces cannot escape before a module and function are selected"
                .to_string(),
            module_key,
            member_chain.start,
            Some("MemberExpression".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(true);
    }
    let consumers = module
        .summary
        .static_function_reference_consumers
        .iter()
        .filter(|consumer| {
            consumer.reference_start == member_chain.start
                && consumer.reference_end == member_chain.end
        })
        .collect::<Vec<_>>();
    if consumers.len() != 1 {
        diagnostics.push(diagnostic_at(
            graph,
            modules,
            "generated-function-reference-escape",
            "generated function references may only be passed directly to one Convex function-reference operation"
                .to_string(),
            module_key,
            member_chain.start,
            Some("MemberExpression".to_string()),
            dependency_chain.to_vec(),
        )?);
        return Ok(true);
    }
    let function_reference = canonical_function_reference(&member_chain.fields);
    authorizations.push(StaticFunctionReferenceAuthorization {
        unit_id: unit_id.to_string(),
        module: module_key.to_string(),
        start: member_chain.start,
        end: member_chain.end,
        visibility: binding.imported.clone(),
        function_reference,
    });
    Ok(true)
}

pub(super) fn validate_scheduler_function_references(
    graph: &GraphInput,
    modules: &BTreeMap<String, LoadedModule>,
    reachable: &BTreeMap<String, ReachableUnit>,
    authorizations: &[StaticFunctionReferenceAuthorization],
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<()> {
    for unit in reachable.values() {
        let module = modules
            .get(&unit.module)
            .context("scheduler reference source module disappeared")?;
        for operation in module.summary.operations.iter().filter(|operation| {
            matches!(
                operation.kind.as_str(),
                "scheduler.runAfter" | "scheduler.runAt"
            ) && operation.start >= unit.start
                && operation.end <= unit.end
        }) {
            let authorization = operation
                .function_reference_start
                .zip(operation.function_reference_end)
                .and_then(|(start, end)| {
                    let matches = authorizations
                        .iter()
                        .filter(|authorization| {
                            authorization.unit_id == unit.id
                                && authorization.module == unit.module
                                && authorization.start == start
                                && authorization.end == end
                        })
                        .collect::<Vec<_>>();
                    (matches.len() == 1).then(|| matches[0])
                });
            let Some(authorization) = authorization else {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "unproved-generated-function-reference",
                    "scheduler function reference is not one exact static api/internal chain from an authenticated generated api module"
                        .to_string(),
                    &unit.module,
                    operation.function_reference_start.unwrap_or(operation.start),
                    Some(operation.kind.clone()),
                    unit.dependency_chain.clone(),
                )?);
                continue;
            };
            ensure!(
                matches!(authorization.visibility.as_str(), "api" | "internal"),
                "authenticated function reference has unsupported visibility"
            );
            if operation.function_reference.as_deref()
                != Some(authorization.function_reference.as_str())
            {
                diagnostics.push(diagnostic_at(
                    graph,
                    modules,
                    "generated-function-reference-mismatch",
                    "scheduler descriptor does not match its authenticated generated function reference"
                        .to_string(),
                    &unit.module,
                    operation.function_reference_start.unwrap_or(operation.start),
                    Some(operation.kind.clone()),
                    unit.dependency_chain.clone(),
                )?);
            }
        }
    }
    Ok(())
}
