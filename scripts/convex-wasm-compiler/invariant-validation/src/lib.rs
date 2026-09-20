#![allow(dead_code)]

include!("../../src/main.rs");

#[derive(Clone, Debug)]
pub struct HarnessModule {
    pub module_key: String,
    pub source: String,
    pub imports: Vec<HarnessImport>,
}

#[derive(Clone, Debug)]
pub struct HarnessImport {
    pub original: String,
    pub resolved: String,
}

#[derive(Clone, Debug)]
pub struct HarnessSourceOperation {
    pub id: String,
    pub helper_module: String,
    pub helper_export: String,
    pub selector: String,
    pub missing_configuration_error: String,
    pub mismatch_error: String,
}

#[derive(Clone, Debug)]
pub struct HarnessDependencyAdapter {
    pub id: String,
    pub module_path: String,
    pub export_name: String,
    pub semantic_kind: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessEffectExecutionMode {
    BlockingFiber,
    GuestPromiseEventLoop,
}

pub const EFFECT_VALUE_CORRUPTION_COUNT: usize = 15;

#[derive(Clone, Debug)]
pub struct HarnessOutput {
    pub compiler_output: Value,
    pub normalized_output: Value,
    pub semantic_projection: Value,
    pub callable_labels: BTreeMap<String, String>,
    pub entry_summary: Value,
    pub context_reuse_summary: Value,
    pub context_reuse_hard_rules: Vec<String>,
    pub context_reuse_loaded_hard_rules: Vec<String>,
}

impl HarnessOutput {
    pub fn eligible(&self) -> bool {
        self.compiler_output["eligible"]
            .as_bool()
            .expect("compiler output eligibility must be Boolean")
    }

    pub fn generated_source(&self) -> Option<&str> {
        self.compiler_output["generatedJavascriptArtifact"]["source"].as_str()
    }
}

mod implementation {
    use super::*;
    use adapter_material::{
        DependencyAdapterCurrentFile, DependencyAdapterCurrentMaterial,
        DependencyAdapterDescriptor, DependencyAdapterDescriptorEntry,
        DependencyAdapterExpectedMaterial, DependencyAdapterExportIdentity,
        DependencyAdapterLockMaterial, DependencyAdapterPackageMaterial, DependencyAdapterSemantic,
        RegistrationAdapterDescriptor, RegistrationAdapterExportIdentity,
        RegistrationAdapterSourceMaterial, RegistrationAdapterSourceOperation,
        RegistrationAdapterSourceOperationSemantic,
    };
    use callable_plans::{CallableLeafControlCandidate, CallableLeafEffectCandidate};
    use callable_value_flow::{
        CallableEffectValueFlowCandidate, CallableEffectValueOriginCandidate,
        CallableEffectValueSinkCandidate, CallableEffectValueStepCandidate,
    };
    use std::{fs, sync::OnceLock};

    const INVARIANT_VALIDATION_DEPENDENCY_ADAPTER_VERSION: &str = "1.0.0";

    fn empty_registration_adapter_material() -> RegistrationAdapterMaterial {
        RegistrationAdapterMaterial {
            kind: "convex-wasm-registration-adapter-material".to_string(),
            descriptor: RegistrationAdapterDescriptor {
                kind: "convex-wasm-registration-adapter-descriptor".to_string(),
                adapters: Vec::new(),
                source_operations: Vec::new(),
            },
            source: RegistrationAdapterSourceMaterial {
                path: "invariant-validation/registration-adapters.json".to_string(),
                sha256: "0".repeat(64),
                bytes: 1,
            },
        }
    }

    fn registration_adapter_material(
        loaded: &BTreeMap<String, LoadedModule>,
        source_operations: &[HarnessSourceOperation],
    ) -> Result<RegistrationAdapterMaterial> {
        let mut material = empty_registration_adapter_material();
        for operation in source_operations {
            let module = loaded.get(&operation.helper_module).with_context(|| {
                format!(
                    "invariant-validation source-operation helper module {} is absent",
                    operation.helper_module
                )
            })?;
            let local = module
                .summary
                .exports
                .get(&operation.helper_export)
                .with_context(|| {
                    format!(
                        "invariant-validation source-operation helper {}#{} is not exported",
                        operation.helper_module, operation.helper_export
                    )
                })?;
            let unit = module.summary.units.get(local).with_context(|| {
                format!(
                    "invariant-validation source-operation helper {}#{} has no runtime unit",
                    operation.helper_module, operation.helper_export
                )
            })?;
            material
                .descriptor
                .source_operations
                .push(RegistrationAdapterSourceOperation {
                    id: operation.id.clone(),
                    helper: RegistrationAdapterExportIdentity {
                        module_path: operation.helper_module.clone(),
                        export_name: operation.helper_export.clone(),
                        source_sha256: hash_bytes(unit.source.as_bytes()),
                    },
                    semantic: RegistrationAdapterSourceOperationSemantic {
                        kind: "hostSecretVerify".to_string(),
                        selector: operation.selector.clone(),
                        missing_configuration_error: operation.missing_configuration_error.clone(),
                        mismatch_error: operation.mismatch_error.clone(),
                    },
                });
        }
        material
            .descriptor
            .source_operations
            .sort_by(|left, right| left.id.cmp(&right.id));
        Ok(material)
    }

    fn empty_dependency_adapter_material() -> DependencyAdapterMaterial {
        DependencyAdapterMaterial {
            kind: "convex-wasm-dependency-adapter-material".to_string(),
            descriptor: DependencyAdapterDescriptor {
                kind: "convex-wasm-dependency-adapter-descriptor".to_string(),
                adapters: Vec::new(),
            },
            source: RegistrationAdapterSourceMaterial {
                path: "invariant-validation/dependency-adapters.json".to_string(),
                sha256: "0".repeat(64),
                bytes: 1,
            },
            current: DependencyAdapterCurrentMaterial {
                files: Vec::new(),
                locks: Vec::new(),
            },
        }
    }

    fn invariant_validation_repo_root() -> &'static Path {
        static ROOT: OnceLock<PathBuf> = OnceLock::new();
        ROOT.get_or_init(|| {
            let root = std::env::temp_dir().join(format!(
                "convex-wasm-compiler-invariant-validation-repository-{}",
                std::process::id()
            ));
            fs::create_dir_all(&root)
                .expect("create process-local compiler invariant-validation repository");
            root
        })
    }

    fn write_invariant_validation_material(path: &Path, bytes: &[u8]) -> Result<()> {
        if fs::read(path).ok().as_deref() == Some(bytes) {
            return Ok(());
        }
        fs::create_dir_all(
            path.parent()
                .context("invariant-validation material path has no parent directory")?,
        )?;
        fs::write(path, bytes).with_context(|| {
            format!(
                "failed to write invariant-validation material {}",
                path.display()
            )
        })
    }

    fn dependency_adapter_package(module_path: &str) -> Result<(String, String)> {
        let parts = module_path.split('/').collect::<Vec<_>>();
        ensure!(
            parts.first() == Some(&"node_modules") && parts.len() >= 3,
            "invariant-validation dependency adapter module must be inside node_modules"
        );
        let package_parts = if parts[1].starts_with('@') {
            ensure!(
                parts.len() >= 4,
                "scoped invariant-validation dependency adapter module has no package path"
            );
            &parts[1..3]
        } else {
            &parts[1..2]
        };
        let package_name = package_parts.join("/");
        let package_key = format!("node_modules/{package_name}");
        Ok((package_name, package_key))
    }

    fn dependency_adapter_material(
        loaded: &BTreeMap<String, LoadedModule>,
        adapters: &[HarnessDependencyAdapter],
    ) -> Result<(DependencyAdapterMaterial, PathBuf)> {
        if adapters.is_empty() {
            return Ok((
                empty_dependency_adapter_material(),
                PathBuf::from("/invariant-validation"),
            ));
        }

        let root = invariant_validation_repo_root();
        let mut descriptor_entries = Vec::new();
        let mut current_files = BTreeMap::<String, DependencyAdapterCurrentFile>::new();
        let mut current_locks = BTreeSet::new();
        let mut lock_packages = BTreeMap::new();
        for adapter in adapters {
            let module = loaded.get(&adapter.module_path).with_context(|| {
                format!(
                    "invariant-validation dependency adapter module {} is absent",
                    adapter.module_path
                )
            })?;
            let local = module
                .summary
                .exports
                .get(&adapter.export_name)
                .with_context(|| {
                    format!(
                        "invariant-validation dependency adapter {}#{} is not exported",
                        adapter.module_path, adapter.export_name
                    )
                })?;
            let unit = module.summary.units.get(local).with_context(|| {
                format!(
                    "invariant-validation dependency adapter {}#{} has no runtime unit",
                    adapter.module_path, adapter.export_name
                )
            })?;
            let (package_name, package_key) = dependency_adapter_package(&adapter.module_path)?;
            let package_json_path = format!("{package_key}/package.json");
            let package_source = format!(
                "{{\"name\":\"{package_name}\",\"version\":\"{INVARIANT_VALIDATION_DEPENDENCY_ADAPTER_VERSION}\"}}\n"
            );
            write_invariant_validation_material(
                &root.join(&package_json_path),
                package_source.as_bytes(),
            )?;
            write_invariant_validation_material(
                &root.join(&adapter.module_path),
                module.source.as_bytes(),
            )?;

            let package_sha256 = hash_bytes(package_source.as_bytes());
            let module_sha256 = hash_bytes(module.source.as_bytes());
            current_files.insert(
                adapter.module_path.clone(),
                DependencyAdapterCurrentFile {
                    path: adapter.module_path.clone(),
                    sha256: module_sha256.clone(),
                    bytes: module.source.len(),
                },
            );
            current_files.insert(
                package_json_path.clone(),
                DependencyAdapterCurrentFile {
                    path: package_json_path.clone(),
                    sha256: package_sha256.clone(),
                    bytes: package_source.len(),
                },
            );
            let lock_entry = serde_json::json!({
                "version": INVARIANT_VALIDATION_DEPENDENCY_ADAPTER_VERSION,
            });
            let lock_entry_sha256 = hash_bytes(&serde_json::to_vec(&lock_entry)?);
            if let Some(previous) = lock_packages.insert(package_key.clone(), lock_entry.clone()) {
                ensure!(
                    previous == lock_entry,
                    "invariant-validation dependency adapter package has conflicting lock entries"
                );
            }
            let package_lock = DependencyAdapterLockMaterial {
                path: "package-lock.json".to_string(),
                package_key: package_key.clone(),
                entry_sha256: lock_entry_sha256.clone(),
            };
            let installed_lock = DependencyAdapterLockMaterial {
                path: "node_modules/.package-lock.json".to_string(),
                package_key,
                entry_sha256: lock_entry_sha256,
            };
            current_locks.insert(package_lock.clone());
            current_locks.insert(installed_lock.clone());
            descriptor_entries.push(DependencyAdapterDescriptorEntry {
                id: adapter.id.clone(),
                export_identity: DependencyAdapterExportIdentity {
                    module_path: adapter.module_path.clone(),
                    export_name: adapter.export_name.clone(),
                    unit_source_sha256: hash_bytes(unit.source.as_bytes()),
                },
                substitution: None,
                material: DependencyAdapterExpectedMaterial {
                    module_source_sha256: module_sha256,
                    semantic_sources: Vec::new(),
                    package_json: DependencyAdapterPackageMaterial {
                        path: package_json_path,
                        sha256: package_sha256,
                        version: INVARIANT_VALIDATION_DEPENDENCY_ADAPTER_VERSION.to_string(),
                    },
                    package_lock,
                    installed_lock,
                },
                semantic: DependencyAdapterSemantic {
                    kind: adapter.semantic_kind.clone(),
                },
            });
        }
        let lock_bytes = serde_json::to_vec(&serde_json::json!({
            "packages": lock_packages,
        }))?;
        for lock_path in ["package-lock.json", "node_modules/.package-lock.json"] {
            write_invariant_validation_material(&root.join(lock_path), &lock_bytes)?;
        }
        descriptor_entries.sort_by(|left, right| {
            (
                &left.export_identity.module_path,
                &left.export_identity.export_name,
            )
                .cmp(&(
                    &right.export_identity.module_path,
                    &right.export_identity.export_name,
                ))
        });
        let descriptor = DependencyAdapterDescriptor {
            kind: "convex-wasm-dependency-adapter-descriptor".to_string(),
            adapters: descriptor_entries,
        };
        let descriptor_bytes = serde_json::to_vec(&descriptor)?;
        let descriptor_sha256 = hash_bytes(&descriptor_bytes);
        let descriptor_path =
            format!("invariant-validation/dependency-adapters-{descriptor_sha256}.json");
        write_invariant_validation_material(&root.join(&descriptor_path), &descriptor_bytes)?;
        Ok((
            DependencyAdapterMaterial {
                kind: "convex-wasm-dependency-adapter-material".to_string(),
                descriptor,
                source: RegistrationAdapterSourceMaterial {
                    path: descriptor_path,
                    sha256: descriptor_sha256,
                    bytes: descriptor_bytes.len(),
                },
                current: DependencyAdapterCurrentMaterial {
                    files: current_files.into_values().collect(),
                    locks: current_locks.into_iter().collect(),
                },
            },
            root.to_path_buf(),
        ))
    }

    fn summarize(module_key: &str, source: &str) -> Result<ModuleSummary> {
        let source_hash = hash_bytes(source.as_bytes());
        summarize_module(
            module_key,
            Path::new(module_key),
            source,
            &source_hash,
            &format!("invariant-validation-{source_hash}"),
            compiler_pipeline_sha256(),
            context_reuse::context_policy_fingerprint(),
            &mut PhaseMeasurements::default(),
        )
    }

    fn remove_runtime_measurements(value: &mut Value) {
        let object = value
            .as_object_mut()
            .expect("serialized compiler output must be an object");
        object.remove("phaseTimingsUs");
        object.remove("moduleCache");
    }

    fn callable_labels(loaded: &BTreeMap<String, LoadedModule>) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        for (module_key, module) in loaded {
            let mut units = module.summary.units.values().collect::<Vec<_>>();
            units.sort_by_key(|unit| (unit.start, unit.end, &unit.name));
            let mut name_counts = BTreeMap::<&str, usize>::new();
            for unit in &units {
                *name_counts.entry(&unit.name).or_default() += 1;
            }
            for (index, unit) in units.into_iter().enumerate() {
                if name_counts.get(unit.name.as_str()) == Some(&1) {
                    labels.insert(
                        format!("{module_key}#{}", unit.name),
                        format!("{module_key}#<unit:{index}>"),
                    );
                }
            }
        }
        labels
    }

    fn operation_projection(output: &Value) -> Value {
        let operations = output
            .get("operations")
            .and_then(Value::as_array)
            .map(|operations| {
                operations
                    .iter()
                    .map(|operation| {
                        let kind = operation
                            .get("kind")
                            .and_then(Value::as_str)
                            .expect("compiler operation kind must be a string");
                        let fields: &[&str] = match kind {
                            "authenticationGetUserIdentity" => &[],
                            "databaseDelete"
                            | "databaseGet"
                            | "databaseInsert"
                            | "databaseNormalizeId"
                            | "databasePatch"
                            | "databaseReplace" => &["table"],
                            "databaseIndexQuery" => &[
                                "table",
                                "index",
                                "indexConstraints",
                                "order",
                                "terminal",
                                "limit",
                            ],
                            "hostSecretVerify" => &["contractVersion", "selector"],
                            "schedulerRunAfter" | "schedulerRunAt" => &["functionReference"],
                            "sha256" => &["algorithm"],
                            other => {
                                panic!("unsupported compiler operation projection kind {other}")
                            }
                        };
                        let mut projected =
                            Map::from_iter([("kind".to_string(), Value::String(kind.to_string()))]);
                        for field in fields {
                            projected.insert(
                                (*field).to_string(),
                                operation
                                    .get(*field)
                                    .unwrap_or_else(|| {
                                        panic!("compiler operation {kind} has no {field}")
                                    })
                                    .clone(),
                            );
                        }
                        Value::Object(projected)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let diagnostic_codes = output
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(|diagnostics| {
                diagnostics
                    .iter()
                    .filter_map(|diagnostic| diagnostic.get("code").cloned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let diagnostics = output
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(|diagnostics| {
                diagnostics
                    .iter()
                    .map(|diagnostic| {
                        serde_json::json!({
                            "code": diagnostic.get("code"),
                            "dependencyChain": diagnostic.get("dependencyChain"),
                            "file": diagnostic.get("file"),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        serde_json::json!({
            "diagnosticCodes": diagnostic_codes,
            "diagnostics": diagnostics,
            "eligible": output.get("eligible"),
            "operations": operations,
            "routing": output.pointer("/routing/decision"),
            "valueMode": output.get("valueMode"),
        })
    }

    fn assert_structurally_complete(output: &Value) -> Result<()> {
        let eligible = output
            .get("eligible")
            .and_then(Value::as_bool)
            .context("compiler output has no Boolean eligible field")?;
        let routing = output
            .pointer("/routing/decision")
            .and_then(Value::as_str)
            .context("compiler output has no routing decision")?;
        ensure!(
            (eligible && routing == "wasm") || (!eligible && routing == "v8Fallback"),
            "compiler eligibility disagrees with routing decision"
        );
        let diagnostics = output
            .get("diagnostics")
            .and_then(Value::as_array)
            .context("compiler output diagnostics are not an array")?;
        if eligible {
            ensure!(
                diagnostics.is_empty(),
                "eligible compiler output has diagnostics"
            );
            let source = output
                .pointer("/generatedJavascriptArtifact/source")
                .and_then(Value::as_str)
                .context("eligible compiler output has no inline generated source")?;
            let allocator = Allocator::default();
            let source_type = SourceType::ts().with_module(true);
            let parsed = Parser::new(&allocator, source, source_type).parse();
            ensure!(
                parsed.diagnostics.is_empty(),
                "eligible generated source has {} parser diagnostics",
                parsed.diagnostics.len()
            );
            let semantic = SemanticBuilder::new_compiler().build(&parsed.program);
            ensure!(
                semantic.diagnostics.is_empty(),
                "eligible generated source has {} semantic diagnostics",
                semantic.diagnostics.len()
            );
        } else {
            ensure!(
                !diagnostics.is_empty(),
                "ineligible compiler output has no fail-closed diagnostic"
            );
            ensure!(
                output
                    .get("generatedJavascriptArtifact")
                    .is_none_or(Value::is_null),
                "ineligible compiler output retained generated source"
            );
        }
        Ok(())
    }

    fn for_each_effect_value_flow(
        summary: &mut ModuleSummary,
        mut visit: impl FnMut(&mut CallableEffectValueFlowCandidate),
    ) {
        for candidate in &mut summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                visit(flow);
            }
        }
    }

    fn for_each_leaf_effect(
        summary: &mut ModuleSummary,
        mut visit: impl FnMut(&mut CallableLeafEffectCandidate),
    ) {
        for candidate in &mut summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::Effect(effect) = &mut candidate.control {
                visit(effect);
            }
        }
    }

    fn require_effect_value_corruption_rejection(
        source: &str,
        expected_error: &str,
        corrupt: impl FnOnce(&mut ModuleSummary, &str) -> Result<()>,
    ) -> Result<()> {
        const MODULE_KEY: &str = "convex/invariant_validation_relation_corruption.ts";
        let mut summary = summarize(MODULE_KEY, source)?;
        corrupt(&mut summary, source)?;
        let unit_name = "selected";
        ensure!(
            summary.units.contains_key(unit_name),
            "relation-corruption fixture has no selected unit"
        );
        let reachable = summary
            .units
            .iter()
            .map(|(name, unit)| {
                let unit_id = format!("{MODULE_KEY}#{name}");
                (
                    unit_id.clone(),
                    ReachableUnit {
                        id: unit_id,
                        module: MODULE_KEY.to_string(),
                        name: name.clone(),
                        start: unit.start,
                        end: unit.end,
                        source: unit.source.clone(),
                        kind: unit.kind.clone(),
                        dependency_chain: vec![unit_name.to_string(), name.clone()],
                        dependencies: BTreeMap::new(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let modules = BTreeMap::from([(
            MODULE_KEY.to_string(),
            LoadedModule::new(summary, source.to_string()),
        )]);
        let graph = GraphInput {
            kind: "convex-wasm-esbuild-graph".to_string(),
            repo_root: PathBuf::from("/invariant-validation"),
            entry_path: MODULE_KEY.to_string(),
            export_name: unit_name.to_string(),
            toolchain: Toolchain {
                esbuild: "invariant-validation-esbuild".to_string(),
                convex: "invariant-validation-convex".to_string(),
            },
            dependency_adapter: empty_dependency_adapter_material(),
            registration_adapter: empty_registration_adapter_material(),
            assumptions: None,
            effect_execution_mode: EffectExecutionMode::BlockingFiber,
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([(
                    MODULE_KEY.to_string(),
                    EsbuildInput {
                        imports: Vec::new(),
                    },
                )]),
                outputs: BTreeMap::new(),
            },
            phase_timings_us: BTreeMap::new(),
        };
        let static_calls = index_reachable_static_calls(&graph, &modules, &reachable)?;
        let error = match build_callable_effect_plan_index(
            &modules,
            &reachable,
            &static_calls,
            EffectExecutionMode::BlockingFiber,
        ) {
            Ok(_) => bail!("relation corruption was accepted"),
            Err(error) => error.to_string(),
        };
        ensure!(
            error.contains(expected_error),
            "relation corruption produced the wrong rejection: expected {expected_error:?}, got {error:?}"
        );
        Ok(())
    }

    pub(super) fn exercise_effect_value_corruption(selector: usize) -> Result<()> {
        match selector % EFFECT_VALUE_CORRUPTION_COUNT {
            0 => require_effect_value_corruption_rejection(
                r#"export async function selected(pending, unrelated) {
  await pending;
  return null;
}
"#,
                "parameter origin conflicts with exact Oxc parameter binding",
                |summary, _source| {
                    let mut changed = false;
                    for_each_effect_value_flow(summary, |flow| {
                        for path in &mut flow.paths {
                            if let CallableEffectValueOriginCandidate::Parameter { origin } =
                                &mut path.origin
                                && origin.name == "pending"
                            {
                                origin.name = "unrelated".to_string();
                                changed = true;
                            }
                        }
                    });
                    ensure!(changed, "parameter-name corruption found no origin");
                    Ok(())
                },
            ),
            1 => require_effect_value_corruption_rejection(
                r#"export async function selected(pending, unrelated) {
  await pending;
  return null;
}
"#,
                "parameter origin conflicts with exact Oxc parameter binding",
                |summary, source| {
                    let unrelated_start = source
                        .find("unrelated")
                        .context("parameter fixture has no unrelated parameter")?
                        as u32;
                    let mut changed = false;
                    for_each_effect_value_flow(summary, |flow| {
                        for path in &mut flow.paths {
                            if let CallableEffectValueOriginCandidate::Parameter { origin } =
                                &mut path.origin
                                && origin.name == "pending"
                            {
                                origin.declaration.start = unrelated_start;
                                changed = true;
                            }
                        }
                    });
                    ensure!(changed, "parameter-binding corruption found no origin");
                    Ok(())
                },
            ),
            2 => require_effect_value_corruption_rejection(
                r#"export async function selected(pending, unrelated) {
  await pending;
  return null;
}
"#,
                "parameter origin conflicts with exact Oxc parameter binding",
                |summary, _source| {
                    let mut changed = false;
                    for_each_effect_value_flow(summary, |flow| {
                        for path in &mut flow.paths {
                            if let CallableEffectValueOriginCandidate::Parameter { origin } =
                                &mut path.origin
                                && origin.name == "pending"
                            {
                                origin.index = 1;
                                changed = true;
                            }
                        }
                    });
                    ensure!(changed, "parameter-index corruption found no origin");
                    Ok(())
                },
            ),
            3..=5 => require_effect_value_corruption_rejection(
                r#"export async function selected(pending, unrelated) {
  const first = pending;
  const other = unrelated;
  void other;
  await first;
  return null;
}
"#,
                "alias conflicts with exact Oxc binding flow",
                |summary, source| {
                    let selector = selector % EFFECT_VALUE_CORRUPTION_COUNT;
                    let other_binding = source
                        .find("other =")
                        .context("alias fixture has no other binding")?
                        as u32;
                    let other_initializer = (source
                        .find("const other = unrelated")
                        .context("alias fixture has no other initializer")?
                        + "const other = ".len())
                        as u32;
                    let other_reference = (source
                        .find("void other")
                        .context("alias fixture has no other reference")?
                        + "void ".len()) as u32;
                    let mut changed = false;
                    for_each_effect_value_flow(summary, |flow| {
                        for path in &mut flow.paths {
                            for step in &mut path.steps {
                                if let CallableEffectValueStepCandidate::Alias { edge } = step
                                    && edge.binding.name == "first"
                                {
                                    match selector {
                                        3 => edge.binding.declaration_start = other_binding,
                                        4 => {
                                            edge.initializer.start = other_initializer;
                                            edge.initializer.end =
                                                other_initializer + "unrelated".len() as u32;
                                        }
                                        5 => {
                                            edge.reference.start = other_reference;
                                            edge.reference.end =
                                                other_reference + "other".len() as u32;
                                        }
                                        _ => unreachable!(),
                                    }
                                    changed = true;
                                }
                            }
                        }
                    });
                    ensure!(changed, "alias corruption found no alias step");
                    Ok(())
                },
            ),
            6 | 7 => require_effect_value_corruption_rejection(
                r#"export async function selected(flag, pending, unrelated) {
  return await (flag ? pending : unrelated);
}
"#,
                "choice conflicts with exact conditional branch provenance",
                |summary, source| {
                    let unrelated_start = source
                        .rfind("unrelated")
                        .context("choice fixture has no unrelated child")?
                        as u32;
                    let mut changed = false;
                    for_each_effect_value_flow(summary, |flow| {
                        for path in &mut flow.paths {
                            if matches!(
                                &path.origin,
                                CallableEffectValueOriginCandidate::Parameter { origin }
                                    if origin.name == "pending"
                            ) {
                                for step in &mut path.steps {
                                    if let CallableEffectValueStepCandidate::Choice {
                                        branch,
                                        child,
                                        ..
                                    } = step
                                    {
                                        if selector % EFFECT_VALUE_CORRUPTION_COUNT == 6 {
                                            *branch = 1;
                                        } else {
                                            child.start = unrelated_start;
                                            child.end = unrelated_start + "unrelated".len() as u32;
                                        }
                                        changed = true;
                                    }
                                }
                            }
                        }
                    });
                    ensure!(changed, "choice corruption found no choice step");
                    Ok(())
                },
            ),
            8 => require_effect_value_corruption_rejection(
                r#"export async function selected() {
  return await Promise.all([loadFirst(), loadSecond()]);
}
function loadFirst() { return Promise.resolve(1); }
function loadSecond() { return Promise.resolve(2); }
"#,
                "Promise.all child conflicts with exact element provenance",
                |summary, _source| {
                    let mut changed = false;
                    for_each_effect_value_flow(summary, |flow| {
                        for path in &mut flow.paths {
                            for step in &mut path.steps {
                                if let CallableEffectValueStepCandidate::PromiseAll {
                                    child_index,
                                    ..
                                } = step
                                    && *child_index == 0
                                {
                                    *child_index = 1;
                                    changed = true;
                                }
                            }
                        }
                    });
                    ensure!(changed, "Promise.all corruption found no first child");
                    Ok(())
                },
            ),
            9 => require_effect_value_corruption_rejection(
                r#"export async function selected() {
  return await Promise.all([loadFirst(), loadSecond()]);
}
function loadFirst() { return Promise.resolve(1); }
function loadSecond() { return Promise.resolve(2); }
"#,
                "Promise.all edge has no unique callsite fact",
                |summary, _source| {
                    let mut conflicting = summary
                        .promise_all_sites
                        .first()
                        .context("Promise.all corruption fixture has no site")?
                        .clone();
                    conflicting.promise_start += 1;
                    summary.promise_all_sites.push(conflicting);
                    Ok(())
                },
            ),
            10 => require_effect_value_corruption_rejection(
                r#"export async function selected() {
  await loadFirst();
  return await loadSecond();
}
function loadFirst() { return Promise.resolve(1); }
function loadSecond() { return Promise.resolve(2); }
"#,
                "path conflicts with ordered expression provenance",
                |summary, _source| {
                    let second_origin = summary
                        .callable_leaf_plans
                        .iter()
                        .filter_map(|leaf_plan| {
                            let CallableLeafControlCandidate::EffectValueFlow(flow) =
                                &leaf_plan.control
                            else {
                                return None;
                            };
                            flow.paths.iter().find_map(|path| match &path.origin {
                                CallableEffectValueOriginCandidate::CallResult { origin }
                                    if origin.callee == "loadSecond" =>
                                {
                                    Some(path.origin.clone())
                                }
                                _ => None,
                            })
                        })
                        .next()
                        .context("path-splice fixture has no second origin")?;
                    let mut changed = false;
                    for_each_effect_value_flow(summary, |flow| {
                        for path in &mut flow.paths {
                            if matches!(
                                &path.origin,
                                CallableEffectValueOriginCandidate::CallResult { origin }
                                    if origin.callee == "loadFirst"
                            ) {
                                path.origin = second_origin.clone();
                                changed = true;
                            }
                        }
                    });
                    ensure!(changed, "path-splice corruption found no first origin");
                    Ok(())
                },
            ),
            11 => require_effect_value_corruption_rejection(
                r#"export async function selected(pending) {
  pending.then(sideEffect);
  return await pending;
}
"#,
                "rejections conflict with exact resolved-binding reference accounting",
                |summary, _source| {
                    let mut removed = 0;
                    for_each_effect_value_flow(summary, |flow| {
                        removed += flow.rejections.len();
                        flow.rejections.clear();
                    });
                    ensure!(removed > 0, "accounting corruption removed no rejection");
                    Ok(())
                },
            ),
            12 => require_effect_value_corruption_rejection(
                r#"export async function selected(pending, unrelated) {
  consume(unrelated, pending);
  return await pending;
}
function consume(first, second) {
  return second ?? first;
}
"#,
                "call argument conflicts with its independent call fact",
                |summary, _source| {
                    let mut changed = false;
                    for_each_effect_value_flow(summary, |flow| {
                        for path in &mut flow.paths {
                            if let CallableEffectValueSinkCandidate::CallArgument {
                                argument_index,
                                ..
                            } = &mut path.sink
                                && *argument_index == 1
                            {
                                *argument_index = 0;
                                changed = true;
                            }
                        }
                    });
                    ensure!(changed, "call-argument corruption found no second argument");
                    Ok(())
                },
            ),
            13 => require_effect_value_corruption_rejection(
                r#"export async function selected(ctx, activity) {
  return await ctx.db.get("documents", activity.activityId);
}
"#,
                "effect operand projection has no callable parameter name",
                |summary, _source| {
                    let mut changed = false;
                    for_each_leaf_effect(summary, |effect| {
                        for projection in effect.dynamic_parameter_projections.iter_mut().flatten()
                        {
                            if projection.index == 1 {
                                projection.index = 2;
                                changed = true;
                            }
                        }
                    });
                    ensure!(
                        changed,
                        "effect-operand projection-index corruption found no compound parameter projection"
                    );
                    Ok(())
                },
            ),
            _ => require_effect_value_corruption_rejection(
                r#"export async function selected(ctx, activity) {
  return await ctx.db.get("documents", activity.activityId);
}
"#,
                "effect operand projection conflicts with its exact Oxc parameter reference",
                |summary, source| {
                    let property_start = source
                        .rfind("activityId")
                        .context("effect-operand fixture has no member property")?
                        as u32;
                    let mut changed = false;
                    for_each_leaf_effect(summary, |effect| {
                        for projection in effect.dynamic_parameter_projections.iter_mut().flatten()
                        {
                            if projection.index == 1 {
                                projection.reference.start = property_start;
                                projection.reference.end =
                                    property_start + "activityId".len() as u32;
                                changed = true;
                            }
                        }
                    });
                    ensure!(
                        changed,
                        "effect-operand projection-reference corruption found no compound parameter projection"
                    );
                    Ok(())
                },
            ),
        }
    }

    pub(super) fn summarize_source(module_key: &str, source: &str) -> Result<Value> {
        serde_json::to_value(summarize(module_key, source)?).context("module summary serialization")
    }

    pub(super) fn compile_modules(
        modules: &[HarnessModule],
        entry_path: &str,
        export_name: &str,
        source_operations: &[HarnessSourceOperation],
        dependency_adapters: &[HarnessDependencyAdapter],
        effect_execution_mode: HarnessEffectExecutionMode,
    ) -> Result<HarnessOutput> {
        ensure!(
            !modules.is_empty(),
            "invariant-validation compilation needs at least one module"
        );
        let mut loaded = BTreeMap::new();
        let mut metafile_inputs = BTreeMap::new();
        for module in modules {
            ensure!(
                !loaded.contains_key(&module.module_key),
                "invariant-validation compilation module keys must be unique"
            );
            let summary = summarize(&module.module_key, &module.source)?;
            loaded.insert(
                module.module_key.clone(),
                LoadedModule::new(summary, module.source.clone()),
            );
            metafile_inputs.insert(
                module.module_key.clone(),
                EsbuildInput {
                    imports: module
                        .imports
                        .iter()
                        .map(|HarnessImport { original, resolved }| EsbuildImport {
                            path: resolved.clone(),
                            kind: "import-statement".to_string(),
                            original: Some(original.clone()),
                            external: false,
                        })
                        .collect(),
                },
            );
        }
        ensure!(
            loaded.contains_key(entry_path),
            "invariant-validation entry module is absent"
        );
        for module in modules {
            for import in &module.imports {
                ensure!(
                    loaded.contains_key(&import.resolved),
                    "invariant-validation import {} resolves to an absent module",
                    import.original
                );
            }
        }
        let entry_summary = serde_json::to_value(
            &*loaded
                .get(entry_path)
                .context("invariant-validation entry module disappeared")?
                .summary,
        )?;
        let callable_labels = callable_labels(&loaded);
        let context_reuse_summary = Value::Object(
            loaded
                .iter()
                .map(|(module_key, module)| {
                    Ok((
                        module_key.clone(),
                        serde_json::to_value(&module.summary.context_reuse)?,
                    ))
                })
                .collect::<Result<Map<String, Value>>>()?,
        );
        let mut context_reuse_loaded_hard_rules = loaded
            .iter()
            .flat_map(|(module_key, module)| {
                module
                    .summary
                    .context_reuse
                    .raw_hard_facts()
                    .map(move |fact| format!("{module_key}:{}", fact.rule))
            })
            .collect::<Vec<_>>();
        context_reuse_loaded_hard_rules.sort();
        let (dependency_adapter, repo_root) =
            dependency_adapter_material(&loaded, dependency_adapters)?;
        let graph = GraphInput {
            kind: "convex-wasm-esbuild-graph".to_string(),
            repo_root,
            entry_path: entry_path.to_string(),
            export_name: export_name.to_string(),
            toolchain: Toolchain {
                esbuild: "invariant-validation-esbuild".to_string(),
                convex: "invariant-validation-convex".to_string(),
            },
            dependency_adapter,
            registration_adapter: registration_adapter_material(&loaded, source_operations)?,
            assumptions: None,
            effect_execution_mode: match effect_execution_mode {
                HarnessEffectExecutionMode::BlockingFiber => EffectExecutionMode::BlockingFiber,
                HarnessEffectExecutionMode::GuestPromiseEventLoop => {
                    EffectExecutionMode::GuestPromiseEventLoop
                }
            },
            metafile: EsbuildMetafile {
                inputs: metafile_inputs,
                outputs: BTreeMap::new(),
            },
            phase_timings_us: BTreeMap::new(),
        };
        let compiled = compile_export(
            &graph,
            Path::new("/invariant-validation-cache-unused"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &loaded,
            GeneratedSourceMode::Inline,
        )?;
        ensure!(
            compiled.diagnostic_census.is_empty(),
            "invariant-validation single-export compilation produced batch census data"
        );
        let compiler_output = serde_json::to_value(compiled.output)?;
        assert_structurally_complete(&compiler_output)?;
        let reachable_modules = compiler_output
            .get("reachableModules")
            .and_then(Value::as_array)
            .context("compiler output reachableModules are not an array")?
            .iter()
            .map(|module| {
                module
                    .as_str()
                    .context("compiler output reachableModules contains a non-string")
            })
            .collect::<Result<Vec<_>>>()?;
        let mut context_reuse_hard_rules = Vec::new();
        for module_key in reachable_modules {
            let module = loaded.get(module_key).with_context(|| {
                format!("reachable invariant-validation module {module_key} disappeared")
            })?;
            context_reuse_hard_rules.extend(
                module
                    .summary
                    .context_reuse
                    .raw_hard_facts()
                    .map(|fact| fact.rule.to_string()),
            );
        }
        context_reuse_hard_rules.sort();
        let mut normalized_output = compiler_output.clone();
        remove_runtime_measurements(&mut normalized_output);
        let semantic_projection = operation_projection(&compiler_output);
        Ok(HarnessOutput {
            compiler_output,
            normalized_output,
            semantic_projection,
            callable_labels,
            entry_summary,
            context_reuse_summary,
            context_reuse_hard_rules,
            context_reuse_loaded_hard_rules,
        })
    }
}

pub fn summarize_source(module_key: &str, source: &str) -> Result<Value, String> {
    implementation::summarize_source(module_key, source).map_err(|error| format!("{error:#}"))
}

pub fn exercise_effect_value_corruption(selector: usize) -> Result<(), String> {
    implementation::exercise_effect_value_corruption(selector).map_err(|error| format!("{error:#}"))
}

pub fn compile_modules(
    modules: &[HarnessModule],
    entry_path: &str,
    export_name: &str,
) -> Result<HarnessOutput, String> {
    compile_modules_in_effect_mode(
        modules,
        entry_path,
        export_name,
        HarnessEffectExecutionMode::BlockingFiber,
    )
}

pub fn compile_modules_in_effect_mode(
    modules: &[HarnessModule],
    entry_path: &str,
    export_name: &str,
    effect_execution_mode: HarnessEffectExecutionMode,
) -> Result<HarnessOutput, String> {
    implementation::compile_modules(
        modules,
        entry_path,
        export_name,
        &[],
        &[],
        effect_execution_mode,
    )
    .map_err(|error| format!("{error:#}"))
}

pub fn compile_modules_with_dependency_adapters(
    modules: &[HarnessModule],
    entry_path: &str,
    export_name: &str,
    dependency_adapters: &[HarnessDependencyAdapter],
) -> Result<HarnessOutput, String> {
    compile_modules_with_dependency_adapters_in_effect_mode(
        modules,
        entry_path,
        export_name,
        dependency_adapters,
        HarnessEffectExecutionMode::BlockingFiber,
    )
}

pub fn compile_modules_with_dependency_adapters_in_effect_mode(
    modules: &[HarnessModule],
    entry_path: &str,
    export_name: &str,
    dependency_adapters: &[HarnessDependencyAdapter],
    effect_execution_mode: HarnessEffectExecutionMode,
) -> Result<HarnessOutput, String> {
    implementation::compile_modules(
        modules,
        entry_path,
        export_name,
        &[],
        dependency_adapters,
        effect_execution_mode,
    )
    .map_err(|error| format!("{error:#}"))
}

pub fn compile_modules_with_source_operations(
    modules: &[HarnessModule],
    entry_path: &str,
    export_name: &str,
    source_operations: &[HarnessSourceOperation],
) -> Result<HarnessOutput, String> {
    implementation::compile_modules(
        modules,
        entry_path,
        export_name,
        source_operations,
        &[],
        HarnessEffectExecutionMode::BlockingFiber,
    )
    .map_err(|error| format!("{error:#}"))
}
