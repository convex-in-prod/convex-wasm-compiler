#[cfg(test)]
mod canonical_compiler_json_tests {
    use super::{canonical_compiler_json_bytes, hash_bytes};

    #[test]
    fn operation_identity_matches_the_javascript_canonical_json_contract() {
        let value = serde_json::from_str(
            r#"[{"stableKey":"operation_\ud83d\ude00\n","table":"documents","limit":null,"kind":"databaseIndexQuery","indexConstraints":[{"valueSource":"args.hash","operator":"eq","field":"hash"}],"id":7}]"#,
        )
        .unwrap();
        let canonical = canonical_compiler_json_bytes(&value).unwrap();

        assert_eq!(
            String::from_utf8(canonical.clone()).unwrap(),
            "[{\"id\":7,\"indexConstraints\":[{\"field\":\"hash\",\"operator\":\"eq\",\"valueSource\":\"args.hash\"}],\"kind\":\"databaseIndexQuery\",\"limit\":null,\"stableKey\":\"operation_😀\\n\",\"table\":\"documents\"}]"
        );
        assert_eq!(
            hash_bytes(&canonical),
            "4980fc52bdc3d866de5d9697af366b188a4d0c3b05ed113f09dca1fc12564113"
        );
    }
}

#[cfg(test)]
mod cli_argument_tests {
    use super::parse_arguments;

    #[test]
    fn single_export_cli_rejects_duplicate_path_options() {
        let required = ["--graph", "graph.json", "--cache-dir", "cache"];
        for duplicate in ["--graph", "--cache-dir", "--output"] {
            let mut arguments = required.map(str::to_string).to_vec();
            if duplicate == "--output" {
                arguments.extend(["--output".to_string(), "first.json".to_string()]);
            }
            arguments.extend([duplicate.to_string(), "second.json".to_string()]);
            assert!(parse_arguments(arguments).is_err(), "{duplicate}");
        }
    }
}

#[cfg(test)]
mod generated_source_publication_tests {
    use super::{hash_bytes, publish_generated_source};
    use std::{
        env, fs,
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn generated_source_publication_rejects_a_symlinked_cache_parent() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "convex-wasm-generated-source-symlink-{}-{unique}",
            std::process::id()
        ));
        let cache = root.join("cache");
        let escaped = root.join("escaped");
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir(&escaped).unwrap();
        symlink(&escaped, cache.join("generated-sources")).unwrap();
        let source = b"export default 1;\n";
        let error = publish_generated_source(&cache, &hash_bytes(source), source).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("generated source cache path is not an owned directory"),
            "{error:#}"
        );
        assert_eq!(fs::read_dir(&escaped).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
fn test_registration_adapter_material() -> RegistrationAdapterMaterial {
    RegistrationAdapterMaterial {
        kind: "convex-wasm-registration-adapter-material".to_string(),
        descriptor: RegistrationAdapterDescriptor {
            kind: "convex-wasm-registration-adapter-descriptor".to_string(),
            adapters: Vec::new(),
            source_operations: Vec::new(),
        },
        source: RegistrationAdapterSourceMaterial {
            path: "scripts/fixture-registration-adapters.json".to_string(),
            sha256: "0".repeat(64),
            bytes: 1,
        },
    }
}

#[cfg(test)]
fn test_dependency_adapter_material() -> DependencyAdapterMaterial {
    DependencyAdapterMaterial {
        kind: "convex-wasm-dependency-adapter-material".to_string(),
        descriptor: DependencyAdapterDescriptor {
            kind: "convex-wasm-dependency-adapter-descriptor".to_string(),
            adapters: Vec::new(),
        },
        source: RegistrationAdapterSourceMaterial {
            path: "scripts/fixture-dependency-adapters.json".to_string(),
            sha256: "0".repeat(64),
            bytes: 1,
        },
        current: DependencyAdapterCurrentMaterial {
            files: Vec::new(),
            locks: Vec::new(),
        },
    }
}

#[cfg(test)]
const TEST_GENERATED_SERVER_MODULE: &str = "convex/_generated/server.js";

#[cfg(test)]
const TEST_GENERATED_SERVER_SOURCE: &str = r#"export const query = undefined;
export const internalQuery = undefined;
export const mutation = undefined;
export const internalMutation = undefined;
"#;

#[cfg(test)]
fn with_test_registration_imports(source: &str) -> String {
    format!(
        "import {{ query, internalQuery, mutation, internalMutation }} from \"./_generated/server\";\n{source}"
    )
}

#[cfg(test)]
mod diagnostic_index_tests {
    use super::{LoadedModule, PhaseMeasurements, hash_bytes, summarize_module};
    use std::{collections::BTreeMap, path::Path};

    fn loaded_module(source: &str) -> LoadedModule {
        let summary = summarize_module(
            "convex/diagnosticIndexFixture.ts",
            Path::new("convex/diagnosticIndexFixture.ts"),
            source,
            &hash_bytes(source.as_bytes()),
            "fixture-cache-key",
            "fixture-pipeline",
            "fixture-context-policy",
            &mut PhaseMeasurements::default(),
        )
        .unwrap();
        LoadedModule::new(summary, source.to_string())
    }

    fn scanned_line_column(source: &str, start: u32) -> (usize, usize) {
        let offset = (start as usize).min(source.len());
        let prefix = &source[..offset];
        (
            prefix.bytes().filter(|byte| *byte == b'\n').count() + 1,
            prefix
                .as_bytes()
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(offset + 1, |newline| offset - newline),
        )
    }

    #[test]
    fn cached_line_columns_match_prefix_scans_at_utf8_boundaries_and_eof() {
        let source = "αβ\nconst emoji = \"🙂\";\n終";
        let module = loaded_module(source);
        let mut offsets = source
            .char_indices()
            .map(|(offset, _)| offset as u32)
            .collect::<Vec<_>>();
        offsets.push(source.len() as u32);
        for offset in offsets {
            assert_eq!(
                module.line_column(offset),
                scanned_line_column(source, offset),
                "byte offset {offset}"
            );
        }
        assert_eq!(module.line_column(2), (1, 3));
        assert_eq!(
            module.line_column(source.len() as u32),
            scanned_line_column(source, source.len() as u32)
        );
    }

    #[test]
    fn cached_diagnostic_ends_match_minimum_construct_end_scans() {
        let source = "export const selected = async (value: string) => ({ value });\n";
        let module = loaded_module(source);
        let mut expected = BTreeMap::new();
        for construct in &module.summary.constructs {
            expected
                .entry(construct.start)
                .and_modify(|end: &mut u32| *end = (*end).min(construct.end))
                .or_insert(construct.end);
        }
        for (start, end) in expected {
            assert_eq!(module.diagnostic_end(start), end, "construct start {start}");
        }
        let eof = source.len() as u32;
        assert_eq!(module.diagnostic_end(eof), eof + 1);
    }
}

#[cfg(test)]
mod dependency_adapter_tests {
    use super::callable_plans::CallableLeafControlCandidate;
    use super::callable_value_flow::{
        CallableEffectValueOriginCandidate, CallableEffectValueSinkCandidate,
        CallableEffectValueStepCandidate,
        authenticate_callable_effect_value_flows_without_effect_plans,
    };
    use super::{
        CompilerModeOutput, DependencyAdapterCurrentFile, DependencyAdapterCurrentMaterial,
        DependencyAdapterDescriptor, DependencyAdapterDescriptorEntry,
        DependencyAdapterExpectedMaterial, DependencyAdapterExportIdentity,
        DependencyAdapterLockMaterial, DependencyAdapterMaterial, DependencyAdapterPackageMaterial,
        DependencyAdapterSemantic, DependencyAdapterSemanticSource, DependencyAdapterSemanticUnit,
        DependencyAdapterSubstitutionIdentity, EsbuildImport, EsbuildInput, EsbuildMetafile,
        GeneratedSourceMode, GraphInput, LoadedModule, PhaseMeasurements, ReachableUnit,
        SourceRange, TEST_GENERATED_SERVER_MODULE, TEST_GENERATED_SERVER_SOURCE, Toolchain,
        adapt_dependency_call, compile_export, dependency_adapter_iterable_is_owned,
        dependency_adapter_material_drift, hash_bytes, summarize_module,
        test_registration_adapter_material,
    };
    use std::{
        collections::BTreeMap,
        env, fs,
        path::{Path, PathBuf},
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    const MODULE_KEY: &str = "convex/dependencyAdapterFixture.ts";

    fn summary(source: &str) -> super::ModuleSummary {
        summarize_module(
            MODULE_KEY,
            Path::new(MODULE_KEY),
            source,
            &hash_bytes(source.as_bytes()),
            "fixture-cache-key",
            "fixture-pipeline",
            "fixture-context-policy",
            &mut PhaseMeasurements::default(),
        )
        .unwrap()
    }

    fn consume_range(source: &str, expression: &str) -> SourceRange {
        let marker = format!("consume({expression})");
        let start = source.find(&marker).unwrap() + "consume(".len();
        SourceRange {
            start: start as u32,
            end: (start + expression.len()) as u32,
        }
    }

    fn graph() -> GraphInput {
        GraphInput {
            kind: "convex-wasm-esbuild-graph".to_string(),
            repo_root: Path::new("/fixture").to_path_buf(),
            functions_root: "convex".to_string(),
            entry_path: MODULE_KEY.to_string(),
            export_name: "selected".to_string(),
            toolchain: Toolchain {
                esbuild: "fixture".to_string(),
                convex: "fixture".to_string(),
            },
            dependency_adapter: DependencyAdapterMaterial {
                kind: "convex-wasm-dependency-adapter-material".to_string(),
                descriptor: DependencyAdapterDescriptor {
                    kind: "convex-wasm-dependency-adapter-descriptor".to_string(),
                    adapters: Vec::new(),
                },
                source: super::RegistrationAdapterSourceMaterial {
                    path: "scripts/fixture-dependency-adapters.json".to_string(),
                    sha256: "0".repeat(64),
                    bytes: 1,
                },
                current: DependencyAdapterCurrentMaterial {
                    files: Vec::new(),
                    locks: Vec::new(),
                },
            },
            registration_adapter: test_registration_adapter_material(),
            assumptions: None,
            effect_execution_mode: super::EffectExecutionMode::BlockingFiber,
            metafile: EsbuildMetafile {
                inputs: BTreeMap::new(),
                outputs: BTreeMap::new(),
            },
            phase_timings_us: BTreeMap::new(),
        }
    }

    struct TemporaryDirectory(PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn temporary_directory(name: &str) -> TemporaryDirectory {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("{name}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        TemporaryDirectory(path)
    }

    fn compile_adapter(
        export_name: &str,
        semantic_kind: &str,
        call: &str,
    ) -> super::CompilerOutput {
        compile_adapter_with_return(export_name, semantic_kind, call, "result")
    }

    fn compile_adapter_with_return(
        export_name: &str,
        semantic_kind: &str,
        call: &str,
        return_expression: &str,
    ) -> super::CompilerOutput {
        compile_adapter_with_options(
            export_name,
            semantic_kind,
            call,
            return_expression,
            "",
            "none",
        )
    }

    fn compile_adapter_with_options(
        export_name: &str,
        semantic_kind: &str,
        call: &str,
        return_expression: &str,
        top_level_source: &str,
        material_change: &str,
    ) -> super::CompilerOutput {
        compile_adapter_with_execution_mode(
            export_name,
            semantic_kind,
            call,
            return_expression,
            top_level_source,
            material_change,
            super::EffectExecutionMode::BlockingFiber,
        )
    }

    fn compile_adapter_with_execution_mode(
        export_name: &str,
        semantic_kind: &str,
        call: &str,
        return_expression: &str,
        top_level_source: &str,
        material_change: &str,
        effect_execution_mode: super::EffectExecutionMode,
    ) -> super::CompilerOutput {
        const ADAPTER_MODULE: &str = "node_modules/fixture-adapter/adapter.js";
        const CONVEX_SERVER_MODULE: &str = "node_modules/convex/dist/esm/server/index.js";
        const PACKAGE_JSON: &str = "node_modules/fixture-adapter/package.json";
        const SEMANTIC_MODULE: &str = "node_modules/fixture-adapter/semantic.js";
        let root = temporary_directory("convex-wasm-dependency-adapter-compile");
        let package_source = "{\"name\":\"fixture-adapter\",\"version\":\"1.0.0\"}\n";
        let adapter_source = format!("export async function {export_name}() {{}}\n");
        let import_specifier = if semantic_kind == "functionHandleCreate" {
            "convex/server"
        } else {
            "fixture-adapter"
        };
        let import_resolved = if semantic_kind == "functionHandleCreate" {
            CONVEX_SERVER_MODULE
        } else {
            ADAPTER_MODULE
        };
        let convex_server_source =
            format!("export {{ {export_name} }} from \"./components/index.js\";\n");
        let entry_source = format!(
            r#"import {{ query }} from "./_generated/server";
import {{ {export_name} as relationship }} from "{import_specifier}";
{top_level_source}
export const selected = query({{
  args: {{ ids: v.array(v.id("docs")), owner: v.string() }},
  handler: async (ctx, args) => {{
    const result = {call};
    return {return_expression};
  }},
}});
"#
        );
        let adapter_summary = summary_for(ADAPTER_MODULE, &adapter_source);
        let unit_source_sha256 = hash_bytes(
            adapter_summary
                .units
                .get(export_name)
                .unwrap()
                .source
                .as_bytes(),
        );
        let actual_module_sha256 = hash_bytes(adapter_source.as_bytes());
        let actual_package_sha256 = hash_bytes(package_source.as_bytes());
        let mut descriptor = DependencyAdapterDescriptorEntry {
            id: format!("fixture{export_name}"),
            export_identity: DependencyAdapterExportIdentity {
                module_path: ADAPTER_MODULE.to_string(),
                export_name: export_name.to_string(),
                unit_source_sha256,
            },
            substitution: (semantic_kind == "functionHandleCreate").then(|| {
                DependencyAdapterSubstitutionIdentity {
                    module_specifier: "convex/server".to_string(),
                    export_name: export_name.to_string(),
                    unit_source_sha256: "5".repeat(64),
                }
            }),
            material: DependencyAdapterExpectedMaterial {
                module_source_sha256: actual_module_sha256.clone(),
                semantic_sources: Vec::new(),
                package_json: DependencyAdapterPackageMaterial {
                    path: PACKAGE_JSON.to_string(),
                    sha256: actual_package_sha256.clone(),
                    version: "1.0.0".to_string(),
                },
                package_lock: DependencyAdapterLockMaterial {
                    path: "package-lock.json".to_string(),
                    package_key: "node_modules/fixture-adapter".to_string(),
                    entry_sha256: "4".repeat(64),
                },
                installed_lock: DependencyAdapterLockMaterial {
                    path: "node_modules/.package-lock.json".to_string(),
                    package_key: "node_modules/fixture-adapter".to_string(),
                    entry_sha256: "4".repeat(64),
                },
            },
            semantic: DependencyAdapterSemantic {
                kind: semantic_kind.to_string(),
            },
        };
        let semantic_source = "export function semanticHelper() {}\n";
        let semantic_summary = summary_for(SEMANTIC_MODULE, semantic_source);
        match material_change {
            "none" => {}
            "selectedIdentityChange" => descriptor.id.push_str("Changed"),
            "unusedDescriptorA" | "unusedDescriptorB" => {}
            "exportUnitDrift" => descriptor.export_identity.unit_source_sha256 = "a".repeat(64),
            "semanticMissing"
            | "semanticSourceDrift"
            | "semanticUnitMissing"
            | "semanticUnitDrift" => {
                descriptor
                    .material
                    .semantic_sources
                    .push(DependencyAdapterSemanticSource {
                        path: SEMANTIC_MODULE.to_string(),
                        source_sha256: if material_change == "semanticSourceDrift" {
                            "b".repeat(64)
                        } else {
                            hash_bytes(semantic_source.as_bytes())
                        },
                        units: vec![DependencyAdapterSemanticUnit {
                            unit_name: if material_change == "semanticUnitMissing" {
                                "missingHelper".to_string()
                            } else {
                                "semanticHelper".to_string()
                            },
                            unit_source_sha256: if material_change == "semanticUnitDrift" {
                                "c".repeat(64)
                            } else {
                                hash_bytes(
                                    semantic_summary
                                        .units
                                        .get("semanticHelper")
                                        .unwrap()
                                        .source
                                        .as_bytes(),
                                )
                            },
                        }],
                    });
            }
            other => panic!("unsupported fixture material change {other}"),
        }
        let mut descriptor_entries = vec![descriptor.clone()];
        if matches!(material_change, "unusedDescriptorA" | "unusedDescriptorB") {
            let mut unused = descriptor.clone();
            unused.id = "unusedFixture".to_string();
            unused.export_identity.module_path = "node_modules/z-unused/adapter.js".to_string();
            unused.export_identity.export_name = "unused".to_string();
            unused.material.module_source_sha256 = if material_change == "unusedDescriptorA" {
                "d".repeat(64)
            } else {
                "e".repeat(64)
            };
            descriptor_entries.push(unused);
        }
        let package_path = root.0.join(PACKAGE_JSON);
        fs::create_dir_all(package_path.parent().unwrap()).unwrap();
        fs::write(&package_path, package_source).unwrap();
        let graph = GraphInput {
            kind: "convex-wasm-esbuild-graph".to_string(),
            repo_root: root.0.clone(),
            functions_root: "convex".to_string(),
            entry_path: MODULE_KEY.to_string(),
            export_name: "selected".to_string(),
            toolchain: Toolchain {
                esbuild: "fixture".to_string(),
                convex: "fixture".to_string(),
            },
            dependency_adapter: DependencyAdapterMaterial {
                kind: "convex-wasm-dependency-adapter-material".to_string(),
                descriptor: DependencyAdapterDescriptor {
                    kind: "convex-wasm-dependency-adapter-descriptor".to_string(),
                    adapters: descriptor_entries,
                },
                source: super::RegistrationAdapterSourceMaterial {
                    path: "scripts/fixture-dependency-adapters.json".to_string(),
                    sha256: "0".repeat(64),
                    bytes: 1,
                },
                current: DependencyAdapterCurrentMaterial {
                    files: {
                        let mut files = vec![
                            super::DependencyAdapterCurrentFile {
                                path: PACKAGE_JSON.to_string(),
                                sha256: actual_package_sha256,
                                bytes: package_source.len(),
                            },
                            super::DependencyAdapterCurrentFile {
                                path: ADAPTER_MODULE.to_string(),
                                sha256: actual_module_sha256,
                                bytes: adapter_source.len(),
                            },
                        ];
                        if !descriptor.material.semantic_sources.is_empty() {
                            files.push(super::DependencyAdapterCurrentFile {
                                path: SEMANTIC_MODULE.to_string(),
                                sha256: hash_bytes(semantic_source.as_bytes()),
                                bytes: semantic_source.len(),
                            });
                        }
                        files
                    },
                    locks: vec![
                        descriptor.material.installed_lock.clone(),
                        descriptor.material.package_lock.clone(),
                    ],
                },
            },
            registration_adapter: test_registration_adapter_material(),
            assumptions: None,
            effect_execution_mode,
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([
                    (
                        MODULE_KEY.to_string(),
                        EsbuildInput {
                            imports: vec![
                                EsbuildImport {
                                    path: TEST_GENERATED_SERVER_MODULE.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some("./_generated/server".to_string()),
                                    external: false,
                                },
                                EsbuildImport {
                                    path: import_resolved.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some(import_specifier.to_string()),
                                    external: false,
                                },
                            ],
                        },
                    ),
                    (
                        TEST_GENERATED_SERVER_MODULE.to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                    (
                        ADAPTER_MODULE.to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                    (
                        CONVEX_SERVER_MODULE.to_string(),
                        EsbuildInput {
                            imports: vec![EsbuildImport {
                                path: ADAPTER_MODULE.to_string(),
                                kind: "import-statement".to_string(),
                                original: Some("./components/index.js".to_string()),
                                external: false,
                            }],
                        },
                    ),
                ]),
                outputs: BTreeMap::new(),
            },
            phase_timings_us: BTreeMap::new(),
        };
        let mut modules = BTreeMap::from([
            (
                MODULE_KEY.to_string(),
                LoadedModule::new(summary(&entry_source), entry_source),
            ),
            (
                ADAPTER_MODULE.to_string(),
                LoadedModule::new(adapter_summary, adapter_source),
            ),
            (
                CONVEX_SERVER_MODULE.to_string(),
                LoadedModule::new(
                    summary_for(CONVEX_SERVER_MODULE, &convex_server_source),
                    convex_server_source,
                ),
            ),
            (
                TEST_GENERATED_SERVER_MODULE.to_string(),
                LoadedModule::new(
                    summary_for(TEST_GENERATED_SERVER_MODULE, TEST_GENERATED_SERVER_SOURCE),
                    TEST_GENERATED_SERVER_SOURCE.to_string(),
                ),
            ),
        ]);
        if !descriptor.material.semantic_sources.is_empty() && material_change != "semanticMissing"
        {
            modules.insert(
                SEMANTIC_MODULE.to_string(),
                LoadedModule::new(semantic_summary, semantic_source.to_string()),
            );
        }
        compile_export(
            &graph,
            &root.0.join("cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output
    }

    fn summary_for(module: &str, source: &str) -> super::ModuleSummary {
        summarize_module(
            module,
            Path::new(module),
            source,
            &hash_bytes(source.as_bytes()),
            "fixture-cache-key",
            "fixture-pipeline",
            "fixture-context-policy",
            &mut PhaseMeasurements::default(),
        )
        .unwrap()
    }

    fn effect_value_authentication_error(
        summary: super::ModuleSummary,
        source: &str,
        unit_name: &str,
    ) -> String {
        let unit = summary.units.get(unit_name).unwrap().clone();
        let unit_id = format!("{MODULE_KEY}#{unit_name}");
        let reachable = BTreeMap::from([(
            unit_id.clone(),
            ReachableUnit {
                id: unit_id,
                module: MODULE_KEY.to_string(),
                name: unit_name.to_string(),
                start: unit.start,
                end: unit.end,
                source: unit.source,
                kind: unit.kind,
                dependency_chain: vec![unit_name.to_string()],
                dependencies: BTreeMap::new(),
            },
        )]);
        let modules = BTreeMap::from([(
            MODULE_KEY.to_string(),
            LoadedModule::new(summary, source.to_string()),
        )]);
        authenticate_callable_effect_value_flows_without_effect_plans(&modules, &reachable)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn direct_suspension_facts_reject_detached_chained_and_conditional_promises() {
        let source = r#"
import { adapter } from "fixture-adapter";
async function awaited() { return await adapter(ctx.db, "docs", "by_owner", owner); }
async function returned() { return adapter(ctx.db, "docs", "by_owner", owner); }
const concise = async () => adapter(ctx.db, "docs", "by_owner", owner);
async function detached() { const pending = adapter(ctx.db, "docs", "by_owner", owner); touch(); return await pending; }
async function chained() { return adapter(ctx.db, "docs", "by_owner", owner).then(use); }
async function conditional() { return flag ? adapter(ctx.db, "docs", "by_owner", owner) : null; }
async function batched() { return Promise.all(ids.map((id) => adapter(ctx.db, "docs", "by_owner", id))); }
"#;
        let summary = summary(source);
        let suspensions = summary
            .calls
            .iter()
            .filter(|call| call.callee == "adapter")
            .map(|call| call.suspension.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            suspensions,
            vec![
                Some("await"),
                Some("return"),
                Some("return"),
                None,
                None,
                None,
                Some("return"),
            ]
        );
    }

    #[test]
    fn effect_value_authentication_rejects_corrupt_sink_rebinding() {
        let await_source = r#"export async function selected(pending, unrelated) {
  await choose(pending, unrelated);
  return null;
}
function choose(first, second) {
  return second ?? first;
}
"#;

        let mut await_summary = summary(await_source);
        let nested_value_start =
            (await_source.find("choose(pending").unwrap() + "choose(".len()) as u32;
        for candidate in &mut await_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    if let CallableEffectValueSinkCandidate::Await { value, .. } = &mut path.sink {
                        *value = SourceRange {
                            start: nested_value_start,
                            end: nested_value_start + "pending".len() as u32,
                        };
                    }
                }
            }
        }
        let error = effect_value_authentication_error(await_summary, await_source, "selected");
        assert!(
            error.contains("await sink conflicts with its exact Oxc operand provenance"),
            "{error}"
        );

        let return_source = r#"export function selected(pending, unrelated) {
  return choose(pending, unrelated);
}
function choose(first, second) {
  return second ?? first;
}
"#;
        let mut return_summary = summary(return_source);
        let nested_value_start =
            (return_source.find("choose(pending").unwrap() + "choose(".len()) as u32;
        for candidate in &mut return_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    if let CallableEffectValueSinkCandidate::Return { value, .. } = &mut path.sink {
                        *value = SourceRange {
                            start: nested_value_start,
                            end: nested_value_start + "pending".len() as u32,
                        };
                    }
                }
            }
        }
        let error = effect_value_authentication_error(return_summary, return_source, "selected");
        assert!(
            error.contains("return sink conflicts with its exact Oxc operand provenance"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_parameter_index_only_rebinding() {
        let source = r#"export async function selected(pending, unrelated) {
  await pending;
  return null;
}
"#;
        let mut module_summary = summary(source);
        let mut changed = false;
        for candidate in &mut module_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    if let CallableEffectValueOriginCandidate::Parameter { origin } =
                        &mut path.origin
                        && origin.name == "pending"
                    {
                        origin.index = 1;
                        changed = true;
                    }
                }
            }
        }
        assert!(changed);
        let error = effect_value_authentication_error(module_summary, source, "selected");
        assert!(
            error.contains("parameter origin conflicts with exact Oxc parameter binding"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_joint_callable_parameter_reordering() {
        let source = r#"export async function selected(first, second) {
  await first;
  return null;
}
"#;
        let mut module_summary = summary(source);
        let mut changed = false;
        for leaf_plan in &mut module_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut leaf_plan.control
                && leaf_plan.parameter_names == ["first", "second"]
            {
                leaf_plan.parameter_names.swap(0, 1);
                leaf_plan.parameter_starts.swap(0, 1);
                for path in &mut flow.paths {
                    if let CallableEffectValueOriginCandidate::Parameter { origin } =
                        &mut path.origin
                    {
                        origin.index = 1;
                    }
                }
                changed = true;
            }
        }
        assert!(changed);
        let error = effect_value_authentication_error(module_summary, source, "selected");
        assert!(
            error.contains("leaf plan conflicts with independent ordered parameter facts"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_alias_initializer_and_reference_rebinding() {
        let source = r#"export async function selected(pending, unrelated) {
  const first = pending;
  const second = unrelated;
  void second;
  await first;
  return null;
}
"#;
        let unrelated_initializer_start =
            (source.find("const second = unrelated").unwrap() + "const second = ".len()) as u32;
        let second_reference_start =
            source.find("void second").unwrap() as u32 + "void ".len() as u32;

        let mut initializer_summary = summary(source);
        let mut changed = false;
        for candidate in &mut initializer_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    for step in &mut path.steps {
                        if let CallableEffectValueStepCandidate::Alias { edge } = step
                            && edge.binding.name == "first"
                        {
                            edge.initializer = SourceRange {
                                start: unrelated_initializer_start,
                                end: unrelated_initializer_start + "unrelated".len() as u32,
                            };
                            changed = true;
                        }
                    }
                }
            }
        }
        assert!(changed);
        let error = effect_value_authentication_error(initializer_summary, source, "selected");
        assert!(
            error.contains("alias conflicts with exact Oxc binding flow"),
            "{error}"
        );

        let mut reference_summary = summary(source);
        let mut changed = false;
        for candidate in &mut reference_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    for step in &mut path.steps {
                        if let CallableEffectValueStepCandidate::Alias { edge } = step
                            && edge.binding.name == "first"
                        {
                            edge.reference = SourceRange {
                                start: second_reference_start,
                                end: second_reference_start + "second".len() as u32,
                            };
                            changed = true;
                        }
                    }
                }
            }
        }
        assert!(changed);
        let error = effect_value_authentication_error(reference_summary, source, "selected");
        assert!(
            error.contains("alias conflicts with exact Oxc binding flow"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_choice_branch_and_child_rebinding() {
        let source = r#"export async function selected(flag, pending, unrelated) {
  return await (flag ? pending : unrelated);
}
"#;
        let unrelated_child_start = source.rfind("unrelated").unwrap() as u32;

        let mut branch_summary = summary(source);
        let mut changed = false;
        for candidate in &mut branch_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    if matches!(
                        &path.origin,
                        CallableEffectValueOriginCandidate::Parameter { origin }
                            if origin.name == "pending"
                    ) {
                        for step in &mut path.steps {
                            if let CallableEffectValueStepCandidate::Choice { branch, .. } = step {
                                *branch = 1;
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        assert!(changed);
        let error = effect_value_authentication_error(branch_summary, source, "selected");
        assert!(
            error.contains("choice conflicts with exact conditional branch provenance"),
            "{error}"
        );

        let mut child_summary = summary(source);
        let mut changed = false;
        for candidate in &mut child_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    if matches!(
                        &path.origin,
                        CallableEffectValueOriginCandidate::Parameter { origin }
                            if origin.name == "pending"
                    ) {
                        for step in &mut path.steps {
                            if let CallableEffectValueStepCandidate::Choice { child, .. } = step {
                                *child = SourceRange {
                                    start: unrelated_child_start,
                                    end: unrelated_child_start + "unrelated".len() as u32,
                                };
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        assert!(changed);
        let error = effect_value_authentication_error(child_summary, source, "selected");
        assert!(
            error.contains("choice conflicts with exact conditional branch provenance"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_corrupt_promise_all_child_index() {
        let source = r#"export async function selected() {
  return await Promise.all([loadFirst(), loadSecond()]);
}
function loadFirst() { return Promise.resolve(1); }
function loadSecond() { return Promise.resolve(2); }
"#;
        let mut module_summary = summary(source);
        let mut changed = false;
        for candidate in &mut module_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    for step in &mut path.steps {
                        if let super::callable_value_flow::CallableEffectValueStepCandidate::PromiseAll {
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
            }
        }
        assert!(changed);
        let error = effect_value_authentication_error(module_summary, source, "selected");
        assert!(
            error.contains("Promise.all child conflicts with exact element provenance"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_promise_all_without_global_provenance() {
        let source = r#"export async function selected() {
  return await Promise.all([loadFirst(), loadSecond()]);
}
function loadFirst() { return Promise.resolve(1); }
function loadSecond() { return Promise.resolve(2); }
"#;
        let mut module_summary = summary(source);
        module_summary
            .globals
            .retain(|reference| reference.name != "Promise");
        let error = effect_value_authentication_error(module_summary, source, "selected");
        assert!(
            error.contains("Promise.all edge lacks unshadowed global provenance"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_duplicate_conflicting_promise_all_sites() {
        let source = r#"export async function selected() {
  return await Promise.all([loadFirst(), loadSecond()]);
}
function loadFirst() { return Promise.resolve(1); }
function loadSecond() { return Promise.resolve(2); }
"#;
        let mut module_summary = summary(source);
        let mut conflicting = module_summary.promise_all_sites[0].clone();
        conflicting.promise_start += 1;
        module_summary.promise_all_sites.push(conflicting);
        let error = effect_value_authentication_error(module_summary, source, "selected");
        assert!(
            error.contains("Promise.all edge has no unique callsite fact"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_corrupt_independent_call_facts() {
        let source = r#"export async function selected(pending, unrelated) {
  consume(unrelated, pending);
  return await pending;
}
function consume(first, second) {
  return second ?? first;
}
"#;
        let mut argument_summary = summary(source);
        for candidate in &mut argument_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    if let CallableEffectValueSinkCandidate::CallArgument { argument_index, .. } =
                        &mut path.sink
                        && *argument_index == 1
                    {
                        *argument_index = 0;
                    }
                }
            }
        }
        let error = effect_value_authentication_error(argument_summary, source, "selected");
        assert!(
            error.contains("call argument conflicts with its independent call fact"),
            "{error}"
        );

        let call_source = r#"export async function selected() {
  return await load();
}
function load() {
  return Promise.resolve(null);
}
"#;
        let mut call_result_summary = summary(call_source);
        for candidate in &mut call_result_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut candidate.control {
                for path in &mut flow.paths {
                    if let CallableEffectValueOriginCandidate::CallResult { origin } =
                        &mut path.origin
                    {
                        origin.callee = "other".to_string();
                    }
                }
            }
        }
        let error = effect_value_authentication_error(call_result_summary, call_source, "selected");
        assert!(
            error.contains("call result conflicts with its independent call fact"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_origin_only_path_splicing() {
        let source = r#"export async function selected() {
  await loadFirst();
  return await loadSecond();
}
function loadFirst() { return Promise.resolve(1); }
function loadSecond() { return Promise.resolve(2); }
"#;
        let mut module_summary = summary(source);
        let second_origin = module_summary
            .callable_leaf_plans
            .iter()
            .filter_map(|leaf_plan| {
                let CallableLeafControlCandidate::EffectValueFlow(flow) = &leaf_plan.control else {
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
            .unwrap();
        let mut changed = false;
        for leaf_plan in &mut module_summary.callable_leaf_plans {
            if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut leaf_plan.control {
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
            }
        }
        assert!(changed);
        let error = effect_value_authentication_error(module_summary, source, "selected");
        assert!(
            error.contains("path conflicts with ordered expression provenance"),
            "{error}"
        );
    }

    #[test]
    fn effect_value_authentication_rejects_deleted_write_and_escape_accounting() {
        let fixtures = [
            r#"export async function selected(pending) {
  pending = Promise.resolve(null);
  return await pending;
}
"#,
            r#"export async function selected(pending) {
  pending.then(sideEffect);
  return await pending;
}
"#,
        ];
        for source in fixtures {
            let mut module_summary = summary(source);
            let mut removed = 0;
            for leaf_plan in &mut module_summary.callable_leaf_plans {
                if let CallableLeafControlCandidate::EffectValueFlow(flow) = &mut leaf_plan.control
                {
                    removed += flow.rejections.len();
                    flow.rejections.clear();
                }
            }
            assert!(removed > 0);
            let error = effect_value_authentication_error(module_summary, source, "selected");
            assert!(
                error.contains(
                    "rejections conflict with exact resolved-binding reference accounting"
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn authenticated_effect_value_graph_composes_generic_callable_value_routes() {
        let fixtures = [
            (
                "const alias to await",
                "await loadAlias(ctx, args.owner)",
                "result",
                r#"
async function loadAlias(ctx, owner) {
  const pending = relationship(ctx.db, "docs", "by_owner", owner);
  return await pending;
}
"#,
            ),
            (
                "transparent typed const alias",
                "await loadTypedAlias(ctx, args.owner)",
                "result",
                r#"
async function loadTypedAlias(ctx, owner) {
  const pending = relationship(ctx.db, "docs", "by_owner", owner) as Promise<unknown>;
  return await pending;
}
"#,
            ),
            (
                "transparent typed await operand",
                "relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "await (result as Promise<unknown>)",
                "",
            ),
            (
                "unrelated pure recursion does not poison effect flow",
                "relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "await consumeWithDepth(result, pureRecursive(1))",
                r#"
function pureRecursive(depth) {
  return depth === 0 ? 0 : pureRecursive(depth - 1);
}
async function consumeWithDepth(pending, _depth) {
  return await pending;
}
"#,
            ),
            (
                "helper return to exact caller result",
                "await loadReturned(ctx, args.owner)",
                "result",
                r#"
async function loadReturned(ctx, owner) {
  return relationship(ctx.db, "docs", "by_owner", owner);
}
"#,
            ),
            (
                "exact call argument to target parameter",
                "await consumePending(relationship(ctx.db, \"docs\", \"by_owner\", args.owner))",
                "result",
                r#"
async function consumePending(pending) {
  return await pending;
}
"#,
            ),
            (
                "escaped identifier parameter",
                "await consumeEscaped(relationship(ctx.db, \"docs\", \"by_owner\", args.owner))",
                "result",
                r#"
async function consumeEscaped(p\u0065nding) {
  return await p\u0065nding;
}
"#,
            ),
            (
                "typed parameter annotation",
                "await consumeTyped(relationship(ctx.db, \"docs\", \"by_owner\", args.owner))",
                "result",
                r#"
async function consumeTyped(pending: Promise<unknown>) {
  return await pending;
}
"#,
            ),
            (
                "nonrecursive helper parameter-return round trip",
                "relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "await returnPending(result)",
                r#"
function returnPending(pending) {
  return pending;
}
"#,
            ),
            (
                "handler tail return",
                "relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "result",
                "",
            ),
            (
                "finite conditional choices",
                "args.owner.length > 0 ? relationship(ctx.db, \"docs\", \"by_owner\", args.owner) : relationship(ctx.db, \"docs\", \"by_owner\", \"fallback\")",
                "await result",
                "",
            ),
            (
                "transparent typed conditional children",
                "args.owner.length > 0 ? (relationship(ctx.db, \"docs\", \"by_owner\", args.owner) as Promise<unknown>) : (relationship(ctx.db, \"docs\", \"by_owner\", \"fallback\") as Promise<unknown>)",
                "await result",
                "",
            ),
            (
                "transparent typed Promise.all child",
                "await Promise.all([(relationship(ctx.db, \"docs\", \"by_owner\", args.owner) as Promise<unknown>)])",
                "result",
                "",
            ),
            (
                "one forwarded value reaches multiple safe target branches",
                "relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "await consumeBranched(result, args.owner.length > 0)",
                r#"
async function consumeBranched(pending, first) {
  if (first) return await pending;
  return await pending;
}
"#,
            ),
        ];

        for (name, call, returned, helpers) in fixtures {
            let output = compile_adapter_with_options(
                "getOneFrom",
                "databaseIndexUnique",
                call,
                returned,
                helpers,
                "none",
            );
            assert!(
                output.eligible,
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert_eq!(output.applied_dependency_adapters.len(), 1, "{name}");
        }
    }

    #[test]
    fn authenticated_effect_value_graph_rejects_inexact_or_escaping_routes() {
        let fixtures = [
            (
                "optional dispatch",
                "await consumePending?.(relationship(ctx.db, \"docs\", \"by_owner\", args.owner))",
                "result",
                r#"
async function consumePending(pending) {
  return await pending;
}
"#,
            ),
            (
                "spread dispatch",
                "await consumePending(...[relationship(ctx.db, \"docs\", \"by_owner\", args.owner)])",
                "result",
                r#"
async function consumePending(pending) {
  return await pending;
}
"#,
            ),
            (
                "ambiguous dispatch",
                "await consumePending(relationship(ctx.db, \"docs\", \"by_owner\", args.owner))",
                "(void consumePending, result)",
                r#"
async function consumePending(pending) {
  return await pending;
}
"#,
            ),
            (
                "written alias",
                "await loadWritten(ctx, args.owner)",
                "result",
                r#"
async function loadWritten(ctx, owner) {
  let pending = relationship(ctx.db, "docs", "by_owner", owner);
  pending = Promise.resolve(null);
  return await pending;
}
"#,
            ),
            (
                "escaping alias reference",
                "await loadEscaped(ctx, args.owner)",
                "result",
                r#"
async function loadEscaped(ctx, owner) {
  const pending = relationship(ctx.db, "docs", "by_owner", owner);
  void pending;
  return await pending;
}
"#,
            ),
            (
                "safe consumer does not hide unknown sibling",
                "relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "(await consumePending(result), consumeUnknown(result), null)",
                r#"
async function consumePending(pending) {
  return await pending;
}
function consumeUnknown(pending) {
  void pending;
}
"#,
            ),
            (
                "awaited caller does not hide dropped helper caller",
                "consumeReturned(ctx, args.owner)",
                "(dropReturned(ctx, args.owner), await result)",
                r#"
function loadReturned(ctx, owner) {
  return relationship(ctx.db, "docs", "by_owner", owner);
}
async function consumeReturned(ctx, owner) {
  return await loadReturned(ctx, owner);
}
function dropReturned(ctx, owner) {
  void loadReturned(ctx, owner);
}
"#,
            ),
            (
                "safe composed branch does not hide unknown composed branch",
                "relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "await consumeBranched(result, args.owner.length > 0)",
                r#"
async function consumeBranched(pending, first) {
  if (first) return await pending;
  consumeUnknown(pending);
  return null;
}
function consumeUnknown(pending) {
  void pending;
}
"#,
            ),
        ];

        for (name, call, returned, helpers) in fixtures {
            let output = compile_adapter_with_options(
                "getOneFrom",
                "databaseIndexUnique",
                call,
                returned,
                helpers,
                "none",
            );
            assert!(!output.eligible, "{name}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-dependency-adapter-suspension"
                }),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn iterable_proof_accepts_owned_direct_shapes_and_rejects_unproved_values() {
        let source = r#"
export const selected = query({
  args: { ids: v.array(v.id("docs")) },
  handler: async (ctx, args) => {
    const accumulated = new Set();
    accumulated.add(args.ids[0]);
    const derivedIds = args.ids.map((id) => id);
    consume(args.ids);
    consume(new Set(args.ids));
    consume([]);
    consume(accumulated);
    consume(derivedIds);
    consume(Promise.resolve(args.ids));
    consume(custom.items);
  },
});
"#;
        let summary = summary(source);
        let registration = summary
            .units
            .get("selected")
            .and_then(|unit| unit.registration.as_ref())
            .unwrap()
            .clone();
        let module = LoadedModule::new(summary, source.to_string());
        let graph = graph();
        let call_start = source.find("consume(accumulated)").unwrap() as u32;
        for needle in ["args.ids", "new Set(args.ids)", "[]", "accumulated"] {
            assert!(
                dependency_adapter_iterable_is_owned(
                    &graph,
                    MODULE_KEY,
                    &module,
                    &registration,
                    registration.handler_start,
                    registration.handler_end,
                    &consume_range(source, needle),
                    call_start,
                    &mut Default::default(),
                    &mut Default::default(),
                ),
                "{needle}"
            );
        }
        for needle in ["derivedIds", "Promise.resolve(args.ids)", "custom.items"] {
            assert!(
                !dependency_adapter_iterable_is_owned(
                    &graph,
                    MODULE_KEY,
                    &module,
                    &registration,
                    registration.handler_start,
                    registration.handler_end,
                    &consume_range(source, needle),
                    call_start,
                    &mut Default::default(),
                    &mut Default::default(),
                ),
                "{needle}"
            );
        }
    }

    #[test]
    fn material_drift_reports_missing_and_changed_module_package_semantic_and_lock_facts() {
        let root = temporary_directory("convex-wasm-dependency-adapter-drift");
        let mut descriptor = descriptor();
        descriptor.material.semantic_sources = vec![DependencyAdapterSemanticSource {
            path: "node_modules/fixture/semantic.js".to_string(),
            source_sha256: "5".repeat(64),
            units: vec![DependencyAdapterSemanticUnit {
                unit_name: "semanticHelper".to_string(),
                unit_source_sha256: "6".repeat(64),
            }],
        }];
        let package_path = root.0.join(&descriptor.material.package_json.path);
        fs::create_dir_all(package_path.parent().unwrap()).unwrap();
        fs::write(&package_path, "{\"version\":\"1.0.0\"}\n").unwrap();
        let mut graph = graph();
        graph.repo_root = root.0.clone();
        graph.dependency_adapter.current.files = vec![
            DependencyAdapterCurrentFile {
                path: descriptor.export_identity.module_path.clone(),
                sha256: descriptor.material.module_source_sha256.clone(),
                bytes: 1,
            },
            DependencyAdapterCurrentFile {
                path: descriptor.material.package_json.path.clone(),
                sha256: descriptor.material.package_json.sha256.clone(),
                bytes: 1,
            },
            DependencyAdapterCurrentFile {
                path: descriptor.material.semantic_sources[0].path.clone(),
                sha256: descriptor.material.semantic_sources[0]
                    .source_sha256
                    .clone(),
                bytes: 1,
            },
        ];
        graph.dependency_adapter.current.locks = vec![
            descriptor.material.package_lock.clone(),
            descriptor.material.installed_lock.clone(),
        ];
        assert_eq!(dependency_adapter_material_drift(&graph, &descriptor), None);

        let module = graph.dependency_adapter.current.files.remove(0);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("no authenticated current file material")
        );
        graph.dependency_adapter.current.files.insert(0, module);
        graph.dependency_adapter.current.files[0].sha256 = "7".repeat(64);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("resolved module source digest")
        );
        graph.dependency_adapter.current.files[0].sha256 =
            descriptor.material.module_source_sha256.clone();

        let package = graph.dependency_adapter.current.files.remove(1);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("package manifest")
        );
        graph.dependency_adapter.current.files.insert(1, package);
        graph.dependency_adapter.current.files[1].sha256 = "8".repeat(64);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("package manifest")
        );
        graph.dependency_adapter.current.files[1].sha256 =
            descriptor.material.package_json.sha256.clone();

        let semantic = graph.dependency_adapter.current.files.remove(2);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("semantic source")
        );
        graph.dependency_adapter.current.files.push(semantic);
        graph.dependency_adapter.current.files[2].sha256 = "9".repeat(64);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("semantic source")
        );
        graph.dependency_adapter.current.files[2].sha256 = descriptor.material.semantic_sources[0]
            .source_sha256
            .clone();

        fs::write(&package_path, "{\"version\":\"2.0.0\"}\n").unwrap();
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("version")
        );
        fs::write(&package_path, "{\"version\":\"1.0.0\"}\n").unwrap();

        let package_lock = graph.dependency_adapter.current.locks.remove(0);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("package-lock.json")
        );
        graph
            .dependency_adapter
            .current
            .locks
            .insert(0, package_lock);
        graph.dependency_adapter.current.locks[0].entry_sha256 = "a".repeat(64);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("package-lock.json")
        );
        graph.dependency_adapter.current.locks[0].entry_sha256 =
            descriptor.material.package_lock.entry_sha256.clone();

        let installed_lock = graph.dependency_adapter.current.locks.remove(1);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("node_modules/.package-lock.json")
        );
        graph.dependency_adapter.current.locks.push(installed_lock);
        graph.dependency_adapter.current.locks[1].entry_sha256 = "b".repeat(64);
        assert!(
            dependency_adapter_material_drift(&graph, &descriptor)
                .unwrap()
                .contains("node_modules/.package-lock.json")
        );
    }

    #[test]
    fn export_and_semantic_source_units_fail_closed_on_missing_or_drifted_material() {
        let cases = [
            (
                "exportUnitDrift",
                "dependency-adapter-export-source-mismatch",
            ),
            (
                "semanticMissing",
                "dependency-adapter-semantic-source-missing",
            ),
            (
                "semanticSourceDrift",
                "dependency-adapter-semantic-source-mismatch",
            ),
            (
                "semanticUnitMissing",
                "dependency-adapter-semantic-unit-missing",
            ),
            (
                "semanticUnitDrift",
                "dependency-adapter-semantic-unit-mismatch",
            ),
        ];
        for (change, expected_code) in cases {
            let output = compile_adapter_with_options(
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "result",
                "",
                change,
            );
            assert!(!output.eligible, "{change}");
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "{change}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn all_database_semantic_kinds_compile_through_generic_alias_adapters() {
        let fixtures = [
            (
                "getAll",
                "databaseGetBatch",
                "await relationship(ctx.db, \"docs\", args.ids)",
                "databaseGet",
                None,
            ),
            (
                "getAllOrThrow",
                "databaseGetBatchOrThrow",
                "await relationship(ctx.db, \"docs\", new Set(args.ids))",
                "databaseGet",
                None,
            ),
            (
                "getManyFrom",
                "databaseIndexCollect",
                "await relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "databaseIndexQuery",
                Some("collect"),
            ),
            (
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, \"docs\", \"by_owner\", args.owner, \"\")",
                "databaseIndexQuery",
                Some("unique"),
            ),
            (
                "getOneFromOrThrow",
                "databaseIndexUniqueOrThrow",
                "await relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "databaseIndexQuery",
                Some("unique"),
            ),
        ];
        for (export_name, semantic_kind, call, operation_kind, terminal) in fixtures {
            let output = compile_adapter(export_name, semantic_kind, call);
            assert!(
                output.eligible,
                "{export_name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert_eq!(output.applied_dependency_adapters.len(), 1, "{export_name}");
            let provenance = &output.applied_dependency_adapters[0];
            assert_eq!(provenance.semantic_kind, semantic_kind);
            assert_eq!(provenance.resolved_export.export_name, export_name);
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("{export_name} did not emit compile output");
            };
            assert_eq!(compiled.operations.len(), 1, "{export_name}");
            assert_eq!(compiled.operations[0].kind, operation_kind, "{export_name}");
            assert_eq!(compiled.operations[0].table.as_deref(), Some("docs"));
            assert_eq!(compiled.operations[0].terminal.as_deref(), terminal);
            if operation_kind == "databaseIndexQuery" {
                assert_eq!(compiled.operations[0].index.as_deref(), Some("by_owner"));
                assert_eq!(compiled.operations[0].index_constraints.len(), 1);
                assert_eq!(compiled.operations[0].index_constraints[0].field, "owner");
                assert_eq!(compiled.operations[0].index_constraints[0].operator, "eq");
                assert_eq!(compiled.operations[0].order.as_deref(), Some("ascending"));
            }
            let generated = compiled
                .generated_javascript_artifact
                .as_ref()
                .and_then(|artifact| artifact.source.as_deref())
                .unwrap();
            assert!(
                generated.contains(&format!("__convexDependencyAdapter_{semantic_kind}")),
                "{export_name}"
            );
            assert!(!generated.contains("relationship("), "{export_name}");
        }
    }

    #[test]
    fn function_handle_adapter_compiles_direct_calls_in_both_execution_modes() {
        for effect_execution_mode in [
            super::EffectExecutionMode::BlockingFiber,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        ] {
            let output = compile_adapter_with_execution_mode(
                "createFunctionHandle",
                "functionHandleCreate",
                "await relationship(args.owner)",
                "result",
                "",
                "none",
                effect_execution_mode,
            );
            assert!(
                output.eligible,
                "{effect_execution_mode:?}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert_eq!(output.applied_dependency_adapters.len(), 1);
            assert_eq!(
                output.applied_dependency_adapters[0].semantic_kind,
                "functionHandleCreate"
            );
            let substitution = output.applied_dependency_adapters[0]
                .substitution
                .as_ref()
                .expect("function-handle provenance must retain substitution authority");
            assert_eq!(substitution.module_specifier, "convex/server");
            assert_eq!(substitution.export_name, "createFunctionHandle");
            assert_eq!(substitution.unit_source_sha256, "5".repeat(64));
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("function-handle adapter did not emit compile output");
            };
            assert_eq!(compiled.effect_execution_mode, effect_execution_mode);
            assert_eq!(compiled.operations.len(), 1);
            assert_eq!(compiled.operations[0].kind, "functionHandleCreate");
            assert_eq!(compiled.operations[0].table, None);
            let generated = compiled
                .generated_javascript_artifact
                .and_then(|artifact| artifact.source)
                .expect("function-handle adapter generated inline JavaScript");
            assert!(generated.contains(
                "function __convexDependencyAdapter_functionHandleCreate(functionReference)"
            ));
            assert!(generated.contains("return __convexCreateFunctionHandle(functionReference)"));
            assert!(!generated.contains("relationship("));
            assert!(!generated.contains("dependency adapter call was not lowered"));
            assert!(!generated.contains("Convex.asyncSyscall"));
            assert!(!generated.contains("performAsyncSyscall"));
        }

        let returned = compile_adapter_with_options(
            "createFunctionHandle",
            "functionHandleCreate",
            "await load(args.owner)",
            "result",
            "function load(reference) { return relationship(reference); }",
            "none",
        );
        assert!(
            returned.eligible,
            "{:#?}",
            returned
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn function_handle_adapter_rejects_inexact_call_and_binding_shapes() {
        for (name, call, expected_code) in [
            (
                "zeroArity",
                "await relationship()",
                "unsupported-dependency-adapter-call-shape",
            ),
            (
                "twoArguments",
                "await relationship(args.owner, args.owner)",
                "unsupported-dependency-adapter-call-shape",
            ),
            (
                "optional",
                "await relationship?.(args.owner)",
                "unsupported-dependency-adapter-suspension",
            ),
            (
                "computedEscape",
                "await ({ relationship })[\"relationship\"](args.owner)",
                "unsupported-dependency-adapter-binding",
            ),
            (
                "aliasEscape",
                "await ((create) => create(args.owner))(relationship)",
                "unsupported-dependency-adapter-binding",
            ),
            (
                "bindingEscape",
                "relationship",
                "unsupported-dependency-adapter-binding",
            ),
        ] {
            let output = compile_adapter("createFunctionHandle", "functionHandleCreate", call);
            assert!(!output.eligible, "{name}");
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn function_handle_adapter_uses_fixed_and_mapped_promise_all_proofs() {
        for (name, call, expected_children) in [
            (
                "mapped",
                "await Promise.all(args.ids.map((reference) => relationship(reference)))",
                None,
            ),
            (
                "fixed",
                r#"await Promise.all([
                  relationship(args.owner),
                  relationship(args.owner),
                ])"#,
                Some(2),
            ),
        ] {
            let output = compile_adapter("createFunctionHandle", "functionHandleCreate", call);
            assert!(
                output.eligible,
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert_eq!(output.proved_direct_async_batches.len(), 1, "{name}");
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("{name} function-handle batch did not emit compile output");
            };
            assert_eq!(compiled.direct_async_batches.len(), 1, "{name}");
            match (&compiled.direct_async_batches[0].shape, expected_children) {
                (
                    super::DirectAsyncBatchAuthorizationShape::SingleEffectMap {
                        operation_kind,
                        result_kind,
                        ..
                    },
                    None,
                ) => {
                    assert_eq!(operation_kind, "functionHandleCreate");
                    assert_eq!(result_kind, "hostValue");
                }
                (
                    super::DirectAsyncBatchAuthorizationShape::FixedEffectArray { children },
                    Some(expected_children),
                ) => {
                    assert_eq!(children.len(), expected_children);
                    assert!(children.iter().all(|child| {
                        child.operation_kind == "functionHandleCreate"
                            && child.result_kind == "hostValue"
                    }));
                }
                _ => panic!("{name} function-handle batch changed authorization kind"),
            }
        }
    }

    #[test]
    fn recursive_capability_forwarding_scc_rejects_effect_value_closure() {
        let helpers = r#"
async function recursiveLoad(ctx, owner, depth) {
  if (depth === 0) {
    return await relationship(ctx.db, "docs", "by_owner", owner);
  }
  return await recursiveForward(ctx, owner, depth - 1);
}
async function recursiveForward(ctx, owner, depth) {
  return await recursiveLoad(ctx, owner, depth);
}
"#;
        let output = compile_adapter_with_options(
            "getManyFrom",
            "databaseIndexCollect",
            "await recursiveLoad(ctx, args.owner, 1)",
            "result",
            helpers,
            "none",
        );

        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-dependency-adapter-suspension"
                && diagnostic.message.contains("exact callable value flow")
        }));
    }

    #[test]
    fn recursive_capability_forwarding_scc_rejects_reconstructed_capability() {
        let helpers = r#"
async function recursiveLoad(ctx, owner, depth) {
  if (depth === 0) {
    return await relationship(ctx.db, "docs", "by_owner", owner);
  }
  return await recursiveForward(ctx, owner, depth - 1);
}
async function recursiveForward(ctx, owner, depth) {
  return await recursiveLoad({ db: ctx.db }, owner, depth);
}
"#;
        let output = compile_adapter_with_options(
            "getManyFrom",
            "databaseIndexCollect",
            "await recursiveLoad(ctx, args.owner, 1)",
            "result",
            helpers,
            "none",
        );

        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "unsupported-dependency-adapter-capability" | "mixed-capability-callsite"
            )
        }));
    }

    #[test]
    fn recursive_capability_forwarding_scc_rejects_awaited_capability() {
        let helpers = r#"
async function recursiveLoad(ctx, owner, depth) {
  if (depth === 0) {
    return await relationship(ctx.db, "docs", "by_owner", owner);
  }
  return await recursiveForward(ctx, owner, depth - 1);
}
async function recursiveForward(ctx, owner, depth) {
  return await recursiveLoad(await ctx, owner, depth);
}
"#;
        let output = compile_adapter_with_options(
            "getManyFrom",
            "databaseIndexCollect",
            "await recursiveLoad(ctx, args.owner, 1)",
            "result",
            helpers,
            "none",
        );

        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "unsupported-dependency-adapter-capability" | "mixed-capability-callsite"
            )
        }));
    }

    #[test]
    fn projected_capability_parameters_authorize_dependency_adapter() {
        let fixtures = [
            (
                "destructured",
                r#"
async function projectedLoad(input, owner) {
  const { ctx } = input;
  return await relationship(ctx.db, "docs", "by_owner", owner);
}
"#,
            ),
            (
                "direct-member",
                r#"
async function projectedLoad(input, owner) {
  return await relationship(input.ctx.db, "docs", "by_owner", owner);
}
"#,
            ),
        ];
        for (name, helpers) in fixtures {
            let output = compile_adapter_with_options(
                "getManyFrom",
                "databaseIndexCollect",
                "await projectedLoad({ ctx }, args.owner)",
                "result",
                helpers,
                "none",
            );

            assert!(
                output.eligible,
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert_eq!(output.applied_dependency_adapters.len(), 1, "{name}");
        }
    }

    #[test]
    fn projected_capability_parameters_reject_reconstructed_awaited_and_mixed_values() {
        let helpers = r#"
async function projectedLoad(input, owner) {
  const { ctx } = input;
  return await relationship(ctx.db, "docs", "by_owner", owner);
}
"#;
        let fixtures = [
            (
                "reconstructed",
                "await projectedLoad({ ctx: { db: ctx.db } }, args.owner)",
            ),
            (
                "awaited",
                "await projectedLoad({ ctx: await ctx }, args.owner)",
            ),
            (
                "mixed",
                "await projectedLoad({ ctx }, args.owner); await projectedLoad({ ctx: { db: ctx.db } }, args.owner)",
            ),
        ];
        for (name, call) in fixtures {
            let output = compile_adapter_with_options(
                "getManyFrom",
                "databaseIndexCollect",
                call,
                "result",
                helpers,
                "none",
            );

            assert!(!output.eligible, "{name}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    matches!(
                        diagnostic.code.as_str(),
                        "unsupported-dependency-adapter-capability" | "mixed-capability-callsite"
                    )
                }),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn projected_capability_parameters_authorize_transitive_object_forwarding() {
        let helpers = r#"
async function projectedLoad(input, owner) {
  return await relationship(input.ctx.db, "docs", "by_owner", owner);
}
async function forwardProjected(input, owner) {
  return await projectedLoad(input, owner);
}
"#;
        let output = compile_adapter_with_options(
            "getManyFrom",
            "databaseIndexCollect",
            "await forwardProjected({ ctx }, args.owner)",
            "result",
            helpers,
            "none",
        );

        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        assert_eq!(output.applied_dependency_adapters.len(), 1);
    }

    #[test]
    fn projected_capability_parameters_reject_unrooted_reconstructed_and_mixed_forwarding() {
        let helpers = r#"
async function projectedLoad(input, owner) {
  return await relationship(input.ctx.db, "docs", "by_owner", owner);
}
async function forwardProjected(input, owner) {
  return await projectedLoad(input, owner);
}
"#;
        let fixtures = [
            ("unrooted", "await forwardProjected(args, args.owner)"),
            (
                "reconstructed",
                "await forwardProjected({ ctx: { db: ctx.db } }, args.owner)",
            ),
            (
                "mixed",
                "await forwardProjected({ ctx }, args.owner); await forwardProjected(args, args.owner)",
            ),
        ];
        for (name, call) in fixtures {
            let output = compile_adapter_with_options(
                "getManyFrom",
                "databaseIndexCollect",
                call,
                "result",
                helpers,
                "none",
            );

            assert!(!output.eligible, "{name}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    matches!(
                        diagnostic.code.as_str(),
                        "unsupported-dependency-adapter-capability" | "mixed-capability-callsite"
                    )
                }),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn adapter_document_and_collection_results_preserve_property_provenance() {
        let unique = compile_adapter_with_return(
            "getOneFrom",
            "databaseIndexUnique",
            "await relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
            "result === null ? null : result.owner",
        );
        let collect = compile_adapter_with_return(
            "getManyFrom",
            "databaseIndexCollect",
            "await relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
            "result.map((document) => document.owner)",
        );
        for (name, output) in [("unique", unique), ("collect", collect)] {
            assert!(
                output.eligible,
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("{name} did not emit compile output");
            };
            assert!(
                compiled
                    .document_properties
                    .iter()
                    .any(|property| { property.table == "docs" && property.property == "owner" }),
                "{name}: {:#?}",
                compiled
                    .document_properties
                    .iter()
                    .map(|property| (&property.table, &property.property))
                    .collect::<Vec<_>>()
            );
        }

        let get_batch = compile_adapter_with_return(
            "getAll",
            "databaseGetBatch",
            "await relationship(ctx.db, \"docs\", args.ids)",
            "result.length",
        );
        assert!(get_batch.eligible);
        let CompilerModeOutput::Compile(compiled) = get_batch.mode_output else {
            panic!("database get batch did not emit compile output");
        };
        assert!(
            !compiled
                .document_properties
                .iter()
                .any(|property| { property.table == "docs" && property.property == "length" })
        );
    }

    #[test]
    fn adapter_calls_fail_closed_for_unproved_shapes_bindings_capabilities_and_iterables() {
        let cases = [
            (
                "arity",
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, \"docs\")",
                "unsupported-dependency-adapter-call-shape",
            ),
            (
                "dynamicTable",
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, args.owner, \"by_owner\", args.owner)",
                "unsupported-dependency-adapter-call-shape",
            ),
            (
                "dynamicIndex",
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, \"docs\", args.owner, args.owner)",
                "unsupported-dependency-adapter-call-shape",
            ),
            (
                "emptyTable",
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, \"\", \"by_owner\", args.owner)",
                "unsupported-dependency-adapter-call-shape",
            ),
            (
                "emptyIndex",
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, \"docs\", \"\", args.owner)",
                "unsupported-dependency-adapter-call-shape",
            ),
            (
                "dynamicField",
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, \"docs\", \"by_owner\", args.owner, args.owner)",
                "unsupported-dependency-adapter-call-shape",
            ),
            (
                "optional",
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship?.(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "unsupported-dependency-adapter-suspension",
            ),
            (
                "computedEscape",
                "getOneFrom",
                "databaseIndexUnique",
                "await ({ relationship })[\"relationship\"](ctx.db, \"docs\", \"by_owner\", args.owner)",
                "unsupported-dependency-adapter-binding",
            ),
            (
                "aliasEscape",
                "getOneFrom",
                "databaseIndexUnique",
                "await ((adapted) => adapted(ctx.db, \"docs\", \"by_owner\", args.owner))(relationship)",
                "unsupported-dependency-adapter-binding",
            ),
            (
                "write",
                "getOneFrom",
                "databaseIndexUnique",
                "(() => { relationship = other; return null; })()",
                "module-state-write",
            ),
            (
                "capability",
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(other.db, \"docs\", \"by_owner\", args.owner)",
                "unsupported-dependency-adapter-capability",
            ),
            (
                "derivedArray",
                "getAll",
                "databaseGetBatch",
                "await relationship(ctx.db, \"docs\", args.ids.map((id) => id))",
                "unsupported-dependency-adapter-iterable",
            ),
            (
                "promisedArray",
                "getAll",
                "databaseGetBatch",
                "await relationship(ctx.db, \"docs\", Promise.resolve(args.ids))",
                "unsupported-dependency-adapter-iterable",
            ),
            (
                "unrelatedSet",
                "getAll",
                "databaseGetBatch",
                "(new Set(), await relationship(ctx.db, \"docs\", args.ids))",
                "unsupported-construct",
            ),
        ];
        for (name, export_name, semantic_kind, call, expected_code) in cases {
            let output = compile_adapter(export_name, semantic_kind, call);
            assert!(!output.eligible, "{name}");
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn index_adapter_inside_direct_promise_all_uses_the_existing_batch_proof() {
        let output = compile_adapter(
            "getOneFrom",
            "databaseIndexUnique",
            "await Promise.all(args.ids.map((owner) => relationship(ctx.db, \"docs\", \"by_owner\", owner)))",
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        assert_eq!(output.proved_direct_async_batches.len(), 1);
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("direct adapter batch did not emit compile output");
        };
        assert_eq!(compiled.direct_async_batches.len(), 1);
        let super::DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            operation_kind,
            result_kind,
            ..
        } = &compiled.direct_async_batches[0].shape
        else {
            panic!("direct adapter batch changed authorization kind");
        };
        assert_eq!(operation_kind, "databaseIndexQuery");
        assert_eq!(result_kind, "hostValue");
    }

    #[test]
    fn index_adapters_inside_fixed_promise_all_use_the_existing_batch_proof() {
        let output = compile_adapter(
            "getOneFrom",
            "databaseIndexUnique",
            r#"await Promise.all([
              relationship(ctx.db, "docs", "by_owner", args.ids[0]),
              relationship(ctx.db, "docs", "by_owner", args.ids[1]),
            ])"#,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        assert_eq!(output.proved_direct_async_batches.len(), 1);
        let super::ProvedDirectAsyncBatchShape::FixedEffectArray { children: proved } =
            &output.proved_direct_async_batches[0].shape
        else {
            panic!("direct adapter batch changed proof kind");
        };
        assert_eq!(proved.len(), 2);
        assert!(proved.iter().all(|child| child.result_kind == "hostValue"));

        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("direct adapter batch did not emit compile output");
        };
        assert_eq!(compiled.direct_async_batches.len(), 1);
        let super::DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } =
            &compiled.direct_async_batches[0].shape
        else {
            panic!("direct adapter batch changed authorization kind");
        };
        assert_eq!(children.len(), 2);
        assert!(children.iter().all(|child| {
            child.operation_kind == "databaseIndexQuery" && child.result_kind == "hostValue"
        }));
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("direct adapter batch generated inline JavaScript");
        assert!(generated.contains("__convexAsyncFixedBatch("));
        assert!(!generated.contains("Promise.all("));
    }

    #[test]
    fn fixed_promise_all_unique_or_throw_helper_composes_its_authenticated_continuation() {
        let helper = r#"
async function load(ctx, owner) {
  const document = await relationship(ctx.db, "docs", "by_owner", owner);
  if (document.owner !== owner) throw new Error("wrong owner");
  return { id: document._id };
}
"#;
        let output = compile_adapter_with_options(
            "getOneFromOrThrow",
            "databaseIndexUniqueOrThrow",
            r#"await Promise.all([
              load(ctx, args.owner),
              ctx.db.get("docs", args.ids[0]),
            ])"#,
            "result",
            helper,
            "none",
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let super::ProvedDirectAsyncBatchShape::FixedEffectArray {
            children: proved_children,
        } = &output.proved_direct_async_batches[0].shape
        else {
            panic!("unique-or-throw helper continuation changed proof kind");
        };
        assert!(proved_children[0].helper_continuation_prebound);
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("unique-or-throw helper continuation did not emit compile output");
        };
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("unique-or-throw helper continuation generated inline JavaScript");
        let rejection = generated
            .find(
                "=== null) throw new Error(\"Can't find a document in \" + \"docs\" + \" with field \" + \"owner\" + \" equal to \" + String(__convexBatchOperationArguments_",
            )
            .expect("generated continuation lost the authenticated null rejection");
        let source_continuation = generated[rejection..]
            .find("if (document.owner !== owner) throw new Error(\"wrong owner\")")
            .expect("generated helper lost its source continuation");
        assert!(source_continuation > 0);
        assert!(generated.contains("__convexAsyncFixedBatch("));
        assert!(!generated.contains("Promise.all("));
        assert!(!generated.contains("await "));
    }

    #[test]
    fn fixed_promise_all_adapter_helper_with_static_argument_falls_back_without_panicking() {
        let helper = r#"
async function load(ctx) {
  const document = await relationship(ctx.db, "docs", "by_owner", "fixed-owner");
  return document;
}
"#;
        let output = compile_adapter_with_options(
            "getOneFrom",
            "databaseIndexUnique",
            r#"await Promise.all([
              load(ctx),
              ctx.db.get("docs", args.ids[0]),
            ])"#,
            "result",
            helper,
            "none",
        );

        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-direct-promise-all"
                && diagnostic
                    .message
                    .contains("must directly perform one database or scheduler effect")
        }));
        assert!(output.proved_direct_async_batches.is_empty());
    }

    #[test]
    fn fixed_promise_all_adapter_children_require_one_raw_operation_semantics() {
        for (export_name, semantic_kind, call) in [
            (
                "getOneFromOrThrow",
                "databaseIndexUniqueOrThrow",
                r#"await Promise.all([
                  relationship(ctx.db, "docs", "by_owner", args.ids[0]),
                  relationship(ctx.db, "docs", "by_owner", args.ids[1]),
                ])"#,
            ),
            (
                "getAll",
                "databaseGetBatch",
                r#"await Promise.all([
                  relationship(ctx.db, "docs", args.ids),
                  relationship(ctx.db, "docs", args.ids),
                ])"#,
            ),
            (
                "getAllOrThrow",
                "databaseGetBatchOrThrow",
                r#"await Promise.all([
                  relationship(ctx.db, "docs", args.ids),
                  relationship(ctx.db, "docs", args.ids),
                ])"#,
            ),
        ] {
            let output = compile_adapter(export_name, semantic_kind, call);
            assert!(!output.eligible, "{semantic_kind}");
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| { diagnostic.code == "unsupported-direct-promise-all" }),
                "{semantic_kind}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert!(output.proved_direct_async_batches.is_empty());
        }
    }

    #[test]
    fn mapped_unique_or_throw_adapter_preserves_its_postprocessing_boundary() {
        let output = compile_adapter(
            "getOneFromOrThrow",
            "databaseIndexUniqueOrThrow",
            "await Promise.all(args.ids.map((owner) => relationship(ctx.db, \"docs\", \"by_owner\", owner)))",
        );
        assert!(!output.eligible);
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "unsupported-direct-promise-all" })
        );
        assert!(output.proved_direct_async_batches.is_empty());
    }

    #[test]
    fn index_adapter_inside_multiple_await_batch_remains_a_v8_boundary() {
        let output = compile_adapter(
            "getOneFrom",
            "databaseIndexUnique",
            r#"await Promise.all(args.ids.map(async (owner) => {
              await 1;
              return await relationship(ctx.db, "docs", "by_owner", owner);
            }))"#,
        );
        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-direct-promise-all"
                && diagnostic
                    .message
                    .contains("independently resumable multiple awaits")
        }));
    }

    #[test]
    fn cached_authentication_failure_keeps_each_import_span_and_dependency_chain() {
        const ADAPTER_MODULE: &str = "node_modules/fixture/adapter.js";
        const CALLER_A: &str = "convex/callerA.ts";
        const CALLER_B: &str = "convex/callerB.ts";
        let caller_a_source = r#"import { adapted as relationship } from "fixture-adapter";
export function callerA(ctx, args) {
  return relationship(ctx.db, "docs", "by_owner", args.owner);
}
"#;
        let caller_b_source = r#"// Keep this import on a distinct call-local source line.
import { adapted as relationship } from "fixture-adapter";
export function callerB(ctx, args) {
  return relationship(ctx.db, "docs", "by_owner", args.owner);
}
"#;
        let caller_a_summary = summary_for(CALLER_A, caller_a_source);
        let caller_b_summary = summary_for(CALLER_B, caller_b_source);
        let caller_a_unit = caller_a_summary.units.get("callerA").unwrap().clone();
        let caller_b_unit = caller_b_summary.units.get("callerB").unwrap().clone();
        let caller_a_binding = caller_a_summary
            .imports
            .get("relationship")
            .unwrap()
            .clone();
        let caller_b_binding = caller_b_summary
            .imports
            .get("relationship")
            .unwrap()
            .clone();
        let caller_a_reference = caller_a_summary
            .references
            .iter()
            .find(|reference| {
                reference.name == "relationship"
                    && reference.start >= caller_a_unit.start
                    && reference.end <= caller_a_unit.end
            })
            .unwrap()
            .clone();
        let caller_b_reference = caller_b_summary
            .references
            .iter()
            .find(|reference| {
                reference.name == "relationship"
                    && reference.start >= caller_b_unit.start
                    && reference.end <= caller_b_unit.end
            })
            .unwrap()
            .clone();
        let registration_source = r#"export const selected = query({
  args: { owner: v.string() },
  handler: async (ctx, args) => args.owner,
});
"#;
        let registration_summary = summary(registration_source);
        let registration = registration_summary
            .units
            .get("selected")
            .and_then(|unit| unit.registration.clone())
            .unwrap();
        let mut graph = graph();
        graph
            .dependency_adapter
            .descriptor
            .adapters
            .push(descriptor());
        let modules = BTreeMap::from([
            (
                CALLER_A.to_string(),
                LoadedModule::new(caller_a_summary, caller_a_source.to_string()),
            ),
            (
                CALLER_B.to_string(),
                LoadedModule::new(caller_b_summary, caller_b_source.to_string()),
            ),
            (
                ADAPTER_MODULE.to_string(),
                LoadedModule::new(
                    summary_for(ADAPTER_MODULE, "export function other() {}\n"),
                    "export function other() {}\n".to_string(),
                ),
            ),
        ]);
        let expected_a = modules
            .get(CALLER_A)
            .unwrap()
            .line_column(caller_a_binding.start);
        let expected_b = modules
            .get(CALLER_B)
            .unwrap()
            .line_column(caller_b_binding.start);
        let mut authentication_cache = BTreeMap::new();
        let mut applied = Vec::new();
        let mut diagnostics = Vec::new();
        for (module, unit, binding, reference) in [
            (
                CALLER_A,
                &caller_a_unit,
                &caller_a_binding,
                &caller_a_reference,
            ),
            (
                CALLER_B,
                &caller_b_unit,
                &caller_b_binding,
                &caller_b_reference,
            ),
        ] {
            assert!(
                adapt_dependency_call(
                    &graph,
                    &modules,
                    module,
                    &format!("{module}#{}", unit.name),
                    unit.start,
                    unit.end,
                    binding,
                    ADAPTER_MODULE,
                    reference,
                    &registration,
                    &[format!("{module}#{}", unit.name)],
                    &mut authentication_cache,
                    &mut applied,
                    &mut diagnostics,
                )
                .unwrap()
            );
        }
        assert_eq!(authentication_cache.len(), 1);
        assert!(applied.is_empty());
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].code, "dependency-adapter-export-missing");
        assert_eq!(diagnostics[1].code, "dependency-adapter-export-missing");
        assert_eq!(
            (
                &diagnostics[0].file,
                diagnostics[0].line,
                diagnostics[0].column
            ),
            (&CALLER_A.to_string(), expected_a.0, expected_a.1)
        );
        assert_eq!(
            (
                &diagnostics[1].file,
                diagnostics[1].line,
                diagnostics[1].column
            ),
            (&CALLER_B.to_string(), expected_b.0, expected_b.1)
        );
        assert_ne!(expected_a, expected_b);
        assert_eq!(
            diagnostics[0].dependency_chain,
            vec![
                "convex/callerA.ts#callerA".to_string(),
                "node_modules/fixture/adapter.js#adapted".to_string(),
            ]
        );
        assert_eq!(
            diagnostics[1].dependency_chain,
            vec![
                "convex/callerB.ts#callerB".to_string(),
                "node_modules/fixture/adapter.js#adapted".to_string(),
            ]
        );
    }

    #[test]
    fn applied_provenance_deduplicates_and_only_selected_identity_changes_fingerprints() {
        let two_calls = compile_adapter_with_options(
            "getOneFrom",
            "databaseIndexUnique",
            "await load(ctx, args.owner)",
            "result",
            r#"
async function load(ctx, owner) {
  await relationship(ctx.db, "docs", "by_owner", owner);
  return relationship(ctx.db, "docs", "by_owner", owner);
}
"#,
            "none",
        );
        assert!(two_calls.eligible);
        assert_eq!(two_calls.applied_dependency_adapters.len(), 1);
        let CompilerModeOutput::Compile(compiled) = two_calls.mode_output else {
            panic!("two-call adapter fixture did not emit compile output");
        };
        assert_eq!(compiled.operations.len(), 2);

        let compile_identity = |change| {
            compile_adapter_with_options(
                "getOneFrom",
                "databaseIndexUnique",
                "await relationship(ctx.db, \"docs\", \"by_owner\", args.owner)",
                "result",
                "",
                change,
            )
        };
        let baseline = compile_identity("none");
        let changed = compile_identity("selectedIdentityChange");
        let unused_a = compile_identity("unusedDescriptorA");
        let unused_b = compile_identity("unusedDescriptorB");
        for output in [&baseline, &changed, &unused_a, &unused_b] {
            assert!(output.eligible);
        }
        assert_ne!(baseline.export_fingerprint, changed.export_fingerprint);
        assert_ne!(
            baseline.source_graph_fingerprint,
            changed.source_graph_fingerprint
        );
        assert_eq!(baseline.export_fingerprint, unused_a.export_fingerprint);
        assert_eq!(baseline.export_fingerprint, unused_b.export_fingerprint);
        assert_eq!(
            baseline.source_graph_fingerprint,
            unused_a.source_graph_fingerprint
        );
        assert_eq!(
            baseline.source_graph_fingerprint,
            unused_b.source_graph_fingerprint
        );
    }

    #[allow(dead_code)]
    fn descriptor() -> DependencyAdapterDescriptorEntry {
        DependencyAdapterDescriptorEntry {
            id: "fixture".to_string(),
            export_identity: DependencyAdapterExportIdentity {
                module_path: "node_modules/fixture/adapter.js".to_string(),
                export_name: "adapted".to_string(),
                unit_source_sha256: "1".repeat(64),
            },
            substitution: None,
            material: DependencyAdapterExpectedMaterial {
                module_source_sha256: "2".repeat(64),
                semantic_sources: Vec::new(),
                package_json: DependencyAdapterPackageMaterial {
                    path: "node_modules/fixture/package.json".to_string(),
                    sha256: "3".repeat(64),
                    version: "1.0.0".to_string(),
                },
                package_lock: DependencyAdapterLockMaterial {
                    path: "package-lock.json".to_string(),
                    package_key: "node_modules/fixture".to_string(),
                    entry_sha256: "4".repeat(64),
                },
                installed_lock: DependencyAdapterLockMaterial {
                    path: "node_modules/.package-lock.json".to_string(),
                    package_key: "node_modules/fixture".to_string(),
                    entry_sha256: "4".repeat(64),
                },
            },
            semantic: DependencyAdapterSemantic {
                kind: "databaseIndexUnique".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod batch_protocol_tests {
    use super::{
        EsbuildMetafile, Toolchain, test_dependency_adapter_material,
        test_registration_adapter_material,
    };
    use crate::compiler_batch::{
        BATCH_REQUEST_KIND, BatchAuthoritativeExport, BatchCommonGraph, BatchCompileSelection,
        BatchExport, BatchGraphAssumptions, BatchProtocol, BatchRequest, batch_protocol,
    };
    use std::{collections::BTreeMap, path::PathBuf};

    fn request(kind: &str, mode: &str, compile_targets: Vec<BatchExport>) -> BatchRequest {
        BatchRequest {
            kind: kind.to_string(),
            mode: mode.to_string(),
            compile_selection: None,
            common_graph: BatchCommonGraph {
                kind: "convex-wasm-esbuild-graph".to_string(),
                repo_root: PathBuf::from("/fixture"),
                functions_root: "fixtures".to_string(),
                toolchain: Toolchain {
                    esbuild: "fixture".to_string(),
                    convex: "fixture".to_string(),
                },
                dependency_adapter: test_dependency_adapter_material(),
                registration_adapter: test_registration_adapter_material(),
                effect_execution_mode: super::EffectExecutionMode::BlockingFiber,
                assumptions: None,
                metafile: EsbuildMetafile {
                    inputs: BTreeMap::new(),
                    outputs: BTreeMap::new(),
                },
                phase_timings_us: BTreeMap::new(),
            },
            entry_candidates: Vec::new(),
            authoritative_exports: Vec::new(),
            compile_targets,
            exports: vec![BatchExport {
                entry_path: "convex/example.ts".to_string(),
                export_name: "example".to_string(),
            }],
        }
    }

    fn assumptions() -> BatchGraphAssumptions {
        BatchGraphAssumptions {
            platform: "browser".to_string(),
            format: "esm".to_string(),
            target: "esnext".to_string(),
            conditions: vec!["convex".to_string(), "module".to_string()],
            graph_construction_semantic_revision: "convex-wasm-deployment-graph-construction"
                .to_string(),
            inner_esbuild_source_sha256:
                "480dfaf1bf88cc55283001377430ad8c3685a3a34603c0926580490b0045d451".to_string(),
            plugins: vec![
                "convex-source-material-snapshot".to_string(),
                "convex-async-hooks-shim".to_string(),
                "convex-server-only".to_string(),
                "convex-node-externals(empty-browser-map)".to_string(),
                "convex-wasm".to_string(),
            ],
            production_artifact: false,
            resolution_authority: "esbuild-metafile".to_string(),
            splitting: true,
        }
    }

    #[test]
    fn explicit_target_selection_supports_compile_and_analysis() {
        let target = BatchExport {
            entry_path: "convex/example.ts".to_string(),
            export_name: "example".to_string(),
        };
        let mut compile = request(BATCH_REQUEST_KIND, "compile", vec![target]);
        compile.common_graph.assumptions = Some(assumptions());
        compile.compile_selection = Some(BatchCompileSelection {
            kind: "explicitTargets".to_string(),
        });
        assert_eq!(
            batch_protocol(&compile).unwrap(),
            BatchProtocol::ExplicitTargets
        );

        let analysis = request(BATCH_REQUEST_KIND, "analysis", Vec::new());
        assert_eq!(
            batch_protocol(&analysis).unwrap(),
            BatchProtocol::ExplicitTargets
        );

        let mut empty_compile = request(BATCH_REQUEST_KIND, "compile", Vec::new());
        empty_compile.common_graph.assumptions = Some(assumptions());
        empty_compile.compile_selection = Some(BatchCompileSelection {
            kind: "explicitTargets".to_string(),
        });
        assert!(
            batch_protocol(&empty_compile)
                .unwrap_err()
                .to_string()
                .contains("explicitTargets mode requires at least one compileTarget")
        );
    }

    #[test]
    fn all_eligible_selection_requires_no_explicit_targets() {
        let mut request = request(BATCH_REQUEST_KIND, "compile", Vec::new());
        request.entry_candidates = vec!["convex/example.ts".to_string()];
        request.authoritative_exports = vec![BatchAuthoritativeExport {
            entry_path: "convex/example.ts".to_string(),
            export_name: "example".to_string(),
            udf_kind: "query".to_string(),
        }];
        request.exports.clear();
        request.common_graph.assumptions = Some(assumptions());
        request.compile_selection = Some(BatchCompileSelection {
            kind: "allEligible".to_string(),
        });
        assert_eq!(
            batch_protocol(&request).unwrap(),
            BatchProtocol::AllEligible
        );

        request.compile_selection = None;
        assert!(
            batch_protocol(&request)
                .unwrap_err()
                .to_string()
                .contains("requires compileSelection")
        );

        request.compile_selection = Some(BatchCompileSelection {
            kind: "other".to_string(),
        });
        assert!(
            batch_protocol(&request)
                .unwrap_err()
                .to_string()
                .contains("unsupported compileSelection kind")
        );

        request.compile_selection = Some(BatchCompileSelection {
            kind: "allEligible".to_string(),
        });
        request.compile_targets.push(BatchExport {
            entry_path: "convex/example.ts".to_string(),
            export_name: "example".to_string(),
        });
        assert!(
            batch_protocol(&request)
                .unwrap_err()
                .to_string()
                .contains("allEligible mode requires no compileTargets")
        );
    }

    #[test]
    fn all_eligible_selection_requires_complete_authoritative_inventory_inputs() {
        let mut request = request(BATCH_REQUEST_KIND, "compile", Vec::new());
        request.compile_selection = Some(BatchCompileSelection {
            kind: "allEligible".to_string(),
        });
        request.entry_candidates = vec!["convex/example.ts".to_string()];
        request.authoritative_exports = vec![BatchAuthoritativeExport {
            entry_path: "convex/example.ts".to_string(),
            export_name: "example".to_string(),
            udf_kind: "query".to_string(),
        }];
        request.common_graph.assumptions = Some(assumptions());

        assert!(
            batch_protocol(&request)
                .unwrap_err()
                .to_string()
                .contains("allEligible mode requires no exports")
        );

        request.exports.clear();
        request.entry_candidates.clear();
        assert!(
            batch_protocol(&request)
                .unwrap_err()
                .to_string()
                .contains("allEligible mode requires entryCandidates")
        );

        request
            .entry_candidates
            .push("convex/example.ts".to_string());
        request.authoritative_exports.clear();
        assert!(
            batch_protocol(&request)
                .unwrap_err()
                .to_string()
                .contains("allEligible mode requires authoritativeExports")
        );

        request
            .authoritative_exports
            .push(BatchAuthoritativeExport {
                entry_path: "convex/example.ts".to_string(),
                export_name: "example".to_string(),
                udf_kind: "query".to_string(),
            });
        request.common_graph.assumptions = None;
        assert!(
            batch_protocol(&request)
                .unwrap_err()
                .to_string()
                .contains("compile mode requires commonGraph assumptions")
        );
    }

    #[test]
    fn explicit_authority_selection_requires_a_selected_subset_and_complete_authority() {
        let target = BatchExport {
            entry_path: "convex/example.ts".to_string(),
            export_name: "example".to_string(),
        };
        let mut request = request(BATCH_REQUEST_KIND, "compile", vec![target]);
        request.exports.clear();
        request.entry_candidates = vec!["convex/example.ts".to_string()];
        request.authoritative_exports = vec![BatchAuthoritativeExport {
            entry_path: "convex/example.ts".to_string(),
            export_name: "example".to_string(),
            udf_kind: "query".to_string(),
        }];
        request.common_graph.assumptions = Some(assumptions());
        request.compile_selection = Some(BatchCompileSelection {
            kind: "explicitAuthority".to_string(),
        });
        assert_eq!(
            batch_protocol(&request).unwrap(),
            BatchProtocol::ExplicitAuthority
        );

        request.compile_targets.clear();
        assert!(
            batch_protocol(&request)
                .unwrap_err()
                .to_string()
                .contains("requires at least one compileTarget")
        );
    }
}

#[cfg(test)]
mod module_summary_cache_tests {
    use super::{
        PhaseMeasurements, compiler_pipeline_sha256, hash_bytes, load_module,
        module_summary_cache_key, prune_module_summary_cache,
    };
    use serde_json::Value;
    use std::{
        collections::BTreeMap,
        env, fs,
        path::PathBuf,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    struct TemporaryDirectory(PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn cache_file(
        root: &TemporaryDirectory,
        name: &str,
        bytes: usize,
        modified: SystemTime,
    ) -> PathBuf {
        let directory = root.0.join("module-summaries").join("ab");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(name);
        fs::write(&path, vec![b'x'; bytes]).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        path
    }

    #[test]
    fn prunes_module_summaries_by_idle_age_then_oldest_first_to_the_size_limit() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-wasm-module-summary-gc-{unique}")),
        );
        let now = SystemTime::now();
        let expired = cache_file(
            &root,
            &format!("ab{}.json", "0".repeat(62)),
            3,
            now - Duration::from_secs(100),
        );
        let older = cache_file(
            &root,
            &format!("ab{}.json", "1".repeat(62)),
            5,
            now - Duration::from_secs(10),
        );
        let newer = cache_file(
            &root,
            &format!("ab{}.json", "2".repeat(62)),
            5,
            now - Duration::from_secs(5),
        );
        let stale_temp = cache_file(
            &root,
            &format!(".ab{}.123.tmp", "3".repeat(62)),
            4,
            now - Duration::from_secs(7_200),
        );
        let active_temp = cache_file(&root, &format!(".ab{}.456.tmp", "4".repeat(62)), 4, now);

        let result = prune_module_summary_cache(&root.0, 6, Duration::from_secs(50), now).unwrap();

        assert_eq!(result.initial_files, 3);
        assert_eq!(result.initial_bytes, 13);
        assert_eq!(result.removed_age_files, 1);
        assert_eq!(result.removed_age_bytes, 3);
        assert_eq!(result.removed_size_files, 1);
        assert_eq!(result.removed_size_bytes, 5);
        assert_eq!(result.removed_stale_temp_files, 1);
        assert_eq!(result.removed_stale_temp_bytes, 4);
        assert_eq!(result.active_temp_files, 1);
        assert_eq!(result.active_temp_bytes, 4);
        assert_eq!(result.remaining_files, 1);
        assert_eq!(result.remaining_bytes, 5);
        assert!(!expired.exists());
        assert!(!older.exists());
        assert!(newer.exists());
        assert!(!stale_temp.exists());
        assert!(active_temp.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symbolic_module_summary_cache_root_without_pruning_its_target() {
        use std::os::unix::fs::symlink;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-wasm-module-summary-root-symlink-{unique}")),
        );
        let cache_dir = root.0.join("cache");
        let target = root.0.join("target");
        fs::create_dir_all(&cache_dir).unwrap();
        let target_cache = TemporaryDirectory(target);
        let target_file = cache_file(
            &target_cache,
            &format!("ab{}.json", "0".repeat(62)),
            3,
            SystemTime::now() - Duration::from_secs(100),
        );
        symlink(
            target_cache.0.join("module-summaries"),
            cache_dir.join("module-summaries"),
        )
        .unwrap();

        let error =
            prune_module_summary_cache(&cache_dir, 1, Duration::from_secs(1), SystemTime::now())
                .unwrap_err();

        assert!(error.to_string().contains("not a directory"), "{error:#}");
        assert!(target_file.exists());
    }

    #[test]
    fn module_summary_identity_changes_with_compiler_and_policy_material() {
        let source_hash = "1".repeat(64);
        let current = module_summary_cache_key(
            "convex/example.ts",
            &source_hash,
            &"2".repeat(64),
            &"3".repeat(64),
        );
        let stale_compiler = module_summary_cache_key(
            "convex/example.ts",
            &source_hash,
            &"4".repeat(64),
            &"3".repeat(64),
        );
        let stale_policy = module_summary_cache_key(
            "convex/example.ts",
            &source_hash,
            &"2".repeat(64),
            &"5".repeat(64),
        );

        assert_ne!(current, stale_compiler);
        assert_ne!(current, stale_policy);
    }

    #[test]
    fn rejects_module_summary_relabeling_under_the_current_cache_key() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-wasm-module-summary-identity-{unique}")),
        );
        let module_key = "convex/example.ts";
        let module_path = root.0.join(module_key);
        fs::create_dir_all(module_path.parent().unwrap()).unwrap();
        let source = "export function helper(value) { return value; }\n";
        fs::write(&module_path, source).unwrap();
        let cache_dir = root.0.join("cache");
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &cache_dir,
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();

        let source_hash = hash_bytes(source.as_bytes());
        let cache_key = module_summary_cache_key(
            module_key,
            &source_hash,
            compiler_pipeline_sha256(),
            super::context_reuse::context_policy_fingerprint(),
        );
        let cache_path = cache_dir
            .join("module-summaries")
            .join(&cache_key[..2])
            .join(format!("{cache_key}.json"));
        let mut cached: Value = serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        cached["compilerPipelineSha256"] = Value::String("0".repeat(64));
        fs::write(&cache_path, serde_json::to_vec(&cached).unwrap()).unwrap();

        modules.clear();
        let error = load_module(
            &root.0,
            &cache_dir,
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("corrupt module cache identity"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_module_summary_cache_entries_before_reading_them() {
        use std::os::unix::fs::symlink;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-wasm-module-summary-symlink-{unique}")),
        );
        let module_key = "convex/example.ts";
        let module_path = root.0.join(module_key);
        fs::create_dir_all(module_path.parent().unwrap()).unwrap();
        let source = "export function helper(value) { return value; }\n";
        fs::write(&module_path, source).unwrap();
        let cache_dir = root.0.join("cache");
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &cache_dir,
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();

        let source_hash = hash_bytes(source.as_bytes());
        let cache_key = module_summary_cache_key(
            module_key,
            &source_hash,
            compiler_pipeline_sha256(),
            super::context_reuse::context_policy_fingerprint(),
        );
        let cache_path = cache_dir
            .join("module-summaries")
            .join(&cache_key[..2])
            .join(format!("{cache_key}.json"));
        fs::remove_file(&cache_path).unwrap();
        symlink("/etc/passwd", &cache_path).unwrap();
        modules.clear();

        let error = load_module(
            &root.0,
            &cache_dir,
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("not a regular file"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_private_module_summary_cache_entries_before_reading_them() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = TemporaryDirectory(
            env::temp_dir().join(format!("convex-wasm-module-summary-mode-{unique}")),
        );
        let module_key = "convex/example.ts";
        let module_path = root.0.join(module_key);
        fs::create_dir_all(module_path.parent().unwrap()).unwrap();
        let source = "export function helper(value) { return value; }\n";
        fs::write(&module_path, source).unwrap();
        let cache_dir = root.0.join("cache");
        let mut modules = BTreeMap::new();
        load_module(
            &root.0,
            &cache_dir,
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap();

        let source_hash = hash_bytes(source.as_bytes());
        let cache_key = module_summary_cache_key(
            module_key,
            &source_hash,
            compiler_pipeline_sha256(),
            super::context_reuse::context_policy_fingerprint(),
        );
        let cache_path = cache_dir
            .join("module-summaries")
            .join(&cache_key[..2])
            .join(format!("{cache_key}.json"));
        fs::set_permissions(&cache_path, fs::Permissions::from_mode(0o644)).unwrap();
        modules.clear();

        let error = load_module(
            &root.0,
            &cache_dir,
            module_key,
            &mut modules,
            &mut PhaseMeasurements::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not private"), "{error:#}");
    }
}

#[cfg(test)]
mod registration_adapter_tests {
    use super::{
        AppliedRegistrationAdapter, CompilerModeOutput, DirectAsyncBatchArgumentAuthorization,
        DirectAsyncBatchAuthorization, DirectAsyncBatchAuthorizationShape,
        DirectAsyncBatchFixedChildAuthorization, DirectBatchHelperContinuationAuthorization,
        DirectBatchHelperDependencyAdapterContinuation, EsbuildImport, EsbuildInput,
        EsbuildMetafile, GeneratedJavascriptAuthority, GeneratedSourceBindingCollision,
        GeneratedSourceMode, GraphInput, Intrinsic, LoadedModule, PhaseMeasurements,
        RegistrationAdapterAuthentication, RegistrationAdapterDescriptor,
        RegistrationAdapterDescriptorEntry, RegistrationAdapterExportIdentity,
        RegistrationAdapterMaterial, RegistrationAdapterResultParameter,
        RegistrationAdapterSourceMaterial, RegistrationAdapterSourceOperation,
        RegistrationAdapterSourceOperationSemantic, SourceRange, Toolchain, ValueMode,
        compile_export, hash_bytes, lower_generated_javascript,
        lower_generated_javascript_for_effect_execution_mode, registration_adapter_handler_source,
        summarize_module, transform_typescript, validate_registration_adapter_material,
    };
    use crate::context_reuse::build_source_inventory;
    use serde_json::Value;
    use std::{
        collections::{BTreeMap, BTreeSet},
        env, fs,
        path::{Path, PathBuf},
        process::Command,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    const ENTRY: &str = "fixtures/entry.ts";
    const WRAPPER: &str = "fixtures/wrapper.ts";
    const HELPER: &str = "fixtures/helper.ts";
    const SOURCE_HELPER: &str = "fixtures/sourceHelper.ts";
    const WRAPPER_SOURCE: &str = r#"
import { authenticate } from "./helper";
export function adapted(config) {
  return config;
}
"#;
    const HELPER_SOURCE: &str = r#"
export async function authenticate(context) {
  const identity = await context.auth.getUserIdentity();
  if (identity === null) throw new Error("Unauthorized");
  const normalizedId = context.db.normalizeId("accounts", identity.subject);
  if (normalizedId === null) throw new Error("Unauthorized");
  const account = await context.db.get("accounts", normalizedId);
  if (account === null) throw new Error("Unauthorized");
  return { principal: account.principal, privileged: account.role === "admin" };
}
"#;
    const SOURCE_HELPER_SOURCE: &str = r#"
export function requireWorkerSecret(providedKey: string | undefined): void {
  const configuredKey = process.env.WORKER_SECRET;
  if (!configuredKey) throw new Error("WORKER_SECRET is not set");
  if (!providedKey || providedKey !== configuredKey) throw new Error("Unauthorized");
}
"#;

    struct TemporaryDirectory(PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temporary_directory(name: &str) -> TemporaryDirectory {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("{name}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        TemporaryDirectory(path)
    }

    fn summary(module_key: &str, source: &str) -> super::ModuleSummary {
        summarize_module(
            module_key,
            Path::new(module_key),
            source,
            &hash_bytes(source.as_bytes()),
            "fixture-cache-key",
            "fixture-pipeline",
            "fixture-context-policy",
            &mut PhaseMeasurements::default(),
        )
        .unwrap()
    }

    fn exported_unit_hash(summary: &super::ModuleSummary, export_name: &str) -> String {
        let local = summary.exports.get(export_name).unwrap();
        hash_bytes(summary.units.get(local).unwrap().source.as_bytes())
    }

    fn adapter(
        registration_kind: &str,
        result_kind: &str,
        result_parameters: Vec<RegistrationAdapterResultParameter>,
    ) -> RegistrationAdapterDescriptorEntry {
        let wrapper = summary(WRAPPER, WRAPPER_SOURCE);
        let helper = summary(HELPER, HELPER_SOURCE);
        RegistrationAdapterDescriptorEntry {
            id: "adapted".to_string(),
            wrapper: RegistrationAdapterExportIdentity {
                module_path: WRAPPER.to_string(),
                export_name: "adapted".to_string(),
                source_sha256: exported_unit_hash(&wrapper, "adapted"),
            },
            registration_kind: registration_kind.to_string(),
            authentication: RegistrationAdapterAuthentication {
                helper: RegistrationAdapterExportIdentity {
                    module_path: HELPER.to_string(),
                    export_name: "authenticate".to_string(),
                    source_sha256: exported_unit_hash(&helper, "authenticate"),
                },
                result_kind: result_kind.to_string(),
                result_parameters,
            },
        }
    }

    fn material(adapter: RegistrationAdapterDescriptorEntry) -> RegistrationAdapterMaterial {
        RegistrationAdapterMaterial {
            kind: "convex-wasm-registration-adapter-material".to_string(),
            descriptor: RegistrationAdapterDescriptor {
                kind: "convex-wasm-registration-adapter-descriptor".to_string(),
                adapters: vec![adapter],
                source_operations: Vec::new(),
            },
            source: RegistrationAdapterSourceMaterial {
                path: "fixtures/registration-adapters.json".to_string(),
                sha256: "1".repeat(64),
                bytes: 1,
            },
        }
    }

    fn source_operation_material() -> RegistrationAdapterMaterial {
        let mut material = object_material("mutation");
        let helper = summary(SOURCE_HELPER, SOURCE_HELPER_SOURCE);
        material.descriptor.source_operations = vec![RegistrationAdapterSourceOperation {
            id: "requireWorkerSecret".to_string(),
            helper: RegistrationAdapterExportIdentity {
                module_path: SOURCE_HELPER.to_string(),
                export_name: "requireWorkerSecret".to_string(),
                source_sha256: exported_unit_hash(&helper, "requireWorkerSecret"),
            },
            semantic: RegistrationAdapterSourceOperationSemantic {
                kind: "hostSecretVerify".to_string(),
                selector: "WORKER_SECRET".to_string(),
                missing_configuration_error: "WORKER_SECRET is not set".to_string(),
                mismatch_error: "Unauthorized".to_string(),
            },
        }];
        material
    }

    fn object_material(registration_kind: &str) -> RegistrationAdapterMaterial {
        material(adapter(
            registration_kind,
            "object",
            vec![
                RegistrationAdapterResultParameter {
                    callback_parameter_index: 2,
                    property: Some("principal".to_string()),
                },
                RegistrationAdapterResultParameter {
                    callback_parameter_index: 3,
                    property: Some("privileged".to_string()),
                },
            ],
        ))
    }

    fn applied_adapter(
        descriptor: RegistrationAdapterDescriptorEntry,
    ) -> AppliedRegistrationAdapter {
        AppliedRegistrationAdapter {
            wrapper_module: descriptor.wrapper.module_path.clone(),
            wrapper_specifier: "./wrapper".to_string(),
            wrapper_unit_name: descriptor.wrapper.export_name.clone(),
            wrapper_unit_source_sha256: descriptor.wrapper.source_sha256.clone(),
            helper_module: descriptor.authentication.helper.module_path.clone(),
            helper_unit_name: descriptor.authentication.helper.export_name.clone(),
            helper_unit_source_sha256: descriptor.authentication.helper.source_sha256.clone(),
            helper_parameter_start: 0,
            descriptor,
        }
    }

    fn fixture(
        callback_source: &str,
        registration_adapter: RegistrationAdapterMaterial,
    ) -> (GraphInput, BTreeMap<String, LoadedModule>) {
        fixture_with_args(callback_source, "{}", registration_adapter)
    }

    fn fixture_with_args(
        callback_source: &str,
        args_source: &str,
        registration_adapter: RegistrationAdapterMaterial,
    ) -> (GraphInput, BTreeMap<String, LoadedModule>) {
        let entry_source = format!(
            "import {{ adapted as registration }} from \"./wrapper\";\n\
             import {{ requireWorkerSecret }} from \"./sourceHelper\";\n\
             export const selected = registration({{ args: {args_source}, handler: \
             {callback_source} }});\n"
        );
        let modules = BTreeMap::from([
            (
                ENTRY.to_string(),
                LoadedModule::new(summary(ENTRY, &entry_source), entry_source),
            ),
            (
                WRAPPER.to_string(),
                LoadedModule::new(summary(WRAPPER, WRAPPER_SOURCE), WRAPPER_SOURCE.to_string()),
            ),
            (
                HELPER.to_string(),
                LoadedModule::new(summary(HELPER, HELPER_SOURCE), HELPER_SOURCE.to_string()),
            ),
            (
                SOURCE_HELPER.to_string(),
                LoadedModule::new(
                    summary(SOURCE_HELPER, SOURCE_HELPER_SOURCE),
                    SOURCE_HELPER_SOURCE.to_string(),
                ),
            ),
        ]);
        let graph = GraphInput {
            kind: "convex-wasm-esbuild-graph".to_string(),
            repo_root: Path::new("/fixture").to_path_buf(),
            functions_root: "fixtures".to_string(),
            entry_path: ENTRY.to_string(),
            export_name: "selected".to_string(),
            toolchain: Toolchain {
                esbuild: "fixture-esbuild".to_string(),
                convex: "fixture-convex".to_string(),
            },
            dependency_adapter: super::test_dependency_adapter_material(),
            registration_adapter,
            assumptions: None,
            effect_execution_mode: super::EffectExecutionMode::BlockingFiber,
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([
                    (
                        ENTRY.to_string(),
                        EsbuildInput {
                            imports: vec![
                                EsbuildImport {
                                    path: WRAPPER.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some("./wrapper".to_string()),
                                    external: false,
                                },
                                EsbuildImport {
                                    path: SOURCE_HELPER.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some("./sourceHelper".to_string()),
                                    external: false,
                                },
                            ],
                        },
                    ),
                    (
                        WRAPPER.to_string(),
                        EsbuildInput {
                            imports: vec![EsbuildImport {
                                path: HELPER.to_string(),
                                kind: "import-statement".to_string(),
                                original: Some("./helper".to_string()),
                                external: false,
                            }],
                        },
                    ),
                    (
                        HELPER.to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                    (
                        SOURCE_HELPER.to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                ]),
                outputs: BTreeMap::new(),
            },
            phase_timings_us: BTreeMap::new(),
        };
        (graph, modules)
    }

    fn compile(
        callback_source: &str,
        registration_adapter: RegistrationAdapterMaterial,
    ) -> super::CompilerOutput {
        let (graph, modules) = fixture(callback_source, registration_adapter);
        compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output
    }

    fn compile_in_effect_mode(
        callback_source: &str,
        registration_adapter: RegistrationAdapterMaterial,
        effect_execution_mode: super::EffectExecutionMode,
    ) -> super::CompilerOutput {
        let (mut graph, modules) = fixture(callback_source, registration_adapter);
        graph.effect_execution_mode = effect_execution_mode;
        compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output
    }

    fn compile_with_args(
        callback_source: &str,
        args_source: &str,
        registration_adapter: RegistrationAdapterMaterial,
    ) -> super::CompilerOutput {
        let (graph, modules) =
            fixture_with_args(callback_source, args_source, registration_adapter);
        compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output
    }

    fn generated_source(output: &super::CompilerOutput) -> &str {
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        compiled
            .generated_javascript_artifact
            .as_ref()
            .and_then(|artifact| artifact.source.as_deref())
            .unwrap()
    }

    fn evaluate_lowered_handler(source: &str) -> serde_json::Value {
        let lowered = lower_generated_javascript(
            source,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::GuestNativeJson,
        )
        .unwrap()
        .source;
        let javascript = transform_typescript(&lowered, Path::new("generated-filter.ts")).unwrap();
        let script =
            format!("{javascript}\nprocess.stdout.write(JSON.stringify(__convexWasmHandler()));");
        let output = Command::new("node")
            .args(["--input-type=module", "--eval", &script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "node rejected lowered filter source: {}\n{javascript}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    #[test]
    fn fixed_batch_continuations_execute_without_capture_and_preserve_ordering() {
        let render_source = |collision: &str| {
            format!(
                r#"let batchMode;
let events;
let reads;
let operationArguments;
	function nextInput() {{ reads.input += 1; return {{ id: "first-id", observedId: "observed-id" }}; }}
	function nextSecond() {{ reads.second += 1; return "second-id"; }}
	async function load(ctx, input, shouldThrow) {{
	  const {collision} = await ctx.db.get("documents", input.id);
	  events.push("user");
	  if (shouldThrow) throw new Error("continuation failed");
	  return {{ id: {collision}._id, observedId: input.observedId }};
}}
function __convexAsyncFixedBatch(_operationIds, argumentsValue) {{
  operationArguments = argumentsValue;
  return batchMode === "null"
    ? [null, {{ _id: "second-result" }}]
    : [{{ _id: "first-result" }}, {{ _id: "second-result" }}];
}}
function __convexMarkArray(values) {{ return values; }}
const __convexWasmHandler = (mode) => {{
  batchMode = mode;
  events = [];
	  reads = {{ input: 0, second: 0 }};
	  try {{
	    const values = Promise.all([load({{}}, nextInput(), mode === "throw"), secondEffect(nextSecond())]);
    return {{ outcome: "ok", values, events, reads, operationArguments }};
  }} catch (error) {{
    return {{ outcome: "error", message: error.message, events, reads, operationArguments }};
  }}
}};"#
            )
        };
        let mut collision = "collision".to_string();
        let source = loop {
            let candidate = render_source(&collision);
            let batch_start = candidate.find("Promise.all([").unwrap();
            let next = format!("__convexBatchContinuationResult_{batch_start}_0");
            if next == collision {
                break candidate;
            }
            collision = next;
        };
        let authorized_argument = |start: usize, end: usize| {
            let value = &source[start..end];
            DirectAsyncBatchArgumentAuthorization {
                source_start: start as u32,
                source_end: end as u32,
                source: value.to_string(),
                source_sha256: hash_bytes(value.as_bytes()),
                generated_start: start as u32,
                generated_end: end as u32,
                generated_sha256: hash_bytes(value.as_bytes()),
            }
        };
        let span_from = |needle: &str, from: usize| {
            let start = source[from..].find(needle).unwrap() + from;
            (start, start + needle.len())
        };
        let batch_source =
            r#"Promise.all([load({}, nextInput(), mode === "throw"), secondEffect(nextSecond())])"#;
        let (batch_start, batch_end) = span_from(batch_source, 0);
        assert_eq!(
            collision,
            format!("__convexBatchContinuationResult_{batch_start}_0")
        );
        let first_child_source = r#"load({}, nextInput(), mode === "throw")"#;
        let second_child_source = "secondEffect(nextSecond())";
        let (first_start, first_end) = span_from(first_child_source, batch_start);
        let (second_start, second_end) = span_from(second_child_source, first_end);
        let helper_start = source.find("async function load(").unwrap();
        let helper_body_start = source[helper_start..].find('{').unwrap() + helper_start + 1;
        let helper_body_end = source[helper_body_start..]
            .find("\n}\nfunction __convexAsyncFixedBatch")
            .unwrap()
            + helper_body_start;
        let suspension_source = r#"await ctx.db.get("documents", input.id)"#;
        let (suspension_start, suspension_end) = span_from(suspension_source, helper_body_start);
        let (effect_id_start, effect_id_end) = span_from("input.id", suspension_start);
        let helper_arguments = ["{}", "nextInput()", r#"mode === "throw""#]
            .into_iter()
            .scan(first_start, |search_start, argument| {
                let (start, end) = span_from(argument, *search_start);
                *search_start = end;
                Some(authorized_argument(start, end))
            })
            .collect::<Vec<_>>();
        let next_input = authorized_argument(
            helper_arguments[1].source_start as usize,
            helper_arguments[1].source_end as usize,
        );
        let (next_second_start, next_second_end) = span_from("nextSecond()", second_start);
        let first_child = DirectAsyncBatchFixedChildAuthorization {
            start: first_start as u32,
            end: first_end as u32,
            operation_start: first_start as u32,
            operation_end: first_end as u32,
            operation_id: 1,
            operation_kind: "databaseIndexQuery".to_string(),
            result_kind: "hostValue".to_string(),
            source: first_child_source.to_string(),
            source_sha256: hash_bytes(first_child_source.as_bytes()),
            dynamic_arguments: vec![next_input],
            generated_start: first_start as u32,
            generated_end: first_end as u32,
            generated_source_sha256: hash_bytes(first_child_source.as_bytes()),
            helper_continuation_prebound: true,
            operation_stable_key: "fixture-first".to_string(),
            helper_callee: Some("load".to_string()),
            helper_dynamic_argument_indices: vec![1],
            helper_continuation: Some(DirectBatchHelperContinuationAuthorization {
                helper_binding: "load".to_string(),
                helper_parameters: vec![
                    "ctx".to_string(),
                    "input".to_string(),
                    "shouldThrow".to_string(),
                ],
                helper_arguments,
                source_sha256: hash_bytes(source[helper_start..helper_body_end].as_bytes()),
                source_body_start: helper_body_start as u32,
                source_body_end: helper_body_end as u32,
                source_suspension_start: suspension_start as u32,
                source_suspension_end: suspension_end as u32,
                source_result_binding: collision.clone(),
                generated_body_start: helper_body_start as u32,
                generated_body_end: helper_body_end as u32,
                generated_suspension_start: suspension_start as u32,
                generated_suspension_end: suspension_end as u32,
                generated_result_binding: collision.clone(),
                generated_effect_arguments: vec![SourceRange {
                    start: effect_id_start as u32,
                    end: effect_id_end as u32,
                }],
                dependency_adapter: Some(DirectBatchHelperDependencyAdapterContinuation {
                    table: "documents".to_string(),
                    field: "owner".to_string(),
                }),
            }),
        };
        let second_child = DirectAsyncBatchFixedChildAuthorization {
            start: second_start as u32,
            end: second_end as u32,
            operation_start: second_start as u32,
            operation_end: second_end as u32,
            operation_id: 2,
            operation_kind: "databaseGet".to_string(),
            result_kind: "hostValue".to_string(),
            source: second_child_source.to_string(),
            source_sha256: hash_bytes(second_child_source.as_bytes()),
            dynamic_arguments: vec![authorized_argument(next_second_start, next_second_end)],
            generated_start: second_start as u32,
            generated_end: second_end as u32,
            generated_source_sha256: hash_bytes(second_child_source.as_bytes()),
            helper_continuation_prebound: false,
            operation_stable_key: "fixture-second".to_string(),
            helper_callee: None,
            helper_dynamic_argument_indices: Vec::new(),
            helper_continuation: None,
        };
        let authorization = DirectAsyncBatchAuthorization {
            id: "batch_collision_fixture".to_string(),
            file: "fixture.ts".to_string(),
            start: batch_start as u32,
            end: batch_end as u32,
            line: 1,
            column: 1,
            source: batch_source.to_string(),
            source_sha256: hash_bytes(batch_source.as_bytes()),
            generated_start: batch_start as u32,
            generated_end: batch_end as u32,
            generated_source_sha256: hash_bytes(batch_source.as_bytes()),
            shape: DirectAsyncBatchAuthorizationShape::FixedEffectArray {
                children: vec![first_child, second_child],
            },
            dependency_chain: Vec::new(),
        };
        let collision_error = lower_generated_javascript_for_effect_execution_mode(
            &source,
            &[],
            std::slice::from_ref(&authorization),
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            &BTreeSet::new(),
            super::EffectExecutionMode::BlockingFiber,
            ValueMode::GuestNativeJson,
            true,
            None,
        )
        .unwrap_err();
        assert!(
            collision_error.to_string().contains("__convexMarkArray"),
            "{collision_error:#}"
        );
        let lowered = lower_generated_javascript(
            &source,
            &[],
            &[authorization],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::Opaque,
        )
        .unwrap_or_else(|error| panic!("{error:#}\n{source}"))
        .source;
        let javascript =
            transform_typescript(&lowered, Path::new("fixed-batch-collision.ts")).unwrap();
        let script = format!(
            "{javascript}\nprocess.stdout.write(JSON.stringify([\"normal\", \"throw\", \"null\"].map((mode) => __convexWasmHandler(mode))));"
        );
        let output = Command::new("node")
            .args(["--input-type=module", "--eval", &script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "node rejected lowered fixed batch source: {}\n{javascript}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            result,
            serde_json::json!([
                {
                    "outcome": "ok",
                    "values": [
                        { "id": "first-result", "observedId": "observed-id" },
                        { "_id": "second-result" },
                    ],
                    "events": ["user"],
                    "reads": { "input": 1, "second": 1 },
                    "operationArguments": [["first-id"], ["second-id"]],
                },
                {
                    "outcome": "error",
                    "message": "continuation failed",
                    "events": ["user"],
                    "reads": { "input": 1, "second": 1 },
                    "operationArguments": [["first-id"], ["second-id"]],
                },
                {
                    "outcome": "error",
                    "message": "Can't find a document in documents with field owner equal to first-id",
                    "events": [],
                    "reads": { "input": 1, "second": 1 },
                    "operationArguments": [["first-id"], ["second-id"]],
                },
            ])
        );
    }

    #[test]
    fn mapped_continuation_lowering_prebinds_member_arguments_once_in_iterator_order() {
        let render_source = |collision: &str| {
            format!(
                r#"let events;
let operationArguments;
const {collision} = "occupied";
function nextSuffix(value) {{
  events.push("suffix:" + value);
  return "-" + value;
}}
async function load(ctx, id, suffix) {{
  const document = await ctx.db.get("documents", id);
  events.push("continuation:" + id);
  return {{ id: document._id, label: document.label + suffix }};
}}
function __convexAsyncBatch(values, _operationId, projectArguments) {{
  events.push("batch");
  operationArguments = values.map(projectArguments);
  return operationArguments.map((argumentsValue) => ({{
    _id: argumentsValue[0],
    label: "label",
  }}));
}}
function __convexMarkArray(values) {{ return values; }}
const __convexWasmHandler = () => {{
  events = [];
  const ctx = {{}};
  const args = {{ items: [{{ id: "a" }}, {{ id: "b" }}] }};
  const values = Promise.all(
    args.items.map((item) => load(ctx, item.id, nextSuffix(item.id))),
  );
  return {{ values, events, operationArguments }};
}};"#
            )
        };
        let mut collision = "collision".to_string();
        let source = loop {
            let candidate = render_source(&collision);
            let batch_start = candidate.find("Promise.all(").unwrap();
            let next = format!("__convexBatchHelperArguments_{batch_start}");
            if next == collision {
                break candidate;
            }
            collision = next;
        };
        let span_from = |needle: &str, from: usize| {
            let start = source[from..].find(needle).unwrap() + from;
            (start, start + needle.len())
        };
        let authorized_argument = |start: usize, end: usize| {
            let value = &source[start..end];
            DirectAsyncBatchArgumentAuthorization {
                source_start: start as u32,
                source_end: end as u32,
                source: value.to_string(),
                source_sha256: hash_bytes(value.as_bytes()),
                generated_start: start as u32,
                generated_end: end as u32,
                generated_sha256: hash_bytes(value.as_bytes()),
            }
        };
        let batch_source = r#"Promise.all(
    args.items.map((item) => load(ctx, item.id, nextSuffix(item.id))),
  )"#;
        let (batch_start, batch_end) = span_from(batch_source, 0);
        assert_eq!(
            collision,
            format!("__convexBatchHelperArguments_{batch_start}")
        );
        let (iterator_start, iterator_end) = span_from("args.items", batch_start);
        let (callback_start, callback_end) = span_from(
            "(item) => load(ctx, item.id, nextSuffix(item.id))",
            iterator_end,
        );
        let (operation_start, operation_end) =
            span_from("load(ctx, item.id, nextSuffix(item.id))", callback_start);
        let helper_arguments = ["ctx", "item.id", "nextSuffix(item.id)"]
            .into_iter()
            .scan(operation_start, |search_start, argument| {
                let (start, end) = span_from(argument, *search_start);
                *search_start = end;
                Some(authorized_argument(start, end))
            })
            .collect::<Vec<_>>();
        let helper_start = source.find("async function load(").unwrap();
        let helper_body_start = source[helper_start..].find('{').unwrap() + helper_start + 1;
        let helper_body_end = source[helper_body_start..]
            .find("\n}\nfunction __convexAsyncBatch")
            .unwrap()
            + helper_body_start;
        let suspension_source = r#"await ctx.db.get("documents", id)"#;
        let (suspension_start, suspension_end) = span_from(suspension_source, helper_body_start);
        let (effect_id_start, effect_id_end_with_paren) = span_from("id)", suspension_start);
        let effect_argument = authorized_argument(
            helper_arguments[1].source_start as usize,
            helper_arguments[1].source_end as usize,
        );
        let mut authorization = DirectAsyncBatchAuthorization {
            id: "batch_mapped_continuation_fixture".to_string(),
            file: "fixture.ts".to_string(),
            start: batch_start as u32,
            end: batch_end as u32,
            line: 1,
            column: 1,
            source: batch_source.to_string(),
            source_sha256: hash_bytes(batch_source.as_bytes()),
            generated_start: batch_start as u32,
            generated_end: batch_end as u32,
            generated_source_sha256: hash_bytes(batch_source.as_bytes()),
            shape: DirectAsyncBatchAuthorizationShape::SingleEffectMap {
                callback_start: callback_start as u32,
                callback_end: callback_end as u32,
                callback_parameter: "item".to_string(),
                operation_start: operation_start as u32,
                operation_end: operation_end as u32,
                operation_id: 1,
                operation_kind: "databaseGet".to_string(),
                result_kind: "hostValue".to_string(),
                helper_continuation_prebound: true,
                argument_field: Some("items".to_string()),
                dynamic_arguments: vec![effect_argument],
                source_iterator_start: iterator_start as u32,
                source_iterator_end: iterator_end as u32,
                generated_iterator_start: iterator_start as u32,
                generated_iterator_end: iterator_end as u32,
                generated_iterator_sha256: hash_bytes("args.items".as_bytes()),
                operation_stable_key: "fixture-get".to_string(),
                helper_callee: Some("load".to_string()),
                helper_dynamic_argument_indices: vec![1],
                helper_continuation: Some(Box::new(DirectBatchHelperContinuationAuthorization {
                    helper_binding: "load".to_string(),
                    helper_parameters: vec![
                        "ctx".to_string(),
                        "id".to_string(),
                        "suffix".to_string(),
                    ],
                    helper_arguments,
                    source_sha256: hash_bytes(source[helper_start..helper_body_end].as_bytes()),
                    source_body_start: helper_body_start as u32,
                    source_body_end: helper_body_end as u32,
                    source_suspension_start: suspension_start as u32,
                    source_suspension_end: suspension_end as u32,
                    source_result_binding: "document".to_string(),
                    generated_body_start: helper_body_start as u32,
                    generated_body_end: helper_body_end as u32,
                    generated_suspension_start: suspension_start as u32,
                    generated_suspension_end: suspension_end as u32,
                    generated_result_binding: "document".to_string(),
                    generated_effect_arguments: vec![SourceRange {
                        start: effect_id_start as u32,
                        end: (effect_id_end_with_paren - 1) as u32,
                    }],
                    dependency_adapter: None,
                })),
            },
            dependency_chain: Vec::new(),
        };

        let DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            helper_continuation_prebound,
            ..
        } = &mut authorization.shape
        else {
            unreachable!();
        };
        *helper_continuation_prebound = false;
        let mismatch =
            super::effect_plan::current_direct_batch_authorization_layout(&authorization)
                .expect_err("tampered continuation prebinding metadata must fail closed");
        assert!(mismatch.message.contains("prebinding metadata disagrees"));
        let DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            helper_continuation_prebound,
            helper_continuation,
            ..
        } = &mut authorization.shape
        else {
            unreachable!();
        };
        *helper_continuation_prebound = true;
        helper_continuation
            .as_mut()
            .unwrap()
            .helper_parameters
            .pop();
        let arity_error = lower_generated_javascript(
            &source,
            &[],
            std::slice::from_ref(&authorization),
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::Opaque,
        )
        .expect_err("tampered mapped helper arity must fail closed");
        assert!(
            arity_error
                .to_string()
                .contains("mapped continuation helper argument count changed")
        );
        let DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            helper_continuation,
            ..
        } = &mut authorization.shape
        else {
            unreachable!();
        };
        helper_continuation
            .as_mut()
            .unwrap()
            .helper_parameters
            .push("suffix".to_string());

        let lowered = lower_generated_javascript(
            &source,
            &[],
            &[authorization],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::Opaque,
        )
        .unwrap_or_else(|error| panic!("{error:#}\n{source}"))
        .source;
        assert!(lowered.contains(&format!("__convexBatchHelperArguments_{batch_start}_")));
        assert!(!lowered.contains("...__convexBatchHelper"));
        let javascript =
            transform_typescript(&lowered, Path::new("mapped-continuation-prebinding.ts")).unwrap();
        let script =
            format!("{javascript}\nprocess.stdout.write(JSON.stringify(__convexWasmHandler()));");
        let output = Command::new("node")
            .args(["--input-type=module", "--eval", &script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "node rejected lowered mapped continuation source: {}\n{javascript}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            result,
            serde_json::json!({
                "values": [
                    { "id": "a", "label": "label-a" },
                    { "id": "b", "label": "label-b" },
                ],
                "events": [
                    "suffix:a",
                    "suffix:b",
                    "batch",
                    "continuation:a",
                    "continuation:b",
                ],
                "operationArguments": [["a"], ["b"]],
            })
        );
    }

    fn assert_guest_native_capability_ineligible(
        callback_source: &str,
        expected_code: &str,
        expected_message: &str,
    ) {
        let output = compile(callback_source, object_material("query"));
        assert!(!output.eligible, "fixture unexpectedly compiled");
        assert!(
            output.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == expected_code
                    && diagnostic.message.contains(expected_message)
                    && diagnostic.construct.as_deref() == Some("Identifier")
                    && diagnostic.file == ENTRY
                    && diagnostic.line == 3
                    && diagnostic.column > 0
                    && !diagnostic.source.is_empty()
            }),
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message, &diagnostic.source))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn guest_native_runtime_capabilities_admit_only_direct_deterministic_uses() {
        for callback_source in [
            "async (ctx, args, principal) => ({ principal, value: Number(\"2\"), finite: Number.isFinite(2), maximum: Number.MAX_SAFE_INTEGER })",
            "async (ctx, args, principal) => ({ principal, value: Math.max(1, 2), floor: Math[\"floor\"](1.5), pi: Math.PI })",
            "async (ctx, args, principal) => { const values = new Set([1, 1]); return { principal, values: [...values] }; }",
            "async (ctx, args, principal) => ({ principal, value: String(3), codePoint: String.fromCodePoint(65) })",
            "async (ctx, args, principal) => { const values = new Map([[\"value\", 1]]); return { principal, value: values.get(\"value\") }; }",
            "async (ctx, args, principal) => ({ principal, value: Object.keys(args).length })",
            "async (ctx, args, principal) => ({ principal, value: JSON.stringify(args) })",
            "async (ctx, args, principal) => ({ principal, value: new Date(0).getTime() })",
        ] {
            let output = compile(callback_source, object_material("query"));
            assert!(
                output.eligible,
                "{:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
                panic!("eligible fixture returned analysis output");
            };
            assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        }
    }

    #[test]
    fn shadowed_runtime_capability_names_remain_ordinary_local_values() {
        let output = compile(
            "async (ctx, args, principal) => { const Math = { max: (left, right) => left + right }; const Date = (value) => value; return { principal, value: Math.max(1, 2), date: Date(0) }; }",
            object_material("query"),
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::Opaque);
    }

    #[test]
    fn existing_opaque_safe_integer_intrinsic_does_not_force_guest_native_values() {
        let output = compile(
            "async (ctx, args, principal) => ({ principal, value: Number.isSafeInteger(args.value) })",
            object_material("query"),
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::Opaque);
    }

    #[test]
    fn reachable_imported_constants_emit_dependency_module_in_source_order() {
        let entry_source = r#"
import { adapted as registration } from "./wrapper";
import { TARGET_SYMBOL } from "./constants";
export const selected = registration({
  args: {},
  handler: async () => TARGET_SYMBOL,
});
"#;
        let constants_path = "convex/constants.ts";
        let constants_source = r#"
export const BASE_QUOTE_SYMBOL = "BASE/QUOTE" as const;
export const TARGET_SYMBOL = BASE_QUOTE_SYMBOL;
"#;
        let (mut graph, mut modules) =
            fixture("async () => TARGET_SYMBOL", object_material("query"));
        modules.insert(
            ENTRY.to_string(),
            LoadedModule::new(summary(ENTRY, entry_source), entry_source.to_string()),
        );
        modules.insert(
            constants_path.to_string(),
            LoadedModule::new(
                summary(constants_path, constants_source),
                constants_source.to_string(),
            ),
        );
        graph
            .metafile
            .inputs
            .get_mut(ENTRY)
            .unwrap()
            .imports
            .push(EsbuildImport {
                path: constants_path.to_string(),
                kind: "import-statement".to_string(),
                original: Some("./constants".to_string()),
                external: false,
            });
        graph.metafile.inputs.insert(
            constants_path.to_string(),
            EsbuildInput {
                imports: Vec::new(),
            },
        );
        let output = compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output;
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let source = generated_source(&output);
        let dependency = source
            .find("const BASE_QUOTE_SYMBOL = \"BASE/QUOTE\";")
            .unwrap();
        let initializer = source
            .find("const TARGET_SYMBOL = BASE_QUOTE_SYMBOL;")
            .unwrap();
        assert!(dependency < initializer, "{source}");
    }

    #[test]
    fn reachable_same_module_constants_preserve_a_genuine_tdz_order() {
        let entry_source = r#"
import { adapted as registration } from "./wrapper";
export const TARGET_SYMBOL = BASE_QUOTE_SYMBOL;
export const BASE_QUOTE_SYMBOL = "BASE/QUOTE" as const;
export const selected = registration({
  args: {},
  handler: async () => TARGET_SYMBOL,
});
"#;
        let (graph, mut modules) = fixture("async () => TARGET_SYMBOL", object_material("query"));
        modules.insert(
            ENTRY.to_string(),
            LoadedModule::new(summary(ENTRY, entry_source), entry_source.to_string()),
        );
        let output = compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output;
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let source = generated_source(&output);
        let initializer = source
            .find("const TARGET_SYMBOL = BASE_QUOTE_SYMBOL;")
            .unwrap();
        let dependency = source
            .find("const BASE_QUOTE_SYMBOL = \"BASE/QUOTE\";")
            .unwrap();
        assert!(initializer < dependency, "{source}");
    }

    #[test]
    fn reachable_runtime_module_cycle_is_an_exact_fallback() {
        let entry_source = r#"
import { adapted as registration } from "./wrapper";
import { value } from "./cycleA";
export const selected = registration({ args: {}, handler: async () => value });
"#;
        let cycle_a_path = "convex/cycleA.ts";
        let cycle_a_source = r#"
import { b } from "./cycleB";
export const value = b;
"#;
        let cycle_b_path = "convex/cycleB.ts";
        let cycle_b_source = r#"
import { value } from "./cycleA";
export const b = value;
"#;
        let (mut graph, mut modules) = fixture("async () => value", object_material("query"));
        for (path, source) in [
            (ENTRY, entry_source),
            (cycle_a_path, cycle_a_source),
            (cycle_b_path, cycle_b_source),
        ] {
            modules.insert(
                path.to_string(),
                LoadedModule::new(summary(path, source), source.to_string()),
            );
        }
        graph
            .metafile
            .inputs
            .get_mut(ENTRY)
            .unwrap()
            .imports
            .push(EsbuildImport {
                path: cycle_a_path.to_string(),
                kind: "import-statement".to_string(),
                original: Some("./cycleA".to_string()),
                external: false,
            });
        graph.metafile.inputs.insert(
            cycle_a_path.to_string(),
            EsbuildInput {
                imports: vec![EsbuildImport {
                    path: cycle_b_path.to_string(),
                    kind: "import-statement".to_string(),
                    original: Some("./cycleB".to_string()),
                    external: false,
                }],
            },
        );
        graph.metafile.inputs.insert(
            cycle_b_path.to_string(),
            EsbuildInput {
                imports: vec![EsbuildImport {
                    path: cycle_a_path.to_string(),
                    kind: "import-statement".to_string(),
                    original: Some("./cycleA".to_string()),
                    external: false,
                }],
            },
        );
        let output = compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output;
        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-module-initialization-cycle"
                && diagnostic.message.contains("ESM initialization order")
                && diagnostic.construct.as_deref() == Some("Identifier")
                && diagnostic.line > 0
                && diagnostic.column > 0
                && !diagnostic.source.is_empty()
        }));
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("inline cycle fixture returned analysis output");
        };
        assert!(compiled.generated_javascript_artifact.is_none());
    }

    #[test]
    fn guest_native_runtime_capabilities_reject_nondeterminism_and_escapes() {
        for callback_source in [
            "async (ctx, args, principal) => ({ principal, value: Math.random() })",
            "async (ctx, args, principal) => ({ principal, value: Math[\"random\"]() })",
            "async (ctx, args, principal) => { const random = Math.random; return { principal, value: random() }; }",
            "async (ctx, args, principal) => { const now = Date.now; return { principal, value: now() }; }",
            "async (ctx, args, principal) => ({ principal, value: Date.now(1) })",
            "async (ctx, args, principal) => ({ principal, value: Date.now.call(Date) })",
            "async (ctx, args, principal) => ({ principal, value: Date(0) })",
            "async (ctx, args, principal) => ({ principal, value: new Date() })",
            "async (ctx, args, principal) => ({ principal, value: new Date(...[]) })",
            "async (ctx, args, principal) => ({ principal, value: new Date(...[0]) })",
            "async (ctx, args, principal) => ({ principal, value: new Date(...args) })",
            "async (ctx, args, principal) => ({ principal, value: Date(...[]) })",
        ] {
            assert_guest_native_capability_ineligible(
                callback_source,
                "unsupported-nondeterminism",
                "not admitted",
            );
        }

        for callback_source in [
            "async (ctx, args, principal) => { const M = Math; return { principal, value: M.max(1, 2) }; }",
            "async (ctx, args, principal) => { const { max } = Math; return { principal, value: max(1, 2) }; }",
            "async (ctx, args, principal) => { const max = Math.max; return { principal, value: max(1, 2) }; }",
            "async (ctx, args, principal) => { const field = \"max\"; return { principal, value: Math[field](1, 2) }; }",
            "async (ctx, args, principal) => { const field = \"now\"; return { principal, value: Date[field]() }; }",
            "async (ctx, args, principal) => ({ principal, value: Math })",
            "async (ctx, args, principal) => { const holder = { math: Math }; return { principal, holder }; }",
            "async (ctx, args, principal) => { Math.PI = 3; return { principal }; }",
            "async (ctx, args, principal) => { Math.random = () => 1; return { principal }; }",
            "async (ctx, args, principal) => ({ principal, value: Object.keys(Math) })",
            "async (ctx, args, principal) => { const json = JSON; return { principal, value: json.stringify(args) }; }",
            "async (ctx, args, principal) => { Map.prototype.clear = () => {}; return { principal }; }",
        ] {
            assert_guest_native_capability_ineligible(
                callback_source,
                "unsupported-runtime-capability-flow",
                "not admitted",
            );
        }

        for callback_source in [
            "async (ctx, args, principal) => ({ principal, value: Date.parse(\"2026-01-01T00:00:00Z\") })",
            "async (ctx, args, principal) => ({ principal, value: Date.UTC(2026, 0, 1) })",
            "async (ctx, args, principal) => ({ principal, value: Math.sumPrecise([1, 2]) })",
        ] {
            assert_guest_native_capability_ineligible(
                callback_source,
                "unsupported-runtime-capability-member",
                "not an admitted",
            );
        }

        assert_guest_native_capability_ineligible(
            "async (ctx, args, principal) => ({ principal, value: new Date(2026, 0, 1) })",
            "unsupported-runtime-capability-flow",
            "exactly one explicit input",
        );
        assert_guest_native_capability_ineligible(
            "async (ctx, args, principal) => { Math = { max: () => 1 }; return { principal }; }",
            "global-write",
            "write to global",
        );
    }

    #[test]
    fn guest_native_mode_lowers_exact_global_invocation_time_calls() {
        for callback_source in [
            "async (ctx, args, principal) => ({ principal, first: Date.now(), second: Date[\"now\"]() })",
            "async (ctx, args, principal) => { const Date = { now: () => 41 }; return { principal, local: Date.now() }; }",
        ] {
            let output = compile(callback_source, object_material("query"));
            assert!(
                output.eligible,
                "{:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
                panic!("eligible fixture returned analysis output");
            };
            let source = generated_source(&output);
            if callback_source.contains("Date[\"now\"]") {
                assert_eq!(
                    compiled.runtime_inputs,
                    ["invocationUnixTimestampMs".to_string()]
                );
                assert_eq!(
                    source
                        .matches("__convexInvocationUnixTimestampMs()")
                        .count(),
                    2,
                    "{source}"
                );
                assert!(!source.contains("Date.now()"), "{source}");
                assert!(!source.contains("Date[\"now\"]()"), "{source}");
            } else {
                assert!(compiled.runtime_inputs.is_empty(), "{source}");
                assert!(source.contains("Date.now()"), "{source}");
                assert!(
                    !source.contains("__convexInvocationUnixTimestampMs"),
                    "{source}"
                );
            }
        }
    }

    #[test]
    fn guest_native_mode_preserves_map_destructuring_and_spread() {
        let output = compile(
            "async (ctx, args, principal) => { const values = new Map(); values.set(\"principal\", { principal, ...args }); const [value] = [...values.values()]; return { ...value }; }",
            object_material("query"),
        );
        assert!(output.eligible, "{:?}", output.diagnostics[0].message);
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        let source = generated_source(&output);
        assert!(source.contains("new Map<any, any>"), "{source}");
        assert!(source.contains("...values.values()"), "{source}");
        assert!(!source.contains("__convexMarkArray"), "{source}");
    }

    #[test]
    fn guest_native_mode_lowers_proved_ordinary_array_filter() {
        let output = compile(
            "async (ctx, args, principal) => { const values = new Map(); return { principal, values: [1, 2].filter((value) => value > 1), size: values.size }; }",
            object_material("query"),
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        let source = generated_source(&output);
        assert!(!source.contains(".filter("), "{source}");
    }

    #[test]
    fn guest_native_array_lowering_rejects_array_prototype_mutation() {
        for callback_source in [
            "async () => { Array.prototype.filter = () => [9]; return [1].filter(() => true); }",
            "async () => { Array.prototype[Symbol.iterator] = function* () { yield 9; }; const values = [1]; const output = []; for (const value of values) output.push(value); return output; }",
            "async () => { const prototype = Array.prototype; prototype.filter = () => [9]; return [1].filter(() => true); }",
            "async () => { const prototype = Array.prototype; prototype[Symbol.iterator] = function* () { yield 9; }; const values = [1]; const output = []; for (const value of values) output.push(value); return output; }",
        ] {
            let output = compile(callback_source, object_material("query"));
            assert!(
                !output.eligible,
                "array prototype mutation compiled with transformed semantics: {}",
                generated_source(&output)
            );
        }
    }

    #[test]
    fn guest_native_array_filter_preserves_sparse_order_snapshot_and_callback_arguments() {
        let result = evaluate_lowered_handler(
            "const __convexWasmHandler = () => { const seen = []; const result = [1, , 3].filter((value, index, array) => { seen.push([value, index, array.length]); if (index === 0) { array.push(4); array[1] = 2; delete array[2]; } return true; }); return { result, seen }; };",
        );
        assert_eq!(
            result,
            serde_json::json!({
                "result": [1, 2],
                "seen": [[1, 0, 3], [2, 1, 4]],
            })
        );
    }

    #[test]
    fn guest_native_array_filter_observes_inherited_indexes_without_object_authority() {
        let result = evaluate_lowered_handler(
            "const __convexWasmHandler = () => { const Object = null; Array.prototype[1] = 2; try { return [1, , 3].filter((value) => value > 0); } finally { delete Array.prototype[1]; } };",
        );
        assert_eq!(result, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn guest_native_array_filter_evaluates_receiver_once_and_propagates_callback_throws() {
        let result = evaluate_lowered_handler(
            "const __convexWasmHandler = () => { let receiverReads = 0; const filtered = Object.values({ get value() { receiverReads += 1; return 2; } }).filter((value) => value === 2); let thrown; try { [1].filter(() => { throw new Error(\"callback failed\"); }); } catch (error) { thrown = error.message; } return { filtered, receiverReads, thrown }; };",
        );
        assert_eq!(
            result,
            serde_json::json!({
                "filtered": [2],
                "receiverReads": 1,
                "thrown": "callback failed",
            })
        );
    }

    #[test]
    fn guest_native_loop_bindings_do_not_capture_escaped_source_identifiers() {
        let mut filter_identifier = "collision".to_string();
        let filter_source = loop {
            let escaped_identifier = filter_identifier.replacen("Array", "\\u0041rray", 1);
            let candidate = format!(
                "const {escaped_identifier} = 'outer'; const __convexWasmHandler = () => [1].filter(() => {escaped_identifier} === 'outer');"
            );
            let filter_start = candidate.find("[1].filter").unwrap();
            let next = format!("__convexFilterArray_{filter_start}");
            if next == filter_identifier {
                break candidate;
            }
            filter_identifier = next;
        };
        assert_eq!(
            evaluate_lowered_handler(&filter_source),
            serde_json::json!([1])
        );

        let mut for_of_identifier = "collision".to_string();
        let for_of_source = loop {
            let escaped_identifier = for_of_identifier.replacen("Array", "\\u0041rray", 1);
            let candidate = format!(
                "const {escaped_identifier} = 'outer'; const __convexWasmHandler = () => {{ let result = null; for (const value of [1]) {{ result = {escaped_identifier}; }} return result; }};"
            );
            let for_of_start = candidate.find("for (const value of").unwrap();
            let next = format!("__convexForOfArray_{for_of_start}");
            if next == for_of_identifier {
                break candidate;
            }
            for_of_identifier = next;
        };
        assert_eq!(
            evaluate_lowered_handler(&for_of_source),
            serde_json::json!("outer")
        );
    }

    #[test]
    fn guest_native_array_filter_preserves_awaited_receiver_suspension() {
        let source =
            "const __convexWasmHandler = async () => (await [1, 2]).filter((value) => value > 1);";
        let lowered = lower_generated_javascript(
            source,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::GuestNativeJson,
        )
        .unwrap()
        .source;
        let javascript =
            transform_typescript(&lowered, Path::new("generated-awaited-filter.ts")).unwrap();
        let script = format!(
            "{javascript}\nprocess.stdout.write(JSON.stringify(await __convexWasmHandler()));"
        );
        let output = Command::new("node")
            .args(["--input-type=module", "--eval", &script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "node rejected lowered awaited filter source: {}\n{javascript}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!([2])
        );
    }

    fn assert_generated_filter_rejected(source: &str, expected_message: &str) {
        let error = lower_generated_javascript(
            source,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::GuestNativeJson,
        )
        .unwrap_err();
        let rejection = error
            .downcast_ref::<super::GeneratedArrayFilterIneligibility>()
            .unwrap();
        assert!(rejection.reason.contains(expected_message), "{rejection:?}");
    }

    #[test]
    fn guest_native_array_filter_rejects_unsupported_semantic_boundaries() {
        for (source, expected_message) in [
            (
                "const __convexWasmHandler = () => [1].filter((value) => value, {});",
                "does not support thisArg",
            ),
            (
                "const __convexWasmHandler = () => [1].filter(async (value) => value);",
                "synchronous and non-generator",
            ),
            (
                "const __convexWasmHandler = (ctx) => [1].filter((value) => ctx.db.get(value));",
                "cannot perform a Convex effect",
            ),
            (
                "const __convexWasmHandler = (values) => values.filter((value) => value);",
                "not one non-escaping, statically proven ordinary array",
            ),
        ] {
            assert_generated_filter_rejected(source, expected_message);
        }
    }

    #[test]
    fn guest_native_array_filter_rejects_escaped_authenticated_array_arguments() {
        let authorization = super::GeneratedArrayArgumentAuthorization {
            parameter_name: "args".to_string(),
            fields: BTreeSet::from(["values".to_string()]),
        };
        for source in [
            "const __convexWasmHandler = (ctx, args) => { const escaped = args.values; return args.values.filter((value) => value); };",
            "const __convexWasmHandler = (ctx, args) => { args.values.filter = () => []; return args.values.filter((value) => value); };",
        ] {
            let error = lower_generated_javascript(
                source,
                &[],
                &[],
                &BTreeMap::new(),
                &BTreeSet::new(),
                Some(&authorization),
                ValueMode::GuestNativeJson,
            )
            .unwrap_err();
            let rejection = error
                .downcast_ref::<super::GeneratedArrayFilterIneligibility>()
                .unwrap();
            assert!(
                rejection.reason.contains("not one non-escaping"),
                "{rejection:?}"
            );
        }
    }

    #[test]
    fn exact_opaque_filter_lowering_remains_selected() {
        let source = "const __convexWasmHandler = () => { const rows = []; const filtered = rows.filter((row) => row.active); return filtered; };";
        let initializer = "rows.filter((row) => row.active)";
        let callback = "(row) => row.active";
        let initializer_start = source.find(initializer).unwrap() as u32;
        let initializer_end = initializer_start + initializer.len() as u32;
        let callback_start = initializer_start + initializer.find(callback).unwrap() as u32;
        let callback_end = callback_start + callback.len() as u32;
        let authorizations = BTreeMap::from([(
            (initializer_start, initializer_end),
            super::GeneratedFilterAuthorization {
                initializer_start,
                initializer_end,
                source_start: initializer_start,
                source_end: initializer_start + "rows".len() as u32,
                callback_start,
                callback_end,
            },
        )]);

        let lowered = lower_generated_javascript(
            source,
            &[],
            &[],
            &authorizations,
            &BTreeSet::new(),
            None,
            ValueMode::Opaque,
        )
        .unwrap()
        .source;

        assert!(
            lowered.contains("__convexMarkArray(__convexFilter(rows, (row) => row.active))"),
            "{lowered}"
        );
        assert!(!lowered.contains("__convexFilterArray_"), "{lowered}");
    }

    #[test]
    fn opaque_array_marks_require_proved_array_expressions() {
        let source = "const __convexWasmHandler = () => { const obj = { map: () => ({ x: 1 }) }; return obj.map(); };";
        let lowered = lower_generated_javascript(
            source,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::Opaque,
        )
        .unwrap()
        .source;
        assert!(lowered.contains("return obj.map();"), "{lowered}");
        assert!(
            !lowered.contains("__convexMarkArray(obj.map())"),
            "{lowered}"
        );

        let shadowed = "const Array = { from: () => ({ x: 1 }) }; const __convexWasmHandler = () => Array.from([]);";
        let lowered = lower_generated_javascript(
            shadowed,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::Opaque,
        )
        .unwrap()
        .source;
        assert!(
            lowered.contains("Array.from(__convexMarkArray([]))"),
            "{lowered}"
        );
        assert!(
            !lowered.contains("__convexMarkArray(Array.from"),
            "{lowered}"
        );

        let builtins = "const __convexWasmHandler = () => { const values = Array(2); return [values.concat([1]), values.splice(0), values.toSorted(), values.toReversed(), values.toSpliced(0, 0), values.with(0, 1)]; };";
        let lowered = lower_generated_javascript(
            builtins,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::Opaque,
        )
        .unwrap()
        .source;
        for expression in [
            "Array(2)",
            "values.concat(__convexMarkArray([1]))",
            "values.splice(0)",
            "values.toSorted()",
            "values.toReversed()",
            "values.toSpliced(0, 0)",
            "values.with(0, 1)",
        ] {
            assert!(
                lowered.contains(&format!("__convexMarkArray({expression})")),
                "{lowered}"
            );
        }

        let builtin_literals = "const __convexWasmHandler = () => [\"a,b\".split(\",\"), /a/.exec(\"a\"), `a`.match(/a/)];";
        let lowered = lower_generated_javascript(
            builtin_literals,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            ValueMode::Opaque,
        )
        .unwrap()
        .source;
        for expression in ["\"a,b\".split(\",\")", "/a/.exec(\"a\")", "`a`.match(/a/)"] {
            assert!(
                lowered.contains(&format!("__convexMarkArray({expression})")),
                "{lowered}"
            );
        }
    }

    #[test]
    fn generated_helper_binding_collisions_fallback_without_weakening_rejection() {
        for (callback_source, helper, message) in [
            (
                "async (ctx, args, principal) => { const __convexMarkArray = (value) => ({ bad: value }); return [1]; }",
                "__convexMarkArray",
                "reserved lowering helper identifier __convexMarkArray",
            ),
            (
                "async (ctx, args, principal) => { const __convexAdapterContext = null; return principal; }",
                "__convexAdapterContext",
                "compiler-generated scoped binding __convexAdapterContext",
            ),
            (
                "async (__convexAdapterContext, args, principal) => principal",
                "__convexAdapterContext",
                "compiler-generated scoped binding __convexAdapterContext",
            ),
        ] {
            let (graph, modules) = fixture(callback_source, object_material("query"));
            let output = compile_export(
                &graph,
                Path::new("/fixture-cache"),
                &mut PhaseMeasurements::default(),
                Instant::now(),
                &modules,
                GeneratedSourceMode::Inline,
            )
            .unwrap()
            .output;
            assert!(!output.eligible, "{helper}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-generated-helper-binding"
                        && diagnostic.message.contains(message)
                        && diagnostic.construct.as_deref() == Some("Identifier")
                        && diagnostic.source == helper
                }),
                "{helper}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message, &diagnostic.source))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn compiler_generated_authority_rejects_source_capture() {
        let source = "function adapter() { return 1; } const adapter = () => 2; const __convexWasmHandler = () => adapter();";
        let authority = GeneratedJavascriptAuthority {
            compiler_top_level_bindings: BTreeSet::from(["adapter".to_string()]),
            ..GeneratedJavascriptAuthority::default()
        };
        let error = lower_generated_javascript_for_effect_execution_mode(
            source,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            &BTreeSet::new(),
            super::EffectExecutionMode::BlockingFiber,
            ValueMode::GuestNativeJson,
            true,
            Some(&authority),
        )
        .unwrap_err();
        assert!(
            error
                .downcast_ref::<GeneratedSourceBindingCollision>()
                .is_some(),
            "{error:#}"
        );

        let helper = "__convexDependencyAdapter_databaseIndexCollect";
        let source = format!(
            "function {helper}() {{ return 1; }} const __convexWasmHandler = () => {{ const {helper} = () => 2; return {helper}(); }};"
        );
        let authority = GeneratedJavascriptAuthority {
            compiler_top_level_bindings: BTreeSet::from([helper.to_string()]),
            ..GeneratedJavascriptAuthority::default()
        };
        let error = lower_generated_javascript_for_effect_execution_mode(
            &source,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            &BTreeSet::new(),
            super::EffectExecutionMode::BlockingFiber,
            ValueMode::GuestNativeJson,
            true,
            Some(&authority),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("is missing or shadowed by a source binding"),
            "{error:#}"
        );

        let source = "function adapter() { return new Error(String(1)); } const Error = class {}; const __convexWasmHandler = () => adapter();";
        let authority = GeneratedJavascriptAuthority {
            compiler_top_level_bindings: BTreeSet::from(["adapter".to_string()]),
            compiler_top_level_globals: BTreeSet::from(["Error".to_string(), "String".to_string()]),
            ..GeneratedJavascriptAuthority::default()
        };
        let error = lower_generated_javascript_for_effect_execution_mode(
            source,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            &BTreeSet::new(),
            super::EffectExecutionMode::BlockingFiber,
            ValueMode::GuestNativeJson,
            true,
            Some(&authority),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("top-level reference Error is captured"),
            "{error:#}"
        );

        let source = "const __convexWasmHandler = () => { const __convexFunctionReference = () => 'captured'; return __convexFunctionReference('expected'); };";
        let authority = GeneratedJavascriptAuthority {
            compiler_application_globals: BTreeSet::from(["__convexFunctionReference".to_string()]),
            ..GeneratedJavascriptAuthority::default()
        };
        let error = lower_generated_javascript_for_effect_execution_mode(
            source,
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            &BTreeSet::new(),
            super::EffectExecutionMode::BlockingFiber,
            ValueMode::GuestNativeJson,
            true,
            Some(&authority),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("application reference __convexFunctionReference can be captured"),
            "{error:#}"
        );
    }

    #[test]
    fn whole_function_intrinsic_does_not_claim_erased_array_marker_authority() {
        let source = "function sha256Hex(value) { Date.now(); return new Uint8Array([value]); } const __convexWasmHandler = () => sha256Hex(1);";
        let authority = GeneratedJavascriptAuthority {
            compiler_top_level_bindings: BTreeSet::from([
                "__convexWasmHandler".to_string(),
                "sha256Hex".to_string(),
            ]),
            ..GeneratedJavascriptAuthority::default()
        };
        let lowered = lower_generated_javascript_for_effect_execution_mode(
            source,
            &[Intrinsic {
                function_name: "sha256Hex".to_string(),
                kind: "sha256".to_string(),
                operation_id: 7,
            }],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            &BTreeSet::new(),
            super::EffectExecutionMode::BlockingFiber,
            ValueMode::Opaque,
            true,
            Some(&authority),
        )
        .unwrap();

        assert!(lowered.runtime_inputs.is_empty());
        let lowered = &lowered.source;

        assert!(
            lowered.contains("{return __convexSha256(7, value);}"),
            "{lowered}"
        );
        assert!(!lowered.contains("__convexMarkArray"), "{lowered}");
        assert!(
            !lowered.contains("__convexInvocationUnixTimestampMs"),
            "{lowered}"
        );

        let collision_source = "function sha256Hex(value) { const __convexMarkArray = (array) => array; return new Uint8Array([value]); } const __convexWasmHandler = () => sha256Hex(1);";
        let collision = lower_generated_javascript_for_effect_execution_mode(
            collision_source,
            &[Intrinsic {
                function_name: "sha256Hex".to_string(),
                kind: "sha256".to_string(),
                operation_id: 7,
            }],
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            &BTreeSet::new(),
            super::EffectExecutionMode::BlockingFiber,
            ValueMode::Opaque,
            true,
            Some(&authority),
        )
        .unwrap_err();
        assert!(
            collision
                .to_string()
                .contains("reserved lowering helper identifier __convexMarkArray"),
            "{collision:#}"
        );
    }

    #[test]
    fn parent_batch_replacement_retains_only_composed_helper_authority() {
        let source =
            "const value = 1; const __convexWasmHandler = () => Promise.all([effect(value)]);";
        let batch_source = "Promise.all([effect(value)])";
        let batch_start = source.find(batch_source).unwrap();
        let batch_end = batch_start + batch_source.len();
        let operation_source = "effect(value)";
        let operation_start = source[batch_start..].find(operation_source).unwrap() + batch_start;
        let operation_end = operation_start + operation_source.len();
        let argument_start = source[operation_start..].find("value").unwrap() + operation_start;
        let argument_end = argument_start + "value".len();
        let argument = DirectAsyncBatchArgumentAuthorization {
            source_start: argument_start as u32,
            source_end: argument_end as u32,
            source: "value".to_string(),
            source_sha256: hash_bytes(b"value"),
            generated_start: argument_start as u32,
            generated_end: argument_end as u32,
            generated_sha256: hash_bytes(b"value"),
        };
        let batch = DirectAsyncBatchAuthorization {
            id: "erased-helper-authority".to_string(),
            file: "fixture.ts".to_string(),
            start: batch_start as u32,
            end: batch_end as u32,
            line: 1,
            column: 1,
            source: batch_source.to_string(),
            source_sha256: hash_bytes(batch_source.as_bytes()),
            generated_start: batch_start as u32,
            generated_end: batch_end as u32,
            generated_source_sha256: hash_bytes(batch_source.as_bytes()),
            shape: DirectAsyncBatchAuthorizationShape::FixedEffectArray {
                children: vec![DirectAsyncBatchFixedChildAuthorization {
                    start: operation_start as u32,
                    end: operation_end as u32,
                    operation_start: operation_start as u32,
                    operation_end: operation_end as u32,
                    operation_id: 1,
                    operation_kind: "databaseGet".to_string(),
                    result_kind: "hostValue".to_string(),
                    source: operation_source.to_string(),
                    source_sha256: hash_bytes(operation_source.as_bytes()),
                    dynamic_arguments: vec![argument],
                    generated_start: operation_start as u32,
                    generated_end: operation_end as u32,
                    generated_source_sha256: hash_bytes(operation_source.as_bytes()),
                    helper_continuation_prebound: false,
                    operation_stable_key: "fixture-effect".to_string(),
                    helper_callee: None,
                    helper_dynamic_argument_indices: Vec::new(),
                    helper_continuation: None,
                }],
            },
            dependency_chain: Vec::new(),
        };
        let lowered = lower_generated_javascript_for_effect_execution_mode(
            source,
            &[],
            &[batch],
            &BTreeMap::new(),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            &BTreeSet::new(),
            super::EffectExecutionMode::BlockingFiber,
            ValueMode::Opaque,
            true,
            None,
        )
        .unwrap();

        assert!(lowered.source.contains("__convexAsyncFixedBatch"));
        assert!(!lowered.source.contains("__convexMarkArray"));
        assert!(lowered.runtime_inputs.is_empty());
    }

    #[test]
    fn guest_native_mode_lowers_authenticated_array_for_of() {
        let output = compile_with_args(
            "async (ctx, args, principal) => { const seen = new Set(); const values = []; for (const value of args.values) { if (seen.has(value)) throw new Error(\"duplicate\"); seen.add(value); values.push({ principal, value }); } return values; }",
            "{ values: v.array(v.number()) }",
            object_material("query"),
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        let source = generated_source(&output);
        assert!(source.contains("new Set<any>"), "{source}");
        assert!(!source.contains("for (const value of"), "{source}");
        assert!(source.contains("let __convexForOfArray_"), "{source}");
        assert!(source.contains("< __convexForOfArray_"), "{source}");
        assert!(
            source.contains("const value = __convexForOfArray_"),
            "{source}"
        );
    }

    #[test]
    fn guest_native_array_for_of_proves_exact_array_parameter_forwarding() {
        let source = lower_generated_javascript(
            "function collectArray() { return []; } function consume(values) { const result = []; for (const value of values) { result.push(value); } return result; } const __convexWasmHandler = () => { const values = collectArray(); return consume(values); };",
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::from(["collectArray".to_string()]),
            None,
            ValueMode::GuestNativeJson,
        )
        .unwrap()
        .source;
        assert!(!source.contains("for (const value of values)"), "{source}");
        assert!(source.contains("let __convexForOfArray_"), "{source}");
    }

    #[test]
    fn guest_native_array_for_of_proves_awaited_array_producer_parameter_forwarding() {
        let source = lower_generated_javascript(
            "function collectArray() { return []; } function consume(values) { const result = []; for (const value of values) { result.push(value); } return result; } const __convexWasmHandler = async () => { const values = await collectArray(); return consume(values); };",
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeSet::from(["collectArray".to_string()]),
            None,
            ValueMode::GuestNativeJson,
        )
        .unwrap()
        .source;
        assert!(!source.contains("await collectArray()"), "{source}");
        assert!(!source.contains("for (const value of values)"), "{source}");
        assert!(source.contains("let __convexForOfArray_"), "{source}");
    }

    #[test]
    fn guest_native_array_for_of_lowers_empty_nonempty_and_sparse_arrays() {
        for callback_source in [
            "async (ctx, args, principal) => { const result = []; for (const value of []) { result.push(value); } return { principal, result }; }",
            "async (ctx, args, principal) => { const result = []; for (const value of [1, 2]) { result.push(value); } return { principal, result }; }",
            "async (ctx, args, principal) => { const result = []; for (const value of [1, , 3]) { result.push(value); } return { principal, result }; }",
        ] {
            let output = compile(callback_source, object_material("query"));
            assert!(
                output.eligible,
                "{:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let source = generated_source(&output);
            assert!(!source.contains("for (const value of"), "{source}");
            assert!(source.contains("[__convexForOfIndex_"), "{source}");
        }
    }

    #[test]
    fn guest_native_array_for_of_evaluates_iterable_once() {
        let output = compile(
            "async (ctx, args, principal) => { const result = []; for (const value of new Array(1, 2)) { result.push(value); } return { principal, result }; }",
            object_material("query"),
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let source = generated_source(&output);
        assert_eq!(source.matches("new Array(1, 2)").count(), 1, "{source}");
        assert_eq!(
            source.matches("let __convexForOfArray_").count(),
            1,
            "{source}"
        );
    }

    #[test]
    fn guest_native_array_for_of_preserves_control_flow() {
        let output = compile(
            "async (ctx, args, principal) => { const result = []; for (const value of [1]) { if (value === 0) break; result.push(value); } for (const value of [2]) { if (value === 0) continue; result.push(value); } for (const value of [3]) { if (value === 0) return { principal, result }; result.push(value); } for (const value of [4]) { if (value === 0) throw new Error(\"zero\"); result.push(value); } return { principal, result }; }",
            object_material("query"),
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let source = generated_source(&output);
        assert_eq!(
            source.matches("let __convexForOfArray_").count(),
            4,
            "{source}"
        );
        for control_flow in ["break;", "continue;", "return {", "throw new Error"] {
            assert!(
                source.contains(control_flow),
                "missing {control_flow}: {source}"
            );
        }
    }

    fn assert_guest_native_for_of_ineligible(callback_source: &str) {
        let output = compile(callback_source, object_material("query"));
        assert!(!output.eligible, "fixture unexpectedly compiled");
        assert!(
            output.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "unsupported-array-for-of-lowering"
                    && diagnostic.construct.as_deref() == Some("ForOfStatement")
            }),
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn guest_native_array_for_of_rejects_unproved_iterables_as_ineligible() {
        for callback_source in [
            "async (ctx, args, principal) => { const result = []; for (const value of new Set([1])) { result.push(value); } return { principal, result }; }",
            "async (ctx, args, principal) => { const iterable = { 0: 1, length: 1 }; const result = []; for (const value of iterable) { result.push(value); } return { principal, result }; }",
            "async (ctx, args, principal) => { const values = [1]; const result = []; for (const value of values) { result.push(value); } return { principal, values, result }; }",
            "async (ctx, args, principal) => { let value; const result = []; for (value of [1]) { result.push(value); } return { principal, result }; }",
            "async (ctx, args, principal) => { const result = []; for (const [value] of [[1]]) { result.push(value); } return { principal, result }; }",
            "async (ctx, args, principal) => { const result = []; for (const outer of [[1]]) { for (const value of outer) { result.push(value); } } return { principal, result }; }",
        ] {
            assert_guest_native_for_of_ineligible(callback_source);
        }
    }

    #[test]
    fn guest_native_preserves_async_for_of_for_static_hermes() {
        let callback = "async (ctx, args, principal) => { const seen = new Set(); for await (const value of args.values) { seen.add(value); } return { principal, values: [...seen] }; }";
        let blocking = compile(callback, object_material("query"));
        assert!(!blocking.eligible);
        assert!(blocking.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-construct"
                && diagnostic.construct.as_deref() == Some("ForAwaitOfStatement")
        }));

        let output = compile_in_effect_mode(
            callback,
            object_material("query"),
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let source = generated_source(&output);
        assert!(
            source.contains("for await (const value of args.values)"),
            "{source}"
        );
        assert!(!source.contains("__convexForOfArray_"), "{source}");
    }

    #[test]
    fn guest_adapter_runtime_root_rejects_nonexact_and_unawaited_helper_inbounds() {
        for (name, helper_use) in [
            ("nonexact reference", "void authenticate;"),
            ("unawaited call", "authenticate(ctx);"),
        ] {
            let (mut graph, mut modules) = fixture(
                "async (ctx, args, principal) => principal",
                object_material("query"),
            );
            graph.effect_execution_mode = super::EffectExecutionMode::GuestPromiseEventLoop;
            let entry_source = format!(
                r#"
import {{ adapted as registration }} from "./wrapper";
import {{ authenticate }} from "./helper";
export const selected = registration({{
  args: {{}},
  handler: async (ctx, _args, principal) => {{
    {helper_use}
    return principal;
  }},
}});
"#
            );
            modules.insert(
                ENTRY.to_string(),
                LoadedModule::new(summary(ENTRY, &entry_source), entry_source),
            );
            graph
                .metafile
                .inputs
                .get_mut(ENTRY)
                .unwrap()
                .imports
                .push(EsbuildImport {
                    path: HELPER.to_string(),
                    kind: "import-statement".to_string(),
                    original: Some("./helper".to_string()),
                    external: false,
                });
            let output = compile_export(
                &graph,
                Path::new("/fixture-cache"),
                &mut PhaseMeasurements::default(),
                Instant::now(),
                &modules,
                GeneratedSourceMode::Inline,
            )
            .unwrap()
            .output;
            let diagnostics = output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>();
            assert!(!output.eligible, "{name}: {diagnostics:#?}");
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "unsupported-convex-effect"),
                "{name}: {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn guest_native_lowers_only_effect_free_promise_all_value_maps() {
        let output = compile(
            "async (ctx, args, principal) => { const mode = new Map(); mode.set(\"selected\", true); const inputs = [3, 1, 2]; const values = await Promise.all(inputs.map((value) => { if (value < 0) throw \"negative\"; return value + 1; })); return { principal, values }; }",
            object_material("query"),
        );
        assert!(output.eligible);
        let source = generated_source(&output);
        assert!(!source.contains("Promise.all"), "{source}");
        assert!(
            source.contains("inputs.map((value) => {")
                && source.contains("throw \"negative\"")
                && source.contains("return value + 1"),
            "{source}"
        );
    }

    #[test]
    fn guest_native_value_map_requires_an_authorized_array_iterator() {
        let output = compile(
            "async (ctx, args, principal) => { const mode = new Map(); mode.set(\"selected\", true); const custom = { map: (callback) => [callback(1)] }; const values = await Promise.all(custom.map((value) => value + 1)); return { principal, values }; }",
            object_material("query"),
        );
        assert!(!output.eligible);
        assert!(
            output.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "unsupported-direct-promise-all"
                    && diagnostic.message.contains("iterator")
            }),
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn guest_native_rejects_effectful_promise_all_value_maps() {
        let output = compile(
            "async (ctx, args, principal) => { const mode = new Map(); mode.set(\"selected\", true); const inputs = [3, 1, 2]; const values = await Promise.all(inputs.map((value) => mode.get(String(value)))); return { principal, values }; }",
            object_material("query"),
        );
        assert!(!output.eligible);
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unsupported-direct-promise-all")
        );
    }

    #[test]
    fn descriptor_bytes_and_request_object_must_match() {
        let root = temporary_directory("convex-wasm-registration-adapter-material");
        let descriptor = object_material("query").descriptor;
        let bytes = serde_json::to_vec(&descriptor).unwrap();
        fs::write(root.0.join("descriptor.json"), &bytes).unwrap();
        let mut mismatched = descriptor;
        mismatched.adapters[0].id = "changed".to_string();
        let material = RegistrationAdapterMaterial {
            kind: "convex-wasm-registration-adapter-material".to_string(),
            descriptor: mismatched,
            source: RegistrationAdapterSourceMaterial {
                path: "descriptor.json".to_string(),
                sha256: hash_bytes(&bytes),
                bytes: bytes.len(),
            },
        };
        let error = validate_registration_adapter_material(&root.0, &material).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("request descriptor disagrees with the authenticated descriptor bytes"),
            "{error:#}"
        );
    }

    #[test]
    fn value_registration_adapter_must_bind_one_callback_parameter() {
        let root = temporary_directory("convex-wasm-registration-adapter-value-result");
        let mut descriptor = object_material("query").descriptor;
        descriptor.adapters[0].authentication.result_kind = "value".to_string();
        descriptor.adapters[0]
            .authentication
            .result_parameters
            .clear();
        let bytes = serde_json::to_vec(&descriptor).unwrap();
        fs::write(root.0.join("descriptor.json"), &bytes).unwrap();
        let material = RegistrationAdapterMaterial {
            kind: "convex-wasm-registration-adapter-material".to_string(),
            descriptor,
            source: RegistrationAdapterSourceMaterial {
                path: "descriptor.json".to_string(),
                sha256: hash_bytes(&bytes),
                bytes: bytes.len(),
            },
        };

        let error = validate_registration_adapter_material(&root.0, &material).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("value result must bind one whole callback parameter"),
            "{error:#}"
        );
    }

    #[test]
    fn exact_source_helper_call_emits_only_the_generic_host_secret_contract() {
        let output = compile_with_args(
            "async (ctx, args, principal) => { requireWorkerSecret(args.workerSecret); return principal; }",
            "{ workerSecret: v.string() }",
            source_operation_material(),
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible source-operation fixture returned analysis output");
        };
        let operation = compiled
            .operations
            .iter()
            .find(|operation| operation.kind == "hostSecretVerify")
            .unwrap();
        assert_eq!(operation.contract_version, Some(1));
        assert_eq!(operation.selector.as_deref(), Some("WORKER_SECRET"));
        let source = generated_source(&output);
        assert!(source.contains("__convexVerifyHostSecret"), "{source}");
        assert!(source.contains("WORKER_SECRET is not set"), "{source}");
        assert!(source.contains("Unauthorized"), "{source}");
        assert!(!source.contains("process.env"), "{source}");
        assert!(!source.contains("super-secret-fixture"), "{source}");
    }

    #[test]
    fn applied_source_operation_semantics_invalidate_source_identities() {
        let callback = "async (ctx, args, principal) => { requireWorkerSecret(args.workerSecret); return principal; }";
        let args = "{ workerSecret: v.string() }";
        let baseline_material = source_operation_material();
        let baseline = compile_with_args(callback, args, baseline_material.clone());
        assert!(baseline.eligible);

        let mut changed_material = baseline_material.clone();
        changed_material.descriptor.source_operations[0]
            .semantic
            .mismatch_error = "Access denied".to_string();
        let changed = compile_with_args(callback, args, changed_material);
        assert!(changed.eligible);
        assert_ne!(baseline.export_fingerprint, changed.export_fingerprint);
        assert_ne!(
            baseline.source_graph_fingerprint,
            changed.source_graph_fingerprint
        );
        assert_ne!(generated_source(&baseline), generated_source(&changed));

        let operation_stable_key = |output: &super::CompilerOutput| {
            let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
                panic!("source-operation fixture returned analysis output");
            };
            compiled
                .operations
                .iter()
                .find(|operation| operation.kind == "hostSecretVerify")
                .unwrap()
                .stable_key
                .clone()
        };
        assert_eq!(
            operation_stable_key(&baseline),
            operation_stable_key(&changed),
            "guest developer-error text must not change the stable host operation contract"
        );

        let mut unused_material = baseline_material;
        let mut unused = unused_material.descriptor.source_operations[0].clone();
        unused.id = "unusedSourceOperation".to_string();
        unused.helper.module_path = "fixtures/unusedSourceHelper.ts".to_string();
        unused.helper.export_name = "unusedSourceHelper".to_string();
        unused.helper.source_sha256 = "2".repeat(64);
        unused_material.descriptor.source_operations.push(unused);
        unused_material
            .descriptor
            .source_operations
            .sort_by(|left, right| left.id.cmp(&right.id));
        let with_unused = compile_with_args(callback, args, unused_material);
        assert_eq!(baseline.export_fingerprint, with_unused.export_fingerprint);
        assert_eq!(
            baseline.source_graph_fingerprint,
            with_unused.source_graph_fingerprint
        );
        assert_eq!(generated_source(&baseline), generated_source(&with_unused));
    }

    #[test]
    fn source_helper_drift_and_non_direct_flow_fail_closed() {
        let callback = "async (ctx, args, principal) => { requireWorkerSecret(args.workerSecret); return principal; }";
        let (graph, mut modules) = fixture_with_args(
            callback,
            "{ workerSecret: v.string() }",
            source_operation_material(),
        );
        let drifted = SOURCE_HELPER_SOURCE.replace("Unauthorized", "Denied");
        modules.insert(
            SOURCE_HELPER.to_string(),
            LoadedModule::new(summary(SOURCE_HELPER, &drifted), drifted),
        );
        let output = compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output;
        assert!(!output.eligible);
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "source-operation-helper-source-mismatch" })
        );

        let escaped = compile_with_args(
            "async (ctx, args, principal) => { const verify = requireWorkerSecret; verify(args.workerSecret); return principal; }",
            "{ workerSecret: v.string() }",
            source_operation_material(),
        );
        assert!(!escaped.eligible);
        assert!(
            escaped
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "source-operation-nondirect-use")
        );
    }

    #[test]
    fn alias_import_authenticates_and_projects_object_results_even_when_callback_omits_them() {
        let output = compile("async (ctx, args) => args", object_material("query"));
        assert!(output.eligible, "{:#?}", output.diagnostics[0].message);
        let provenance = output.applied_registration_adapter.as_ref().unwrap();
        assert_eq!(provenance.adapter_id, "adapted");
        assert_eq!(provenance.registration_kind, "query");
        assert_eq!(provenance.wrapper.module_path, WRAPPER);
        assert_eq!(provenance.wrapper.export_name, "adapted");
        assert_eq!(provenance.authentication.helper.module_path, HELPER);
        assert_eq!(provenance.authentication.helper.export_name, "authenticate");
        assert_eq!(provenance.authentication.result_kind, "object");
        assert_eq!(provenance.authentication.result_parameters.len(), 2);
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible adapter returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| operation.kind.as_str())
                .collect::<Vec<_>>(),
            vec![
                "authenticationGetUserIdentity",
                "databaseNormalizeId",
                "databaseGet",
            ]
        );
        assert!(compiled.direct_async_batches.is_empty());
        let fields = compiled
            .document_properties
            .iter()
            .map(|property| property.property.as_str())
            .collect::<BTreeSet<_>>();
        assert!(fields.contains("subject"));
        assert!(fields.contains("principal"));
        assert!(fields.contains("role"));
        assert_eq!(compiled.target.registration_kind, "query");
        assert!(
            compiled
                .reachable_units
                .iter()
                .any(|unit| unit.module == HELPER && unit.name == "authenticate")
        );
        assert!(compiled.resolved_imports.iter().any(|import| {
            import.importer == ENTRY
                && import.imported_name == "adapted"
                && import.resolved == WRAPPER
        }));
        let generated = generated_source(&output);
        assert!(generated.contains("authenticate(__convexAdapterContext)"));
        assert!(generated.contains("__convexAdapterAuthentication.principal"));
        assert!(generated.contains("__convexAdapterAuthentication.privileged"));
    }

    #[test]
    fn authenticating_helper_adapter_keeps_original_provenance_after_predicate_reparse() {
        let helper_source = r#"
function hasDb(context) {
  return "db" in context;
}
export async function authenticate(context) {
  if (hasDb(context)) {
    const identity = await context.auth.getUserIdentity();
    if (identity === null) throw new Error("Unauthorized");
    const normalizedId = context.db.normalizeId("accounts", identity.subject);
    if (normalizedId === null) throw new Error("Unauthorized");
    const account = await context.db.get("accounts", normalizedId);
    if (account === null) throw new Error("Unauthorized");
    return { principal: account.principal, privileged: account.role === "admin" };
  }
  return await context.runQuery(actionOnly.missing, {});
}
"#;
        let helper_summary = summary(HELPER, helper_source);
        let mut registration_adapter = object_material("query");
        registration_adapter.descriptor.adapters[0]
            .authentication
            .helper
            .source_sha256 = exported_unit_hash(&helper_summary, "authenticate");
        let (graph, mut modules) = fixture(
            "async (ctx, args, principal) => ({ args, principal })",
            registration_adapter,
        );
        modules.insert(
            HELPER.to_string(),
            LoadedModule::new(helper_summary, helper_source.to_string()),
        );
        let output = compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output;
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            output
                .applied_registration_adapter
                .as_ref()
                .map(|adapter| adapter.adapter_id.as_str()),
            Some("adapted")
        );
        let generated = generated_source(&output);
        for removed in ["hasDb", "runQuery", "actionOnly"] {
            assert!(!generated.contains(removed), "{removed}: {generated}");
        }
        assert!(generated.contains("context.db.normalizeId"), "{generated}");
        assert!(generated.contains("context.db.get"), "{generated}");
    }

    #[test]
    fn value_projection_and_arrow_callback_forms_preserve_awaited_callback_completion() {
        let value_material = material(adapter(
            "mutation",
            "value",
            vec![RegistrationAdapterResultParameter {
                callback_parameter_index: 2,
                property: None,
            }],
        ));
        for callback in [
            "async (ctx, args, principal) => { return principal; }",
            "async (ctx, args, principal) => principal",
            "(ctx, args, principal) => principal",
        ] {
            let output = compile(callback, value_material.clone());
            assert!(
                output.eligible,
                "callback {callback}: {}",
                output
                    .diagnostics
                    .first()
                    .map(|diagnostic| diagnostic.message.as_str())
                    .unwrap_or("no diagnostic")
            );
            let generated = generated_source(&output);
            assert!(
                generated.contains("__convexAdapterArguments, __convexAdapterAuthentication"),
                "{generated}"
            );
            assert!(!generated.contains("__convexAdapterAuthentication.principal"));

            let raw_handler = registration_adapter_handler_source(
                callback,
                &applied_adapter(value_material.descriptor.adapters[0].clone()),
            )
            .unwrap();
            assert!(raw_handler.starts_with("async ("), "{raw_handler}");
            assert!(
                raw_handler.contains("= await authenticate(__convexAdapterContext)"),
                "{raw_handler}"
            );
            assert!(raw_handler.contains("return await ("), "{raw_handler}");
        }
    }

    #[test]
    fn applied_adapter_identity_ignores_unrelated_descriptor_material() {
        let base = object_material("query");
        let mut changed = base.clone();
        changed.source.sha256 = "2".repeat(64);
        let mut unused = changed.descriptor.adapters[0].clone();
        unused.id = "unused".to_string();
        unused.wrapper.module_path = "fixtures/z-unused-wrapper.ts".to_string();
        unused.wrapper.export_name = "unused".to_string();
        changed.descriptor.adapters.push(unused);
        let first = compile("async (ctx, args, principal) => principal", base);
        let second = compile("async (ctx, args, principal) => principal", changed);
        assert_eq!(first.export_fingerprint, second.export_fingerprint);
        assert_eq!(
            first.source_graph_fingerprint,
            second.source_graph_fingerprint
        );
    }

    #[test]
    fn wrapper_source_drift_and_function_expression_callback_are_diagnostic_fallbacks() {
        let mut drifted = object_material("query");
        drifted.descriptor.adapters[0].wrapper.source_sha256 = "0".repeat(64);
        let drift = compile("async (ctx, args, principal) => principal", drifted);
        assert!(!drift.eligible);
        assert_eq!(drift.routing.decision, "v8Fallback");
        assert_eq!(
            drift.diagnostics[0].code,
            "registration-adapter-wrapper-source-mismatch"
        );

        let mut helper_drifted = object_material("query");
        helper_drifted.descriptor.adapters[0]
            .authentication
            .helper
            .source_sha256 = "0".repeat(64);
        let helper_drift = compile("async (ctx, args, principal) => principal", helper_drifted);
        assert!(!helper_drift.eligible);
        assert_eq!(helper_drift.routing.decision, "v8Fallback");
        assert_eq!(
            helper_drift.diagnostics[0].code,
            "registration-adapter-helper-source-mismatch"
        );

        let function_expression = compile(
            "async function (ctx, args, principal) { return principal; }",
            object_material("query"),
        );
        assert!(!function_expression.eligible);
        assert_eq!(function_expression.routing.decision, "v8Fallback");
        assert!(function_expression.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "registration-adapter-handler-shape-mismatch"
        }));
    }

    #[test]
    fn named_reexport_retains_adapter_kind_for_deterministic_fallback_selection() {
        let root = temporary_directory("convex-wasm-registration-adapter-reexport");
        for (module, source) in [
            (
                "fixtures/index.ts",
                "export { selected } from \"./registration\";\n",
            ),
            (
                "fixtures/registration.ts",
                "import { adapted as registration } from \"./wrapper\";\nexport const selected = registration({ args: {}, handler: async (ctx, args) => args });\n",
            ),
            (WRAPPER, WRAPPER_SOURCE),
            (HELPER, HELPER_SOURCE),
        ] {
            let path = root.0.join(module);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        let metafile = EsbuildMetafile {
            inputs: BTreeMap::from([
                (
                    "fixtures/index.ts".to_string(),
                    EsbuildInput {
                        imports: vec![EsbuildImport {
                            path: "fixtures/registration.ts".to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./registration".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    "fixtures/registration.ts".to_string(),
                    EsbuildInput {
                        imports: vec![EsbuildImport {
                            path: WRAPPER.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./wrapper".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    WRAPPER.to_string(),
                    EsbuildInput {
                        imports: vec![EsbuildImport {
                            path: HELPER.to_string(),
                            kind: "import-statement".to_string(),
                            original: Some("./helper".to_string()),
                            external: false,
                        }],
                    },
                ),
                (
                    HELPER.to_string(),
                    EsbuildInput {
                        imports: Vec::new(),
                    },
                ),
            ]),
            outputs: BTreeMap::new(),
        };
        let mut modules = BTreeMap::new();
        let inventory = build_source_inventory(
            &root.0,
            &metafile,
            &["fixtures/index.ts".to_string()],
            &root.0.join("cache"),
            &mut modules,
            &mut PhaseMeasurements::default(),
            &object_material("query"),
            "fixtures",
        )
        .unwrap();
        assert!(inventory.diagnostics.is_empty());
        assert_eq!(inventory.functions.len(), 1);
        assert_eq!(inventory.functions[0].udf_kind, "query");
        assert!(!inventory.functions[0].direct);
        let first_graph_sha256 = serde_json::to_value(&inventory).unwrap()["graphSha256"]
            .as_str()
            .unwrap()
            .to_string();
        let mut changed_material = object_material("query");
        changed_material.source.sha256 = "3".repeat(64);
        let changed_inventory = build_source_inventory(
            &root.0,
            &metafile,
            &["fixtures/index.ts".to_string()],
            &root.0.join("cache"),
            &mut modules,
            &mut PhaseMeasurements::default(),
            &changed_material,
            "fixtures",
        )
        .unwrap();
        let changed_graph_sha256 = serde_json::to_value(&changed_inventory).unwrap()["graphSha256"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(first_graph_sha256, changed_graph_sha256);
    }
}

#[cfg(test)]
mod ordinary_syntax_tests {
    use super::{
        CompilerModeOutput, EsbuildImport, EsbuildInput, EsbuildMetafile, GeneratedSourceMode,
        GraphInput, LoadedModule, PhaseMeasurements, TEST_GENERATED_SERVER_MODULE,
        TEST_GENERATED_SERVER_SOURCE, Toolchain, admission::compile_admitted_static_hermes_globals,
        callable_control::CallableControlEdgeKind, callable_control::CallableControlPointKind,
        compile_export, contains_node_type, count_node_type, hash_bytes, summarize_module,
        test_registration_adapter_material, transform_typescript, with_test_registration_imports,
    };
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    use serde_json::Value;
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::Path,
        process::Command,
        time::Instant,
    };

    const MODULE_KEY: &str = "convex/fixture.ts";

    fn summary(source: &str) -> super::ModuleSummary {
        summary_at(MODULE_KEY, source)
    }

    fn summary_at(module_key: &str, source: &str) -> super::ModuleSummary {
        summarize_module(
            module_key,
            Path::new(module_key),
            source,
            &hash_bytes(source.as_bytes()),
            "fixture-cache-key",
            "fixture-pipeline",
            "fixture-context-policy",
            &mut PhaseMeasurements::default(),
        )
        .unwrap()
    }

    fn compile(source: &str, export_name: &str) -> super::CompilerOutput {
        compile_entry(&with_test_registration_imports(source), export_name, true)
    }

    fn compile_entry(
        source: &str,
        export_name: &str,
        has_generated_server_import: bool,
    ) -> super::CompilerOutput {
        compile_entry_in_effect_mode(
            source,
            export_name,
            has_generated_server_import,
            super::EffectExecutionMode::BlockingFiber,
        )
    }

    fn compile_entry_in_effect_mode(
        source: &str,
        export_name: &str,
        has_generated_server_import: bool,
        effect_execution_mode: super::EffectExecutionMode,
    ) -> super::CompilerOutput {
        compile_entry_with_toolchain(
            source,
            export_name,
            has_generated_server_import,
            effect_execution_mode,
            "fixture",
        )
    }

    fn compile_entry_with_toolchain(
        source: &str,
        export_name: &str,
        has_generated_server_import: bool,
        effect_execution_mode: super::EffectExecutionMode,
        convex_toolchain: &str,
    ) -> super::CompilerOutput {
        let modules = BTreeMap::from([
            (
                MODULE_KEY.to_string(),
                LoadedModule::new(summary(source), source.to_string()),
            ),
            (
                TEST_GENERATED_SERVER_MODULE.to_string(),
                LoadedModule::new(
                    summary_at(TEST_GENERATED_SERVER_MODULE, TEST_GENERATED_SERVER_SOURCE),
                    TEST_GENERATED_SERVER_SOURCE.to_string(),
                ),
            ),
        ]);
        let graph = GraphInput {
            kind: "convex-wasm-esbuild-graph".to_string(),
            repo_root: Path::new("/fixture").to_path_buf(),
            functions_root: "convex".to_string(),
            entry_path: MODULE_KEY.to_string(),
            export_name: export_name.to_string(),
            toolchain: Toolchain {
                esbuild: "fixture".to_string(),
                convex: convex_toolchain.to_string(),
            },
            dependency_adapter: super::test_dependency_adapter_material(),
            registration_adapter: test_registration_adapter_material(),
            assumptions: None,
            effect_execution_mode,
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([
                    (
                        MODULE_KEY.to_string(),
                        EsbuildInput {
                            imports: if has_generated_server_import {
                                vec![EsbuildImport {
                                    path: TEST_GENERATED_SERVER_MODULE.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some("./_generated/server".to_string()),
                                    external: false,
                                }]
                            } else {
                                Vec::new()
                            },
                        },
                    ),
                    (
                        TEST_GENERATED_SERVER_MODULE.to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                ]),
                outputs: BTreeMap::new(),
            },
            phase_timings_us: BTreeMap::new(),
        };
        compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output
    }

    #[test]
    fn source_graph_identity_binds_the_convex_toolchain() {
        let source = with_test_registration_imports(
            "export const selected = query({ args: {}, handler: async () => null });",
        );
        let baseline = compile_entry_with_toolchain(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::BlockingFiber,
            "convex-a",
        );
        let changed = compile_entry_with_toolchain(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::BlockingFiber,
            "convex-b",
        );

        assert_ne!(
            baseline.source_graph_fingerprint,
            changed.source_graph_fingerprint
        );
        assert_ne!(baseline.export_fingerprint, changed.export_fingerprint);
    }

    fn compile_with_import(
        entry_source: &str,
        helper_source: &str,
        export_name: &str,
    ) -> super::CompilerOutput {
        compile_with_import_result(entry_source, helper_source, export_name).unwrap()
    }

    fn compile_with_import_result(
        entry_source: &str,
        helper_source: &str,
        export_name: &str,
    ) -> anyhow::Result<super::CompilerOutput> {
        compile_with_import_result_in_effect_mode(
            entry_source,
            helper_source,
            export_name,
            super::EffectExecutionMode::BlockingFiber,
        )
    }

    fn compile_with_import_in_effect_mode(
        entry_source: &str,
        helper_source: &str,
        export_name: &str,
        effect_execution_mode: super::EffectExecutionMode,
    ) -> super::CompilerOutput {
        compile_with_import_result_in_effect_mode(
            entry_source,
            helper_source,
            export_name,
            effect_execution_mode,
        )
        .unwrap()
    }

    fn compile_with_import_result_in_effect_mode(
        entry_source: &str,
        helper_source: &str,
        export_name: &str,
        effect_execution_mode: super::EffectExecutionMode,
    ) -> anyhow::Result<super::CompilerOutput> {
        const HELPER_KEY: &str = "convex/helper.ts";
        let entry_source = with_test_registration_imports(entry_source);
        let modules = BTreeMap::from([
            (
                MODULE_KEY.to_string(),
                LoadedModule::new(summary_at(MODULE_KEY, &entry_source), entry_source),
            ),
            (
                HELPER_KEY.to_string(),
                LoadedModule::new(
                    summary_at(HELPER_KEY, helper_source),
                    helper_source.to_string(),
                ),
            ),
            (
                TEST_GENERATED_SERVER_MODULE.to_string(),
                LoadedModule::new(
                    summary_at(TEST_GENERATED_SERVER_MODULE, TEST_GENERATED_SERVER_SOURCE),
                    TEST_GENERATED_SERVER_SOURCE.to_string(),
                ),
            ),
        ]);
        let graph = GraphInput {
            kind: "convex-wasm-esbuild-graph".to_string(),
            repo_root: Path::new("/fixture").to_path_buf(),
            functions_root: "convex".to_string(),
            entry_path: MODULE_KEY.to_string(),
            export_name: export_name.to_string(),
            toolchain: Toolchain {
                esbuild: "fixture".to_string(),
                convex: "fixture".to_string(),
            },
            dependency_adapter: super::test_dependency_adapter_material(),
            registration_adapter: test_registration_adapter_material(),
            assumptions: None,
            effect_execution_mode,
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([
                    (
                        MODULE_KEY.to_string(),
                        EsbuildInput {
                            imports: vec![
                                EsbuildImport {
                                    path: TEST_GENERATED_SERVER_MODULE.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some("./_generated/server".to_string()),
                                    external: false,
                                },
                                EsbuildImport {
                                    path: HELPER_KEY.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some("./helper".to_string()),
                                    external: false,
                                },
                            ],
                        },
                    ),
                    (
                        TEST_GENERATED_SERVER_MODULE.to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                    (
                        HELPER_KEY.to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                ]),
                outputs: BTreeMap::new(),
            },
            phase_timings_us: BTreeMap::new(),
        };
        compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .map(|compiled| compiled.output)
    }

    fn parse_javascript(source: &str) -> Value {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
        assert!(parsed.diagnostics.is_empty(), "{:#?}", parsed.diagnostics);
        serde_json::from_str(&parsed.program.to_estree_json(true, false)).unwrap()
    }

    fn generated_source(output: &super::CompilerOutput) -> &str {
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        compiled
            .generated_javascript_artifact
            .as_ref()
            .and_then(|artifact| artifact.source.as_deref())
            .expect("eligible fixture has no generated source")
    }

    fn assert_guest_effect_is_rejected_without_lowering(output: &super::CompilerOutput) {
        assert!(
            !output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unsupported-convex-effect"),
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        if let CompilerModeOutput::Compile(compiled) = &output.mode_output
            && let Some(generated) = compiled
                .generated_javascript_artifact
                .as_ref()
                .and_then(|artifact| artifact.source.as_deref())
        {
            assert!(
                !generated.contains("__convexStartAsyncOperation("),
                "rejected guest effect was lowered:\n{generated}"
            );
        }
    }

    fn evaluate_generated_handler(
        output: &super::CompilerOutput,
        context: &str,
        arguments: &str,
    ) -> Value {
        let source = generated_source(output);
        let javascript = transform_typescript(source, Path::new("ordinary-syntax-fixture.ts"))
            .expect("generated fixture TypeScript transform failed");
        let script = format!(
            "{javascript}\nprocess.stdout.write(JSON.stringify(__convexWasmHandler({context}, {arguments})));"
        );
        let result = Command::new("node")
            .args(["--input-type=module", "--eval", &script])
            .output()
            .expect("failed to execute generated fixture");
        assert!(
            result.status.success(),
            "node rejected generated fixture: {}\n{javascript}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice(&result.stdout).expect("generated fixture returned invalid JSON")
    }

    #[test]
    fn capability_predicates_prune_fallbacks_for_direct_local_alias_and_imported_guards() {
        let cases = [
            compile(
                r#"
function hasDb(ctx: unknown): ctx is object { return "db" in (ctx as object); }
const predicate = hasDb satisfies typeof hasDb;
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    if ((predicate as typeof predicate)(ctx as typeof ctx)) {
      return await ctx.db.get("documents", args.id);
    }
    return await ctx.runQuery(actionOnly.missing, args);
  },
});
"#,
                "selected",
            ),
            compile(
                r#"
export const selected = query({
  args: {},
  handler: (ctx, args) => "db" in (ctx as object)
    ? ctx.db.get("documents", args.id)
    : ctx.runQuery(actionOnly.missing, args),
});
"#,
                "selected",
            ),
            compile_with_import(
                r#"
import { hasDb as importedHasDb } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    if (importedHasDb(ctx)) {
      return await ctx.db.get("documents", args.id);
    } else {
      return await ctx.runQuery(actionOnly.missing, args);
    }
  },
});
"#,
                r#"export function hasDb(ctx: unknown) { return "db" in (ctx as object); }"#,
                "selected",
            ),
        ];

        for output in cases {
            assert!(
                output.eligible,
                "{:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
                panic!("eligible predicate fixture returned analysis output");
            };
            assert_eq!(compiled.operations.len(), 1);
            assert_eq!(compiled.operations[0].kind, "databaseGet");
            assert_eq!(compiled.operations[0].table.as_deref(), Some("documents"));
            let generated = generated_source(&output);
            for removed in [
                "hasDb",
                "predicate",
                "importedHasDb",
                "runQuery",
                "actionOnly",
            ] {
                assert!(!generated.contains(removed), "{removed}: {generated}");
            }
            assert_eq!(
                evaluate_generated_handler(
                    &output,
                    r#"{ db: { get: (table, id) => ({ table, id, selected: true }) } }"#,
                    r#"{ id: "doc-1" }"#,
                ),
                serde_json::json!({
                    "table": "documents",
                    "id": "doc-1",
                    "selected": true,
                })
            );
        }
    }

    #[test]
    fn capability_predicates_fail_closed_for_inexact_calls_and_bindings() {
        let fixtures = [
            r#"
function hasDb(ctx) { return "db" in ctx; }
let predicate = hasDb;
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if (predicate(ctx)) return await ctx.db.get("documents", args.id);
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
            r#"
function hasDb(ctx) { return "db" in ctx; }
var predicate = hasDb;
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if (predicate(ctx)) return await ctx.db.get("documents", args.id);
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
            r#"
const first = second;
const second = first;
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if (first(ctx)) return await ctx.db.get("documents", args.id);
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
            r#"
function hasDb(ctx) { return "db" in ctx; }
const predicate = hasDb;
predicate = hasDb;
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if (predicate(ctx)) return await ctx.db.get("documents", args.id);
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
            r#"
function hasDb(ctx) { return "db" in ctx; }
export const selected = query({ args: {}, handler: async (ctx, args) => {
  const hasDb = (_value) => true;
  if (hasDb(ctx)) return await ctx.db.get("documents", args.id);
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
            r#"
function hasDb(ctx) { return "db" in ctx; }
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if (hasDb(...[ctx])) return await ctx.db.get("documents", args.id);
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
            r#"
function hasDb(ctx) { return "db" in ctx; }
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if (hasDb(await ctx)) return await ctx.db.get("documents", args.id);
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
            r#"
function hasDb(ctx) { return "db" in ctx; }
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if (hasDb(ctx) && args.enabled) return await ctx.db.get("documents", args.id);
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
        ];
        for source in fixtures {
            let output = compile(source, "selected");
            assert!(!output.eligible, "{source}");
            assert!(!output.diagnostics.is_empty(), "{source}");
        }
    }

    #[test]
    fn capability_predicates_emit_varied_real_continuation_shapes_without_fallbacks() {
        let nested_completion = compile(
            r#"
function hasDb(ctx) { return "db" in ctx; }
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if (hasDb(ctx)) {
    const normalizedId = ctx.db.normalizeId("documents", args.id);
    if (normalizedId === null) return null;
    return await ctx.db.get("documents", normalizedId);
  }
  return await ctx.runQuery(actionOnly.missing, args);
} });
"#,
            "selected",
        );
        assert!(
            nested_completion.eligible,
            "{:#?}",
            nested_completion
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &nested_completion.mode_output else {
            panic!("nested predicate fixture returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| operation.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["databaseNormalizeId", "databaseGet"]
        );
        let generated = generated_source(&nested_completion);
        assert!(generated.contains("ctx.db.normalizeId"), "{generated}");
        assert!(generated.contains("ctx.db.get"), "{generated}");
        assert!(!generated.contains("hasDb"), "{generated}");
        assert!(!generated.contains("runQuery"), "{generated}");

        for source in [
            r#"
async function runFallback(callback) { return await callback(); }
export const selected = query({ args: {}, handler: async (ctx, args) => {
  if ("db" in ctx) return await ctx.db.get("documents", args.id);
  const error = await runFallback(async () =>
    await ctx.runQuery(actionOnly.missing, args));
  return error;
} });
"#,
            r#"
async function runFallback(callback) { return await callback(); }
export const selected = query({ args: {}, handler: async (ctx, args) => {
  const document = "db" in ctx
    ? await ctx.db.get("documents", args.id)
    : await runFallback(async () =>
        await ctx.runQuery(actionOnly.missing, args));
  return document;
} });
"#,
        ] {
            let output = compile(source, "selected");
            assert!(
                output.eligible,
                "{:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
                panic!("continuation predicate fixture returned analysis output");
            };
            assert_eq!(compiled.operations.len(), 1);
            assert_eq!(compiled.operations[0].kind, "databaseGet");
            let generated = generated_source(&output);
            for removed in ["runFallback", "runQuery", "actionOnly"] {
                assert!(!generated.contains(removed), "{removed}: {generated}");
            }
            assert!(generated.contains("ctx.db.get"), "{generated}");
        }
    }

    #[test]
    fn rejects_local_declaration_named_like_a_registration_builder() {
        let source = r#"
const mutation = (definition) => definition;
export const selected = mutation({
  args: {},
  handler: async () => null,
});
"#;
        let output = compile_entry(source, "selected", false);
        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-registration-builder"
                && diagnostic
                    .message
                    .contains("not an imported generated Convex server binding")
        }));
    }

    #[test]
    fn generated_server_aliases_use_canonical_registration_kinds() {
        let source = r#"
import { query as registerQuery, mutation as registerMutation } from "./_generated/server";
export const selectedQuery = registerQuery({
  args: {},
  handler: async () => null,
});
export const selectedMutation = registerMutation({
  args: {},
  handler: async () => null,
});
"#;
        for (export_name, expected_kind) in
            [("selectedQuery", "query"), ("selectedMutation", "mutation")]
        {
            let output = compile_entry(source, export_name, true);
            assert!(
                output.eligible,
                "{:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert_eq!(output.source.udf_kind, expected_kind);
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("eligible generated-server alias returned analysis output");
            };
            assert_eq!(compiled.target.registration_kind, expected_kind);
        }
    }

    #[test]
    fn unmatched_custom_registration_builder_returns_an_error_instead_of_panicking() {
        let result = compile_with_import_result(
            r#"
import { registerQuery } from "./helper";
export const selected = registerQuery({
  args: {},
  handler: async () => null,
});
"#,
            "export const registerQuery = (definition) => definition;\n",
            "selected",
        );
        let Err(error) = result else {
            panic!("unmatched custom registration builder compiled successfully");
        };
        assert!(
            error
                .to_string()
                .contains("registration builder registerQuery has unsupported kind registerQuery after binding authentication"),
            "{error:#}"
        );
    }

    #[test]
    fn imported_function_aliases_preserve_target_and_shadowed_local_bindings() {
        let output = compile_with_import(
            r#"
import { addOne as importedAddOne } from "./helper";
function invokeShadowed(importedAddOne, value) {
  return importedAddOne(value);
}
export const selected = query({
  args: {},
  handler: (_ctx, args) => {
    const addOne = (value) => value + 2;
    return {
      imported: importedAddOne(args.value),
      local: addOne(args.value),
      shadowed: invokeShadowed((value) => value * 2, args.value),
    };
  },
});
"#,
            "export function addOne(value) { return value + 1; }\n",
            "selected",
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let generated = generated_source(&output);
        assert!(generated.contains("function addOne(value)"), "{generated}");
        assert!(
            generated.contains("const importedAddOne = addOne"),
            "{generated}"
        );
        assert!(
            generated.contains("importedAddOne(args.value)"),
            "{generated}"
        );
        assert!(generated.contains("addOne(args.value)"), "{generated}");
        assert!(generated.contains("importedAddOne(value)"), "{generated}");
        assert_eq!(
            evaluate_generated_handler(&output, "{}", r#"{ value: 3 }"#),
            serde_json::json!({ "imported": 4, "local": 5, "shadowed": 6 })
        );

        let collision = compile_with_import(
            r#"
import { addOne as importedAddOne } from "./helper";
function addOne(value) {
  return value + 2;
}
export const selected = query({
  args: {},
  handler: (_ctx, args) => ({
    imported: importedAddOne(args.value),
    local: addOne(args.value),
  }),
});
"#,
            "export function addOne(value) { return value + 1; }\n",
            "selected",
        );
        assert!(!collision.eligible);
        assert!(collision.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "flattened-runtime-binding-collision"
                && diagnostic.message.contains("addOne")
        }));
    }

    #[test]
    fn flattened_bindings_cannot_capture_cross_module_runtime_globals() {
        let imported_alias = compile_with_import(
            r#"
import { addOne as Math, maximum } from "./helper";
export const selected = query({
  args: {},
  handler: (_ctx, args) => Math(maximum(args.left, args.right)),
});
"#,
            r#"
export function addOne(value) { return value + 1; }
export function maximum(left, right) { return Math.max(left, right); }
"#,
            "selected",
        );
        assert!(!imported_alias.eligible);
        assert!(imported_alias.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "flattened-runtime-binding-collision"
                && diagnostic
                    .message
                    .contains("admitted runtime global Math in convex/helper.ts")
                && diagnostic.message.contains("import alias")
        }));

        let reachable_declaration = compile_with_import(
            r#"
import { Math as helperMath } from "./helper";
export const selected = query({
  args: {},
  handler: (_ctx, args) => ({
    native: Math.max(args.left, args.right),
    helper: helperMath(args.left),
  }),
});
"#,
            "export function Math(value) { return value + 1; }\n",
            "selected",
        );
        assert!(!reachable_declaration.eligible);
        assert!(
            reachable_declaration.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "flattened-runtime-binding-collision"
                    && diagnostic
                        .message
                        .contains("admitted runtime global Math in convex/fixture.ts")
                    && diagnostic.message.contains("convex/helper.ts#Math")
            }),
            "{:#?}",
            reachable_declaration
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn specializes_one_suspension_database_get_helpers_from_exact_callsites() {
        let helper = r#"
export async function requiredDocument(ctx, table, id) {
  const document = await ctx.db.get(table, id);
  if (!document) throw new Error(`Document not found in ${table}: ${id}`);
  return document;
}
"#;
        let output = compile_with_import(
            r#"
import { requiredDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => await requiredDocument(ctx, "documents", args.id),
});
"#,
            helper,
            "selected",
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible specialized helper returned analysis output");
        };
        assert_eq!(
            compiled.operations.len(),
            1,
            "{:#?}",
            compiled
                .operations
                .iter()
                .map(|operation| (
                    operation.id,
                    &operation.kind,
                    &operation.file,
                    operation.start,
                    operation.end,
                    &operation.table,
                    &operation.source,
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(compiled.operations[0].kind, "databaseGet");
        assert_eq!(compiled.operations[0].table.as_deref(), Some("documents"));
        assert_eq!(compiled.operations[0].source, "ctx.db.get(table, id)");
        let generated = generated_source(&output);
        assert!(generated.contains("ctx.db.get(table, id)"), "{generated}");
        assert!(
            generated.contains("Document not found in ${table}: ${id}"),
            "{generated}"
        );
        assert!(!generated.contains("await"), "{generated}");
        assert!(!generated.contains("async"), "{generated}");

        let dynamic_table = compile_with_import(
            r#"
import { requiredDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => await requiredDocument(ctx, args.table, args.id),
});
"#,
            helper,
            "selected",
        );
        assert!(!dynamic_table.eligible);
        assert!(dynamic_table.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-convex-effect"
                && diagnostic.message.contains("ctx.db.get")
        }));

        let transparent_arguments = compile_with_import(
            r#"
import { requiredDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) =>
    await requiredDocument((ctx as any), ("documents" satisfies string), args.id!),
});
"#,
            helper,
            "selected",
        );
        assert!(
            transparent_arguments.eligible,
            "{:#?}",
            transparent_arguments
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );

        for (arguments, expected_message) in [
            (
                r#"await ctx, "documents", args.id"#,
                "capability access ctx is not represented",
            ),
            (
                r#"ctx, await "documents", args.id"#,
                "capability access ctx.db.get is not represented",
            ),
            (
                r#"ctx, "documents", await args.id"#,
                "capability access ctx.db.get is not represented",
            ),
            (
                r#"ctx, "documents", (await args.id, args.id)"#,
                "capability access ctx.db.get is not represented",
            ),
            (
                r#"await ctx, await "documents", await args.id"#,
                "capability access ctx is not represented",
            ),
        ] {
            let entry = format!(
                r#"
import {{ requiredDocument }} from "./helper";
export const selected = query({{
  args: {{}},
  handler: async (ctx, args) => await requiredDocument({arguments}),
}});
"#
            );
            let awaited_argument = compile_with_import(&entry, helper, "selected");
            assert!(!awaited_argument.eligible, "{arguments}");
            assert!(
                awaited_argument.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-convex-effect"
                        && diagnostic.message.contains(expected_message)
                }),
                "{arguments}: {:#?}",
                awaited_argument
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn sequential_database_get_helper_aliases_remain_exact_and_fail_closed() {
        let helper = r#"
export async function requiredDocument(ctx, table, id) {
  const document = await ctx.db.get(table, id);
  if (!document) throw new Error(`Document not found in ${table}: ${id}`);
  return document;
}
"#;
        let aliased = compile_with_import(
            r#"
import { requiredDocument as load } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const first = await load(ctx, "firstDocuments", args.firstId);
    const second = await load(ctx, "secondDocuments", args.secondId);
    return { first: first.label, second: second.role };
  },
});
"#,
            helper,
            "selected",
        );
        assert!(
            aliased.eligible,
            "{:#?}",
            aliased
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let sequential_plan = aliased
            .callable_control_plans
            .iter()
            .find(|plan| plan.effects.len() == 2 && plan.control.await_count >= 2)
            .expect("two-call helper sequence has no shared callable control plan");
        assert!(sequential_plan.current_batch_leaf().is_none());
        let CompilerModeOutput::Compile(compiled) = &aliased.mode_output else {
            panic!("eligible aliased helper returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| (operation.kind.as_str(), operation.table.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("databaseGet", Some("firstDocuments")),
                ("databaseGet", Some("secondDocuments")),
            ]
        );
        assert_eq!(
            compiled
                .document_properties
                .iter()
                .map(|property| {
                    (
                        property.table.as_str(),
                        property.property.as_str(),
                        property.reason.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                ("firstDocuments", "label", "opaque-property-read"),
                ("secondDocuments", "role", "opaque-property-read"),
            ]
        );
        assert_eq!(
            evaluate_generated_handler(
                &aliased,
                r#"{
                  db: {
                    get: (table, id) => table === "firstDocuments"
                      ? { label: `first:${id}` }
                      : { role: `second:${id}` },
                  },
                }"#,
                r#"{ firstId: "one", secondId: "two" }"#,
            ),
            serde_json::json!({ "first": "first:one", "second": "second:two" })
        );

        let same_table = compile_with_import(
            r#"
import { requiredDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const first = await requiredDocument(ctx, "documents", args.firstId);
    const second = await requiredDocument(ctx, "documents", args.secondId);
    return { first, second };
  },
});
"#,
            helper,
            "selected",
        );
        assert!(
            same_table.eligible,
            "{:#?}",
            same_table
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &same_table.mode_output else {
            panic!("eligible repeated-table helper returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| (operation.kind.as_str(), operation.table.as_deref()))
                .collect::<Vec<_>>(),
            vec![("databaseGet", Some("documents"))]
        );
        let generated = generated_source(&same_table);
        assert_eq!(
            generated
                .matches("requiredDocument(ctx, \"documents\"")
                .count(),
            2,
            "{generated}"
        );
        assert_eq!(
            evaluate_generated_handler(
                &same_table,
                r#"{ db: { get: (_table, id) => ({ _id: id }) } }"#,
                r#"{ firstId: "first", secondId: "second" }"#,
            ),
            serde_json::json!({
                "first": { "_id": "first" },
                "second": { "_id": "second" },
            })
        );

        for entry in [
            r#"
import { requiredDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const load = requiredDocument;
    return await load(ctx, "documents", args.id);
  },
});
"#,
            r#"
import { requiredDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const context = ctx;
    return await requiredDocument(context, "documents", args.id);
  },
});
"#,
            r#"
import { requiredDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const pending = requiredDocument(ctx, "documents", args.id);
    return pending;
  },
});
"#,
        ] {
            let output = compile_with_import(entry, helper, "selected");
            assert!(!output.eligible, "{entry}");
            assert!(output.diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.code.as_str(),
                    "capability-helper-binding-write"
                        | "indirect-capability-callsite"
                        | "mixed-capability-callsite"
                        | "unsupported-convex-effect"
                )
            }));
        }

        let multiple_awaits = compile_with_import(
            r#"
import { requiredDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => await requiredDocument(ctx, "documents", args.id),
});
"#,
            r#"
export async function requiredDocument(ctx, table, id) {
  const first = await ctx.db.get(table, id);
  const second = await ctx.db.get(table, id);
  return { first, second };
}
"#,
            "selected",
        );
        assert!(
            multiple_awaits.eligible,
            "{:#?}",
            multiple_awaits
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &multiple_awaits.mode_output else {
            panic!("eligible multiple-effect helper returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| (operation.kind.as_str(), operation.table.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("databaseGet", Some("documents")),
                ("databaseGet", Some("documents")),
            ]
        );
        assert_eq!(
            evaluate_generated_handler(
                &multiple_awaits,
                r#"(() => {
                  let sequence = 0;
                  return {
                    db: {
                      get: (table, id) => ({ table, id, sequence: ++sequence }),
                    },
                  };
                })()"#,
                r#"{ id: "doc" }"#,
            ),
            serde_json::json!({
                "first": { "table": "documents", "id": "doc", "sequence": 1 },
                "second": { "table": "documents", "id": "doc", "sequence": 2 },
            })
        );
    }

    #[test]
    fn guest_sequential_effects_require_closed_exact_helper_paths() {
        let helper = r#"
export function loadDocument(ctx, id) {
  return ctx.db.get("documents", id);
}
"#;
        let direct = compile_entry_in_effect_mode(
            &with_test_registration_imports(
                r#"
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    return await ctx.db.get("documents", args.id);
  },
});
"#,
            ),
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            direct.eligible,
            "{:#?}",
            direct
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let generated = generated_source(&direct);
        assert!(!generated.contains("ctx.db.get"), "{generated}");
        assert_eq!(
            generated
                .matches("return __convexStartAsyncOperation(")
                .count(),
            1,
            "{generated}"
        );

        let closed = compile_with_import_in_effect_mode(
            r#"
import { loadDocument as load } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    return await load(ctx, args.id);
  },
});
"#,
            helper,
            "selected",
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            closed.eligible,
            "{:#?}",
            closed
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &closed.mode_output else {
            panic!("closed guest helper returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| (operation.kind.as_str(), operation.table.as_deref()))
                .collect::<Vec<_>>(),
            vec![("databaseGet", Some("documents"))]
        );
        let generated = generated_source(&closed);
        assert!(!generated.contains("ctx.db.get"), "{generated}");
        assert_eq!(
            generated
                .matches("return __convexStartAsyncOperation(")
                .count(),
            1,
            "{generated}"
        );

        let detached = compile_with_import_in_effect_mode(
            r#"
import { loadDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => loadDocument(ctx, args.id),
});
"#,
            r#"
export function loadDocument(ctx, id) {
  ctx.db.get("documents", id);
  return null;
}
"#,
            "selected",
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&detached);
        assert!(detached.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-convex-effect"
                && diagnostic.message.contains("ctx.db.get")
        }));

        let escaped = compile_with_import_in_effect_mode(
            r#"
import { loadDocument } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => await loadDocument(ctx, args.id),
});
"#,
            r#"
export async function loadDocument(ctx, id) {
  const pending = ctx.db.get("documents", id);
  JSON.stringify(pending);
  return await pending;
}
"#,
            "selected",
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&escaped);
        assert!(escaped.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-convex-effect"
                && diagnostic.message.contains("ctx.db.get")
        }));
    }

    #[test]
    fn guest_sequential_effects_reject_conditionally_awaited_promises() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const pending = ctx.db.get("documents", args.id);
    if (args.wait) await pending;
    return null;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-convex-effect"
                && diagnostic.message.contains("ctx.db.get")
        }));
    }

    #[test]
    fn guest_sequential_effects_reject_dropped_helper_calls() {
        let source = with_test_registration_imports(
            r#"
async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    load(ctx, args.id);
    return null;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn guest_sequential_effects_reject_unawaited_async_iifes() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    (async () => {
      await ctx.db.get("documents", args.id);
    })();
    return null;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn guest_sequential_effects_reject_finally_overridden_effect_returns() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    try {
      return ctx.db.get("documents", args.id);
    } finally {
      return null;
    }
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);

        let helper_source = with_test_registration_imports(
            r#"
function load(ctx, id) {
  return ctx.db.get("documents", id);
}
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    try {
      return load(ctx, args.id);
    } finally {
      return null;
    }
  },
});
"#,
        );
        let helper_output = compile_entry_in_effect_mode(
            &helper_source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&helper_output);

        let pending_source = with_test_registration_imports(
            r#"
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const pending = ctx.db.get("documents", args.id);
    try {
      return pending;
    } finally {
      return null;
    }
  },
});
"#,
        );
        let pending_output = compile_entry_in_effect_mode(
            &pending_source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&pending_output);
    }

    #[test]
    fn guest_sequential_effects_reject_mixed_awaited_and_dropped_helper_calls() {
        let source = with_test_registration_imports(
            r#"
async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    const safe = await load(ctx, args.id);
    load(ctx, args.otherId);
    return safe;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn deterministic_encoding_and_regexp_globals_preserve_guest_native_semantics() {
        let source = r#"
export const deterministicGlobals = query({
  args: { pattern: null, value: null },
  handler: (_ctx, args) => {
    const pattern = new RegExp(args.pattern, "u");
    const encoded = new TextEncoder().encode(args.value);
    const base64 = btoa(args.value);
    return {
      bytes: encoded.length,
      decoded: atob(base64),
      matches: pattern.test(args.value),
    };
  },
});
"#;
        let output = compile(source, "deterministicGlobals");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        assert_eq!(
            evaluate_generated_handler(&output, "{}", r#"{ pattern: "^hello$", value: "hello" }"#,),
            serde_json::json!({ "bytes": 5, "decoded": "hello", "matches": true })
        );
    }

    #[test]
    fn inventory_generated_application_global_facade_is_admitted_without_raw_global_flow() {
        let facade = compile(
            r#"
export const facade = query({
  args: {},
  handler: () => {
    const applicationGlobal = __convexWasmApplicationGlobalThis;
    const spreadGlobal = { ...applicationGlobal };
    return [
      applicationGlobal.Object.entries({ value: 1 }),
      applicationGlobal["Object"] === Object,
      spreadGlobal.Object === Object,
      applicationGlobal.globalThis === applicationGlobal,
    ];
  },
});
"#,
            "facade",
        );
        assert!(
            facade.eligible,
            "{:#?}",
            facade
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );

        let raw = compile(
            r#"
export const raw = query({ args: {}, handler: () => globalThis });
"#,
            "raw",
        );
        assert!(!raw.eligible);
        assert!(
            raw.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unsupported-global"),
            "{:#?}",
            raw.diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ordinary_text_decoder_semantics_are_owned_by_the_pinned_engine() {
        let source = r#"
export const decode = query({
  args: {
    constructorOptions: null,
    decodeOptions: null,
    encoding: null,
    first: null,
    second: null,
  },
  handler: (_ctx, args) => {
    const decoder = new TextDecoder(args.encoding, args.constructorOptions);
    const first = decoder.decode(args.first, args.decodeOptions);
    const second = decoder.decode(args.second);
    return { first, second, instance: decoder instanceof TextDecoder };
  },
});
"#;
        let output = compile(source, "decode");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );

        let inline = compile(
            r#"
export const decode = query({
  args: { bytes: null },
  handler: (_ctx, args) => new TextDecoder().decode(args.bytes),
});
"#,
            "decode",
        );
        assert!(
            inline.eligible,
            "{:#?}",
            inline
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );

        let instance_of = compile(
            r#"
export const check = query({
  args: { value: null },
  handler: (_ctx, args) => args.value instanceof TextDecoder,
});
"#,
            "check",
        );
        assert!(
            instance_of.eligible,
            "{:#?}",
            instance_of
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn ordinary_engine_globals_do_not_require_operation_shape_parity() {
        for expression in [
            "const decode = atob; return decode(args.value);",
            "return new TextEncoder(\"utf-8\").encode(args.value);",
            "return TextDecoder(\"utf-8\");",
            "return atob.call(null, args.value);",
            "const Decoder = TextDecoder; return new Decoder();",
            "return new TextDecoder(1, 2, 3).decode(args.value);",
            "return new TextDecoder().decode(args.value, {}, 3);",
            "const decoder = new TextDecoder(); return decoder.encoding;",
            "const decoder = new TextDecoder(); const decode = decoder.decode; return decode(args.value);",
            "const decoder = new TextDecoder(); return decoder.decode.call(decoder, args.value);",
            "const decoder = new TextDecoder(); return decoder;",
            "const decoder = new TextDecoder(); return decoder instanceof Object;",
        ] {
            let source = format!(
                r#"
export const rejected = query({{
  args: {{ value: null }},
  handler: (_ctx, args) => {{ {expression} }},
}});
"#
            );
            let output = compile(&source, "rejected");
            assert!(
                output.eligible,
                "{expression}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn reviewed_engine_global_bindings_reject_direct_writes_in_every_assignment_form() {
        let expressions = compile_admitted_static_hermes_globals()
            .iter()
            .map(|name| format!("{name} = Object;"))
            .chain(
                ["Array++;", "({ Array } = args);", "[Promise] = [];"]
                    .into_iter()
                    .map(str::to_string),
            );
        for expression in expressions {
            let source = format!(
                r#"
export const rejected = query({{
  args: {{ value: null }},
  handler: (_ctx, args) => {{ {expression} return args.value; }},
}});
"#
            );
            let output = compile(&source, "rejected");
            assert!(
                !output.eligible,
                "fixture unexpectedly admitted global write: {expression}"
            );
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "global-write"),
                "{expression}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn compiler_output_exposes_the_exact_static_hermes_global_policy_identity() {
        let output = compile(
            r#"
export const selected = query({
  args: {},
  handler: () => 1,
});
"#,
            "selected",
        );
        let serialized = serde_json::to_value(output).unwrap();
        let expected: Value = serde_json::from_str(include_str!(
            "../../convex-wasm-runtime-surface-policy-identity.json"
        ))
        .unwrap();
        assert_eq!(serialized["compiler"]["staticHermesGlobalPolicy"], expected);
    }

    #[test]
    fn compiler_accepts_the_extensible_application_global_facade_policy() {
        let inventory: Value = serde_json::from_str(include_str!(
            "../../convex-wasm-static-hermes-engine-globals.json"
        ))
        .unwrap();
        assert_eq!(
            inventory["accessPolicy"]["applicationGlobalFacade"],
            "inventory-derived-extensible-null-prototype-immutable-builtins"
        );
        let runtime_support_globals = inventory["semantics"]
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(name, semantic)| {
                (semantic["provider"] == "shared-untyped-runtime-support"
                    && semantic["read"]["state"] == "admitted")
                    .then(|| name.clone())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            runtime_support_globals,
            BTreeSet::from([
                "DOMException".to_string(),
                "Intl".to_string(),
                "URL".to_string(),
                "URLSearchParams".to_string(),
            ])
        );
        assert!(
            runtime_support_globals.is_subset(compile_admitted_static_hermes_globals()),
            "runtime-support globals must remain admitted after the formatter installs them"
        );

        let output = compile(
            r#"
export const selected = query({
  args: {},
  handler: () => 1,
});
"#,
            "selected",
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn shadowed_deterministic_global_names_do_not_receive_global_capability_admission() {
        let source = r#"
const RegExp = (pattern) => ({ test: (value) => value === pattern });
const atob = (value) => `local:${value}`;
export const shadowed = query({
  args: { value: null },
  handler: (_ctx, args) => ({
    decoded: atob(args.value),
    matches: RegExp(args.value).test(args.value),
  }),
});
"#;
        let module = summary(source);
        assert!(
            module
                .globals
                .iter()
                .all(|global| !matches!(global.name.as_str(), "RegExp" | "atob"))
        );
        let output = compile(source, "shadowed");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::Opaque);
    }

    #[test]
    fn while_try_and_default_assignment_patterns_preserve_ordinary_semantics() {
        let source = r#"
function summarize({ values: [first = 1] = [], limit = 4 } = {}) {
  let total = first;
  let current = first;
  while (current < limit) {
    total += current;
    current += 1;
  }
  try {
    if (total > 10) throw new Error("large");
  } catch (error) {
    total = error.message.length;
  }
  return total;
}
export const ordinaryControl = query({
  args: { options: null, replacements: null },
  handler: (_ctx, args) => {
    let replacement;
    [replacement = 3] = args.replacements;
    return summarize(args.options) + replacement;
  },
});
"#;
        let output = compile(source, "ordinaryControl");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        let generated = generated_source(&output);
        assert!(
            generated.contains(": any = {}"),
            "default parameter lacks a Static Hermes typed-mode annotation: {generated}"
        );
        assert_eq!(
            evaluate_generated_handler(
                &output,
                "{}",
                r#"{ options: { values: [4], limit: 7 }, replacements: [] }"#,
            ),
            serde_json::json!(8)
        );
    }

    #[test]
    fn try_catch_around_a_suspending_convex_effect_remains_an_exact_v8_boundary() {
        for source in [
            r#"
export const caught = query({
  args: { id: null },
  handler: async (ctx, args) => {
    try {
      return await ctx.db.get("documents", args.id);
    } catch (_error) {
      return null;
    }
  },
});
"#,
            r#"
async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const caught = query({
  args: { id: null },
  handler: async (ctx, args) => {
    try {
      return await load(ctx, args.id);
    } catch (_error) {
      return null;
    }
  },
});
"#,
        ] {
            let output = compile(source, "caught");
            assert!(!output.eligible);
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-try-suspended-convex-error"
                        && diagnostic.construct.as_deref() == Some("TryStatement")
                        && diagnostic.source.starts_with("try {")
                }),
                "{:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message, &diagnostic.source))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn transparent_typescript_wrappers_preserve_registration_reachability_and_effect_matching() {
        let source = r#"
type QueryContext = {
  db: { get(table: string, id: string): Promise<unknown> };
};
const identity = <Value>(value: Value): Value => value;
async function lookup(helperContext: QueryContext, id: string) {
  return await ((((helperContext as QueryContext)!).db.get))(
    ("documents" as const),
    (id satisfies string),
  );
}

export const wrapped = (query as (registration: object) => unknown)(({
  args: ({ id: null } satisfies { id: null }),
  handler: ((async (ctx: QueryContext, args: { id: string }) => {
    const typedIdentity = identity<string>;
    const id = typedIdentity((args.id as string)!);
    return await (lookup as typeof lookup)((<QueryContext>ctx), id);
  }) satisfies (ctx: QueryContext, args: { id: string }) => Promise<unknown>),
} as const));
"#;
        let module = summary(source);
        for wrapper in [
            "TSAsExpression",
            "TSTypeAssertion",
            "TSNonNullExpression",
            "TSSatisfiesExpression",
            "TSInstantiationExpression",
        ] {
            assert!(
                module
                    .constructs
                    .iter()
                    .all(|construct| construct.kind != wrapper),
                "{wrapper} leaked into runtime admission"
            );
        }
        assert_eq!(module.operations.len(), 1);
        assert_eq!(module.operations[0].kind, "db.get");
        assert_eq!(module.operations[0].table.as_deref(), Some("documents"));
        assert_eq!(
            module.operations[0].effect_path.as_deref(),
            Some("helperContext.db.get")
        );
        let lookup_call = module
            .calls
            .iter()
            .find(|call| call.callee == "lookup")
            .unwrap();
        assert_eq!(
            &source[lookup_call.arguments[0].start as usize..lookup_call.arguments[0].end as usize],
            "ctx"
        );

        let output = compile(source, "wrapped");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|d| &d.message)
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("inline compilation returned analysis output");
        };
        assert_eq!(
            compiled.operations.len(),
            1,
            "{:#?}",
            compiled
                .operations
                .iter()
                .map(|operation| (
                    operation.id,
                    &operation.kind,
                    &operation.file,
                    operation.start,
                    operation.end,
                    &operation.table,
                    &operation.source,
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(compiled.operations[0].kind, "databaseGet");
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .unwrap();
        let generated_ast = parse_javascript(&generated);
        assert!(!contains_node_type(&generated_ast, "TSAsExpression"));
        assert!(!contains_node_type(&generated_ast, "TSTypeAssertion"));
        assert!(!contains_node_type(&generated_ast, "TSNonNullExpression"));
        assert!(!contains_node_type(&generated_ast, "TSSatisfiesExpression"));
        assert!(!contains_node_type(
            &generated_ast,
            "TSInstantiationExpression"
        ));
    }

    #[test]
    fn ordinary_optional_members_and_calls_lower_to_nullish_short_circuits() {
        let source = r#"
export const optional = query({
  args: { value: null },
  handler: (_ctx, args) => {
    const nested = args.value?.nested;
    return nested?.method?.() ?? args.value?.fallback;
  },
});
"#;
        let module = summary(source);
        assert!(
            module
                .constructs
                .iter()
                .any(|construct| construct.kind == "ChainExpression")
        );
        let output = compile(source, "optional");
        assert!(output.eligible);
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("inline compilation returned analysis output");
        };
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .unwrap();
        let generated_ast = parse_javascript(&generated);
        assert!(!contains_node_type(&generated_ast, "ChainExpression"));
        assert!(count_node_type(&generated_ast, "ConditionalExpression") >= 3);
        assert!(contains_node_type(&generated_ast, "CallExpression"));
    }

    #[test]
    fn optional_convex_effect_is_not_misclassified_as_an_unconditional_operation() {
        let source = r#"
export const optionalEffect = query({
  args: { id: null },
  handler: async (ctx, args) =>
    await ctx?.db.get("documents", args.id),
});
"#;
        let module = summary(source);
        assert!(module.operations.is_empty());
        assert!(
            module
                .effects
                .iter()
                .any(|effect| effect.path == "ctx.db.get")
        );
        let output = compile(source, "optionalEffect");
        assert!(!output.eligible);
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unsupported-convex-effect")
        );
    }

    #[test]
    fn shadowed_optional_promise_call_is_not_a_direct_async_batch() {
        let source = r#"
const Promise = { all: (values: unknown[]) => values };
export const shadowedPromise = query({
  args: { value: null },
  handler: (_ctx, args) => Promise?.all?.([args.value]),
});
"#;
        let module = summary(source);
        assert!(module.direct_async_batches.is_empty());
        assert!(compile(source, "shadowedPromise").eligible);
    }

    #[test]
    fn shadowed_fixed_promise_all_has_no_semantic_aggregate_graph_edge() {
        let source = r#"
const Promise = { all: (values: unknown[]) => values };
function project(value: unknown) { return value; }
export const shadowedPromise = mutation({
  args: { firstId: v.id("documents"), secondId: v.id("documents") },
  handler: async (ctx, args) => await Promise.all([
    ctx.db.get("documents", args.firstId),
    ctx.db.get("documents", args.secondId),
  ]),
});
"#;
        let module = summary(source);
        assert_eq!(module.promise_all_sites.len(), 1);
        assert!(module.callable_leaf_plans.iter().all(|candidate| {
            let super::callable_plans::CallableLeafControlCandidate::EffectValueFlow(flow) =
                &candidate.control
            else {
                return true;
            };
            flow.paths.iter().all(|path| {
                path.steps.iter().all(|step| {
                    !matches!(
                        step,
                        super::callable_value_flow::CallableEffectValueStepCandidate::PromiseAll {
                            ..
                        }
                    )
                })
            })
        }));
        let output = compile(source, "shadowedPromise");
        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-direct-promise-all"
                && diagnostic.message.contains("unshadowed global Promise")
        }));
    }

    #[test]
    fn shadowed_effect_free_promise_all_map_is_not_rewritten_to_map() {
        let source = with_test_registration_imports(
            r#"
const Promise = { all: (values) => ["custom", ...values] };
export const selected = query({
  args: {},
  handler: (_ctx, _args) => {
    const mode = new Map();
    mode.set("selected", true);
    return Promise.all([1, 2].map((value) => value + 1));
  },
});
"#,
        );
        let output = compile_entry(&source, "selected", true);
        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-direct-promise-all"
                && diagnostic.message.contains("unshadowed global Promise")
        }));
    }

    #[test]
    fn multiple_await_direct_batch_callback_remains_a_v8_boundary() {
        let source = r#"
export const multipleAwaitBatch = query({
  args: { ids: v.array(null) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map(async (id) => {
      const first = await ctx.db.get("documents", id);
      return await ctx.db.get("documents", first._id);
    }),
  ),
});
"#;
        let module = summary(source);
        assert_eq!(module.direct_async_batches.len(), 1);
        assert_eq!(
            module.direct_async_batches[0].shape_error.as_deref(),
            Some("direct Promise.all callback has independently resumable multiple awaits")
        );
        let output = compile(source, "multipleAwaitBatch");
        assert!(!output.eligible);
        let helper_plan = output
            .callable_control_plans
            .iter()
            .find(|plan| plan.effects.len() == 2 && plan.control.await_count == 2)
            .expect("multiple-await helper has no generic callable control plan");
        assert!(helper_plan.current_batch_leaf().is_none());
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-direct-promise-all"
                && diagnostic
                    .message
                    .contains("independently resumable multiple awaits")
        }));
    }

    #[test]
    fn guest_promise_mode_rejects_effectful_multiple_await_control() {
        let source = with_test_registration_imports(
            r#"
export const multipleAwaitBatch = query({
  args: { ids: v.array(null) },
  handler: async (ctx, args) => {
    try {
      return await Promise.all(args.ids.map(async (id) => {
        const first = await ctx.db.get("documents", id);
        return await ctx.db.get("documents", first._id);
      }));
    } catch (_error) {
      return [];
    }
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "multipleAwaitBatch",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn guest_promise_mode_rejects_effectful_shadowed_promise_calls() {
        let source = with_test_registration_imports(
            r#"
const Promise = { all: (values: unknown[]) => values };
export const shadowedPromise = mutation({
  args: { ids: v.array(v.id("documents")) },
  handler: async (ctx, args) => {
    return await Promise.all(args.ids.map(async (id) => {
      const first = await ctx.db.get("documents", id);
      return await ctx.db.get("documents", first._id);
    }));
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "shadowedPromise",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn guest_promise_mode_rejects_effectful_shadowed_fixed_arrays() {
        let source = with_test_registration_imports(
            r#"
const Promise = { all: (values: unknown[]) => values };
export const shadowedPromise = query({
  args: {},
  handler: async (ctx, args) => await Promise.all([
    ctx.db.get("documents", args.firstId),
    ctx.db.get("documents", args.secondId),
  ]),
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "shadowedPromise",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn guest_promise_helper_effects_reject_all_consumer_positions() {
        let callbacks = [
            r#"(id) => load(ctx, "documents", id)"#,
            r#"async (id) => {
              const pending = load(ctx, "documents", id);
              return await pending;
            }"#,
            r#"async (id) => {
              const pending = load(ctx, "documents", id);
              const document = await pending;
              return document._id;
            }"#,
        ];
        for callback in &callbacks {
            let source = with_test_registration_imports(&format!(
                r#"
async function load(ctx, table, id) {{
  return await ctx.db.get(table, id);
}}
export const selected = query({{
  args: {{ ids: v.array(v.string()) }},
  handler: async (ctx, args) => await Promise.all(args.ids.map({callback})),
}});
"#,
            ));
            let output = compile_entry_in_effect_mode(
                &source,
                "selected",
                true,
                super::EffectExecutionMode::GuestPromiseEventLoop,
            );
            assert_guest_effect_is_rejected_without_lowering(&output);
        }

        let blocking_source = format!(
            r#"
async function load(ctx, table, id) {{
  return await ctx.db.get(table, id);
}}
export const selected = query({{
  args: {{ ids: v.array(v.string()) }},
  handler: async (ctx, args) => await Promise.all(args.ids.map({})),
}});
"#,
            callbacks[2]
        );
        let blocking = compile(&blocking_source, "selected");
        assert!(!blocking.eligible);
        assert!(blocking.callable_effect_plans.iter().all(|plan| {
            plan.provenance.caller_callsite.is_none()
                || plan
                    .effect_key
                    .static_operands
                    .get("table")
                    .is_none_or(|table| table != "documents")
        }));
        assert!(
            blocking.diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.code.as_str(),
                    "unsupported-convex-effect" | "unsupported-direct-promise-all"
                )
            }),
            "{:#?}",
            blocking
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn guest_callable_plan_keeps_multiple_helper_effects_at_one_consumer_site() {
        let source = with_test_registration_imports(
            r#"
async function loadPair(ctx, table, firstId, secondId) {
  const first = await ctx.db.get(table, firstId);
  const second = await ctx.db.get(table, secondId);
  return [first, second];
}
export const selected = query({
  args: { firstId: null, secondId: null },
  handler: async (ctx, args) => {
    return await loadPair(ctx, "documents", args.firstId, args.secondId);
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let specialized = output
            .callable_effect_plans
            .iter()
            .filter(|plan| {
                plan.provenance.caller_callsite.is_some()
                    && plan.effect_key.operation_kind == "databaseGet"
                    && plan
                        .effect_key
                        .static_operands
                        .get("table")
                        .is_some_and(|table| table == "documents")
            })
            .collect::<Vec<_>>();
        assert_eq!(specialized.len(), 2);
        let callsite = specialized[0]
            .provenance
            .caller_callsite
            .as_ref()
            .expect("specialized pair lost its callsite");
        assert!(specialized.iter().all(|plan| {
            plan.provenance.caller_callsite.as_ref() == Some(callsite)
                && plan.callable == specialized[0].callable
        }));
        let control = output
            .callable_control_plans
            .iter()
            .find(|control| control.callable == specialized[0].callable)
            .expect("multi-effect helper consumer has no generic control plan");
        assert_eq!(
            control
                .effects
                .iter()
                .filter(|effect| effect.effect.consumer_site() == callsite)
                .count(),
            2
        );
        assert_eq!(
            control
                .calls
                .iter()
                .filter(|call| call.callsite == *callsite)
                .count(),
            1
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("eligible multi-effect helper fixture returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .filter(|operation| {
                    operation.kind == "databaseGet"
                        && operation.table.as_deref() == Some("documents")
                })
                .count(),
            2
        );
        let generated = compiled
            .generated_javascript_artifact
            .expect("multi-effect helper fixture has no generated source")
            .source
            .expect("multi-effect helper fixture has no inline generated source");
        assert!(!generated.contains("ctx.db.get"), "{generated}");
        assert_eq!(
            generated.matches("function __convexEffectSite_").count(),
            2,
            "{generated}"
        );
    }

    #[test]
    fn guest_callable_plan_rejects_unmaterialized_aliased_helper_effects() {
        for (name, body) in [
            (
                "unawaited",
                "const pending = ctx.db.get(table, id); return null;",
            ),
            (
                "same-block alias",
                "const pending = ctx.db.get(table, id); await pending; return null;",
            ),
        ] {
            let source = with_test_registration_imports(&format!(
                r#"
async function load(ctx, table, id) {{
  {body}
}}
export const selected = query({{
  args: {{ id: null }},
  handler: async (ctx, args) => await load(ctx, "documents", args.id),
}});
"#,
            ));
            let output = compile_entry_in_effect_mode(
                &source,
                "selected",
                true,
                super::EffectExecutionMode::GuestPromiseEventLoop,
            );
            assert!(
                output.callable_effect_plans.iter().any(|plan| {
                    plan.provenance.caller_callsite.is_some()
                        && plan.effect_key.operation_kind == "databaseGet"
                        && plan
                            .effect_key
                            .static_operands
                            .get("table")
                            .is_some_and(|table| table == "documents")
                }),
                "{name}: helper effect did not specialize"
            );
            assert_guest_effect_is_rejected_without_lowering(&output);
        }
    }

    #[test]
    fn guest_promise_mode_rebinds_the_global_capability_not_method_shapes() {
        let source = with_test_registration_imports(
            r#"
function useShadowedPromise(value) {
  const Promise = { resolve: (input) => input };
  return Promise.resolve(value);
}
export const promiseSurface = query({
  args: { value: null },
  handler: async (_ctx, args) => {
    const created = new Promise((resolve) => resolve(args.value));
    const resolved = Promise.resolve(created);
    const raced = Promise.race([resolved]);
    return Promise.all([raced, useShadowedPromise(args.value)]);
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "promiseSurface",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("eligible Promise-mode output did not compile");
        };
        let generated = compiled
            .generated_javascript_artifact
            .expect("Promise-mode output has no generated source")
            .source
            .expect("inline Promise-mode output has no source");
        assert!(
            generated.contains("new __convexGuestPromise"),
            "{generated}"
        );
        assert!(
            generated.contains("__convexGuestPromise.resolve"),
            "{generated}"
        );
        assert!(
            generated.contains("__convexGuestPromise.race"),
            "{generated}"
        );
        assert!(
            generated.contains("__convexGuestPromise.all"),
            "{generated}"
        );
        assert!(
            generated.contains("return Promise.resolve(value)"),
            "{generated}"
        );
    }

    #[test]
    fn effect_execution_mode_is_bound_into_source_identities() {
        let source = with_test_registration_imports(
            r#"
export const identity = query({
  args: { value: null },
  handler: async (_ctx, args) => args.value,
});
"#,
        );
        let blocking = compile_entry_in_effect_mode(
            &source,
            "identity",
            true,
            super::EffectExecutionMode::BlockingFiber,
        );
        let promise = compile_entry_in_effect_mode(
            &source,
            "identity",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(blocking.eligible && promise.eligible);
        assert_ne!(
            blocking.source_graph_fingerprint,
            promise.source_graph_fingerprint
        );
        assert_ne!(blocking.export_fingerprint, promise.export_fingerprint);
    }

    #[test]
    fn oxc_callable_control_skeleton_uses_local_blocks_and_explicit_suspension_points() {
        let source = r#"
async function controlled(ctx, id, enabled) {
  if (enabled) return await ctx.db.get("documents", id);
  if (!id) throw new Error("missing id");
  return null;
  ctx.db.get("unreachable", id);
}
"#;
        let module = summary(source);
        let start = u32::try_from(source.find("async function controlled").unwrap()).unwrap();
        let skeleton = module
            .callable_control_skeletons
            .iter()
            .find(|skeleton| skeleton.callable_start == start)
            .expect("controlled function has no Oxc control skeleton");
        assert_eq!(
            skeleton
                .blocks
                .iter()
                .map(|block| block.id)
                .collect::<Vec<_>>(),
            (0..u32::try_from(skeleton.blocks.len()).unwrap()).collect::<Vec<_>>()
        );
        assert_eq!(
            skeleton.intra_block_order,
            crate::callable_control::CallableIntraBlockOrder::Unresolved
        );
        assert!(
            skeleton
                .points
                .iter()
                .any(|point| point.kind == CallableControlPointKind::Await)
        );
        assert!(skeleton.blocks.iter().any(|block| {
            block
                .successors
                .iter()
                .any(|edge| edge.kind == CallableControlEdgeKind::Jump)
        }));
        assert!(skeleton.blocks.iter().any(|block| {
            block
                .successors
                .iter()
                .any(|edge| edge.kind == CallableControlEdgeKind::Unreachable)
        }));
        assert!(skeleton.blocks.iter().any(|block| {
            block.instructions.iter().any(|instruction| {
                instruction.kind == crate::callable_control::CallableControlInstructionKind::Throw
            })
        }));
        assert!(skeleton.blocks.iter().any(|block| {
            block
                .successors
                .iter()
                .any(|edge| edge.kind == CallableControlEdgeKind::ImplicitError)
        }));
    }

    #[test]
    fn helper_await_with_child_continuation_reports_the_intentional_v8_boundary() {
        let source = r#"
async function loadDocument(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const helperChildBatch = query({
  args: { ids: v.array(null) },
  handler: async (ctx, args) => {
    const batches = [args.ids];
    return await Promise.all(batches.flat().map(async (ids) => {
      const document = await loadDocument(ctx, ids[0]);
      return { id: document._id };
    }));
  },
});
"#;
        let module = summary(source);
        assert_eq!(module.direct_async_batches.len(), 1);
        assert_eq!(
            module.direct_async_batches[0].shape_error.as_deref(),
            Some(
                "direct Promise.all callback awaits helper loadDocument and resumes afterward; helper-backed resumable children are an intentional V8 boundary"
            )
        );
        let output = compile(source, "helperChildBatch");
        assert!(!output.eligible);
        let callback_plan = output
            .callable_control_plans
            .iter()
            .find(|plan| {
                plan.effects.len() == 1
                    && plan.control.await_count == 1
                    && plan.effects[0].effect.provenance.caller_callsite.is_some()
                    && plan.current_batch_leaf().is_none()
            })
            .expect("helper-backed callback continuation has no generic control plan");
        assert_eq!(callback_plan.effects[0].target_control.await_count, 1);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-direct-promise-all"
                && diagnostic.message.contains("intentional V8 boundary")
        }));
    }

    #[test]
    fn fixed_promise_all_preserves_ordered_heterogeneous_effects_and_rejects_unsafe_children() {
        let source = r#"
export const fixedBatch = mutation({
  args: { id: null, otherId: null, owner: null },
  handler: async (ctx, args) => await Promise.all([
    ctx.db
      .query("documents")
      .withIndex("by_owner", (q) => q.eq("owner", args.owner))
      .collect(),
    ctx.db.patch("documents", args.id, { state: "done" }),
    ctx.db.delete("documents", args.otherId),
  ]),
});
"#;
        let output = compile(source, "fixedBatch");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        assert_eq!(output.proved_direct_async_batches.len(), 1);
        let super::ProvedDirectAsyncBatchShape::FixedEffectArray { children: proved } =
            &output.proved_direct_async_batches[0].shape
        else {
            panic!("fixed batch changed proof kind");
        };
        assert_eq!(proved.len(), 3);
        assert_eq!(
            proved
                .iter()
                .map(|child| child.result_kind.as_str())
                .collect::<Vec<_>>(),
            vec!["hostArray", "undefined", "undefined"]
        );

        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("eligible fixed batch returned analysis output");
        };
        assert_eq!(compiled.direct_async_batches.len(), 1);
        let super::DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } =
            &compiled.direct_async_batches[0].shape
        else {
            panic!("fixed batch changed authorization kind");
        };
        assert_eq!(children.len(), 3);
        assert_eq!(
            children
                .iter()
                .map(|child| (
                    child.operation_kind.as_str(),
                    child.result_kind.as_str(),
                    child.dynamic_arguments.len(),
                ))
                .collect::<Vec<_>>(),
            vec![
                ("databaseIndexQuery", "hostArray", 1),
                ("databasePatch", "undefined", 2),
                ("databaseDelete", "undefined", 1),
            ]
        );
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("fixed batch generated inline JavaScript");
        let ordered_operation_ids = children
            .iter()
            .map(|child| child.operation_id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            generated.contains(&format!(
                "__convexAsyncFixedBatch([{ordered_operation_ids}]"
            )),
            "{generated}"
        );
        assert!(!generated.contains("Promise.all("));

        for (name, handler) in [
            (
                "implicit return",
                "async (ctx, args) => Promise.all([ctx.db.get(\"documents\", args.id)])",
            ),
            (
                "explicit return",
                "async (ctx, args) => { return Promise.all([ctx.db.get(\"documents\", args.id)]); }",
            ),
            (
                "then continuation",
                "async (ctx, args) => await Promise.all([ctx.db.get(\"documents\", args.id)]).then((values) => values)",
            ),
        ] {
            let rejected_source = format!(
                r#"
export const rejected = query({{
  args: {{ id: null }},
  handler: {handler},
}});
"#
            );
            let module = summary(&rejected_source);
            assert_eq!(module.direct_async_batches.len(), 1, "{name}");
            assert_eq!(
                module.direct_async_batches[0].shape_error.as_deref(),
                Some("fixed Promise.all must be directly awaited"),
                "{name}"
            );
            let rejected = compile(&rejected_source, "rejected");
            assert!(!rejected.eligible, "{name}");
            assert!(
                rejected.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-direct-promise-all"
                        && diagnostic.message == "fixed Promise.all must be directly awaited"
                }),
                "{name}: {:#?}",
                rejected
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }

        for (name, prefix, children) in [
            (
                "hole",
                "",
                "ctx.db.get(\"documents\", args.id),, ctx.db.get(\"documents\", args.otherId)",
            ),
            ("spread", "", "...args.values"),
            ("awaited", "", "await ctx.db.get(\"documents\", args.id)"),
            ("value", "", "args.id"),
            ("thenable", "", "Promise.resolve(args.id)"),
            ("empty", "", ""),
        ] {
            let rejected_source = format!(
                r#"{prefix}
export const rejected = query({{
  args: {{ id: null, otherId: null, values: null }},
  handler: async (ctx, args) => await Promise.all([{children}]),
}});
"#
            );
            let rejected = compile(&rejected_source, "rejected");
            assert!(!rejected.eligible, "{name}");
            assert!(
                rejected
                    .diagnostics
                    .iter()
                    .any(|diagnostic| { diagnostic.code == "unsupported-direct-promise-all" }),
                "{name}: {:#?}",
                rejected
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn direct_promise_all_lowers_fixed_and_mapped_single_effect_helpers() {
        let fixed_source = r#"
async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const fixedHelperBatch = query({
  args: { first: null, second: null },
  handler: async (ctx, args) => await Promise.all([
    load(ctx, args.first),
    load(ctx, args.second),
  ]),
});
"#;
        let fixed = compile(fixed_source, "fixedHelperBatch");
        assert!(
            fixed.eligible,
            "{:#?}",
            fixed
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(fixed_compiled) = fixed.mode_output else {
            panic!("fixed helper batch returned analysis output");
        };
        let fixed_generated = fixed_compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("fixed helper batch generated inline JavaScript");
        assert!(fixed_generated.contains("__convexAsyncFixedBatch([2, 3]"));
        assert!(fixed_generated.contains("[[args.first], [args.second]]"));
        assert!(!fixed_generated.contains("Promise.all("));

        let mapped_source = r#"
async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const mappedHelperBatch = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map((id) => load(ctx, id)),
  ),
});
"#;
        let mapped = compile(mapped_source, "mappedHelperBatch");
        assert!(
            mapped.eligible,
            "{:#?}",
            mapped
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(mapped_compiled) = mapped.mode_output else {
            panic!("mapped helper batch returned analysis output");
        };
        let mapped_generated = mapped_compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("mapped helper batch generated inline JavaScript");
        assert!(
            mapped_generated.contains("__convexAsyncBatch(args.ids, 2, (id) => [id])"),
            "{mapped_generated}"
        );
        assert!(!mapped_generated.contains("Promise.all("));

        let query_source = r#"
const loadByOwner = async (ctx, owner) => await ctx.db
  .query("documents")
  .withIndex("by_owner", (q) => q.eq("owner", owner))
  .collect();
export const queryHelperBatch = query({
  args: { owners: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.owners.map((owner) => loadByOwner(ctx, owner)),
  ),
});
"#;
        let query = compile(query_source, "queryHelperBatch");
        assert!(
            query.eligible,
            "{:#?}",
            query
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(query_compiled) = query.mode_output else {
            panic!("query helper batch returned analysis output");
        };
        assert_eq!(query_compiled.operations.len(), 2);
        assert_eq!(query_compiled.operations[1].kind, "databaseIndexQuery");
        let query_generated = query_compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("query helper batch generated inline JavaScript");
        assert!(query_generated.contains("__convexAsyncBatch(args.owners, 2, (owner) => [owner])"));
        assert!(!query_generated.contains("Promise.all("));

        let void_write_source = r#"
async function patch(ctx, id, value) {
  await ctx.db.patch("documents", id, value);
}
export const fixedVoidHelperBatch = mutation({
  args: { first: null, second: null, value: null },
  handler: async (ctx, args) => await Promise.all([
    patch(ctx, args.first, args.value),
    patch(ctx, args.second, args.value),
  ]),
});
"#;
        let void_write = compile(void_write_source, "fixedVoidHelperBatch");
        assert!(
            void_write.eligible,
            "{:#?}",
            void_write
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(void_write_compiled) = void_write.mode_output else {
            panic!("fixed void helper batch returned analysis output");
        };
        let void_write_generated = void_write_compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("fixed void helper batch generated inline JavaScript");
        assert!(void_write_generated.contains("__convexAsyncFixedBatch([2, 3]"));
        assert!(
            void_write_generated.contains("[[args.first, args.value], [args.second, args.value]]")
        );
        assert!(!void_write_generated.contains("Promise.all("));
    }

    #[test]
    fn mapped_helper_batch_preserves_implicit_undefined_callback_results() {
        for (name, operation) in [
            ("get", "ctx.db.get(\"documents\", id)"),
            ("insert", "ctx.db.insert(\"documents\", id)"),
        ] {
            let source = format!(
                r#"
async function perform(ctx, id) {{
  return await {operation};
}}
export const selected = mutation({{
  args: {{ ids: v.array(v.string()) }},
  handler: async (ctx, args) => await Promise.all(
    args.ids.map(async (id) => {{
      await perform(ctx, id);
    }}),
  ),
}});
"#
            );
            let output = compile(&source, "selected");
            assert!(!output.eligible, "{name}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-direct-promise-all"
                        && diagnostic
                            .message
                            .contains("implicit undefined callback requires a void Convex effect")
                }),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }

        let void_source = r#"
async function patch(ctx, id, value) {
  await ctx.db.patch("documents", id, value);
}
export const selected = mutation({
  args: { ids: v.array(v.string()), value: null },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map(async (id) => {
      await patch(ctx, id, args.value);
    }),
  ),
});
"#;
        let output = compile(void_source, "selected");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn direct_promise_all_lowers_statically_resolved_imported_helper() {
        let entry_source = r#"
import { load } from "./helper";
export const importedHelperBatch = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map((id) => load(ctx, id)),
  ),
});
"#;
        let helper_source = r#"
export async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
"#;
        let output = compile_with_import(entry_source, helper_source, "importedHelperBatch");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("imported helper batch returned analysis output");
        };
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("imported helper batch generated inline JavaScript");
        assert!(
            generated.contains("__convexAsyncBatch(args.ids, 2, (id) => [id])"),
            "{generated}"
        );
        assert!(!generated.contains("Promise.all("));
    }

    #[test]
    fn mapped_leaf_database_get_forms_share_one_semantic_callable_plan() {
        let direct_forms = [
            r#"export const selected = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map((id) => ctx.db.get("documents", id)),
  ),
});"#,
            r#"export const selected = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map(async (id) => await ctx.db.get("documents", id)),
  ),
});"#,
            r#"export const selected = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map(async (id) => {
      return await ctx.db.get("documents", id);
    }),
  ),
});"#,
            r#"const load = (ctx, id) => ctx.db.get("documents", id);
export const selected = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map((id) => load(ctx, id)),
  ),
});"#,
            r#"async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const selected = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map((id) => load(ctx, id)),
  ),
});"#,
            r#"async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
export const selected = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map((id) => load(ctx, "documents", id)),
  ),
});"#,
        ];
        let imported_entry = r#"import { load as fetchDocument } from "./helper";
export const selected = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map((id) => fetchDocument(ctx, "documents", id)),
  ),
});"#;
        let imported_helper = r#"export async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}"#;

        let mut outputs = direct_forms
            .iter()
            .map(|source| compile(source, "selected"))
            .collect::<Vec<_>>();
        outputs.push(compile_with_import(
            imported_entry,
            imported_helper,
            "selected",
        ));

        let mut expected_plan = None;
        for (form_index, output) in outputs.iter().enumerate() {
            assert!(
                output.eligible,
                "form {form_index}: diagnostics {:#?}; plans {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>(),
                output.callable_effect_plans
            );
            let [batch] = output.proved_direct_async_batches.as_slice() else {
                panic!("mapped leaf form did not produce one direct batch");
            };
            let super::ProvedDirectAsyncBatchShape::SingleEffectMap {
                callback_start,
                callback_end,
                operation_start,
                operation_end,
                operation_id,
                ..
            } = &batch.shape
            else {
                panic!("mapped leaf form produced a fixed batch");
            };
            let plan = output
                .callable_effect_plans
                .iter()
                .find(|plan| {
                    plan.callable_source.module == batch.file
                        && plan.callable_source.start == *callback_start
                        && plan.callable_source.end == *callback_end
                })
                .expect("mapped callback has no semantic callable effect plan");
            assert_eq!(plan.effect_key.operation_kind, "databaseGet");
            assert_eq!(plan.effect_key.result_kind, "hostValue");
            assert_eq!(
                plan.effect_key
                    .static_operands
                    .get("table")
                    .map(String::as_str),
                Some("documents")
            );
            assert_eq!(
                plan.normalized_projection().dynamic_operands,
                vec![super::effect_plan::SemanticOperand::Parameter(0)]
            );
            if let Some(expected) = &expected_plan {
                assert!(plan.semantically_equivalent(expected));
            } else {
                expected_plan = Some(plan.clone());
            }
            let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
                panic!("eligible mapped leaf form returned analysis output");
            };
            assert_eq!(
                compiled
                    .operations
                    .iter()
                    .map(|operation| (&operation.file, operation.start, operation.end))
                    .collect::<BTreeSet<_>>()
                    .len(),
                compiled.operations.len(),
                "form {form_index} emitted one operation site more than once"
            );
            assert!(!compiled.operations.is_empty());
            assert!(compiled.operations.iter().all(|operation| {
                operation.kind == "databaseGet" && operation.table.as_deref() == Some("documents")
            }));
            let batch_operation = compiled
                .operations
                .iter()
                .find(|operation| operation.id == *operation_id)
                .expect("mapped semantic consumer operation was not emitted");
            assert_eq!(batch_operation.file, batch.file);
            assert_eq!(batch_operation.start, *operation_start);
            assert_eq!(batch_operation.end, *operation_end);
            let generated = generated_source(output);
            assert_eq!(
                generated.matches("__convexAsyncBatch").count(),
                1,
                "{generated}"
            );
            assert!(!generated.contains("Promise.all"), "{generated}");
            assert!(!generated.contains("await"), "{generated}");
        }

        let local_helper_plan = outputs[3]
            .callable_effect_plans
            .iter()
            .find(|plan| plan.provenance.caller_callsite.is_some())
            .expect("local function-valued helper has no specialized callable range");
        assert_eq!(
            local_helper_plan.provenance.target_callable_source.module,
            "convex/fixture.ts"
        );
        assert!(
            local_helper_plan.provenance.target_callable_source.start
                <= local_helper_plan.provenance.target_effect.start
                && local_helper_plan.provenance.target_effect.end
                    <= local_helper_plan.provenance.target_callable_source.end
        );
        let imported_helper_plan = outputs
            .last()
            .expect("imported helper output disappeared")
            .callable_effect_plans
            .iter()
            .find(|plan| plan.provenance.caller_callsite.is_some())
            .expect("imported alias has no specialized callable range");
        assert_eq!(
            imported_helper_plan
                .provenance
                .target_callable_source
                .module,
            "convex/helper.ts"
        );
        assert!(
            imported_helper_plan.provenance.target_callable_source.start
                <= imported_helper_plan.provenance.target_effect.start
                && imported_helper_plan.provenance.target_effect.end
                    <= imported_helper_plan.provenance.target_callable_source.end
        );

        let sequential_source = r#"async function load(id, ctx) {
  return await ctx.db.get("documents", id);
}
async function sequential(id, ctx) {
  return await load(id, ctx);
}
export const selected = query({
  args: { id: v.string() },
  handler: async (ctx, args) => await sequential(args.id, ctx),
});"#;
        let sequential = compile(sequential_source, "selected");
        assert!(
            sequential.eligible,
            "{:#?}",
            sequential
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let sequential_plan = sequential
            .callable_effect_plans
            .iter()
            .find(|plan| {
                plan.provenance.caller_callsite.is_some()
                    && plan.callable != plan.provenance.target_callable
            })
            .unwrap_or_else(|| {
                panic!(
                    "sequential helper did not consume the semantic callable plan: plans {:?}",
                    sequential
                        .callable_effect_plans
                        .iter()
                        .map(|plan| (
                            plan.callable_source.start,
                            plan.callable_source.end,
                            &plan.effect_key.operation_kind,
                            plan.provenance
                                .caller_callsite
                                .as_ref()
                                .map(|anchor| (anchor.start, anchor.end)),
                            &plan.callable.unit_id,
                            &plan.provenance.target_callable.unit_id,
                        ))
                        .collect::<Vec<_>>()
                )
            });
        assert!(
            sequential_plan.semantically_equivalent(
                expected_plan
                    .as_ref()
                    .expect("mapped normalization corpus was empty")
            )
        );

        let dynamic_table = compile(
            r#"async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
export const selected = query({
  args: { ids: v.array(v.string()), table: v.string() },
  handler: async (ctx, args) => await Promise.all(
    args.ids.map((id) => load(ctx, args.table, id)),
  ),
});"#,
            "selected",
        );
        assert!(!dynamic_table.eligible);
        assert!(dynamic_table.callable_effect_plans.iter().all(|plan| {
            plan.effect_key
                .static_operands
                .get("table")
                .is_none_or(|table| table != "documents")
        }));

        let fixed_dynamic_table = compile(
            r#"async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
export const selected = query({
  args: { id: null, table: v.string() },
  handler: async (ctx, args) => await Promise.all([
    load(ctx, args.table, args.id),
  ]),
});"#,
            "selected",
        );
        assert!(!fixed_dynamic_table.eligible);
        assert!(fixed_dynamic_table.proved_direct_async_batches.is_empty());
        match &fixed_dynamic_table.mode_output {
            CompilerModeOutput::Analysis(analysis) => {
                assert_eq!(analysis.analysis_summary.operation_count, 0);
            }
            CompilerModeOutput::Compile(compiled) => {
                assert!(compiled.operations.is_empty());
                assert!(compiled.direct_async_batches.is_empty());
            }
        }
        assert!(
            fixed_dynamic_table
                .callable_control_plans
                .iter()
                .any(|plan| { plan.source_effects.len() == 1 && plan.effects.is_empty() })
        );
    }

    #[test]
    fn parameterized_leaf_database_kinds_share_plan_owned_static_specialization() {
        let fixtures = [
            (
                "databaseNormalizeId",
                r#"function effect(ctx, table, id) {
  return ctx.db.normalizeId(table, id);
}
export const selected = mutation({
  args: {},
  handler: (ctx, args) => effect(ctx, "documents", args.id),
});"#,
            ),
            (
                "databaseGet",
                r#"async function effect(ctx, table, id) {
  return await ctx.db.get(table, id);
}
export const selected = mutation({
  args: {},
  handler: async (ctx, args) => await effect(ctx, "documents", args.id),
});"#,
            ),
            (
                "databaseInsert",
                r#"async function effect(ctx, table, value) {
  return await ctx.db.insert(table, value);
}
export const selected = mutation({
  args: {},
  handler: async (ctx, args) => await effect(ctx, "documents", args.value),
});"#,
            ),
            (
                "databasePatch",
                r#"async function effect(ctx, table, id, value) {
  return await ctx.db.patch(table, id, value);
}
export const selected = mutation({
  args: {},
  handler: async (ctx, args) => await effect(ctx, "documents", args.id, args.value),
});"#,
            ),
            (
                "databaseReplace",
                r#"async function effect(ctx, table, id, value) {
  return await ctx.db.replace(table, id, value);
}
export const selected = mutation({
  args: {},
  handler: async (ctx, args) => await effect(ctx, "documents", args.id, args.value),
});"#,
            ),
            (
                "databaseDelete",
                r#"async function effect(ctx, table, id) {
  return await ctx.db.delete(table, id);
}
export const selected = mutation({
  args: {},
  handler: async (ctx, args) => await effect(ctx, "documents", args.id),
});"#,
            ),
        ];

        for (expected_kind, source) in fixtures {
            let output = compile(source, "selected");
            assert!(
                output.eligible,
                "{expected_kind}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert!(output.callable_effect_plans.iter().any(|plan| {
                plan.effect_key.operation_kind == expected_kind
                    && plan
                        .effect_key
                        .static_operands
                        .get("table")
                        .is_some_and(|table| table == "documents")
            }));
            let target = output
                .callable_effect_plans
                .iter()
                .find(|plan| {
                    plan.effect_key.operation_kind == expected_kind
                        && plan
                            .effect_key
                            .static_operands
                            .get("table")
                            .is_some_and(|table| table == "documents")
                        && plan.provenance.caller_callsite.is_some()
                })
                .map(|plan| {
                    (
                        plan.provenance.target_effect.module.clone(),
                        plan.provenance.target_effect.start,
                        plan.provenance.target_effect.end,
                    )
                })
                .expect("parameterized effect has no specialized semantic target");
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("{expected_kind} returned analysis output");
            };
            let target_operations = compiled
                .operations
                .iter()
                .filter(|operation| {
                    operation.file == target.0
                        && operation.start == target.1
                        && operation.end == target.2
                })
                .collect::<Vec<_>>();
            assert_eq!(
                target_operations.len(),
                1,
                "{expected_kind} target must have one plan-owned descriptor"
            );
            assert_eq!(target_operations[0].kind, expected_kind);
            assert_eq!(target_operations[0].table.as_deref(), Some("documents"));

            if expected_kind != "databaseNormalizeId" {
                let guest_source = with_test_registration_imports(source);
                let guest = compile_entry_in_effect_mode(
                    &guest_source,
                    "selected",
                    true,
                    super::EffectExecutionMode::GuestPromiseEventLoop,
                );
                assert!(
                    guest.eligible,
                    "guest {expected_kind}: {:#?}",
                    guest
                        .diagnostics
                        .iter()
                        .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                        .collect::<Vec<_>>()
                );
                let CompilerModeOutput::Compile(compiled) = guest.mode_output else {
                    panic!("guest {expected_kind} returned analysis output");
                };
                let generated = compiled
                    .generated_javascript_artifact
                    .expect("guest parameterized effect has no generated source")
                    .source
                    .expect("guest parameterized effect has no inline generated source");
                assert_eq!(
                    generated.matches("function __convexEffectSite_").count(),
                    1,
                    "{expected_kind}: {generated}"
                );
                assert_eq!(
                    generated
                        .matches("return __convexStartAsyncOperation(")
                        .count(),
                    1,
                    "{expected_kind}: {generated}"
                );
                assert!(
                    !generated.contains(&format!(
                        "ctx.db.{}",
                        match expected_kind {
                            "databaseGet" => "get",
                            "databaseInsert" => "insert",
                            "databasePatch" => "patch",
                            "databaseReplace" => "replace",
                            "databaseDelete" => "delete",
                            _ => unreachable!(),
                        }
                    )),
                    "{expected_kind}: {generated}"
                );
            }
        }
    }

    #[test]
    fn guest_plan_owned_effect_sites_admit_complete_helper_promise_all() {
        let source = with_test_registration_imports(
            r#"
async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
export const selected = query({
  args: { firstId: null, secondId: null },
  handler: async (ctx, args) => await Promise.all([
    load(ctx, "documents", args.firstId),
    load(ctx, "accounts", args.secondId),
  ]),
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        assert!(output.proved_direct_async_batches.is_empty());
        let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
            panic!("eligible helper aggregate returned analysis output");
        };
        assert!(compiled.direct_async_batches.is_empty());
        assert_eq!(
            compiled
                .operations
                .iter()
                .filter(|operation| operation.kind == "databaseGet")
                .count(),
            2
        );
        let generated = generated_source(&output);
        assert!(generated.contains("Promise.all"), "{generated}");
        assert!(!generated.contains("ctx.db.get"), "{generated}");
        assert!(
            !generated.contains("__convexAsyncFixedBatch"),
            "{generated}"
        );
    }

    #[test]
    fn guest_promise_all_requires_universal_helper_call_ownership() {
        let source = with_test_registration_imports(
            r#"
async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const selected = query({
  args: { ownedId: null, droppedId: null },
  handler: async (ctx, args) => {
    load(ctx, args.droppedId);
    return await Promise.all([load(ctx, args.ownedId)]);
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn guest_promise_all_admits_equivalent_inline_and_const_alias_helper_aggregates() {
        let aggregates = [
            (
                "inline",
                r#"return await Promise.all([
      follow(ctx, "documents", args.firstId),
      follow(ctx, "documents", args.secondId),
    ]);"#,
            ),
            (
                "const alias",
                r#"const children = [
      follow(ctx, "documents", args.firstId),
      follow(ctx, "documents", args.secondId),
    ];
    return await Promise.all(children);"#,
            ),
        ];
        let mut admitted_shapes = Vec::new();
        for (name, aggregate) in aggregates {
            let source = with_test_registration_imports(&format!(
                r#"
async function follow(ctx, table, id) {{
  const first = await ctx.db.get(table, id);
  return await ctx.db.get(table, id);
}}
export const selected = query({{
  args: {{ firstId: null, secondId: null }},
  handler: async (ctx, args) => {{
    {aggregate}
  }},
}});
"#,
            ));
            let output = compile_entry_in_effect_mode(
                &source,
                "selected",
                true,
                super::EffectExecutionMode::GuestPromiseEventLoop,
            );
            assert!(
                output.eligible,
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            assert!(output.proved_direct_async_batches.is_empty(), "{name}");
            let specialized = output
                .callable_effect_plans
                .iter()
                .filter(|plan| {
                    plan.provenance.caller_callsite.is_some()
                        && plan.effect_key.operation_kind == "databaseGet"
                        && plan
                            .effect_key
                            .static_operands
                            .get("table")
                            .is_some_and(|table| table == "documents")
                })
                .collect::<Vec<_>>();
            assert_eq!(specialized.len(), 4, "{name}: {specialized:#?}");
            let mut effects_by_callsite = BTreeMap::new();
            for plan in specialized {
                let callsite = plan
                    .provenance
                    .caller_callsite
                    .as_ref()
                    .expect("specialized aggregate effect lost its caller callsite");
                *effects_by_callsite
                    .entry((callsite.start, callsite.end))
                    .or_insert(0usize) += 1;
            }
            assert_eq!(effects_by_callsite.len(), 2, "{name}");
            assert!(
                effects_by_callsite.values().all(|effects| *effects == 2),
                "{name}: {effects_by_callsite:#?}"
            );
            let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
                panic!("{name}: eligible helper aggregate returned analysis output");
            };
            assert_eq!(
                compiled.effect_execution_mode,
                super::EffectExecutionMode::GuestPromiseEventLoop,
                "{name}"
            );
            assert!(compiled.direct_async_batches.is_empty(), "{name}");
            assert_eq!(
                compiled
                    .operations
                    .iter()
                    .filter(|operation| {
                        operation.kind == "databaseGet"
                            && operation.table.as_deref() == Some("documents")
                    })
                    .count(),
                2,
                "{name}"
            );
            let generated = generated_source(&output);
            assert!(generated.contains("Promise.all"), "{name}: {generated}");
            assert!(
                generated.contains("__convexGuestPromise.all"),
                "{name}: {generated}"
            );
            assert!(generated.contains("await"), "{name}: {generated}");
            assert!(!generated.contains("ctx.db.get"), "{name}: {generated}");
            assert!(
                generated.contains("__convexStartAsyncOperation("),
                "{name}: {generated}"
            );
            assert!(
                !generated.contains("__convexAsyncFixedBatch"),
                "{name}: {generated}"
            );
            assert!(
                !generated.contains("__convexAsyncBatch"),
                "{name}: {generated}"
            );
            admitted_shapes.push((
                compiled.operations.len(),
                effects_by_callsite.values().copied().collect::<Vec<_>>(),
            ));
        }
        assert_eq!(admitted_shapes[0], admitted_shapes[1]);
    }

    #[test]
    fn guest_promise_all_keeps_target_only_dependent_helper_operands_at_the_effect_site() {
        let aggregates = [
            (
                "inline",
                r#"return await Promise.all([
      follow(ctx, "documents", args.firstId),
      follow(ctx, "documents", args.secondId),
    ]);"#,
            ),
            (
                "const alias",
                r#"const children = [
      follow(ctx, "documents", args.firstId),
      follow(ctx, "documents", args.secondId),
    ];
    return await Promise.all(children);"#,
            ),
        ];
        for (name, aggregate) in aggregates {
            let source = with_test_registration_imports(&format!(
                r#"
async function follow(ctx, table, id) {{
  const first = await ctx.db.get(table, id);
  const second = await ctx.db.get(table, first.nextId);
  return second.marker;
}}
export const selected = query({{
  args: {{ firstId: null, secondId: null }},
  handler: async (ctx, args) => {{
    {aggregate}
  }},
}});
"#,
            ));
            let output = compile_entry_in_effect_mode(
                &source,
                "selected",
                true,
                super::EffectExecutionMode::GuestPromiseEventLoop,
            );
            assert!(
                output.eligible,
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let specialized = output
                .callable_effect_plans
                .iter()
                .filter(|plan| {
                    plan.provenance.caller_callsite.is_some()
                        && plan.effect_key.operation_kind == "databaseGet"
                        && plan
                            .effect_key
                            .static_operands
                            .get("table")
                            .is_some_and(|table| table == "documents")
                })
                .collect::<Vec<_>>();
            assert_eq!(specialized.len(), 4, "{name}: {specialized:#?}");
            let target_only = specialized
                .iter()
                .flat_map(|plan| &plan.dynamic_operands)
                .filter(|operand| operand.is_target_only())
                .collect::<Vec<_>>();
            assert_eq!(target_only.len(), 2, "{name}: {target_only:#?}");
            assert!(target_only.iter().all(|operand| {
                matches!(
                    operand.value,
                    super::effect_plan::SemanticOperand::RuntimeInput(0)
                ) && operand.consumer_provenance().is_none()
            }));
            assert!(
                specialized
                    .iter()
                    .flat_map(|plan| &plan.dynamic_operands)
                    .filter(|operand| !operand.is_target_only())
                    .all(|operand| operand.consumer_provenance().is_some()),
                "{name}: caller-projected operands lost their exact caller anchors"
            );
            let CompilerModeOutput::Compile(compiled) = &output.mode_output else {
                panic!("{name}: target-only helper fixture returned analysis output");
            };
            assert!(compiled.direct_async_batches.is_empty(), "{name}");
            assert_eq!(
                compiled
                    .operations
                    .iter()
                    .filter(|operation| {
                        operation.kind == "databaseGet"
                            && operation.table.as_deref() == Some("documents")
                    })
                    .count(),
                2,
                "{name}"
            );
            let generated = generated_source(&output);
            assert!(generated.contains("first.nextId"), "{name}: {generated}");
            assert!(!generated.contains("ctx.db.get"), "{name}: {generated}");
            assert!(
                generated.contains("__convexGuestPromise.all"),
                "{name}: {generated}"
            );
            assert!(
                generated.contains("__convexStartAsyncOperation("),
                "{name}: {generated}"
            );
            assert!(
                !generated.contains("__convexAsyncFixedBatch"),
                "{name}: {generated}"
            );
            assert!(
                !generated.contains("__convexAsyncBatch"),
                "{name}: {generated}"
            );

            let blocking = compile_entry_in_effect_mode(
                &source,
                "selected",
                true,
                super::EffectExecutionMode::BlockingFiber,
            );
            assert!(
                !blocking.eligible,
                "{name}: blocking unexpectedly admitted target-only operand"
            );
            assert!(
                blocking
                    .callable_effect_plans
                    .iter()
                    .flat_map(|plan| &plan.dynamic_operands)
                    .all(|operand| !operand.is_target_only()),
                "{name}: blocking built a target-only plan"
            );
        }
    }

    #[test]
    fn guest_specialization_keeps_generic_target_only_expressions_at_the_effect_site() {
        let source = with_test_registration_imports(
            r#"
async function follow(ctx, table, id) {
  const chosen = id ?? id;
  return await ctx.db.get(table, chosen);
}
export const selected = query({
  args: { firstId: null, secondId: null },
  handler: async (ctx, args) => await Promise.all([
    follow(ctx, "documents", args.firstId),
    follow(ctx, "documents", args.secondId),
  ]),
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let target_only = output
            .callable_effect_plans
            .iter()
            .filter(|plan| plan.provenance.caller_callsite.is_some())
            .flat_map(|plan| &plan.dynamic_operands)
            .filter(|operand| operand.is_target_only())
            .collect::<Vec<_>>();
        assert_eq!(target_only.len(), 2, "{target_only:#?}");
        assert!(target_only.iter().all(|operand| {
            matches!(
                operand.value,
                super::effect_plan::SemanticOperand::RuntimeInput(0)
            ) && operand.consumer_provenance().is_none()
        }));
        let generated = generated_source(&output);
        assert!(generated.contains("id ?? id"), "{generated}");
        assert!(!generated.contains("ctx.db.get"), "{generated}");
    }

    #[test]
    fn guest_promise_all_const_alias_requires_immediate_awaited_handoff() {
        let source = with_test_registration_imports(
            r#"
async function load(ctx, id) {
  return await ctx.db.get("documents", id);
}
export const selected = query({
  args: { firstId: null, secondId: null },
  handler: async (ctx, args) => {
    const children = [load(ctx, args.firstId), load(ctx, args.secondId)];
    const marker = args.firstId;
    return await Promise.all(children);
  },
});
"#,
        );
        assert!(summary(&source).promise_all_alias_handoffs.is_empty());
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn guest_promise_all_const_alias_rejects_extra_references_mutation_and_escape() {
        for (name, tail) in [
            ("extra reference", "void children;"),
            ("mutation", "children[0] = null;"),
            ("escape", "consume(children);"),
        ] {
            let source = with_test_registration_imports(&format!(
                r#"
async function load(ctx, id) {{
  return await ctx.db.get("documents", id);
}}
function consume(_value) {{
  return null;
}}
export const selected = query({{
  args: {{ firstId: null, secondId: null }},
  handler: async (ctx, args) => {{
    const children = [load(ctx, args.firstId), load(ctx, args.secondId)];
    await Promise.all(children);
    {tail}
    return null;
  }},
}});
"#,
            ));
            assert_eq!(
                summary(&source).promise_all_alias_handoffs.len(),
                1,
                "{name} must retain the immediate awaited handoff"
            );
            let output = compile_entry_in_effect_mode(
                &source,
                "selected",
                true,
                super::EffectExecutionMode::GuestPromiseEventLoop,
            );
            assert_guest_effect_is_rejected_without_lowering(&output);
        }
    }

    #[test]
    fn guest_promise_mode_rejects_direct_effect_fixed_promise_all() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: { firstId: null, secondId: null },
  handler: async (ctx, args) => await Promise.all([
    ctx.db.get("documents", args.firstId),
    ctx.db.get("documents", args.secondId),
  ]),
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(output.proved_direct_async_batches.is_empty());
        assert_guest_effect_is_rejected_without_lowering(&output);
    }

    #[test]
    fn guest_effect_sites_rewrite_inside_branches_switches_and_loops() {
        let source = with_test_registration_imports(
            r#"
export const selected = mutation({
  args: { ids: v.array(null), kind: v.string(), value: null },
  handler: async (ctx, args) => {
    let result = null;
    for (let index = 0; index < args.ids.length; index += 1) {
      if (index % 2 === 0) {
        result = await ctx.db.get("documents", args.ids[index]);
      } else {
        result = await ctx.db.get("accounts", args.ids[index]);
      }
    }
    switch (args.kind) {
      case "patch":
        await ctx.db.patch("documents", args.ids[0], args.value);
        break;
      default:
        await ctx.db.replace("documents", args.ids[0], args.value);
    }
    return result;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("guest control-shape fixture returned analysis output");
        };
        let generated = compiled
            .generated_javascript_artifact
            .expect("guest control-shape fixture has no generated source")
            .source
            .expect("guest control-shape fixture has no inline generated source");
        assert!(!generated.contains("ctx.db."), "{generated}");
        assert_eq!(
            generated.matches("function __convexEffectSite_").count(),
            4,
            "{generated}"
        );
        assert!(generated.contains("for (let index = 0;"), "{generated}");
        assert!(generated.contains("switch (args.kind)"), "{generated}");
    }

    #[test]
    fn guest_query_take_preserves_the_authenticated_builder_source() {
        let source = with_test_registration_imports(
            r#"
async function loadByOwner(ctx, owner) {
  const rows = await ctx.db
    .query("documents")
    .withIndex("by_owner", (q) => q.eq("owner", owner))
    .take(2);
  return rows.filter((row) => row.owner === owner);
}
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => {
    const rows = await loadByOwner(ctx, args.owner);
    return rows.length;
  },
});
"#,
        );
        let module = summary(&source);
        assert!(
            module.callable_leaf_plans.iter().any(|candidate| matches!(
                &candidate.control,
                super::callable_plans::CallableLeafControlCandidate::Effect(effect)
                    if effect.operation.kind == "db.query"
            )),
            "guest index query has no callable candidate: {}",
            serde_json::to_string_pretty(&module.callable_leaf_plans).unwrap()
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output
                .callable_effect_plans
                .iter()
                .any(|plan| { plan.effect_key.operation_kind == "databaseIndexQuery" }),
            "guest index query has no semantic callable plan: {:#?}",
            output.callable_effect_plans
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("guest index-query fixture returned analysis output");
        };
        let operation = compiled
            .operations
            .iter()
            .find(|operation| operation.kind == "databaseIndexQuery")
            .expect("guest index-query fixture has no operation descriptor");
        assert_eq!(operation.limit, Some(2));
        let generated = compiled
            .generated_javascript_artifact
            .expect("guest index-query fixture has no generated source")
            .source
            .expect("guest index-query fixture has no inline generated source");
        assert!(generated.contains("ctx.db"), "{generated}");
        assert!(generated.contains(".query(\"documents\")"), "{generated}");
        assert!(generated.contains(".withIndex("), "{generated}");
        assert!(generated.contains(".take(2)"), "{generated}");
        assert!(!generated.contains("__convexEffectSite_"), "{generated}");
        assert!(generated.contains("await loadByOwner"), "{generated}");
    }

    #[test]
    fn guest_native_paginate_allows_dynamic_destructured_result_consumers() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: {
    cursorField: null,
    documentField: null,
    owner: null,
    paginationOpts: null,
  },
  handler: async (ctx, args) => {
    const result = await ctx.db
      .query("documents")
      .withIndex("by_owner", (q) => q.eq("owner", args.owner))
      .order("desc")
      .paginate(args.paginationOpts);
    const { page, ...metadata } = result;
    return {
      continueCursor: metadata[args.cursorField],
      isDone: result.isDone,
      page: page.map((document) => document[args.documentField]),
    };
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("guest paginate fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        let operation = compiled
            .operations
            .iter()
            .find(|operation| operation.kind == "databaseIndexQuery")
            .expect("guest paginate fixture has no query operation");
        assert_eq!(operation.order.as_deref(), Some("descending"));
        assert_eq!(operation.terminal.as_deref(), Some("paginate"));
        assert_eq!(operation.limit, None);
        assert_eq!(operation.limit_argument_index, None);
        assert!(
            compiled.document_properties.is_empty(),
            "guest-native pagination inferred document properties: {}",
            serde_json::to_string_pretty(&compiled.document_properties).unwrap()
        );
        let generated = compiled
            .generated_javascript_artifact
            .expect("guest paginate fixture has no generated source")
            .source
            .expect("guest paginate fixture has no inline generated source");
        assert!(
            generated.contains(".paginate(args.paginationOpts)"),
            "{generated}"
        );
        assert!(generated.contains("const { page, ...metadata } = result"));
        assert!(generated.contains("metadata[args.cursorField]"));
        assert!(generated.contains("document[args.documentField]"));
    }

    #[test]
    fn paginate_uses_guest_native_page_and_metadata_values() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: { owner: null, paginationOpts: null },
  handler: async (ctx, args) => {
    const result = await ctx.db
      .query("documents")
      .withIndex("by_owner", (q) => q.eq("owner", args.owner))
      .paginate(args.paginationOpts);
    return {
      isDone: result.isDone,
      page: result.page.map((document) => document.name),
    };
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("pagination value-mode fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        assert!(compiled.document_properties.is_empty());
    }

    #[test]
    fn guest_query_value_stream_preserves_builder_control_and_document_provenance() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: { owner: null, activeAfter: null },
  handler: async (ctx, args) => {
    const planned = ctx.db
      .query("documents")
      .withIndex("by_owner_active", (range) =>
        range.eq("owner", args.owner).gte("activeAt", args.activeAfter),
      );
    for await (const row of planned) {
      if (row.enabled) return row.name;
    }
    return null;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("query-value stream fixture returned analysis output");
        };
        let stream = compiled
            .operations
            .iter()
            .filter(|operation| {
                operation.kind == "databaseIndexQuery"
                    && operation.terminal.as_deref() == Some("stream")
            })
            .collect::<Vec<_>>();
        assert_eq!(stream.len(), 1);
        assert_eq!(
            stream[0]
                .index_constraints
                .iter()
                .map(|constraint| constraint.value_source.as_str())
                .collect::<Vec<_>>(),
            vec!["args.owner", "args.activeAfter"]
        );
        assert!(
            compiled
                .document_properties
                .iter()
                .all(|property| { property.property != "enabled" && property.property != "name" })
        );
        let generated = compiled
            .generated_javascript_artifact
            .expect("query-value stream fixture has no generated source")
            .source
            .expect("query-value stream fixture has no inline generated source");
        assert!(generated.contains(".query(\"documents\")"), "{generated}");
        assert!(
            generated.contains("for await (const row of planned)"),
            "{generated}"
        );
        assert!(!generated.contains("__convexEffectSite_"), "{generated}");
    }

    #[test]
    fn guest_query_builder_graph_forwards_two_sources_to_one_helper_stream() {
        let source = with_test_registration_imports(
            r#"
async function enabledName(candidates) {
  for await (const row of candidates) {
    if (row.enabled) return row.name;
  }
  return null;
}
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => {
    const current = await enabledName(
      ctx.db
        .query("documents")
        .withIndex("by_owner", (range) => range.eq("owner", args.owner)),
    );
    const archived = await enabledName(
      ctx.db
        .query("archivedDocuments")
        .withIndex("by_owner", (range) => range.eq("owner", args.owner)),
    );
    return current === null ? archived : current;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("transitive query-builder fixture returned analysis output");
        };
        let streams = compiled
            .operations
            .iter()
            .filter(|operation| {
                operation.kind == "databaseIndexQuery"
                    && operation.terminal.as_deref() == Some("stream")
            })
            .collect::<Vec<_>>();
        assert_eq!(streams.len(), 2);
        assert_eq!(
            streams
                .iter()
                .filter_map(|operation| operation.table.as_deref())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["archivedDocuments", "documents"])
        );
        assert_eq!(
            streams
                .iter()
                .map(|operation| (operation.start, operation.end))
                .collect::<BTreeSet<_>>()
                .len(),
            1,
            "both source authorizations must converge on one helper consumer"
        );
        assert!(
            compiled
                .document_properties
                .iter()
                .all(|property| { property.property != "enabled" && property.property != "name" })
        );
    }

    #[test]
    fn guest_query_builder_graph_materializes_correlated_range_variants() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: { owner: null, activeAfter: null },
  handler: async (ctx, args) => {
    const rows = await ctx.db
      .query("documents")
      .withIndex("by_owner_active", (range) => {
        const owned = range.eq("owner", args.owner);
        return args.activeAfter === null
          ? owned
          : owned.gte("activeAt", args.activeAfter);
      })
      .order("asc")
      .take(2);
    return rows.length;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("conditional query-builder fixture returned analysis output");
        };
        let mut variants = compiled
            .operations
            .iter()
            .filter(|operation| {
                operation.kind == "databaseIndexQuery"
                    && operation.table.as_deref() == Some("documents")
                    && operation.terminal.as_deref() == Some("collect")
            })
            .map(|operation| {
                operation
                    .index_constraints
                    .iter()
                    .map(|constraint| format!("{}:{}", constraint.field, constraint.operator))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect::<Vec<_>>();
        variants.sort();
        assert_eq!(variants, vec!["owner:eq", "owner:eq,activeAt:gte"],);
    }

    #[test]
    fn guest_query_value_stream_rejects_a_shadowed_context_provider() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: {},
  handler: async (_ctx) => {
    const ctx = {
      db: {
        query: () => ({
          withIndex: () => ({
            async *[Symbol.asyncIterator]() { yield { enabled: true }; },
          }),
        }),
      },
    };
    const planned = ctx.db.query("documents").withIndex("by_owner");
    for await (const row of planned) {
      if (row.enabled) return true;
    }
    return false;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(!output.eligible);
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("shadowed query-value stream returned analysis output");
        };
        assert!(!compiled.operations.iter().any(|operation| {
            operation.kind == "databaseIndexQuery"
                && operation.terminal.as_deref() == Some("stream")
        }));
    }

    #[test]
    fn guest_query_stream_propagates_an_exact_nullable_assignment() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => {
    const planned = ctx.db
      .query("documents")
      .withIndex("by_owner", (range) => range.eq("owner", args.owner));
    let saved = null;
    for await (const row of planned) {
      saved = row;
      break;
    }
    return saved === null ? false : saved.enabled;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("query stream assignment fixture returned analysis output");
        };
        assert!(
            compiled
                .document_properties
                .iter()
                .all(|property| property.property != "enabled")
        );
    }

    #[test]
    fn guest_native_query_stream_allows_ordinary_container_flow() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => {
    const planned = ctx.db
      .query("documents")
      .withIndex("by_owner", (range) => range.eq("owner", args.owner));
    const rows = [];
    for await (const row of planned) {
      rows.push(row);
      break;
    }
    return rows[0].enabled;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("query stream container fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
        let generated = compiled
            .generated_javascript_artifact
            .expect("query stream container fixture has no generated source")
            .source
            .expect("query stream container fixture has no inline generated source");
        assert!(generated.contains("for await (const row of planned)"));
        assert!(generated.contains("rows.push(row)"));
    }

    #[test]
    fn guest_bound_query_collect_propagates_document_elements_through_array_callbacks() {
        let source = with_test_registration_imports(
            r#"
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => {
    const planned = ctx.db
      .query("documents")
      .withIndex("by_owner", (range) => range.eq("owner", args.owner));
    const rows = await planned.collect();
    return rows.map((row) => row.enabled);
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("query collect result-flow fixture returned analysis output");
        };
        assert_eq!(compiled.value_mode, super::ValueMode::Opaque);
        assert!(compiled.operations.iter().any(|operation| {
            operation.kind == "databaseIndexQuery"
                && operation.terminal.as_deref() == Some("collect")
        }));
        assert!(
            compiled.document_properties.iter().any(|property| {
                property.table == "documents" && property.property == "enabled"
            })
        );
        let generated = compiled
            .generated_javascript_artifact
            .expect("query collect result-flow fixture has no generated source")
            .source
            .expect("query collect result-flow fixture has no inline generated source");
        assert!(generated.contains("await planned.collect()"), "{generated}");
        assert!(
            generated.contains("__convexMarkArray(rows.map((row) => row.enabled))"),
            "{generated}"
        );
    }

    #[test]
    fn guest_query_take_propagates_arrays_through_alias_helpers_filter_map_and_for_of() {
        let source = with_test_registration_imports(
            r#"
function activeNames(input) {
  const rows = input;
  const active = rows.filter((row) => row.enabled);
  const names = active.map((row) => row.name);
  let totalLength = 0;
  for (const name of names) {
    totalLength += name.length;
  }
  return totalLength;
}
export const selected = query({
  args: { owner: null, limit: null },
  handler: async (ctx, args) => {
    const planned = ctx.db
      .query("documents")
      .withIndex("by_owner", (range) => range.eq("owner", args.owner));
    const rows = await planned.take(args.limit);
    return activeNames(rows);
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("query take result-flow fixture returned analysis output");
        };
        let operation = compiled
            .operations
            .iter()
            .find(|operation| {
                operation.kind == "databaseIndexQuery"
                    && operation.terminal.as_deref() == Some("collect")
                    && operation.limit_argument_index.is_some()
            })
            .expect("query take result-flow fixture has no operation descriptor");
        assert_eq!(operation.limit, None);
        assert_eq!(operation.limit_argument_index, Some(1));
        assert!(
            compiled
                .document_properties
                .iter()
                .all(|property| { property.property != "enabled" && property.property != "name" })
        );
        let generated = compiled
            .generated_javascript_artifact
            .expect("query take result-flow fixture has no generated source")
            .source
            .expect("query take result-flow fixture has no inline generated source");
        assert!(
            generated.contains("planned.take(args.limit)"),
            "{generated}"
        );
        assert!(generated.contains("activeNames(rows)"), "{generated}");
        assert!(generated.contains("rows.filter((row) => row.enabled)"));
        assert!(generated.contains("for (const name of names)"));
    }

    #[test]
    fn authenticated_query_take_proves_repair_loop_results_in_both_effect_modes() {
        let source = with_test_registration_imports(
            r#"
export const selected = mutation({
  args: { now: null, limit: null },
  handler: async (ctx, args) => {
    const rows = await ctx.db
      .query("documents")
      .withIndex("by_status_deadline", (q) =>
        q.eq("status", "running").lte("deadline", args.now)
      )
      .take(args.limit);
    for (const operation of rows) {
      await ctx.db.patch("documents", operation._id, {
        status: "pending",
        deadline: undefined,
        message:
          operation.remoteRequestStartedAt === undefined
            ? "A prepared attempt will retry."
            : "A started attempt will recover.",
        updatedAt: args.now,
      });
    }
    return rows.length;
  },
});
"#,
        );
        for effect_execution_mode in [
            super::EffectExecutionMode::GuestPromiseEventLoop,
            super::EffectExecutionMode::BlockingFiber,
        ] {
            let output =
                compile_entry_in_effect_mode(&source, "selected", true, effect_execution_mode);
            assert!(
                output.eligible,
                "{effect_execution_mode:?}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("{effect_execution_mode:?} repair-loop fixture returned analysis output");
            };
            let query = compiled
                .operations
                .iter()
                .find(|operation| operation.kind == "databaseIndexQuery")
                .expect("repair-loop fixture has no query descriptor");
            assert_eq!(query.table.as_deref(), Some("documents"));
            assert_eq!(query.index.as_deref(), Some("by_status_deadline"));
            assert_eq!(query.order.as_deref(), Some("ascending"));
            assert_eq!(query.terminal.as_deref(), Some("collect"));
            assert_eq!(query.limit, None);
            assert_eq!(query.limit_argument_index, Some(2));
            assert_eq!(query.index_constraints.len(), 2);
            assert_eq!(
                compiled
                    .operations
                    .iter()
                    .filter(|operation| operation.kind == "databasePatch")
                    .count(),
                1
            );
            for property in ["_id", "remoteRequestStartedAt"] {
                let present = compiled
                    .document_properties
                    .iter()
                    .any(|document_property| {
                        document_property.table == "documents"
                            && document_property.property == property
                    });
                if effect_execution_mode == super::EffectExecutionMode::BlockingFiber {
                    assert!(
                        present,
                        "{effect_execution_mode:?} did not authenticate {property}"
                    );
                } else {
                    assert!(
                        !present,
                        "guest-native document-property inference still admitted {property}"
                    );
                }
            }
            let generated = compiled
                .generated_javascript_artifact
                .expect("repair-loop fixture has no generated source")
                .source
                .expect("repair-loop fixture has no inline generated source");
            assert!(generated.contains("rows.length"), "{generated}");
            if effect_execution_mode == super::EffectExecutionMode::BlockingFiber {
                assert!(
                    !generated.contains("for (const operation of rows)"),
                    "{generated}"
                );
                assert!(generated.contains("let __convexForOfArray_"), "{generated}");
                assert!(!generated.contains("await "), "{generated}");
            } else {
                assert!(
                    generated.contains("for (const operation of rows)"),
                    "{generated}"
                );
            }
        }
    }

    #[test]
    fn guest_query_first_result_flows_through_helper_return_and_projection() {
        let source = with_test_registration_imports(
            r#"
async function loadFirst(ctx, owner) {
  return await ctx.db
    .query("documents")
    .withIndex("by_owner", (range) => range.eq("owner", owner))
    .first();
}
function selectedName(row) {
  if (row === null) return null;
  const alias = row;
  return alias.name;
}
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => selectedName(await loadFirst(ctx, args.owner)),
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("query first result-flow fixture returned analysis output");
        };
        assert!(compiled.operations.iter().any(|operation| {
            operation.kind == "databaseIndexQuery" && operation.terminal.as_deref() == Some("first")
        }));
        assert!(
            compiled
                .document_properties
                .iter()
                .any(|property| { property.table == "documents" && property.property == "name" })
        );
        let generated = compiled
            .generated_javascript_artifact
            .expect("query first result-flow fixture has no generated source")
            .source
            .expect("query first result-flow fixture has no inline generated source");
        assert!(generated.contains(".first()"), "{generated}");
        assert!(
            generated.contains("selectedName(await loadFirst"),
            "{generated}"
        );
    }

    #[test]
    fn guest_query_stream_document_flows_through_an_exact_helper_parameter() {
        let source = with_test_registration_imports(
            r#"
function enabledName(row) {
  return row.enabled ? row.name : null;
}
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => {
    const planned = ctx.db
      .query("documents")
      .withIndex("by_owner", (range) => range.eq("owner", args.owner));
    for await (const row of planned) {
      const name = enabledName(row);
      if (name !== null) return name;
    }
    return null;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("query stream helper-flow fixture returned analysis output");
        };
        assert!(
            compiled
                .document_properties
                .iter()
                .all(|property| { property.property != "enabled" && property.property != "name" })
        );
        let generated = compiled
            .generated_javascript_artifact
            .expect("query stream helper-flow fixture has no generated source")
            .source
            .expect("query stream helper-flow fixture has no inline generated source");
        assert!(generated.contains("enabledName(row)"), "{generated}");
        assert!(
            generated.contains("for await (const row of planned)"),
            "{generated}"
        );
    }

    #[test]
    fn guest_query_result_flow_preserves_computed_document_access_and_array_mutation() {
        for (name, terminal, body, legacy_body, preserved_fragment) in [
            (
                "computed document property",
                "first()",
                "return { marker: marker.size, value: row === null ? null : row[args.field] };",
                "return row === null ? null : row[args.field];",
                "row[args.field]",
            ),
            (
                "collection mutation",
                "collect()",
                "rows.push({ enabled: true }); return { length: rows.length, marker: marker.size };",
                "rows.push({ enabled: true }); return rows.length;",
                "rows.push(",
            ),
        ] {
            let binding = if terminal == "first()" {
                "const row"
            } else {
                "const rows"
            };
            let source = with_test_registration_imports(&format!(
                r#"
export const selected = query({{
  args: {{ owner: null, field: null }},
  handler: async (ctx, args) => {{
    const marker = new Map();
    marker.set("query-result", true);
    const planned = ctx.db
      .query("documents")
      .withIndex("by_owner", (range) => range.eq("owner", args.owner));
    {binding} = await planned.{terminal};
    {body}
  }},
}});
"#,
            ));
            let output = compile_entry_in_effect_mode(
                &source,
                "selected",
                true,
                super::EffectExecutionMode::GuestPromiseEventLoop,
            );
            assert!(
                output.eligible,
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("{name} returned analysis output");
            };
            assert_eq!(compiled.value_mode, super::ValueMode::GuestNativeJson);
            assert!(
                compiled.document_properties.is_empty(),
                "{name} inferred document properties: {}",
                serde_json::to_string_pretty(&compiled.document_properties).unwrap()
            );
            let generated = compiled
                .generated_javascript_artifact
                .expect("query-result consumer fixture has no generated source")
                .source
                .expect("query-result consumer fixture has no inline generated source");
            assert!(
                generated.contains(preserved_fragment),
                "{name}: {generated}"
            );

            let legacy_source = source
                .replace(
                    "    const marker = new Map();\n    marker.set(\"query-result\", true);\n",
                    "",
                )
                .replace(body, legacy_body);
            for legacy_mode in [
                super::EffectExecutionMode::GuestPromiseEventLoop,
                super::EffectExecutionMode::BlockingFiber,
            ] {
                let legacy_output =
                    compile_entry_in_effect_mode(&legacy_source, "selected", true, legacy_mode);
                assert!(!legacy_output.eligible, "{name}: {legacy_mode:?}");
                assert!(
                    legacy_output
                        .diagnostics
                        .iter()
                        .any(|diagnostic| { diagnostic.code == "unsupported-query-result-flow" }),
                    "{name}: {legacy_mode:?}: {:#?}",
                    legacy_output
                        .diagnostics
                        .iter()
                        .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn guest_query_take_preserves_a_dynamic_limit_after_constraints() {
        let source = with_test_registration_imports(
            r#"
async function loadByOwner(ctx, owner, limit) {
  return await ctx.db
    .query("documents")
    .withIndex("by_owner", (q) => q.eq("owner", owner))
    .take(limit);
}
export const selected = query({
  args: { owner: null, limit: null },
  handler: async (ctx, args) => {
    const rows = await loadByOwner(ctx, args.owner, args.limit + 1);
    return rows.length;
  },
});
"#,
        );
        let output = compile_entry_in_effect_mode(
            &source,
            "selected",
            true,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("dynamic-limit index-query fixture returned analysis output");
        };
        let operation = compiled
            .operations
            .iter()
            .find(|operation| operation.kind == "databaseIndexQuery")
            .expect("dynamic-limit fixture has no index-query descriptor");
        assert_eq!(operation.limit, None);
        assert_eq!(operation.limit_argument_index, Some(1));
        assert_eq!(operation.index_constraints.len(), 1);
        let generated = compiled
            .generated_javascript_artifact
            .expect("dynamic-limit fixture has no generated source")
            .source
            .expect("dynamic-limit fixture has no inline generated source");
        assert!(generated.contains(".query(\"documents\")"), "{generated}");
        assert!(generated.contains(".withIndex("), "{generated}");
        assert!(generated.contains(".take(limit)"), "{generated}");
        assert!(!generated.contains("__convexEffectSite_"), "{generated}");
        assert!(
            generated.contains("loadByOwner(ctx, args.owner, args.limit + 1)"),
            "{generated}"
        );
    }

    #[test]
    fn guest_query_result_plan_preserves_static_terminal_source() {
        for terminal in ["collect()", "first()", "unique()", "take(2)"] {
            let source = with_test_registration_imports(&format!(
                r#"
async function loadByOwner(ctx, owner) {{
  return await ctx.db
    .query("documents")
    .withIndex("by_owner", (q) => q.eq("owner", owner))
    .{terminal};
}}
export const selected = query({{
  args: {{ owner: null }},
  handler: async (ctx, args) => await loadByOwner(ctx, args.owner),
}});
"#
            ));
            let output = compile_entry_in_effect_mode(
                &source,
                "selected",
                true,
                super::EffectExecutionMode::GuestPromiseEventLoop,
            );
            assert!(
                output.eligible,
                "{terminal}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("{terminal} returned analysis output");
            };
            let generated = compiled
                .generated_javascript_artifact
                .expect("static-terminal fixture has no generated source")
                .source
                .expect("static-terminal fixture has no inline generated source");
            assert!(
                generated.contains(".query(\"documents\")"),
                "{terminal}: {generated}"
            );
            assert!(generated.contains(".withIndex("), "{terminal}: {generated}");
            assert!(generated.contains(terminal), "{terminal}: {generated}");
            assert!(
                !generated.contains("__convexEffectSite_"),
                "{terminal}: {generated}"
            );
        }
    }

    #[test]
    fn callable_plan_representation_does_not_authorize_a_reconstructed_capability() {
        let output = compile(
            r#"async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
export const selected = query({
  args: {},
  handler: async (ctx, args) =>
    await load({ db: ctx.db }, "documents", args.id),
});"#,
            "selected",
        );

        assert!(!output.eligible);
        assert!(output.callable_effect_plans.iter().any(|plan| {
            plan.effect_key.operation_kind == "databaseGet"
                && plan
                    .effect_key
                    .static_operands
                    .get("table")
                    .is_some_and(|table| table == "documents")
        }));
        assert!(output.diagnostics.iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "unsupported-convex-effect" | "mixed-capability-callsite"
            )
        }));
    }

    #[test]
    fn incomplete_leaf_dispatch_cannot_specialize_a_literal_call() {
        let output = compile(
            r#"async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
const escaped = [load];
export const selected = query({
  args: {},
  handler: async (ctx, args) => {
    if (escaped.length === 0) throw new Error("unreachable");
    return await load(ctx, "documents", args.id);
  },
});"#,
            "selected",
        );

        assert!(!output.eligible);
        assert!(output.callable_effect_plans.iter().all(|plan| {
            plan.effect_key
                .static_operands
                .get("table")
                .is_none_or(|table| table != "documents")
        }));
    }

    #[test]
    fn unreachable_sibling_callable_reference_does_not_poison_exact_dispatch() {
        let output = compile_with_import(
            r#"
import { load } from "./helper";
export const selected = query({
  args: {},
  handler: async (ctx, args) => await load(ctx, "documents", args.id),
});
"#,
            r#"
export async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
export async function unusedSibling(ctx, table, id) {
  return await load(ctx, table, id);
}
"#,
            "selected",
        );

        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("reachable helper with an unreachable sibling returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| (operation.kind.as_str(), operation.table.as_deref()))
                .collect::<Vec<_>>(),
            vec![("databaseGet", Some("documents"))]
        );
    }

    #[test]
    fn unreachable_sibling_registration_reference_does_not_poison_exact_dispatch() {
        let output = compile_with_import(
            r#"
import { load } from "./helper";
export const unused = query({
  args: {},
  handler: async (ctx, args) => await load(ctx, "unusedDocuments", args.id),
});
export const selected = query({
  args: {},
  handler: async (ctx, args) => await load(ctx, "documents", args.id),
});
"#,
            r#"
export async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
"#,
            "selected",
        );

        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("reachable helper with an unreachable registration returned analysis output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| (operation.kind.as_str(), operation.table.as_deref()))
                .collect::<Vec<_>>(),
            vec![("databaseGet", Some("documents"))]
        );
    }

    #[test]
    fn ambiguous_forwarded_static_values_do_not_choose_a_callable_plan() {
        let output = compile(
            r#"async function load(ctx, table, id) {
  return await ctx.db.get(table, id);
}
async function forward(ctx, table, id) {
  return await load(ctx, table, id);
}
export const selected = query({
  args: {},
  handler: async (ctx, args) => await Promise.all([
    forward(ctx, "documents", args.first),
    forward(ctx, "accounts", args.second),
  ]),
});"#,
            "selected",
        );

        assert!(!output.eligible);
        assert!(output.callable_effect_plans.iter().all(|plan| {
            plan.provenance.target_effect.module != "convex/fixture.ts"
                || !matches!(
                    plan.effect_key
                        .static_operands
                        .get("table")
                        .map(String::as_str),
                    Some("documents" | "accounts")
                )
        }));
    }

    #[test]
    fn fixed_promise_all_lowers_one_direct_effect_helper_continuation_after_the_join() {
        let source = r#"
function requireOwned(value, id) {
  if (value === null || value._id !== id) throw new Error("wrong document");
}
function project(value, suffix) {
  return { id: value._id, label: value.label + suffix };
}
async function load(ctx, id, suffix) {
  const value = await ctx.db.get("documents", id);
  requireOwned(value, id);
  return project(value, suffix);
}
export const fixedContinuationBatch = query({
  args: { first: null, second: null, suffix: null },
  handler: async (ctx, args) => await Promise.all([
    load(ctx, args.first, args.suffix),
    ctx.db.get("documents", args.second),
  ]),
});
"#;
        let output = compile(source, "fixedContinuationBatch");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("fixed helper continuation returned analysis output");
        };
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("fixed helper continuation generated inline JavaScript");
        assert!(generated.contains("__convexAsyncFixedBatch(["));
        assert!(generated.contains("__convexBatchResults_"));
        assert!(generated.contains("requireOwned(value, id)"));
        assert!(generated.contains("return project(value, suffix)"));
        assert!(generated.contains("return __convexMarkArray(["));
        assert!(!generated.contains("Promise.all("));
        assert!(!generated.contains("await "));
    }

    #[test]
    fn fixed_promise_all_helper_reuses_one_argument_for_compound_effect_arguments() {
        let source = r#"
async function load(ctx, activity) {
  const value = await ctx.db
    .query("documents")
    .withIndex("by_activity", (q) =>
      q.eq("activityId", activity.activityId).eq("activatedAt", activity.activatedAt)
    )
    .unique();
  if (value !== null && value.owner !== activity.owner) throw new Error("wrong owner");
  return value;
}
export const fixedCompoundHelperBatch = query({
  args: { activityId: null, activatedAt: null, owner: null, otherId: null },
  handler: async (ctx, args) => await Promise.all([
    load(ctx, args),
    ctx.db.get("documents", args.otherId),
  ]),
});
"#;
        let output = compile(source, "fixedCompoundHelperBatch");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let super::ProvedDirectAsyncBatchShape::FixedEffectArray {
            children: proved_children,
        } = &output.proved_direct_async_batches[0].shape
        else {
            panic!("compound helper batch changed proof kind");
        };
        assert!(proved_children[0].helper_continuation_prebound);
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("compound helper batch returned analysis output");
        };
        let super::DirectAsyncBatchAuthorizationShape::FixedEffectArray { children } =
            &compiled.direct_async_batches[0].shape
        else {
            panic!("compound helper batch changed authorization kind");
        };
        assert_eq!(children[0].helper_dynamic_argument_indices, vec![1, 1]);
        assert!(children[0].helper_continuation_prebound);
        assert_eq!(children[0].dynamic_arguments.len(), 2);
        assert_eq!(
            children[0].dynamic_arguments[0].source_start,
            children[0].dynamic_arguments[1].source_start
        );
        let continuation = children[0]
            .helper_continuation
            .as_ref()
            .expect("compound helper lost its continuation");
        assert_eq!(continuation.generated_effect_arguments.len(), 2);

        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("compound helper batch generated inline JavaScript");
        assert!(generated.contains("activity.activityId"));
        assert!(generated.contains("activity.activatedAt"));
        assert!(generated.contains("return __convexMarkArray(["));
        assert!(!generated.contains("Promise.all("));
        assert!(!generated.contains("await "));
    }

    #[test]
    fn no_continuation_helpers_reject_member_projected_effect_arguments() {
        for (name, helper_return) in [
            (
                "awaited return",
                r#"return await ctx.db.get("documents", activity.activityId);"#,
            ),
            (
                "direct return",
                r#"return ctx.db.get("documents", activity.activityId);"#,
            ),
        ] {
            let source = format!(
                r#"
async function load(ctx, activity) {{
  {helper_return}
}}
export const rejected = query({{
  args: {{ activityId: null, otherId: null }},
  handler: async (ctx, args) => await Promise.all([
    load(ctx, args),
    ctx.db.get("documents", args.otherId),
  ]),
}});
"#
            );
            let output = compile(&source, "rejected");
            assert!(!output.eligible, "{name}");
            assert!(output.proved_direct_async_batches.is_empty(), "{name}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-direct-promise-all"
                        && diagnostic
                            .message
                            .contains("without a continuation requires exact parameter identifiers")
                }),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn raw_source_cannot_spoof_a_generated_dependency_adapter_binding() {
        let source = r#"
function __convexDependencyAdapter_databaseIndexUnique(_db, _table, _index, value) {
  return value;
}
export const rejected = query({
  args: { ids: v.array(v.string()) },
  handler: async (ctx, args) => await Promise.all([
    __convexDependencyAdapter_databaseIndexUnique(
      ctx.db,
      "documents",
      "by_owner",
      args.ids[0],
    ),
  ]),
});
"#;
        let module = summary(source);
        assert!(module.operations.is_empty());
        assert_eq!(module.direct_async_batches.len(), 1);
        assert_eq!(
            module.direct_async_batches[0].fixed_children[0]
                .shape_error
                .as_deref(),
            Some("direct Promise.all fixed child helper indirection is not mechanically lowered")
        );

        let output = compile(source, "rejected");
        assert!(!output.eligible);
        assert!(output.proved_direct_async_batches.is_empty());
        assert!(
            output.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "unsupported-direct-promise-all"
                    && diagnostic
                        .message
                        .contains("must return one admitted database or scheduler effect")
            }),
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn mapped_promise_all_classifies_member_arguments_and_captures_but_routes_continuations_to_v8()
    {
        let source = r#"
async function nonNullDoc(ctx, id, suffix) {
  const document = await ctx.db.get("documents", id);
  if (document === null) throw new Error("missing mapped document");
  return { id: document._id, label: document.label + suffix };
}
export const mappedContinuationBatch = query({
  args: { items: v.array(v.object({ id: v.string() })), suffix: v.string() },
  handler: async (ctx, args) => await Promise.all(
    args.items.map((item) => nonNullDoc(ctx, item.id, args.suffix)),
  ),
});
"#;
        let output = compile(source, "mappedContinuationBatch");
        assert!(!output.eligible);
        assert_eq!(output.proved_direct_async_batches.len(), 1);
        let super::ProvedDirectAsyncBatchShape::SingleEffectMap {
            helper_continuation_prebound,
            ..
        } = &output.proved_direct_async_batches[0].shape
        else {
            panic!("mapped helper continuation changed proof kind");
        };
        assert!(*helper_continuation_prebound);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-direct-promise-all"
                && diagnostic.message.contains(
                    "remain on V8 because Wasm batching cannot preserve source-order rejection",
                )
        }));
    }

    #[test]
    fn direct_promise_all_helper_indirection_rejects_resumable_and_unsafe_mapping() {
        for (name, helper, handler_prefix, call, expected) in [
            (
                "multiple awaits",
                "async function load(ctx, id) { const first = await ctx.db.get(\"documents\", id); return await ctx.db.get(\"documents\", first._id); }",
                "",
                "load(ctx, id)",
                "independently resumable multiple awaits",
            ),
            (
                "nested suspending helper",
                "async function base(ctx, id) { return await ctx.db.get(\"documents\", id); } async function load(ctx, id) { const value = await base(ctx, id); return value; }",
                "",
                "load(ctx, id)",
                "nested suspending helpers and nested batches are unsupported",
            ),
            (
                "nested batch helper",
                "async function load(ctx, id) { const values = await Promise.all([ctx.db.get(\"documents\", id)]); return values[0]; }",
                "",
                "load(ctx, id)",
                "nested suspending helpers and nested batches are unsupported",
            ),
            (
                "effectful continuation call",
                "async function second(ctx, id) { return await ctx.db.get(\"documents\", id); } async function load(ctx, id) { const value = await ctx.db.get(\"documents\", id); return second(ctx, value._id); }",
                "",
                "load(ctx, id)",
                "continuation call second suspends or performs a Convex effect",
            ),
            (
                "default parameter",
                "async function load(ctx, id = \"fallback\") { return await ctx.db.get(\"documents\", id); }",
                "",
                "load(ctx, id)",
                "parameters must be identifiers without defaults",
            ),
            (
                "spread call",
                "async function load(ctx, id) { return await ctx.db.get(\"documents\", id); }",
                "",
                "load(...[ctx, id])",
                "does not allow spread arguments",
            ),
            (
                "escaped helper",
                "async function load(ctx, id) { return await ctx.db.get(\"documents\", id); }",
                "void load;",
                "load(ctx, id)",
                "escapes or has an ambiguous reference",
            ),
            (
                "shadowed helper",
                "async function load(ctx, id) { return await ctx.db.get(\"documents\", id); }",
                "const load = async (_ctx, id) => id;",
                "load(ctx, id)",
                "ambiguous or not a direct static source call",
            ),
        ] {
            let source = format!(
                r#"{helper}
export const rejected = query({{
  args: {{ ids: v.array(v.string()) }},
  handler: async (ctx, args) => {{
    {handler_prefix}
    return await Promise.all(args.ids.map((id) => {call}));
  }},
}});
"#
            );
            let output = compile(&source, "rejected");
            assert!(!output.eligible, "{name}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-direct-promise-all"
                        && diagnostic.message.contains(expected)
                }),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn index_take_distinguishes_static_limits_from_dynamic_operands() {
        for (expression, admitted, expected_limit, expected_limit_argument_index) in [
            ("1", true, Some(1), None),
            ("100000", true, Some(100_000), None),
            ("0", false, None, None),
            ("100001", false, None, None),
            ("1.5", false, None, None),
            ("-1", true, None, Some(1)),
            ("+1", true, None, Some(1)),
            ("1 + 1", true, None, Some(1)),
            ("args.limit", true, None, Some(1)),
        ] {
            let source = format!(
                r#"
export const selected = query({{
  args: {{ owner: null, limit: null }},
  handler: async (ctx, args) => await ctx.db
    .query("documents")
    .withIndex("by_owner", (q) => q.eq("owner", args.owner))
    .take({expression}),
}});
"#
            );
            let module = summary(&source);
            let operation = module
                .operations
                .iter()
                .find(|operation| operation.kind == "db.query");
            if admitted {
                let operation = operation.expect(expression);
                assert_eq!(
                    operation.order.as_deref(),
                    Some("ascending"),
                    "{expression}"
                );
                assert_eq!(
                    operation.terminal.as_deref(),
                    Some("collect"),
                    "{expression}"
                );
                assert_eq!(operation.limit, expected_limit, "{expression}");
                assert_eq!(
                    operation.limit_argument_index, expected_limit_argument_index,
                    "{expression}"
                );
                let output = compile(&source, "selected");
                assert!(
                    output.eligible,
                    "{expression}: {:#?}",
                    output
                        .diagnostics
                        .iter()
                        .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                        .collect::<Vec<_>>()
                );
                let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                    panic!("expected compile output for {expression}");
                };
                assert_eq!(compiled.operations.len(), 1, "{expression}");
                assert_eq!(compiled.operations[0].order.as_deref(), Some("ascending"));
                assert_eq!(compiled.operations[0].terminal.as_deref(), Some("collect"));
                assert_eq!(compiled.operations[0].limit, expected_limit);
                assert_eq!(
                    compiled.operations[0].limit_argument_index,
                    expected_limit_argument_index
                );
            } else {
                assert!(operation.is_none(), "{expression}");
                assert!(!compile(&source, "selected").eligible, "{expression}");
            }
        }
    }

    #[test]
    fn static_index_identity_uses_oxc_decoded_string_values() {
        let source = r#"
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => await ctx.db
    .query('\x64ocuments')
    .withIndex("by_\u006fwner", (q) => q.eq('\u006fwner', args.owner))
    .collect(),
        });
"#;
        let output = compile(source, "selected");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("escaped static index identity returned analysis output");
        };
        let operation = compiled
            .operations
            .iter()
            .find(|operation| operation.kind == "databaseIndexQuery")
            .expect("escaped static index query was not admitted");
        assert_eq!(operation.table.as_deref(), Some("documents"));
        assert_eq!(operation.index.as_deref(), Some("by_owner"));
        assert_eq!(operation.index_constraints[0].field, "owner");
    }

    #[test]
    fn module_index_accepts_string_named_import_specifiers() {
        let source = r#"import { "remote-name" as localName } from "fixture";
export const selected = localName;
"#;
        let module = summary(source);
        let import = module
            .imports
            .get("localName")
            .expect("string-named import was not indexed");
        assert_eq!(import.imported, "remote-name");
    }

    #[test]
    fn index_query_canonicalization_unifies_equivalent_operation_identities() {
        let operation = |order: &str, terminal: &str| {
            let source = format!(
                r#"
export const selected = query({{
  args: {{ owner: null }},
  handler: async (ctx, args) => await ctx.db
    .query("documents")
    .withIndex("by_owner", (q) => q.eq("owner", args.owner)){order}
    .{terminal},
}});
"#
            );
            let output = compile(&source, "selected");
            assert!(
                output.eligible,
                "{order}.{terminal}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
            let CompilerModeOutput::Compile(compiled) = output.mode_output else {
                panic!("expected index query compile output");
            };
            assert_eq!(compiled.operations.len(), 1);
            compiled.operations.into_iter().next().unwrap()
        };

        let implicit_take = operation("", "take(2)");
        let explicit_ascending_take = operation(r#".order("asc")"#, "take(2)");
        for candidate in [&implicit_take, &explicit_ascending_take] {
            assert_eq!(candidate.order.as_deref(), Some("ascending"));
            assert_eq!(candidate.terminal.as_deref(), Some("collect"));
            assert_eq!(candidate.limit, Some(2));
        }
        assert_eq!(
            implicit_take.stable_key,
            explicit_ascending_take.stable_key,
            "implicit={} explicit={}",
            serde_json::to_string(&implicit_take).unwrap(),
            serde_json::to_string(&explicit_ascending_take).unwrap()
        );

        let descending_take = operation(r#".order("desc")"#, "take(2)");
        let different_limit = operation("", "take(3)");
        let unbounded_collect = operation("", "collect()");
        let first = operation("", "first()");
        assert_eq!(descending_take.order.as_deref(), Some("descending"));
        assert_eq!(unbounded_collect.limit, None);
        assert_eq!(first.terminal.as_deref(), Some("first"));
        for candidate in [
            &descending_take,
            &different_limit,
            &unbounded_collect,
            &first,
        ] {
            assert_ne!(implicit_take.stable_key, candidate.stable_key);
        }

        for unsupported_chain in [
            r#".order("ascending").take(2)"#,
            r#".order(args.order).take(2)"#,
            r#".order("asc", "desc").take(2)"#,
            r#".order("asc").order("desc").take(2)"#,
            ".take()",
            ".take(2, 3)",
            ".collect(2)",
        ] {
            let unsupported = format!(
                r#"
export const selected = query({{
  args: {{ owner: null, order: null }},
  handler: (ctx, args) => ctx.db
    .query("documents")
    .withIndex("by_owner", (q) => q.eq("owner", args.owner)){unsupported_chain},
}});
"#
            );
            assert!(
                summary(&unsupported)
                    .operations
                    .iter()
                    .all(|operation| operation.kind != "db.query"),
                "{unsupported_chain}"
            );
            assert!(
                !compile(&unsupported, "selected").eligible,
                "{unsupported_chain}"
            );
        }
    }

    #[test]
    fn compound_index_constraints_preserve_order_and_authorize_mapped_take() {
        let source = r#"
export const selected = query({
  args: { owners: v.array(null), activeAfter: null },
  handler: async (ctx, args) => await Promise.all(
    args.owners.map((owner) => ctx.db
      .query("documents")
      .withIndex("by_owner_kind_terminal_active_updated", (q) => q
        .eq("owner", owner)
        .eq("kind", "worker")
        .eq("terminal", undefined)
        .eq("active", true)
        .gt("updated", args.activeAfter))
      .order("desc")
      .take(2)),
  ),
});
"#;
        let module = summary(source);
        let operation = module
            .operations
            .iter()
            .find(|operation| operation.kind == "db.query")
            .unwrap();
        assert_eq!(
            operation
                .index_constraints
                .iter()
                .map(|constraint| (
                    constraint.field.as_str(),
                    constraint.operator.as_str(),
                    constraint.value_source.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                ("owner", "eq", "owner"),
                ("kind", "eq", "\"worker\""),
                ("terminal", "eq", "undefined"),
                ("active", "eq", "true"),
                ("updated", "gt", "args.activeAfter"),
            ]
        );
        let output = compile(source, "selected");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("expected compound query compile output");
        };
        assert_eq!(compiled.operations.len(), 1);
        assert_eq!(compiled.operations[0].index_constraints.len(), 5);
        assert_eq!(compiled.operations[0].order.as_deref(), Some("descending"));
        assert_eq!(compiled.operations[0].terminal.as_deref(), Some("collect"));
        assert_eq!(compiled.operations[0].limit, Some(2));
        assert_eq!(compiled.direct_async_batches.len(), 1);
        let super::DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            dynamic_arguments,
            result_kind,
            ..
        } = &compiled.direct_async_batches[0].shape
        else {
            panic!("compound query batch changed authorization kind");
        };
        assert_eq!(dynamic_arguments.len(), 5);
        assert_eq!(result_kind, "hostArray");

        let range_only = r#"export const rangeOnly = query({
  args: { activeAfter: null },
  handler: (ctx, args) => ctx.db
    .query("documents")
    .withIndex("by_updated", (q) => q.gt("updated", args.activeAfter))
    .take(2),
});"#;
        let range_only_output = compile(range_only, "rangeOnly");
        assert!(
            range_only_output.eligible,
            "{:#?}",
            range_only_output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );

        for range in [
            r#"q.eq("owner", args.owner).gt("updated", 1).eq("kind", "worker")"#,
            r#"q.eq("owner", args.owner).gt("updated", 1).lt("created", 2)"#,
            r#"q.eq("owner", args.owner).eq("owner", args.owner)"#,
        ] {
            let rejected = format!(
                r#"export const rejected = query({{
  args: {{ owner: null, activeAfter: null }},
  handler: (ctx, args) => ctx.db
    .query("documents")
    .withIndex("by_owner_updated", (q) => {range})
    .take(2),
}});"#
            );
            assert!(
                summary(&rejected)
                    .operations
                    .iter()
                    .all(|operation| operation.kind != "db.query"),
                "{range}"
            );
            assert!(!compile(&rejected, "rejected").eligible, "{range}");
        }
    }

    #[test]
    fn mapped_index_query_preserves_dynamic_take_as_the_final_batch_operand() {
        let source = r#"
export const selected = query({
  args: { owners: v.array(null), limit: null },
  handler: async (ctx, args) => await Promise.all(
    args.owners.map((owner) => ctx.db
      .query("documents")
      .withIndex("by_owner", (q) => q.eq("owner", owner))
      .take(args.limit)),
  ),
});
"#;
        let output = compile(source, "selected");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("dynamic mapped query returned analysis output");
        };
        let operation = compiled
            .operations
            .iter()
            .find(|operation| operation.kind == "databaseIndexQuery")
            .expect("dynamic mapped query has no operation");
        assert_eq!(operation.limit, None);
        assert_eq!(operation.limit_argument_index, Some(1));
        let super::DirectAsyncBatchAuthorizationShape::SingleEffectMap {
            dynamic_arguments, ..
        } = &compiled.direct_async_batches[0].shape
        else {
            panic!("dynamic mapped query changed batch shape");
        };
        assert_eq!(dynamic_arguments.len(), 2);
    }

    #[test]
    fn direct_batch_iterator_accepts_only_non_escaping_constant_arrays() {
        let source = r#"
const KINDS: string[] = ["primary", "secondary"];
export const selected = query({
  args: { owner: null },
  handler: async (ctx, args) => await Promise.all(
    KINDS.map((kind) => ctx.db
      .query("documents")
      .withIndex("by_owner_kind", (q) => q.eq("owner", args.owner).eq("kind", kind))
      .take(2)),
  ),
});
"#;
        let module = summary(source);
        assert_eq!(module.constant_array_bindings.len(), 1);
        assert_eq!(
            module.constant_array_bindings[0].values,
            vec![
                Value::String("primary".to_string()),
                Value::String("secondary".to_string())
            ]
        );
        let output = compile(source, "selected");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("expected constant-array batch compile output");
        };
        assert_eq!(compiled.direct_async_batches.len(), 1);

        for (name, declaration, extra_use) in [
            ("dynamic", "const kinds = [args.owner];", ""),
            (
                "escape",
                "const kinds = [\"primary\", \"secondary\"];",
                "const escaped = kinds; void escaped;",
            ),
            (
                "write",
                "let kinds = [\"primary\", \"secondary\"];",
                "kinds = [\"replacement\"];",
            ),
        ] {
            let rejected = format!(
                r#"export const rejected = query({{
  args: {{ owner: null }},
  handler: async (ctx, args) => {{
    {declaration}
    {extra_use}
    return await Promise.all(kinds.map((kind) => ctx.db
      .query("documents")
      .withIndex("by_owner_kind", (q) => q.eq("owner", args.owner).eq("kind", kind))
      .take(2)));
  }},
}});"#
            );
            let output = compile(&rejected, "rejected");
            assert!(!output.eligible, "{name}");
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| { diagnostic.code == "unsupported-direct-promise-all" }),
                "{name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn authenticating_helper_flow_emits_exact_operations_and_opaque_fields() {
        let source = r#"
async function authenticate(helperContext) {
  const identity = await helperContext.auth.getUserIdentity();
  if (identity === null) throw new Error("Unauthorized");
  const normalizedId = helperContext.db.normalizeId("user", identity.subject);
  if (normalizedId === null) throw new Error("Unauthorized");
  const user = await helperContext.db.get("user", normalizedId);
  if (user === null) throw new Error("Unauthorized");
  return user;
}
function projectUser(user) {
  return { userId: user.userId, isAdmin: user.role === "admin" };
}
export const selected = query({
  args: {},
  handler: async (ctx) => projectUser(await authenticate(ctx)),
});
"#;
        let output = compile(source, "selected");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("expected compile output");
        };
        assert_eq!(
            compiled
                .operations
                .iter()
                .map(|operation| (operation.kind.as_str(), operation.table.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("authenticationGetUserIdentity", None),
                ("databaseNormalizeId", Some("user")),
                ("databaseGet", Some("user")),
            ]
        );
        assert!(compiled.direct_async_batches.is_empty());
        let properties = compiled
            .document_properties
            .iter()
            .map(|property| property.property.as_str())
            .collect::<BTreeSet<_>>();
        assert!(properties.contains("subject"));
        assert!(properties.contains("userId"));
        assert!(properties.contains("role"));
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .unwrap();
        assert!(!generated.contains("async"));
        assert!(!generated.contains("await"));
        assert!(generated.contains("helperContext.auth.getUserIdentity()"));
        assert!(generated.contains("helperContext.db.normalizeId(\"user\", identity.subject)"));
        assert!(generated.contains("helperContext.db.get(\"user\", normalizedId)"));
    }

    #[test]
    fn capability_helpers_reject_awaited_context_arguments() {
        let source = |context_argument: &str| {
            format!(
                r#"
async function loadDocument(helperContext, id) {{
  return await helperContext.db.get("documents", id);
}}
export const selected = query({{
  args: {{}},
  handler: async (ctx, args) =>
    await loadDocument({context_argument}, args.id),
}});
"#
            )
        };
        for context_argument in ["ctx", "(ctx as any)"] {
            let output = compile(&source(context_argument), "selected");
            assert!(
                output.eligible,
                "{context_argument}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }

        for context_argument in ["await ctx", "(await ctx) as any", "await (ctx as any)"] {
            let output = compile(&source(context_argument), "selected");
            assert!(!output.eligible, "{context_argument}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unsupported-convex-effect"
                        && diagnostic.message.contains("capability access ctx")
                }),
                "{context_argument}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn conflicting_opaque_provenance_widens_through_existing_return_paths() {
        let source = r#"
function shared(value) {
  return value;
}
function project(value) {
  const sharedValue = shared(value);
  return sharedValue.label;
}
function delayedSecond(value) {
  return value;
}
function delayedFirst(value) {
  const delayed = delayedSecond(value);
  return delayed;
}
export const selected = query({
  args: { accountId: null, profileId: null },
  handler: async (ctx, args) => {
    const account = await ctx.db.get("accounts", args.accountId);
    const profile = await ctx.db.get("profiles", args.profileId);
    if (account === null || profile === null) throw new Error("missing");
    const delayed = delayedFirst(profile);
    return { first: project(account), second: project(delayed) };
  },
});
"#;
        let output = compile(source, "selected");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("expected compile output");
        };
        let label_properties = compiled
            .document_properties
            .iter()
            .filter(|property| property.property == "label")
            .collect::<Vec<_>>();
        assert_eq!(
            label_properties.len(),
            1,
            "{}",
            serde_json::to_string_pretty(&compiled.document_properties).unwrap()
        );
        assert_eq!(label_properties[0].table, "opaqueValue");
        assert_eq!(label_properties[0].reason, "opaque-property-read");
    }

    #[test]
    fn opaque_provenance_crosses_static_return_call_expressions() {
        let source = r#"
function shared(value) {
  return value;
}
function returnCall(value) {
  return shared(value);
}
const returnArrow = (value) => shared(value);
export const selected = query({
  args: { accountId: null },
  handler: async (ctx, args) => {
    const account = await ctx.db.get("accounts", args.accountId);
    if (account === null) throw new Error("missing");
    const returned = returnCall(account);
    const arrowReturned = returnArrow(account);
    return { label: returned.label, role: arrowReturned.role };
  },
});
"#;
        let output = compile(source, "selected");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("expected compile output");
        };
        assert!(compiled.document_properties.iter().any(|property| {
            property.table == "accounts"
                && property.property == "label"
                && property.reason == "opaque-property-read"
        }));
        assert!(compiled.document_properties.iter().any(|property| {
            property.table == "accounts"
                && property.property == "role"
                && property.reason == "opaque-property-read"
        }));
    }

    #[test]
    fn rejects_inexact_authentication_and_normalize_id_shapes_statically() {
        let cases = [
            (
                "computedAuth",
                "await ctx.auth[\"getUserIdentity\"]()",
                "unsupported-authentication-get-user-identity-shape",
                "non-computed",
            ),
            (
                "optionalAuth",
                "await ctx.auth?.getUserIdentity()",
                "unsupported-authentication-get-user-identity-shape",
                "optional",
            ),
            (
                "authArity",
                "await ctx.auth.getUserIdentity(args.id)",
                "unsupported-authentication-get-user-identity-shape",
                "zero arguments",
            ),
            (
                "computedNormalize",
                "ctx.db[\"normalizeId\"](\"user\", args.id)",
                "unsupported-database-normalize-id-shape",
                "non-computed",
            ),
            (
                "optionalNormalize",
                "ctx.db?.normalizeId(\"user\", args.id)",
                "unsupported-database-normalize-id-shape",
                "optional",
            ),
            (
                "normalizeArity",
                "ctx.db.normalizeId(\"user\")",
                "unsupported-database-normalize-id-shape",
                "two arguments",
            ),
            (
                "dynamicNormalizeTable",
                "ctx.db.normalizeId(args.table, args.id)",
                "unsupported-database-normalize-id-shape",
                "static string table",
            ),
            (
                "emptyNormalizeTable",
                "ctx.db.normalizeId(\"\", args.id)",
                "unsupported-database-normalize-id-shape",
                "static string table",
            ),
        ];
        for (export_name, expression, code, message) in cases {
            let source = format!(
                r#"
export const {export_name} = query({{
  args: {{ id: null, table: null }},
  handler: async (ctx, args) => {expression},
}});
"#
            );
            let output = compile(&source, export_name);
            assert!(!output.eligible, "{export_name}");
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == code && diagnostic.message.contains(message)
                }),
                "{export_name}: {:#?}",
                output
                    .diagnostics
                    .iter()
                    .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn empty_database_descriptor_names_are_not_admitted() {
        let cases = [
            ("emptyGetTable", r#"await ctx.db.get("", args.id)"#),
            (
                "emptyQueryTable",
                r#"await ctx.db.query("").withIndex("by_id", (q) => q.eq("_id", args.id)).first()"#,
            ),
            (
                "emptyQueryIndex",
                r#"await ctx.db.query("documents").withIndex("", (q) => q.eq("_id", args.id)).first()"#,
            ),
        ];
        for (export_name, expression) in cases {
            let source = format!(
                r#"
export const {export_name} = query({{
  args: {{ id: null }},
  handler: async (ctx, args) => {expression},
}});
"#
            );
            let output = compile(&source, export_name);
            assert!(!output.eligible, "{export_name}");
        }
    }
}

#[cfg(test)]
mod generated_function_reference_tests {
    use super::{
        CompilerModeOutput, EsbuildImport, EsbuildInput, EsbuildMetafile, GeneratedSourceMode,
        GraphInput, LoadedModule, PhaseMeasurements, TEST_GENERATED_SERVER_MODULE,
        TEST_GENERATED_SERVER_SOURCE, Toolchain, compile_export, hash_bytes, summarize_module,
        test_registration_adapter_material, with_test_registration_imports,
    };
    use std::{collections::BTreeMap, path::Path, time::Instant};

    const ENTRY: &str = "convex/fixture.ts";
    const GENERATED_API: &str = "convex/_generated/api.js";
    const CONVEX_SERVER: &str = "node_modules/convex/dist/esm/server/index.js";
    const GENERATED_SOURCE: &str = r#"
import { anyApi } from "convex/server";
export const api = anyApi;
export const internal = anyApi;
"#;

    fn summary(module_key: &str, source: &str) -> super::ModuleSummary {
        summarize_module(
            module_key,
            Path::new(module_key),
            source,
            &hash_bytes(source.as_bytes()),
            "fixture-cache-key",
            "fixture-pipeline",
            "fixture-context-policy",
            &mut PhaseMeasurements::default(),
        )
        .unwrap()
    }

    fn compile_with_generated_source(
        source: &str,
        export_name: &str,
        generated_source: &str,
        convex_server_resolution: &str,
    ) -> super::CompilerOutput {
        compile_with_generated_source_in_effect_mode(
            source,
            export_name,
            generated_source,
            convex_server_resolution,
            super::EffectExecutionMode::BlockingFiber,
        )
    }

    fn compile_with_generated_source_in_effect_mode(
        source: &str,
        export_name: &str,
        generated_source: &str,
        convex_server_resolution: &str,
        effect_execution_mode: super::EffectExecutionMode,
    ) -> super::CompilerOutput {
        let source = with_test_registration_imports(source);
        let modules = BTreeMap::from([
            (
                ENTRY.to_string(),
                LoadedModule::new(summary(ENTRY, &source), source),
            ),
            (
                GENERATED_API.to_string(),
                LoadedModule::new(
                    summary(GENERATED_API, generated_source),
                    generated_source.to_string(),
                ),
            ),
            (
                TEST_GENERATED_SERVER_MODULE.to_string(),
                LoadedModule::new(
                    summary(TEST_GENERATED_SERVER_MODULE, TEST_GENERATED_SERVER_SOURCE),
                    TEST_GENERATED_SERVER_SOURCE.to_string(),
                ),
            ),
        ]);
        let graph = GraphInput {
            kind: "convex-wasm-esbuild-graph".to_string(),
            repo_root: Path::new("/fixture").to_path_buf(),
            functions_root: "convex".to_string(),
            entry_path: ENTRY.to_string(),
            export_name: export_name.to_string(),
            toolchain: Toolchain {
                esbuild: "fixture-esbuild".to_string(),
                convex: "fixture-convex".to_string(),
            },
            dependency_adapter: super::test_dependency_adapter_material(),
            registration_adapter: test_registration_adapter_material(),
            assumptions: None,
            effect_execution_mode,
            metafile: EsbuildMetafile {
                inputs: BTreeMap::from([
                    (
                        ENTRY.to_string(),
                        EsbuildInput {
                            imports: vec![
                                EsbuildImport {
                                    path: TEST_GENERATED_SERVER_MODULE.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some("./_generated/server".to_string()),
                                    external: false,
                                },
                                EsbuildImport {
                                    path: GENERATED_API.to_string(),
                                    kind: "import-statement".to_string(),
                                    original: Some("./_generated/api.js".to_string()),
                                    external: false,
                                },
                            ],
                        },
                    ),
                    (
                        TEST_GENERATED_SERVER_MODULE.to_string(),
                        EsbuildInput {
                            imports: Vec::new(),
                        },
                    ),
                    (
                        GENERATED_API.to_string(),
                        EsbuildInput {
                            imports: vec![EsbuildImport {
                                path: convex_server_resolution.to_string(),
                                kind: "import-statement".to_string(),
                                original: Some("convex/server".to_string()),
                                external: false,
                            }],
                        },
                    ),
                ]),
                outputs: BTreeMap::new(),
            },
            phase_timings_us: BTreeMap::new(),
        };
        compile_export(
            &graph,
            Path::new("/fixture-cache"),
            &mut PhaseMeasurements::default(),
            Instant::now(),
            &modules,
            GeneratedSourceMode::Inline,
        )
        .unwrap()
        .output
    }

    fn compile(source: &str, export_name: &str) -> super::CompilerOutput {
        compile_with_generated_source(source, export_name, GENERATED_SOURCE, CONVEX_SERVER)
    }

    #[test]
    fn lowers_public_internal_and_import_aliased_static_references_into_scheduler_descriptors() {
        let source = r#"
import { api, internal as privateApi } from "./_generated/api.js";
export const schedule = mutation({
  args: {},
  handler: async (ctx) => {
    await ctx.scheduler.runAfter(0, api.jobs.cleanup, {});
    await ctx.scheduler.runAt(1, privateApi.automation.ticks.run, {});
    return null;
  },
});
"#;
        let output = compile(source, "schedule");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|d| (&d.code, &d.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("expected compile output");
        };
        assert_eq!(compiled.operations.len(), 2);
        assert_eq!(
            compiled.operations[0].function_reference.as_deref(),
            Some("_reference/function/jobs:cleanup")
        );
        assert_eq!(
            compiled.operations[1].function_reference.as_deref(),
            Some("_reference/function/automation/ticks:run")
        );
        assert!(
            !compiled
                .reachable_modules
                .iter()
                .any(|module| module == GENERATED_API)
        );
        assert!(compiled.resolved_imports.iter().any(|resolved| {
            resolved.importer == GENERATED_API
                && resolved.imported_name == "anyApi"
                && resolved.resolved == CONVEX_SERVER
        }));
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .unwrap();
        assert!(
            generated.contains("__convexFunctionReference(\"_reference/function/jobs:cleanup\")")
        );
        assert!(
            generated.contains(
                "__convexFunctionReference(\"_reference/function/automation/ticks:run\")"
            )
        );
        assert!(!generated.contains("anyApi"));
        assert!(!generated.contains("api.jobs.cleanup"));
        assert!(!generated.contains("privateApi.automation.ticks.run"));
    }

    #[test]
    fn guest_scheduler_site_rewrite_composes_with_static_reference_rebinding() {
        let source = r#"
import { api } from "./_generated/api.js";
async function scheduleOne(ctx, delay, payload) {
  return await ctx.scheduler.runAfter(delay, api.jobs.cleanup, payload);
}
export const schedule = mutation({
  args: { delay: null, payload: null },
  handler: async (ctx, args) => await scheduleOne(ctx, args.delay, args.payload),
});
"#;
        let output = compile_with_generated_source_in_effect_mode(
            source,
            "schedule",
            GENERATED_SOURCE,
            CONVEX_SERVER,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("guest scheduler fixture returned analysis output");
        };
        let operation = compiled
            .operations
            .iter()
            .find(|operation| operation.kind == "schedulerRunAfter")
            .expect("guest scheduler fixture has no operation descriptor");
        assert_eq!(
            operation.function_reference.as_deref(),
            Some("_reference/function/jobs:cleanup")
        );
        let operation_id = operation.id;
        let generated = compiled
            .generated_javascript_artifact
            .expect("guest scheduler fixture has no generated source")
            .source
            .expect("guest scheduler fixture has no inline generated source");
        assert!(!generated.contains("ctx.scheduler.runAfter"), "{generated}");
        assert!(
            generated.contains(
                "__convexInternalFunctionReference(argument1) === \"_reference/function/jobs:cleanup\""
            ),
            "{generated}"
        );
        assert!(
            generated.contains("__convexFunctionReference(\"_reference/function/jobs:cleanup\")"),
            "{generated}"
        );
        assert!(
            generated.contains(&format!(
                "return __convexStartAsyncOperation({}, __convexMarkArray([argument0, argument2]))",
                operation_id
            )),
            "{generated}"
        );
    }

    #[test]
    fn guest_scheduler_site_rewrite_preserves_implicit_undefined_helper_result() {
        let source = r#"
import { api } from "./_generated/api.js";
async function scheduleOne(ctx, delay, payload) {
  await ctx.scheduler.runAfter(delay, api.jobs.cleanup, payload);
}
export const schedule = mutation({
  args: { delay: null, payload: null },
  handler: async (ctx, args) => {
    await scheduleOne(ctx, args.delay, args.payload);
    return "done";
  },
});
"#;
        let output = compile_with_generated_source_in_effect_mode(
            source,
            "schedule",
            GENERATED_SOURCE,
            CONVEX_SERVER,
            super::EffectExecutionMode::GuestPromiseEventLoop,
        );
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        assert!(output.callable_control_plans.iter().any(|plan| {
            plan.effects.iter().any(|effect| {
                effect.effect.effect_key.operation_kind == "schedulerRunAfter"
                    && effect.effect.provenance.caller_callsite.is_some()
            }) && plan.current_batch_leaf().is_none()
        }));
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("guest implicit-undefined scheduler fixture returned analysis output");
        };
        let generated = compiled
            .generated_javascript_artifact
            .expect("guest implicit-undefined scheduler fixture has no generated source")
            .source
            .expect("guest implicit-undefined scheduler fixture has no inline generated source");
        assert!(!generated.contains("ctx.scheduler.runAfter"), "{generated}");
        assert!(generated.contains("return \"done\""), "{generated}");
    }

    #[test]
    fn direct_promise_all_lowers_single_effect_scheduler_helper() {
        let source = r#"
import { api } from "./_generated/api.js";
async function scheduleOne(ctx, delay, payload) {
  return await ctx.scheduler.runAfter(delay, api.jobs.cleanup, payload);
}
export const scheduleBatch = mutation({
  args: { delays: v.array(null), payload: null },
  handler: async (ctx, args) => await Promise.all(
    args.delays.map((delay) => scheduleOne(ctx, delay, args.payload)),
  ),
});
"#;
        let output = compile(source, "scheduleBatch");
        assert!(
            output.eligible,
            "{:#?}",
            output
                .diagnostics
                .iter()
                .map(|diagnostic| (&diagnostic.code, &diagnostic.message))
                .collect::<Vec<_>>()
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("scheduler helper batch returned analysis output");
        };
        assert_eq!(compiled.operations.len(), 2);
        assert_eq!(compiled.operations[1].kind, "schedulerRunAfter");
        assert_eq!(
            compiled.operations[1].function_reference.as_deref(),
            Some("_reference/function/jobs:cleanup")
        );
        let generated = compiled
            .generated_javascript_artifact
            .and_then(|artifact| artifact.source)
            .expect("scheduler helper batch generated inline JavaScript");
        assert!(
            generated
                .contains("__convexAsyncBatch(args.delays, 2, (delay) => [delay, args.payload])")
        );
        assert!(!generated.contains("Promise.all("));
    }

    #[test]
    fn rejects_computed_and_dynamic_generated_reference_keys() {
        for (export_name, expression) in [
            ("computed", "internal[\"jobs\"].cleanup"),
            ("dynamic", "internal[args.module].cleanup"),
        ] {
            let source = format!(
                r#"
import {{ internal }} from "./_generated/api.js";
export const {export_name} = mutation({{
  args: {{ module: null }},
  handler: async (ctx, args) => {{
    await ctx.scheduler.runAfter(0, {expression}, {{}});
  }},
}});
"#
            );
            let output = compile(&source, export_name);
            assert!(!output.eligible);
            assert!(output.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "unsupported-generated-function-reference"
                    && diagnostic.message.contains("non-computed")
            }));
            assert!(
                output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unproved-generated-function-reference"
                })
            );
        }
    }

    #[test]
    fn rejects_escaped_reflection_and_unproved_local_aliases() {
        let sources = [
            (
                "escaped",
                r#"
import { api } from "./_generated/api.js";
export const escaped = mutation({
  args: {},
  handler: async () => api.jobs.cleanup,
});
"#,
            ),
            (
                "reflected",
                r#"
import { api } from "./_generated/api.js";
export const reflected = mutation({
  args: {},
  handler: async () => Object.keys(api.jobs),
});
"#,
            ),
            (
                "aliased",
                r#"
import { internal } from "./_generated/api.js";
export const aliased = mutation({
  args: {},
  handler: async (ctx) => {
    const target = internal.jobs.cleanup;
    await ctx.scheduler.runAfter(0, target, {});
  },
});
"#,
            ),
        ];
        for (export_name, source) in sources {
            let output = compile(source, export_name);
            assert!(!output.eligible);
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|diagnostic| { diagnostic.code == "generated-function-reference-escape" })
            );
            if export_name == "aliased" {
                assert!(output.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "unproved-generated-function-reference"
                }));
            }
        }
    }

    #[test]
    fn rejects_shadowed_function_reference_roots() {
        let source = r#"
import { internal } from "./_generated/api.js";
export const shadowed = mutation({
  args: {},
  handler: async (ctx) => {
    const internal = { jobs: { cleanup: {} } };
    await ctx.scheduler.runAfter(0, internal.jobs.cleanup, {});
    return null;
  },
});
"#;
        let output = compile(source, "shadowed");
        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unproved-generated-function-reference"
                && diagnostic
                    .message
                    .contains("authenticated generated api module")
        }));
    }

    #[test]
    fn rejects_local_function_reference_values_without_materializing_an_invalid_scheduler_plan() {
        let source = r#"
const runFunction = makeInternalMutationReference("migrations/runner:run");
export const schedule = mutation({
  args: {},
  handler: async (ctx) => {
    await ctx.scheduler.runAfter(0, runFunction, {});
  },
});
function makeInternalMutationReference(name) {
  return { name };
}
"#;
        let output = compile(source, "schedule");
        assert!(!output.eligible);
        assert!(
            output
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "unproved-generated-function-reference" })
        );
        let CompilerModeOutput::Compile(compiled) = output.mode_output else {
            panic!("dynamic scheduler reference returned analysis output");
        };
        assert!(
            compiled
                .operations
                .iter()
                .all(|operation| operation.kind != "schedulerRunAfter")
        );
    }

    #[test]
    fn rejects_stale_generated_source_and_unpinned_any_api_resolution() {
        let source = r#"
import { internal } from "./_generated/api.js";
export const schedule = mutation({
  args: {},
  handler: async (ctx) => {
    await ctx.scheduler.runAfter(0, internal.jobs.cleanup, {});
  },
});
"#;
        let stale = compile_with_generated_source(
            source,
            "schedule",
            r#"
import { anyApi } from "convex/server";
export const api = anyApi;
export const internal = {};
"#,
            CONVEX_SERVER,
        );
        assert!(!stale.eligible);
        assert!(stale.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "generated-api-source-mismatch"
                && diagnostic.message.contains("export both api and internal")
        }));

        let unpinned = compile_with_generated_source(
            source,
            "schedule",
            GENERATED_SOURCE,
            "convex/testing/fake-server.js",
        );
        assert!(!unpinned.eligible);
        assert!(unpinned.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "generated-api-source-mismatch"
                && diagnostic
                    .message
                    .contains("outside the pinned convex/server module")
        }));
    }

    #[test]
    fn binds_generated_api_source_and_resolved_any_api_material_into_export_identity() {
        let source = r#"
import { api } from "./_generated/api.js";
export const schedule = mutation({
  args: {},
  handler: async (ctx) => {
    await ctx.scheduler.runAfter(0, api.jobs.cleanup, {});
  },
});
"#;
        let baseline = compile(source, "schedule");
        let changed_source = compile_with_generated_source(
            source,
            "schedule",
            &format!("{GENERATED_SOURCE}\n// regenerated material\n"),
            CONVEX_SERVER,
        );
        let changed_resolution = compile_with_generated_source(
            source,
            "schedule",
            GENERATED_SOURCE,
            "node_modules/convex/dist/cjs/server/index.js",
        );
        for output in [&baseline, &changed_source, &changed_resolution] {
            assert!(output.eligible);
        }
        assert_ne!(
            baseline.source_graph_fingerprint,
            changed_source.source_graph_fingerprint
        );
        assert_ne!(
            baseline.export_fingerprint,
            changed_source.export_fingerprint
        );
        assert_ne!(
            baseline.source_graph_fingerprint,
            changed_resolution.source_graph_fingerprint
        );
        assert_ne!(
            baseline.export_fingerprint,
            changed_resolution.export_fingerprint
        );
    }

    #[test]
    fn authenticates_static_references_for_other_convex_operation_diagnostics() {
        let source = r#"
import { api } from "./_generated/api.js";
export const invoke = mutation({
  args: {},
  handler: async (ctx) => await ctx.runMutation(api.jobs.cleanup, {}),
});
"#;
        let output = compile(source, "invoke");
        assert!(!output.eligible);
        assert!(output.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-convex-effect"
                && diagnostic.message.contains("runMutation")
        }));
        assert!(!output.diagnostics.iter().any(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "unsupported-runtime-import"
                    | "generated-function-reference-escape"
                    | "generated-api-source-mismatch"
            )
        }));
    }
}
