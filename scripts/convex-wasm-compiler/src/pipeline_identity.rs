use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::CANONICAL_SHA256_HELPER_SOURCE;

const PIPELINE_SOURCES: &[(&str, &str)] = &[
    ("src/main.rs", include_str!("main.rs")),
    (
        "src/adapter_material.rs",
        include_str!("adapter_material.rs"),
    ),
    (
        "src/adapter_semantics.rs",
        include_str!("adapter_semantics.rs"),
    ),
    ("src/admission.rs", include_str!("admission.rs")),
    (
        "src/callable_control.rs",
        include_str!("callable_control.rs"),
    ),
    (
        "src/callable_effects.rs",
        include_str!("callable_effects.rs"),
    ),
    (
        "src/callable_plan_builder.rs",
        include_str!("callable_plan_builder.rs"),
    ),
    ("src/callable_plans.rs", include_str!("callable_plans.rs")),
    (
        "src/callable_resolution.rs",
        include_str!("callable_resolution.rs"),
    ),
    (
        "src/callable_value_flow.rs",
        include_str!("callable_value_flow.rs"),
    ),
    ("src/capability_flow.rs", include_str!("capability_flow.rs")),
    (
        "src/capability_predicates.rs",
        include_str!("capability_predicates.rs"),
    ),
    (
        "src/capability_specialization.rs",
        include_str!("capability_specialization.rs"),
    ),
    ("src/compiler_batch.rs", include_str!("compiler_batch.rs")),
    ("src/context_reuse.rs", include_str!("context_reuse.rs")),
    (
        "src/diagnostic_census.rs",
        include_str!("diagnostic_census.rs"),
    ),
    ("src/direct_batches.rs", include_str!("direct_batches.rs")),
    (
        "src/effect_materialization.rs",
        include_str!("effect_materialization.rs"),
    ),
    ("src/effect_plan.rs", include_str!("effect_plan.rs")),
    (
        "src/effect_site_rewrites.rs",
        include_str!("effect_site_rewrites.rs"),
    ),
    (
        "src/generated_source.rs",
        include_str!("generated_source.rs"),
    ),
    (
        "src/module_summary_cache.rs",
        include_str!("module_summary_cache.rs"),
    ),
    (
        "src/pipeline_identity.rs",
        include_str!("pipeline_identity.rs"),
    ),
    (
        "src/query_materialization.rs",
        include_str!("query_materialization.rs"),
    ),
    (
        "src/query_result_flow.rs",
        include_str!("query_result_flow.rs"),
    ),
    (
        "src/query_value_graph.rs",
        include_str!("query_value_graph.rs"),
    ),
    ("src/query_values.rs", include_str!("query_values.rs")),
    ("src/source_graph.rs", include_str!("source_graph.rs")),
    ("Cargo.toml", include_str!("../Cargo.toml")),
    ("Cargo.lock", include_str!("../Cargo.lock")),
    (
        "rust-toolchain.toml",
        include_str!("../rust-toolchain.toml"),
    ),
    (
        "../../package-lock.json",
        include_str!("../../../package-lock.json"),
    ),
    (
        "../lib/convex-wasm-source-graph.mjs",
        include_str!("../../lib/convex-wasm-source-graph.mjs"),
    ),
    (
        "../lib/convex-wasm-dependency-adapters.mjs",
        include_str!("../../lib/convex-wasm-dependency-adapters.mjs"),
    ),
    (
        "../lib/convex-wasm-registration-adapters.mjs",
        include_str!("../../lib/convex-wasm-registration-adapters.mjs"),
    ),
    ("../../shared/sha256.ts", CANONICAL_SHA256_HELPER_SOURCE),
];

pub(super) fn compiler_pipeline_sha256() -> &'static str {
    static FINGERPRINT: OnceLock<String> = OnceLock::new();
    FINGERPRINT
        .get_or_init(|| {
            compiler_pipeline_sha256_from_sources(
                PIPELINE_SOURCES.iter().map(|(_, source)| *source),
            )
        })
        .as_str()
}

fn compiler_pipeline_sha256_from_sources<'a>(sources: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for source in sources {
        hasher.update(source.len().to_le_bytes());
        hasher.update(source.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::PathBuf};

    use super::{
        PIPELINE_SOURCES, compiler_pipeline_sha256, compiler_pipeline_sha256_from_sources,
    };

    fn compiler_source_directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|candidate| candidate.join("src/pipeline_identity.rs").is_file())
            .expect("compiler source directory must exist")
            .join("src")
    }

    #[test]
    fn pipeline_identity_binds_every_compiler_rust_source() {
        let included_rust_sources = PIPELINE_SOURCES
            .iter()
            .filter_map(|(path, _)| path.strip_prefix("src/"))
            .filter(|path| path.ends_with(".rs"))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let current_rust_sources = fs::read_dir(compiler_source_directory())
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                (entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("rs")
                    && entry.file_name() != "tests.rs")
                    .then(|| entry.file_name().into_string().unwrap())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(included_rust_sources, current_rust_sources);
    }

    #[test]
    fn pipeline_identity_binds_direct_non_rust_semantic_dependencies() {
        let included = PIPELINE_SOURCES
            .iter()
            .filter(|(path, _)| !path.starts_with("src/"))
            .map(|(path, _)| *path)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            included,
            BTreeSet::from([
                "../lib/convex-wasm-dependency-adapters.mjs",
                "../lib/convex-wasm-registration-adapters.mjs",
                "../lib/convex-wasm-source-graph.mjs",
                "../../package-lock.json",
                "../../shared/sha256.ts",
                "Cargo.lock",
                "Cargo.toml",
                "rust-toolchain.toml",
            ])
        );
    }

    #[test]
    fn every_pipeline_source_mutates_pipeline_identity() {
        let baseline = compiler_pipeline_sha256_from_sources(
            PIPELINE_SOURCES.iter().map(|(_, source)| *source),
        );
        assert_eq!(baseline, compiler_pipeline_sha256());
        for (changed_pipeline_path, source) in PIPELINE_SOURCES {
            let changed_source = format!("{}\n", source);
            let changed = compiler_pipeline_sha256_from_sources(PIPELINE_SOURCES.iter().map(
                |(path, source)| {
                    if *path == *changed_pipeline_path {
                        changed_source.as_str()
                    } else {
                        *source
                    }
                },
            ));
            assert_ne!(
                changed, baseline,
                "editing {changed_pipeline_path} did not change pipeline identity"
            );
        }
    }
}
