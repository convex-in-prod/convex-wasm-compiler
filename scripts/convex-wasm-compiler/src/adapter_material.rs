use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{checked_module_path, hash_bytes};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegistrationAdapterMaterial {
    pub(super) kind: String,
    pub(super) descriptor: RegistrationAdapterDescriptor,
    pub(super) source: RegistrationAdapterSourceMaterial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RegistrationAdapterSourceMaterial {
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RegistrationAdapterDescriptor {
    pub(super) kind: String,
    pub(super) adapters: Vec<RegistrationAdapterDescriptorEntry>,
    pub(super) source_operations: Vec<RegistrationAdapterSourceOperation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RegistrationAdapterSourceOperation {
    pub(super) id: String,
    pub(super) helper: RegistrationAdapterExportIdentity,
    pub(super) semantic: RegistrationAdapterSourceOperationSemantic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RegistrationAdapterSourceOperationSemantic {
    pub(super) kind: String,
    pub(super) selector: String,
    pub(super) missing_configuration_error: String,
    pub(super) mismatch_error: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RegistrationAdapterDescriptorEntry {
    pub(super) id: String,
    pub(super) wrapper: RegistrationAdapterExportIdentity,
    pub(super) registration_kind: String,
    pub(super) authentication: RegistrationAdapterAuthentication,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RegistrationAdapterExportIdentity {
    pub(super) module_path: String,
    pub(super) export_name: String,
    pub(super) source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RegistrationAdapterAuthentication {
    pub(super) helper: RegistrationAdapterExportIdentity,
    pub(super) result_kind: String,
    pub(super) result_parameters: Vec<RegistrationAdapterResultParameter>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RegistrationAdapterResultParameter {
    pub(super) callback_parameter_index: usize,
    pub(super) property: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterMaterial {
    pub(super) kind: String,
    pub(super) descriptor: DependencyAdapterDescriptor,
    pub(super) source: RegistrationAdapterSourceMaterial,
    pub(super) current: DependencyAdapterCurrentMaterial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterDescriptor {
    pub(super) kind: String,
    pub(super) adapters: Vec<DependencyAdapterDescriptorEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterDescriptorEntry {
    pub(super) id: String,
    #[serde(rename = "export")]
    pub(super) export_identity: DependencyAdapterExportIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) substitution: Option<DependencyAdapterSubstitutionIdentity>,
    pub(super) material: DependencyAdapterExpectedMaterial,
    pub(super) semantic: DependencyAdapterSemantic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterExportIdentity {
    pub(super) module_path: String,
    pub(super) export_name: String,
    pub(super) unit_source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterSubstitutionIdentity {
    pub(super) module_specifier: String,
    pub(super) export_name: String,
    pub(super) unit_source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterExpectedMaterial {
    pub(super) module_source_sha256: String,
    pub(super) semantic_sources: Vec<DependencyAdapterSemanticSource>,
    pub(super) package_json: DependencyAdapterPackageMaterial,
    pub(super) package_lock: DependencyAdapterLockMaterial,
    pub(super) installed_lock: DependencyAdapterLockMaterial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterSemanticSource {
    pub(super) path: String,
    pub(super) source_sha256: String,
    pub(super) units: Vec<DependencyAdapterSemanticUnit>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterSemanticUnit {
    pub(super) unit_name: String,
    pub(super) unit_source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterPackageMaterial {
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterLockMaterial {
    pub(super) path: String,
    pub(super) package_key: String,
    pub(super) entry_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterSemantic {
    pub(super) kind: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterCurrentMaterial {
    pub(super) files: Vec<DependencyAdapterCurrentFile>,
    pub(super) locks: Vec<DependencyAdapterLockMaterial>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DependencyAdapterCurrentFile {
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) bytes: usize,
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

fn valid_host_secret_selector(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_module_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

pub(crate) fn validate_registration_adapter_material(
    repo_root: &Path,
    material: &RegistrationAdapterMaterial,
) -> Result<()> {
    ensure!(
        material.kind == "convex-wasm-registration-adapter-material",
        "unsupported registration adapter material kind {}",
        material.kind
    );
    ensure!(
        material.descriptor.kind == "convex-wasm-registration-adapter-descriptor",
        "unsupported registration adapter descriptor kind {}",
        material.descriptor.kind
    );
    ensure!(
        valid_module_path(&material.source.path)
            && valid_sha256(&material.source.sha256)
            && material.source.bytes > 0,
        "registration adapter source material identity is invalid"
    );
    let descriptor_path = checked_module_path(repo_root, &material.source.path)?;
    let descriptor_bytes = fs::read(&descriptor_path).with_context(|| {
        format!(
            "failed to read registration adapter descriptor {}",
            descriptor_path.display()
        )
    })?;
    ensure!(
        descriptor_bytes.len() == material.source.bytes
            && hash_bytes(&descriptor_bytes) == material.source.sha256,
        "registration adapter descriptor bytes do not match their authenticated material identity"
    );
    let descriptor: RegistrationAdapterDescriptor = serde_json::from_slice(&descriptor_bytes)
        .with_context(|| {
            format!(
                "invalid registration adapter descriptor {}",
                descriptor_path.display()
            )
        })?;
    ensure!(
        descriptor == material.descriptor,
        "registration adapter request descriptor disagrees with the authenticated descriptor bytes"
    );
    let mut previous = None;
    let mut ids = BTreeSet::new();
    for adapter in &material.descriptor.adapters {
        ensure!(
            valid_identifier(&adapter.id) && ids.insert(adapter.id.as_str()),
            "registration adapter ID is invalid or duplicated: {}",
            adapter.id
        );
        ensure!(
            matches!(adapter.registration_kind.as_str(), "query" | "mutation"),
            "registration adapter {} has unsupported registration kind {}",
            adapter.id,
            adapter.registration_kind
        );
        for identity in [&adapter.wrapper, &adapter.authentication.helper] {
            ensure!(
                valid_module_path(&identity.module_path)
                    && valid_identifier(&identity.export_name)
                    && valid_sha256(&identity.source_sha256),
                "registration adapter {} has an invalid export identity",
                adapter.id
            );
        }
        let key = (
            adapter.wrapper.module_path.as_str(),
            adapter.wrapper.export_name.as_str(),
        );
        if let Some(previous) = previous {
            ensure!(
                previous < key,
                "registration adapters must be sorted by unique wrapper identity"
            );
        }
        previous = Some(key);
        ensure!(
            matches!(
                adapter.authentication.result_kind.as_str(),
                "object" | "value"
            ),
            "registration adapter {} has unsupported authentication result kind {}",
            adapter.id,
            adapter.authentication.result_kind
        );
        if adapter.authentication.result_kind == "value" {
            ensure!(
                adapter.authentication.result_parameters.len() == 1,
                "registration adapter {} value result must bind one whole callback parameter",
                adapter.id
            );
        }
        let mut parameter_indexes = BTreeSet::new();
        for parameter in &adapter.authentication.result_parameters {
            ensure!(
                parameter.callback_parameter_index >= 2
                    && parameter_indexes.insert(parameter.callback_parameter_index),
                "registration adapter {} has an invalid or duplicate callback parameter index",
                adapter.id
            );
            match adapter.authentication.result_kind.as_str() {
                "object" => ensure!(
                    parameter.property.as_deref().is_some_and(valid_identifier),
                    "registration adapter {} object result parameter has no valid property",
                    adapter.id
                ),
                "value" => ensure!(
                    parameter.property.is_none(),
                    "registration adapter {} value result must bind one whole callback parameter",
                    adapter.id
                ),
                _ => unreachable!(),
            }
        }
        for (offset, callback_parameter_index) in parameter_indexes.iter().enumerate() {
            ensure!(
                *callback_parameter_index == offset + 2,
                "registration adapter {} callback parameter indexes must be contiguous from 2",
                adapter.id
            );
        }
    }
    let mut previous_source_operation_id = None;
    let mut source_operation_ids = BTreeSet::new();
    let mut source_operation_helpers = BTreeSet::new();
    for operation in &material.descriptor.source_operations {
        ensure!(
            valid_identifier(&operation.id) && source_operation_ids.insert(operation.id.as_str()),
            "registration source operation ID is invalid or duplicated: {}",
            operation.id
        );
        if let Some(previous) = previous_source_operation_id {
            ensure!(
                previous < operation.id.as_str(),
                "registration source operations must be sorted by unique ID"
            );
        }
        previous_source_operation_id = Some(operation.id.as_str());
        ensure!(
            valid_module_path(&operation.helper.module_path)
                && valid_identifier(&operation.helper.export_name)
                && valid_sha256(&operation.helper.source_sha256),
            "registration source operation {} has an invalid helper identity",
            operation.id
        );
        ensure!(
            source_operation_helpers.insert((
                operation.helper.module_path.as_str(),
                operation.helper.export_name.as_str(),
            )),
            "registration source operation helper identity is duplicated: {}#{}",
            operation.helper.module_path,
            operation.helper.export_name
        );
        ensure!(
            operation.semantic.kind == "hostSecretVerify"
                && valid_host_secret_selector(&operation.semantic.selector)
                && !operation.semantic.missing_configuration_error.is_empty()
                && !operation
                    .semantic
                    .missing_configuration_error
                    .contains('\0')
                && !operation.semantic.mismatch_error.is_empty()
                && !operation.semantic.mismatch_error.contains('\0'),
            "registration source operation {} has invalid host-secret semantics",
            operation.id
        );
    }
    Ok(())
}

fn dependency_lock_entry_sha256(
    repo_root: &Path,
    lock: &DependencyAdapterLockMaterial,
) -> Result<String> {
    let path = checked_module_path(repo_root, &lock.path)?;
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read dependency adapter lock {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid dependency adapter lock {}", path.display()))?;
    let entry = value
        .get("packages")
        .and_then(|packages| packages.get(&lock.package_key))
        .with_context(|| {
            format!(
                "dependency adapter lock {} has no packages[{}] entry",
                lock.path, lock.package_key
            )
        })?;
    Ok(hash_bytes(&serde_json::to_vec(entry)?))
}

pub(super) fn validate_dependency_adapter_material(
    repo_root: &Path,
    material: &DependencyAdapterMaterial,
) -> Result<()> {
    ensure!(
        material.kind == "convex-wasm-dependency-adapter-material",
        "unsupported dependency adapter material kind {}",
        material.kind
    );
    ensure!(
        material.descriptor.kind == "convex-wasm-dependency-adapter-descriptor",
        "unsupported dependency adapter descriptor kind {}",
        material.descriptor.kind
    );
    ensure!(
        valid_module_path(&material.source.path)
            && valid_sha256(&material.source.sha256)
            && material.source.bytes > 0,
        "dependency adapter source material identity is invalid"
    );
    let descriptor_path = checked_module_path(repo_root, &material.source.path)?;
    let descriptor_bytes = fs::read(&descriptor_path).with_context(|| {
        format!(
            "failed to read dependency adapter descriptor {}",
            descriptor_path.display()
        )
    })?;
    ensure!(
        descriptor_bytes.len() == material.source.bytes
            && hash_bytes(&descriptor_bytes) == material.source.sha256,
        "dependency adapter descriptor bytes do not match their authenticated material identity"
    );
    let descriptor: DependencyAdapterDescriptor = serde_json::from_slice(&descriptor_bytes)
        .with_context(|| {
            format!(
                "invalid dependency adapter descriptor {}",
                descriptor_path.display()
            )
        })?;
    ensure!(
        descriptor == material.descriptor,
        "dependency adapter request descriptor disagrees with the authenticated descriptor bytes"
    );
    let mut previous = None;
    let mut ids = BTreeSet::new();
    for adapter in &descriptor.adapters {
        ensure!(
            valid_identifier(&adapter.id) && ids.insert(adapter.id.as_str()),
            "dependency adapter ID is invalid or duplicated: {}",
            adapter.id
        );
        let export = &adapter.export_identity;
        ensure!(
            valid_module_path(&export.module_path)
                && valid_identifier(&export.export_name)
                && valid_sha256(&export.unit_source_sha256),
            "dependency adapter {} has an invalid resolved export identity",
            adapter.id
        );
        let key = (export.module_path.as_str(), export.export_name.as_str());
        if let Some(previous) = previous {
            ensure!(
                previous < key,
                "dependency adapters must be sorted by unique resolved export identity"
            );
        }
        previous = Some(key);
        ensure!(
            matches!(
                adapter.semantic.kind.as_str(),
                "databaseGetBatch"
                    | "databaseGetBatchOrThrow"
                    | "databaseIndexCollect"
                    | "databaseIndexUnique"
                    | "databaseIndexUniqueOrThrow"
                    | "functionHandleCreate"
            ),
            "dependency adapter {} has unsupported semantic kind {}",
            adapter.id,
            adapter.semantic.kind
        );
        ensure!(
            match (&adapter.substitution, adapter.semantic.kind.as_str()) {
                (Some(substitution), "functionHandleCreate") =>
                    valid_module_path(&substitution.module_specifier)
                        && valid_identifier(&substitution.export_name)
                        && valid_sha256(&substitution.unit_source_sha256),
                (None, "functionHandleCreate") | (Some(_), _) => false,
                (None, _) => true,
            },
            "dependency adapter {} has invalid substitution identity",
            adapter.id
        );
        let expected = &adapter.material;
        ensure!(
            valid_sha256(&expected.module_source_sha256)
                && valid_module_path(&expected.package_json.path)
                && valid_sha256(&expected.package_json.sha256)
                && !expected.package_json.version.is_empty(),
            "dependency adapter {} has invalid expected file material",
            adapter.id
        );
        let mut previous_source = None;
        for source in &expected.semantic_sources {
            ensure!(
                valid_module_path(&source.path)
                    && valid_sha256(&source.source_sha256)
                    && !source.units.is_empty(),
                "dependency adapter {} has invalid semantic source material",
                adapter.id
            );
            if let Some(previous) = previous_source {
                ensure!(
                    previous < source.path.as_str(),
                    "dependency adapter {} semantic sources must be sorted and unique",
                    adapter.id
                );
            }
            previous_source = Some(source.path.as_str());
            let mut previous_unit = None;
            for unit in &source.units {
                ensure!(
                    valid_identifier(&unit.unit_name) && valid_sha256(&unit.unit_source_sha256),
                    "dependency adapter {} has invalid semantic unit material",
                    adapter.id
                );
                if let Some(previous) = previous_unit {
                    ensure!(
                        previous < unit.unit_name.as_str(),
                        "dependency adapter {} semantic units must be sorted and unique",
                        adapter.id
                    );
                }
                previous_unit = Some(unit.unit_name.as_str());
            }
        }
        for lock in [&expected.package_lock, &expected.installed_lock] {
            ensure!(
                valid_module_path(&lock.path)
                    && valid_module_path(&lock.package_key)
                    && valid_sha256(&lock.entry_sha256),
                "dependency adapter {} has invalid expected lock material",
                adapter.id
            );
        }
    }
    let mut previous_file = None;
    for file in &material.current.files {
        ensure!(
            valid_module_path(&file.path) && valid_sha256(&file.sha256) && file.bytes > 0,
            "dependency adapter current file material is invalid"
        );
        if let Some(previous) = previous_file {
            ensure!(
                previous < file.path.as_str(),
                "dependency adapter current files must be sorted and unique"
            );
        }
        previous_file = Some(file.path.as_str());
        let path = checked_module_path(repo_root, &file.path)?;
        let bytes = fs::read(&path).with_context(|| {
            format!(
                "failed to read dependency adapter material {}",
                path.display()
            )
        })?;
        ensure!(
            bytes.len() == file.bytes && hash_bytes(&bytes) == file.sha256,
            "dependency adapter current file {} changed after material collection",
            file.path
        );
    }
    let mut previous_lock = None;
    for lock in &material.current.locks {
        ensure!(
            valid_module_path(&lock.path)
                && valid_module_path(&lock.package_key)
                && valid_sha256(&lock.entry_sha256),
            "dependency adapter current lock material is invalid"
        );
        let key = (lock.path.as_str(), lock.package_key.as_str());
        if let Some(previous) = previous_lock {
            ensure!(
                previous < key,
                "dependency adapter current locks must be sorted and unique"
            );
        }
        previous_lock = Some(key);
        ensure!(
            dependency_lock_entry_sha256(repo_root, lock)? == lock.entry_sha256,
            "dependency adapter current lock {} packages[{}] changed after material collection",
            lock.path,
            lock.package_key
        );
    }
    Ok(())
}
