use std::collections::BTreeSet;

use anyhow::{Result, ensure};

use super::effect_plan::{
    AuthorizedEffectLeaf, SemanticEffectKey, SemanticStaticEffectOperand, SourceAnchor,
};
use super::generated_source::{SourceEdit, apply_source_edits, edit_is_owned_by, source_edit};
use super::{ReachableUnit, hash_bytes, source_slice};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorizedDirectEffectVariant {
    pub(super) effect_key: SemanticEffectKey,
    pub(super) static_operands: Vec<SemanticStaticEffectOperand>,
    pub(super) dynamic_operands: Vec<AuthorizedDirectDynamicOperand>,
    pub(super) effect: AuthorizedEffectLeaf,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthorizedDirectDynamicOperand {
    pub(super) target_argument_index: Option<usize>,
    pub(super) target_provenance: SourceAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorizedDirectEffectSite {
    pub(super) authorization_id: String,
    pub(super) target_effect: SourceAnchor,
    pub(super) target_callee: SourceAnchor,
    pub(super) variants: Vec<AuthorizedDirectEffectVariant>,
}

pub(super) fn supports_direct_effect_site(effect_key: &SemanticEffectKey) -> bool {
    matches!(
        effect_key.operation_kind.as_str(),
        "databaseGet"
            | "databaseInsert"
            | "databasePatch"
            | "databaseReplace"
            | "databaseDelete"
            | "databaseIndexQuery"
            | "schedulerRunAfter"
            | "schedulerRunAt"
    )
}

pub(super) fn direct_effect_site_helper_name(site: &AuthorizedDirectEffectSite) -> String {
    format!("__convexEffectSite_{}", site.authorization_id)
}

pub(super) fn array_producing_direct_effect_site_helpers(
    sites: &[AuthorizedDirectEffectSite],
) -> Result<BTreeSet<String>> {
    let mut helpers = BTreeSet::new();
    for site in sites {
        let first = site.variants.first().ok_or_else(|| {
            anyhow::anyhow!("authorized direct effect site has no exact variants")
        })?;
        ensure!(
            site.variants
                .iter()
                .all(|variant| variant.effect_key.result_kind == first.effect_key.result_kind),
            "authorized direct effect-site variants disagree about result kind"
        );
        if first.effect_key.result_kind == "hostArray" {
            let name = direct_effect_site_helper_name(site);
            ensure!(
                helpers.insert(name.clone()),
                "duplicate array-producing direct effect-site helper {name}"
            );
        }
    }
    Ok(helpers)
}

fn helper_variant_guard(variant: &AuthorizedDirectEffectVariant) -> Result<String> {
    let [operand] = variant.static_operands.as_slice() else {
        anyhow::bail!("direct effect site does not have one exact static operand")
    };
    let argument_index = operand.target_argument_index.ok_or_else(|| {
        anyhow::anyhow!("direct effect site static operand has no argument index")
    })?;
    let argument = format!("argument{argument_index}");
    if operand.field == "table" {
        ensure!(
            variant.effect_key.static_operands.len() == 1
                && variant.effect_key.static_operands.get("table") == Some(&operand.value),
            "direct database effect site has an unexpected static operand set"
        );
        return Ok(format!(
            "{argument} === {}",
            serde_json::to_string(&operand.value)?
        ));
    }
    ensure!(
        matches!(
            variant.effect_key.operation_kind.as_str(),
            "schedulerRunAfter" | "schedulerRunAt"
        ) && operand.field == "functionReference"
            && variant.effect_key.static_operands.len() == 1
            && variant.effect_key.static_operands.get("functionReference") == Some(&operand.value),
        "direct scheduler effect site has an unexpected static operand set"
    );
    Ok(format!(
        "__convexInternalFunctionReference({argument}) === {}",
        serde_json::to_string(&operand.value)?
    ))
}

fn helper_layout(variant: &AuthorizedDirectEffectVariant) -> Result<(String, String)> {
    let mut indices = BTreeSet::new();
    for operand in &variant.static_operands {
        ensure!(
            indices.insert(operand.target_argument_index.ok_or_else(|| {
                anyhow::anyhow!("direct effect site static operand has no argument index")
            })?),
            "direct effect site duplicates an argument projection"
        );
    }
    let mut dynamic_indices = Vec::new();
    for operand in &variant.dynamic_operands {
        let index = operand.target_argument_index.ok_or_else(|| {
            anyhow::anyhow!("direct effect site dynamic operand has no argument index")
        })?;
        ensure!(
            indices.insert(index),
            "direct effect site duplicates an argument projection"
        );
        dynamic_indices.push(index);
    }
    let argument_count = indices.last().copied().map_or(0, |index| index + 1);
    ensure!(
        indices == (0..argument_count).collect(),
        "direct effect site argument provenance is not contiguous"
    );
    Ok((
        (0..argument_count)
            .map(|index| format!("argument{index}"))
            .collect::<Vec<_>>()
            .join(", "),
        format!(
            "[{}]",
            dynamic_indices
                .iter()
                .map(|index| format!("argument{index}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ))
}

pub(super) fn direct_effect_site_helper_source(
    sites: &[AuthorizedDirectEffectSite],
    bindings: &mut BTreeSet<String>,
) -> Result<String> {
    if !sites.is_empty() {
        ensure!(
            bindings.insert("__convexStartAsyncOperation".to_string()),
            "generated direct effect sites conflict with the guest async-operation primitive"
        );
    }
    let mut output = String::new();
    for site in sites {
        ensure!(
            !site.variants.is_empty(),
            "authorized direct effect site has no exact variants"
        );
        let kind = &site.variants[0].effect_key.operation_kind;
        ensure!(
            site.variants
                .iter()
                .all(|variant| variant.effect_key.operation_kind == *kind),
            "authorized direct effect site mixes operation kinds"
        );
        if kind == "databaseIndexQuery" {
            let [variant] = site.variants.as_slice() else {
                anyhow::bail!("whole-effect index-query site must have one exact descriptor")
            };
            ensure!(
                variant.static_operands.is_empty()
                    && variant
                        .dynamic_operands
                        .iter()
                        .all(|operand| operand.target_argument_index.is_none()),
                "whole-effect index-query site has direct-call argument projections"
            );
            let name = direct_effect_site_helper_name(site);
            ensure!(
                bindings.insert(name.clone()),
                "generated direct effect-site helper binding collision for {name}"
            );
            let parameters = (0..variant.dynamic_operands.len())
                .map(|index| format!("argument{index}"))
                .collect::<Vec<_>>()
                .join(", ");
            let arguments = (0..variant.dynamic_operands.len())
                .map(|index| format!("argument{index}"))
                .collect::<Vec<_>>()
                .join(", ");
            output.push_str(&format!(
                "function {name}({parameters}) {{\n  return __convexStartAsyncOperation({}, [{arguments}]);\n}}\n\n",
                variant.effect.operation_id
            ));
            continue;
        }
        let (parameters, dynamic_arguments) = helper_layout(&site.variants[0])?;
        ensure!(
            site.variants
                .iter()
                .skip(1)
                .map(helper_layout)
                .collect::<Result<Vec<_>>>()?
                .iter()
                .all(|layout| layout == &(parameters.clone(), dynamic_arguments.clone())),
            "authorized direct effect-site variants disagree about argument provenance"
        );
        let name = direct_effect_site_helper_name(site);
        ensure!(
            bindings.insert(name.clone()),
            "generated direct effect-site helper binding collision for {name}"
        );
        output.push_str(&format!("function {name}({parameters}) {{\n"));
        let mut guards = BTreeSet::new();
        for variant in &site.variants {
            let guard = helper_variant_guard(variant)?;
            ensure!(
                guards.insert(guard.clone()),
                "authorized direct effect site has a duplicate exact static variant"
            );
            output.push_str(&format!(
                "  if ({guard}) return __convexStartAsyncOperation({}, {dynamic_arguments});\n",
                variant.effect.operation_id
            ));
        }
        output.push_str(
            "  throw new Error(\"Convex effect site received an unauthorized static operand\");\n}\n\n",
        );
    }
    Ok(output)
}

pub(super) fn append_direct_effect_site_edits(
    source: &str,
    unit: &ReachableUnit,
    sites: &[AuthorizedDirectEffectSite],
    consumed: &mut BTreeSet<String>,
    edits: &mut Vec<SourceEdit>,
) -> Result<()> {
    for site in sites.iter().filter(|site| {
        site.target_callee.module == unit.module
            && site.target_callee.start >= unit.start
            && site.target_callee.end <= unit.end
    }) {
        let name = direct_effect_site_helper_name(site);
        ensure!(
            !source.contains(&name),
            "source unit already uses reserved direct effect-site helper {name}"
        );
        let whole_effect = site
            .variants
            .first()
            .is_some_and(|variant| variant.effect_key.operation_kind == "databaseIndexQuery");
        let anchor = if whole_effect {
            &site.target_effect
        } else {
            &site.target_callee
        };
        let start = anchor.start - unit.start;
        let end = anchor.end - unit.start;
        ensure!(
            hash_bytes(source_slice(source, start, end)?.as_bytes()) == anchor.slice_sha256,
            "authenticated direct effect-site source changed before source emission"
        );
        let replacement = if whole_effect {
            let [variant] = site.variants.as_slice() else {
                anyhow::bail!("whole-effect index-query site has multiple variants")
            };
            let nested_edits = edits.clone();
            let arguments = variant
                .dynamic_operands
                .iter()
                .map(|operand| {
                    let operand = &operand.target_provenance;
                    ensure!(
                        operand.module == unit.module
                            && operand.start >= site.target_effect.start
                            && operand.end <= site.target_effect.end,
                        "whole-effect index-query operand escaped its authenticated target"
                    );
                    apply_source_edits(
                        source,
                        operand.start - unit.start,
                        operand.end - unit.start,
                        &nested_edits,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            edits.retain(|edit| !edit_is_owned_by(edit, start, end));
            format!("{name}({})", arguments.join(", "))
        } else {
            name
        };
        edits.push(source_edit(start, end, replacement, (start, end)));
        ensure!(
            consumed.insert(site.authorization_id.clone()),
            "authorized direct effect site was consumed more than once"
        );
    }
    Ok(())
}
