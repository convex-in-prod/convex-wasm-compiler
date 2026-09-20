use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::{Diagnostic, hash_bytes};

pub(super) const DIAGNOSTIC_CENSUS_MEMBERSHIP_KIND: &str =
    "convex-wasm-batch-diagnostic-census-membership";
pub(super) const MAX_DIAGNOSTIC_CENSUS_MEMBERSHIP_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DiagnosticCensusKey {
    pub(super) code: String,
    pub(super) message: String,
    pub(super) file: String,
    pub(super) line: usize,
    pub(super) column: usize,
    pub(super) construct: Option<String>,
    pub(super) source: String,
}

impl From<&Diagnostic> for DiagnosticCensusKey {
    fn from(diagnostic: &Diagnostic) -> Self {
        Self {
            code: diagnostic.code.clone(),
            message: diagnostic.message.clone(),
            file: diagnostic.file.clone(),
            line: diagnostic.line,
            column: diagnostic.column,
            construct: diagnostic.construct.clone(),
            source: diagnostic.source.clone(),
        }
    }
}

pub(super) fn diagnostic_census_id(diagnostic: &DiagnosticCensusKey) -> Result<String> {
    Ok(format!(
        "diagnostic_{}",
        hash_bytes(&serde_json::to_vec(&(
            &diagnostic.code,
            &diagnostic.message,
            &diagnostic.file,
            diagnostic.line,
            diagnostic.column,
            &diagnostic.construct,
            &diagnostic.source,
        ))?)
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BatchDiagnosticCensusEntry {
    pub(super) id: String,
    pub(super) code: String,
    pub(super) message: String,
    pub(super) file: String,
    pub(super) line: usize,
    pub(super) column: usize,
    pub(super) construct: Option<String>,
    pub(super) source: String,
    pub(super) occurrence_count: usize,
    pub(super) export_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DiagnosticCensusMembership {
    kind: &'static str,
    by_result_index: Vec<Vec<usize>>,
}

impl DiagnosticCensusMembership {
    fn new(by_result_index: Vec<Vec<usize>>) -> Self {
        Self {
            kind: DIAGNOSTIC_CENSUS_MEMBERSHIP_KIND,
            by_result_index,
        }
    }

    pub(super) fn telemetry(&self) -> Result<DiagnosticCensusMembershipTelemetry> {
        self.telemetry_with_max_bytes(MAX_DIAGNOSTIC_CENSUS_MEMBERSHIP_BYTES)
    }

    fn telemetry_with_max_bytes(
        &self,
        max_bytes: usize,
    ) -> Result<DiagnosticCensusMembershipTelemetry> {
        let bytes = serialized_size(self)?;
        ensure!(
            bytes <= max_bytes,
            "diagnostic census membership exceeds {max_bytes} bytes: {bytes}"
        );
        let mut reference_count = 0usize;
        let mut max_references_per_result = 0usize;
        for indexes in &self.by_result_index {
            reference_count = reference_count
                .checked_add(indexes.len())
                .context("diagnostic census membership reference count overflow")?;
            max_references_per_result = max_references_per_result.max(indexes.len());
        }
        Ok(DiagnosticCensusMembershipTelemetry {
            bytes,
            reference_count,
            max_references_per_result,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct DiagnosticCensusTelemetry {
    pub(super) occurrence_count: usize,
    pub(super) distinct_count: usize,
    pub(super) max_diagnostics_per_export: usize,
    pub(super) membership_reference_count: usize,
}

#[derive(Clone, Copy, Default)]
pub(super) struct DiagnosticCensusMembershipTelemetry {
    pub(super) bytes: usize,
    pub(super) reference_count: usize,
    pub(super) max_references_per_result: usize,
}

#[derive(Default)]
struct DiagnosticCensusCounts {
    occurrence_count: usize,
    export_count: usize,
}

struct ProvisionalDiagnosticCensusEntry {
    ordinal: usize,
    counts: DiagnosticCensusCounts,
}

pub(super) struct DiagnosticCensusAccumulator {
    entries: BTreeMap<DiagnosticCensusKey, ProvisionalDiagnosticCensusEntry>,
    keys_by_ordinal: Vec<DiagnosticCensusKey>,
    membership_by_result_index: Option<Vec<Option<Vec<usize>>>>,
    recorded_results: Vec<bool>,
    occurrence_count: usize,
    max_diagnostics_per_export: usize,
    membership_reference_count: usize,
}

impl DiagnosticCensusAccumulator {
    pub(super) fn new(result_count: usize, capture_membership: bool) -> Self {
        Self {
            entries: BTreeMap::new(),
            keys_by_ordinal: Vec::new(),
            membership_by_result_index: capture_membership.then(|| vec![None; result_count]),
            recorded_results: vec![false; result_count],
            occurrence_count: 0,
            max_diagnostics_per_export: 0,
            membership_reference_count: 0,
        }
    }

    pub(super) fn record_result(
        &mut self,
        result_index: usize,
        diagnostics: Vec<DiagnosticCensusKey>,
    ) -> Result<()> {
        let recorded = self
            .recorded_results
            .get_mut(result_index)
            .with_context(|| {
                format!("diagnostic census result index {result_index} is out of range")
            })?;
        ensure!(
            !*recorded,
            "diagnostic census result index {result_index} was recorded more than once"
        );
        *recorded = true;
        self.occurrence_count = self
            .occurrence_count
            .checked_add(diagnostics.len())
            .context("diagnostic census occurrence count overflow")?;
        self.max_diagnostics_per_export = self.max_diagnostics_per_export.max(diagnostics.len());

        let mut provisional_membership = BTreeSet::new();
        for diagnostic in diagnostics {
            let next_ordinal = self.entries.len();
            let entry = self.entries.entry(diagnostic.clone()).or_insert_with(|| {
                self.keys_by_ordinal.push(diagnostic);
                ProvisionalDiagnosticCensusEntry {
                    ordinal: next_ordinal,
                    counts: DiagnosticCensusCounts::default(),
                }
            });
            entry.counts.occurrence_count = entry
                .counts
                .occurrence_count
                .checked_add(1)
                .context("diagnostic census entry occurrence count overflow")?;
            provisional_membership.insert(entry.ordinal);
        }
        for ordinal in &provisional_membership {
            let key = self
                .keys_by_ordinal
                .get(*ordinal)
                .context("diagnostic census provisional ordinal disappeared")?;
            let entry = self
                .entries
                .get_mut(key)
                .context("diagnostic census provisional entry disappeared")?;
            entry.counts.export_count = entry
                .counts
                .export_count
                .checked_add(1)
                .context("diagnostic census entry export count overflow")?;
        }
        self.membership_reference_count = self
            .membership_reference_count
            .checked_add(provisional_membership.len())
            .context("diagnostic census membership reference count overflow")?;
        if let Some(by_result_index) = &mut self.membership_by_result_index {
            let slot = by_result_index
                .get_mut(result_index)
                .context("diagnostic census membership result index disappeared")?;
            ensure!(
                slot.replace(provisional_membership.into_iter().collect())
                    .is_none(),
                "diagnostic census membership result index {result_index} was recorded more than once"
            );
        }
        Ok(())
    }

    pub(super) fn telemetry(&self) -> DiagnosticCensusTelemetry {
        DiagnosticCensusTelemetry {
            occurrence_count: self.occurrence_count,
            distinct_count: self.entries.len(),
            max_diagnostics_per_export: self.max_diagnostics_per_export,
            membership_reference_count: self.membership_reference_count,
        }
    }

    pub(super) fn finalize(self) -> Result<FinalizedDiagnosticCensus> {
        for (index, recorded) in self.recorded_results.iter().enumerate() {
            ensure!(*recorded, "diagnostic census omitted result index {index}");
        }
        let telemetry = self.telemetry();
        let mut final_index_by_ordinal = vec![usize::MAX; self.entries.len()];
        let mut ids = BTreeSet::new();
        let mut entries = Vec::with_capacity(self.entries.len());
        for (final_index, (diagnostic, provisional)) in self.entries.into_iter().enumerate() {
            let id = diagnostic_census_id(&diagnostic)?;
            ensure!(
                ids.insert(id.clone()),
                "diagnostic census ID collision for {id}"
            );
            final_index_by_ordinal[provisional.ordinal] = final_index;
            entries.push(BatchDiagnosticCensusEntry {
                id,
                code: diagnostic.code,
                message: diagnostic.message,
                file: diagnostic.file,
                line: diagnostic.line,
                column: diagnostic.column,
                construct: diagnostic.construct,
                source: diagnostic.source,
                occurrence_count: provisional.counts.occurrence_count,
                export_count: provisional.counts.export_count,
            });
        }
        ensure!(
            final_index_by_ordinal
                .iter()
                .all(|index| *index != usize::MAX),
            "diagnostic census final index remapping is incomplete"
        );
        let membership = self
            .membership_by_result_index
            .map(|by_result_index| {
                by_result_index
                    .into_iter()
                    .enumerate()
                    .map(|(result_index, provisional)| {
                        let mut indexes = provisional.with_context(|| {
                            format!(
                                "diagnostic census membership omitted result index {result_index}"
                            )
                        })?;
                        for index in &mut indexes {
                            *index = *final_index_by_ordinal.get(*index).with_context(|| {
                                format!(
                                    "diagnostic census membership result {result_index} has an invalid provisional ordinal"
                                )
                            })?;
                        }
                        indexes.sort_unstable();
                        ensure!(
                            indexes.windows(2).all(|pair| pair[0] < pair[1]),
                            "diagnostic census membership result {result_index} is not strictly sorted and deduplicated"
                        );
                        Ok(indexes)
                    })
                    .collect::<Result<Vec<_>>>()
                    .map(DiagnosticCensusMembership::new)
            })
            .transpose()?;
        Ok(FinalizedDiagnosticCensus {
            entries,
            membership,
            telemetry,
        })
    }
}

pub(super) struct FinalizedDiagnosticCensus {
    pub(super) entries: Vec<BatchDiagnosticCensusEntry>,
    pub(super) membership: Option<DiagnosticCensusMembership>,
    pub(super) telemetry: DiagnosticCensusTelemetry,
}

#[derive(Default)]
struct ByteCounter {
    bytes: usize,
}

impl Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("serialized byte count overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialized_size<T: Serialize>(value: &T) -> Result<usize> {
    let mut counter = ByteCounter::default();
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: &str, line: usize) -> DiagnosticCensusKey {
        DiagnosticCensusKey {
            code: code.to_string(),
            message: format!("{code} message"),
            file: "convex/test.ts".to_string(),
            line,
            column: 1,
            construct: Some("Identifier".to_string()),
            source: format!("{code} source"),
        }
    }

    #[test]
    fn finalizes_sorted_exact_membership_after_out_of_order_results() -> Result<()> {
        let alpha = key("alpha", 1);
        let beta = key("beta", 2);
        let shared = key("shared", 3);
        let mut accumulator = DiagnosticCensusAccumulator::new(2, true);
        accumulator.record_result(1, vec![beta.clone(), shared.clone()])?;
        accumulator.record_result(0, vec![alpha.clone(), alpha, shared])?;
        let finalized = accumulator.finalize()?;
        assert_eq!(
            finalized
                .entries
                .iter()
                .map(|entry| entry.code.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta", "shared"]
        );
        assert_eq!(finalized.entries[0].occurrence_count, 2);
        assert_eq!(finalized.entries[0].export_count, 1);
        assert_eq!(finalized.entries[2].export_count, 2);
        assert_eq!(
            finalized.membership.expect("membership").by_result_index,
            [vec![0, 2], vec![1, 2]]
        );
        Ok(())
    }

    #[test]
    fn membership_is_not_capped_at_sixteen_diagnostics() -> Result<()> {
        let diagnostics = (0..20)
            .map(|index| key(&format!("diagnostic-{index:02}"), index + 1))
            .collect::<Vec<_>>();
        let mut accumulator = DiagnosticCensusAccumulator::new(1, true);
        accumulator.record_result(0, diagnostics)?;
        let finalized = accumulator.finalize()?;
        assert_eq!(finalized.entries.len(), 20);
        assert_eq!(
            finalized.membership.expect("membership").by_result_index[0],
            (0..20).collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn membership_dto_serialization_limit_fails_instead_of_truncating() -> Result<()> {
        let membership = DiagnosticCensusMembership::new(vec![vec![0, 2], vec![]]);
        let serialized_bytes = serialized_size(&membership)?;
        let telemetry = membership.telemetry_with_max_bytes(serialized_bytes)?;
        assert_eq!(telemetry.bytes, serialized_bytes);
        assert_eq!(telemetry.reference_count, 2);
        assert_eq!(telemetry.max_references_per_result, 2);
        let oversized_error = membership
            .telemetry_with_max_bytes(serialized_bytes - 1)
            .err()
            .expect("oversized membership");
        assert_eq!(
            oversized_error.to_string(),
            format!(
                "diagnostic census membership exceeds {} bytes: {serialized_bytes}",
                serialized_bytes - 1
            )
        );
        Ok(())
    }
}
