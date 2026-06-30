//! `logs_applied(blob, log1, log2) -> STRUCT(applied, entries_replayed,
//! dirty_pages, became_clean, log_format)` — explicit, auditable inspection of a
//! transaction-log replay against supplied `.LOG1`/`.LOG2` blobs. The seam for
//! cases where logs aren't co-located with the primary in a glob.
//!
//! The actual byte-level replay is `notatin`'s; this probe reports *what* a
//! replay consists of by independently summarizing the log entry stream
//! (`reghive_core::logparse`) and comparing sequence numbers, so the answer is
//! auditable without trusting a side effect.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder, UInt32Builder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use reghive_core::{baseblock, logparse};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::scalar::io::blob_val;

pub struct LogsApplied;

fn fields() -> Fields {
    Fields::from(vec![
        Field::new("applied", DataType::Boolean, true),
        Field::new("entries_replayed", DataType::UInt32, true),
        Field::new("dirty_pages", DataType::UInt32, true),
        Field::new("became_clean", DataType::Boolean, true),
        Field::new("log_format", DataType::Utf8, true),
    ])
}

/// Combine the summaries of up to two logs.
fn combine(logs: &[logparse::LogSummary]) -> (u32, u32, u32, &'static str) {
    let mut entries = 0u32;
    let mut dirty = 0u32;
    let mut max_seq = 0u32;
    let mut fmt = "none";
    for s in logs {
        entries = entries.saturating_add(s.entries);
        dirty = dirty.saturating_add(s.dirty_pages);
        max_seq = max_seq.max(s.max_sequence);
        if s.format_label == "new" {
            fmt = "new";
        } else if s.format_label == "old" && fmt != "new" {
            fmt = "old";
        }
    }
    (entries, dirty, max_seq, fmt)
}

impl ScalarFunction for LogsApplied {
    fn name(&self) -> &str {
        "logs_applied"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Report a transaction-log replay against supplied .LOG1/.LOG2 blobs: \
                          applied, entries_replayed, dirty_pages, became_clean, log_format"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT reghive.main.logs_applied('regf'::BLOB, NULL, NULL);"
                    .into(),
                description: "Inspect a transaction-log replay (NULL struct for a non-hive blob).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Transaction-Log Replay Report",
                "Inspect replaying a dirty hive's transaction logs (.LOG1/.LOG2): whether a replay \
                 applies (the primary is dirty and the logs carry usable entries), how many log \
                 entries would be replayed, the total dirty pages they touch, whether the hive \
                 would become clean, and the log_format (old pre-Win8.1 dirty-vector, new Win8.1+ \
                 HvLE entry stream, or none). Use it when the logs are not co-located with the \
                 primary in a glob.",
                "Report a transaction-log replay against supplied .LOG1/.LOG2 blobs: applied, \
                 entries_replayed, dirty_pages, became_clean, log_format.",
                "logs applied, transaction log, LOG1, LOG2, replay, recovery, dirty hive, became \
                 clean, sequence number, HvLE",
                "scalar/logs_applied.rs",
            ),
            // NULL .LOG args mean "log not available" — receive them, do not
            // null-propagate the whole result.
            null_handling: Some("SPECIAL".to_string()),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::column_typed(
                "blob",
                0,
                DataType::Binary,
                "The dirty primary hive bytes (a BLOB).",
            ),
            ArgSpec::column_typed(
                "log1",
                1,
                DataType::Binary,
                "The first transaction log (.LOG1) bytes, or NULL if not available.",
            ),
            ArgSpec::column_typed(
                "log2",
                2,
                DataType::Binary,
                "The second transaction log (.LOG2) bytes, or NULL if not available.",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let primary = batch.column(0);
        let log1 = batch.column(1);
        let log2 = batch.column(2);
        let rows = batch.num_rows();

        let mut applied = BooleanBuilder::new();
        let mut entries_replayed = UInt32Builder::new();
        let mut dirty_pages = UInt32Builder::new();
        let mut became_clean = BooleanBuilder::new();
        let mut log_format = StringBuilder::new();
        let mut valid: Vec<bool> = Vec::with_capacity(rows);

        for i in 0..rows {
            let p = blob_val(primary, i)?;
            let base = p.as_ref().and_then(|b| baseblock::parse(b).0);
            match base {
                Some(base) => {
                    let was_dirty = base.is_dirty();
                    let mut summaries = Vec::new();
                    if let Some(l) = blob_val(log1, i)? {
                        summaries.push(logparse::summarize(&l));
                    }
                    if let Some(l) = blob_val(log2, i)? {
                        summaries.push(logparse::summarize(&l));
                    }
                    let (entries, dirty, max_seq, fmt) = combine(&summaries);
                    let has_logs = fmt != "none";
                    let did_apply = was_dirty && has_logs;
                    // The hive becomes clean when a replay advances the secondary
                    // sequence to match the primary (new format), or when an
                    // old-format log is present for a dirty primary.
                    let clean = did_apply
                        && (fmt == "old" || max_seq >= base.primary_seq.max(base.secondary_seq));

                    applied.append_value(did_apply);
                    entries_replayed.append_value(entries);
                    dirty_pages.append_value(dirty);
                    became_clean.append_value(clean);
                    log_format.append_value(fmt);
                    valid.push(true);
                }
                None => {
                    applied.append_null();
                    entries_replayed.append_null();
                    dirty_pages.append_null();
                    became_clean.append_null();
                    log_format.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(applied.finish()),
            Arc::new(entries_replayed.finish()),
            Arc::new(dirty_pages.finish()),
            Arc::new(became_clean.finish()),
            Arc::new(log_format.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(
            fields(),
            arrays,
            Some(NullBuffer::from(valid)),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
