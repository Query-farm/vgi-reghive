//! `hive_info(blob) -> STRUCT(hive_type, major, minor, root_path, primary_seq,
//! secondary_seq, is_dirty, last_written)` — the base-block summary; the
//! triage-first probe ("is this hive recovered, or do I need logs?").

use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, StringBuilder, TimestampMicrosecondBuilder, UInt16Builder, UInt32Builder,
};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use reghive_core::baseblock;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_map::timestamptz;
use crate::scalar::io::blob_val;

pub struct HiveInfo;

fn fields() -> Fields {
    Fields::from(vec![
        Field::new("hive_type", DataType::Utf8, true),
        Field::new("major", DataType::UInt16, true),
        Field::new("minor", DataType::UInt16, true),
        Field::new("root_path", DataType::Utf8, true),
        Field::new("primary_seq", DataType::UInt32, true),
        Field::new("secondary_seq", DataType::UInt32, true),
        Field::new("is_dirty", DataType::Boolean, true),
        Field::new("last_written", timestamptz(), true),
    ])
}

impl ScalarFunction for HiveInfo {
    fn name(&self) -> &str {
        "hive_info"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Summarize a hive's base block: type, version, sequence numbers, dirty \
                          flag, and last-written time"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT reghive.main.hive_info('\\x72656766'::BLOB);".into(),
                description: "Probe a hive's base-block summary (returns NULL on a non-hive blob)."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Hive Header Summary",
                "Return the regf base-block summary of a hive BLOB: logical hive_type, major/minor \
                 format version, the canonical root path, the primary/secondary sequence numbers, \
                 the is_dirty recovery flag (true when the checksum is wrong or the sequence \
                 numbers disagree), and the header's last-written UTC timestamp. The triage-first \
                 probe to decide whether a hive needs transaction-log recovery.",
                "Summarize a hive's base block (type, version, sequence numbers, is_dirty, \
                 last_written). Returns NULL for a non-hive blob.",
                "hive info, base block, header, is_dirty, sequence number, version, recovery, \
                 triage, regf",
                "Header & validation",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "blob",
            0,
            DataType::Binary,
            "The raw contents of a registry hive file, e.g. from read_blob('NTUSER.DAT'). NULL or \
             a non-hive input yields a NULL struct.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();

        let mut hive_type = StringBuilder::new();
        let mut major = UInt16Builder::new();
        let mut minor = UInt16Builder::new();
        let mut root_path = StringBuilder::new();
        let mut primary_seq = UInt32Builder::new();
        let mut secondary_seq = UInt32Builder::new();
        let mut is_dirty = BooleanBuilder::new();
        let mut last_written = TimestampMicrosecondBuilder::new().with_timezone("UTC");
        let mut valid: Vec<bool> = Vec::with_capacity(rows);

        for i in 0..rows {
            let bytes = blob_val(col, i)?;
            let bb = bytes.as_ref().and_then(|b| baseblock::parse(b).0);
            match bb {
                Some(bb) => {
                    // root_path: best-effort root key name via notatin.
                    let root = bytes
                        .as_ref()
                        .and_then(|b| crate::hive::open::open_blob(b, false, false, &[]).ok())
                        .map(|o| o.root_name);
                    hive_type.append_value(bb.hive_type(root.as_deref()).label());
                    major.append_value(bb.major as u16);
                    minor.append_value(bb.minor as u16);
                    match root {
                        Some(r) if !r.is_empty() => root_path.append_value(r),
                        _ => root_path.append_null(),
                    }
                    primary_seq.append_value(bb.primary_seq);
                    secondary_seq.append_value(bb.secondary_seq);
                    is_dirty.append_value(bb.is_dirty());
                    last_written
                        .append_value(baseblock::filetime_to_unix_micros(bb.last_written_filetime));
                    valid.push(true);
                }
                None => {
                    hive_type.append_null();
                    major.append_null();
                    minor.append_null();
                    root_path.append_null();
                    primary_seq.append_null();
                    secondary_seq.append_null();
                    is_dirty.append_null();
                    last_written.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(hive_type.finish()),
            Arc::new(major.finish()),
            Arc::new(minor.finish()),
            Arc::new(root_path.finish()),
            Arc::new(primary_seq.finish()),
            Arc::new(secondary_seq.finish()),
            Arc::new(is_dirty.finish()),
            Arc::new(last_written.finish()),
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
