//! `well_formed(blob) -> STRUCT(ok BOOL, hive_type VARCHAR, error VARCHAR,
//! kind VARCHAR)` — validate a blob as a primary regf hive. **Never panics** — a
//! hostile / garbage / truncated blob returns `ok = false`, never a crash.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_schema::{DataType, Field, Fields};
use reghive_core::baseblock::{self, WellFormedKind};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::scalar::io::blob_val;

pub struct WellFormed;

fn fields() -> Fields {
    Fields::from(vec![
        Field::new("ok", DataType::Boolean, true),
        Field::new("hive_type", DataType::Utf8, true),
        Field::new("error", DataType::Utf8, true),
        Field::new("kind", DataType::Utf8, true),
    ])
}

fn error_for(kind: WellFormedKind) -> Option<&'static str> {
    match kind {
        WellFormedKind::Ok => None,
        WellFormedKind::Truncated => Some("blob too short to be a hive"),
        WellFormedKind::ShortBaseBlock => Some("incomplete base block"),
        WellFormedKind::BadSignature => Some("not a regf hive (bad signature)"),
        WellFormedKind::NotAHive => Some("regf file is not a primary hive"),
        WellFormedKind::BadChecksum => Some("base-block checksum mismatch (dirty hive)"),
        WellFormedKind::BinSizeOverrun => Some("hive-bins size overruns the blob"),
    }
}

impl ScalarFunction for WellFormed {
    fn name(&self) -> &str {
        "well_formed"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Validate a BLOB as a primary regf hive; never panics on hostile input"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT reghive.main.well_formed('not a hive'::BLOB);".into(),
                description: "Validate a blob as a regf hive (ok=false for non-hives).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Validate Hive",
                "Check whether a BLOB is a parseable primary regf hive without walking it. Returns \
                 ok (boolean), the best-effort hive_type, a human error message, and a kind tag \
                 (one of not-a-hive, bad-signature, bad-checksum, truncated, short-base-block, \
                 bin-size-overrun). Never raises — a garbage or truncated blob returns ok=false so \
                 a bulk scan never crashes on one bad file.",
                "Validate a BLOB as a regf hive: returns ok, hive_type, error, and a kind tag. \
                 Never panics on hostile input.",
                "well formed, validate, is hive, regf, bad signature, bad checksum, truncated, \
                 corrupt, sanity check",
                "scalar/well_formed.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "blob",
            0,
            DataType::Binary,
            "The bytes to validate (a BLOB). NULL yields a NULL struct; any non-hive bytes yield \
             ok=false with a kind tag rather than an error.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();

        let mut ok = BooleanBuilder::new();
        let mut hive_type = StringBuilder::new();
        let mut error = StringBuilder::new();
        let mut kind = StringBuilder::new();

        for i in 0..rows {
            match blob_val(col, i)? {
                Some(bytes) => {
                    let (bb, k) = baseblock::parse(&bytes);
                    ok.append_value(k == WellFormedKind::Ok);
                    let root = crate::hive::open::open_blob(&bytes, false, false, &[])
                        .ok()
                        .map(|o| o.root_name);
                    match bb {
                        Some(bb) => hive_type.append_value(bb.hive_type(root.as_deref()).label()),
                        None => hive_type.append_value("UNKNOWN"),
                    }
                    error.append_option(error_for(k));
                    kind.append_value(k.label());
                }
                None => {
                    // NULL input -> a row of NULLs (no struct-level null buffer
                    // here; well_formed is a total function over present bytes).
                    ok.append_null();
                    hive_type.append_null();
                    error.append_null();
                    kind.append_null();
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(ok.finish()),
            Arc::new(hive_type.finish()),
            Arc::new(error.finish()),
            Arc::new(kind.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(fields(), arrays, None));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
