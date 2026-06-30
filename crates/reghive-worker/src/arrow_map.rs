//! The §5 output schema and the row → Arrow `RecordBatch` mapping for
//! `read_hive` / `hive_subtree`, plus the small struct types the scalar probes
//! return. Centralizes every explicit Arrow type (TIMESTAMPTZ, BLOB, nested
//! STRUCT/LIST) so the schema is declared once and built once.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, Int64Builder, StringBuilder, TimestampMicrosecondBuilder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef, TimeUnit};
use vgi_rpc::{Result, RpcError};

/// DuckDB `TIMESTAMPTZ` maps to Arrow `Timestamp(Microsecond, "UTC")`.
pub fn timestamptz() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
}

/// A field carrying a `comment` (surfaced via `duckdb_columns().comment`).
fn commented(name: &str, ty: DataType, nullable: bool, comment: &str) -> Field {
    Field::new(name, ty, nullable).with_metadata(HashMap::from([(
        "comment".to_string(),
        comment.to_string(),
    )]))
}

/// The §5 row schema returned by `read_hive` and `hive_subtree`.
pub fn row_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "key_path",
            DataType::Utf8,
            false,
            "Full path from the hive root (backslash-separated; the synthetic root key name is \
             stripped, no synthetic HKLM mount). Deleted orphans use a `$Deleted\\…` prefix.",
        ),
        commented(
            "value_name",
            DataType::Utf8,
            true,
            "Value name; NULL for the key's (Default) value and for key-only rows.",
        ),
        commented(
            "value_type",
            DataType::Utf8,
            true,
            "REG_* type name, e.g. REG_SZ / REG_DWORD / REG_MULTI_SZ / REG_BINARY, or REG_<n> for \
             an unrecognized code. NULL on key-only rows.",
        ),
        commented(
            "value_data",
            DataType::Utf8,
            true,
            "Typed/coerced rendering: UTF-16 decoded for strings, ints stringified, MULTI_SZ joined \
             with newlines, binary as lowercase hex. Lossy for binary — see value_raw.",
        ),
        commented(
            "value_raw",
            DataType::Binary,
            true,
            "The exact on-disk value bytes (lossless). The credential-bearing column for SAM / \
             SECURITY hives — never decoded by the worker; pair with vgi-mask to redact.",
        ),
        commented(
            "value_dword",
            DataType::Int64,
            true,
            "Populated for REG_DWORD / REG_QWORD (NULL otherwise) — saves a cast in the common \
             integer case.",
        ),
        commented(
            "key_last_write",
            timestamptz(),
            true,
            "Parent key's last-write FILETIME as a UTC timestamp; repeated across that key's value \
             rows. The primary registry-forensics time pivot.",
        ),
        commented(
            "is_deleted",
            DataType::Boolean,
            false,
            "True when the row was reconstructed from unallocated space (deleted-cell recovery).",
        ),
        commented(
            "hive_type",
            DataType::Utf8,
            true,
            "Best-effort logical hive type: SYSTEM / SOFTWARE / NTUSER / SAM / SECURITY / USRCLASS \
             / AMCACHE / UNKNOWN.",
        ),
        commented(
            "source",
            DataType::Utf8,
            true,
            "Originating file path (glob member) or '<blob>' for an in-memory hive.",
        ),
        commented(
            "recovery",
            DataType::Utf8,
            true,
            "NULL on a clean live cell; else dirty-no-logs, logs-applied, deleted-orphan, \
             deleted-reparented, or modified-prior.",
        ),
        commented(
            "diagnostics",
            DataType::Utf8,
            true,
            "NULL on clean decode; else truncated, bad-checksum, bad-utf16, etc.",
        ),
    ]))
}

/// One normalized output row (§5).
#[derive(Clone, Debug, Default)]
pub struct Row {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_type: Option<String>,
    pub value_data: Option<String>,
    pub value_raw: Option<Vec<u8>>,
    pub value_dword: Option<i64>,
    pub key_last_write: Option<i64>,
    pub is_deleted: bool,
    pub hive_type: String,
    pub source: String,
    pub recovery: Option<String>,
    pub diagnostics: Option<String>,
}

/// Accumulates [`Row`]s and finalizes a `RecordBatch` in the §5 schema.
pub struct RowBatchBuilder {
    schema: SchemaRef,
    key_path: StringBuilder,
    value_name: StringBuilder,
    value_type: StringBuilder,
    value_data: StringBuilder,
    value_raw: BinaryBuilder,
    value_dword: Int64Builder,
    key_last_write: TimestampMicrosecondBuilder,
    is_deleted: BooleanBuilder,
    hive_type: StringBuilder,
    source: StringBuilder,
    recovery: StringBuilder,
    diagnostics: StringBuilder,
    len: usize,
}

impl RowBatchBuilder {
    pub fn new(schema: SchemaRef) -> Self {
        RowBatchBuilder {
            schema,
            key_path: StringBuilder::new(),
            value_name: StringBuilder::new(),
            value_type: StringBuilder::new(),
            value_data: StringBuilder::new(),
            value_raw: BinaryBuilder::new(),
            value_dword: Int64Builder::new(),
            // Carry the UTC tz so the built array matches the declared field.
            key_last_write: TimestampMicrosecondBuilder::new().with_timezone("UTC"),
            is_deleted: BooleanBuilder::new(),
            hive_type: StringBuilder::new(),
            source: StringBuilder::new(),
            recovery: StringBuilder::new(),
            diagnostics: StringBuilder::new(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push(&mut self, r: &Row) {
        self.key_path.append_value(&r.key_path);
        self.value_name.append_option(r.value_name.as_deref());
        self.value_type.append_option(r.value_type.as_deref());
        self.value_data.append_option(r.value_data.as_deref());
        match &r.value_raw {
            Some(b) => self.value_raw.append_value(b),
            None => self.value_raw.append_null(),
        }
        self.value_dword.append_option(r.value_dword);
        self.key_last_write.append_option(r.key_last_write);
        self.is_deleted.append_value(r.is_deleted);
        self.hive_type.append_value(&r.hive_type);
        self.source.append_value(&r.source);
        self.recovery.append_option(r.recovery.as_deref());
        self.diagnostics.append_option(r.diagnostics.as_deref());
        self.len += 1;
    }

    pub fn finish(mut self) -> Result<RecordBatch> {
        let cols: Vec<ArrayRef> = vec![
            Arc::new(self.key_path.finish()),
            Arc::new(self.value_name.finish()),
            Arc::new(self.value_type.finish()),
            Arc::new(self.value_data.finish()),
            Arc::new(self.value_raw.finish()),
            Arc::new(self.value_dword.finish()),
            Arc::new(self.key_last_write.finish()),
            Arc::new(self.is_deleted.finish()),
            Arc::new(self.hive_type.finish()),
            Arc::new(self.source.finish()),
            Arc::new(self.recovery.finish()),
            Arc::new(self.diagnostics.finish()),
        ];
        RecordBatch::try_new(self.schema.clone(), cols)
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// `STRUCT(value_name, value_type, value_data, value_raw)` — the per-value struct
/// inlined by `hive_key` and returned (minus `value_name`) by `hive_value`.
pub fn value_struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("value_name", DataType::Utf8, true),
        Field::new("value_type", DataType::Utf8, true),
        Field::new("value_data", DataType::Utf8, true),
        Field::new("value_raw", DataType::Binary, true),
    ])
}
