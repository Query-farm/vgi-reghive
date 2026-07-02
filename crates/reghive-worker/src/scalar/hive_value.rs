//! `hive_value(blob, key_path, value_name) -> STRUCT(value_type, value_data,
//! value_raw)` — a single named value (`value_name := ''` or `NULL` -> the key's
//! (Default) value).

use std::sync::Arc;

use arrow_array::builder::{BinaryBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::hive::value;
use crate::scalar::io::{blob_val, text_val};

pub struct HiveValue;

fn fields() -> Fields {
    Fields::from(vec![
        Field::new("value_type", DataType::Utf8, true),
        Field::new("value_data", DataType::Utf8, true),
        Field::new("value_raw", DataType::Binary, true),
    ])
}

impl ScalarFunction for HiveValue {
    fn name(&self) -> &str {
        "hive_value"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return a single named registry value as a struct (value_type, \
                          value_data, value_raw)"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT reghive.main.hive_value('regf'::BLOB, 'Software', 'Run');"
                    .into(),
                description: "Read one named value (NULL struct for a non-hive blob).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Single Value as Struct",
                "Return one named value from a key in a hive BLOB as a struct: the REG_* \
                 value_type, the coerced value_data rendering, and the lossless value_raw bytes. \
                 Pass an empty string or NULL value_name for the key's (Default) value. Returns a \
                 NULL struct when the key or value is absent.",
                "Return one named value as a struct (value_type, value_data, value_raw). Empty/NULL \
                 name selects the (Default) value; NULL struct if absent.",
                "hive value, single value, get value, default value, value_data, value_raw, lookup",
                "Targeted lookup",
            ),
            // A NULL value_name selects the (Default) value — receive it rather
            // than null-propagating.
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
                "The raw contents of a registry hive file, e.g. from read_blob('NTUSER.DAT').",
            ),
            ArgSpec::column_typed(
                "key_path",
                1,
                DataType::Utf8,
                "The key path from the hive root (root name omitted).",
            ),
            ArgSpec::column_typed(
                "value_name",
                2,
                DataType::Utf8,
                "The value name to read; an empty string or NULL selects the key's (Default) value.",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let blob = batch.column(0);
        let path = batch.column(1);
        let vname = batch.column(2);
        let rows = batch.num_rows();

        let mut value_type = StringBuilder::new();
        let mut value_data = StringBuilder::new();
        let mut value_raw = BinaryBuilder::new();
        let mut valid: Vec<bool> = Vec::with_capacity(rows);

        for i in 0..rows {
            // value_name is optional: NULL means the (Default) value.
            let name = text_val(vname, i)?.unwrap_or_default();
            let found = match (blob_val(blob, i)?, text_val(path, i)?) {
                (Some(bytes), Some(kp)) => lookup(&bytes, &kp, &name),
                _ => None,
            };
            match found {
                Some(dv) => {
                    value_type.append_value(&dv.value_type);
                    value_data.append_value(&dv.value_data);
                    value_raw.append_value(&dv.value_raw);
                    valid.push(true);
                }
                None => {
                    value_type.append_null();
                    value_data.append_null();
                    value_raw.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(value_type.finish()),
            Arc::new(value_data.finish()),
            Arc::new(value_raw.finish()),
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

fn lookup(bytes: &[u8], key_path: &str, value_name: &str) -> Option<value::DecodedValue> {
    let mut opened = crate::hive::open::open_blob(bytes, true, true, &[]).ok()?;
    let key = opened.parser.get_key(key_path, false).ok().flatten()?;
    // notatin's get_value is case-insensitive and matches "" for the default.
    let v = key.get_value(value_name)?;
    Some(value::decode(&v))
}
