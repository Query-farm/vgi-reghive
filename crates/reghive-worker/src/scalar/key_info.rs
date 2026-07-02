//! `key_info(blob, key_path) -> STRUCT(last_write, subkey_count, value_count,
//! class_name, is_deleted)` — key metadata only, no value materialization (cheap
//! timeline pivots over many keys).

use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, StringBuilder, TimestampMicrosecondBuilder, UInt32Builder,
};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_map::timestamptz;
use crate::scalar::io::{blob_val, text_val};

pub struct KeyInfo;

fn fields() -> Fields {
    Fields::from(vec![
        Field::new("last_write", timestamptz(), true),
        Field::new("subkey_count", DataType::UInt32, true),
        Field::new("value_count", DataType::UInt32, true),
        Field::new("class_name", DataType::Utf8, true),
        Field::new("is_deleted", DataType::Boolean, true),
    ])
}

impl ScalarFunction for KeyInfo {
    fn name(&self) -> &str {
        "key_info"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return a key's metadata (last_write, subkey_count, value_count, \
                          class_name, is_deleted) without materializing its values"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT reghive.main.key_info('regf'::BLOB, 'Software\\Microsoft');"
                    .into(),
                description: "Cheap key-metadata pivot (NULL struct for a non-hive blob).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Key Metadata",
                "Return just a key's metadata for a given key_path in a hive BLOB: the last-write \
                 UTC timestamp, the subkey and value counts, the class name (usually NULL), and \
                 whether the key is a recovered deleted cell. Materializes no value data, so it is \
                 cheap to call across many keys for timeline pivots. Returns a NULL struct when the \
                 key is not found.",
                "Return a key's metadata (last_write, subkey_count, value_count, class_name, \
                 is_deleted) without reading its values. NULL struct if the key is absent.",
                "key info, key metadata, last write, subkey count, value count, timeline, pivot, \
                 last modified",
                "Targeted lookup",
            ),
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
                "The key path from the hive root (backslash-separated, root name omitted), e.g. \
                 'Software\\Microsoft\\Windows'.",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let blob = batch.column(0);
        let path = batch.column(1);
        let rows = batch.num_rows();

        let mut last_write = TimestampMicrosecondBuilder::new().with_timezone("UTC");
        let mut subkey_count = UInt32Builder::new();
        let mut value_count = UInt32Builder::new();
        let mut class_name = StringBuilder::new();
        let mut is_deleted = BooleanBuilder::new();
        let mut valid: Vec<bool> = Vec::with_capacity(rows);

        for i in 0..rows {
            let found = match (blob_val(blob, i)?, text_val(path, i)?) {
                (Some(bytes), Some(kp)) => lookup(&bytes, &kp),
                _ => None,
            };
            match found {
                Some(info) => {
                    last_write.append_value(info.last_write);
                    subkey_count.append_value(info.subkeys);
                    value_count.append_value(info.values);
                    class_name.append_null();
                    is_deleted.append_value(info.is_deleted);
                    valid.push(true);
                }
                None => {
                    last_write.append_null();
                    subkey_count.append_null();
                    value_count.append_null();
                    class_name.append_null();
                    is_deleted.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(last_write.finish()),
            Arc::new(subkey_count.finish()),
            Arc::new(value_count.finish()),
            Arc::new(class_name.finish()),
            Arc::new(is_deleted.finish()),
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

struct KeyMeta {
    last_write: i64,
    subkeys: u32,
    values: u32,
    is_deleted: bool,
}

fn lookup(bytes: &[u8], key_path: &str) -> Option<KeyMeta> {
    let mut opened = crate::hive::open::open_blob(bytes, true, true, &[]).ok()?;
    let key = opened.parser.get_key(key_path, false).ok().flatten()?;
    Some(KeyMeta {
        last_write: key.last_key_written_date_and_time().timestamp_micros(),
        subkeys: key.detail.number_of_sub_keys(),
        values: key.detail.number_of_key_values(),
        is_deleted: key.cell_state.is_deleted(),
    })
}
