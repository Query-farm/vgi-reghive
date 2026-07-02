//! `hive_key(blob, key_path) -> STRUCT(key_path, last_write, class_name,
//! subkey_count, value_count, is_deleted, values LIST<STRUCT(...)>)` — one key as
//! a struct with its values inlined; the "give me exactly this key" scalar.

use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, ListBuilder, StringBuilder, StructBuilder,
    TimestampMicrosecondBuilder, UInt32Builder,
};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Fields};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_map::{timestamptz, value_struct_fields};
use crate::hive::value;
use crate::scalar::io::{blob_val, text_val};

pub struct HiveKey;

fn values_list_field() -> Arc<Field> {
    Arc::new(Field::new(
        "values",
        DataType::List(Arc::new(Field::new(
            "item",
            DataType::Struct(value_struct_fields()),
            true,
        ))),
        true,
    ))
}

fn fields() -> Fields {
    Fields::from(vec![
        Field::new("key_path", DataType::Utf8, true),
        Field::new("last_write", timestamptz(), true),
        Field::new("class_name", DataType::Utf8, true),
        Field::new("subkey_count", DataType::UInt32, true),
        Field::new("value_count", DataType::UInt32, true),
        Field::new("is_deleted", DataType::Boolean, true),
        values_list_field().as_ref().clone(),
    ])
}

/// The `StructBuilder` field list for the inner value structs.
fn value_struct_builder() -> StructBuilder {
    StructBuilder::new(
        value_struct_fields(),
        vec![
            Box::new(StringBuilder::new()),
            Box::new(StringBuilder::new()),
            Box::new(StringBuilder::new()),
            Box::new(BinaryBuilder::new()),
        ],
    )
}

impl ScalarFunction for HiveKey {
    fn name(&self) -> &str {
        "hive_key"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return one registry key as a struct with its values inlined".into(),
            examples: vec![FunctionExample {
                sql: "SELECT reghive.main.hive_key('regf'::BLOB, 'ControlSet001\\Services');"
                    .into(),
                description: "Look up a key as a struct (NULL struct for a non-hive blob).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Single Key as Struct",
                "Return exactly one registry key from a hive BLOB as a struct: its key_path, \
                 last-write UTC timestamp, class name, subkey/value counts, deleted flag, and a \
                 LIST of its values (each a struct of value_name, value_type, value_data, and the \
                 lossless value_raw bytes). Use it to pull a single service, Run key, or settings \
                 node without scanning the whole hive. Returns a NULL struct if the key is absent.",
                "Return one key as a struct with its values inlined (value_name, value_type, \
                 value_data, value_raw). NULL struct if the key is absent.",
                "hive key, single key, get key, service, run key, struct, values, lookup",
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
                "The key path from the hive root (root name omitted), e.g. \
                 'ControlSet001\\Services\\Schedule'.",
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

        let mut key_path_b = StringBuilder::new();
        let mut last_write = TimestampMicrosecondBuilder::new().with_timezone("UTC");
        let mut class_name = StringBuilder::new();
        let mut subkey_count = UInt32Builder::new();
        let mut value_count = UInt32Builder::new();
        let mut is_deleted = BooleanBuilder::new();
        let mut values = ListBuilder::new(value_struct_builder());
        let mut valid: Vec<bool> = Vec::with_capacity(rows);

        for i in 0..rows {
            let found = match (blob_val(blob, i)?, text_val(path, i)?) {
                (Some(bytes), Some(kp)) => lookup(&bytes, &kp),
                _ => None,
            };
            match found {
                Some(k) => {
                    key_path_b.append_value(&k.key_path);
                    last_write.append_value(k.last_write);
                    class_name.append_null();
                    subkey_count.append_value(k.subkeys);
                    value_count.append_value(k.values);
                    is_deleted.append_value(k.is_deleted);
                    let vb = values.values();
                    for dv in &k.decoded {
                        vb.field_builder::<StringBuilder>(0)
                            .unwrap()
                            .append_option(dv.name.as_deref());
                        vb.field_builder::<StringBuilder>(1)
                            .unwrap()
                            .append_value(&dv.value_type);
                        vb.field_builder::<StringBuilder>(2)
                            .unwrap()
                            .append_value(&dv.value_data);
                        vb.field_builder::<BinaryBuilder>(3)
                            .unwrap()
                            .append_value(&dv.value_raw);
                        vb.append(true);
                    }
                    values.append(true);
                    valid.push(true);
                }
                None => {
                    key_path_b.append_null();
                    last_write.append_null();
                    class_name.append_null();
                    subkey_count.append_null();
                    value_count.append_null();
                    is_deleted.append_null();
                    values.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(key_path_b.finish()),
            Arc::new(last_write.finish()),
            Arc::new(class_name.finish()),
            Arc::new(subkey_count.finish()),
            Arc::new(value_count.finish()),
            Arc::new(is_deleted.finish()),
            Arc::new(values.finish()),
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

struct FoundKey {
    key_path: String,
    last_write: i64,
    subkeys: u32,
    values: u32,
    is_deleted: bool,
    decoded: Vec<value::DecodedValue>,
}

fn lookup(bytes: &[u8], key_path: &str) -> Option<FoundKey> {
    let mut opened = crate::hive::open::open_blob(bytes, true, true, &[]).ok()?;
    let key = opened.parser.get_key(key_path, false).ok().flatten()?;
    let decoded = key.value_iter().map(|v| value::decode(&v)).collect();
    Some(FoundKey {
        key_path: key_path.trim_start_matches('\\').to_string(),
        last_write: key.last_key_written_date_and_time().timestamp_micros(),
        subkeys: key.detail.number_of_sub_keys(),
        values: key.detail.number_of_key_values(),
        is_deleted: key.cell_state.is_deleted(),
        decoded,
    })
}
