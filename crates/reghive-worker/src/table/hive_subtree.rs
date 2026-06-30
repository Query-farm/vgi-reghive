//! `hive_subtree(blob, key_path [, apply_logs, recover_deleted]) -> TABLE` — the
//! §5 schema scoped to the subtree rooted at `key_path` (recursive). The
//! targeted-triage surface (Run-keys, a Services branch, an AmCache subtree) that
//! avoids materializing a whole large hive when you know where you're looking.

use arrow_array::RecordBatch;
use vgi::arguments::Arguments;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_map::{row_schema, RowBatchBuilder};
use crate::hive::{self, walk::Mode};
use crate::table::common;

pub struct HiveSubtree;

fn opts(args: &Arguments) -> (bool, bool) {
    let apply_logs = args.named_bool("apply_logs").unwrap_or(true);
    let recover = args.named_bool("recover_deleted").unwrap_or(true);
    (apply_logs, recover)
}

impl TableFunction for HiveSubtree {
    fn name(&self) -> &str {
        "hive_subtree"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Read Hive Subtree",
            "Scan only the subtree of a hive BLOB rooted at a given key_path (recursive) into the \
             same typed key/value rows as read_hive. The targeted-triage surface for when you know \
             where you're looking — a Run-key branch, a Services subtree, or an AmCache \
             InventoryApplicationFile node — without materializing a whole large hive. By default \
             replays transaction logs (apply_logs) and recovers deleted cells (recover_deleted).",
            "Scan one subtree of a hive BLOB (rooted at key_path, recursive) into the §5 key/value \
             rows. Args: blob, key_path, apply_logs (default true), recover_deleted (default true).",
            "hive subtree, subtree, branch, scoped, run keys, services, amcache, registry, regf, \
             targeted, triage",
            "table/hive_subtree.rs",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            common::RESULT_COLUMNS_MD.into(),
        ));
        FunctionMetadata {
            description: "Read one subtree of a hive BLOB (rooted at key_path) into typed rows"
                .into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::const_arg("blob", 0, "blob", "The hive bytes (a BLOB)."),
            ArgSpec::const_arg(
                "key_path",
                1,
                "varchar",
                "The subtree root path from the hive root (root name omitted), e.g. \
                 'Root\\InventoryApplicationFile' or 'ControlSet001\\Services'.",
            ),
            ArgSpec::const_arg(
                "apply_logs",
                -1,
                "boolean",
                "Replay sibling transaction logs before emitting rows (default true).",
            ),
            ArgSpec::const_arg(
                "recover_deleted",
                -1,
                "boolean",
                "Reconstruct keys/values from unallocated cells; recovered rows are flagged \
                 is_deleted (default true).",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: row_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let (apply_logs, recover) = opts(&params.arguments);
        let bytes = params
            .arguments
            .const_bytes(0)
            .ok_or_else(|| RpcError::value_error("hive_subtree: missing BLOB argument"))?;
        let key_path = params
            .arguments
            .const_str(1)
            .ok_or_else(|| RpcError::value_error("hive_subtree: missing key_path argument"))?;
        Ok(Box::new(SubtreeProducer {
            schema: params.output_schema.clone(),
            bytes,
            key_path,
            apply_logs,
            recover,
            done: false,
        }))
    }
}

struct SubtreeProducer {
    schema: arrow_schema::SchemaRef,
    bytes: Vec<u8>,
    key_path: String,
    apply_logs: bool,
    recover: bool,
    done: bool,
}

impl TableProducer for SubtreeProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;

        let mut b = RowBatchBuilder::new(self.schema.clone());
        if let Ok(opened) = hive::open::open_blob(&self.bytes, self.apply_logs, self.recover, &[]) {
            let base_recovery = hive::base_recovery_label(opened.was_dirty, false, self.apply_logs);
            let diag = match opened.kind {
                reghive_core::baseblock::WellFormedKind::BadChecksum => Some("bad-checksum"),
                _ => None,
            };
            let rows = hive::walk::walk(
                &opened,
                "<blob>",
                Mode::Values,
                base_recovery.as_deref(),
                diag,
                Some(&self.key_path),
            );
            for r in &rows {
                b.push(r);
            }
        }
        Ok(Some(b.finish()?))
    }
}
