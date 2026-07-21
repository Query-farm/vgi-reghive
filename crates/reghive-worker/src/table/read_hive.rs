//! `read_hive(glob_or_blob [, apply_logs, recover_deleted, mode]) -> TABLE` — the
//! bulk entry point. A VARCHAR arg is a **local file glob**; a BLOB is a single
//! in-memory hive. Walks the key tree from the root and emits the §5 schema.
//!
//! The only externalized scan state is the file-glob playlist cursor (§4): when a
//! glob spans many hives across HTTP-transport batch boundaries, the producer
//! carries `HiveGlobCursor` so a fan-out resumes at the right file rather than
//! restarting. A single-blob call carries no cursor. (Cloud globs — `s3://` etc.
//! — are read upstream via DuckDB `read_blob(...)` and passed in as a BLOB.)

use arrow_array::RecordBatch;
use arrow_schema::DataType;
use reghive_core::cursor::HiveGlobCursor;
use vgi::arguments::Arguments;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_map::{row_schema, RowBatchBuilder};
use crate::hive::{self, walk::Mode};
use crate::table::common;

pub struct ReadHive;

/// Read `apply_logs` / `recover_deleted` / `mode` from the arguments.
pub fn read_opts(args: &Arguments) -> (bool, bool, Mode) {
    let apply_logs = args.named_bool("apply_logs").unwrap_or(true);
    let recover = args.named_bool("recover_deleted").unwrap_or(true);
    let mode = args
        .named_str("mode")
        .map(|s| Mode::parse(&s))
        .unwrap_or(Mode::Values);
    (apply_logs, recover, mode)
}

impl TableFunction for ReadHive {
    fn name(&self) -> &str {
        "read_hive"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Read Registry Hives",
            "Scan Windows Registry hive files (regf: SYSTEM, SOFTWARE, NTUSER.DAT, SAM, SECURITY, \
             UsrClass.dat, AmCache.hve) into typed key/value rows for DFIR. The first argument is \
             either a local file glob (`VARCHAR`, e.g. '/cases/*/NTUSER.DAT') or a single \
             in-memory hive (`BLOB`, e.g. from read_blob('s3://...')). By default it replays \
             sibling .LOG1/.LOG2 transaction logs to recover a dirty hive (apply_logs) and \
             reconstructs keys/values from unallocated cells (recover_deleted, flagged \
             is_deleted). The named `mode` argument is 'values' (one row per value, default), \
             'keys' (one row per key), or 'all' (both). Emits full key paths, value \
             name/type/data, the lossless value_raw bytes, per-key last-write timestamps, and \
             recovery/diagnostics tags. Join it to IOC, CVE, YARA, and Sigma workers for \
             fleet-scale registry triage.",
            "Scan regf registry hives into typed key/value rows. Arg 1 is a local glob \
             (`VARCHAR`) or a hive `BLOB`. Named args: apply_logs (replay .LOG1/.LOG2, default \
             true), recover_deleted (default true), mode ('values'/'keys'/'all'). Pass a `BLOB` \
             from read_blob() for cloud/s3 hives.",
            "read hive, registry, regf, NTUSER, SOFTWARE, SYSTEM, SAM, AmCache, DFIR, forensics, \
             persistence, run key, deleted, transaction log, recovery",
            "Bulk parsing",
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            common::RESULT_COLUMNS_SCHEMA.into(),
        ));
        // A fully self-contained example: the committed synthetic SOFTWARE hive
        // (with a classic Run-key persistence value) inlined as a BLOB literal, so
        // it binds AND returns rows under `vgi-lint --execute`. Table functions
        // bind literal args only, hence `unhex(...)` rather than a column.
        let demo = crate::sample::demo_hive_hex();
        let example_sql = format!(
            "SELECT key_path, value_name, value_type, value_data \
             FROM reghive.main.read_hive(unhex('{demo}')::BLOB) \
             WHERE value_name = 'Updater'"
        );
        let example_desc = "Scan a whole hive and pull the Run-key persistence value (Updater) it \
                            plants — the bread-and-butter triage query.";
        // VGI515: described-example carrier for the native example below.
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&[(example_desc, example_sql.as_str())]),
        ));
        FunctionMetadata {
            description: "Read regf registry hives (glob or BLOB) into typed key/value rows".into(),
            examples: vec![FunctionExample {
                sql: example_sql.clone(),
                description: example_desc.into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::const_arg(
                "glob_or_blob",
                0,
                "any",
                "Either a local file glob (e.g. '/cases/*/NTUSER.DAT' — matching files are read \
                 in sorted order) or a single in-memory hive read with read_blob. For cloud hives \
                 (s3://, https://) fetch the bytes with read_blob(...) and pass those.",
            ),
            ArgSpec::const_arg(
                "apply_logs",
                -1,
                "boolean",
                "Replay sibling .LOG1/.LOG2 transaction logs to recover a dirty hive before \
                 emitting rows (default true). Set false to parse the primary file as-is.",
            ),
            ArgSpec::const_arg(
                "recover_deleted",
                -1,
                "boolean",
                "Reconstruct keys/values from unallocated cells; recovered rows are flagged \
                 is_deleted (default true).",
            ),
            ArgSpec::const_arg(
                "mode",
                -1,
                "varchar",
                "Which rows to emit: 'values' (one row per value, default), 'keys' (one row per \
                 key), or 'all' (both).",
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
        let (apply_logs, recover, mode) = read_opts(&params.arguments);

        // Detect BLOB vs VARCHAR for arg 0.
        let blob = params
            .arguments
            .arg_field(0)
            .map(|f| {
                matches!(
                    f.data_type(),
                    DataType::Binary | DataType::LargeBinary | DataType::BinaryView
                )
            })
            .unwrap_or(false);

        let plan = if blob {
            let bytes = params
                .arguments
                .const_bytes(0)
                .ok_or_else(|| RpcError::value_error("read_hive: missing BLOB argument"))?;
            Plan::Blob { bytes, done: false }
        } else {
            let pat = params
                .arguments
                .const_str(0)
                .ok_or_else(|| RpcError::value_error("read_hive: missing path argument"))?;
            let files = common::expand_glob(&pat);
            Plan::Glob {
                cursor: HiveGlobCursor::new(files),
            }
        };

        Ok(Box::new(ReadHiveProducer {
            schema: params.output_schema.clone(),
            apply_logs,
            recover,
            mode,
            plan,
        }))
    }
}

enum Plan {
    Blob { bytes: Vec<u8>, done: bool },
    Glob { cursor: HiveGlobCursor },
}

struct ReadHiveProducer {
    schema: arrow_schema::SchemaRef,
    apply_logs: bool,
    recover: bool,
    mode: Mode,
    plan: Plan,
}

/// Build the rows for one source (blob or one glob file). A free function so it
/// does not borrow the producer while the glob cursor is mutably borrowed.
fn build_rows(
    apply_logs: bool,
    recover: bool,
    mode: Mode,
    bytes: &[u8],
    source: &str,
    logs: &[Vec<u8>],
) -> Vec<crate::arrow_map::Row> {
    match hive::open::open_blob(bytes, apply_logs, recover, logs) {
        Ok(opened) => {
            let base_recovery =
                hive::base_recovery_label(opened.was_dirty, !logs.is_empty(), apply_logs);
            let diag = match opened.kind {
                reghive_core::baseblock::WellFormedKind::BadChecksum => Some("bad-checksum"),
                _ => None,
            };
            crate::hive::walk::walk(&opened, source, mode, base_recovery.as_deref(), diag, None)
        }
        // A malformed hive yields no rows (the scan continues); the well_formed()
        // scalar is the per-file validation surface.
        Err(_) => Vec::new(),
    }
}

impl TableProducer for ReadHiveProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        match &mut self.plan {
            Plan::Blob { bytes, done } => {
                if *done {
                    return Ok(None);
                }
                *done = true;
                let bytes = std::mem::take(bytes);
                let rows = build_rows(
                    self.apply_logs,
                    self.recover,
                    self.mode,
                    &bytes,
                    "<blob>",
                    &[],
                );
                let mut b = RowBatchBuilder::new(self.schema.clone());
                for r in &rows {
                    b.push(r);
                }
                Ok(Some(b.finish()?))
            }
            Plan::Glob { cursor } => {
                // One file per batch (a hive is bounded, parsed whole in memory).
                loop {
                    let file = match cursor.current_file.clone() {
                        Some(f) => f,
                        None => return Ok(None),
                    };
                    let bytes = std::fs::read(&file).ok();
                    let logs = common::sibling_logs(&file);
                    let mut b = RowBatchBuilder::new(self.schema.clone());
                    if let Some(bytes) = bytes {
                        let rows = build_rows(
                            self.apply_logs,
                            self.recover,
                            self.mode,
                            &bytes,
                            &file,
                            &logs,
                        );
                        for r in &rows {
                            b.push(r);
                        }
                    }
                    cursor.advance_file();
                    if b.is_empty() {
                        // Skip empty/unreadable files without emitting a 0-row batch.
                        if cursor.is_exhausted() {
                            return Ok(None);
                        }
                        continue;
                    }
                    return Ok(Some(b.finish()?));
                }
            }
        }
    }

    fn resume_supported(&self) -> bool {
        matches!(self.plan, Plan::Glob { .. })
    }

    fn encode_resume(&self) -> Vec<u8> {
        match &self.plan {
            Plan::Glob { cursor } => cursor.to_bytes(),
            Plan::Blob { .. } => Vec::new(),
        }
    }

    fn restore_resume(&mut self, bytes: &[u8]) {
        if let Plan::Glob { cursor } = &mut self.plan {
            *cursor = HiveGlobCursor::from_bytes(bytes);
        }
    }
}
