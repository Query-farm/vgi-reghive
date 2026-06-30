//! `reghive_version()` — return the worker's version string.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

pub struct ReghiveVersion;

impl ScalarFunction for ReghiveVersion {
    fn name(&self) -> &str {
        "reghive_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Returns the reghive worker version string".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT reghive.main.reghive_version();".into(),
                description: "Return the reghive worker version string.".into(),
                expected_output: None,
            }],
            tags: {
                let mut t = crate::meta::object_tags(
                    "Reghive Worker Version",
                    "Return the semantic version string of the running reghive worker binary. \
                     Useful for diagnostics and confirming which build is attached.",
                    "Return the reghive worker version string, e.g. `reghive_version()` -> '0.1.0'.",
                    "version, build version, reghive_version, diagnostics, worker version, semver",
                    "scalar/version.rs",
                );
                // A guaranteed-runnable, self-contained example (VGI509) so agents
                // have a verified example to learn from. Two fully self-contained
                // statements: the version, and a no-file validation probe.
                t.push((
                    "vgi.executable_examples".to_string(),
                    r#"[
  {
    "description": "Return the running worker version.",
    "sql": "SELECT reghive.main.reghive_version() AS version"
  },
  {
    "description": "Validate that a non-hive blob is rejected without crashing.",
    "sql": "SELECT (reghive.main.well_formed('not a hive'::BLOB)).ok AS ok, (reghive.main.well_formed('not a hive'::BLOB)).kind AS kind"
  }
]"#
                    .to_string(),
                ));
                t
            },
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let rows = batch.num_rows();
        let out: ArrayRef = Arc::new(StringArray::from(vec![crate::version(); rows]));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
