//! Native `reghive` VGI worker binary.
//!
//! A standalone executable DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'reghive' (TYPE vgi, LOCATION '…')`). It parses Windows Registry hive
//! files (the on-disk `regf` format) into typed key/value rows for DFIR under the
//! catalog `reghive`, schema `main`:
//!
//! ```sql
//! ATTACH 'reghive' (TYPE vgi, LOCATION './target/release/reghive-worker');
//! SET search_path = 'reghive.main';
//!
//! SELECT * FROM read_hive('/cases/*/NTUSER.DAT');           -- bulk key/value rows
//! SELECT * FROM hive_subtree(content, 'ControlSet001\Services') FROM read_blob('SYSTEM');
//! SELECT hive_key(content, 'ControlSet001\Services\Schedule') FROM read_blob('SYSTEM');
//! SELECT hive_info(content) FROM read_blob('NTUSER.DAT');    -- is it dirty?
//! ```
//!
//! All function registration and catalog metadata live in the library crate
//! (`build_worker`) so the wasm build serves an identical worker.

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    reghive_worker::build_worker().run();
}
