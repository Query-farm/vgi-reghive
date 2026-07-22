//! Library surface of the `reghive` VGI worker.
//!
//! Function registration and catalog metadata live here so both entrypoints
//! share them verbatim: `main.rs` (the native binary, stdio/HTTP transport) and
//! the `reghive-wasm` crate (the browser build, which serves the same `Worker`
//! over a SharedArrayBuffer byte channel instead). The `lib` target also exposes
//! the parsing modules so integration tests under `tests/` can exercise them
//! directly, without the Arrow IPC / RPC plumbing.

pub mod arrow_map;
pub mod hive;
pub mod meta;
pub mod sample;
pub mod scalar;
pub mod table;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Worker version string, published as the catalog `implementation_version`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The catalog name DuckDB sees in `ATTACH 'reghive' (TYPE vgi, …)`. Defaults to
/// `reghive`, but honors an explicit override so a test harness can rename it.
/// Also exports the variable so downstream SDK code observes the same default.
pub fn catalog_name() -> String {
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "reghive");
    }
    std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "reghive".to_string())
}

/// Build a fully-registered worker: every scalar and table function plus the
/// catalog metadata. Callers choose the transport — `run()` natively,
/// `serve_reader_writer()` in the browser.
pub fn build_worker() -> Worker {
    let name = catalog_name();
    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.set_catalog(catalog_metadata(&name));
    worker
}

/// Catalog + schema metadata surfaced to DuckDB and the `vgi-lint` linter.
fn catalog_metadata(name: &str) -> CatalogModel {
    // Self-contained schema example queries: the committed synthetic SOFTWARE
    // hive inlined as a BLOB literal (so they bind AND run under
    // `vgi-lint --execute`), plus a browse of the reference view. Each carries a
    // description (VGI515) and projects columns rather than `SELECT *` (VGI514).
    let demo = sample::demo_hive_hex();
    let read_hive_ex = format!(
        "SELECT key_path, value_name, value_data \
         FROM reghive.main.read_hive(unhex('{demo}')::BLOB) \
         WHERE value_name = 'Updater'"
    );
    let hive_info_ex =
        format!("SELECT (reghive.main.hive_info(unhex('{demo}')::BLOB)).is_dirty AS is_dirty");
    let forensic_ex = "SELECT key_path, mitre_technique FROM reghive.main.forensic_keys \
                       WHERE category = 'Persistence' ORDER BY key_path";
    let schema_example_queries = meta::example_queries_json(&[
        (
            "Scan a collected hive and pull the Run-key persistence value it plants.",
            read_hive_ex.as_str(),
        ),
        (
            "Probe a hive's base-block header to decide whether it needs transaction-log recovery.",
            hive_info_ex.as_str(),
        ),
        (
            "Browse the well-known persistence keys to triage first, with their ATT&CK technique.",
            forensic_ex,
        ),
    ]);

    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Parse Windows Registry hive files (regf) into typed key/value rows for DFIR — \
             transaction-log replay and deleted-cell recovery."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "Windows Registry Hive Parsing (regf) for DFIR".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                meta::keywords_json(
                    "registry, regf, windows registry, hive, NTUSER, SOFTWARE, SYSTEM, SAM, \
                     SECURITY, AmCache, UsrClass, DFIR, forensics, incident response, persistence, \
                     run keys, services, deleted recovery, transaction log, LOG1, LOG2, threat hunt",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Parse offline Windows Registry hive files (the regf format used by SYSTEM, \
                 SOFTWARE, NTUSER.DAT, SAM, SECURITY, UsrClass.dat, AmCache.hve) into typed \
                 key/value rows for digital forensics. Read a directory of collected hives with \
                 read_hive(glob) or a single hive `BLOB`; pull a subtree with hive_subtree, a key \
                 with hive_key, or a value with hive_value; probe the header with hive_info / \
                 well_formed; and inspect transaction-log replay with logs_applied. Supports \
                 .LOG1/.LOG2 transaction-log replay of dirty hives and deleted-cell recovery from \
                 unallocated space. Use for fleet-scale registry triage joined to IOC/CVE/YARA \
                 feeds."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# Reghive — Windows Registry Hive Parsing for DFIR in SQL\n\n\
                 **Parse Windows Registry hive files (the on-disk `regf` format) directly in \
                 DuckDB SQL** — `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `SAM`, `SECURITY`, \
                 `UsrClass.dat`, and `AmCache.hve` — into typed key/value rows for digital \
                 forensics and incident response. ATTACH a directory of thousands of collected \
                 hives and run **one query** that joins registry evidence (Run-key persistence, \
                 Services, installed software, AmCache program-execution) to the rest of your \
                 detection surface — IOC feeds, CVE data, YARA, Sigma — with no per-host RegRipper \
                 invocation and no result-wrangling.\n\n\
                 The differentiators over export-only tools are **transaction-log (`.LOG1`/`.LOG2`) \
                 replay** of dirty hives captured mid-write and **deleted-cell recovery** of \
                 keys/values from unallocated space (flagged `is_deleted`), both powered by the \
                 Apache-2.0 [`notatin`](https://github.com/strozfriedberg/notatin) parser. Every \
                 value is surfaced both as a coerced `value_data` string and the lossless \
                 `value_raw` bytes; per-key last-write timestamps are a first-class column.\n\n\
                 **Sensitivity note.** `SAM`/`SECURITY` hives contain password-hash material. This \
                 worker exposes hive structure faithfully (so those bytes appear in `value_raw`) \
                 but **never decodes credentials** — pair it with `vgi-mask`/`vgi-pii` to redact \
                 before results leave the analyst's session.\n\n\
                 **How you work with it.** Point it at a directory glob of collected hives for \
                 bulk triage, or hand it a single in-memory hive to drill into one subtree, key, \
                 or value; header and validity probes tell you up front whether a hive is dirty \
                 and needs transaction-log recovery. The worker opens no socket and makes no \
                 outbound calls — zero egress, safe for air-gapped evidence stores.\n\n\
                 Format references: the [msuhanov regf \
                 specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md) \
                 and Google Project Zero's \"Windows Registry Adventure #5: regf\"."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                meta::agent_test_tasks_json(&[
                    meta::AgentTask {
                        name: "validate_non_hive",
                        prompt: "Is the text 'definitely not a hive' a valid registry hive? \
                                 Return one boolean column named ok.",
                        reference_sql:
                            "SELECT (reghive.main.well_formed('definitely not a hive'::BLOB)).ok \
                             AS ok",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    meta::AgentTask {
                        name: "non_hive_header_is_null",
                        prompt: "For the bytes 'not a registry hive', does the base-block header \
                                 summary come back as NULL (i.e. it is not a parseable hive)? \
                                 Return one boolean column named is_null.",
                        reference_sql:
                            "SELECT reghive.main.hive_info('not a registry hive'::BLOB) IS NULL \
                             AS is_null",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    meta::AgentTask {
                        name: "well_formed_kind_of_non_hive",
                        prompt: "Classify why the bytes 'nope' are not a valid registry hive — \
                                 return the well-formedness kind label in one column named kind.",
                        reference_sql:
                            "SELECT (reghive.main.well_formed('nope'::BLOB)).kind AS kind",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    // Browse the curated reference view.
                    meta::AgentTask {
                        name: "persistence_reference_keys",
                        prompt: "The worker ships a reference list of well-known forensic \
                                 registry keys. How many of them are in the 'Persistence' \
                                 category? Return the count in one column named n.",
                        reference_sql: "SELECT count(*) AS n FROM reghive.main.forensic_keys \
                                        WHERE category = 'Persistence'",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    meta::AgentTask {
                        name: "reference_key_for_run",
                        prompt: "In the worker's reference list of well-known forensic registry \
                                 keys, which MITRE ATT&CK technique is mapped to the classic \
                                 CurrentVersion\\Run autostart key? Return one column named \
                                 mitre_technique.",
                        reference_sql: "SELECT mitre_technique FROM reghive.main.forensic_keys \
                                        WHERE key_path = \
                                        'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    // Exercise the parsers' robustness contract: non-registry input
                    // must yield an empty/NULL result, never an error. Each task
                    // references a distinct object so every function is covered.
                    meta::AgentTask {
                        name: "read_hive_non_hive_empty",
                        prompt: "The bulk hive reader must tolerate non-registry input without \
                                 error. When you read the bytes 'not a hive' as a hive, how many \
                                 rows come back? Return the count in one column named n.",
                        reference_sql: "SELECT count(*) AS n FROM \
                                        reghive.main.read_hive('not a hive'::BLOB)",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    meta::AgentTask {
                        name: "hive_subtree_non_hive_empty",
                        prompt: "Reading the subtree 'Software' out of the non-registry bytes \
                                 'not a hive' must return no rows rather than failing. How many \
                                 rows come back? Return the count in one column named n.",
                        reference_sql: "SELECT count(*) AS n FROM \
                                        reghive.main.hive_subtree('not a hive'::BLOB, 'Software')",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    meta::AgentTask {
                        name: "hive_key_non_hive_null",
                        prompt: "Looking up the key 'Software' in the non-registry bytes 'nope' \
                                 must yield NULL, not an error. Does it come back NULL? Return one \
                                 boolean column named is_null.",
                        reference_sql: "SELECT reghive.main.hive_key('nope'::BLOB, 'Software') \
                                        IS NULL AS is_null",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    meta::AgentTask {
                        name: "hive_value_non_hive_null",
                        prompt: "Reading the value 'Updater' under key 'Run' from the \
                                 non-registry bytes 'nope' must yield NULL, not an error. Does it \
                                 come back NULL? Return one boolean column named is_null.",
                        reference_sql: "SELECT reghive.main.hive_value('nope'::BLOB, 'Run', \
                                        'Updater') IS NULL AS is_null",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    meta::AgentTask {
                        name: "key_info_non_hive_null",
                        prompt: "Asking for the metadata of key 'Software' in the non-registry \
                                 bytes 'nope' must yield NULL, not an error. Does it come back \
                                 NULL? Return one boolean column named is_null.",
                        reference_sql: "SELECT reghive.main.key_info('nope'::BLOB, 'Software') \
                                        IS NULL AS is_null",
                        unordered: true,
                        ignore_column_names: true,
                    },
                    meta::AgentTask {
                        name: "logs_applied_non_hive_null",
                        prompt: "Inspecting a transaction-log replay for the non-registry bytes \
                                 'nope' (with no logs supplied) must yield NULL, not an error. \
                                 Does it come back NULL? Return one boolean column named is_null.",
                        reference_sql: "SELECT reghive.main.logs_applied('nope'::BLOB, NULL, \
                                        NULL) IS NULL AS is_null",
                        unordered: true,
                        ignore_column_names: true,
                    },
                ]),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-reghive/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-reghive/blob/main/README.md".to_string(),
            ),
        ],
        // VGI139: the catalog-level source_url points at the authoritative regf
        // format specification (the worker's provenance), per the build spec.
        source_url: Some(
            "https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md"
                .to_string(),
        ),
        // VGI328: the worker build version is published as catalog metadata
        // (surfaced via `duckdb_databases()` / `catalog_catalogs`) rather than as
        // a parameterless `reghive_version()` scalar spending a slot in the
        // function surface.
        implementation_version: Some(version().to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "Registry-hive parsing functions for DFIR triage: bulk directory scans, scoped \
                 subtree and single key/value lookups, header and validity probes, and \
                 transaction-log replay reporting."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "Reghive — main".to_string()),
                // VGI413: ordered category registry. Each function declares a
                // `vgi.category` (via meta::object_tags) naming one of these.
                (
                    "vgi.categories".to_string(),
                    r#"[{"name":"Bulk parsing","description":"Scan whole hives — a directory glob or a single blob — into typed key/value rows for triage."},{"name":"Targeted lookup","description":"Pull one key or value (or a key's metadata) from a hive without scanning the whole tree."},{"name":"Header & validation","description":"Read a hive's base-block header and confirm the bytes are a well-formed regf hive."},{"name":"Transaction logs","description":"Report on .LOG1/.LOG2 transaction-log replay of a dirty hive."},{"name":"Reference","description":"Curated browsable reference data, such as the well-known forensic registry keys to triage."}]"#
                        .to_string(),
                ),
                (
                    "vgi.keywords".to_string(),
                    meta::keywords_json(
                        "registry, regf, hive, read_hive, hive_subtree, hive_key, hive_value, \
                         key_info, hive_info, well_formed, logs_applied, DFIR, forensics",
                    ),
                ),
                ("domain".to_string(), "security-and-forensics".to_string()),
                ("category".to_string(), "windows-registry".to_string()),
                ("topic".to_string(), "dfir-triage".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "Registry-hive parsing functions for DFIR: scan hives into key/value rows \
                     (read_hive / hive_subtree), pull a single key/value (hive_key / hive_value), \
                     probe metadata and validity (key_info / hive_info / well_formed), and inspect \
                     transaction-log replay (logs_applied)."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "## Registry-hive parsing for DFIR\n\n\
                     The single schema of the `reghive` worker. It turns offline Windows \
                     Registry hive files (`NTUSER.DAT`, `SYSTEM`, `SOFTWARE`, `SAM`, …) into \
                     typed key/value rows so a hive on disk can be queried as SQL.\n\n\
                     Every read is offline and best-effort: dirty hives still parse, deleted \
                     cells can be recovered and labelled, and sensitive bytes are preserved raw \
                     and never decoded. The functions group into a few kinds of work:\n\n\
                     - **Bulk parsing** — scan a whole hive (a directory glob, or a single \
                     blob) into rows for triage.\n\
                     - **Targeted lookup** — pull one key or value, or a key's metadata, \
                     without walking the whole tree.\n\
                     - **Header & validation** — read the base-block header and confirm the \
                     bytes are a well-formed regf hive.\n\
                     - **Transaction logs** — report on `.LOG1`/`.LOG2` replay of a dirty hive.\n\n\
                     Use it whenever you have a registry hive on disk and need its contents as \
                     rows, from fleet-wide triage down to a single key or value."
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    schema_example_queries,
                ),
            ],
            // A browsable, VALUES-backed reference view: something an agent can
            // scan (no file, no credential) to learn which key paths to triage
            // before it has a hive in hand.
            views: vec![sample::forensic_keys_view()],
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}
