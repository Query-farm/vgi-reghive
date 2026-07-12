//! Shared helpers for the table functions: local-glob expansion, sibling
//! transaction-log discovery, and the shared result-columns documentation.

/// The §5 result-schema, shared by `read_hive` and `hive_subtree`, as the
/// structured `vgi.result_columns_schema` JSON (array of `{name, type,
/// description}`). Column names, types, and ORDER mirror
/// [`crate::arrow_map::row_schema`] exactly so `vgi-lint`'s VGI910 DESCRIBE
/// cross-check matches what the functions actually return. One row per value,
/// plus one key-only row for a key with no values (`mode` controls this);
/// repeated key columns are denormalized onto each value row.
pub const RESULT_COLUMNS_SCHEMA: &str = r#"[
  {"name":"key_path","type":"VARCHAR","description":"Full path from the hive root (backslash-separated; the synthetic root key name is stripped). Deleted orphans use a $Deleted\\… prefix."},
  {"name":"value_name","type":"VARCHAR","description":"Value name; NULL for the key's (Default) value and for key-only rows."},
  {"name":"value_type","type":"VARCHAR","description":"REG_* type name (REG_SZ / REG_DWORD / REG_MULTI_SZ / REG_BINARY / …), or REG_<n> for an unrecognized code. NULL on key-only rows."},
  {"name":"value_data","type":"VARCHAR","description":"Typed/coerced rendering: UTF-16 for strings, ints stringified, MULTI_SZ newline-joined, binary as lowercase hex. Lossy for binary — see value_raw."},
  {"name":"value_raw","type":"BLOB","description":"Exact on-disk value bytes (lossless). The credential-bearing column for SAM/SECURITY hives — never decoded by the worker."},
  {"name":"value_dword","type":"BIGINT","description":"Populated for REG_DWORD / REG_QWORD (NULL otherwise) — saves a cast in the common integer case."},
  {"name":"key_last_write","type":"TIMESTAMP WITH TIME ZONE","description":"Parent key's last-write FILETIME as a UTC timestamp; repeated across that key's value rows. The primary registry-forensics time pivot."},
  {"name":"is_deleted","type":"BOOLEAN","description":"True when the row was reconstructed from unallocated space (deleted-cell recovery)."},
  {"name":"hive_type","type":"VARCHAR","description":"Best-effort logical hive type: SYSTEM / SOFTWARE / NTUSER / SAM / SECURITY / USRCLASS / AMCACHE / UNKNOWN."},
  {"name":"source","type":"VARCHAR","description":"Originating file path (glob member) or '<blob>' for an in-memory hive."},
  {"name":"recovery","type":"VARCHAR","description":"NULL on a clean live cell; else dirty-no-logs, logs-applied, deleted-orphan, deleted-reparented, or modified-prior."},
  {"name":"diagnostics","type":"VARCHAR","description":"NULL on clean decode; else truncated, bad-checksum, bad-utf16, etc."}
]"#;

/// Expand a local path spec to a sorted list of files. A literal path returns
/// itself (if it exists); a glob (`*`, `?`, `[`, `**`) expands via the `glob`
/// crate. Unreadable / non-matching specs yield an empty list (the scan emits no
/// rows rather than erroring — bulk triage tolerates one bad path).
pub fn expand_glob(spec: &str) -> Vec<String> {
    if spec.contains(['*', '?', '[']) {
        match glob::glob(spec) {
            Ok(paths) => {
                let mut out: Vec<String> = paths
                    .flatten()
                    .filter(|p| p.is_file())
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                out.sort();
                out
            }
            Err(_) => Vec::new(),
        }
    } else if std::path::Path::new(spec).is_file() {
        vec![spec.to_string()]
    } else {
        Vec::new()
    }
}

/// Discover sibling `.LOG1` / `.LOG2` transaction logs next to a primary hive
/// file (same basename), returning their bytes in order. Missing logs are simply
/// omitted (the worker parses the primary best-effort).
pub fn sibling_logs(primary: &str) -> Vec<Vec<u8>> {
    let mut logs = Vec::new();
    for ext in [".LOG1", ".LOG2", ".log1", ".log2"] {
        let candidate = format!("{primary}{ext}");
        if let Ok(bytes) = std::fs::read(&candidate) {
            if !bytes.is_empty() {
                logs.push(bytes);
            }
        }
    }
    logs
}
