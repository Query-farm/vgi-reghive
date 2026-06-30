//! Shared helpers for the table functions: local-glob expansion, sibling
//! transaction-log discovery, and the shared result-columns documentation.

/// The §5 result-columns table, shared by `read_hive` and `hive_subtree`.
pub const RESULT_COLUMNS_MD: &str = "One row per **value**, plus one key-only row for a key with no \
values (`mode` controls this). Repeated key columns are denormalized onto each value row.\n\n\
| column | type | description |\n\
|---|---|---|\n\
| `key_path` | VARCHAR | Path from the hive root (root name stripped; `$Deleted\\…` for orphans). |\n\
| `value_name` | VARCHAR | Value name; NULL for (Default) and key-only rows. |\n\
| `value_type` | VARCHAR | REG_SZ / REG_DWORD / REG_MULTI_SZ / REG_BINARY / … / REG_<n>. |\n\
| `value_data` | VARCHAR | Coerced rendering (UTF-16 / int / hex). Lossy for binary. |\n\
| `value_raw` | BLOB | Exact on-disk bytes (lossless; credential-bearing for SAM/SECURITY). |\n\
| `value_dword` | BIGINT | Populated for REG_DWORD/REG_QWORD. |\n\
| `key_last_write` | TIMESTAMPTZ | Parent key's last-write FILETIME as UTC. |\n\
| `is_deleted` | BOOLEAN | Row reconstructed from unallocated space. |\n\
| `hive_type` | VARCHAR | SYSTEM/SOFTWARE/NTUSER/SAM/SECURITY/USRCLASS/AMCACHE/UNKNOWN. |\n\
| `source` | VARCHAR | Originating file path or '<blob>'. |\n\
| `recovery` | VARCHAR | NULL on clean; dirty-no-logs / logs-applied / deleted-orphan / … |\n\
| `diagnostics` | VARCHAR | NULL on clean decode; truncated / bad-checksum / bad-utf16 / … |";

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
