//! Walk an opened hive's key tree into normalized §5 rows.
//!
//! Path normalization emits the canonical path from the hive root (the synthetic
//! root key name stripped), and tags recovered-from-unallocated cells with
//! `is_deleted` + a `recovery` label. Deleted orphans recovered with no surviving
//! ancestry get a `$Deleted\…` prefix (§3).

use notatin::parser::{Parser, ParserIterator};

use crate::arrow_map::Row;
use crate::hive::open::Opened;
use crate::hive::value;

/// Which rows to emit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// One row per value, plus one key-only row for a key with no values.
    Values,
    /// One key-only row per key (no value rows).
    Keys,
    /// Both: a key-only row per key and a row per value.
    All,
}

impl Mode {
    /// Parse the `mode` argument; unknown values fall back to `values`.
    pub fn parse(s: &str) -> Mode {
        match s.to_ascii_lowercase().as_str() {
            "keys" => Mode::Keys,
            "all" => Mode::All,
            _ => Mode::Values,
        }
    }
}

/// Normalize a notatin full path (`\RootName\a\b`) to the canonical hive-root
/// path (`a\b`). Returns `(path, is_orphan)`; an orphan is a recovered cell whose
/// path does not descend from the live root (gets a `$Deleted\…` prefix).
fn normalize(path: &str, root_name: &str) -> (String, bool) {
    let p = path.strip_prefix('\\').unwrap_or(path);
    if !root_name.is_empty() {
        if p == root_name {
            return (String::new(), false);
        }
        let prefix = format!("{root_name}\\");
        if let Some(rest) = p.strip_prefix(&prefix) {
            return (rest.to_string(), false);
        }
    } else if p.is_empty() {
        return (String::new(), false);
    }
    (format!("$Deleted\\{p}"), true)
}

/// The recovery label for a deleted row given its (already normalized) path.
fn deleted_label(is_orphan: bool) -> &'static str {
    if is_orphan {
        "deleted-orphan"
    } else {
        "deleted-reparented"
    }
}

/// Walk the whole hive into rows. `base_recovery` is the per-hive recovery state
/// for live cells (`logs-applied` / `dirty-no-logs` / `None`); `hive_diag` is a
/// per-hive diagnostic (e.g. `bad-checksum`). `key_filter` optionally restricts
/// to a subtree path prefix (canonical, root-stripped) for `hive_subtree`.
pub fn walk(
    opened: &Opened,
    source: &str,
    mode: Mode,
    base_recovery: Option<&str>,
    hive_diag: Option<&str>,
    key_filter: Option<&str>,
) -> Vec<Row> {
    let parser: &Parser = &opened.parser;
    let root_name = opened.root_name.as_str();
    let hive_type = opened.hive_type.as_str();

    let filter_norm = key_filter.map(normalize_filter);

    let mut rows = Vec::new();
    for key in ParserIterator::new(parser).get_modified_items(true).iter() {
        let (key_path, is_orphan) = normalize(&key.path, root_name);

        if let Some(ref f) = filter_norm {
            if !subtree_match(&key_path, f) {
                continue;
            }
        }

        let key_deleted = key.cell_state.is_deleted();
        let last_write = Some(key.last_key_written_date_and_time().timestamp_micros());

        let key_recovery = if key_deleted {
            Some(deleted_label(is_orphan).to_string())
        } else {
            base_recovery.map(|s| s.to_string())
        };

        // Collect this key's values up front so we know whether it is empty.
        let values: Vec<_> = key.value_iter().collect();

        let want_key_row = match mode {
            Mode::Keys | Mode::All => true,
            Mode::Values => values.is_empty(),
        };
        if want_key_row {
            rows.push(Row {
                key_path: key_path.clone(),
                value_name: None,
                value_type: None,
                value_data: None,
                value_raw: None,
                value_dword: None,
                key_last_write: last_write,
                is_deleted: key_deleted,
                hive_type: hive_type.to_string(),
                source: source.to_string(),
                recovery: key_recovery.clone(),
                diagnostics: hive_diag.map(|s| s.to_string()),
            });
        }

        if matches!(mode, Mode::Values | Mode::All) {
            for v in &values {
                let dv = value::decode(v);
                let v_deleted = key_deleted || v.cell_state.is_deleted();
                let recovery = if v_deleted {
                    Some(deleted_label(is_orphan).to_string())
                } else {
                    base_recovery.map(|s| s.to_string())
                };
                // Per-row diagnostics: prefer the value's own (e.g. bad-utf16),
                // else the hive-level diagnostic.
                let diagnostics = dv
                    .diagnostics
                    .clone()
                    .or_else(|| hive_diag.map(|s| s.to_string()));
                rows.push(Row {
                    key_path: key_path.clone(),
                    value_name: dv.name,
                    value_type: Some(dv.value_type),
                    value_data: Some(dv.value_data),
                    value_raw: Some(dv.value_raw),
                    value_dword: dv.value_dword,
                    key_last_write: last_write,
                    is_deleted: v_deleted,
                    hive_type: hive_type.to_string(),
                    source: source.to_string(),
                    recovery,
                    diagnostics,
                });
            }
        }
    }
    rows
}

/// Normalize a user-supplied subtree filter path: strip a leading backslash and
/// an optional leading root-name segment, lowercased for case-insensitive match.
fn normalize_filter(f: &str) -> String {
    f.trim_start_matches('\\').to_ascii_lowercase()
}

/// True when `key_path` is the filter subtree root or a descendant of it.
fn subtree_match(key_path: &str, filter_lower: &str) -> bool {
    if filter_lower.is_empty() {
        return true;
    }
    let kp = key_path.to_ascii_lowercase();
    kp == filter_lower || kp.starts_with(&format!("{filter_lower}\\"))
}
