//! The hive-parsing core of the worker: open a blob into a `notatin` parser
//! (`open`), decode individual values (`value`), and walk the key tree into
//! normalized §5 rows (`walk`). `notatin` owns the byte-level cell parsing,
//! transaction-log application, and deleted-record recovery; this module owns the
//! normalized schema, path reconstruction, and the diagnostics discipline.

pub mod open;
pub mod value;
pub mod walk;

/// Compute the per-hive `recovery` label for **live** cells, given the dirty
/// state and whether sibling logs were available and applied.
pub fn base_recovery_label(
    was_dirty: bool,
    logs_present: bool,
    apply_logs: bool,
) -> Option<String> {
    if !was_dirty {
        return None;
    }
    if apply_logs && logs_present {
        Some("logs-applied".to_string())
    } else {
        Some("dirty-no-logs".to_string())
    }
}
