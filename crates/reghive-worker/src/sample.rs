//! Self-contained demonstration data for discovery, examples, and agent tests.
//!
//! Two things live here so the rest of the worker stays parser-focused:
//!
//! 1. [`demo_hive_blob_sql`] — the committed synthetic **SOFTWARE** fixture
//!    (`tests/hives/software.hve`) embedded at build time via `include_bytes!`
//!    and rendered as a compact `unhex(…)::BLOB` expression, so the `read_hive` /
//!    `hive_subtree` example queries are fully self-contained and cannot drift
//!    from the fixture the tests use. The
//!    hive carries a classic Run-key persistence value
//!    (`Software\Microsoft\Windows\CurrentVersion\Run` → `Updater` =
//!    `C:\Windows\evil.exe`).
//! 2. [`forensic_keys_view`] — a curated, VALUES-backed browsable view of
//!    well-known forensic registry locations. It gives an agent something to
//!    *browse* (which key paths to triage) before it has a hive in hand, scans
//!    with no file or credential, and clears the "table functions but nothing
//!    browsable" gap.

use vgi::catalog::CatView;

/// The demo SOFTWARE hive (`tests/hives/software.hve`), embedded at build time so
/// it always matches the golden hive the tests parse.
const DEMO_HIVE: &[u8] = include_bytes!("../../../tests/hives/software.hve");

/// Zero runs at least this long are emitted as `repeat('00', n)` in
/// [`demo_hive_blob_sql`] rather than spelled out.
const ZERO_RUN_MIN: usize = 32;

/// The demo SOFTWARE hive as a self-contained SQL BLOB expression,
/// `unhex('…' || repeat('00', n) || '…')::BLOB`.
///
/// The 12 KiB fixture is about 90% zero padding, so spelling it out as one hex
/// literal costs ~24,600 characters, far past vgi-lint's 4,000-character
/// agent-context bound for a metadata value (VGI417). Folding the long zero runs
/// into `repeat('00', n)` keeps the identical bytes in ~2,700 characters while
/// the example still binds AND returns rows under `vgi-lint --execute` (table
/// functions take constant expressions, so the concatenation folds at bind).
pub fn demo_hive_blob_sql() -> String {
    compact_blob_sql(DEMO_HIVE)
}

/// Render `bytes` as `unhex(<parts joined by ||>)::BLOB`, folding runs of at
/// least [`ZERO_RUN_MIN`] zero bytes into `repeat('00', n)`.
fn compact_blob_sql(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut parts: Vec<String> = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let run = bytes[i..].iter().take_while(|&&b| b == 0).count();
        if run >= ZERO_RUN_MIN {
            if !lit.is_empty() {
                parts.push(format!("'{lit}'"));
                lit.clear();
            }
            parts.push(format!("repeat('00', {run})"));
            i += run;
        } else {
            let _ = write!(lit, "{:02x}", bytes[i]);
            i += 1;
        }
    }
    if !lit.is_empty() {
        parts.push(format!("'{lit}'"));
    }
    if parts.is_empty() {
        parts.push("''".to_string());
    }
    format!("unhex({})::BLOB", parts.join(" || "))
}

/// The Run-key path inside the demo hive (root name stripped, as `read_hive`
/// emits it). Handy for the `hive_subtree` / `hive_key` examples.
pub const DEMO_RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/// A curated reference of well-known Windows Registry forensic locations, exposed
/// as a VALUES-backed [`CatView`]. Browsable with a plain scan (no file, no
/// credential); an analyst reads it to learn *which* key paths to pull from a
/// hive with `hive_subtree` / `hive_key`.
pub fn forensic_keys_view() -> CatView {
    // NOTE: single-quoted DuckDB string literals take backslashes literally, so
    // the registry paths need no SQL escaping (only Rust's own `\\`).
    let definition = "\
SELECT * FROM (VALUES \
('Software\\Microsoft\\Windows\\CurrentVersion\\Run','SOFTWARE','Persistence','Executables launched automatically at user logon; the canonical autostart persistence location.','T1547.001'),\
('Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','SOFTWARE','Persistence','Executables launched once at the next logon and then deleted.','T1547.001'),\
('ControlSet001\\Services','SYSTEM','Persistence','Windows services and kernel drivers; malicious services and driver loading are configured here.','T1543.003'),\
('Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon','SOFTWARE','Persistence','Shell / Userinit values executed at logon and abused for persistence.','T1547.004'),\
('Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','SOFTWARE','Configuration','Inventory of installed applications (DisplayName, InstallDate, publisher).',NULL),\
('Root\\InventoryApplicationFile','AMCACHE','Execution','AmCache program-execution evidence: first-seen time, full path, and SHA-1 of executed binaries.','T1059'),\
('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist','NTUSER','Execution','ROT13-encoded per-user GUI program-execution counts and last-run times.','T1204'),\
('ControlSet001\\Control\\Session Manager\\AppCompatCache','SYSTEM','Execution','ShimCache: recently-run executable paths and their timestamps.','T1059') \
) AS t(key_path, hive, category, description, mitre_technique)";

    let mut tags = crate::meta::object_tags(
        "Well-Known Forensic Registry Keys",
        "A curated reference of well-known Windows Registry locations that matter in DFIR triage — \
         Run/RunOnce and Winlogon persistence, the Services branch, AmCache and ShimCache and \
         UserAssist execution evidence, and the installed-software inventory. Each row gives the \
         root-stripped key_path (exactly the form read_hive and hive_subtree emit and accept), the \
         hive it lives in, a triage category, a plain-English description, and the MITRE ATT&CK \
         technique it maps to. Browse this first to decide which key paths to pull from a collected \
         hive with hive_subtree or hive_key.",
        "Curated reference of well-known forensic registry keys (persistence, execution, \
         configuration) with their hive, category, description, and MITRE ATT&CK technique. The \
         key_path column is in the same root-stripped form read_hive/hive_subtree use.",
        "forensic keys, well known keys, registry reference, persistence, run key, runonce, \
         winlogon, services, amcache, shimcache, userassist, mitre, att&ck, triage, DFIR",
        "Reference",
    );
    // Classifying tags (VGI123) — reuse the schema's vocabulary (VGI132) so the
    // facets stay a small shared set rather than unique per object.
    tags.push(("domain".to_string(), "security-and-forensics".to_string()));
    tags.push(("topic".to_string(), "dfir-triage".to_string()));
    tags.push((
        "vgi.example_queries".to_string(),
        r#"[
  {
    "description": "List the persistence-related registry keys to triage first, with their ATT&CK technique.",
    "sql": "SELECT key_path, description, mitre_technique FROM reghive.main.forensic_keys WHERE category = 'Persistence' ORDER BY key_path"
  },
  {
    "description": "Count the well-known forensic keys grouped by triage category.",
    "sql": "SELECT category, count(*) AS n FROM reghive.main.forensic_keys GROUP BY category ORDER BY n DESC, category"
  }
]"#
        .to_string(),
    ));

    CatView {
        name: "forensic_keys".to_string(),
        definition: definition.to_string(),
        comment: Some(
            "Curated reference of well-known Windows Registry forensic locations (persistence, \
             execution, configuration) with their hive, category, description, and MITRE ATT&CK \
             technique; key_path matches the form read_hive/hive_subtree use."
                .to_string(),
        ),
        tags,
        column_comments: vec![
            (
                "key_path".to_string(),
                "Root-stripped registry key path, exactly the form read_hive/hive_subtree emit and \
                 accept (backslash-separated, no synthetic HKLM mount)."
                    .to_string(),
            ),
            (
                "hive".to_string(),
                "The hive file this key lives in: SOFTWARE / SYSTEM / NTUSER / SAM / SECURITY / \
                 AMCACHE / USRCLASS."
                    .to_string(),
            ),
            (
                "category".to_string(),
                "Triage category: Persistence, Execution, or Configuration.".to_string(),
            ),
            (
                "description".to_string(),
                "Why this key matters in a DFIR investigation and what it holds.".to_string(),
            ),
            (
                "mitre_technique".to_string(),
                "MITRE ATT&CK technique id this location maps to (e.g. T1547.001), or NULL when \
                 the key is purely informational."
                    .to_string(),
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the expression back to bytes the way DuckDB would evaluate it.
    fn eval(sql: &str) -> Vec<u8> {
        let inner = sql
            .strip_prefix("unhex(")
            .and_then(|s| s.strip_suffix(")::BLOB"))
            .expect("unhex(...)::BLOB wrapper");
        let mut hex = String::new();
        for part in inner.split(" || ") {
            if let Some(n) = part
                .strip_prefix("repeat('00', ")
                .and_then(|s| s.strip_suffix(')'))
            {
                hex.push_str(&"00".repeat(n.parse().unwrap()));
            } else {
                hex.push_str(part.trim_matches('\''));
            }
        }
        (0..hex.len())
            .step_by(2)
            .map(|k| u8::from_str_radix(&hex[k..k + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn demo_blob_sql_round_trips_and_fits_agent_context() {
        let sql = demo_hive_blob_sql();
        assert_eq!(eval(&sql), DEMO_HIVE);
        assert!(sql.len() < 3_000, "demo blob SQL is {} chars", sql.len());
    }

    #[test]
    fn compact_blob_sql_edge_cases() {
        for bytes in [
            vec![],
            vec![0u8; 5],
            vec![0u8; 40],
            vec![1, 2, 3],
            [vec![7u8], vec![0u8; 64], vec![9u8]].concat(),
        ] {
            assert_eq!(eval(&compact_blob_sql(&bytes)), bytes);
        }
    }
}
