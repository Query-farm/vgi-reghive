//! Self-contained demonstration data for discovery, examples, and agent tests.
//!
//! Two things live here so the rest of the worker stays parser-focused:
//!
//! 1. [`demo_hive_hex`] — the committed synthetic **SOFTWARE** fixture
//!    (`tests/hives/software.hve`) hex-encoded at build time via `include_bytes!`,
//!    so the `read_hive` / `hive_subtree` example queries are fully self-contained
//!    (`unhex('…')::BLOB`) and cannot drift from the fixture the tests use. The
//!    hive carries a classic Run-key persistence value
//!    (`Software\Microsoft\Windows\CurrentVersion\Run` → `Updater` =
//!    `C:\Windows\evil.exe`).
//! 2. [`forensic_keys_view`] — a curated, VALUES-backed browsable view of
//!    well-known forensic registry locations. It gives an agent something to
//!    *browse* (which key paths to triage) before it has a hive in hand, scans
//!    with no file or credential, and clears the "table functions but nothing
//!    browsable" gap.

use vgi::catalog::CatView;

/// The demo SOFTWARE hive (`tests/hives/software.hve`) as a lowercase hex string,
/// suitable for `unhex('…')::BLOB`. Encoded from the committed fixture at build
/// time so it always matches the golden hive the tests parse.
pub fn demo_hive_hex() -> String {
    const BYTES: &[u8] = include_bytes!("../../../tests/hives/software.hve");
    let mut s = String::with_capacity(BYTES.len() * 2);
    for b in BYTES {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
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
