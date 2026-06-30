//! Golden-fixture integration tests over the full open → walk pipeline, driven by
//! the synthetic hive builder in `reghive_core::hivegen` (so the fixtures are
//! reproducible and license-clean — no committed real SAM/SECURITY).

use reghive_core::hivegen::{HiveSpec, KeySpec, ValueSpec};
use reghive_worker::arrow_map::Row;
use reghive_worker::hive::walk::Mode;
use reghive_worker::hive::{self, open, walk};

/// UTF-16LE encode with a trailing NUL (REG_SZ on-disk shape).
fn sz(s: &str) -> Vec<u8> {
    let mut o = Vec::new();
    for u in s.encode_utf16() {
        o.extend_from_slice(&u.to_le_bytes());
    }
    o.extend_from_slice(&[0, 0]);
    o
}

/// REG_MULTI_SZ on-disk shape.
fn multi(parts: &[&str]) -> Vec<u8> {
    let mut o = Vec::new();
    for p in parts {
        for u in p.encode_utf16() {
            o.extend_from_slice(&u.to_le_bytes());
        }
        o.extend_from_slice(&[0, 0]);
    }
    o.extend_from_slice(&[0, 0]);
    o
}

/// A SOFTWARE-shaped hive: a Run key with one value of every coercion class,
/// plus a recoverable deleted key.
fn software_hive() -> Vec<u8> {
    let run = KeySpec::new("Run")
        .with_value(ValueSpec::new("Updater", 1, sz("C:\\Windows\\evil.exe")))
        .with_value(ValueSpec::new("Start", 4, 2u32.to_le_bytes().to_vec()))
        .with_value(ValueSpec::new(
            "Big",
            11,
            0x1122_3344_5566u64.to_le_bytes().to_vec(),
        ))
        .with_value(ValueSpec::new("List", 7, multi(&["alpha", "beta"])))
        .with_value(ValueSpec::new("Blob", 3, vec![0xde, 0xad, 0xbe, 0xef]));
    let cv = KeySpec::new("CurrentVersion").with_subkey(run);
    let windows = KeySpec::new("Windows").with_subkey(cv);
    let ms = KeySpec::new("Microsoft").with_subkey(windows);
    let software = KeySpec::new("Software").with_subkey(ms);

    let mut root = KeySpec::new("CMI-CreateHive-{SOFTWARE-GUID}");
    root.subkeys.push(software);

    let mut spec = HiveSpec::new("\\SystemRoot\\System32\\Config\\SOFTWARE", root);
    spec.deleted_orphans
        .push(KeySpec::new("GhostKey").with_value(ValueSpec::new("Trace", 1, sz("was-here"))));
    reghive_core::hivegen::build(&spec)
}

fn walk_values(bytes: &[u8], recover: bool) -> Vec<Row> {
    let opened = open::open_blob(bytes, true, recover, &[]).expect("open");
    let base_recovery = hive::base_recovery_label(opened.was_dirty, false, true);
    walk::walk(
        &opened,
        "<blob>",
        Mode::Values,
        base_recovery.as_deref(),
        None,
        None,
    )
}

#[test]
fn reads_run_key_values_with_coercion() {
    let bytes = software_hive();
    let rows = walk_values(&bytes, false);

    let run = |name: &str| {
        rows.iter().find(|r| {
            r.key_path == "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                && r.value_name.as_deref() == Some(name)
        })
    };

    let updater = run("Updater").expect("Updater value present");
    assert_eq!(updater.value_type.as_deref(), Some("REG_SZ"));
    assert_eq!(updater.value_data.as_deref(), Some("C:\\Windows\\evil.exe"));
    assert_eq!(updater.hive_type, "SOFTWARE");

    let start = run("Start").expect("Start value");
    assert_eq!(start.value_type.as_deref(), Some("REG_DWORD"));
    assert_eq!(start.value_data.as_deref(), Some("2"));
    assert_eq!(start.value_dword, Some(2));

    let big = run("Big").expect("Big value");
    assert_eq!(big.value_type.as_deref(), Some("REG_QWORD"));
    assert_eq!(
        big.value_data.as_deref(),
        Some(&0x1122_3344_5566u64.to_string()[..])
    );

    let list = run("List").expect("List value");
    assert_eq!(list.value_type.as_deref(), Some("REG_MULTI_SZ"));
    assert_eq!(list.value_data.as_deref(), Some("alpha\nbeta"));

    let blob = run("Blob").expect("Blob value");
    assert_eq!(blob.value_type.as_deref(), Some("REG_BINARY"));
    assert_eq!(blob.value_data.as_deref(), Some("deadbeef"));
    assert_eq!(
        blob.value_raw.as_deref(),
        Some(&[0xde, 0xad, 0xbe, 0xef][..])
    );

    // Every live value row has a key_last_write and is not deleted.
    assert!(updater.key_last_write.is_some());
    assert!(!updater.is_deleted);
}

#[test]
fn deleted_cell_recovery_is_labelled_and_isolatable() {
    let bytes = software_hive();

    // Without recovery, the ghost is invisible.
    let live = walk_values(&bytes, false);
    assert!(
        !live.iter().any(|r| r.key_path.contains("GhostKey")),
        "deleted key must not appear without recovery"
    );

    // With recovery, exactly the deleted rows carry is_deleted + a deleted label.
    let recovered = walk_values(&bytes, true);
    let ghost: Vec<_> = recovered
        .iter()
        .filter(|r| r.key_path.contains("GhostKey"))
        .collect();
    assert!(!ghost.is_empty(), "deleted key must be recovered");
    for r in &ghost {
        assert!(r.is_deleted, "recovered rows must be flagged is_deleted");
        assert!(r.key_path.starts_with("$Deleted\\"), "orphan path prefix");
        assert_eq!(r.recovery.as_deref(), Some("deleted-orphan"));
    }
    // A WHERE NOT is_deleted view excludes them.
    assert!(recovered
        .iter()
        .filter(|r| !r.is_deleted)
        .all(|r| !r.key_path.contains("GhostKey")));
}

#[test]
fn dirty_hive_is_flagged_and_parses_best_effort() {
    let spec = HiveSpec::new("SYSTEM", {
        let svc = KeySpec::new("Schedule").with_value(ValueSpec::new(
            "Start",
            4,
            3u32.to_le_bytes().to_vec(),
        ));
        let services = KeySpec::new("Services").with_subkey(svc);
        let cs = KeySpec::new("ControlSet001").with_subkey(services);
        let mut root = KeySpec::new("CMI-CreateHive-{SYSTEM-GUID}");
        root.subkeys.push(cs);
        root
    })
    .dirty();
    let bytes = reghive_core::hivegen::build(&spec);

    let opened = open::open_blob(&bytes, false, false, &[]).expect("open dirty");
    assert!(
        opened.was_dirty,
        "seq-number mismatch must mark the hive dirty"
    );

    // With no logs available, rows still come back, tagged dirty-no-logs.
    let base_recovery = hive::base_recovery_label(opened.was_dirty, false, true);
    let rows = walk::walk(
        &opened,
        "<blob>",
        Mode::Values,
        base_recovery.as_deref(),
        None,
        None,
    );
    let start = rows
        .iter()
        .find(|r| r.value_name.as_deref() == Some("Start"))
        .expect("Start value parsed from dirty hive");
    assert_eq!(start.recovery.as_deref(), Some("dirty-no-logs"));
    assert_eq!(start.value_data.as_deref(), Some("3"));
}

#[test]
fn subtree_filter_scopes_rows() {
    let bytes = software_hive();
    let opened = open::open_blob(&bytes, true, false, &[]).expect("open");
    let rows = walk::walk(
        &opened,
        "<blob>",
        Mode::Values,
        None,
        None,
        Some("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    );
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|r| r
        .key_path
        .starts_with("Software\\Microsoft\\Windows\\CurrentVersion\\Run")));
}

#[test]
fn sensitivity_raw_bytes_preserved_never_decoded() {
    // A SAM-like value blob (opaque credential material) must land in value_raw
    // verbatim and never be "helpfully" decoded.
    let secret = vec![0x01u8, 0x00, 0xde, 0xad, 0xc0, 0xde, 0xff, 0x00];
    let v = KeySpec::new("000001F4").with_value(ValueSpec::new("V", 3, secret.clone()));
    let users = KeySpec::new("Users").with_subkey(v);
    let sam = KeySpec::new("SAM").with_subkey(users);
    let mut root = KeySpec::new("CMI-CreateHive-{SAM-GUID}");
    root.subkeys.push(sam);
    let bytes = reghive_core::hivegen::build(&HiveSpec::new("\\Config\\SAM", root));

    let rows = walk_values(&bytes, false);
    let vrow = rows
        .iter()
        .find(|r| r.value_name.as_deref() == Some("V"))
        .expect("V value");
    assert_eq!(
        vrow.value_raw.as_deref(),
        Some(&secret[..]),
        "raw bytes verbatim"
    );
    assert_eq!(vrow.value_type.as_deref(), Some("REG_BINARY"));
    assert_eq!(vrow.hive_type, "SAM");
}
