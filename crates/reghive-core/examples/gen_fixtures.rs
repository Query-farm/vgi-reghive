//! Generate the committed golden hive fixtures under `tests/hives/`.
//!
//! Run from the repo root: `cargo run -p reghive-core --example gen_fixtures`.
//! The fixtures are synthetic (no real SAM/SECURITY with live hashes) and
//! reproducible, so the haybarn SQLLogic E2E and the integration tests share one
//! source of truth.

use std::path::PathBuf;

use reghive_core::hivegen::{build, HiveSpec, KeySpec, ValueSpec};

fn sz(s: &str) -> Vec<u8> {
    let mut o = Vec::new();
    for u in s.encode_utf16() {
        o.extend_from_slice(&u.to_le_bytes());
    }
    o.extend_from_slice(&[0, 0]);
    o
}

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

/// SOFTWARE hive: a Run key (persistence) with one value of every coercion class,
/// plus a recoverable deleted "GhostKey".
fn software() -> Vec<u8> {
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
    build(&spec)
}

/// SYSTEM hive: ControlSet001\Services\Schedule, marked dirty (seq mismatch).
fn system_dirty() -> Vec<u8> {
    let svc = KeySpec::new("Schedule")
        .with_value(ValueSpec::new("Start", 4, 3u32.to_le_bytes().to_vec()))
        .with_value(ValueSpec::new("ImagePath", 2, sz("%SystemRoot%\\svc.exe")));
    let services = KeySpec::new("Services").with_subkey(svc);
    let cs = KeySpec::new("ControlSet001").with_subkey(services);
    let mut root = KeySpec::new("CMI-CreateHive-{SYSTEM-GUID}");
    root.subkeys.push(cs);
    build(&HiveSpec::new("\\Config\\SYSTEM", root).dirty())
}

/// A clean SYSTEM reference (same content, not dirty) for the recovery contrast.
fn system_clean() -> Vec<u8> {
    let svc = KeySpec::new("Schedule")
        .with_value(ValueSpec::new("Start", 4, 3u32.to_le_bytes().to_vec()))
        .with_value(ValueSpec::new("ImagePath", 2, sz("%SystemRoot%\\svc.exe")));
    let services = KeySpec::new("Services").with_subkey(svc);
    let cs = KeySpec::new("ControlSet001").with_subkey(services);
    let mut root = KeySpec::new("CMI-CreateHive-{SYSTEM-GUID}");
    root.subkeys.push(cs);
    build(&HiveSpec::new("\\Config\\SYSTEM", root))
}

/// A redacted SAM-like hive: a binary V value (zeroed credential bytes).
fn sam() -> Vec<u8> {
    let user = KeySpec::new("000001F4")
        .with_value(ValueSpec::new("V", 3, vec![0u8; 16]))
        .with_value(ValueSpec::new("F", 3, vec![0u8; 8]));
    let users = KeySpec::new("Users").with_subkey(user);
    let sam = KeySpec::new("SAM").with_subkey(users);
    let mut root = KeySpec::new("CMI-CreateHive-{SAM-GUID}");
    root.subkeys.push(sam);
    build(&HiveSpec::new("\\Config\\SAM", root))
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Default: <repo>/tests/hives relative to this crate.
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("tests")
                .join("hives")
        });
    std::fs::create_dir_all(&out_dir).expect("create fixtures dir");

    let files: &[(&str, Vec<u8>)] = &[
        ("software.hve", software()),
        ("system_dirty.hve", system_dirty()),
        ("system_clean.hve", system_clean()),
        ("sam.hve", sam()),
        // A non-hive blob for the well_formed / robustness checks.
        (
            "garbage.bin",
            b"this is definitely not a registry hive".to_vec(),
        ),
    ];
    for (name, bytes) in files {
        let path = out_dir.join(name);
        std::fs::write(&path, bytes).expect("write fixture");
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    }
}
