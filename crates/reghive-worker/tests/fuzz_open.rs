//! Zero-panic proptest over the `notatin`-backed open path. A hostile, truncated,
//! or garbage blob must yield a classified error, never a crash — the
//! untrusted-binary-input contract (§7). Complements the pure-parser proptest in
//! `reghive-core`.

use proptest::prelude::*;

use reghive_core::hivegen::{HiveSpec, KeySpec, ValueSpec};
use reghive_worker::hive::open;
use reghive_worker::hive::walk::{self, Mode};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    /// Opening arbitrary bytes never panics (it returns Ok or a classified Err).
    #[test]
    fn open_arbitrary_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..9000)) {
        if let Ok(opened) = open::open_blob(&bytes, true, true, &[]) {
            // If it opened, walking it must also not panic.
            let _ = walk::walk(&opened, "<blob>", Mode::All, None, None, None);
        }
    }

    /// Truncations of a valid hive (the "copied off mid-write" shape) never panic.
    #[test]
    fn open_truncated_valid_hive_never_panics(cut in 0usize..7000) {
        let run = KeySpec::new("Run").with_value(ValueSpec::new(
            "Updater",
            1,
            {
                let mut o = Vec::new();
                for u in "x".encode_utf16() { o.extend_from_slice(&u.to_le_bytes()); }
                o.extend_from_slice(&[0, 0]);
                o
            },
        ));
        let mut root = KeySpec::new("ROOT");
        root.subkeys.push(KeySpec::new("Software").with_subkey(run));
        let blob = reghive_core::hivegen::build(&HiveSpec::new("SOFTWARE", root));
        let end = cut.min(blob.len());
        let _ = open::open_blob(&blob[..end], true, true, &[]);
    }
}
