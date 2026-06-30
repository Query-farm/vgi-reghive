//! Zero-panic proptest gate for the pure `reghive-core` parsers.
//!
//! The worker treats hive bytes as **untrusted binary input**: a hostile,
//! truncated, or garbage blob must yield a classified error, never a crash. The
//! `notatin`-backed open path is covered by a worker-side proptest; here we
//! fuzz the pure header/log/coercion paths the worker layers on top, asserting
//! they never panic on arbitrary or truncated bytes.

use proptest::prelude::*;

use reghive_core::{baseblock, cursor::HiveGlobCursor, logparse, valuetype};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Base-block parsing never panics on arbitrary bytes.
    #[test]
    fn baseblock_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..9000)) {
        let _ = baseblock::parse(&bytes);
        let _ = baseblock::xor32_checksum(&bytes);
    }

    /// Truncations of a *valid* synthetic hive never panic (prefix fuzzing —
    /// the classic "copied off mid-write" shape).
    #[test]
    fn baseblock_truncation_never_panics(prefix_len in 0usize..6000) {
        use reghive_core::hivegen::{HiveSpec, KeySpec};
        let blob = reghive_core::hivegen::build(&HiveSpec::new("SYSTEM", KeySpec::new("ROOT")));
        let cut = prefix_len.min(blob.len());
        let _ = baseblock::parse(&blob[..cut]);
    }

    /// Transaction-log summarization never panics.
    #[test]
    fn logparse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..9000)) {
        let _ = logparse::summarize(&bytes);
    }

    /// Value coercion never panics for any type code / byte payload.
    #[test]
    fn coerce_never_panics(type_raw in any::<u32>(), bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = valuetype::coerce(type_raw, &bytes);
        let _ = valuetype::type_name(type_raw);
    }

    /// The glob cursor round-trips losslessly for any field values.
    #[test]
    fn cursor_roundtrips(
        pending in proptest::collection::vec(".*", 0..8),
        current in proptest::option::of(".*"),
        emitted in any::<u64>(),
    ) {
        let c = HiveGlobCursor {
            pending_files: pending,
            current_file: current,
            emitted_in_current: emitted,
        };
        let back = HiveGlobCursor::from_bytes(&c.to_bytes());
        prop_assert_eq!(c, back);
    }
}
