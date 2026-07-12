# CLAUDE.md — vgi-reghive

Guidance for working in this repository.

## What this is

A production VGI worker (Rust) that parses Windows Registry hive files (`regf`)
into typed key/value rows for DFIR, served to DuckDB over Apache Arrow IPC under
the catalog `reghive`, schema `main`. It mirrors the `vgi-fixedformat` /
`vgi-units` fleet template: a Cargo workspace with a `*-worker` binary crate and
a `*-core` library crate, `ci/` scripts, transport-matrix CI, and a `vgi-lint`
metadata gate.

## Layout

```
crates/
  reghive-core/            # pure, no Arrow / no notatin / no vgi
    src/baseblock.rs       # regf base-block parser (hive_info / well_formed / is_dirty), FILETIME→micros
    src/valuetype.rs       # REG_* type naming + value_data coercion (UTF-16 / DWORD / QWORD / MULTI_SZ / hex)
    src/logparse.rs        # transaction-log format detection + HvLE entry/dirty-page counts
    src/cursor.rs          # HiveGlobCursor — serde file-glob scan state (§4), round-trip proven
    src/hivegen.rs         # minimal synthetic regf hive WRITER for fixtures/tests
    examples/gen_fixtures.rs   # writes tests/hives/*.hve
    tests/proptest_nopanic.rs  # zero-panic gate over the pure parsers
  reghive-worker/          # the binary; notatin + vgi + arrow
    src/main.rs            # bootstrap + catalog metadata; registers scalars + tables
    src/arrow_map.rs       # §output schema + Row → RecordBatch; struct field sets
    src/hive/{open,walk,value}.rs   # notatin open (logs+recover), tree walk → rows, value decode
    src/scalar/*.rs        # hive_key, hive_value, key_info, hive_info, well_formed, logs_applied, version
    src/table/*.rs         # read_hive (glob cursor + resume), hive_subtree, common (glob/sibling-logs)
    tests/integration.rs   # golden fixtures: coercion, deleted recovery, dirty hive, subtree, sensitivity
    tests/fuzz_open.rs     # zero-panic proptest over the notatin open path
tests/hives/               # committed synthetic fixtures (regenerate with gen_fixtures)
test/sql/*.test            # haybarn SQLLogic E2E
```

`notatin` owns byte-level cell parsing, transaction-log *application*, and
deleted-record *recovery*. This worker owns the normalized schema, path
reconstruction, the glob cursor, the diagnostics discipline, and the Arrow map.

## Non-negotiables

- **Licensing.** Worker is **MIT**. The regf parser is **`notatin` (Apache-2.0)
  ONLY**. The GPL crates `nt-hive` (GPL-2.0+) and `nt_hive2` (GPL-3.0) must
  **never** enter the dependency tree.
- **`nom` pin.** `notatin 1.0.1` declares `nom >= 6` but does not compile against
  `nom 8`. `Cargo.lock` pins `nom` to `7.1.3` (one node, used by notatin). If you
  regenerate the lock, re-run `cargo update -p nom --precise 7.1.3`.
- **Never panics on hostile input.** Every hive open / cell walk / value decode
  is slice-checked and runs under a catch; bounded allocation; cycle/recursion
  guards (notatin's). The two proptests are zero-panic gates.
- **No credential decoding.** `SAM`/`SECURITY` bytes land in `value_raw` as
  opaque `BLOB` and are never interpreted (see the sensitivity test).

## Platform facts (save yourself the rediscovery)

- A DuckDB **scalar**'s output type is fixed at bind time; per-row work is a
  scalar. A DuckDB **table function rejects** correlated `LATERAL` / column /
  subquery arguments — pass `read_hive` a glob `VARCHAR` literal or a `BLOB`
  literal (`unhex(...)`); the per-row probes are scalars over a `read_blob`
  column.
- `notatin`'s deleted-cell recovery outer loop compares an *absolute* hbin
  offset against the *relative* `hive_bins_data_size`, so a single 4096-byte bin
  is never scanned — the synthetic fixtures use a ≥ 8192-byte bin so recovery
  runs (documented in `hivegen.rs`).
- `logs_applied` / `hive_value` set `null_handling = "SPECIAL"` so a NULL `.LOG`
  or `value_name` argument reaches the function instead of null-propagating.

## Gates (all must be green)

```sh
cargo build --release
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo test
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uvx --from vgi-lint-check vgi-lint lint ./target/release/reghive-worker --fail-on info
HAYBARN_UNITTEST=$(command -v haybarn-unittest) WORKER_BIN=$PWD/target/release/reghive-worker \
  TRANSPORT=subprocess ci/run-integration.sh   # also unix / http
```

The E2E needs the signed community `vgi` extension (CI provisions it; haybarn's
warm step `INSTALL vgi FROM community`).
