<img src="docs/vgi-logo.png" alt="VGI" height="64">

# vgi-reghive

A [VGI](https://query.farm) worker that parses **Windows Registry hive files** —
the on-disk `regf` format used by `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `SAM`,
`SECURITY`, `UsrClass.dat`, and `AmCache.hve` — into typed key/value rows for
**DFIR**, directly inside DuckDB over Apache Arrow. Full key paths, value
names/types/data (`REG_SZ`/`REG_DWORD`/`REG_BINARY`/`REG_MULTI_SZ`/`REG_QWORD`/…),
per-key last-write timestamps, **transaction-log (`.LOG1`/`.LOG2`) replay** of
dirty hives, and **deleted-cell recovery** from unallocated space. Offline
forensics compute, in-engine, no agent on the host, no egress.

It is a sibling to `vgi-evtx` and `vgi-mft` in the Windows-DFIR bundle — a
separate worker because `regf` is neither the EVTX binary-XML format nor the
MFT/`$MFT` record format.

## What it is for

The *parse* is well-served by mature free incumbents — RegRipper, regipy, Eric
Zimmerman's Registry Explorer / RECmd — and we do not try to win on "dump a hive
to rows". The value is **fleet-scale, in-SQL registry triage** the incumbents do
not offer: ATTACH a directory of thousands of collected hives and run **one
query** that joins registry evidence to the rest of your security surface
(`vgi-ioc`/threat-intel, `vgi-cve`, `vgi-yara`, `vgi-sigma`, `vgi-secretscan`)
— with no per-host RegRipper invocation and no result-wrangling.

> **Sensitivity note.** `SAM` and `SECURITY` hives contain **password-hash
> material**. This worker exposes hive structure faithfully, so those bytes
> **will** appear in the `value_raw` column. That is correct DFIR behavior, but
> it is sensitive: the worker **never decodes credentials** and is designed to
> pair with `vgi-mask`/`vgi-pii` downstream so a triage query can redact hash
> bytes before results leave the analyst's session. No credential cracking, no
> secret provider, ever.

## SQL surface

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'reghive' AS reghive (TYPE vgi);   -- spawns the worker binary
SET search_path = 'reghive.main';

-- 1. Read a directory of collected hives into key/value rows. read_hive()
--    auto-detects regf, walks the key tree, and (by default) applies sibling
--    .LOG1/.LOG2 transaction logs found next to each file.
SELECT key_path, value_name, value_type, value_data, key_last_write, is_deleted
FROM read_hive('/cases/4421/*/NTUSER.DAT')
WHERE key_path LIKE 'Software\Microsoft\Windows\CurrentVersion\Run%';

-- 2. Persistence triage: surface Run-keys across the fleet, joined to IOCs.
SELECT r.source, r.key_path, r.value_name, r.value_data, i.feed, i.category
FROM read_hive('/cases/4421/*/{NTUSER.DAT,SOFTWARE}') r
LEFT JOIN ioc.indicators i
       ON i.kind = 'filepath' AND r.value_data ILIKE '%' || i.value || '%'
WHERE r.key_path LIKE '%CurrentVersion\Run%'
  AND i.value IS NOT NULL;

-- 3. Surface deleted cells (recovered keys/values from unallocated space).
SELECT key_path, value_name, value_type, value_data, key_last_write, recovery
FROM read_hive('/cases/4421/*/SOFTWARE')
WHERE is_deleted;            -- recovered-from-free-space evidence only

-- 4. Probe a hive header: is it dirty (does it need transaction-log recovery)?
SELECT (hive_info(content)).hive_type, (hive_info(content)).is_dirty
FROM read_blob('/cases/4421/host7/SYSTEM');

-- 5. Pull one subtree / one key (BLOB from read_blob, fed as a literal).
SELECT * FROM reghive.main.hive_subtree(unhex('...regf bytes...'), 'ControlSet001\Services');
SELECT reghive.main.hive_key(content, 'ControlSet001\Services\Schedule') AS svc
FROM read_blob('SYSTEM');
```

> **Note on `read_blob` and the cloud.** Cloud hives (`s3://`, `https://`) are
> fetched upstream with DuckDB's `read_blob(...)` and passed to the scalar probes
> as a `BLOB` column. `read_hive(glob)` reads **local** files itself (and applies
> sibling logs); for a single hive in memory call `read_hive(blob)`.
>
> **Note on table-function arguments.** A DuckDB table function cannot take a
> correlated column / `LATERAL` / subquery argument. `read_hive` and
> `hive_subtree` therefore take a *constant*: a glob `VARCHAR` literal, or a
> `BLOB` literal (e.g. `unhex(...)`). The per-row probes (`hive_key`,
> `hive_value`, `key_info`, `hive_info`, `well_formed`, `logs_applied`) are
> **scalars** and take an ordinary `BLOB` column from `read_blob(...)`.

## Function catalog

| Function | Kind | Returns |
|---|---|---|
| `read_hive(glob_or_blob [, apply_logs, recover_deleted, mode])` | table | the §output-schema rows |
| `hive_subtree(blob, key_path [, apply_logs, recover_deleted])` | table | the same rows, scoped to a subtree |
| `hive_key(blob, key_path)` | scalar | `STRUCT(key_path, last_write, class_name, subkey_count, value_count, is_deleted, values LIST<STRUCT(value_name, value_type, value_data, value_raw)>)` |
| `hive_value(blob, key_path, value_name)` | scalar | `STRUCT(value_type, value_data, value_raw)` — `value_name := ''`/`NULL` → the (Default) value |
| `key_info(blob, key_path)` | scalar | `STRUCT(last_write, subkey_count, value_count, class_name, is_deleted)` |
| `hive_info(blob)` | scalar | `STRUCT(hive_type, major, minor, root_path, primary_seq, secondary_seq, is_dirty, last_written)` |
| `well_formed(blob)` | scalar | `STRUCT(ok, hive_type, error, kind)` — **never panics** |
| `logs_applied(blob, log1, log2)` | scalar | `STRUCT(applied, entries_replayed, dirty_pages, became_clean, log_format)` |
| `reghive_version()` | scalar | `VARCHAR` |

`read_hive` / `hive_subtree` named options: `apply_logs` (replay sibling
`.LOG1`/`.LOG2`, default `true`), `recover_deleted` (scan unallocated cells,
default `true`), `mode ∈ {values, keys, all}` (default `values`).

### Output schema (`read_hive` / `hive_subtree`)

One row per **value**, plus one key-only row for a key with no values
(`mode` controls this). Repeated key columns are denormalized onto each value row.

| column | type | notes |
|---|---|---|
| `key_path` | VARCHAR | path from the hive root (synthetic root key name stripped; `$Deleted\…` for orphans) |
| `value_name` | VARCHAR | value name; `NULL` for the **(Default)** value and key-only rows |
| `value_type` | VARCHAR | `REG_SZ`/`REG_DWORD`/`REG_MULTI_SZ`/`REG_BINARY`/…/`REG_<n>` |
| `value_data` | VARCHAR | **coerced** rendering (UTF-16 decoded, ints stringified, MULTI_SZ newline-joined, binary hex). Lossy for binary |
| `value_raw` | BLOB | the **exact** on-disk bytes (lossless; the credential-bearing column for `SAM`/`SECURITY`) |
| `value_dword` | BIGINT | populated for `REG_DWORD`/`REG_QWORD` |
| `key_last_write` | TIMESTAMPTZ | parent key's last-write FILETIME → UTC |
| `is_deleted` | BOOLEAN | row reconstructed from unallocated space |
| `hive_type` | VARCHAR | `SYSTEM`/`SOFTWARE`/`NTUSER`/`SAM`/`SECURITY`/`USRCLASS`/`AMCACHE`/`UNKNOWN` |
| `source` | VARCHAR | originating file path or `'<blob>'` |
| `recovery` | VARCHAR | `NULL` on clean; else `dirty-no-logs`, `logs-applied`, `deleted-orphan`, `deleted-reparented`, `modified-prior` |
| `diagnostics` | VARCHAR | `NULL` on clean decode; else `truncated`, `bad-checksum`, `bad-utf16`, … |

## The differentiators

- **Transaction-log replay.** A collected hive is frequently *dirty* — copied
  off a live system mid-write, with its latest changes only in the logs. A hive
  is dirty when its base-block checksum is wrong **or** its primary/secondary
  sequence numbers disagree. `read_hive` applies the sibling `.LOG1`/`.LOG2`
  logs by default (turning a dirty hive into its recovered state before emitting
  rows) and reports what it did via the `recovery` column and `logs_applied`.
- **Deleted-cell recovery.** Freeing a key/value usually just flips a cell's
  size sign and unlinks it — the bytes remain until reused. With
  `recover_deleted` (the default), `read_hive` reconstructs those cells from
  unallocated space, flags them `is_deleted`, and labels them `deleted-orphan` /
  `deleted-reparented` so a query can include or exclude them with
  `WHERE is_deleted` / `WHERE NOT is_deleted`.

## Build & test

```sh
cargo build --release --bin reghive-worker     # the worker binary (a DuckDB vgi LOCATION)
cargo test                                     # unit + golden-fixture + zero-panic proptest
cargo run -p reghive-core --example gen_fixtures   # regenerate tests/hives/*.hve
TRANSPORT=subprocess ci/run-integration.sh     # haybarn SQLLogic E2E (also unix / http)
```

The golden fixtures under `tests/hives/` are **synthetic** (built by
`reghive-core`'s hive writer) and license-clean — we never commit a real
`SAM`/`SECURITY` with live hashes.

## Licensing

- **Worker:** MIT (see `LICENSE`).
- **Parser engine:** [`notatin`](https://github.com/strozfriedberg/notatin)
  (Stroz Friedberg), **Apache-2.0** — the modern, 100%-safe-Rust offline regf
  parser that uniquely provides transaction-log application and deleted/modified
  record recovery. The GPL Rust regf crates `nt-hive` (GPL-2.0+) and `nt_hive2`
  (GPL-3.0) are **deliberately kept out** of the dependency tree.

The `regf` format itself is openly documented (the
[msuhanov regf spec](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md),
libyal/libregf, Google Project Zero's "Windows Registry Adventure #5: regf").
No ToS, no redistributed dataset.

## Pairs with

`vgi-evtx` and `vgi-mft`/`vgi-prefetch` (the Windows-DFIR bundle),
`vgi-ioc`/threat-intel, `vgi-cve`, `vgi-yara`/`vgi-sigma`, `vgi-secretscan`, and
`vgi-mask`/`vgi-pii` (redact `SAM`/`SECURITY` hash bytes before results leave the
session). Sold inside the Windows-DFIR / security bundle, behind the governance
proxy.

---

Copyright 2026 Query Farm LLC — https://query.farm
