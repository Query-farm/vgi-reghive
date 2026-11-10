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

## Quick start

Every [GitHub release](https://github.com/Query-farm/vgi-reghive/releases) ships a prebuilt worker binary. The `vgi` extension downloads the one for your platform, checks its SHA-256 and caches it, so there is nothing to install besides DuckDB:

```sql
INSTALL vgi FROM community;
LOAD vgi;

ATTACH 'reghive' AS reghive (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-reghive@v0.3.0');

-- Scan a collected hive and pull the Run-key persistence value it plants.
SELECT key_path, value_name, value_data FROM reghive.main.read_hive(unhex('7265676601000000010000000000056936c0d501010000000300000000000000010000002000000000200000010000005c00530079007300740065006d0052006f006f0074005c00530079007300740065006d00330032005c0043006f006e006600690067005c0053004f00460054' || repeat('00', 397) || '1085c20e' || repeat('00', 3584) || '6862696e0000000000200000000000000000000000000000000000000000000090ffffff6e6b24000000056936c0d50100000000000000000100000000000000b0030000ffffffff00000000ffffffffffffffffffffffff00000000000000000000000000000000000000001e000000434d492d437265617465486976652d7b534f4654574152452d475549447d0000a8ffffff6e6b20000000056936c0d50100000000200000000100000000000000a0030000ffffffff00000000ffffffffffffffffffffffff000000000000000000000000000000000000000008000000536f667477617265a0ffffff6e6b20000000056936c0d5010000000090000000010000000000000090030000ffffffff00000000ffffffffffffffffffffffff0000000000000000000000000000000000000000090000004d6963726f736f667400000000000000a8ffffff6e6b20000000056936c0d50100000000e8000000010000000000000080030000ffffffff00000000ffffffffffffffffffffffff00000000000000000000000000000000000000000700000057696e646f777300a0ffffff6e6b20000000056936c0d5010000000048010000010000000000000070030000ffffffff00000000ffffffffffffffffffffffff00000000000000000000000000000000000000000e00000043757272656e7456657273696f6e0000a8ffffff6e6b20000000056936c0d50100000000a0010000000000000000000000000000ffffffff0500000058030000ffffffffffffffff00000000000000000000000000000000000000000300000052756e0000000000d0ffffff43003a005c00570069006e0064006f00770073005c006500760069006c002e00650078006500000000000000e0ffffff766b0700280000005802000001000000010000005570646174657200e0ffffff766b0500040000800200000004000000010000005374617274000000f0ffffff665544332211000000000000e0ffffff766b030008000000c80200000b000000010000004269670000000000e0ffffff61006c00700068006100000062006500740061000000000000000000e0ffffff766b040018000000f802000007000000010000004c69737400000000e0ffffff766b040004000080deadbeef0300000001000000426c6f6200000000e8ffffff88020000a8020000d80200001803000038030000f0ffffff6c6601000002000052756e00f0ffffff6c660100a001000043757272f0ffffff6c6601004801000057696e64f0ffffff6c660100e80000004d696372f0ffffff6c66010090000000536f6674180000007700610073002d0068006500720065000000000020000000766b050012000000c00300000100000001000000547261636500000008000000d8030000580000006e6b20000000056936c0d5010000000000000000000000000000000000000000ffffffff01000000f8030000ffffffffffffffff00000000000000000000000000000000000000000800000047686f73744b6579a81b' || repeat('00', 7078))::BLOB) WHERE value_name = 'Updater';

-- Browse the well-known persistence keys to triage first, with their ATT&CK technique.
SELECT key_path, mitre_technique FROM reghive.main.forensic_keys WHERE category = 'Persistence' ORDER BY key_path;
```

Prebuilt binaries cover macOS (Apple silicon), Linux (x86-64 and arm64). `github-auto://` needs an explicit release tag; change `@v0.3.0` to move to a newer release.

### Other ways to run it

- **Docker** (the image bundles the worker; needs a container runtime):

  ```sql
  ATTACH 'reghive' AS reghive (TYPE vgi, LOCATION 'docker://ghcr.io/query-farm/vgi-reghive:0.3.0');
  ```

- **Manual download.** Download the archive for your platform from the [releases page](https://github.com/Query-farm/vgi-reghive/releases), verify it against its `.sha256` file (a cosign `.cosign.bundle` is published alongside), unpack it, and set `LOCATION` to the path of the extracted worker executable.

### Build from source

To build the worker yourself, see [Build & test](#build--test).

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

The worker speaks VGI protocol vgi.v3 (3.2), so it requires haybarn 2.0 and its
community `vgi` extension; haybarn 1.5 cannot attach it.

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'reghive' AS reghive (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-reghive@v0.3.0');
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
