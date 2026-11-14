# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Composed example queries combining the worker's objects (read_hive joined to
  forensic_keys, key_info coverage over forensic_keys, well_formed + hive_info
  header triage), two composed agent tasks, and `test/sql/composed.test`.

### Fixed

- README listed a `reghive_version()` scalar that is not registered; README
  example 6 now probes every reference key against every collected hive.

## [0.4.0]

### Changed

- Port to VGI protocol 3.3 (vgi 0.51.0, vgi-rpc 0.32.4). Requires the current
  VGI DuckDB extension; 3.2 extensions are incompatible.

## [0.1.0]

### Added

- Initial `vgi-reghive` VGI worker: Windows Registry hive parsing for DuckDB
  over Apache Arrow IPC (`ATTACH 'reghive' (TYPE vgi, LOCATION '…')`).
- SQL surface: `read_hive`, `hive_subtree`, `hive_key`, `hive_value`, `key_info`,
  `hive_info`, `well_formed`, `logs_applied`, and `reghive_version`.
- Transaction-log replay (apply `.LOG1`/`.LOG2` recovery logs to a dirty hive)
  and deleted-cell recovery for carving unallocated keys/values.
