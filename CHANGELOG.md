# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- Initial `vgi-reghive` VGI worker: Windows Registry hive parsing for DuckDB
  over Apache Arrow IPC (`ATTACH 'reghive' (TYPE vgi, LOCATION '…')`).
- SQL surface: `read_hive`, `hive_subtree`, `hive_key`, `hive_value`, `key_info`,
  `hive_info`, `well_formed`, `logs_applied`, and `reghive_version`.
- Transaction-log replay (apply `.LOG1`/`.LOG2` recovery logs to a dirty hive)
  and deleted-cell recovery for carving unallocated keys/values.
