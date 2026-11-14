# VGI Reghive notebooks

[01 · Recovery changes the evidence population](01_recovery_changes_the_evidence_population.ipynb)
uses visible Haybarn SQL to audit six inputs, inspect typed Registry values, and
compare allocated values with recovered rows. Seaborn/Matplotlib charts preserve
input coverage and separate recovery provenance. The saved notebook is executed.

## Run

Install `uv`, then from this directory:

```sh
uv sync --locked
uv run --locked python execute.py
```

The runner uses a temporary kernel, works from this directory, and replaces the
saved notebook only after successful execution. The entire `notebooks/` directory
can be copied elsewhere; no worker checkout or Rust build is needed. Internet access
is required initially for the Python environment, community VGI extension and native
GitHub release. The release must have an asset for your platform; this example was
verified on macOS Apple silicon with Haybarn 2.0.0rc11.

For VS Code, select this directory's `.venv/bin/python` interpreter as the notebook
kernel. Alternatively register it explicitly:

```sh
uv run --locked python -m ipykernel install --user --name vgi-reghive-notebooks --display-name 'Python (vgi-reghive notebooks)'
```

Keep the working directory here when running interactively. Connection SQL and
analytical SQL remain visible; helper code is folded. Restart and run all after
editing `RECOVER_DELETED`.

## Experiment

```sh
uv run --locked python execute.py --parameters '{"RECOVER_DELETED": true}' --output-dir validation/recovery
```

The output directory receives the notebook and its branding, fixture and environment
companions. Overrides without a separate destination are rejected. The default has
nine allocated value rows and no recovered rows; enabling recovery keeps those nine
and exposes two SOFTWARE rows with different recovery labels for the same synthetic
deleted value. They are not two distinct deletion events. The input audit stays the
same. Restore `False` to reset the example.

## Worker and data provenance

The connection uses the literal published native location
`github-auto://Query-farm/vgi-reghive@v0.4.0`. To upgrade it, change the visible pin
and rerun both parameter settings; output details depend on the parser release.
The reader does not need the source build used for repository validation.

`fixtures/software.hve`, `system_clean.hve`, `system_dirty.hve`, and `garbage.bin`
are unchanged synthetic fixtures from `tests/hives` at commit
`b8e9cb9dd4bea9b6181c36ffeb4dce2d8a81dbd5`. `empty.bin` is an authored zero-byte input;
SQL adds a separate NULL missing-input record. `fixtures/manifest.json` records all
five hashes. The source fixture generator is
`crates/reghive-core/examples/gen_fixtures.rs`. No SAM hive or log file is included.
All hive timestamps are fixed test values; no machine was surveyed. Path strings
are inert example content and are never executed.

Header validity, dirty state and recovery scope answer different questions. A valid
base block does not certify every cell. `apply_logs:=false` is explicit; the scalar
log probe receives NULL log arguments. This notebook does not demonstrate transaction
replay, establish acquisition completeness, infer deletion times, classify malware,
or decode credentials. `mode:='values'` also returns key-only rows in this release;
the SQL uses `value_type IS NOT NULL` when counting values. Recovery may represent
the same deleted content through multiple paths, so returned-row counts are not
counts of distinct historical settings.

## Validation

The default and a detached copy with recovery enabled execute through the real
published worker. Twelve SQL checks plus a chart-row reconciliation cover input
coverage, dirty state, typed decoding, source-scoped joins and recovery labels.
Both charts are inspected in each mode. Runner checks cover overrides without a
destination, unknown parameters and a failing invalid-parameter run preserving
saved outputs. Fixture hashes match their provenance manifest.

Repository validation passes locked release build, 36 Rust tests, Clippy, formatting,
warning-clean Rust documentation and 118/128/118 SQL assertions across subprocess,
HTTP and Unix transports (five cases each). The existing metadata gate exits 2:
99/100, L0, zero errors and two VGI417 warnings for oversized example-query tags
on `reghive.main` and `read_hive`; structural and behavioral checks ran. This baseline
metadata limitation is unchanged by the notebook-only change.

The official Query.Farm Strata Sun wordmark and VGI logo are bundled unchanged in
`assets/`; the wordmark links to Query.Farm at the top and final bottom of the notebook.
