# Windows Registry Hives

Two executed, SQL-first examples use small synthetic Registry hives:

- [01 · Recovery changes the evidence population](01_recovery_changes_the_evidence_population.ipynb) retains all six supplied/missing inputs, separates header health from recovery, and counts allocated versus recovered value rows.
- [02 · A missing key needs a search scope](02_a_missing_key_needs_a_search_scope.ipynb) combines the built-in reference list with key metadata, a nested key, one named value and a relational subtree. It preserves absent keys instead of presenting them as empty keys.

Each notebook has an **Open in Colab** link. A notebook downloaded on its own
retrieves checksum-verified fixtures and plotting code. Initial setup needs network
access; the analyses then use local synthetic bytes, without credentials, a Rust
compiler or a worker checkout. The visible connection uses the native release:

```sql
ATTACH 'reghive' (TYPE vgi,
  LOCATION 'github-auto://Query-farm/vgi-reghive@v0.4.0');
```

For local execution, install [uv](https://docs.astral.sh/uv/) and run:

```sh
cd notebooks
uv sync --locked
uv run --locked vgi-notebooks
```

Select `notebooks/.venv/bin/python` in a notebook editor. Colab uses the shared base
package and preserves compatible preloaded plotting and kernel libraries; the local
lock additionally installs the runner. Setup is checked in a compatible preloaded
local kernel, without claiming a manual hosted-Colab session. GitHub shows saved
tables and SVG charts; it does not honor editor cell-folding metadata.

## Experiments

Restart and run all after editing a parameter. To preserve the saved defaults:

```sh
uv run --locked vgi-notebooks 01_recovery_changes_the_evidence_population.ipynb \
  --parameters '{"RECOVER_DELETED":true}' --output-dir artifacts/recovery
uv run --locked vgi-notebooks 02_a_missing_key_needs_a_search_scope.ipynb \
  --parameters '{"TARGET_KEY":"RunOnce"}' --output-dir artifacts/missing-key
```

Recovery adds two returned representations of one deleted Trace value, while the
nine allocated value rows and six-input audit stay fixed. Those representations
are not two independent deletion events. Selecting RunOnce changes the selected
key/value structures to NULL and its subtree from five value rows to none. The
four-key reference audit and input bytes stay fixed.

## Inputs and scope

[fixtures/manifest.json](fixtures/manifest.json) records the origin and hashes of
four unchanged worker test fixtures plus an authored empty input. A SQL NULL
represents missing input. All three hives are synthetic, with fixed timestamps and
inert example path strings. No live machine, personal hive or credential material
is used. No transaction logs are supplied; `logs_applied` is demonstrated as a
no-log diagnostic, without claiming successful replay coverage.

The first example explicitly disables log replay and controls recovery on
`read_hive`. The second disables both options on `hive_subtree`. Scalar key/value
lookups have no recovery switch, so their reconciliation is limited to the known
live key in this fixture. Absence means not found in the supplied file and search
scope; it does not prove historical absence. A key last-write time is not an
execution or deletion timestamp, and a reference technique is not a verdict.

All **9/9 named SQL surfaces** in release v0.4.0 are demonstrated. Complete exports,
source review, per-cell execution receipts and narrative mappings are retained in
[coverage.json](coverage.json) and [coverage/](coverage/). Current-main registrations
and implementations match these released interfaces; only metadata/examples and
tests changed. Exact runtime execution is against the public release, not a rebuilt
current-main binary. Existing green source CI is reused for these notebook-only edits.

The shared [notebook standard](https://github.com/Query-farm/vgi-example-notebooks/blob/main/docs/standard.md)
owns branding, bootstrap, execution and SVG publication.
