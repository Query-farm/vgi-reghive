#!/usr/bin/env bash
# Build the reghive VGI worker and run the sqllogictest suite against it using
# the prebuilt standalone `haybarn-unittest` runner and the signed community
# `vgi` extension (see ci/README.md). This is a convenience wrapper around
# ci/run-integration.sh for local runs.
#
# Prerequisites (one-time):
#   uv tool install haybarn-unittest      # the DuckDB unittest binary
#
# TRANSPORT defaults to subprocess; set it to http or unix to exercise the
# other transports:
#   TRANSPORT=http ./run_tests.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

HAYBARN_UNITTEST="${HAYBARN_UNITTEST:-$(command -v haybarn-unittest || true)}"
if [[ -z "$HAYBARN_UNITTEST" || ! -x "$HAYBARN_UNITTEST" ]]; then
    echo "ERROR: haybarn-unittest not found. Install it with:" >&2
    echo "       uv tool install haybarn-unittest" >&2
    exit 1
fi

echo "==> Building reghive-worker (release)"
cargo build --release --bin reghive-worker

export WORKER_BIN="$REPO_ROOT/target/release/reghive-worker"
export HAYBARN_UNITTEST

echo "==> Running SQLLogic suite"
echo "    worker:   $WORKER_BIN"
echo "    unittest: $HAYBARN_UNITTEST"
echo "    transport: ${TRANSPORT:-subprocess}"

TRANSPORT="${TRANSPORT:-subprocess}" ci/run-integration.sh
