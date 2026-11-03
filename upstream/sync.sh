#!/bin/sh
# upstream/sync.sh - maintain the generated crypto/tls mirror in internal/tls.
#
# Thin wrapper around the portable Go tool in upstream/cmd/utls-sync (no GNU
# sed/find/diff assumptions). Run from anywhere; it operates on this repo.
#
#   sync.sh pristine <goversion> <outdir>   write pristine(goversion) to outdir
#   sync.sh update <goversion>              merge the mirror onto a new Go release
#   sync.sh finish                          complete an update after resolving conflicts
#   sync.sh diff                            print the [uTLS] patch
#   sync.sh check                           fail if the patch/shims are stale or an update is unresolved
#   sync.sh shims                           print upstream hashes for the hand-maintained shims
#
# Extra flags go before the command, e.g.:  sync.sh -goroot go1.28.0=/path/to/go update go1.28.0
# See docs/UPSTREAM_SYNC.md.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
exec go run ./upstream/cmd/utls-sync -root "$ROOT" "$@"
