# AGENTS.md — maintaining uTLS

This file is the operating manual for an AI coding agent (or a human) maintaining
uTLS. Read it before making changes. It explains the architecture that makes
this repository cheap to keep current, and the exact procedures for the jobs you
will actually be asked to do: following a new Go release, adding or fixing a
fingerprint, and extending the API without breaking downstream.

If you read nothing else, read **The one rule** and **The map**.

## The one rule

**All coupling to the Go standard library lives in `internal/tls`, and that
directory is generated, not authored.** It is a mechanical copy of a single Go
release's `crypto/tls`, carrying only import rewrites and a tiny, marked patch.
Your freedom to write code is in the `u_*.go` files (uTLS-owned, never synced)
and in the root package (`*.go` at the module root). Fight the urge to "just
edit" a mirrored file; nearly always the change belongs in a `u_*.go` file or
the root package instead. When it genuinely cannot, see
[docs/UPSTREAM_SYNC.md](docs/UPSTREAM_SYNC.md) and keep the hunk marked `[uTLS]`.

Why this matters: v1 of uTLS hand-patched thousands of lines across the whole of
`crypto/tls`, so every Go release broke it and every fix was archaeology. v2
keeps the patch to ~100 added lines across 6 files, all marked, so a Go update is a
scripted re-sync plus a handful of merge resolutions.

## The map

```
.                      root package `utls` (module .../utls/v2) — the PUBLIC API
  config.go            crypto/tls.Config <-> internal conversion (the one boundary)
  conn.go              UConn, UClient, Dial/Dialer, hook, sessions, fragmentation, HandOff
  quic.go              QUICConn on standard crypto/tls QUIC types
  spec.go              ClientHelloSpec + extension/const re-exports
  fingerprint.go       ClientHelloID, ParseFingerprint, the preset registry
  parrots.go           the browser fingerprint presets (provenance in the header)
  randomized.go        randomized + seeded fingerprints
  profile.go           versioned JSON profiles
  ja.go                JA3 / JA4 and SpecFromJA3
  transport.go         http.RoundTripper (native net/http h1/h2 per proxy route)
  fingerprinter.go     ParseClientHello: raw bytes -> spec
  api/v2.txt           the exported API; api_test.go is the compatibility GATE
  config_fields_test.go  the reflection GUARDRAIL (see below)
  fidelity_test.go     presets vs real browser captures in testdata/
  downstream_test.go   Xray/sing-box/Psiphon migration fixtures

internal/tls           MIRROR of crypto/tls (generated) + uTLS renderer
  *.go (no u_ prefix)  upstream-owned: crypto/tls verbatim + [uTLS] hunks only
  u_common.go          uTLS constants, GREASE helpers
  u_extensions.go      the TLSExtension types and their wire encoding
  u_spec.go            ClientHelloSpec + the renderer (spec -> bytes)
  u_conn.go            UConn driver, ClientHelloContext, hooks, sessions
  u_negotiate.go       cert compression, ALPS, record_size_limit
  u_fragment.go        first-ClientHello fragmentation
  u_handoff.go         TLS 1.3 record-layer handoff
  u_stdcompat.go       the ONLY private-field coupling to crypto/tls types
  u_testpeer.go        test server for negotiated features
  u_*_test.go          uTLS-owned tests

internal/{godebug,boring,tls12,tls13,byteorder,fips140tls,cryptotest,testenv}
                       shims for std-internal packages (see internal/README.md)

upstream/              the sync machinery
  sync.sh              wrapper for cmd/utls-sync: pristine/update/finish/diff/check/shims
  cmd/utls-sync        the portable sync tool (+ fixtures in sync_test.go)
  VERSION              the Go release the mirror is pinned to
  files.txt            which dirs are mirrored
  imports.txt          std-internal import -> shim rewrites
  exclude.txt          mirrored files we skip (with reasons)
  utls.patch           the committed [uTLS] diff; `sync.sh check` guards it
  PATCHES.md           every hunk, explained

docs/                  the rest of the documentation (read as needed)
```

## Jobs

### 1. A new Go version is out (the main recurring job)

Full procedure: [docs/UPSTREAM_SYNC.md](docs/UPSTREAM_SYNC.md). In short:

```
upstream/sync.sh update go1.28.0      # 3-way merges the mirror onto the new release
# resolve conflicts if any, then: upstream/sync.sh finish
go build ./... && go test ./...        # fix fallout (mirror tests first, then uTLS)
upstream/sync.sh diff > upstream/utls.patch   # re-record the patch
upstream/sync.sh check && go test ./... # includes the reflection guardrail
```

Expect conflicts only where a `[uTLS]` hunk touches code that upstream also
changed. Resolve them keeping the `[uTLS]` markers. If `crypto/tls` added a
field to `Config` or `ConnectionState`, `config_fields_test.go` fails and names
it — decide in `config.go` whether to convert it or mark it unsupported.

### 2. Add or update a browser fingerprint

Full procedure: [docs/FINGERPRINTS.md](docs/FINGERPRINTS.md). You add a spec
builder in `parrots.go` and `register` it. You do **not** touch `internal/tls`
unless the fingerprint needs an extension that does not exist yet (then add the
type in `internal/tls/u_extensions.go` and re-export it in `spec.go`).

### 3. Extend the API

Keep the extension interface's methods unexported (so adding extensions never
breaks downstream). Prefer adding to the root package. If you must add a
handshake hook, express it as a `u_*.go` method plus the smallest possible
`[uTLS]` hunk, and document the hunk in `upstream/PATCHES.md`.

## Guardrails that will catch you

- `go test ./...` runs the **entire upstream crypto/tls test suite** against the
  mirror. If a sync or a hunk broke TLS behaviour, it fails here.
- `config_fields_test.go` fails if a new stdlib `Config`/`ConnectionState` field
  is unhandled, or if the mirror drifts from stdlib's field set.
- `upstream/sync.sh check` fails in CI if `upstream/utls.patch` is stale (a
  mirrored file was edited without re-recording the patch), an update is
  unresolved, a mirrored file imports an unmapped std-internal package, or an
  upstream package behind a shim changed.
- `api_test.go` fails if the exported API differs from `api/v2.txt`. Removing
  or changing a line is a breaking change (needs /v3); additions are recorded
  with `go test -run TestAPICompatibility -update-api .` after review.
- `fidelity_test.go` fails if a preset drifts from its real browser capture.

## Non-negotiables

- Never widen the `[uTLS]` patch when a `u_*.go` file would do.
- Never make a mirrored-file change without a `[uTLS]` marker and a line in
  `upstream/PATCHES.md`.
- Never return uTLS-specific copies of `tls.Config`/`tls.ConnectionState` from
  the public API; the whole point is to speak the standard types.
- A fingerprint preset's `Spec()` must return a FRESH spec each call.
- Never claim browser fidelity without a real capture with provenance in
  `testdata/` (see docs/FINGERPRINTS.md); never fabricate a capture.
- Keep `go vet ./...` clean.

## Orientation reading

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the two layers fit together.
- [docs/API_DESIGN.md](docs/API_DESIGN.md) — why the API looks the way it does,
  traced to real downstream usage.
- [docs/USAGE_SURVEY.md](docs/USAGE_SURVEY.md) — the evidence base: how ~30 real
  projects use uTLS and what they need.
- [docs/MIGRATION.md](docs/MIGRATION.md) — mapping v1 API to v2, for downstream.
