# Releasing uTLS v2

v2 is published as module `github.com/refraction-networking/utls/v2`
(tags `v2.x.y`). A release requires every gate below to pass on the exact
revision being tagged; `.github/workflows/go.yml` runs the same gates.

| # | Gate | Command |
|---|------|---------|
| 1 | Build | `go build ./...` |
| 2 | Vet clean | `go vet ./...` |
| 3 | Full tests (upstream crypto/tls suite on the mirror, uTLS tests, API gate, fidelity vs captures, profile golden files, fuzz seed corpora) | `go test -count=1 ./...` |
| 4 | Race | `go test -count=1 -race ./...` |
| 5 | Mirror consistent with `upstream/VERSION` + `upstream/utls.patch`, no unresolved update, no unmapped std-internal import, shims current | `upstream/sync.sh check` |
| 6 | Sync tool fixtures | `go test -count=1 ./upstream/cmd/utls-sync` |
| 7 | Type-checked API compatibility and gate fixtures | `go test -count=1 -run 'TestAPI' .` |
| 8 | Bounded fuzzing (minimization bounded so the budget explores; the target has a per-input watchdog because Go's fuzzer has none) | `go test -run '^$' -fuzz FuzzParseClientHello -fuzztime 60s -fuzzminimizetime 5s .` and `go test -run '^$' -fuzz FuzzSNIHostRange -fuzztime 60s -fuzzminimizetime 5s ./internal/tls` |
| 9 | Independent peer interop | build `interop/boringssl` (pinned BoringSSL commit) and `UTLS_BSSL_PEER=... go test -tags bsslinterop -run BoringSSL .` |
| 9b | Real REALITY counterpart (isolated module; pinned github.com/xtls/reality) | `cd interop/reality && go test -count=1 -race .` |
| 10 | Vulnerabilities in the runtime module (what users import) | `govulncheck ./...` at the repository root (golang.org/x/vuln v1.9.0 or newer); CI runs exactly this |
| 11 | Toolchain | the tests ran on the minimum Go in `go.mod` (= `upstream/VERSION`) and on the newest stable Go |

Not a release gate, but useful extra evidence: `interop/reality` is a test-only
module whose code is all in test files, so a plain `govulncheck ./...` there
scans nothing of the REALITY peer. Audit it with
`cd interop/reality && govulncheck -test ./...`; its findings concern the pinned
test peer, not the uTLS runtime.

Before tagging also:

- Re-capture the `*_Auto` browsers if a new stable version shipped since the
  last capture (docs/FINGERPRINTS.md); a stale `*_Auto` is a fidelity bug.
- Check that `upstream/VERSION` is the newest patch release of its Go minor
  (security fixes in crypto/tls arrive in point releases).
- Review `api/v2.txt` changes since the last tag (additions only).
