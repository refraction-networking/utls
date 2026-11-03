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
| 7 | API compatibility | `go test -count=1 -run TestAPICompatibility .` |
| 8 | Bounded fuzzing | `go test -run '^$' -fuzz FuzzParseClientHello -fuzztime 60s .` and `go test -run '^$' -fuzz FuzzSNIHostRange -fuzztime 60s ./internal/tls` |
| 9 | Independent peer interop | build `interop/boringssl` (pinned BoringSSL commit) and `UTLS_BSSL_PEER=... go test -tags bsslinterop -run BoringSSL .` |
| 10 | Vulnerabilities | `govulncheck ./...` (golang.org/x/vuln v1.9.0 or newer) |
| 11 | Toolchain | the tests ran on the minimum Go in `go.mod` (= `upstream/VERSION`) and on the newest stable Go |

Before tagging also:

- Re-capture the `*_Auto` browsers if a new stable version shipped since the
  last capture (docs/FINGERPRINTS.md); a stale `*_Auto` is a fidelity bug.
- Check that `upstream/VERSION` is the newest patch release of its Go minor
  (security fixes in crypto/tls arrive in point releases).
- Review `api/v2.txt` changes since the last tag (additions only).
