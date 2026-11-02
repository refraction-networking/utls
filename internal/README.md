# `internal/` — the upstream mirror and its shims

Everything under `internal/` is private to this module. Public code lives at the
module root (package `utls`) and is the only thing downstream may import.

## `internal/tls` — the mirrored `crypto/tls`

`internal/tls` is a copy of the Go standard library's `crypto/tls`, taken from a
single Go release (see `upstream/VERSION`). It is produced mechanically by
`upstream/sync.sh`, not written by hand. Two kinds of file live here:

- **Upstream-owned** (`alert.go`, `conn.go`, `handshake_*.go`, …): byte-for-byte
  `crypto/tls` from the pinned Go release, with only two changes applied by the
  sync script — import paths rewritten (see `upstream/imports.txt`) and a small,
  reviewed set of hunks marked `[uTLS]` (see `upstream/utls.patch` and
  `upstream/PATCHES.md`). **Do not edit these by hand** except to add or adjust a
  marked hunk; the sync script re-derives them on every Go update.
- **uTLS-owned** (`u_*.go`): written by us. These add the ClientHello renderer,
  the hook points the public API drives, and test support. The sync script never
  touches `u_*.go`.

Keeping the stdlib coupling confined to this one directory, and keeping our
changes to a tiny auditable patch, is what lets uTLS move to a new Go release by
re-running the sync and resolving a handful of merge hunks, instead of
hand-porting thousands of lines. See `docs/UPSTREAM_SYNC.md`.

## Shim packages

`crypto/tls` imports a few packages that cannot be imported from outside GOROOT
(`crypto/internal/...`, `internal/...`). Each is replaced, via
`upstream/imports.txt`, by a shim here that reproduces just the behaviour
`crypto/tls` needs:

| Shim | Replaces | Notes |
|------|----------|-------|
| `internal/godebug` | `internal/godebug` | Live-reads the `GODEBUG` env var; no runtime-metrics counters. |
| `internal/boring` | `crypto/internal/boring` | BoringCrypto always disabled (`Enabled == false`). |
| `internal/tls12` | `crypto/internal/fips140/tls12` | TLS 1.2 PRF over the public `hash`/`hmac`. |
| `internal/tls13` | `crypto/internal/fips140/tls13` | TLS 1.3 key schedule over the public `crypto/hkdf`. |
| `internal/byteorder` | `internal/byteorder` | Mirrored verbatim (no internal deps). |
| `internal/fips140tls` | `crypto/tls/internal/fips140tls` | Mirrored verbatim (uses public `crypto/fips140`). |
| `internal/cryptotest` | `crypto/internal/cryptotest` | Test only: `MustMinimumFIPS140ModuleVersion`. |
| `internal/testenv` | `internal/testenv` | Test only: network/source skips, `SetGODEBUG`. |

FIPS 140-3 note: uTLS is never a FIPS build. `fips140tls.Required()` can still be
forced on in tests, but the AES-GCM construction uses `crypto/cipher` rather than
the unimportable FIPS module (`cipher_suites.go`, a `[uTLS]` hunk). This changes
no bytes on the wire versus the standard non-FIPS path.

## Running the mirror's own tests

The upstream `crypto/tls` test suite is mirrored too and must stay green after a
sync:

```
go test ./internal/...            # offline; network tests skip themselves
UTLS_NETWORK_TESTS=1 go test ./internal/tls/   # also runs the few net tests
```
