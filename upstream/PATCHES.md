# The `[uTLS]` patch set

`upstream/utls.patch` is the complete diff between a pristine, import-rewritten
mirror of the pinned Go release's `crypto/tls` (and friends) and the
upstream-owned files actually committed here. Regenerate and review it with:

```
upstream/sync.sh diff > upstream/utls.patch   # regenerate
upstream/sync.sh check                         # fail if committed copy is stale
```

Every hunk is marked with a `[uTLS]` comment in the source so it survives the
three-way merge during a Go update. Keep this set as small as possible: anything
that can live in a `u_*.go` file or a shim should, not in an upstream-owned file.

## Current hunks

### `internal/tls/cipher_suites.go` — AES-GCM construction
Upstream builds the TLS AES-GCM AEAD from the `crypto/internal/fips140/aes/gcm`
module, which cannot be imported outside GOROOT. uTLS is not a FIPS build, so the
two call sites use `crypto/cipher`'s `NewGCM` instead. Identical bytes on the
wire versus the standard non-FIPS path.

### `internal/tls/handshake_server_test.go` — benchmark RNG (test only)
`benchmarkHandshakeServer` forced a deterministic RNG through
`crypto/internal/rand`, which is not importable here and which the public
`testing/cryptotest.SetGlobalRandom` cannot drive for a `*testing.B`. The hunk
drops that override; the benchmark runs with real randomness.

## Hooks added as `u_*.go` instead of hunks

The ClientHello renderer and the handshake hook points the public API needs are
added in `internal/tls/u_*.go` files, which the sync script never touches. They
are listed in `docs/ARCHITECTURE.md`. Prefer adding behaviour there; only reach
for an upstream-owned hunk when a hook genuinely cannot be expressed without one.
