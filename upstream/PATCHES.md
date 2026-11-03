# The `[uTLS]` patch set

`upstream/utls.patch` is the complete diff between a pristine, import-rewritten
mirror of the pinned Go release's `crypto/tls` (and friends, see
`upstream/files.txt`) and the upstream-owned files committed here. It is
generated, never hand-edited:

```
upstream/sync.sh diff > upstream/utls.patch   # regenerate after changing a hunk
upstream/sync.sh check                         # CI: fail if stale or inconsistent
```

Every added line carries a `[uTLS]` comment so it survives the three-way merge
of a Go update (`upstream/sync.sh update goX.Y.Z`). The patch is ~100 added and
~20 removed lines; everything else lives in `internal/tls/u_*.go`, which the sync
tool never touches. **Keep it that way:** add a hunk only when a hook cannot be
expressed from a `u_*.go` file, keep each hunk to a call into a `u_*` function,
and list it below.

Hunks by file (pinned release: `upstream/VERSION`):

## `internal/tls/cipher_suites.go`
- **AES-GCM construction (2 call sites).** Upstream builds the AEAD from
  `crypto/internal/fips140/aes/gcm`, which cannot be imported outside GOROOT.
  uTLS is not a FIPS build, so it uses `crypto/cipher.NewGCM` with the same
  nonce handling. Bytes on the wire are identical to the non-FIPS stdlib path.

## `internal/tls/conn.go`
- **`Conn` fields** `uconn *UConn` (set for spec-rendered clients, nil
  otherwise) and `userver *uServerHooks` (set only by the test peer). With both
  nil every hook below is a no-op and the code path is upstream's.
- **record_size_limit (RFC 8449).** `uRecordTooLarge` rejects records larger
  than the limit we advertised (TLS 1.3 inner plaintext before and after
  decryption; TLS 1.2 plaintext). `uLimitPayload` caps outgoing records to the
  peer's limit.
- **ClientHello fragmentation.** In `Conn.write`, `uFragmentPending` routes the
  first ClientHello record to `UConn.writeFragmented` (u_fragment.go), which
  splits it into records and/or writes; runs under `c.out`'s lock, so no field
  of `Conn` is swapped.
- **CompressedCertificate (RFC 8879).** `readHandshake` accepts message type 25
  (`typeCompressedCertificate`) — rejected later unless compression was offered.
- **Handshake observer.** `uObserveHandshake` sees each parsed handshake message
  (validates ALPS and record_size_limit in EncryptedExtensions).

## `internal/tls/handshake_client.go`
- **Build stage.** `makeClientHello` calls `uconn.prepareHello`, which builds the
  logical hello from the spec, generates every offered key share and attaches
  the renderer (u_conn.go, u_spec.go).
- **Session stage.** `clientHandshake` calls `uLoadSession` instead of
  `loadSession`: spec reconciliation, injected sessions (`SetSession` /
  `SetSessionParams`), the ClientHello hook and PSK binder recomputation.
- **ServerHello exposure.** `setServerHello` records the raw ServerHello and the
  server's key share.
- **Offered-version check.** `pickTLSVersion` calls `uCheckOfferedVersion`:
  the server's version must be one the rendered ClientHello actually offered
  (a spec's list can be narrower than, or noncontiguous within, the Config
  bounds that `mutualVersion` checks; without supported_versions the server may
  not use the extension and may pick at most legacy_version).
- **Downgrade check.** `uMaxOfferedVersion`: the downgrade canary is checked
  against the highest version the spec actually offered (a TLS-1.2-only spec
  must not reject a TLS 1.2 server).
- **session_ticket.** A spec may advertise `session_ticket` on the wire even
  when no cache is configured; the ticket is then not stored (nil-cache guard).

## `internal/tls/handshake_client_tls13.go`
- **Key selection.** `establishHandshakeKeys` takes the private key for the
  group the server chose from the keys the spec offered (`keyShareKeyForGroup`),
  so any offered share — PQ hybrid, classical, or the reused classical half —
  completes.
- **CompressedCertificate.** `uDecompressCertificate` decompresses (zlib,
  brotli, zstd; 1 MiB cap, exact length) before the certificate is parsed.
- **ALPS.** `uSendClientEncryptedExtensions` sends the client's
  application_settings after the server Finished when ALPS was negotiated.

## `internal/tls/handshake_messages.go`
- **Renderer.** `clientHelloMsg.uRender`: when set, `marshal()` and the ECH
  inner encoding render from the live logical fields in the spec's shape
  (extension order, GREASE, padding), so HelloRetryRequest, PSK binders and ECH
  all re-render correctly. `clone` copies the field.

## `internal/tls/handshake_server_tls13.go` (test peer only)
- Three hooks gated on `c.userver != nil`, used only by `NewTestPeer`
  (u_testpeer.go) to give the test suite a server that negotiates certificate
  compression, ALPS and record_size_limit. Never active for clients.

## `internal/tls/handshake_server_test.go` (test only)
- **Benchmark RNG.** `benchmarkHandshakeServer` forced a deterministic RNG via
  `crypto/internal/rand`, which is not importable here; the public
  `testing/cryptotest.SetGlobalRandom` cannot drive a `*testing.B`. The hunk
  drops the override; the benchmark runs with real randomness.

## Shims (not hunks)

Standard-library internals the mirror imports are replaced by small shims under
`internal/` (e.g. `internal/godebug`, `internal/fips140tls`), listed with their
upstream source in `upstream/shims-sources.txt`; `upstream/shims.txt` records
their hashes so `sync.sh check` notices when upstream changes what they mimic.
`upstream/imports.txt` maps each std-internal import to its replacement.
