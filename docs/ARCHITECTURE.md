# Architecture

uTLS is two layers with a hard boundary between them.

```
          downstream imports github.com/refraction-networking/utls/v2
                   │
   ┌───────────────▼───────────────────────────────────────────┐
   │  root package `utls`  (hand-written, stable public API,     │
   │  guarded by api/v2.txt)                                     │
   │                                                             │
   │  *crypto/tls.Config ──fromStdConfig──► internal config       │
   │  internal state     ──toStd*/StdError─► crypto/tls types     │
   │                                                             │
   │  UConn, Dialer, QUICConn, ClientHelloID presets,           │
   │  profiles, JA3/JA4, ParseClientHello, fragmentation, HandOff│
   └───────────────┬───────────────────────────────────────────┘
                   │  (one import, one conversion boundary)
   ┌───────────────▼───────────────────────────────────────────┐
   │  internal/tls  (not importable by downstream)               │
   │                                                             │
   │  u_*.go (uTLS-owned): spec + extension types, renderer,     │
   │    UConn driver and hook, negotiated features, fragmentation,│
   │    handoff, std-type bridge, test peer                       │
   │                                                             │
   │  *.go (upstream-owned): crypto/tls of upstream/VERSION,      │
   │    verbatim except import rewrites + ~100 lines of marked    │
   │    [uTLS] hunks (upstream/PATCHES.md)                        │
   └───────────────┬───────────────────────────────────────────┘
                   │  (import rewrites, upstream/imports.txt)
   ┌───────────────▼───────────────────────────────────────────┐
   │  internal shims: godebug, boring, tls12, tls13, byteorder,   │
   │  fips140tls, cryptotest, testenv (+ golang.org/x/sys/cpu)    │
   └─────────────────────────────────────────────────────────────┘
```

## Why two layers

The volatile part of uTLS is its dependence on `crypto/tls` internals, which
move every release. v2 quarantines that in `internal/tls`, generated from a
pinned Go release by `upstream/sync.sh` with a small marked patch. The public
API never exposes `crypto/tls` internals, so it stays stable while the inner
layer is re-synced underneath it (docs/UPSTREAM_SYNC.md).

## The ClientHello lifecycle

The handshake is the stock `crypto/tls` client state machine. uTLS attaches at
four stages:

1. **Build** (`makeClientHello` → `UConn.prepareHello`, u_conn.go). The spec's
   extensions `apply` themselves to the logical `clientHelloMsg` (versions,
   groups, ALPN, SNI, ticket support, key shares, ECH GREASE...), so the stock
   state machine sees a consistent hello. Config/spec precedence is fixed here
   (`helloBuild`, u_spec.go): the Config bounds versions and supplies
   ServerName/NextProtos; the spec decides shape. A fresh private key is
   generated for every offered key-share group. A `helloRenderer` is attached
   to the message.
2. **Session** (`uLoadSession`, replacing `loadSession`). Loads a cached or
   injected session (`SetSession`, `SetSessionParams`), reconciles it with the
   spec (PSK only if the spec has psk_key_exchange_modes; a TLS 1.2 ticket only
   with session_ticket), runs the ClientHello hook on the final bytes (binders
   zeroed), then recomputes PSK binders over the hooked hello.
3. **Render at marshal** (`clientHelloMsg.marshal` → `helloRenderer`). Every
   time the hello is serialized — first flight, HelloRetryRequest, binder
   computation, ECH inner encoding — it is rendered from the *current* logical
   fields in the spec's order with per-connection GREASE and padding. There are
   no cached bytes to go stale.
4. **Negotiate** (u_negotiate.go). An observer validates EncryptedExtensions
   (ALPS, record_size_limit); CompressedCertificate is decompressed before the
   stock certificate parser; the client sends its ALPS EncryptedExtensions;
   record sizes are enforced both ways. `establishHandshakeKeys` picks the
   private key for whichever offered group the server chose.

After the handshake: `HandOff` (u_handoff.go) can detach the TLS 1.3 record
layer; fragmentation (u_fragment.go) affects only the first ClientHello write.

## The `[uTLS]` patch

The complete, explained list is `upstream/PATCHES.md`; `upstream/sync.sh check`
proves the committed mirror is exactly pristine + that patch. Each hunk is a
call into a `u_*.go` function, guarded so that a plain `*Conn` (no `uconn`)
runs upstream's code path.

## The standard-type boundary

The root package speaks `*crypto/tls.Config`, `crypto/tls.ConnectionState`,
`*crypto/tls.ClientSessionState`, `tls.QUICEvent` and the stdlib error types.

- **Config** (config.go): converted field by field once per connection. The
  struct and its plain-data slices (ALPN, suites, curves, ECH list, certificate
  bytes) are snapshotted; referenced objects (roots, keys, callbacks, caches,
  writers) are shared as in crypto/tls and must not be mutated while in use
  (config_ownership_test.go);
  `config_fields_test.go` classifies every field of both structs by reflection
  (converted / client-irrelevant / unsupported), so a new stdlib field fails a
  test instead of being silently ignored. Callbacks are wrapped:
  `VerifyConnection` and `EncryptedClientHelloRejectionVerify` receive standard
  `ConnectionState`s; `GetClientCertificate` receives a standard
  `CertificateRequestInfo` whose `Context()` is the handshake context.
- **Session cache**: a stdlib `ClientSessionCache` is bridged both ways via
  `ResumptionState`/`SessionState.Bytes`/`ParseSessionState`/
  `NewResumptionState` (same encoding as the mirrored release).
- **Two unexported fields** cannot be set through public API: the exporter
  behind `ConnectionState.ExportKeyingMaterial` and the context inside
  `CertificateRequestInfo`. `internal/tls/u_stdcompat.go` is the only place
  that sets them (reflect + unsafe, validated against the field's type at
  start-up). If the bridge is ever unavailable on a future Go, uTLS degrades
  explicitly: the exporter returns `ErrExporterUnavailable` (never panics) and
  a config with `GetClientCertificate` fails before any I/O rather than passing
  a context-less request.
- **Errors** (`StdError`): `ECHRejectionError`, `AlertError`,
  `CertificateVerificationError` and `RecordHeaderError` are returned as the
  crypto/tls types; when wrapped (QUIC), the original chain is kept too.

## Scope and the integration boundary

uTLS stops at TLS. It negotiates versions, suites, key shares, ALPN, ALPS,
certificate compression, record_size_limit, ECH and sessions, and returns a
`net.Conn` with standard crypto/tls state. Application protocols are the
caller's: `UConn` implements `ConnectionState()` and `HandshakeContext`, so a
caller can hand it to an HTTP stack through a dial function (net/http's
`DialTLSContext`, for example), but pooling, proxies, retries and HTTP/2 frame
handling are that stack's behaviour, not uTLS's.

ALPS (application_settings) is negotiated as opaque bytes: uTLS sends the
spec's settings, validates the extension in EncryptedExtensions and exposes
the peer's bytes via `NegotiatedApplicationSettings`. It never parses them.
For HTTP/2, the ALPS draft makes the server's initial SETTINGS live in TLS; the
standard library's net/http does not consume ALPS, so a caller that negotiates
ALPS with an HTTP/2 server needs an HTTP/2 implementation that applies those
settings.

## Test infrastructure

- The mirrored upstream crypto/tls test suite runs against `internal/tls`.
- `NewTestPeer` (u_testpeer.go) is a mirrored server with inert hooks that
  negotiates certificate compression, ALPS and record_size_limit, so those
  features are tested end to end in-process.
- `interop/boringssl` builds an independent BoringSSL server (zlib certificate
  compression, ALPS) for `go test -tags bsslinterop`.
- `testdata/*_clienthello*.hex` are real browser captures with provenance;
  fidelity_test.go compares presets with them byte by byte.
