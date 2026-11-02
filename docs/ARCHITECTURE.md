# Architecture

uTLS is two layers with a hard boundary between them.

```
          downstream imports this
                   │
   ┌───────────────▼───────────────────────────────────────────┐
   │  root package `utls`  (hand-written, stable public API)     │
   │                                                             │
   │  *crypto/tls.Config  ─fromStdConfig─►  internal config       │
   │  internal ConnState  ─toStdConnState─►  crypto/tls.ConnState  │
   │                                                             │
   │  ClientHelloID / ParseFingerprint / presets / Transport /   │
   │  Fingerprinter — all built on ClientHelloSpec + UConn        │
   └───────────────┬───────────────────────────────────────────┘
                   │  (one import, one conversion boundary)
   ┌───────────────▼───────────────────────────────────────────┐
   │  internal/tls  (NOT importable by downstream)               │
   │                                                             │
   │  u_*.go (uTLS-owned):                                        │
   │    ClientHelloSpec, TLSExtension types, the renderer,        │
   │    UConn driver, ClientHelloContext hook                     │
   │                                                             │
   │  *.go (upstream-owned): crypto/tls from one Go release,      │
   │    verbatim except import rewrites + ~140 lines of marked    │
   │    [uTLS] hunks                                              │
   └───────────────┬───────────────────────────────────────────┘
                   │  (import rewrites)
   ┌───────────────▼───────────────────────────────────────────┐
   │  internal shims: godebug, boring, tls12, tls13, byteorder,   │
   │  fips140tls, cryptotest, testenv                             │
   └─────────────────────────────────────────────────────────────┘
```

## Why two layers

The problem v2 solves is maintainability across Go releases. The volatile part
of uTLS is its dependence on `crypto/tls` internals — which move every release.
v2 quarantines that volatility in `internal/tls`, which is generated from a
pinned Go release by `upstream/sync.sh` and carries only a tiny marked patch.
The public API never touches `crypto/tls` internals, so it stays stable while
the inner layer is re-synced underneath it.

## How a ClientHello is rendered

1. The public `UClient(conn, cfg, id)` resolves `id` to a fresh
   `ClientHelloSpec` and builds an internal `UConn`, converting the standard
   `*tls.Config` once via `fromStdConfig`.
2. The handshake runs the stock `crypto/tls` client path. In `makeClientHello`,
   a `[uTLS]` hook calls `UConn.buildClientHello`:
   - each extension's `writeToHello` populates the logical `clientHelloMsg`
     (versions, groups, ALPN, SNI, generated key shares) so the stock state
     machine stays consistent;
   - the renderer serialises the spec's cipher suites, compression methods and
     ordered extensions into the exact wire bytes (two passes, so a padding
     extension can target a length), substituting GREASE;
   - the bytes are stored in `clientHelloMsg.original`.
3. `clientHelloMsg.marshal()` (a `[uTLS]` hunk) returns `original` when set, so
   the wire bytes and the handshake transcript are the rendered bytes.
4. A `ClientHello` hook, if installed, runs last and may rewrite `Random` /
   `SessionID` in place and read the ephemeral key-share private keys.
5. The rest of the handshake is stock `crypto/tls`. A second `[uTLS]` hunk in
   `establishHandshakeKeys` selects the private key for whichever group the
   server chose (specs offer several key shares) and exposes the server key
   share and ServerHello for schemes like REALITY.

## The [uTLS] patch

Six files carry marked hunks (see `upstream/PATCHES.md` for the text):

| File | Hunk | Why it must live in upstream code |
|------|------|-----------------------------------|
| `conn.go` | `uconn *UConn` field on `Conn` | the handshake needs a back-reference to the spec |
| `handshake_messages.go` | `marshal()` returns `original` | makes the rendered bytes the bytes sent + transcribed |
| `handshake_client.go` | render from spec in `makeClientHello` | the injection point |
| `handshake_client.go` | nil-cache guard in `saveSessionTicket` | a spec advertises session_ticket even without a cache |
| `handshake_client_tls13.go` | key-share fallback + expose server share | specs offer multiple key shares |
| `handshake_server_test.go` | drop a std-internal RNG override (test only) | the override is unimportable |

Everything else uTLS adds is in `u_*.go` files, which the sync never touches.

## The conversion boundary

`crypto/tls.Config` and `internal/tls.Config` are field-identical (the mirror is
a copy of the same Go release), but they are distinct Go types, so a value of one
cannot be assigned to the other. `config.go` converts field by field at the
single boundary. `config_fields_test.go` uses reflection to guarantee the
converter considers every field and that the mirror never drifts from stdlib's
field set — turning a future silent breakage into a failing test.

`CurveID` and `SignatureScheme` are exposed as the uTLS types (so specs compose
without importing `internal`), while `ConnectionState` is exposed as the
standard `crypto/tls.ConnectionState` (so net/http and friends consume it
directly). Converting between the uTLS and stdlib `CurveID` is an ordinary
`uint16` conversion.

## Net/http interoperability

`UConn` implements the implicit interface net/http uses to discover TLS state
(`ConnectionState() tls.ConnectionState` + `HandshakeContext(context.Context)`),
and returns the standard `ConnectionState`. That is why `Transport` can hand an
h2 connection to `x/net/http2` and an h1 connection to `net/http` without any
forked HTTP stack — the thing most downstream projects had to build.

Known gap: `ExportKeyingMaterial` on the returned `ConnectionState` does not work
(the exporter is in an unexported stdlib field that cannot cross the type
boundary). Use `(*utls.UConn)` for keying material instead.
