# Migrating from uTLS v1

v2 is a ground-up redesign of the public API. This maps common v1 patterns to
v2. The guiding change: **v2 speaks `crypto/tls` types**, so most of the glue
code v1 required disappears.

## Dialing

```go
// v1
uConn := tls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
err := uConn.Handshake()

// v2 — standard *crypto/tls.Config
uConn := utls.UClient(tcpConn, &tls.Config{ServerName: host}, utls.HelloChrome_Auto)
err := uConn.Handshake()

// v2 — or dial + handshake in one call
uConn, err := utls.Dial("tcp", host+":443", &tls.Config{ServerName: host}, utls.HelloChrome_Auto)
```

## Config and ConnectionState

| v1 | v2 |
|---|---|
| `utls.Config{...}` (a copy of tls.Config) | `*crypto/tls.Config` directly |
| `uConn.ConnectionState()` → `utls.ConnectionState` | → `crypto/tls.ConnectionState` (no conversion needed) |
| hand-copying fields into `utls.Config` | nothing — pass your `*tls.Config` |
| reflection whitelist of supported fields | the converter documents support; a reflection test guards it |

If you forked net/http (fhttp, oohttp, …) only to carry uTLS's
`ConnectionState`, you no longer need to: a `utls.UConn` returns the standard
type and satisfies net/http's TLS interface. For HTTP, use `utls.Transport`.

## Fingerprint selection

```go
// v1: hand-written name table mapping to Hello* vars
// v2:
id, err := utls.ParseFingerprint(userSuppliedName) // "", "chrome", "firefox", "golang", ...
uConn := utls.UClient(conn, cfg, id)
names := utls.Fingerprints()
```

## Custom fingerprints

```go
// v1
uConn := tls.UClient(conn, cfg, utls.HelloCustom)
uConn.ApplyPreset(spec)

// v2 — same shape; spec is built from the re-exported extension types
uConn := utls.UClient(conn, cfg, utls.HelloCustom)
uConn.ApplyPreset(spec)

// or register a reusable fingerprint from a spec factory
id := utls.CustomFingerprint("my-app", func() (*utls.ClientHelloSpec, error) { return buildSpec(), nil })
```

`ClientHelloSpec` and all extension types are re-exported from the root package,
so existing spec-building code mostly compiles after changing the import.

## Writing into the ClientHello (REALITY / ShadowTLS / passthrough)

v1 required `BuildHandshakeState` → mutate `HandshakeState.Hello.{Raw,SessionId,
Random}` → `MarshalClientHello`, often with hard-coded `Raw[39:]` offsets and
reflect/unsafe for the key share. v2 gives you a hook:

```go
uConn.SetClientHelloHook(func(h *utls.ClientHelloContext) error {
    // h.Raw is the full ClientHello; h.Random and h.SessionID alias into it.
    ecdhe := h.EphemeralKey(utls.X25519MLKEM768) // classical half of the hybrid
    authValue := deriveREALITYSessionID(ecdhe, serverStaticKey, h.Raw)
    copy(h.SessionID, authValue)
    return nil
})
```

For the server-verification side, after the handshake read
`uConn.ServerKeyShareGroup()`, `uConn.ServerKeyShareData()`, and
`uConn.ServerHelloRaw()` (or do it inside `Config.VerifyConnection`).

## Parsing a captured ClientHello

```go
// v1: Fingerprinter{}.FingerprintClientHello(raw)
// v2:
spec, err := utls.ParseClientHello(raw) // record or handshake-message bytes
// or utls.Fingerprinter{}.FingerprintClientHello(raw)
```

## Things that moved or went away

- `utls.Config`/`utls.ConnectionState` → use the `crypto/tls` types.
- Public `HandshakeState`, `PubClientHelloMsg`, `PubServerHelloMsg`,
  `State12`/`State13`, `BuildHandshakeState`, `MarshalClientHello` → replaced by
  the ClientHello hook and `UConn` accessors.
- `SetSNI`/`RemoveSNIExtension` → `SNIExtension{}` uses `ServerName`; omit the
  extension to drop SNI.
- `EnableWeakCiphers` (global) → put the cipher in your spec.
- `Roller` → use `Transport` (fallback across fingerprints) or retry with
  different `ParseFingerprint` results.

## Not yet in v2

Out-of-band resumption, ClientHello fragmentation, kTLS/record-layer handoff,
ECH, and the QUIC surface are not yet ported (see
[API_DESIGN.md](API_DESIGN.md) "Not yet"). If you depend on these, pin v1 for
now or open an issue; the v2 hooks make them straightforward to add.
