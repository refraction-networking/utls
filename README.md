# uTLS

uTLS is a drop-in TLS **client** for Go that lets you control the exact bytes of
the ClientHello — to mimic a browser's TLS fingerprint — while speaking the
standard library everywhere else.

```go
import (
    "crypto/tls"
    utls "github.com/refraction-networking/utls"
)

// Dial with a Chrome fingerprint:
conn, err := utls.Dial("tcp", "example.com:443",
    &tls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)

// Or make HTTPS requests that look like a browser (ALPN picks h2/h1):
rt := &utls.Transport{ClientHelloID: utls.HelloChrome_Auto}
resp, err := rt.RoundTrip(req)
```

The connection you get back returns the standard `crypto/tls.ConnectionState`
and satisfies the interface `net/http` uses to discover TLS state, so it plugs
into `net/http`, `golang.org/x/net/http2`, and the rest of the ecosystem without
any wrapper or forked HTTP stack.

> **This is uTLS v2**, a ground-up redesign. If you are coming from v1, see
> [docs/MIGRATION.md](docs/MIGRATION.md).

## Why v2 exists

uTLS is a fork of `crypto/tls`. v1 hand-patched thousands of lines across the
whole package, so every Go release broke it, and it exposed deep handshake
internals as its API, so downstream projects accumulated reflection hacks,
type-conversion glue, and forked HTTP stacks to work around it.

v2 fixes both problems:

- **Maintainability.** All coupling to `crypto/tls` lives in one internal
  package that is *generated* from a pinned Go release by a sync script, carrying
  only ~140 lines of marked patch. Following a new Go release is a scripted
  re-sync, not a hand-port. The full upstream `crypto/tls` test suite runs
  against the mirror to prove behaviour is intact.
- **A stable, intent-shaped public API**, designed from a survey of how ~30 real
  projects (Xray/REALITY, sing-box, mihomo, Psiphon, Tor, OONI, tls-client,
  CycleTLS, and more) actually use uTLS. See [docs/USAGE_SURVEY.md](docs/USAGE_SURVEY.md).

## Features

- **Browser fingerprints:** `HelloChrome_Auto`, `HelloFirefox_Auto`,
  `HelloSafari_Auto`, `HelloEdge_Auto`, `HelloIOS_Auto`, and `HelloGolang` (the
  standard hello). Resolve by name with `ParseFingerprint` (accepts aliases and
  the `""`→Chrome, `golang`/`none`→stdlib conventions).
- **Randomized fingerprints:** `HelloRandomized{,ALPN,NoALPN}` — always
  negotiable, good against blocklists.
- **Custom fingerprints:** build a `ClientHelloSpec` from the re-exported
  extension types, or register one with `CustomFingerprint`.
- **Parse captured hellos:** `ParseClientHello(raw)` → a dialable spec.
- **ClientHello hook:** rewrite `Random`/`SessionID` and read the ephemeral
  key-share private key — everything REALITY, ShadowTLS, and similar need.
- **Standard config:** pass your `*crypto/tls.Config`; verification, roots,
  client certs, ALPN, key logging, min/max version all work.

## Quickstart: custom fingerprint

```go
spec := &utls.ClientHelloSpec{
    CipherSuites: []uint16{utls.GREASE_PLACEHOLDER, utls.TLS_AES_128_GCM_SHA256 /* ... */},
    CompressionMethods: []uint8{0},
    Extensions: []utls.TLSExtension{
        &utls.UtlsGREASEExtension{},
        &utls.SNIExtension{},
        &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
        &utls.KeyShareExtension{KeyShares: []utls.KeyShareEntry{{Group: utls.X25519}}},
        // ... in the order your target sends them ...
    },
}
uc := utls.UClient(conn, &tls.Config{ServerName: host}, utls.HelloCustom)
uc.ApplyPreset(spec)
err := uc.Handshake()
```

## Documentation

- [AGENTS.md](AGENTS.md) — maintainer's manual (for AI agents and humans).
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the two-layer design.
- [docs/UPSTREAM_SYNC.md](docs/UPSTREAM_SYNC.md) — following a new Go release.
- [docs/FINGERPRINTS.md](docs/FINGERPRINTS.md) — adding/updating fingerprints.
- [docs/API_DESIGN.md](docs/API_DESIGN.md) — why the API looks the way it does.
- [docs/USAGE_SURVEY.md](docs/USAGE_SURVEY.md) — the downstream survey.
- [docs/MIGRATION.md](docs/MIGRATION.md) — v1 → v2.

## Status and scope

v2 is a client library. It handshakes against standard servers over TLS 1.2 and
1.3 with GREASE, hybrid post-quantum key shares, ALPN, certificate compression,
and multiple key shares. Out-of-band resumption, ClientHello fragmentation,
kTLS/record-layer handoff, ECH, and a QUIC surface are not yet ported — see
[docs/API_DESIGN.md](docs/API_DESIGN.md). Contributions welcome.

**Minimum Go version:** see `go.mod`. uTLS pins a specific Go release for its
mirror (`upstream/VERSION`).

## License

BSD-style, inherited from Go's `crypto/tls`. See [LICENSE](LICENSE).
