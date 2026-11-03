# uTLS

uTLS is a drop-in TLS **client** for Go that lets you control the exact bytes of
the ClientHello — to mimic a browser's TLS fingerprint — while speaking the
standard library everywhere else.

```go
import (
    "crypto/tls"
    utls "github.com/refraction-networking/utls/v2"
)

// Dial with a Chrome fingerprint:
conn, err := utls.Dial("tcp", "example.com:443",
    &tls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)

// Or make HTTPS requests that look like a browser (ALPN picks h2/h1):
client := &http.Client{Transport: &utls.Transport{ClientHelloID: utls.HelloChrome_Auto}}
resp, err := client.Get("https://example.com/")
```

The connection you get back returns the standard `crypto/tls.ConnectionState`
and satisfies the interface `net/http` uses to discover TLS state, so it plugs
into `net/http`, `golang.org/x/net/http2`, and the rest of the ecosystem without
any wrapper or forked HTTP stack.

> **This is uTLS v2** (module `github.com/refraction-networking/utls/v2`), a
> redesign. v1 users: see [docs/MIGRATION.md](docs/MIGRATION.md) and
> [docs/REMOVALS.md](docs/REMOVALS.md).

## Why v2 exists

uTLS is a fork of `crypto/tls`. v1 hand-patched thousands of lines across the
whole package, so every Go release broke it, and it exposed deep handshake
internals as its API, so downstream projects accumulated reflection hacks,
type-conversion glue, and forked HTTP stacks to work around it.

v2 fixes both problems:

- **Maintainability.** All coupling to `crypto/tls` lives in one internal
  package that is *generated* from a pinned Go release by a portable Go sync
  tool, carrying ~100 lines of marked patch ([upstream/PATCHES.md](upstream/PATCHES.md)). Following a new Go release is a scripted
  re-sync, not a hand-port. The full upstream `crypto/tls` test suite runs
  against the mirror to prove behaviour is intact.
- **A stable, intent-shaped public API**, designed from a survey of how ~30 real
  projects (Xray/REALITY, sing-box, mihomo, Psiphon, Tor, OONI, tls-client,
  CycleTLS, and more) actually use uTLS. See [docs/USAGE_SURVEY.md](docs/USAGE_SURVEY.md).

## Features

- **Browser fingerprints checked against real captures:** Chrome 156/155,
  Firefox 158, Safari 27 (`testdata/*.md` has the provenance), plus Edge, iOS,
  Android OkHttp, QQ, Firefox 148 and `HelloGolang`. Resolve by name with
  `ParseFingerprint`. See [docs/FINGERPRINTS.md](docs/FINGERPRINTS.md).
- **Randomized fingerprints:** `HelloRandomized{,ALPN,NoALPN}`, and replayable
  `SeededRandomized(seed, weights)`.
- **Custom fingerprints as code or data:** build a `ClientHelloSpec`, register
  it with `CustomFingerprint`, or ship it as a versioned JSON `Profile`.
- **Parse and measure:** `ParseClientHello(raw)` → a dialable spec; `JA3`,
  `JA4`, `SpecFromJA3`.
- **Negotiated, not just offered:** certificate compression (zlib, brotli,
  zstd), ALPS (old and new codepoints), record_size_limit, hybrid
  post-quantum and multiple key shares, ECH (real and GREASE), PSK resumption
  and HelloRetryRequest all work with the fingerprint.
- **ClientHello hook:** rewrite `Random`/`SessionID` over the final bytes with
  access to the ephemeral keys (REALITY, ShadowTLS, passthrough).
- **Circumvention helpers:** ClientHello fragmentation (records/writes, split at
  SNI), forged sessions (`SetSessionParams`), TLS 1.3 record-layer `HandOff`
  (kTLS, Vision, custom record layers).
- **QUIC:** `QUICClient` with the standard `crypto/tls` QUIC types.
- **Standard types throughout:** `*crypto/tls.Config` (verification, roots,
  client certificates, session caches, key logging, ECH), standard
  `ConnectionState` (with a working `ExportKeyingMaterial`), crypto/tls error
  types; `Transport` uses net/http's own HTTP/2.

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
- [docs/REMOVALS.md](docs/REMOVALS.md) — every removed v1 identifier and its replacement.
- [docs/RELEASING.md](docs/RELEASING.md) — release gates.

## Status and scope

v2 is a client library. Server-side TLS stays with `crypto/tls`.

**Go version:** the mirror is crypto/tls from the release in `upstream/VERSION`
(currently go1.27.3, which includes the ECH security fix), and `go.mod` requires
it as the minimum. CI also tests the newest stable Go.

**Stability:** the exported API is recorded in `api/v2.txt` and gated in CI;
removals or changes require a new major version.

Security issues: see [SECURITY.md](SECURITY.md). Contributing:
[CONTRIBUTING.md](CONTRIBUTING.md) and [CONTRIBUTORS_GUIDE.md](CONTRIBUTORS_GUIDE.md).

## License

BSD-style, inherited from Go's `crypto/tls`. See [LICENSE](LICENSE).
