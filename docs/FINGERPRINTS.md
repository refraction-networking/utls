# Adding and updating fingerprints

A fingerprint is a function that returns a fresh `ClientHelloSpec`, registered
under a name. Everything lives in the root package; you do not touch
`internal/tls` unless you need an extension type that does not exist yet.

## Add a preset

In `parrots.go`:

```go
var HelloChrome_150 = register(
    ClientHelloID{Client: "Chrome", Version: "150", specFactory: chrome150Spec},
    "chrome-150", // optional extra aliases
)

func chrome150Spec() (*ClientHelloSpec, error) {
    return &ClientHelloSpec{
        CipherSuites: []uint16{
            GREASE_PLACEHOLDER,
            TLS_AES_128_GCM_SHA256,
            // ...
        },
        CompressionMethods: []uint8{0},
        Extensions: []TLSExtension{
            &UtlsGREASEExtension{},
            &SNIExtension{},            // empty: uses the dial's ServerName
            &SupportedCurvesExtension{Curves: []CurveID{GREASE_PLACEHOLDER, X25519MLKEM768, X25519}},
            // ... in the exact order the browser sends them ...
            &KeyShareExtension{KeyShares: []KeyShareEntry{
                {Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
                {Group: X25519MLKEM768},  // empty Data => fresh key generated per connection
                {Group: X25519},
            }},
            &SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
            &UtlsGREASEExtension{Body: []byte{0}},
            &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
        },
    }, nil
}
```

Rules that keep it correct:

- **The factory must return a fresh spec every call.** Never share extension
  pointers between specs or connections; extensions hold per-connection state
  (GREASE values, padding length). `ClientHelloID.Spec()` relies on this.
- **Order is the fingerprint.** Emit extensions in the exact order the target
  sends them. GREASE goes where the browser puts it (usually first, with a
  second GREASE near the end for Chromium).
- **Leave key_share `Data` empty** for groups you want a real, fresh key for.
  Supply `Data` only for a GREASE share (one `0x00` byte) or when you
  deliberately want fixed bytes (the server must then not select that group).
- **`SNIExtension{}` with an empty name** takes the connection's `ServerName`.
  Omit the extension entirely to omit SNI.
- Register aliases users are likely to type; `ParseFingerprint` already handles
  `""`→Chrome and `golang`/`none`→stdlib.

Then add a line to the interop test matrix in `utls_test.go` so CI proves your
preset handshakes against a standard server.

## Need an extension that doesn't exist?

Add the type in `internal/tls/u_extensions.go`, implementing `TLSExtension`
(`ID`, `marshal`, `writeToHello`), then re-export it with an alias in `spec.go`.
Use `GenericExtension{Id, Data}` first if a verbatim body is enough; only add a
typed extension when it must influence the handshake (key material, ALPN,
versions, groups) or be introspectable.

## Fidelity: how exact is a parrot?

The presets here reproduce the **structure** of a browser hello — the extension
set and order, GREASE placement, the hybrid + classical key share, cipher list
shape, padding. That defeats structural fingerprinting and is what most uses
need.

Byte-for-byte equality with a specific browser build (so a JA3/JA4 hash matches
exactly) additionally requires the browser's precise cipher and extension
values for that version, and BoringSSL's exact GREASE derivation (uTLS currently
draws valid GREASE values per connection, which is what the browser does, but
not from the same seed algorithm). If you need an exact hash match:

1. Capture a real ClientHello from the target build.
2. Feed it to `utls.ParseClientHello` to get a spec skeleton.
3. Hand-reconcile the cipher/extension values against the capture.
4. Add a golden test asserting the rendered bytes equal the capture (modulo the
   per-connection random, session_id and key-share bytes).

Keeping parrots current is the ongoing maintenance cost; it is intentionally
isolated to `parrots.go` so it never entangles the sync machinery.

## Randomized fingerprints

`randomized.go` generates valid, always-negotiable hellos (always TLS 1.3 with
X25519). Prefer these when you do not need to look like one specific browser —
they defeat blocklists without a parrot-is-dead risk.
