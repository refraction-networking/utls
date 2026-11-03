# Fingerprints

A fingerprint is a function returning a fresh `ClientHelloSpec`, registered
under a name. Everything lives in the root package; you touch `internal/tls`
only for an extension type that does not exist yet.

## Presets and their provenance

| ID (`ParseFingerprint` names) | Evidence |
|---|---|
| `HelloChrome_156` = `HelloChrome_Auto` (`chrome`, `chromium`, `chrome156`) | 3 captures of Chrome 156.0.8078.80, `testdata/chrome156_clienthello.md` |
| `HelloChrome_155` (`chrome155`) | capture of Chrome 155.0.8059.40, `testdata/chrome155_clienthello.md` |
| `HelloEdge_Auto` (`edge`) | Chromium; uses the Chrome 155/156 spec (no Edge capture) |
| `HelloFirefox_158` = `HelloFirefox_Auto` (`firefox`, `firefox158`) | 2 captures of Firefox 158.0, `testdata/firefox158_clienthello.md` |
| `HelloFirefox_148` (`firefox148`) | ported from uTLS v1 (no capture bundled) |
| `HelloSafari_27` = `HelloSafari_Auto` (`safari`, `safari27`) | 3 captures of Safari 27.0.1, `testdata/safari27_clienthello.md` |
| `HelloSafari_26_3`, `HelloIOS_14`/`Auto`, `HelloAndroid_11_OkHttp`, `HelloQQ_11_1`/`Auto` | ported from uTLS v1 (no capture bundled) |
| `HelloRandomized{,ALPN,NoALPN}`, `SeededRandomized` | generated; always negotiable |
| `HelloGolang` (`golang`, `go`, `none`) | the stock crypto/tls ClientHello |

"360" is deliberately unsupported (`ParseFingerprint` explains why: NPN and
Channel ID cannot be negotiated). `HelloCustom` sends only what `ApplyPreset`
gives it and fails with `ErrNoSpec` otherwise — uTLS never silently sends a
different fingerprint.

`fidelity_test.go` compares each captured preset with its captures: cipher
suites, extension set (and order for Firefox/Safari, which do not permute),
every extension body, GREASE extension bodies, key-share groups and lengths,
GREASE ECH suite and payload length family, JA3/JA4. Only per-connection values
(randoms, keys, GREASE codepoints, Chrome's extension permutation, GREASE ECH
bytes) may differ.

## Capturing a browser (the only acceptable evidence)

Never write a capture by hand or "update" one from documentation. Record one:

```
interop/capture/capture-browsers.sh OUTDIR     # Chrome and Firefox, headless
```

It builds `interop/capture` (a loopback listener that saves the first TLS
record of each connection and closes it), and runs each installed browser
headless with a brand-new temporary profile against
`https://utls-capture.test:<port>/`, mapped to 127.0.0.1. For Safari, open a
private window by hand to `https://localhost:<port>/` while `go run
./interop/capture PORT PREFIX` listens. Never use or modify a real profile, and
never point a capture browser at other sites.

Then:

1. Copy the `.hex` files to `testdata/<browser><version>_clienthello*.hex` and
   write a `.md` next to them: exact browser version (from `--version`), OS,
   date, command line / procedure, SHA-256 of each file and of the handshake.
2. Parse a capture as a starting point: `spec, _ := utls.ParseClientHello(raw)`.
   Hand-write the preset in `parrots.go` from it (named extension types, not
   `GenericExtension`, wherever a type exists; `SNIExtension{}` with an empty
   name; empty key-share `Data`). If the new capture is identical to the
   previous version's spec, reuse the spec and say so in the provenance header.
3. Add a test in `fidelity_test.go` (use `compareChromeCapture` for
   Chromium-family; the Safari/Firefox tests for fixed-order browsers) and add
   the preset to `allPresets()` in `utls_test.go` so it is interop-tested.
4. Update the table above and the provenance header of `parrots.go`.

## Writing a spec

```go
var HelloChrome_157 = register(preset("Chrome", "157", chrome157Spec), "chrome157")

func chrome157Spec() (*ClientHelloSpec, error) {
    return &ClientHelloSpec{
        CipherSuites:       []uint16{GREASE_PLACEHOLDER, TLS_AES_128_GCM_SHA256 /* ... */},
        CompressionMethods: []uint8{0},
        Extensions: shuffleChromeExtensions([]TLSExtension{
            &UtlsGREASEExtension{},
            &SNIExtension{},
            &SupportedCurvesExtension{Curves: []CurveID{GREASE_PLACEHOLDER, X25519MLKEM768, X25519}},
            &KeyShareExtension{KeyShares: []KeyShareEntry{
                {Group: GREASE_PLACEHOLDER, Data: []byte{0}},
                {Group: X25519MLKEM768}, // empty Data: fresh key per connection
                {Group: X25519},
            }},
            // ... in the browser's order ...
            &UtlsGREASEExtension{Body: []byte{0}}, // BoringSSL: 1-byte body on the second
        }),
    }, nil
}
```

Rules:

- **Fresh spec per call.** Never share extension objects between specs.
- **Order is the fingerprint** (unless the browser permutes; then use
  `shuffleChromeExtensions`, which keeps GREASE, padding and pre_shared_key in
  place). GREASE values are chosen per connection, BoringSSL-style (one value
  per slot; the key-share GREASE equals the supported-groups GREASE).
- **Key shares**: empty `Data` for real groups. `ReuseClassicalFromHybrid` only
  if the capture shows the X25519 share equal to the hybrid's X25519 half
  (Firefox does; Chrome does not).
- **Padding**: `UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}` only
  if the browser pads.
- A spec can be shipped as data: `ExportProfile(id)` / `ParseProfile(json)`
  (docs/API_DESIGN.md "Profiles"). `testdata/profiles/*.json` are golden files
  for the format.

## A new extension type

Add it in `internal/tls/u_extensions.go` (`ID`, `clone`, `apply`, `render`),
re-export it in `spec.go`, map it in `fingerprinter.go` (`ParseClientHello`) and
`profile.go` (`profileTypes`), and record the API addition
(`go test -run TestAPICompatibility -update-api .`). Use `GenericExtension` when
a verbatim body is enough; `Validate` refuses Generic for extensions that must
influence the handshake.

## JA3 / JA4

`JA3` and `JA4` compute the standard fingerprints of a raw ClientHello.
`SpecFromJA3` builds a spec only when every listed extension's body can be
derived from the JA3 fields plus explicit `JA3SpecOptions`; otherwise it
returns an error naming the missing information (JA3 omits extension bodies
such as ALPS settings or trust anchors). JA4 is a lossy hash and cannot be
turned into a spec.
