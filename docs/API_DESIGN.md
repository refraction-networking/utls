# API design rationale

The v2 public API is derived from [USAGE_SURVEY.md](USAGE_SURVEY.md). This
document records the decisions and the reasoning, so future changes stay
faithful to the goals: **maintainability across Go releases** and **not breaking
downstream**.

## Principles

1. **Speak the standard types.** The public API takes `*crypto/tls.Config` and
   returns `crypto/tls.ConnectionState`. The #1 friction in v1 was a parallel
   `utls.Config`/`utls.ConnectionState` that every consumer had to convert,
   whitelist by reflection, or fork net/http around. v2 converts once, at a
   single boundary, guarded by a reflection test.

2. **The fingerprint is a value, resolved by name.** `ClientHelloID` +
   `ParseFingerprint` replace the drifting name tables every project wrote.
   `Spec()` returns a fresh `ClientHelloSpec` per call so nothing is shared
   between connections.

3. **Intents, not internals.** Downstream wanted to *do* things (authenticate in
   session_id, pick h2 vs h1, verify a pinned cert, replay a captured hello).
   v2 exposes those as `ClientHelloContext`, `Transport`, the standard verify
   callbacks, and `ParseClientHello` — not as raw `HandshakeState` structs.

4. **Additive evolution.** The `TLSExtension` interface has unexported methods,
   so uTLS can add extension kinds (which must wire into the handshake) without
   breaking downstream, which composes the provided types and uses
   `GenericExtension` for the rest. This is the specific mistake v1 made that
   caused churn.

5. **Confine volatility.** Nothing in the public API references `crypto/tls`
   internals. All such coupling is in `internal/tls`, regenerated per Go release.

## Decisions and trade-offs

**`CurveID`/`SignatureScheme` are uTLS types; `ConnectionState` is the stdlib
type.** A spec is built from extension types whose fields use the uTLS
`CurveID`, so exposing the uTLS type there lets specs compose without importing
`internal`. `ConnectionState` is consumed by net/http, so it must be the stdlib
type. The seam is a `uint16` conversion. We accepted this small asymmetry
because it removes two larger frictions at once.

**`ClientSessionCache` from the stdlib config is not carried across.** Bridging
`crypto/tls.ClientSessionState` to the internal one cannot be done losslessly
(the session encoding is explicitly opaque and version-dependent). Rather than
ship something subtly wrong, v2 marks it unsupported-from-std in the reflection
test and will expose resumption through a uTLS-native option. Most fingerprinting
downstreams do not resume.

**`ExportKeyingMaterial` on the returned `ConnectionState` does not work.** The
exporter lives in an unexported stdlib field. We document it and provide the
method on `UConn`. Silently returning a broken EKM (as some forks did via unsafe
field copies) is worse than a documented, typed alternative.

**Server-side config fields are not converted.** uTLS v2's public API is a
client. Server-side callbacks (`GetCertificate`, `GetConfigForClient`,
session wrapping, server ECH keys) are marked unsupported in the reflection
test. A uTLS "server" in the wild is almost always a probe-resistant front
(REALITY/Restls/JLS) built on the *raw ClientHello parser* plus a stock
`crypto/tls` server — which `ParseClientHello` supports — not on a parallel
server Config.

**Byte-exact parroting is a `parrots.go` concern, not an API concern.** The API
renders whatever spec it is given, exactly. How close a preset is to a specific
browser build is a data question isolated to `parrots.go` and
[FINGERPRINTS.md](FINGERPRINTS.md), so fidelity work never touches the engine or
the sync machinery.

## Mapping survey intents to API

| Intent (survey rank) | API |
|---|---|
| 1 name→fingerprint | `ParseFingerprint`, `Fingerprints`, `ClientHelloID`, aliases |
| 2 dial + handshake-first | `Dial`, `DialContext`, `UClient`+`Handshake` |
| 3 crypto/tls interop | `fromStdConfig`/`toStdConnectionState`, `ConnectionState`, `Transport` |
| 4 verify ≠ SNI | standard config fields; `SNIExtension{}`/omit; `VerifyConnection` |
| 5 write into hello + ephemeral key | `ClientHelloContext` (Random/SessionID/EphemeralKey) |
| 6 custom server auth | `UConn.ServerKeyShareGroup/Data`, `ServerHelloRaw`, `EphemeralKey` |
| 7 spec from data | `ParseClientHello`, `ClientHelloSpec`, randomized presets |
| 8 per-connection freshness | `Spec()` fresh each call; renderer GREASE/keys |
| 9 h2/h1 RoundTripper | `Transport` |
| 10 multiple key shares / PQ | renderer + establishHandshakeKeys hunk |

## Not yet (deliberate, documented gaps)

These are real survey needs the architecture supports but which v2 does not yet
ship as first-class helpers. They are natural additions that fit the existing
shape without new `crypto/tls` coupling:

- JA3/JA4 *string* parsing (today: `ParseClientHello` from raw bytes).
- Out-of-band / forged session resumption (Psiphon, Lantern).
- ClientHello fragmentation hook (Psiphon fork, Lantern, samizdat).
- Post-handshake record-layer handoff for kTLS/Vision/Restls.
- ECH with a fingerprinted outer hello.
- A QUIC client surface mirroring the stdlib QUIC types (see the QUIC survey).

Each should be added as root-package API plus, if unavoidable, a marked `[uTLS]`
hunk documented in `upstream/PATCHES.md`.
