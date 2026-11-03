# API design rationale

The v2 public API is derived from [USAGE_SURVEY.md](USAGE_SURVEY.md). This
document records the decisions and the reasoning, so future changes stay
faithful to the goals: **maintainability across Go releases** and **not breaking
downstream**.

## Principles

1. **Speak the standard types.** The public API takes `*crypto/tls.Config` and
   returns `crypto/tls.ConnectionState`. The #1 friction in v1 was a parallel
   `utls.Config`/`utls.ConnectionState` that every consumer had to convert,
   whitelist by reflection, or fork HTTP stacks around. v2 converts once, at a
   single boundary, guarded by a reflection test.

2. **The fingerprint is a value, resolved by name.** `ClientHelloID` +
   `ParseFingerprint` replace the drifting name tables every project wrote.
   `Spec()` returns a fresh `ClientHelloSpec` per call so nothing is shared
   between connections.

3. **Intents, not internals.** Downstream wanted to *do* things (authenticate in
   session_id, pick h2 vs h1, verify a pinned cert, replay a captured hello).
   v2 exposes those as `ClientHelloContext`, `Dialer`, the standard verify
   callbacks, and `ParseClientHello` — not as raw `HandshakeState` structs.

4. **Additive evolution.** The `TLSExtension` interface has unexported methods,
   so uTLS can add extension kinds (which must wire into the handshake) without
   breaking downstream, which composes the provided types and uses
   `GenericExtension` for the rest. This is the specific mistake v1 made that
   caused churn.

5. **Confine volatility.** Nothing in the public API references `crypto/tls`
   internals. All such coupling is in `internal/tls`, regenerated per Go release.

## Decisions and trade-offs

**Module path `github.com/refraction-networking/utls/v2`.** The API removes or
changes most v1 identifiers (docs/REMOVALS.md), so semantic import versioning
requires a new major path; v1 users are not broken by `go get -u`, and both can
coexist in one build during migration. `api/v2.txt` plus `api_test.go` gate
every later change: removals/changes fail CI, additions are recorded.

**`CurveID`/`SignatureScheme` are uTLS types; `ConnectionState` is the stdlib
type.** Specs compose from extension types whose fields use the uTLS `CurveID`
without importing `internal`; `ConnectionState` is consumed by net/http, so it
must be the stdlib type. The seam is a `uint16` conversion.

**Sessions speak the stdlib types.** A stdlib `ClientSessionCache` in the Config
works unchanged (bridged through `ResumptionState`/`SessionState.Bytes`, the
same encoding as the mirrored release). `SetSession(*tls.ClientSessionState)`
injects a session explicitly. Forged/out-of-band sessions without certificates
cannot be expressed as a `*tls.ClientSessionState` (crypto/tls refuses to
parse a client session without certificates), so they have a native path:
`SetSessionParams(ClientSessionParams)`.

**`ExportKeyingMaterial` works on the returned `ConnectionState`, and
`CertificateRequestInfo.Context()` is the handshake context.** Both sit in
unexported stdlib fields; `internal/tls/u_stdcompat.go` is the single place that
sets them, validated at start-up. If a future Go changes those fields, uTLS
fails explicitly (`ErrExporterUnavailable`; GetClientCertificate configs refused
before I/O) instead of panicking or passing a nil context.

**Server-side config fields are not converted.** uTLS v2 is a client.
Server behaviour belongs to the corresponding server implementation: the
standard library's crypto/tls for ordinary TLS servers, and the protocol's own
server for schemes whose server deviates from standard TLS. REALITY is such a
scheme: its server sends a deliberately modified Ed25519 certificate (the
signature field carries an HMAC) and always signs CertificateVerify with
Ed25519, which stock crypto/tls does not do. uTLS's REALITY coverage is
therefore against the real pinned XTLS/REALITY server in `interop/reality`.
(The ShadowTLS-style fixture in downstream_test.go only checks the client's
session-ID authenticator with a peeking test server.)

**No silent fallbacks.** An unusable fingerprint (zero `ClientHelloID`,
`HelloCustom` without `ApplyPreset`, a failing factory, an invalid spec) fails
the handshake before any byte is written. Configuration methods
(`ApplyPreset`, `SetClientHelloHook`, `SetSession*`, `SetFragmentation`) return
an error once the handshake started. Spec getters return copies.

**Byte-exact parroting is data, not engine.** The engine renders whatever spec
it is given; fidelity is a property of `parrots.go`, proven only against real
captures (docs/FINGERPRINTS.md).

## Capabilities beyond the handshake

**ClientHello hook.** Runs once on the final first ClientHello (after session
load, before binders): `Random`/`SessionID` writable in place, `Raw` for MACs,
`EphemeralKey(group)` for ECDH-derived authenticators. Binders are recomputed
afterwards; changing anything else is an error; combining with ECH is refused
(`ErrHookWithECH`) because the hook would see bytes that are never sent.

**Fragmentation** (`SetFragmentation`, `Dialer.Fragmentation`).
Splits only the first ClientHello into TLS records and/or separate writes,
optionally in the middle of the SNI host name; fails before writing if asked to
split at an SNI that is not there. Implemented under the record lock (no
`net.Conn` swapping).

**Record-layer handoff** (`HandOff`). For a completed TLS 1.3 connection,
returns keys, IVs, traffic secrets, sequence numbers, decrypted-but-unread
plaintext, undecrypted input and the transport; afterwards Read/Write fail with
`ErrHandedOff` and Close sends no alert under stale state. Enough for kTLS,
Vision-style splicing or a custom record layer. TLS 1.2 is refused (its keys
are not retained).

**QUIC** (`QUICClient`). The same event-driven API as `tls.QUICClient`, with
standard `tls.QUICConfig`/`QUICEvent`/`QUICEncryptionLevel`/`SessionState`.
Edits to `SessionState.EarlyData/Extra` in resume/store events reach the
handshake. Browser QUIC hellos differ from TCP ones: supply a QUIC spec with a
`QUICTransportParametersExtension` slot.

**Profiles** (`ExportProfile`, `ParseProfile`, `Profile.ClientHelloID`).
Versioned JSON (`"format": "utls-profile", "version": 1`), strict: unknown
versions, fields or extension types are errors; the result must `Validate`.
`testdata/profiles/*.json` are the format's golden files.

**Randomization.** `HelloRandomized*` and `SeededRandomized(seed, weights)`
(replayable: same seed and weights, same spec).

**JA3/JA4.** Computed from raw hellos; `SpecFromJA3` only when the JA3 string
plus explicit options determine every extension body (otherwise an error that
names what is missing). There is no JA4-to-spec: JA4 is a hash.

## Scope: no HTTP

uTLS is a TLS library. An earlier draft of v2 included an `http.RoundTripper`
(`Transport`); it was removed before the first v2 release. HTTP behaviour —
pooling, proxy routing, retries, HTTP/2 SETTINGS and ACKs, HTTP-level browser
fingerprints — belongs to the caller's HTTP stack, which receives a uTLS
connection through a dial function. uTLS returns the negotiated ALPN protocol
and the peer's ALPS settings as opaque bytes and does not interpret HTTP/2
frames. The survey's HTTP intents (rank 9) are historical evidence of how
consumers integrate, not a requirement for uTLS to own HTTP.

## Mapping survey intents to API

| Intent (survey rank) | API |
|---|---|
| 1 name→fingerprint | `ParseFingerprint`, `Fingerprints`, `ClientHelloID`, aliases |
| 2 dial + handshake-first | `Dial`, `DialContext`, `Dialer`, `UClient`+`Handshake` |
| 3 crypto/tls interop | std `Config`/`ConnectionState`/sessions/errors |
| 4 verify ≠ SNI | standard config fields; `SNIExtension{}`/omit; `VerifyConnection` |
| 5 write into hello + ephemeral key | `SetClientHelloHook`, `ClientHelloContext` |
| 6 custom server auth | `ServerKeyShareGroup/Data`, `ServerHelloRaw`, `EphemeralKey` |
| 7 spec from data | `ParseClientHello`, `ParseProfile`, `SpecFromJA3`, `SeededRandomized` |
| 8 per-connection freshness | `Spec()` fresh each call; renderer GREASE/keys |
| 9 h2/h1 RoundTripper | out of scope: uTLS is a TLS library (see below) |
| 10 multiple key shares / PQ | renderer + establishHandshakeKeys hunk |
| 11 forged resumption, fragmentation, handoff, ECH, QUIC | `SetSessionParams`, `SetFragmentation`, `HandOff`, std ECH config fields, `QUICClient` |

Additions follow the same rule: root-package API, plus — only if unavoidable —
a marked `[uTLS]` hunk documented in `upstream/PATCHES.md`, and an
`api/v2.txt` update.
