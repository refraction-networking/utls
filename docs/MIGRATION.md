# Migrating from uTLS v1

v2 is a redesign of the public API published as a new major version:

```go
import utls "github.com/refraction-networking/utls/v2"
```

v1 (`github.com/refraction-networking/utls`) keeps working; both can be in one
build while you migrate. The guiding change: **v2 speaks `crypto/tls` types**,
so most glue code disappears. `docs/REMOVALS.md` lists every removed v1
identifier with its replacement. `downstream_test.go` contains runnable
migrations of Xray REALITY, sing-box (ShadowTLS v3, PQ opt-out, ALPN, ECH) and
Psiphon (seeded profiles, passthrough random, obfuscated session tickets,
fragmentation) — read them next to this page.

## Dialing

```go
// v1
uConn := utls.UClient(tcpConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
err := uConn.Handshake()

// v2 — standard *crypto/tls.Config
uConn := utls.UClient(tcpConn, &tls.Config{ServerName: host}, utls.HelloChrome_Auto)
err := uConn.Handshake()

// v2 — dial + handshake in one call (or utls.Dialer as a net.Dialer-like value)
uConn, err := utls.DialContext(ctx, "tcp", host+":443", &tls.Config{ServerName: host}, utls.HelloChrome_Auto)
```

Behaviour changes to know:

- An unusable fingerprint (zero `ClientHelloID`, `HelloCustom` without
  `ApplyPreset`, a failing factory) fails the handshake with nothing written.
  v1 silently fell back to the Go fingerprint in some of these cases.
- `ApplyPreset`, `SetClientHelloHook`, `SetSession*`, `SetFragmentation` return
  an error after the handshake has started.
- `Config.NextProtos`, when set, overrides the spec's ALPN list.

## Config, ConnectionState, sessions, errors

| v1 | v2 |
|---|---|
| `utls.Config{...}` | `*crypto/tls.Config` |
| `uConn.ConnectionState()` → `utls.ConnectionState` | → `crypto/tls.ConnectionState`, `ExportKeyingMaterial` works |
| `utls.ClientSessionCache` | any `crypto/tls.ClientSessionCache` |
| `uConn.SetSessionState(cs)` | `uConn.SetSession(*tls.ClientSessionState)` |
| `utls.MakeClientSessionState(ticket, vers, suite, secret, …)` (forged) | `uConn.SetSessionParams(utls.ClientSessionParams{…})` |
| `errors.As(err, *utls.ECHRejectionError)` etc. | the `crypto/tls` error types |

If you forked net/http (fhttp, oohttp, …) only to carry uTLS's
`ConnectionState`, drop the fork: `utls.UConn` satisfies net/http's TLS
interface, and `utls.Transport` is a ready `http.RoundTripper` (h2/h1 by ALPN,
per-route proxies, standard pooling).

## Fingerprint selection

```go
id, err := utls.ParseFingerprint(name) // "", "chrome", "firefox", "safari", "golang", ...
names := utls.Fingerprints()
```

Old versioned IDs (`HelloChrome_120`, `HelloFirefox_105`, …) were removed:
stale parrots are themselves a fingerprint. If you must keep one, export it from
v1 as a spec and load it as a v2 profile.

## Custom fingerprints

```go
uConn := utls.UClient(conn, cfg, utls.HelloCustom)
err := uConn.ApplyPreset(spec)

// reusable, by name
id := utls.CustomFingerprint("my-app", "1", func() (*utls.ClientHelloSpec, error) { return buildSpec(), nil })

// as data
p, err := utls.ParseProfile(jsonBytes) // versioned; see ExportProfile
id = p.ClientHelloID()
```

Extension type renames (full list in REMOVALS.md): `UtlsCompressCertExtension` →
`CompressCertificateExtension`; `FakeRecordSizeLimitExtension` →
`RecordSizeLimitExtension`; `ApplicationSettingsExtensionNew` →
`ApplicationSettingsExtension{CodePoint: utls.ALPSCodepointNew}`;
`BoringGREASEECH()` → `&EncryptedClientHelloExtension{GREASE: true}`;
`FakeDelegatedCredentialsExtension` → `GenericExtension{Id: 34, Data: ...}`;
`KeyShareExtension{KeyShares: ReuseHybridAndClassicalKeyShares(...)}` →
`KeyShareExtension{KeyShares: ..., ReuseClassicalFromHybrid: true}`.

## Writing into the ClientHello (Xray REALITY, ShadowTLS, Psiphon passthrough)

v1: `BuildHandshakeState` → mutate `HandshakeState.Hello.{SessionId,Random}`
and `Raw[39:]` → read `State13.KeyShareKeys.Ecdhe` → `MarshalClientHello`. v2:

```go
cfg := &tls.Config{ServerName: dest, SessionTicketsDisabled: true, InsecureSkipVerify: true,
    VerifyPeerCertificate: verifyWithAuthKey} // custom server authentication
uConn := utls.UClient(conn, cfg, utls.HelloChrome_Auto)
uConn.SetClientHelloHook(func(h *utls.ClientHelloContext) error {
    if h.PSK { return errors.New("resumption must be off") }  // binders would cover the SID
    priv := h.EphemeralKey(utls.X25519) // the X25519 share (or a hybrid's X25519 half)
    authKey := deriveAuthKey(priv, serverPublicKey, h.Random[:20])
    aad := bytes.Clone(h.Raw); clear(aad[39:71])                // SID zeroed, as v1's Raw[39:]
    copy(h.SessionID, seal(authKey, h.Random[20:], plaintext, aad))
    return nil
})
```

Notes: `h.Raw` is the handshake message (offsets as v1's `Raw`); the hook runs
on the final hello, after session load, and binders are recomputed after it.
Chrome sends an independent X25519 share (not the hybrid's half), so use
`EphemeralKey(utls.X25519)`; `EphemeralKey(utls.X25519MLKEM768)` returns the
hybrid's own X25519 half. A hook cannot be combined with ECH.

sing-box's `SessionIDGenerator` (sagernet fork) becomes the same hook (see
`shadowTLSv3Hook` in downstream_test.go). After the handshake,
`ServerHelloRaw()`, `ServerKeyShareGroup()` and `ServerKeyShareData()` expose
the server side for schemes that authenticate it.

## Psiphon-specific

| v1 (Psiphon fork) | v2 |
|---|---|
| seeded randomized ClientHello (`PRNGSeed`) | `seed, _ := utls.NewPRNGSeed()`; `utls.SeededRandomized(seed, &weights)` (store the 32 bytes) |
| obfuscated session ticket (`MakeClientSessionState`) | `SetSessionParams(ClientSessionParams{Version, CipherSuite, Secret, Ticket, ExtendedMasterSecret})` |
| passthrough client random | `SetClientHelloHook` writing `h.Random` |
| ClientHello fragmentation | `SetFragmentation(utls.FragmentOptions{Records: true, SplitAtSNI: true})` (or `Segments`, `MaxPieceSize`, `Delay`); `Dialer.Fragmentation`, `Transport.Fragmentation` |

## Record-layer handoff (Xray Vision, sing-box kTLS, Restls)

v1 users reached into `Conn.input`/`rawInput` by reflection, or used
`GetOutKeystream`. v2:

```go
st, err := uConn.HandOff() // TLS 1.3 only
// st.Plaintext: decrypted but unread; st.RawInput: received, not yet decrypted
// st.Read/WriteKey, Read/WriteIV, Read/WriteSeq, traffic secrets; st.Conn: the transport
```

After `HandOff`, `Read`/`Write` return `utls.ErrHandedOff`, and `Close` sends no
alert under stale keys.

## QUIC

```go
// v1: utls.UQUICClient(&utls.QUICConfig{TLSConfig: &utls.Config{...}}, utls.HelloChrome_Auto)
q := utls.QUICClient(&tls.QUICConfig{TLSConfig: tlsCfg}, id) // standard QUIC types
```

`Start`, `NextEvent` (returns `tls.QUICEvent`), `HandleData`,
`SetTransportParameters`, `StoreSession(*tls.SessionState)` behave as
crypto/tls's. Transport-parameter encoders (`utls.TransportParameters` …) were
part of uquic's needs and are not in v2: pass encoded bytes.

## Parsing captures, JA3/JA4

```go
spec, err := utls.ParseClientHello(raw)  // was Fingerprinter{}.FingerprintClientHello
ja3, hash, err := utls.JA3(raw)
ja4, err := utls.JA4(raw)
spec, err = utls.SpecFromJA3(ja3, utls.JA3SpecOptions{...}) // only when determinable
```
