# How uTLS is actually used (downstream survey)

This is the evidence base for the v2 API. We read the source of ~30 real
projects that depend on uTLS (not just their import lists — what they are trying
to achieve at the protocol level) and catalogued how and why. The API in the
root package is shaped directly by the ranked intents below.

## Projects read

**Anti-censorship proxy cores:** Xray-core (REALITY, Vision), v2ray-core,
sing-box (REALITY/ShadowTLS/kTLS), mihomo/Clash.Meta (REALITY/JLS/Vision/Restls),
trojan-go, go-gost, warp-plus, xray-knife.

**Pluggable transports / measurement:** Tor Snowflake, lyrebird (obfs4/meek_lite/
webtunnel), meek, Refraction Networking Conjure + gotapdance, OONI probe-cli +
oohttp, Psiphon tunnel-core.

**Fronting / resumption infra:** getlantern flashlight, fronted, tlsdialer,
tlsresumption, samizdat.

**HTTP impersonation / scraping:** imroc/req, CycleTLS, bogdanfinn/tls-client,
enetx/surf, projectdiscovery/fastdialer, CLIProxyAPI, wi1dcard/fingerproxy,
yaklang.

**QUIC:** refraction uquic, enetx/uquic, Dharmey747/quic-go-utls, (vs quic-go).

**Forks we studied for unmet needs:** metacubex/utls, sagernet/utls,
Psiphon-Labs/utls, bogdanfinn/utls, yawning/utls, restls-client-go.

## Ranked usage intents

1. **Pick a fingerprint by name.** Every project. Each had a hand-written,
   drifting name→ID table; all agreed on the special cases (`""`→default,
   `none`/`golang`→stdlib) and on excluding `HelloCustom`/`HelloRandomized` from
   "named" lists. → `ParseFingerprint`, `Fingerprints`, aliases, conventions.

2. **Dial a browser-shaped `net.Conn` and handshake before returning.** Every
   project (each re-learned utls#75: call `Handshake` before the first `Read`).
   → `Dial`/`DialContext` handshake before returning; `UClient` + `Handshake`.

3. **Interoperate as crypto/tls.** Accept `*crypto/tls.Config`, return
   `crypto/tls.ConnectionState` (with ALPN) so net/http and x/net/http2 work.
   OONI, uquic, oohttp, req, CycleTLS, surf, CLIProxyAPI, yaklang, fastdialer,
   sing-box, mihomo all hand-converted types, forked net/http (oohttp, fhttp,
   metacubex/http), or kept reflection whitelists. → the conversion boundary in
   `config.go`; `ConnectionState = crypto/tls.ConnectionState`; `Transport`.

4. **Cert verification decoupled from SNI.** Omit SNI, front SNI, verify a
   different name, pin a leaf, custom roots. Psiphon, flashlight, fronted,
   tlsdialer, lyrebird, snowflake, Conjure. All forced `InsecureSkipVerify` +
   `VerifyPeerCertificate`. → honoured via the standard config fields; empty
   `SNIExtension` uses ServerName, omit it to drop SNI; `VerifyConnection`/
   `VerifyPeerCertificate` carried through.

5. **Write chosen bytes into a ClientHello field, computed over the final
   serialized hello, with PSK binders still valid.** session_id for REALITY
   (Xray, sing-box, mihomo) and ShadowTLS v3; client_random for JLS and Psiphon
   passthrough; session_id for samizdat. Needs the ephemeral key-share private
   key. This was the single biggest friction: build→mutate→remarshal with
   hard-coded `Raw[39:]` offsets, reflect/unsafe, and "uTLS does not expose a
   hook for [binder recompute]". → the `ClientHello` hook: `ClientHelloContext`
   gives in-place `Random`/`SessionID` and `EphemeralKey(group)`.

6. **Custom server authentication with ServerHello/key-share visible.** REALITY
   verifies a cert signed by a key derived from the server's share; JLS
   authenticates the ServerHello random. → `UConn.ServerKeyShareGroup/Data`,
   `ServerHelloRaw`, `EphemeralKey`, plus the standard `VerifyConnection`.

7. **Build a spec from data:** JA3/JA4 string (CycleTLS, tls-client, fastdialer,
   yaklang), raw captured bytes (fastdialer, flashlight, fingerproxy), JSON
   (Psiphon tactics, watm), or a seeded randomized fingerprint replayed later
   (Psiphon). → `ParseClientHello`; `ClientHelloSpec` is plain data; randomized
   presets. (JA3/JA4 string parsing is a thin future addition over
   `ParseClientHello`.)

8. **Per-connection freshness.** GREASE (incl. signature_algorithms — a common
   fork patch), extension shuffling, fresh key shares, and never sharing
   extension objects across connections (surf wrote a 400-line unsafe deep-clone;
   fastdialer/Psiphon hit the shared-slice bug). → `Spec()` returns a fresh spec
   each call; the renderer generates fresh keys and GREASE per connection.

9. **An http.RoundTripper that dispatches h2/h1 by ALPN.** meek, lyrebird,
   snowflake, Conjure, oohttp, gotapdance, req, CycleTLS, surf, CLIProxyAPI,
   yaklang — many forked net/http. → `Transport`.

10. **Multiple key shares / PQ.** Offer X25519MLKEM768 + X25519 and complete
    whichever the server picks; drop PQ for old servers. bogdanfinn and Psiphon
    forks added fallback-key maps; yaklang injected keys by hand. → the renderer
    retains every offered group's private key and the `[uTLS]`
    establishHandshakeKeys hunk selects the right one.

11. **Out-of-band / forged resumption, ClientHello fragmentation, record-layer
    handoff (kTLS/Vision/Restls), ECH, QUIC mimicry.** Real but narrower needs
    (Psiphon, Lantern, sing-box, mihomo, uquic). The hooks and raw-bytes access
    in v2 make these implementable downstream without forking core; first-class
    helpers are the natural next additions (see API_DESIGN.md "Not yet").

## Identifiers the survey said to drop or demote

Downstream worked *around* these far more than it wanted them, so v2 does not put
them front and centre: a separate `utls.Config`/`utls.ConnectionState`; the
public `HandshakeState`/`PubClientHelloMsg`/`PubServerHelloMsg`/`State12`/
`State13`; the two-phase `BuildHandshakeState`+`MarshalClientHello`; `SetSNI`/
`RemoveSNIExtension`; the global `EnableWeakCiphers`; `Roller`; versioned
`Hello*` variables as the primary surface; and `MakeConnWithCompleteHandshake`.
Where a real need sat behind one of these (e.g. keystream export for TapDance),
v2 re-expresses it as an intent-shaped method rather than exposed internals.
