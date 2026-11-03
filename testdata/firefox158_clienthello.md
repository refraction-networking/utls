# Firefox 158 ClientHello fixtures

Both files are the complete first TLS record of a fresh HTTPS connection made by
the official Mozilla Firefox 158.0 build (`firefox --version`: "Mozilla Firefox
158.0") installed on macOS (Darwin 27.0.0, arm64). They were recorded on
November 2, 2026 by `interop/capture` (a loopback listener that writes the first
TLS record of each connection as hex and then closes the connection, so no
handshake completed).

Firefox ran headless with a brand-new throwaway profile (`--no-remote -profile
<empty temp dir>`); the user's own profile was not used. Apart from
telemetry/update/safe-browsing/captive-portal prefs being switched off in that
profile, no TLS preferences were changed.

| file | URL | SNI | record bytes | SHA-256 of handshake (record minus 5-byte header) |
|------|-----|-----|-------------:|------|
| `firefox158_clienthello.hex` | `https://utls-capture.test:47615/` (mapped to 127.0.0.1 with `network.dns.localDomains`) | `utls-capture.test` | 1895 | `0d81fa209436b3a59ee8efb9d9c6d50790f780a937c53073ce5feaa7b3cfe3eb` |
| `firefox158_ip_clienthello.hex` | `https://127.0.0.1:47614/` | none (IP literal) | 1869 | `2c26860a283f852aa7cc0880623c565bc9f5b50f3556347e50493c1a2857d64b` |

Observations used by `HelloFirefox_158` (parrots.go):

- 15 cipher suites; the ECDHE-ECDSA-AES-CBC-SHA suites present in the v1
  Firefox 148 profile are gone.
- supported_groups X25519MLKEM768, X25519, P-256, P-384, P-521 (no FFDHE).
- key_share X25519MLKEM768 (1216 bytes), X25519, P-256; the X25519 share is the
  classical half of the hybrid share.
- session_ticket (empty) is sent; no pre_shared_key (fresh profile).
- GREASE ECH: outer type, HKDF-SHA256 + ChaCha20-Poly1305, 32-byte enc and a
  240-byte payload in both captures (config ID random).
- record_size_limit 16385, compress_certificate zlib/brotli/zstd,
  delegated_credentials, no padding.

`fidelity_test.go` compares both captures with the generated profile: extension
order and every extension body exactly, except key-share key material and the
GREASE ECH config ID / enc / payload bytes (suite and lengths are compared).

Chrome 156.0.8078.80 could not be captured in the build sandbox (Chrome aborts:
"Failed to create socket directory" after a Seatbelt `sandbox_extension` denial);
`interop/capture/capture-browsers.sh` reproduces the procedure on a host.
