# Yandex Browser 26.11 fixture provenance

Captured on Windows 10.0.26300, 15 November 2026, from official Yandex Browser
26.11.0.1993. Its installer Authenticode signature validated as YANDEX LLC.
The executable was extracted without changing the user's installed browsers.
User-Agent reports Chromium 154.0.0.0 and YaBrowser/26.11.0.0.

Six headless and six headed launches used separate new user-data directories.
QUIC was disabled to select TCP; there were no TLS capability overrides.
A loopback HTTP CONNECT relay forwarded to the real `www.example.com:443`.
All twelve page navigations returned HTTPS 200, title Example Domain.
Only the first complete client TLS record is retained, no key logs, cookies,
HTTP payloads, session tickets, private keys, or client addresses.

There are eight headless and eleven headed records. Parallel speculative
connections account for multiple records per launch. One headless speculative
connection (`yandex2611-5-8.hex`) had no captured server reply; the completed
page navigation from that launch used the other connection. Do not claim all
nineteen speculative connections completed TLS solely because the pages did.
The fixtures offer empty session_ticket and no pre_shared_key.

Observed TLS record lengths: 1923 / 1955 / 1987 / 2019 bytes. The independent
Chrome155 wire parser compares every extension body, ordered capability list,
ALPN, key-share group/length, and trust anchor IDs, normalizing only GREASE,
extension permutation, and ephemeral/random data according to that parser.
ClientHello random and session ID are compared by length, not random bytes;
key-share public keys by group and length; ECH random bytes are ignored but
its lengths must stay in BoringSSL's 144/176/208/240-byte payload family.
All nineteen match the pinned Chrome155 spec, including X25519MLKEM768.

`HelloYandex_26_11` is therefore an explicit version/provenance alias to
`HelloChrome_155`, not new wire diversity. It deliberately does not track
`HelloChrome_Auto`. No Yandex Auto profile is introduced. This does not emulate
browser HTTP behavior, TCP stack, post-handshake record sizes, or future Yandex
versions. The comparison is Windows-specific; Android/macOS were not captured.

Tests also ensure mutating a Yandex preset cannot change a later Chrome preset.
