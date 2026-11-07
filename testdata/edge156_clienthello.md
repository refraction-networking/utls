# Edge 156 ClientHello fixture

`edge156_clienthello.hex` is the complete first TLS record of a fresh HTTPS
connection made by Microsoft Edge 156.0.4314.58 (stable, x64) on Windows 11 on
November 7, 2026. Edge ran with a new dedicated profile, no TLS feature
overrides, and QUIC disabled so the connection used TCP.

Edge was pointed at `https://www.example.com/` with
`--host-resolver-rules=MAP www.example.com 127.0.0.1:<port>`. A small local
relay on that port saved the first record and forwarded the connection to the
real `www.example.com:443`. The server answered with a ServerHello selecting
TLS 1.3. No keylog was taken, so the rest of the handshake was not decrypted.

The record is 1,797 bytes; its ClientHello handshake is 1,792 bytes. SHA-256 of
the ClientHello handshake (excluding the five-byte record header):

```
7ada30682ec8e3601ad51c7f41f1e580e4b5b9f0a6add3d7b160eecbc8f8df37
```

A second capture made the same way had the same extensions and bodies apart
from the randomized parts. Neither carried `trust_anchors` (0xca34). Edge also
left it out with `--enable-features=TLSTrustAnchorIDs`.

Apart from that one extension, the capture matches the Chrome 155 fixture:
the same cipher suites, groups, key shares, signature algorithms (ML-DSA
included), ALPS codepoint and GREASE ECH shape. `u_edge156_test.go` compares
it with the generated `HelloEdge_156` profile using the same normalization as
`u_chrome155_test.go`, and also checks it against the Chrome 155 fixture with
`trust_anchors` and the server name removed.
