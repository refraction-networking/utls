# Safari 27 ClientHello fixtures

`safari27_clienthello.{0,1,2}.hex` are the first TLS records of three
connections made by the installed Safari 27.0.1 (macOS) on November 3, 2026
00:30 UTC, captured on the host: a new private window was opened through the
native UI and pointed at `https://localhost:47692/`, served by the
`interop/capture` listener on 127.0.0.1. Only that private window was used and
then closed; no certificate warning was bypassed (the listener closes before
sending a certificate).

| file | record bytes | SHA-256 of the .hex text | SHA-256 of the handshake (record minus header) |
|------|-----:|------|------|
| `.0.hex` | 1532 | `29ad7f734ceab89d423bfbbbc4dd7d6c69a32402f51ea100017330797d2d9927` | `2138e0daf1fd68e87ebce3d73fab73e019ca48192ad64df420c022cf6fd7b529` |
| `.1.hex` | 1532 | `20f1a484a24554e998c4e36536d849e8b50b65e36b8f0091f2effd6edaebf1b9` | `067edefe7cf5a4941d9de1923f620656f375726e22a215061d0d55f986c55652` |
| `.2.hex` | 1532 | `555d37158ffccaabcbe0ae4e151769c469a5af1b0d8bc45f9454152b880cd6dd` | `6480903a8bf47b9b129854bf16bd909fc4c6228753b9703daf6656011f628b4c` |

Safari does not permute extensions. Apart from GREASE values and key material
the three records are identical to each other and to the Safari 26.3 profile
ported from uTLS v1, with one correction found by these captures: the second
GREASE extension carries a one-byte body (`00`), as in every BoringSSL client.
uTLS v1 added that byte implicitly in ApplyPreset; the v2 port had dropped it
for Safari, iOS and QQ (fixed). `TestSafari27MatchesBrowserCaptures` compares
order, every extension body, GREASE bodies, record length, JA3 and JA4.
