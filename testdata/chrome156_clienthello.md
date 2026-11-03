# Chrome 156 ClientHello fixtures

`chrome156_clienthello.{0,1,2}.hex` are the first TLS records of three fresh
connections made by the installed official Google Chrome 156.0.8078.80 (macOS)
on November 2, 2026. The capture ran on the host (the build sandbox blocks
Chrome's process-singleton socket directory) with the listener in
`interop/capture` (source SHA-256 `2ec2c0e4...` at capture time; the committed
copy only adds a read deadline, usage text and write-error handling):

    "Google Chrome" --headless=new --user-data-dir=<new empty dir> --no-first-run
      --no-default-browser-check --disable-quic --disable-background-networking
      --disable-component-update --disable-sync --disable-crash-reporter
      --disable-breakpad --host-resolver-rules="MAP utls-capture.test 127.0.0.1"
      https://utls-capture.test:47691/

Fresh isolated profile, loopback only; the listener closes each connection after
the first record, so no handshake completed. The user's own profile was not used.

| file | record bytes | SHA-256 of the .hex text | SHA-256 of the handshake (record minus header) |
|------|-----:|------|------|
| `.0.hex` | 1989 | `99c252a4128436df19c4a3e7bbb0c450df1dbd5b4b7f100dc8869299e3d48519` | `d5b5e29a1c2b55f6a0d54ece559e3728d1da6f805130d0f63342f767e26f3e19` |
| `.1.hex` | 1925 | `404a05a51041d55e5ab095a27170b58cb74bc479f721d649fb2eb534219d99db` | `c4eaff35bcd1d5b2083510875a23563c3ce911bb372b2b175b9fec5c1b99514f` |
| `.2.hex` | 1957 | `1df1eaf3962bf6a7526f5d20eaf482ad720ef418efab7f556e5254e251362da7` | `acde90d425d0889a18f8a448eb5bd0488309c6471a3b6930c27a143f1a5b4bc9` |

The three records differ only in extension permutation, GREASE values, key
material and the GREASE ECH payload length (208, 144 and 176 bytes: BoringSSL's
144 + 32k family). Every other byte matches the Chrome 155 profile, including
the 28 trust anchor IDs, so `HelloChrome_156` uses the Chrome 155 spec;
`TestChrome156MatchesBrowserCaptures` enforces this with the same rules as the
Chrome 155 fixture (and compares GREASE extension bodies).
