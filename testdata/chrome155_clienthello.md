# Chrome 155 ClientHello fixture

`chrome155_clienthello.hex` is the complete first TLS record from a fresh HTTPS
connection made by official, branded Google Chrome 155.0.8059.40 on macOS arm64
on October 6, 2026. The browser version was checked in `chrome://version`.
The browser ran with a new dedicated profile, no TLS feature overrides, and QUIC
disabled so that the HTTPS connection used TCP. The page was opened through
native computer use at `https://www.example.com/`.

Wireshark's `dumpcap` recorded the connection, and `tshark` extracted TCP stream
0's ClientHello. The original TLS keylog was used separately to verify that the
connection completed a full TLS 1.3 handshake. Neither the keylog nor the
certificate/application traffic is included in this fixture.

The retained record is 1,955 bytes; its ClientHello handshake is 1,950 bytes.
SHA-256 of the decoded ClientHello handshake (excluding the five-byte TLS record
header):

```
235618e3922e52a71a9f6593a71ec4ca182dab6b3ab4e90a2a1733133e97439a
```

The original capture showed a new TCP SYN in frame 1, SYN/ACK in frame 3, and
ClientHello in frame 6. The ClientHello contains an empty `session_ticket` and
no `pre_shared_key`. The ServerHello in frame 13 selected TLS 1.3 and
`TLS_AES_128_GCM_SHA256`, without selecting a PSK. The decrypted server flight
in frame 19 contains EncryptedExtensions, CompressedCertificate,
CertificateVerify, and Finished; the client Finished follows in frame 21.
NewSessionTickets appear later in frame 35 and do not indicate resumption of
this connection. Chrome also opened an independent, fresh parallel connection
in stream 1, which completed a full handshake.

The profile advertises 28 trust anchor IDs in the captured order, three ML-DSA
signature schemes preceded by GREASE, X25519MLKEM768 and X25519 key shares, and
the new ALPS codepoint. The TLS server-padding extension is absent from this
normal Chrome capture.

Extraction command, using the original capture filename:

```sh
tshark -r chrome155-example.pcapng \
  -Y 'tcp.stream == 0 && tls.handshake.type == 1' \
  -T fields -e tcp.reassembled.data > chrome155_clienthello.hex
```

`u_chrome155_test.go` compares this independent browser capture with the generated
profile. It ignores only randomized extension permutation, GREASE codepoints,
ephemeral key material, and GREASE ECH config/key/payload randomness. The ECH
payload length must belong to BoringSSL's 144/176/208/240-byte family. Cipher,
signature, group, version, ALPN, key-share group/length, and trust-anchor list
order remain significant; other extension bodies are compared exactly. The
same fixture also exercises default Fingerprinter parsing and regeneration.
