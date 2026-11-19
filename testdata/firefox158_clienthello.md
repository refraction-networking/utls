# Firefox 158 ClientHello fixture

`firefox158_clienthello.hex` is the complete first TLS record from a fresh HTTPS
connection made by the official Mozilla Firefox 158.0 build (snap `158.0-2`,
publisher Mozilla) on Ubuntu 25.10 x86_64 on October 19, 2026. The browser ran
headless with a new dedicated profile in normal (not private) browsing mode, with
`network.http.http3.enable` set to false so that the HTTPS connection used TCP.
It opened `https://www.example.com/`.

Wireshark's `dumpcap` recorded the connection, and `tshark -z follow,tcp,raw`
extracted the client's first TLS record from the TCP stream; the ClientHello
spans two TCP segments. `SSLKEYLOGFILE` was used separately to verify that the
connection completed a full TLS 1.3 handshake: the decrypted server flight
contains EncryptedExtensions, CompressedCertificate, CertificateVerify and
Finished, followed by the client Finished and HTTP/2 traffic. Neither the keylog
nor the certificate/application traffic is included in this fixture.

The retained record is 1,893 bytes; its ClientHello handshake is 1,888 bytes.
SHA-256 of the decoded ClientHello handshake (excluding the five-byte TLS record
header):

```
a9f5a024e7a3e7b07afe280c9435e0e7eafe67ca6e84a2933f9c11b488584eac
```

The ClientHello contains an empty `session_ticket` and `psk_key_exchange_modes`
(`psk_dhe_ke`), and no `pre_shared_key`. The outer SNI is `www.example.com`, so
the `encrypted_client_hello` extension is GREASE, not a real ECH offer.

Notes:

- Private browsing: the same build in private browsing mode sends the same
  ClientHello without `session_ticket` (35) and `psk_key_exchange_modes` (45).
  Firefox 148.0 behaves the same way, and `HelloFirefox_148` matches its private
  browsing ClientHello.
- GREASE ECH: the HPKE AEAD alternates between AES-128-GCM and
  ChaCha20-Poly1305 across connections. The payload was 240 bytes in 12 of 12
  Firefox 158 captures, while Firefox 148 sent both 239 and 240 bytes, so
  `HelloFirefox_158` keeps the 239-byte payload used by `HelloFirefox_148`.
