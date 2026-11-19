package tls

import (
	"errors"
	"io"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// innerClientHello builds the ClientHelloInner of a custom ClientHello from
// the extensions the outer hello was built from, as BoringSSL derives Chrome's
// from one configuration (ssl_add_clienthello_tlsext_inner and
// ssl_write_client_cipher_list in ssl/):
//
//   - the cipher suites are the outer's GREASE and TLS 1.3 suites, in order;
//   - server_name carries the configured name, encrypted_client_hello the
//     inner marker, and supported_versions the outer's GREASE values and
//     TLS 1.3 only: these differ from the outer's and come first, in outer
//     order, uncompressed;
//   - renegotiation_info, extended_master_secret, session_ticket,
//     ec_point_formats and next_protocol_negotiation are TLS 1.2-only and
//     left out, as are padding and pre-shared keys;
//   - every other extension is the outer's, so it is compressed; ECH can only
//     compress one contiguous run, so they follow the uncompressed ones, in
//     outer order.
//
// Config.NextProtos, when set, replaces the outer's ALPN in the inner hello,
// uncompressed when it differs, so an application can offer a protocol under
// cover of the outer's. random is the inner hello's random, which a
// HelloRetryRequest keeps. The compressed extensions are recorded in ech for
// encodeInnerClientHelloFromRaw.
//
// Call it while uconn.Extensions holds the spec's ECH extension, not the
// outer payload computeAndUpdateOuterECHExtension swaps in.
func (uconn *UConn) innerClientHello(ech *echClientContext, random []byte) (*clientHelloMsg, error) {
	outer := uconn.HandshakeState.Hello

	var cipherSuites []uint16
	for _, id := range outer.CipherSuites {
		if isGREASEUint16(id) || isTLS13CipherSuiteID(id) {
			cipherSuites = append(cipherSuites, id)
		}
	}

	var uncompressed, compressed []TLSExtension
	var compressedIDs []uint16
	compress := func(ext TLSExtension) error {
		id, err := extensionType(ext)
		if err != nil {
			return err
		}
		compressed = append(compressed, ext)
		compressedIDs = append(compressedIDs, id)
		return nil
	}
	for _, ext := range uconn.Extensions {
		switch e := ext.(type) {
		case *RenegotiationInfoExtension, *ExtendedMasterSecretExtension, *SessionTicketExtension,
			*SupportedPointsExtension, *NPNExtension, *UtlsPaddingExtension, PreSharedKeyExtension:
			continue
		case *SNIExtension:
			if name := hostnameInSNI(uconn.config.ServerName); name != "" {
				uncompressed = append(uncompressed, &SNIExtension{ServerName: name})
			}
		case EncryptedClientHelloExtension:
			uncompressed = append(uncompressed, &GenericExtension{Id: utlsExtensionECH, Data: []byte{InnerClientHello}})
		case *SupportedVersionsExtension:
			var versions []uint16
			for _, v := range e.Versions {
				if isGREASEUint16(v) || v >= VersionTLS13 {
					versions = append(versions, v)
				}
			}
			uncompressed = append(uncompressed, &SupportedVersionsExtension{Versions: versions})
		case *ALPNExtension:
			if protos := uconn.config.NextProtos; len(protos) > 0 && !slices.Equal(protos, e.AlpnProtocols) {
				uncompressed = append(uncompressed, &ALPNExtension{AlpnProtocols: protos})
			} else if err := compress(ext); err != nil {
				return nil, err
			}
		default:
			if err := compress(ext); err != nil {
				return nil, err
			}
		}
	}

	raw, err := marshalClientHelloMsg(outer.Vers, random, outer.SessionId, cipherSuites, outer.CompressionMethods, append(uncompressed, compressed...))
	if err != nil {
		return nil, err
	}
	inner := new(clientHelloMsg)
	if !inner.unmarshal(raw) {
		return nil, errors.New("tls: built an unparsable inner client hello")
	}
	ech.innerOuterExts = compressedIDs
	return inner, nil
}

// isTLS13CipherSuiteID reports whether id is a TLS 1.3 cipher suite, offered
// or not by this implementation.
func isTLS13CipherSuiteID(id uint16) bool {
	return id >= 0x1301 && id <= 0x1305
}

// extensionType returns the extension type ext marshals as.
func extensionType(ext TLSExtension) (uint16, error) {
	buf := make([]byte, ext.Len())
	if _, err := ext.Read(buf); err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	if len(buf) < 2 {
		return 0, errors.New("tls: extension marshals to fewer than two bytes")
	}
	return uint16(buf[0])<<8 | uint16(buf[1]), nil
}

// marshalClientHelloMsg serializes a ClientHello handshake message, header
// included, from its fields and marshaled extensions.
func marshalClientHelloMsg(vers uint16, random, sessionID []byte, cipherSuites []uint16, compressionMethods []byte, exts []TLSExtension) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(vers)
		b.AddBytes(random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sessionID) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, id := range cipherSuites {
				b.AddUint16(id)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(compressionMethods) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, ext := range exts {
				buf := make([]byte, ext.Len())
				n, err := ext.Read(buf)
				if err != nil && !errors.Is(err, io.EOF) {
					b.SetError(err)
					return
				}
				b.AddBytes(buf[:n])
			}
		})
	})
	return b.Bytes()
}

// encodeInnerClientHelloFromRaw returns the EncodedClientHelloInner of inner
// (RFC 9849, section 6.1): its marshaled form with an empty session ID and
// the extensions listed in outerExts, one contiguous run in that order,
// replaced by ech_outer_extensions, then padded.
func encodeInnerClientHelloFromRaw(inner *clientHelloMsg, outerExts []uint16, maxNameLength int) ([]byte, error) {
	s := cryptobyte.String(inner.original)
	var versionAndRandom, sessionID, cipherSuites, compressionMethods []byte
	var extensions cryptobyte.String
	if !s.Skip(4) || !s.ReadBytes(&versionAndRandom, 2+32) ||
		!readUint8LengthPrefixed(&s, &sessionID) ||
		!readUint16LengthPrefixed(&s, &cipherSuites) ||
		!readUint8LengthPrefixed(&s, &compressionMethods) ||
		!s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, errors.New("tls: malformed inner client hello")
	}

	var b cryptobyte.Builder
	b.AddBytes(versionAndRandom)
	b.AddUint8(0) // the session ID is the outer's
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(cipherSuites) })
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(compressionMethods) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		compressed := 0
		for !extensions.Empty() {
			var extType uint16
			var extData cryptobyte.String
			if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
				b.SetError(errors.New("tls: malformed inner client hello extensions"))
				return
			}
			if compressed < len(outerExts) && extType == outerExts[compressed] {
				if compressed == 0 {
					b.AddUint16(extensionECHOuterExtensions)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, id := range outerExts {
								b.AddUint16(id)
							}
						})
					})
				}
				compressed++
				continue
			}
			if compressed > 0 && compressed < len(outerExts) {
				b.SetError(errors.New("tls: compressed inner client hello extensions are not contiguous"))
				return
			}
			b.AddUint16(extType)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(extData) })
		}
		if compressed != len(outerExts) {
			b.SetError(errors.New("tls: inner client hello lacks a compressed extension"))
		}
	})
	h, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return padInnerClientHello(h, inner.serverName, maxNameLength), nil
}
