package tls

import (
	"bytes"
	"crypto/sha256"
	"net"
	"testing"
)

const x25519PublicKeySize = 32

type incrementingSource struct {
	next byte
}

func (s *incrementingSource) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = s.next
		s.next++
	}
	return len(b), nil
}

func findKeyShareExtension(t *testing.T, exts []TLSExtension) *KeyShareExtension {
	t.Helper()

	for _, ext := range exts {
		if keyShareExt, ok := ext.(*KeyShareExtension); ok {
			return keyShareExt
		}
	}

	t.Fatal("key_share extension not found")
	return nil
}

func findKeyShareData(t *testing.T, keyShareExt *KeyShareExtension, group CurveID) []byte {
	t.Helper()

	for _, keyShare := range keyShareExt.KeyShares {
		if keyShare.Group == group {
			return keyShare.Data
		}
	}

	t.Fatalf("key_share for group %v not found", group)
	return nil
}

func newTestUConnWithIncrementingRand() *UConn {
	return UClient(&net.TCPConn{}, &Config{
		ServerName: "example.com",
		Rand:       &incrementingSource{},
	}, HelloCustom)
}

func fingerprintsWithHybridClassicalKeyShareReuse() []ClientHelloID {
	return []ClientHelloID{
		HelloFirefox_148,
	}
}

func TestParrotFingerprintsReuseHybridClassicalKeyShare(t *testing.T) {
	for _, helloID := range fingerprintsWithHybridClassicalKeyShareReuse() {
		t.Run(helloID.Str(), func(t *testing.T) {
			spec, err := UTLSIdToSpec(helloID)
			if err != nil {
				t.Fatalf("unexpected error creating %s spec: %v", helloID.Str(), err)
			}

			uconn := newTestUConnWithIncrementingRand()
			if err := uconn.ApplyPreset(&spec); err != nil {
				t.Fatalf("unexpected error applying %s spec: %v", helloID.Str(), err)
			}

			keyShareExt := findKeyShareExtension(t, uconn.Extensions)
			hybridData := findKeyShareData(t, keyShareExt, X25519MLKEM768)
			classicalData := findKeyShareData(t, keyShareExt, X25519)

			if len(hybridData) < x25519PublicKeySize {
				t.Fatalf("hybrid keyshare is too short: got %d bytes", len(hybridData))
			}
			hybridClassicalPart := hybridData[len(hybridData)-x25519PublicKeySize:]
			if !bytes.Equal(hybridClassicalPart, classicalData) {
				t.Fatalf("expected %s to reuse classical keyshare: hybrid classical part != X25519 keyshare", helloID.Str())
			}

			keys := uconn.HandshakeState.State13.KeyShareKeys
			if keys == nil || keys.MlkemEcdhe == nil || keys.Ecdhe == nil {
				t.Fatal("expected both hybrid and classical ECDHE private keys to be set")
			}
			if keys.MlkemEcdhe != keys.Ecdhe {
				t.Fatalf("expected %s hybrid/classical keyshares to reuse the same ECDHE private key", helloID.Str())
			}
		})
	}
}

func TestHybridClassicalKeySharesAreIndependentByDefault(t *testing.T) {
	spec := ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
		},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{
				Curves: []CurveID{
					X25519MLKEM768,
					X25519,
				},
			},
			&KeyShareExtension{
				KeyShares: []KeyShare{
					{
						Group: X25519MLKEM768,
					},
					{
						Group: X25519,
					},
				},
			},
			&SupportedVersionsExtension{
				Versions: []uint16{
					VersionTLS13,
					VersionTLS12,
				},
			},
		},
	}

	uconn := newTestUConnWithIncrementingRand()
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("unexpected error applying independent keyshare spec: %v", err)
	}

	keyShareExt := findKeyShareExtension(t, uconn.Extensions)
	hybridData := findKeyShareData(t, keyShareExt, X25519MLKEM768)
	classicalData := findKeyShareData(t, keyShareExt, X25519)

	if len(hybridData) < x25519PublicKeySize {
		t.Fatalf("hybrid keyshare is too short: got %d bytes", len(hybridData))
	}
	hybridClassicalPart := hybridData[len(hybridData)-x25519PublicKeySize:]
	if bytes.Equal(hybridClassicalPart, classicalData) {
		t.Fatalf("expected independent keyshares by default: hybrid classical part == X25519 keyshare")
	}

	keys := uconn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.MlkemEcdhe == nil || keys.Ecdhe == nil {
		t.Fatal("expected both hybrid and classical ECDHE private keys to be set")
	}
	if keys.MlkemEcdhe == keys.Ecdhe {
		t.Fatal("expected independent keyshares by default: hybrid/classical ECDHE private keys should differ")
	}
}

func TestClientHelloSpecCloneDeepCopy(t *testing.T) {
	cachedLength := 17
	spec := &ClientHelloSpec{
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
		CompressionMethods: []uint8{compressionNone},
		TLSVersMin:         VersionTLS12,
		TLSVersMax:         VersionTLS13,
		GetSessionID:       sha256.Sum256,
		Extensions: []TLSExtension{
			&KeyShareExtension{
				KeyShares: []KeyShare{
					{Group: X25519, Data: []byte{1, 2, 3}},
				},
			},
			&GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []HPKESymmetricCipherSuite{{KdfId: 1, AeadId: 2}},
				CandidateConfigIds:    []uint8{3},
				EncapsulatedKey:       []byte{4, 5},
				CandidatePayloadLens:  []uint16{6},
				payload:               []byte{7, 8},
			},
			&UtlsPreSharedKeyExtension{
				PreSharedKeyCommon: PreSharedKeyCommon{
					EarlySecret: []byte{9},
					BinderKey:   []byte{10},
					Identities: []PskIdentity{{
						Label:               []byte{11, 12},
						ObfuscatedTicketAge: 13,
					}},
					Binders: [][]byte{{14, 15}},
				},
				cachedLength: &cachedLength,
				OmitEmptyPsk: true,
			},
		},
	}

	cloned := spec.clone()
	if cloned == spec {
		t.Fatal("expected Clone to allocate a new ClientHelloSpec")
	}

	cloned.CipherSuites[0] = TLS_CHACHA20_POLY1305_SHA256
	if spec.CipherSuites[0] == TLS_CHACHA20_POLY1305_SHA256 {
		t.Fatal("expected CipherSuites to be deep copied")
	}

	clonedKeyShare := cloned.Extensions[0].(*KeyShareExtension)
	originalKeyShare := spec.Extensions[0].(*KeyShareExtension)
	if clonedKeyShare == originalKeyShare {
		t.Fatal("expected KeyShareExtension to be deep copied")
	}
	clonedKeyShare.KeyShares[0].Data[0] = 99
	if originalKeyShare.KeyShares[0].Data[0] == 99 {
		t.Fatal("expected KeyShareExtension key data to be deep copied")
	}

	clonedECH := cloned.Extensions[1].(*GREASEEncryptedClientHelloExtension)
	originalECH := spec.Extensions[1].(*GREASEEncryptedClientHelloExtension)
	if clonedECH == originalECH {
		t.Fatal("expected GREASEEncryptedClientHelloExtension to be deep copied")
	}
	clonedECH.EncapsulatedKey[0] = 88
	clonedECH.payload[0] = 77
	if originalECH.EncapsulatedKey[0] == 88 || originalECH.payload[0] == 77 {
		t.Fatal("expected GREASE ECH extension buffers to be deep copied")
	}

	clonedPSK := cloned.Extensions[2].(*UtlsPreSharedKeyExtension)
	originalPSK := spec.Extensions[2].(*UtlsPreSharedKeyExtension)
	if clonedPSK == originalPSK {
		t.Fatal("expected UtlsPreSharedKeyExtension to be deep copied")
	}
	if clonedPSK.cachedLength == originalPSK.cachedLength {
		t.Fatal("expected UtlsPreSharedKeyExtension cachedLength to be deep copied")
	}
	clonedPSK.Identities[0].Label[0] = 66
	clonedPSK.Binders[0][0] = 55
	*clonedPSK.cachedLength = 44
	if originalPSK.Identities[0].Label[0] == 66 || originalPSK.Binders[0][0] == 55 || *originalPSK.cachedLength == 44 {
		t.Fatal("expected UtlsPreSharedKeyExtension nested state to be deep copied")
	}

	if cloned.GetSessionID == nil {
		t.Fatal("expected GetSessionID function to be preserved")
	}
}

func TestApplyPresetDoesNotMutateOriginalSpec(t *testing.T) {
	spec := ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
		},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{
				Curves: []CurveID{
					X25519MLKEM768,
					X25519,
				},
			},
			&KeyShareExtension{
				KeyShares: []KeyShare{
					{Group: X25519MLKEM768},
					{Group: X25519},
				},
			},
			&SupportedVersionsExtension{
				Versions: []uint16{
					VersionTLS13,
					VersionTLS12,
				},
			},
		},
	}

	uconn := newTestUConnWithIncrementingRand()
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("unexpected error applying spec: %v", err)
	}

	keyShareExt := findKeyShareExtension(t, spec.Extensions)
	for _, keyShare := range keyShareExt.KeyShares {
		if len(keyShare.Data) != 0 {
			t.Fatal("expected ApplyPreset to leave the original ClientHelloSpec unchanged")
		}
	}
}
