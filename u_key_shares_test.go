package tls

import (
	"fmt"
	"testing"
)

// classicalKeyShareGroups lists the groups of a spec's classical key shares,
// the ones a server may select without a HelloRetryRequest.
func classicalKeyShareGroups(spec *ClientHelloSpec) []CurveID {
	var groups []CurveID
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*KeyShareExtension); ok {
			for _, share := range ks.KeyShares {
				switch share.Group {
				case X25519, CurveP256, CurveP384, CurveP521:
					groups = append(groups, share.Group)
				}
			}
		}
	}
	return groups
}

// TestUTLSEveryClassicalKeyShareIsUsable checks that a server may select any
// of the classical key shares a spec offers, not only the first: Firefox
// offers X25519 and P-256 shares, and a server preferring P-256 completes the
// handshake with it, without a HelloRetryRequest.
func TestUTLSEveryClassicalKeyShareIsUsable(t *testing.T) {
	specs := map[string]*ClientHelloSpec{}
	for _, id := range []ClientHelloID{HelloFirefox_105, HelloFirefox_120, HelloFirefox_148} {
		spec, err := utlsIdToSpec(id)
		if err != nil {
			t.Fatal(err)
		}
		specs[id.Str()] = &spec
	}
	specs["three classical shares"] = &ClientHelloSpec{
		CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256, CurveP384}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}, {Group: CurveP256}, {Group: CurveP384}}},
		},
	}

	for name, spec := range specs {
		groups := classicalKeyShareGroups(spec)
		if len(groups) < 2 {
			t.Fatalf("%s: offers %v classical key shares, want at least two", name, groups)
		}
		for _, group := range groups {
			t.Run(fmt.Sprintf("%s/%v", name, group), func(t *testing.T) {
				clientConfig := testConfigClient.Clone()
				serverConfig := testConfigServer.Clone()
				serverConfig.CurvePreferences = []CurveID{group}
				_, state, err := testUtlsHandshake(t, clientConfig, serverConfig, spec)
				if err != nil {
					t.Fatalf("server selecting %v: %v", group, err)
				}
				if state.CurveID != group || state.HelloRetryRequest {
					t.Fatalf("negotiated %v with HelloRetryRequest=%v, want %v without a retry", state.CurveID, state.HelloRetryRequest, group)
				}
			})
		}
	}
}
