package tls

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrNoExtensionID = errors.New("no extension ID in JSON object")

type JSONClientHelloSpec struct {
	CipherSuites []struct {
		ID   uint16 `json:"id"`
		Name string `json:"name,omitempty"` // optional
	} `json:"cipher_suites"`
	CompressionMethods []struct {
		ID   uint8  `json:"id"`
		Name string `json:"name,omitempty"` // optional
	} `json:"compression_methods"`
	Extensions []TLSExtensionJSONUnmarshaler `json:"extensions"`
	TLSVersMin uint16                        `json:"min_vers,omitempty"` // optional
	TLSVersMax uint16                        `json:"max_vers,omitempty"` // optional
}

type TLSExtensionJSONUnmarshaler struct {
	id             uint16
	name           string // optional
	data           []byte // unknown ext
	unmarshalInput []byte // debug
	tlsExtension   TLSExtension
}

func (e *TLSExtensionJSONUnmarshaler) UnmarshalJSON(raw []byte) error {
	e.unmarshalInput = raw

	// First unmarshal the ID and Name (metadata)
	var metadata struct {
		ID   uint16 `json:"id"`
		Name string `json:"name,omitempty"` // optional
		Data []byte `json:"data,omitempty"` // optional, for UNKNOWN extensions
	}
	metadata.ID = 0xFFFF // invalid ID to detect if set

	if err := json.Unmarshal(raw, &metadata); err != nil {
		return err
	}

	if metadata.ID == 0xFFFF {
		return ErrNoExtensionID // no ID in JSON object (so default value was used)
	}
	e.id = metadata.ID
	e.name = metadata.Name
	e.data = metadata.Data

	// get extension type from ID
	ext := ExtensionFromID(e.id)
	if ext == nil {
		return fmt.Errorf("unknown extension ID: %d", e.id)
	}

	if e.tlsExtension == nil {
		e.fallbackToGenericExtension()
	}

	return nil
}

func (e *TLSExtensionJSONUnmarshaler) fallbackToGenericExtension() {
	var warningMsg string = "WARNING: extension "
	warningMsg += fmt.Sprintf("%d ", e.id)
	if len(e.name) > 0 {
		warningMsg += fmt.Sprintf("(%s) ", e.name)
	}
	warningMsg += "is falling back to generic extension"
	if len(e.data) == 0 {
		warningMsg += " with no data"
	}
	warningMsg += "\n"

	// fallback to generic extension
	genericExt := &GenericExtension{e.id, e.data}
	e.tlsExtension = genericExt
}

/*
{
	"cipher_suites": [
		{"id": 0x1301, "name": "TLS_AES_128_GCM_SHA256"},
		{"id": 0x1302, "name": "TLS_AES_256_GCM_SHA384"}
	],
	"compression_methods": [
		{"id": 0x00, "name": "null"}
	],
	"extensions": [
		{"id": 0x7a7a, "name": "GREASE"}, // grease, id could be any 0xNaNa where N in 0~f
		{"id": 0x0000, "name": "server_name"}, // don't use SNI's data
		{"id": 0x0017, "name": "extended_master_secret"}, // no data
		{"id": 0xff01, "name": "renegotiation_info", "renegotiation": 1},
		{"id": 0x000a, "name": "supported_groups", "named_group_list": [
			{"id": 0x1a1a, "name": "GREASE"},
			{"id": 0x001d, "name": "x25519"},
			{"id": 0x0017, "name": "secp256r1"},
			{"id": 0x0018, "name": "secp384r1"}
		]},
		{"id": 0x0010, "name": "application_layer_protocol_negotiation", "protocol_name_list": [
			"h2",
			"http/1.1"
		]},
		...
	]
}
*/
