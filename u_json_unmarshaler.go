package tls

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrNoExtensionID = errors.New("no extension ID in JSON object")

type ClientHelloSpecJSONUnmarshaler struct {
	CipherSuites       *CipherSuitesJSONUnmarshaler       `json:"cipher_suites"`
	CompressionMethods *CompressionMethodsJSONUnmarshaler `json:"compression_methods"`
	Extensions         *TLSExtensionsJSONUnmarshaler      `json:"extensions"`
	TLSVersMin         uint16                             `json:"min_vers,omitempty"` // optional
	TLSVersMax         uint16                             `json:"max_vers,omitempty"` // optional
}

type CipherSuitesJSONUnmarshaler struct {
	cipherSuites []uint16
}

func (c *CipherSuitesJSONUnmarshaler) UnmarshalJSON(jsonStr []byte) error {
	var accepters []struct {
		ID   uint16 `json:"id"`
		Name string `json:"name,omitempty"` // optional
	}
	if err := json.Unmarshal(jsonStr, &accepters); err != nil {
		return err
	}

	var ciphers []uint16 = make([]uint16, 0, len(accepters))
	for _, accepter := range accepters {
		ciphers = append(ciphers, unGREASEUint16(accepter.ID))
	}

	c.cipherSuites = ciphers
	return nil
}

type CompressionMethodsJSONUnmarshaler struct {
	compressionMethods []uint8
}

func (c *CompressionMethodsJSONUnmarshaler) UnmarshalJSON(jsonStr []byte) error {
	var accepters []struct {
		ID   uint8  `json:"id"`
		Name string `json:"name,omitempty"` // optional
	}
	if err := json.Unmarshal(jsonStr, &accepters); err != nil {
		return err
	}

	var compressions []uint8 = make([]uint8, 0, len(accepters))
	for _, accepter := range accepters {
		compressions = append(compressions, accepter.ID)
	}

	c.compressionMethods = compressions
	return nil
}

type TLSExtensionsJSONUnmarshaler struct {
	extensions []TLSExtensionJSON
}

func (e *TLSExtensionsJSONUnmarshaler) UnmarshalJSON(jsonStr []byte) error {
	var accepters []tlsExtensionJSONAccepter
	if err := json.Unmarshal(jsonStr, &accepters); err != nil {
		return err
	}

	var exts []TLSExtensionJSON = make([]TLSExtensionJSON, 0, len(accepters))
	for _, accepter := range accepters {
		var extID uint16 = accepter.idNameObj.ID
		var extName string = accepter.idNameObj.Name

		// get extension type from ID
		var ext TLSExtension = ExtensionFromID(extID)
		if ext == nil {
			// fallback to generic extension
			ext = genericExtension(extID, extName)
		}

		if extJsonCompatible, ok := ext.(TLSExtensionJSON); ok {
			exts = append(exts, extJsonCompatible)
		} else {
			return fmt.Errorf("extension %d (%s) is not JSON compatible", extID, extName)
		}
	}

	// unmashal extensions
	for idx, ext := range exts {
		// json.Unmarshal will call the UnmarshalJSON method of the extension
		if err := json.Unmarshal(accepters[idx].jsonStr, ext); err != nil {
			return err
		}
	}

	e.extensions = exts
	return nil
}

func genericExtension(id uint16, name string) TLSExtension {
	var warningMsg string = "WARNING: extension "
	warningMsg += fmt.Sprintf("%d ", id)
	if len(name) > 0 {
		warningMsg += fmt.Sprintf("(%s) ", name)
	}
	warningMsg += "is falling back to generic extension"
	warningMsg += "\n"

	// fallback to generic extension
	return &GenericExtension{Id: id}
}

type tlsExtensionJSONAccepter struct {
	idNameObj struct {
		ID   uint16 `json:"id"`
		Name string `json:"name,omitempty"`
	}
	jsonStr []byte
}

func (t *tlsExtensionJSONAccepter) UnmarshalJSON(jsonStr []byte) error {
	t.jsonStr = make([]byte, len(jsonStr))
	copy(t.jsonStr, jsonStr)
	return json.Unmarshal(jsonStr, &t.idNameObj)
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
		{"id": 0x7a7a, "name": "GREASE", "data": []}, // grease, id could be any 0xNaNa where N in 0~f, data is an optional byte slice
		{"id": 0x0000, "name": "server_name"}, // SNI may(should) have data but will be ignored
		{"id": 0x0017, "name": "extended_master_secret"}, // always no data
		{"id": 0xff01, "name": "renegotiation_info", "renegotiated_connection": []}, // no data for initial ClientHello
		{"id": 0x000a, "name": "supported_groups", "named_group_list": [
			{"id": 0x1a1a, "name": "GREASE"},
			{"id": 0x001d, "name": "x25519"},
			{"id": 0x0017, "name": "secp256r1"},
			{"id": 0x0018, "name": "secp384r1"}
		]},
		{"id": 0x000b, "name": "ec_point_formats", "ec_point_format_list": [
			{"id": 0x00, "name": "uncompressed"},
		]},
		{"id": 0x0023, "name": "session_ticket"}, // always no data
		{"id": 0x0010, "name": "application_layer_protocol_negotiation", "protocol_name_list": [
			"h2",
			"http/1.1"
		]},
		{"id": 0x0005, "name": "status_request"}, // always no data
		{"id": 0x000d, "name": "signature_algorithms", "supported_signature_algorithms": [
			{"id": 0x0403, "name": "ecdsa_secp256r1_sha256"},
			{"id": 0x0804, "name": "rsa_pss_rsae_sha256"},
			...
		]},
		...
	]
}
*/
