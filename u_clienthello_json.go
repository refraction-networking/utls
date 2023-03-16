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

func (chsju *ClientHelloSpecJSONUnmarshaler) ClientHelloSpec() ClientHelloSpec {
	return ClientHelloSpec{
		CipherSuites:       chsju.CipherSuites.CipherSuites(),
		CompressionMethods: chsju.CompressionMethods.CompressionMethods(),
		Extensions:         chsju.Extensions.Extensions(),
		TLSVersMin:         chsju.TLSVersMin,
		TLSVersMax:         chsju.TLSVersMax,
	}
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

func (c *CipherSuitesJSONUnmarshaler) CipherSuites() []uint16 {
	return c.cipherSuites
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

func (c *CompressionMethodsJSONUnmarshaler) CompressionMethods() []uint8 {
	return c.compressionMethods
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
		var extID uint16 = accepter.idDescObj.ID
		var extName string = accepter.idDescObj.Description

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

func (e *TLSExtensionsJSONUnmarshaler) Extensions() []TLSExtension {
	var exts []TLSExtension = make([]TLSExtension, 0, len(e.extensions))
	for _, ext := range e.extensions {
		exts = append(exts, ext)
	}
	return exts
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
	idDescObj struct {
		ID          uint16 `json:"id"`
		Description string `json:"description,omitempty"`
	}
	jsonStr []byte
}

func (t *tlsExtensionJSONAccepter) UnmarshalJSON(jsonStr []byte) error {
	t.jsonStr = make([]byte, len(jsonStr))
	copy(t.jsonStr, jsonStr)
	return json.Unmarshal(jsonStr, &t.idDescObj)
}
