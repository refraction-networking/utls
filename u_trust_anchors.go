package tls

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// TrustAnchorsExtension implements the draft trust_anchors ClientHello extension
// (0xca34). Each TrustAnchorID contains 1 to 255 bytes; an empty list is valid.
// The IDs are advertised to the server and do not change Config.RootCAs.
type TrustAnchorsExtension struct {
	TrustAnchorIDs [][]byte `json:"trust_anchor_ids"`
}

func (e *TrustAnchorsExtension) writeToUConn(_ *UConn) error {
	return nil
}

func (e *TrustAnchorsExtension) Len() int {
	n := 6 // Extension header and RequestedTrustAnchorList length.
	for _, id := range e.TrustAnchorIDs {
		n += 1 + len(id)
	}
	return n
}

func (e *TrustAnchorsExtension) validate() error {
	listLen := 0
	for _, id := range e.TrustAnchorIDs {
		if len(id) == 0 || len(id) > 255 {
			return fmt.Errorf("tls: trust anchor ID length %d is outside 1..255", len(id))
		}
		listLen += 1 + len(id)
		// The extension_data length also includes the two-byte list length.
		if listLen > (1<<16)-3 {
			return errors.New("tls: trust anchors extension data exceeds 65535 bytes")
		}
	}
	return nil
}

func (e *TrustAnchorsExtension) Read(b []byte) (int, error) {
	if err := e.validate(); err != nil {
		return 0, err
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	listLen := e.Len() - 6
	b[0] = byte(utlsExtensionTrustAnchors >> 8)
	b[1] = byte(utlsExtensionTrustAnchors & 0xff)
	b[2] = byte((2 + listLen) >> 8)
	b[3] = byte(2 + listLen)
	b[4] = byte(listLen >> 8)
	b[5] = byte(listLen)
	offset := 6
	for _, id := range e.TrustAnchorIDs {
		b[offset] = byte(len(id))
		offset++
		offset += copy(b[offset:], id)
	}
	return offset, io.EOF
}

func (e *TrustAnchorsExtension) Write(b []byte) (int, error) {
	if len(b) > (1<<16)-1 {
		return 0, errors.New("tls: trust anchors extension data exceeds 65535 bytes")
	}
	extData := cryptobyte.String(b)
	var list cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&list) || !extData.Empty() {
		return 0, errors.New("tls: unable to read trust anchors extension data")
	}
	ids := make([][]byte, 0)
	for !list.Empty() {
		var id cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&id) || id.Empty() {
			return 0, errors.New("tls: unable to read trust anchor ID")
		}
		ids = append(ids, append([]byte(nil), id...))
	}
	e.TrustAnchorIDs = ids
	return len(b), nil
}

func (e *TrustAnchorsExtension) UnmarshalJSON(data []byte) error {
	var value struct {
		TrustAnchorIDs [][]byte `json:"trust_anchor_ids"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parsed := TrustAnchorsExtension{TrustAnchorIDs: value.TrustAnchorIDs}
	if err := parsed.validate(); err != nil {
		return err
	}
	e.TrustAnchorIDs = parsed.TrustAnchorIDs
	return nil
}
