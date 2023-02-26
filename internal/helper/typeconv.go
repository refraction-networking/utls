package helper

import (
	"bytes"
	"encoding/binary"
	"io"
)

func ReadUint16(r io.Reader, v *uint16) error {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	*v = binary.BigEndian.Uint16(buf[:])
	return nil
}

// Uint8to16 converts a slice of uint8 to a slice of uint16.
// e.g. []uint8{0x00, 0x01, 0x00, 0x02} -> []uint16{0x0001, 0x0002}
func Uint8to16(in []uint8) ([]uint16, error) {
	reader := bytes.NewReader(in)
	var out []uint16
	for {
		var v uint16
		err := ReadUint16(reader, &v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
