package tls

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"github.com/dsnet/compress/brotli"
	"golang.org/x/crypto/cryptobyte"
)

const (
	// TEMPORARY: draft-ietf-tls-certificate-compression-04
	typeCompressedCertificate    uint8  = 25
	extensionCompressCertificate uint16 = 27
)

type CompressCertificateExtension struct {
	Algorithms []CertCompressionAlgo
}

func (e *CompressCertificateExtension) writeToUConn(uc *UConn) error {
	uc.extCompressCerts = true
	return nil
}

func (e *CompressCertificateExtension) Len() int {
	return 4 + 1 + (2 * len(e.Algorithms))
}

func (e *CompressCertificateExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	extLen := 2 * len(e.Algorithms)
	if extLen > 255 {
		return 0, errors.New("too many supported algorithms")
	}

	b[0] = byte(extensionCompressCertificate >> 8)
	b[1] = byte(extensionCompressCertificate)
	b[2] = byte((extLen + 1) >> 8)
	b[3] = byte((extLen + 1))
	b[4] = byte(extLen)

	i := 5
	for _, alg := range e.Algorithms {
		b[i] = byte(alg >> 8)
		b[i+1] = byte(alg)
		i += 2
	}
	return e.Len(), io.EOF
}

type compressedCertificateMsg struct {
	raw []byte

	algorithm                    CertCompressionAlgo
	uncompressedLength           uint32
	compressedCertificateMessage []byte
}

func (m *compressedCertificateMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	panic("utls: compressedCertificateMsg.marshal() not actually implemented")
}

func (m *compressedCertificateMsg) unmarshal(data []byte) bool {
	m.raw = append([]byte{}, data...)

	s := cryptobyte.String(data[4:])

	var algID uint16
	if !s.ReadUint16(&algID) {
		return false
	}
	if !s.ReadUint24(&m.uncompressedLength) {
		return false
	}
	if !readUint24LengthPrefixed(&s, &m.compressedCertificateMessage) {
		return false
	}
	m.algorithm = CertCompressionAlgo(algID)

	return true
}

func (m *compressedCertificateMsg) toCertificateMsg() (*certificateMsgTLS13, error) {
	var (
		decompressed []byte
		rd           io.ReadCloser
		err          error
	)

	if m.uncompressedLength > 1<<24 {
		return nil, fmt.Errorf("utls: oversized decompressed certificate length")
	}

	compressed := bytes.NewBuffer(m.compressedCertificateMessage)
	switch m.algorithm {
	case CertCompressionZlib:
		rd, err = zlib.NewReader(compressed)
	case CertCompressionBrotli:
		rd, err = brotli.NewReader(compressed, nil)
	default:
		return nil, fmt.Errorf("utls: unknown certificate compression algorithm: %v", m.algorithm)
	}
	if err != nil {
		return nil, err
	}
	defer rd.Close()

	decompressed = make([]byte, m.uncompressedLength)
	if _, err = io.ReadFull(rd, decompressed); err != nil {
		return nil, err
	}

	// Enforce the length just to be sure.
	length := len(decompressed)
	if length != int(m.uncompressedLength) {
		return nil, fmt.Errorf("utls: invalid decompressed certificate length: %v", length)
	}

	// Prepend the type and record length to the synthetic Certificate message.
	// Technically this can be 4 bytes of 0x00 since nothing examines it, but
	// being correct doesn't hurt.
	decompressed = append([]byte{
		typeCertificate,
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}, decompressed...)

	var mm certificateMsgTLS13
	if !mm.unmarshal(decompressed) {
		return nil, fmt.Errorf("utls: failed to unmarshal decompressed certificateMsgTLS13")
	}

	return &mm, nil
}
