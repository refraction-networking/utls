package tls

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"

	"github.com/refraction-networking/utls/internal/quicvarint"
)

const (
	// RFC IDs
	max_idle_timeout                    uint64 = 0x1
	max_udp_payload_size                uint64 = 0x3
	initial_max_data                    uint64 = 0x4
	initial_max_stream_data_bidi_local  uint64 = 0x5
	initial_max_stream_data_bidi_remote uint64 = 0x6
	initial_max_stream_data_uni         uint64 = 0x7
	initial_max_streams_bidi            uint64 = 0x8
	initial_max_streams_uni             uint64 = 0x9
	max_ack_delay                       uint64 = 0xb
	disable_active_migration            uint64 = 0xc
	active_connection_id_limit          uint64 = 0xe
	initial_source_connection_id        uint64 = 0xf
	version_information                 uint64 = 0x11 // RFC 9368
	padding                             uint64 = 0x15
	max_datagram_frame_size             uint64 = 0x20 // RFC 9221
	grease_quic_bit                     uint64 = 0x2ab2

	// Legacy IDs from draft
	version_information_legacy uint64 = 0xff73db // draft-ietf-quic-version-negotiation-13 and early
)

// TransportParameters is an ordered list of QUIC transport parameters, as carried by
// QUICTransportParametersExtension. Slice order is wire order: RFC 9000 §7.4 lets a
// client send them in any order, and real clients differ (Chrome randomizes per
// handshake), so the order is itself a fingerprinting signal.
type TransportParameters []TransportParameter

// Marshal serializes the parameters into the extension body: each one as its varint ID,
// its varint value length, then its value bytes, concatenated in slice order.
func (tps TransportParameters) Marshal() []byte {
	var b []byte
	for _, tp := range tps {
		b = quicvarint.Append(b, tp.ID())
		b = quicvarint.Append(b, uint64(len(tp.Value())))
		b = append(b, tp.Value()...)
	}
	return b
}

// TransportParameter represents a QUIC transport parameter.
//
// Caller will write the following to the wire:
//
//	var b []byte
//	b = quicvarint.Append(b, ID())
//	b = quicvarint.Append(b, len(Value()))
//	b = append(b, Value())
//
// Therefore Value() should return the exact bytes to be written to the wire AFTER the length field,
// i.e., the bytes MAY be a Variable Length Integer per RFC depending on the type of the transport
// parameter, but MUST NOT including the length field unless the parameter is defined so.
type TransportParameter interface {
	ID() uint64
	Value() []byte
}

// GREASETransportParameter is a reserved ("GREASE") transport parameter: an ID of
// 31*N+27 carrying meaningless bytes, which conformant servers must ignore (RFC 9000
// §18.1). Clients send one to keep servers tolerant of unknown parameters, so its
// presence — and the fact that its ID and length differ between handshakes — is part of
// a realistic fingerprint.
//
// Both random draws are made lazily and then cached in the struct: ID() picks a GREASE
// ID and stores it in IdOverride, Value() fills ValueOverride with Length random bytes.
// After either is called the parameter is frozen, so reusing one value across
// connections repeats the same ID and bytes. Build a fresh parameter per connection to
// vary them, and vary Length too if the client being mimicked does.
type GREASETransportParameter struct {
	IdOverride    uint64 // if set to a valid GREASE ID, use this instead of randomly generated one.
	Length        uint16 // if len(ValueOverride) == 0, will generate random data of this size.
	ValueOverride []byte // if len(ValueOverride) > 0, use this instead of random bytes.
}

const (
	GREASE_MAX_MULTIPLIER = (0x3FFFFFFFFFFFFFFF - 27) / 31
)

// IsGREASEID returns true if id is a valid GREASE ID for
// transport parameters.
func (GREASETransportParameter) IsGREASEID(id uint64) bool {
	return id >= 27 && (id-27)%31 == 0
}

// GetGREASEID returns a random valid GREASE ID for transport parameters.
func (GREASETransportParameter) GetGREASEID() uint64 {
	max := big.NewInt(GREASE_MAX_MULTIPLIER)

	randMultiply, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 27
	}

	return 27 + randMultiply.Uint64()*31
}

func (g *GREASETransportParameter) ID() uint64 {
	if !g.IsGREASEID(g.IdOverride) {
		g.IdOverride = g.GetGREASEID()
	}
	return g.IdOverride
}

func (g *GREASETransportParameter) Value() []byte {
	if len(g.ValueOverride) == 0 {
		g.ValueOverride = make([]byte, g.Length)
		rand.Read(g.ValueOverride)
	}
	return g.ValueOverride
}

type MaxIdleTimeout uint64 // in milliseconds

func (MaxIdleTimeout) ID() uint64 {
	return max_idle_timeout
}

func (m MaxIdleTimeout) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(m))
}

type MaxUDPPayloadSize uint64

func (MaxUDPPayloadSize) ID() uint64 {
	return max_udp_payload_size
}

func (m MaxUDPPayloadSize) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(m))
}

type InitialMaxData uint64

func (InitialMaxData) ID() uint64 {
	return initial_max_data
}

func (i InitialMaxData) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamDataBidiLocal uint64

func (InitialMaxStreamDataBidiLocal) ID() uint64 {
	return initial_max_stream_data_bidi_local
}

func (i InitialMaxStreamDataBidiLocal) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamDataBidiRemote uint64

func (InitialMaxStreamDataBidiRemote) ID() uint64 {
	return initial_max_stream_data_bidi_remote
}

func (i InitialMaxStreamDataBidiRemote) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamDataUni uint64

func (InitialMaxStreamDataUni) ID() uint64 {
	return initial_max_stream_data_uni
}

func (i InitialMaxStreamDataUni) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamsBidi uint64

func (InitialMaxStreamsBidi) ID() uint64 {
	return initial_max_streams_bidi
}

func (i InitialMaxStreamsBidi) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamsUni uint64

func (InitialMaxStreamsUni) ID() uint64 {
	return initial_max_streams_uni
}

func (i InitialMaxStreamsUni) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type MaxAckDelay uint64

func (MaxAckDelay) ID() uint64 {
	return max_ack_delay
}

func (m MaxAckDelay) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(m))
}

type DisableActiveMigration struct{}

func (*DisableActiveMigration) ID() uint64 {
	return disable_active_migration
}

// Its Value MUST ALWAYS be empty.
func (*DisableActiveMigration) Value() []byte {
	return []byte{}
}

type ActiveConnectionIDLimit uint64

func (ActiveConnectionIDLimit) ID() uint64 {
	return active_connection_id_limit
}

func (a ActiveConnectionIDLimit) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(a))
}

type InitialSourceConnectionID []byte // if empty, will be set to the Connection ID used for the Initial packet.

func (InitialSourceConnectionID) ID() uint64 {
	return initial_source_connection_id
}

func (i InitialSourceConnectionID) Value() []byte {
	return []byte(i)
}

// VersionInformation is the version_information transport parameter (RFC 9368): the
// QUIC version the client chose, followed by every version it would accept. Chrome
// sends it with a GREASE version first in the available list:
//
//	&VersionInformation{
//		ChoosenVersion:    VERSION_1,
//		AvailableVersions: []uint32{VERSION_GREASE, VERSION_1},
//	}
type VersionInformation struct {
	// ChoosenVersion is the version of the connection being established, written
	// first in the parameter value. Note the spelling: ChoosenVersion, not
	// ChosenVersion.
	ChoosenVersion uint32

	// AvailableVersions lists the versions the client is willing to use, in wire
	// order. A VERSION_GREASE entry is a placeholder, not a literal: Value replaces
	// each occurrence with a freshly drawn random reserved version, so the bytes
	// differ every time the parameter is serialized.
	AvailableVersions []uint32 // Also known as "Other Versions" in early drafts.

	LegacyID bool // If true, use the legacy-assigned ID (0xff73db) instead of the RFC-assigned one (0x11).
}

const (
	VERSION_NEGOTIATION uint32 = 0x00000000 // rfc9000
	VERSION_1           uint32 = 0x00000001 // rfc9000
	VERSION_2           uint32 = 0x6b3343cf // rfc9369

	// VERSION_GREASE is a placeholder for "a reserved version here", not a version to
	// send literally. In VersionInformation.AvailableVersions it is replaced at
	// serialization time by GetGREASEVersion's random draw from the 0x?a?a?a?a family
	// (RFC 9000 §15), which servers must ignore.
	VERSION_GREASE uint32 = 0x0a0a0a0a // -> 0x?a?a?a?a
)

func (v *VersionInformation) ID() uint64 {
	if v.LegacyID {
		return version_information_legacy
	}
	return version_information
}

func (v *VersionInformation) Value() []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, v.ChoosenVersion)
	for _, version := range v.AvailableVersions {
		if version != VERSION_GREASE {
			b = binary.BigEndian.AppendUint32(b, version)
		} else {
			b = binary.BigEndian.AppendUint32(b, v.GetGREASEVersion())
		}
	}
	return b
}

// GetGREASEVersion returns a random reserved ("GREASE") QUIC version matching the
// 0x?a?a?a?a pattern. It draws fresh randomness on every call — Value calls it once per
// VERSION_GREASE entry — so the version differs between handshakes, as real clients'
// do. It falls back to the fixed VERSION_GREASE if the system RNG fails.
func (*VersionInformation) GetGREASEVersion() uint32 {
	// get a random uint32
	max := big.NewInt(math.MaxUint32)
	randVal, err := rand.Int(rand.Reader, max)
	if err != nil {
		return VERSION_GREASE
	}

	// Reserved ("GREASE") versions follow the pattern 0x?a?a?a?a (RFC 9000 §15), i.e. the
	// low nibble of every byte must be exactly 0xa. Those nibbles have to be masked off
	// before they are set: OR-ing alone leaves the random bits underneath, so a random
	// nibble of 0x5 becomes 0xf rather than 0xa and the version is not a GREASE value at
	// all. Only 1 draw in 256 came out valid before the mask was added.
	return uint32(randVal.Uint64()&math.MaxUint32)&0xf0f0f0f0 | 0x0a0a0a0a
}

type PaddingTransportParameter []byte

func (PaddingTransportParameter) ID() uint64 {
	return padding
}

func (p PaddingTransportParameter) Value() []byte {
	return p
}

type MaxDatagramFrameSize uint64

func (MaxDatagramFrameSize) ID() uint64 {
	return max_datagram_frame_size
}

func (m MaxDatagramFrameSize) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(m))
}

type GREASEQUICBit struct{}

func (*GREASEQUICBit) ID() uint64 {
	return grease_quic_bit
}

// Its Value MUST ALWAYS be empty.
func (*GREASEQUICBit) Value() []byte {
	return []byte{}
}

// FakeQUICTransportParameter is the escape hatch for any transport parameter this
// package has no named type for: it sends Id with Val as its value, verbatim. Use it
// for vendor-specific parameters — e.g. Google's google_quic_version (0x4752),
// google_connection_options (0x3128) and google_initial_rtt (0x3127) — and for any
// parameter whose value must be exact bytes.
//
// Val is the value *after* the length field, so a numeric parameter must already be
// varint-encoded (quicvarint.Append, or a hand-written 0x40-prefixed 2-byte form). Id
// must be set; ID panics on a zero Id rather than silently emitting parameter 0.
type FakeQUICTransportParameter struct {
	Id  uint64
	Val []byte
}

func (f *FakeQUICTransportParameter) ID() uint64 {
	if f.Id == 0 {
		panic("it is not allowed to use a FakeQUICTransportParameter without setting the ID")
	}
	return f.Id
}

func (f *FakeQUICTransportParameter) Value() []byte {
	return f.Val
}
