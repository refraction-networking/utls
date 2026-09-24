package tls

import (
	"encoding/binary"
	"testing"
)

// isReservedQUICVersion reports whether v follows the reserved "GREASE" version pattern
// 0x?a?a?a?a from RFC 9000 §15 — the low nibble of every byte is 0xa.
func isReservedQUICVersion(v uint32) bool {
	return v&0x0f0f0f0f == 0x0a0a0a0a
}

// TestGetGREASEVersion pins that generated GREASE versions actually match the reserved
// pattern. GetGREASEVersion used to OR a random uint32 with 0x0a0a0a0a without first
// masking the low nibbles, so those nibbles could only ever be 0xa, 0xb, 0xe or 0xf —
// leaving just 1 draw in 256 a genuine GREASE value, and making the QUIC
// version_information transport parameter a reliable "this is not a real browser" signal.
func TestGetGREASEVersion(t *testing.T) {
	const draws = 4096

	var vi VersionInformation
	highNibbles := make(map[uint32]bool)
	for i := 0; i < draws; i++ {
		v := vi.GetGREASEVersion()
		if !isReservedQUICVersion(v) {
			t.Fatalf("GetGREASEVersion() = %#08x, which is not a 0x?a?a?a?a version", v)
		}
		highNibbles[v&0xf0f0f0f0] = true
	}

	// The bits that are not pinned to 0xa must still be random. Any fixed return value
	// (e.g. always the VERSION_GREASE fallback) would be a GREASE version but a constant,
	// which is its own fingerprint.
	if len(highNibbles) < draws/2 {
		t.Errorf("GetGREASEVersion() produced only %d distinct values in %d draws", len(highNibbles), draws)
	}
}

// TestVersionInformationGREASESubstitution covers the sentinel mechanism: VERSION_GREASE
// in AvailableVersions is replaced with a freshly generated GREASE version on every
// Value() call, and nothing else in the parameter is touched.
func TestVersionInformationGREASESubstitution(t *testing.T) {
	vi := &VersionInformation{
		ChoosenVersion:    VERSION_1,
		AvailableVersions: []uint32{VERSION_GREASE, VERSION_1, VERSION_2},
	}

	readVersions := func() []uint32 {
		val := vi.Value()
		if len(val)%4 != 0 {
			t.Fatalf("Value() returned %d bytes, want a multiple of 4", len(val))
		}
		versions := make([]uint32, 0, len(val)/4)
		for i := 0; i < len(val); i += 4 {
			versions = append(versions, binary.BigEndian.Uint32(val[i:i+4]))
		}
		return versions
	}

	first := readVersions()
	if len(first) != 4 { // ChoosenVersion + 3 available
		t.Fatalf("Value() encoded %d versions, want 4", len(first))
	}
	if first[0] != VERSION_1 {
		t.Errorf("ChoosenVersion on the wire = %#08x, want %#08x", first[0], VERSION_1)
	}
	if !isReservedQUICVersion(first[1]) {
		t.Errorf("substituted GREASE version = %#08x, which is not a 0x?a?a?a?a version", first[1])
	}
	if first[2] != VERSION_1 || first[3] != VERSION_2 {
		t.Errorf("non-GREASE available versions were rewritten: got %#08x, %#08x", first[2], first[3])
	}

	// The sentinel is replaced per call, so a spec reused for another connection does not
	// repeat the same GREASE version. A collision is possible (1 in 2^28 of the free
	// bits), so allow a few retries rather than asserting on a single pair.
	var differed bool
	for i := 0; i < 8 && !differed; i++ {
		differed = readVersions()[1] != first[1]
	}
	if !differed {
		t.Error("Value() returned the same GREASE version on every call, want a fresh draw")
	}

	// The sentinel itself must survive in the struct, so later calls keep substituting.
	if vi.AvailableVersions[0] != VERSION_GREASE {
		t.Errorf("AvailableVersions[0] = %#08x, want the VERSION_GREASE sentinel", vi.AvailableVersions[0])
	}
}

// TestVersionGREASEConstantIsReserved guards the sentinel/fallback value itself.
func TestVersionGREASEConstantIsReserved(t *testing.T) {
	if !isReservedQUICVersion(VERSION_GREASE) {
		t.Errorf("VERSION_GREASE = %#08x, which is not a 0x?a?a?a?a version", VERSION_GREASE)
	}
}
