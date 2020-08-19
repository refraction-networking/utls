// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"testing"
)

func TestUTLSIsGrease(t *testing.T) {

	var testMap = []struct {
		version  uint16
		isGREASE bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a1a, false},
		{0x2a2a, true},
		{0x1234, false},
		{0x1a2a, false},
		{0xdeed, false},
		{0xb1b1, false},
		{0x0b0b, false},
	}

	for _, testCase := range testMap {
		if isGREASEUint16(testCase.version) != testCase.isGREASE {
			t.Errorf("misidentified GREASE: testing %x, isGREASE: %v", testCase.version, isGREASEUint16(testCase.version))
		}
	}
}
