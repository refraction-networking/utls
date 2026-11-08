// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"
)

func edge156Fixture(t *testing.T) []byte {
	t.Helper()
	text, err := os.ReadFile("testdata/edge156_clienthello.hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The comparison and its normalization are the Chrome 155 ones, see
// u_chrome155_test.go.
func TestEdge156CapturedClientHello(t *testing.T) {
	if HelloEdge_Auto != HelloEdge_156 {
		t.Fatalf("HelloEdge_Auto = %s, want %s", HelloEdge_Auto.Str(), HelloEdge_156.Str())
	}
	want, _, captured := chrome155ParseWire(t, edge156Fixture(t))
	if _, ok := captured[0xca34]; ok {
		t.Fatal("the Edge capture carries trust_anchors")
	}
	client := chrome155Build(t, HelloEdge_156, chrome155FixtureServerName(t, captured), nil)
	got, _, generated := chrome155ParseWire(t, client.HandshakeState.Hello.Raw)
	if !equalWire(want, got) {
		t.Errorf("generated ClientHello differs from the Edge 156 capture:\n got: %+v\nwant: %+v", got, want)
	}
	if _, ok := generated[41]; ok {
		t.Fatal("fresh profile unexpectedly offers pre_shared_key")
	}
}

// Edge 156 is Chrome 155 without trust_anchors, so removing that one
// extension from the Chrome capture must give the Edge capture.
func TestEdge156IsChrome155WithoutTrustAnchors(t *testing.T) {
	edge, _, _ := chrome155ParseWire(t, edge156Fixture(t))
	chrome, _, _ := chrome155ParseWire(t, chrome155Fixture(t))
	delete(chrome.Extensions, 0xca34)
	delete(chrome.Extensions, 0) // the two captures went to different hosts
	delete(edge.Extensions, 0)
	if !equalWire(edge, chrome) {
		t.Errorf("Edge 156 and Chrome 155 differ beyond trust_anchors:\nedge:   %+v\nchrome: %+v", edge, chrome)
	}
}

func TestEdge156PresetDoesNotTouchChrome155(t *testing.T) {
	if _, err := UTLSIdToSpec(HelloEdge_156); err != nil {
		t.Fatal(err)
	}
	spec, err := UTLSIdToSpec(HelloChrome_155)
	if err != nil {
		t.Fatal(err)
	}
	chrome155TrustAnchors(t, spec.Extensions)
}

func equalWire(a, b chrome155WireHello) bool {
	return reflect.DeepEqual(a, b)
}
