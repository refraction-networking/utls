// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// runParsers runs every parser of untrusted ClientHello bytes on b and fails
// if one panics or does not return within a second. (Go's fuzzer has no
// per-input timeout: a hanging input just stalls every worker silently.)
func runParsers(t *testing.T, b []byte) {
	t.Helper()
	done := make(chan string, 1)
	stage := make(chan string, 8)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Sprint("panic: ", r)
			}
		}()
		stage <- "ParseClientHello"
		s, err := ParseClientHello(b)
		stage <- "JA3"
		JA3(b)
		stage <- "JA4"
		JA4(b)
		if err == nil {
			stage <- "Validate/Clone"
			s.Validate()
			s.Clone()
		}
		done <- ""
	}()
	last := ""
	timeout := time.After(time.Second)
	for {
		select {
		case last = <-stage:
		case msg := <-done:
			if msg != "" {
				t.Fatalf("%s on %s", msg, hex.EncodeToString(b))
			}
			return
		case <-timeout:
			t.Fatalf("%s did not return on %s", last, hex.EncodeToString(b))
		}
	}
}

// Regression: JA3 looped forever (appending without bound) on an odd-length
// supported_versions list, found when FuzzParseClientHello stalled.
func TestJA3OddSupportedVersions(t *testing.T) {
	raw := loadCapture(t, "firefox158_clienthello.hex")
	i := bytes.Index(raw, []byte{0x00, 0x2b, 0x00, 0x05, 0x04})
	if i < 0 {
		t.Fatal("supported_versions not found in the capture")
	}
	raw[i+4] = 3 // list length 3: one and a half versions
	runParsers(t, raw)
	if _, _, err := JA3(raw); err == nil {
		t.Fatal("malformed supported_versions accepted by JA3")
	}
}

// Deterministic mutation sweep over real captures: every parser terminates.
func TestParsersTerminateOnMutatedHellos(t *testing.T) {
	seeds := [][]byte{
		loadCapture(t, "chrome155_clienthello.hex"),
		loadCapture(t, "chrome156_clienthello.0.hex"),
		loadCapture(t, "firefox158_clienthello.hex"),
		loadCapture(t, "safari27_clienthello.0.hex"),
	}
	r := rand.New(rand.NewPCG(1, 2))
	n := 50000
	if testing.Short() {
		n = 5000
	}
	for range n {
		b := bytes.Clone(seeds[r.IntN(len(seeds))])
		for range 1 + r.IntN(4) {
			switch r.IntN(4) {
			case 0:
				b[r.IntN(len(b))] = byte(r.IntN(256))
			case 1:
				b = b[:r.IntN(len(b))+1]
			case 2:
				b[r.IntN(len(b))] = 0
			case 3:
				b[r.IntN(len(b))] = 0xff
			}
		}
		runParsers(t, b)
	}
}
