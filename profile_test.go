// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
)

var updateProfiles = flag.Bool("update-profiles", false, "rewrite testdata/profiles golden files")

func TestProfileRoundTripAllPresets(t *testing.T) {
	for _, id := range allPresets() {
		if id == HelloGolang {
			continue
		}
		p, err := ExportProfile(id)
		if err != nil {
			t.Fatalf("%s: %v", id.Str(), err)
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("%s: %v", id.Str(), err)
		}
		q, err := ParseProfile(b)
		if err != nil {
			t.Fatalf("%s: %v\n%s", id.Str(), err, b)
		}
		pid := q.ClientHelloID()
		a, b2 := renderHello(t, id, "utls.test"), renderHello(t, pid, "utls.test")
		if id.kind == kindRandomized {
			// A fresh random spec per call: compare the profile with itself.
			j1, _, _ := JA3(b2)
			j2, _, _ := JA3(renderHello(t, pid, "utls.test"))
			if j1 != j2 {
				t.Fatalf("%s: profile of a randomized spec is not stable", id.Str())
			}
		} else if p.Shuffle == "" {
			j1, _, _ := JA3(a)
			j2, _, _ := JA3(b2)
			if j1 != j2 {
				t.Fatalf("%s: JA3 changed through the profile\n%s\n%s", id.Str(), j1, j2)
			}
		} else {
			j1, _ := JA4(a)
			j2, _ := JA4(b2)
			if j1 != j2 {
				t.Fatalf("%s: JA4 changed through the profile: %s %s", id.Str(), j1, j2)
			}
		}
		handshakeStd(t, pid, clientConfig(t), serverConfig(t), nil).ok(t)
	}
}

// The profile files in testdata/profiles are the format's compatibility
// contract: they must keep parsing to the same fingerprint.
func TestProfileGoldenFiles(t *testing.T) {
	for _, tc := range []struct {
		file string
		id   ClientHelloID
	}{
		{"firefox158.json", HelloFirefox_158},
		{"android11okhttp.json", HelloAndroid_11_OkHttp},
	} {
		path := "testdata/profiles/" + tc.file
		p, _ := ExportProfile(tc.id)
		want, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, '\n')
		if *updateProfiles {
			os.MkdirAll("testdata/profiles", 0o755)
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the preset no longer matches its golden profile (run with -update-profiles after review)", tc.file)
		}
		q, err := ParseProfile(got)
		if err != nil {
			t.Fatal(err)
		}
		j1, _, _ := JA3(renderHello(t, q.ClientHelloID(), "utls-capture.test"))
		j2, _, _ := JA3(renderHello(t, tc.id, "utls-capture.test"))
		if j1 != j2 {
			t.Fatalf("%s: %s vs %s", tc.file, j1, j2)
		}
	}
	// The Firefox 158 profile reproduces the real capture's JA4 too.
	b, _ := os.ReadFile("testdata/profiles/firefox158.json")
	p, _ := ParseProfile(b)
	j1, _ := JA4(renderHello(t, p.ClientHelloID(), "utls-capture.test"))
	j2, _ := JA4(loadCapture(t, "firefox158_clienthello.hex"))
	if j1 != j2 {
		t.Fatalf("profile JA4 %s, capture %s", j1, j2)
	}
}

func TestProfileErrors(t *testing.T) {
	good := `{"format":"utls-profile","version":1,"client":"X","client_version":"1","cipher_suites":[4865],"compression_methods":[0],"extensions":[{"type":"server_name"},{"type":"supported_versions","params":{"Versions":[772]}},{"type":"supported_groups","params":{"Curves":[29]}},{"type":"key_share","params":{"KeyShares":[{"Group":29}]}},{"type":"signature_algorithms","params":{"SupportedSignatureAlgorithms":[1027]}}]}`
	p, err := ParseProfile([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	handshakeStd(t, p.ClientHelloID(), clientConfig(t), serverConfig(t), nil).ok(t)
	for name, bad := range map[string]string{
		"format":          strings.Replace(good, `"utls-profile"`, `"other"`, 1),
		"version":         strings.Replace(good, `"version":1`, `"version":2`, 1),
		"unknown field":   strings.Replace(good, `"client":"X"`, `"client":"X","extra":1`, 1),
		"unknown type":    strings.Replace(good, `"server_name"`, `"next_protocol_negotiation"`, 1),
		"unknown param":   strings.Replace(good, `"Versions":[772]`, `"Versions":[772],"Foo":1`, 1),
		"paramless":       strings.Replace(good, `{"type":"server_name"}`, `{"type":"server_name","params":{"x":1}}`, 1),
		"duplicate":       strings.Replace(good, `{"type":"server_name"}`, `{"type":"server_name"},{"type":"server_name"}`, 1),
		"padding style":   strings.Replace(good, `{"type":"server_name"}`, `{"type":"server_name"},{"type":"padding","params":{"style":"random"}}`, 1),
		"compression":     strings.Replace(good, `[0]`, `[256]`, 1),
		"shuffle":         strings.Replace(good, `"client":"X"`, `"client":"X","shuffle":"firefox"`, 1),
		"trailing":        good + `{}`,
		"not json":        `{`,
	} {
		if _, err := ParseProfile([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	custom := &ClientHelloSpec{CipherSuites: []uint16{4865}, CompressionMethods: []uint8{0}, Extensions: []TLSExtension{
		&UtlsPaddingExtension{GetPaddingLen: func(int) (int, bool) { return 0, false }}}}
	if _, err := json.Marshal(&Profile{Spec: custom}); err == nil {
		t.Error("custom padding function marshaled")
	}
}
