// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ClientHelloID names a fingerprint: a built-in preset, HelloGolang (the stock
// crypto/tls ClientHello), HelloCustom (supply a spec with ApplyPreset), a
// seeded randomized fingerprint, or a CustomFingerprint. It is a comparable
// value; Str is a stable name for logs and configuration.
type ClientHelloID struct {
	Client  string
	Version string

	kind    idKind
	factory *specFactory       // presets / custom (pointer: comparable, GC-able)
	seed    *[32]byte          // randomized
	weights *RandomizedWeights // randomized
}

// specFactory holds a factory; IDs compare by holder identity.
type specFactory struct {
	f func() (*ClientHelloSpec, error)
}

func preset(client, version string, f func() (*ClientHelloSpec, error)) ClientHelloID {
	return ClientHelloID{Client: client, Version: version, kind: kindPreset, factory: &specFactory{f}}
}

type idKind uint8

const (
	kindNone idKind = iota
	kindPreset
	kindGolang
	kindCustom
	kindRandomized
)

// Str returns "Client-Version".
func (id ClientHelloID) Str() string { return id.Client + "-" + id.Version }

// IsSet reports whether id names something usable on its own (HelloCustom
// needs ApplyPreset; the zero value is unusable).
func (id ClientHelloID) IsSet() bool { return id.kind != kindNone && id.kind != kindCustom }

func (id ClientHelloID) isZero() bool { return id.kind == kindNone && id.Client == "" }

// Spec returns a FRESH ClientHelloSpec for this fingerprint (specs hold
// mutable slices and must not be shared between connections). HelloGolang and
// HelloCustom have no spec.
func (id ClientHelloID) Spec() (*ClientHelloSpec, error) {
	switch id.kind {
	case kindPreset:
		if id.factory == nil || id.factory.f == nil {
			return nil, fmt.Errorf("utls: fingerprint %q has a nil spec factory", id.Str())
		}
		spec, err := id.factory.f()
		if err == nil && spec == nil {
			err = fmt.Errorf("utls: fingerprint %q factory returned a nil spec", id.Str())
		}
		return spec, err
	case kindRandomized:
		return randomizedSpec(id.seed, id.weights)
	case kindGolang:
		return nil, errors.New("utls: HelloGolang sends the stock crypto/tls ClientHello and has no ClientHelloSpec")
	case kindCustom:
		return nil, ErrNoSpec
	}
	return nil, fmt.Errorf("utls: fingerprint %q is not a known preset", id.Str())
}

// resolve returns the spec to send, or golang=true for HelloGolang. A missing
// spec is reported at handshake time (ErrNoSpec) so ApplyPreset can supply it.
func (id ClientHelloID) resolve() (spec *ClientHelloSpec, golang bool, err error) {
	switch id.kind {
	case kindGolang:
		return nil, true, nil
	case kindCustom, kindNone:
		if id.kind == kindNone && id.Client != "" {
			return nil, false, fmt.Errorf("utls: ClientHelloID %q was not created by uTLS (use a Hello* preset, ParseFingerprint or CustomFingerprint)", id.Str())
		}
		return nil, false, nil
	}
	spec, err = id.Spec()
	if err == nil {
		err = spec.Validate()
	}
	if err != nil {
		return nil, false, fmt.Errorf("utls: fingerprint %s: %w", id.Str(), err)
	}
	return spec, false, nil
}

// CustomFingerprint builds a named fingerprint from a spec factory, which must
// return a fresh spec on each call.
func CustomFingerprint(name, version string, factory func() (*ClientHelloSpec, error)) ClientHelloID {
	return preset(name, version, factory)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]ClientHelloID{}
	canonical  = map[string]ClientHelloID{}
)

func register(id ClientHelloID, aliases ...string) ClientHelloID {
	registryMu.Lock()
	defer registryMu.Unlock()
	canonical[id.Str()] = id
	for _, k := range append([]string{id.Str(), id.Client + id.Version}, aliases...) {
		registry[strings.ToLower(k)] = id
	}
	return id
}

// unsupported records names downstream configurations use for fingerprints
// uTLS deliberately does not offer, with the reason, so configuration errors
// are explicit rather than silently mapped to another fingerprint.
var unsupported = map[string]string{
	"360": "the 360 Browser 7.5 fingerprint advertises NPN and Channel ID, which uTLS cannot negotiate",
}

// ParseFingerprint resolves a configuration name, case-insensitively, to a
// fingerprint: canonical names ("Chrome-155"), bare client names ("chrome"),
// and aliases. "" maps to HelloChrome_Auto; "golang"/"go"/"none" to
// HelloGolang; "random"/"randomized" to a fresh HelloRandomized.
func ParseFingerprint(name string) (ClientHelloID, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	switch key {
	case "":
		return HelloChrome_Auto, nil
	case "golang", "hellogolang", "none", "go":
		return HelloGolang, nil
	}
	if why, ok := unsupported[key]; ok {
		return ClientHelloID{}, fmt.Errorf("utls: fingerprint %q is not supported: %s", name, why)
	}
	registryMu.RLock()
	defer registryMu.RUnlock()
	if id, ok := registry[key]; ok {
		return id, nil
	}
	return ClientHelloID{}, fmt.Errorf("utls: unknown fingerprint %q (see Fingerprints())", name)
}

// Fingerprints returns the canonical names of all registered fingerprints.
func Fingerprints() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var names []string
	for n := range canonical {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
