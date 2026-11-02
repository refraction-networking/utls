// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ClientHelloID names a fingerprint. It is either a built-in preset (Client +
// Version, e.g. {"Chrome","Auto"}) or a custom fingerprint carrying its own
// spec factory. Resolve it to a fresh ClientHelloSpec with Spec.
//
// A ClientHelloID is a value: pass it around, compare it with Str, and reuse a
// working one across connections. Unlike v1 it is not used as a map key, so the
// spec-factory field does not make it non-comparable in practice; use Str for
// equality.
type ClientHelloID struct {
	Client  string
	Version string

	// specFactory builds a FRESH spec per call. It is non-nil for every usable
	// fingerprint (presets register one); nil means "unset" (HelloCustom).
	specFactory func() (*ClientHelloSpec, error)
}

// Str returns "Client-Version", a stable identifier for logging and equality.
func (id ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%s", id.Client, id.Version)
}

// IsSet reports whether id names a usable fingerprint.
func (id ClientHelloID) IsSet() bool { return id.specFactory != nil }

// Spec returns a fresh ClientHelloSpec for this fingerprint. A new spec is
// returned on every call so that specs (which hold mutable extension objects
// and per-connection key material) are never shared between connections — a
// recurring source of bugs in downstream uses of v1.
func (id ClientHelloID) Spec() (*ClientHelloSpec, error) {
	if id.specFactory == nil {
		return nil, fmt.Errorf("utls: fingerprint %q has no spec (did you mean HelloCustom + ApplyPreset?)", id.Str())
	}
	return id.specFactory()
}

// CustomFingerprint builds a ClientHelloID from a spec factory. The factory
// must return a fresh spec each call.
func CustomFingerprint(name string, factory func() (*ClientHelloSpec, error)) ClientHelloID {
	return ClientHelloID{Client: name, Version: "Custom", specFactory: factory}
}

// registry maps canonical lowercase names (and aliases) to presets.
var (
	registryMu sync.RWMutex
	registry   = map[string]ClientHelloID{}
)

func register(id ClientHelloID, aliases ...string) ClientHelloID {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[strings.ToLower(id.Str())] = id
	registry[strings.ToLower(id.Client+id.Version)] = id
	for _, a := range aliases {
		registry[strings.ToLower(a)] = id
	}
	return id
}

// ParseFingerprint resolves a user- or config-supplied name to a fingerprint.
// It accepts canonical names ("Chrome-Auto"), bare client names ("chrome"),
// and registered aliases, case-insensitively. The conventional special cases
// are honoured:
//
//	""                  -> HelloChrome_Auto (a sensible modern default)
//	"golang", "none"    -> HelloGolang (the standard crypto/tls fingerprint)
//
// Every surveyed downstream re-implemented a table like this; ParseFingerprint
// replaces it.
func ParseFingerprint(name string) (ClientHelloID, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	switch key {
	case "":
		return HelloChrome_Auto, nil
	case "golang", "hellogolang", "none", "go":
		return HelloGolang, nil
	}
	registryMu.RLock()
	defer registryMu.RUnlock()
	if id, ok := registry[key]; ok {
		return id, nil
	}
	return ClientHelloID{}, fmt.Errorf("utls: unknown fingerprint %q", name)
}

// Fingerprints returns the canonical names of all registered presets, sorted.
func Fingerprints() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	seen := map[string]bool{}
	var names []string
	for _, id := range registry {
		if !seen[id.Str()] {
			seen[id.Str()] = true
			names = append(names, id.Str())
		}
	}
	sort.Strings(names)
	return names
}
