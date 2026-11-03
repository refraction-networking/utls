// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug is a uTLS shim for the standard library's internal
// internal/godebug package, which cannot be imported from outside GOROOT.
//
// Upstream crypto/tls reads a handful of GODEBUG settings (tlssha1,
// tlsmlkem, tlssecpmlkem, fips140ems, tlsmaxrsasize, ...) through this
// package. This shim resolves them the way the standard library does — the
// GODEBUG environment variable, then the binary's DefaultGODEBUG (the main
// module's go version and godebug directives) — so uTLS honours the same
// settings as crypto/tls in the same program, while the mirrored files stay
// identical to upstream. See internal/README.md and upstream/PATCHES.md.
//
// The metrics side of the upstream package (IncNonDefault / counters exposed
// via runtime/metrics) is not needed by crypto/tls's behaviour, so it is a
// no-op here.
package godebug

import (
	"os"
	"runtime/debug"
	"strings"
	"sync"
)

// A Setting is a single setting in the $GODEBUG environment variable.
type Setting struct {
	name string
}

// New returns a new Setting for the $GODEBUG setting with the given name.
func New(name string) *Setting {
	return &Setting{name: name}
}

// Name returns the name of the setting.
func (s *Setting) Name() string { return s.name }

// Undocumented reports whether this is an undocumented setting. Upstream uses
// this only for metric naming; crypto/tls never calls it, but it is provided
// for API completeness.
func (s *Setting) Undocumented() bool { return strings.HasSuffix(s.name, "#") }

// Value returns the current value for the GODEBUG setting.
//
// The value is read live from the GODEBUG environment variable on every call.
// This matches the standard library's internal/godebug, which the Go runtime
// keeps in sync with os.Setenv at run time; crypto/tls tests rely on flipping
// GODEBUG (via testenv.SetGODEBUG) and observing the change immediately.
func (s *Setting) Value() string {
	return lookup(s.name)
}

// IncNonDefault is a no-op. Upstream increments a runtime/metrics counter when
// a non-default GODEBUG value changes behaviour; crypto/tls's correctness does
// not depend on the counter.
func (s *Setting) IncNonDefault() {}

// lookup returns the value of name as the standard library would see it: the
// $GODEBUG environment variable if it sets name (last occurrence wins),
// otherwise the binary's default from its build info (DefaultGODEBUG, derived
// by the go command from the main module's go version and its godebug /
// //go:debug directives), otherwise "".
func lookup(name string) string {
	if v, ok := find(os.Getenv("GODEBUG"), name); ok {
		return v
	}
	v, _ := find(defaultGODEBUG(), name)
	return v
}

func find(list, name string) (string, bool) {
	val, found := "", false
	for _, kv := range strings.Split(list, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			val, found = v, true
		}
	}
	return val, found
}

var defaultGODEBUG = sync.OnceValue(func() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "DefaultGODEBUG" {
			return s.Value
		}
	}
	return ""
})
