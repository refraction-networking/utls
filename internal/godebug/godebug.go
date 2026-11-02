// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug is a uTLS shim for the standard library's internal
// internal/godebug package, which cannot be imported from outside GOROOT.
//
// Upstream crypto/tls reads a handful of GODEBUG settings (tlssha1,
// tlsmlkem, tlssecpmlkem, fips140ems, tlsmaxrsasize) through this package.
// This shim reads the real GODEBUG environment variable so those settings
// keep working, while letting the mirrored crypto/tls files stay byte-for-byte
// identical to upstream. See internal/README.md and upstream/PATCHES.md.
//
// The metrics side of the upstream package (IncNonDefault / counters exposed
// via runtime/metrics) is not needed by crypto/tls's behaviour, so it is a
// no-op here.
package godebug

import (
	"os"
	"strings"
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

// lookup returns the value of name in the $GODEBUG environment variable, or ""
// if it is not present. GODEBUG is a comma-separated list of key=value pairs;
// the last occurrence wins, matching the std library.
func lookup(name string) string {
	val := ""
	for _, kv := range strings.Split(os.Getenv("GODEBUG"), ",") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k == name {
			val = v
		}
	}
	return val
}
