// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package boring is a uTLS shim for crypto/internal/boring, which cannot be
// imported from outside GOROOT.
//
// uTLS is never built in the Go+BoringCrypto configuration, so BoringCrypto is
// always disabled here: Enabled is false and the GCM constructors are never
// reached (crypto/tls guards every call with `if boring.Enabled`). The shim
// exists only so the mirrored crypto/tls files can import it unchanged. See
// internal/README.md.
package boring

import (
	"crypto/cipher"
	"errors"
)

// Enabled reports whether BoringCrypto is in use. Always false in uTLS.
const Enabled = false

// Unreachable marks code that should be unreachable when BoringCrypto is in
// use. It is a no-op here because BoringCrypto is never enabled.
func Unreachable() {}

// NewGCMTLS is never called because Enabled is false.
func NewGCMTLS(cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring: not available")
}

// NewGCMTLS13 is never called because Enabled is false.
func NewGCMTLS13(cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring: not available")
}
