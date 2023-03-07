// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
<<<<<<< HEAD
package tls

import (
	"crypto/cipher"
	"errors"
)
=======

//go:build !boringcrypto

package tls
>>>>>>> crypto-tls-1-19-6

func needFIPS() bool { return false }

func supportedSignatureAlgorithms() []SignatureScheme {
	return defaultSupportedSignatureAlgorithms
}

func fipsMinVersion(c *Config) uint16          { panic("fipsMinVersion") }
func fipsMaxVersion(c *Config) uint16          { panic("fipsMaxVersion") }
func fipsCurvePreferences(c *Config) []CurveID { panic("fipsCurvePreferences") }
func fipsCipherSuites(c *Config) []uint16      { panic("fipsCipherSuites") }

var fipsSupportedSignatureAlgorithms []SignatureScheme
<<<<<<< HEAD

// [uTLS]
// Boring struct is only to be used to record static env variables
// in boring package. We do not implement BoringSSL compatibliity here.
type Boring struct {
	Enabled bool
}

func (*Boring) NewGCMTLS(_ cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring not implemented")
}

func (*Boring) Unreachable() {
	// do nothing
}

var boring Boring
=======
>>>>>>> crypto-tls-1-19-6
