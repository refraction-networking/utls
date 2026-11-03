// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package godebug

import "testing"

func TestLookupPrecedence(t *testing.T) {
	defaultGODEBUG = func() string { return "tlsmlkem=0,tlssha1=1" }
	t.Setenv("GODEBUG", "")
	if v := New("tlsmlkem").Value(); v != "0" {
		t.Fatalf("default not applied: %q", v)
	}
	t.Setenv("GODEBUG", "tlsmlkem=1,x=2,tlsmlkem=2")
	if v := New("tlsmlkem").Value(); v != "2" {
		t.Fatalf("env (last wins) not preferred: %q", v)
	}
	if v := New("tlssha1").Value(); v != "1" {
		t.Fatalf("default for unset key: %q", v)
	}
	if v := New("nope").Value(); v != "" {
		t.Fatalf("unknown key: %q", v)
	}
}
