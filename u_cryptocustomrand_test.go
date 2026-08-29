// The reference tests replay a recorded transcript from testdata. They compare the
// bytes that the client writes against the recorded bytes. Thus the client must make
// the same ephemeral keys on each run.
//
// Go 1.27 gives the io.Reader of the caller to rand.CustomReader in
// ecdh.GenerateKey. That function returns the system source, and not the reader of the
// caller. Thus the deterministic reader of the tests has no effect, and each run makes
// a different key. The setting cryptocustomrand=1 makes rand.CustomReader give the
// reader of the caller through, which makes the tests deterministic again.
//
//go:debug cryptocustomrand=1

package tls
