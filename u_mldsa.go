package tls

// clientSupportedSignatureAlgorithms returns the signature algorithms that a client of
// the given maximum version can advertise and can accept.
//
// It adds the ML-DSA schemes to supportedSignatureAlgorithms for TLS 1.3 only, for 2
// reasons. The ML-DSA codepoints are defined for TLS 1.3 only. And this fork verifies
// ML-DSA signatures for the client role only.
//
// The 3 server call sites of supportedSignatureAlgorithms keep that function. Thus a
// uTLS server does not advertise the ML-DSA codepoints, and rejects an ML-DSA client
// certificate.
//
// Go 1.27 crypto/tls does this differently. It puts ML-DSA in the shared list and
// removes it again in isDisabledSignatureAlgorithm. The base of this fork is older and
// has no such function.
func clientSupportedSignatureAlgorithms(vers uint16) []SignatureScheme {
	shared := supportedSignatureAlgorithms()
	if vers < VersionTLS13 {
		return shared
	}

	// Make a new slice. An append to shared can write into the array behind
	// defaultSupportedSignatureAlgorithms, which the server call sites read.
	algorithms := make([]SignatureScheme, 0, len(shared)+3)
	algorithms = append(algorithms, MLDSA44, MLDSA65, MLDSA87)

	return append(algorithms, shared...)
}
