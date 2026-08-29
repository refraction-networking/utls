package tls

// clientSupportedSignatureAlgorithms returns the signature algorithms that a client
// accepts in the CertificateVerify message of a server.
//
// It adds the ML-DSA schemes to supportedSignatureAlgorithms for TLS 1.3 only, because
// the ML-DSA codepoints are defined for TLS 1.3 only.
//
// The client does not advertise these schemes in a default ClientHello. Only a profile
// that holds the ML-DSA codepoints in its own signature_algorithms extension offers
// them, such as HelloChrome_150. Thus the bytes of a default ClientHello, and the
// fingerprint of HelloGolang, do not change. The reference tests in
// handshake_client_test.go hold this line.
//
// The 3 server call sites of supportedSignatureAlgorithms keep that function. Thus a
// uTLS server does not advertise the ML-DSA codepoints, and rejects an ML-DSA client
// certificate.
//
// Go 1.27 crypto/tls does this differently. It advertises ML-DSA in the default
// ClientHello, and removes the schemes again in isDisabledSignatureAlgorithm. The base
// of this fork is older and has no such function.
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
