module github.com/refraction-networking/utls/v2

// go1.27.3 is the minimum: the mirror is synced to go1.27.3 crypto/tls
// (go1.27.2 ECH security fix) and certificate verification uses the
// toolchain's crypto/x509, which received security fixes in go1.27.3.
go 1.27.3

require (
	github.com/klauspost/compress v1.20.1
	github.com/molecule-man/go-brrr v1.2.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
)

require golang.org/x/tools v0.49.0 // indirect
