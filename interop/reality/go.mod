// Isolated interop module: the real XTLS/REALITY server (the revision pinned
// by Xray-core's go.mod) against the uTLS v2 client. It is a separate module
// so REALITY and its dependencies never enter the uTLS runtime module.
module github.com/refraction-networking/utls/v2/interop/reality

go 1.27.3

require (
	github.com/refraction-networking/utls/v2 v2.0.0-00010101000000-000000000000
	github.com/xtls/reality v0.0.0-20261014101318-83f621788ca8
)

require (
	github.com/andybalholm/brotli v1.2.3 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/refraction-networking/utls/v2 => ../..
