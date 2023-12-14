module github.com/refraction-networking/utls

go 1.20

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.0.5
	github.com/cloudflare/circl v1.3.6
	github.com/klauspost/compress v1.16.7
	github.com/quic-go/quic-go v0.37.4
	golang.org/x/crypto v0.14.0
	golang.org/x/net v0.17.0
	golang.org/x/sys v0.13.0
)

require golang.org/x/text v0.13.0 // indirect
