//module github.com/jiwu-moz/utls
module github.com/jiwu-moz/utls

go 1.22.5

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.0.6
	github.com/cloudflare/circl v1.5.0
	github.com/klauspost/compress v1.17.4
	golang.org/x/crypto v0.21.0
	golang.org/x/net v0.23.0
	golang.org/x/sys v0.18.0
)

require golang.org/x/text v0.14.0 // indirect
