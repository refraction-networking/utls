module github.com/refraction-networking/utls

go 1.27

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/klauspost/compress v1.20.1
	github.com/molecule-man/go-brrr v1.2.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
)

require (
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
)
