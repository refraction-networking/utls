module github.com/refraction-networking/utls

go 1.26

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/klauspost/compress v1.17.4
	github.com/molecule-man/go-brrr v1.2.0
	golang.org/x/crypto v0.36.0
	golang.org/x/net v0.38.0
	golang.org/x/sys v0.31.0
)

require golang.org/x/text v0.23.0 // indirect
