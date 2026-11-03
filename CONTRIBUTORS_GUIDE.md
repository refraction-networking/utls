# How this package works
### Chapter 1: [Making private things public](./u_public.go)
There are numerous handshake-related structs in crypto/tls, most of which are either private or have private fields.
One of them — `clientHandshakeState` — has private function `handshake()`,
which is called in the beginning of default handshake.  
Unfortunately, user will not be able to directly access this struct outside of tls package.
As a result, we decided to employ following workaround: declare public copies of private structs.
Now user is free to manipulate fields of public `ClientHandshakeState`.
Then, right before handshake, we can shallow-copy public state into private `clientHandshakeState`,
call `handshake()` on it and carry on with default Golang handshake process.
After handshake is done we shallow-copy private state back to public, allowing user to read results of handshake.

### Chapter 2: [TLSExtension](./u_tls_extensions.go)
The way we achieve reasonable flexibilty with extensions is inspired by
[ztls'](https://github.com/zmap/zcrypto/blob/master/tls/handshake_extensions.go) design.
However, our design has several differences, so we wrote it from scratch.
This design allows us to have an array of `TLSExtension` objects and then marshal them in order:
```Golang
type TLSExtension interface {
	writeToUConn(*UConn) error

	Len() int // includes header

	// Read reads up to len(p) bytes into p.
	// It returns the number of bytes read (0 <= n <= len(p)) and any error encountered.
	Read(p []byte) (n int, err error) // implements io.Reader
}
```
`writeToUConn()` applies appropriate per-extension changes to `UConn`.

`Len()` provides the size of marshaled extension, so we can allocate appropriate buffer beforehand,
catch out-of-bound errors easily and guide size-dependent extensions such as padding.

`Read(buffer []byte)` _writes(see: io.Reader interface)_ marshaled extensions into provided buffer.
This avoids extra allocations.

### Chapter 3: [UConn](./u_conn.go)
`UConn` extends standard `tls.Conn`. Most notably, it stores slice with `TLSExtension`s and public
`ClientHandshakeState`.  
Whenever `UConn.BuildHandshakeState()` gets called (happens automatically in `UConn.Handshake()`
or could be called manually), config will be applied according to chosen `ClientHelloID`.
From contributor's view there are 2 main behaviors:  
 * `HelloGolang` simply calls default Golang's [`makeClientHello()`](./handshake_client.go)
 and directly stores it into `HandshakeState.Hello`. utls-specific stuff is ignored.  
 * Other ClientHelloIDs fill `UConn.Hello.{Random, CipherSuites, CompressionMethods}` and `UConn.Extensions` with
per-parrot setup, which then gets applied to appropriate standard tls structs,
and then marshaled by utls into `HandshakeState.Hello`.

### Chapter 4: Tests

Tests exist, but coverage is very limited. What's covered is a conjunction of
 * TLS 1.2
 * Working parrots without any unsupported extensions (only Android 5.1 at this time)
 * Ciphersuites offered by parrot.
 * Ciphersuites supported by Golang
 * Simple conversation with reference implementation of OpenSSL.
(e.g. no automatic checks for renegotiations, parroting quality and such)

plus we test some other minor things.
Basically, current tests aim to provide a sanity check.

# Merging upstream

Merge the `src/crypto/tls` subtree from an exact Go release tag. The recent
Go 1.23.4 (`cefe226`), Go 1.24.0 (`a99feac`), and Go 1.26.0 (`ec54fa8`)
updates are two-parent merges whose second parent is the upstream TLS subtree.
Preserve that history so Git can identify the upstream merge base on the next
update; do not squash the merge or replace it with a directory copy.

Start with a clean uTLS working tree on an update branch. For example:

```bash
# Add this remote once, if it does not already exist.
git remote add golang https://github.com/golang/go.git
git fetch --no-tags golang tag go1.27.1
git switch -c codex/update-go1.27.1
git subtree split --prefix=src/crypto/tls refs/tags/go1.27.1 \
    --branch golang-tls-go1.27.1
git merge --no-ff --no-commit golang-tls-go1.27.1
```

Use the release tag, not the moving Go development or release branch. Keep the
upstream history available for the split, and inspect the previous sync merges
before resolving conflicts. Record the Go tag and split commit in the update's
description.

During the merge:

* Preserve the uTLS-specific behavior marked by `[uTLS]` comments. Review the
  resulting code even where Git merges it cleanly. Propagate relevant upstream
  changes into duplicated paths such as `u_handshake_client.go` and `u_quic.go`,
  and check the public/private conversions in `u_public.go`.
* Audit dependencies outside `src/crypto/tls`, especially the local `internal/`
  packages, against the same Go release. The subtree merge does not update
  these copies. Prefer exported standard-library APIs where available, and
  preserve the local adaptations for inaccessible Go internal packages.
* uTLS does not implement Go's internal `godebug` machinery. Retain this
  limitation when porting upstream defaults and tests; environment-dependent
  TLS compatibility tests cannot assume the standard library's switches work
  here. Distinguish those switches from ones honored by imported standard-library
  packages. Port useful test helpers instead of importing Go-only internal
  packages, and explain tests that cannot be carried over.
* Follow upstream changes to private structs and functions that uTLS exposes.
  If those changes break a public uTLS field or method, document the old and new
  API and any direct migration. Do not reconstruct removed internal state or
  add compatibility machinery solely to preserve the old API.
* Update the minimum Go version in `go.mod` and the toolchain used by
  `.github/workflows/go.yml` when required by the imported code.

After resolving conflicts, format changed Go files and run:

```bash
go build ./...
go test ./...
go test -race ./...
git diff --check
```

Pay particular attention to custom ClientHello handshakes, ECH (including the
inner transcript), HelloRetryRequest, PSK/session resumption and binder updates,
hybrid key shares, and public/private state conversions on failed handshakes.
Previous syncs needed follow-up fixes in these areas. Exercise both `HelloGolang`
and custom/parrot paths where applicable. Keep upstream test fixtures from the
same release, and report any unavailable platform or external-network checks.
Once validation is complete, commit the resolved merge with both parents intact.
