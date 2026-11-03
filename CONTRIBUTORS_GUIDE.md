# How uTLS v2 works (contributor's guide)

uTLS v1 worked by publishing copies of crypto/tls's private handshake state and
hand-patching thousands of lines of crypto/tls. v2 does neither. Start with:

1. [AGENTS.md](AGENTS.md) — the maintainer's manual: the one rule about
   `internal/tls`, the map of the repository, and the recurring jobs.
2. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — the two layers and the
   ClientHello lifecycle (build, session, render-at-marshal, negotiate).
3. [upstream/PATCHES.md](upstream/PATCHES.md) — every line uTLS changes in the
   mirrored crypto/tls, and why.
4. [docs/FINGERPRINTS.md](docs/FINGERPRINTS.md) — adding a fingerprint from a
   real capture.
5. [docs/UPSTREAM_SYNC.md](docs/UPSTREAM_SYNC.md) — following a Go release.

Before sending a change, run the gates in [docs/RELEASING.md](docs/RELEASING.md)
that apply (at least `go vet ./...`, `go test ./...`, `upstream/sync.sh check`).
If you changed the exported API, `TestAPICompatibility` will tell you; record an
intended addition with `go test -run TestAPICompatibility -update-api .`.
