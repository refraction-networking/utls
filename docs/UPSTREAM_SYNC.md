# Following a new Go release

uTLS tracks the Go standard library's `crypto/tls`. When a new Go version ships,
the mirror in `internal/tls` is re-generated from it and the small `[uTLS]`
patch is replayed on top. This is designed to be a routine, mostly-scripted
operation. This document is the full procedure.

## Mental model

The committed `internal/tls` equals:

```
pristine(GoVersion)  +  the [uTLS] patch (upstream/utls.patch)  +  u_*.go files
```

where `pristine(GoVersion)` is `crypto/tls` from that Go release with the
import rewrites in `upstream/imports.txt` applied, minus the files in
`upstream/exclude.txt`. `upstream/sync.sh` can produce `pristine(V)` for any V,
diff the committed tree against it, and three-way-merge the tree onto a new V.

The `u_*.go` files and the shim packages are uTLS-owned and never regenerated.

## Procedure

Assume the new release is `go1.28.0`. From the repo root:

### 0. Prerequisites

`upstream/sync.sh` runs the portable Go tool `upstream/cmd/utls-sync` (it needs
only Go and `git merge-file`). It finds the Go sources for a release, in order,
from `-goroot goX.Y.Z=DIR`, the active toolchain if its VERSION matches, a
`golang.org/toolchain` module already in the module cache, or
`go mod download golang.org/toolchain@v0.0.1-<version>.linux-amd64` — no git
access to go.googlesource.com is needed. Use a toolchain whose release you have
verified (checksum of the official archive).

Confirm a clean tree and that the current mirror is consistent:

```
git status --porcelain      # should be empty
upstream/sync.sh check      # should say the patch is up to date
```

### 1. Re-sync

```
upstream/sync.sh update go1.28.0
```

This computes `pristine(old)` and `pristine(new)`, then three-way merges each
mirrored file {committed tree, pristine(old), pristine(new)}. Before touching
the tree it aborts if the new release imports a std-internal package that
`upstream/imports.txt` does not map. Renames are detected deterministically by
content similarity; an ambiguous rename is reported as a conflict rather than
guessed. Because our changes are small and marked, most files merge cleanly.

On a clean merge, `upstream/VERSION` is updated. On any conflict — content,
modify/delete, add/add (a rename onto an existing file keeps both), ambiguous
rename — or when an upstream package that a shim replaces changed
(`upstream/shims.txt`), it writes `upstream/UPDATE_STATE` and leaves VERSION
alone, so `sync.sh check` and CI cannot mistake the tree for a finished update.
If the update fails part way (I/O error), UPDATE_STATE says "aborted": restore
the tree with git and start again.

Resolve each conflict so the `[uTLS]`-marked intent sits on top of the new
upstream code (keep the `[uTLS]` comment; hunk intents are in
`upstream/PATCHES.md`). For a deleted-upstream file that carried a hunk, move
the behaviour into a `u_*.go` file. Review any changed shim against its
upstream package, refresh `upstream/shims.txt` with `upstream/sync.sh shims >
upstream/shims.txt`, then:

```
upstream/sync.sh finish        # refuses while markers or an abort remain
```

### 2. Build and test, inner layer first

```
go build ./internal/...
go test ./internal/...
```

The mirror ships the upstream `crypto/tls` test suite, so this is a strong
signal: if the handshake still behaves, these pass. Typical fallout after a Go
update:

- A std-internal package that `crypto/tls` now imports is not yet rewritten:
  add a line to `upstream/imports.txt` pointing it at an existing shim, or write
  a new shim in `internal/` (see `internal/README.md`) and add the mapping. Re-run
  `upstream/sync.sh update` is not needed — just re-run `pristine` is implicit;
  simplest is to re-run the whole update from a clean tree once the config is fixed.
- A new test file references a symbol from an excluded file: add a stub in
  `internal/tls/u_mirror_stubs_test.go` (there is precedent there).
- A GODEBUG default changed: the `internal/godebug` shim resolves settings like
  the standard library (GODEBUG env var, then the binary's DefaultGODEBUG), so
  behaviour follows the new defaults; usually nothing to do.

Then the uTLS layer:

```
go build ./...
go test ./...
```

`config_fields_test.go` is the important one here: if `crypto/tls.Config` or
`ConnectionState` gained a field, it fails and names it. Add the field to the
converter in `config.go` and to the field map in the test (as `converted` or,
with a reason, `unsupported`).

### 3. Re-record the patch

```
upstream/sync.sh diff > upstream/utls.patch
upstream/sync.sh check          # now passes
```

Review the diff: it should contain only your `[uTLS]`-marked hunks and the
import rewrites. If it contains anything you did not intend, a mirrored file was
edited by accident — revert that and re-record.

### 4. Bump the module's Go version

The mirror is the new release's crypto/tls and may rely on its standard library
(and go1.27.3 carries the crypto/tls ECH and crypto/x509 security fixes).
Update `go.mod`'s `go` directive to the mirrored release and the minimum-version
lane in `.github/workflows/go.yml`. Run the full gate list in
docs/RELEASING.md.

### 5. Commit

Commit `internal/`, `upstream/VERSION`, `upstream/utls.patch`, and any shim or
converter changes together, with a message naming the old and new Go versions.

## When a hunk can't be replayed

If upstream restructured the code so a hunk no longer has a home (e.g. the
function it patched was split), reconsider whether the behaviour can move into a
`u_*.go` file. The marshal-redirect hunk and the key-share-fallback hunk are the
only ones that fundamentally need to sit inside upstream code; the rest are
guards that have natural new homes. Update `upstream/PATCHES.md` whenever the set
of hunks changes.

## Reference: what the config files control

- `upstream/files.txt` — which directories are mirrored and whether all files or
  only `.go` files are copied.
- `upstream/imports.txt` — std-internal import path → shim/public replacement.
  `@MODULE@` expands to the module path.
- `upstream/exclude.txt` — mirrored files deliberately not copied, each with a
  reason (BoGo shim, FIPS-module tests, GOROOT-only link tests).
