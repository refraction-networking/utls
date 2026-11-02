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

Have the target toolchain available. `sync.sh` finds sources either from the
active toolchain (if `go version` matches) or by downloading the
`golang.org/toolchain@v0.0.1-<version>.linux-amd64` module from the Go module
proxy — no git access to go.googlesource.com is needed.

Confirm a clean tree and that the current mirror is consistent:

```
git status --porcelain      # should be empty
upstream/sync.sh check      # should say the patch is up to date
```

### 1. Re-sync

```
upstream/sync.sh update go1.28.0
```

This computes `pristine(old)` and `pristine(new)`, then for each mirrored file
does a `git merge-file` three-way merge of {committed tree, pristine(old),
pristine(new)}. Because our changes are small and marked, most files merge
cleanly. The command prints `merged` / `added` / `removed` per file and a
summary, and writes the new version into `upstream/VERSION`.

If it reports conflicts, they are in files where a `[uTLS]` hunk sits on code
that upstream also changed. Open each file, find the `<<<<<<<`/`=======`/
`>>>>>>>` markers, and resolve them so the `[uTLS]`-marked intent is preserved
on top of the new upstream code. Keep the `[uTLS]` comment on the resulting
hunk. The known hunks and their intent are in `upstream/PATCHES.md`.

An `add/add` or `modify/delete` conflict means upstream added a file we also
have, or deleted a file we patched. These are rare; handle per PATCHES.md (the
usual resolution for a deleted-upstream file that carried a hunk is to move the
behaviour into a `u_*.go` file).

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
- A GODEBUG default changed: the `internal/godebug` shim reads the real env var,
  so behaviour follows `GODEBUG`; usually nothing to do.

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

### 4. Bump the module's Go version if needed

If the new release is the minimum you now require, update `go.mod`'s `go`
directive and the toolchain references in CI.

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
