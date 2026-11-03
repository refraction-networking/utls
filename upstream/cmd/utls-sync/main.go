// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command utls-sync maintains the generated crypto/tls mirror in internal/tls.
//
// It is portable (pure Go plus `git merge-file` for three-way merges) and is
// normally run through upstream/sync.sh from the repository root:
//
//	utls-sync pristine <goversion> <outdir>   write pristine(goversion) to outdir
//	utls-sync update <goversion>              merge the mirror onto a new Go release
//	utls-sync finish                          complete an update after resolving conflicts
//	utls-sync diff                            print the [uTLS] patch (tree vs pristine(VERSION))
//	utls-sync check                           fail if anything is stale or unresolved
//	utls-sync shims                           print upstream hashes for the shim packages
//
// pristine(V) is the set of directories in upstream/files.txt copied from
// $GOROOT/src of Go release V, minus upstream/exclude.txt, with the import
// rewrites of upstream/imports.txt applied to every .go file.
//
// Go sources for a release are located, in order: a -goroot V=DIR flag, the
// active toolchain if its VERSION matches, a golang.org/toolchain module for V
// already in the module cache (any platform: sources are identical), and
// finally `go mod download golang.org/toolchain@v0.0.1-V.linux-amd64`.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type gorootFlags map[string]string

func (g gorootFlags) String() string { return fmt.Sprint(map[string]string(g)) }
func (g gorootFlags) Set(s string) error {
	v, dir, ok := strings.Cut(s, "=")
	if !ok || v == "" || dir == "" {
		return errors.New("want -goroot goVERSION=DIR")
	}
	g[v] = dir
	return nil
}

var (
	rootFlag = flag.String("root", ".", "repository root")
	goroots  = gorootFlags{}
)

func main() {
	flag.Var(goroots, "goroot", "use DIR (a GOROOT containing src/) for Go release V: -goroot go1.27.3=/path/to/go (repeatable)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: utls-sync [-root DIR] [-goroot V=DIR] pristine V OUTDIR | update V | finish | diff | check | shims")
		flag.PrintDefaults()
	}
	flag.Parse()
	r, err := newRepo(*rootFlag)
	if err == nil {
		err = run(r, flag.Args())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "utls-sync:", err)
		os.Exit(1)
	}
}

func run(r *repo, args []string) error {
	if len(args) == 0 {
		flag.Usage()
		return errors.New("missing command")
	}
	switch args[0] {
	case "pristine":
		if len(args) != 3 {
			return errors.New("usage: pristine <goversion> <outdir>")
		}
		_, err := r.pristine(args[1], args[2])
		return err
	case "update":
		if len(args) != 2 {
			return errors.New("usage: update <goversion>")
		}
		return r.update(args[1], os.Stdout)
	case "finish":
		return r.finish(os.Stdout)
	case "diff":
		p, err := r.diff()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(p)
		return err
	case "check":
		return r.check(os.Stdout)
	case "shims":
		v, err := r.version()
		if err != nil {
			return err
		}
		s, err := r.shimHashes(v)
		if err != nil {
			return err
		}
		os.Stdout.WriteString(s)
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// repo is the repository being maintained.
type repo struct {
	root   string
	module string
}

func newRepo(root string) (*repo, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(string(gomod), "\n") {
		if m, ok := strings.CutPrefix(strings.TrimSpace(l), "module "); ok {
			return &repo{root: root, module: strings.TrimSpace(m)}, nil
		}
	}
	return nil, errors.New("go.mod has no module line")
}

func (r *repo) up(name string) string { return filepath.Join(r.root, "upstream", name) }

func (r *repo) version() (string, error) {
	b, err := os.ReadFile(r.up("VERSION"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// configLines returns the non-comment, non-empty fields of an upstream/*.txt file.
func (r *repo) configLines(name string) ([][]string, error) {
	b, err := os.ReadFile(r.up(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && name == "shims.txt" {
			return nil, nil
		}
		return nil, err
	}
	var out [][]string
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if f := strings.Fields(l); len(f) > 0 {
			out = append(out, f)
		}
	}
	return out, nil
}

type mirrorDir struct{ updir, local, mode string }

func (r *repo) mirrorDirs() ([]mirrorDir, error) {
	ls, err := r.configLines("files.txt")
	if err != nil {
		return nil, err
	}
	var out []mirrorDir
	for _, f := range ls {
		if len(f) != 3 || (f[2] != "go" && f[2] != "all") {
			return nil, fmt.Errorf("files.txt: bad line %q", strings.Join(f, " "))
		}
		out = append(out, mirrorDir{f[0], f[1], f[2]})
	}
	return out, nil
}

// goroot returns a GOROOT whose src/ holds the sources of Go release v.
func (r *repo) goroot(v string) (string, error) {
	if d, ok := goroots[v]; ok {
		return d, checkGoroot(d, v)
	}
	if out, err := exec.Command("go", "env", "GOROOT").Output(); err == nil {
		d := strings.TrimSpace(string(out))
		if checkGoroot(d, v) == nil {
			return d, nil
		}
	}
	if out, err := exec.Command("go", "env", "GOMODCACHE").Output(); err == nil {
		matches, _ := filepath.Glob(filepath.Join(strings.TrimSpace(string(out)), "golang.org", "toolchain@v0.0.1-"+v+".*"))
		sort.Strings(matches)
		for _, d := range matches {
			if checkGoroot(d, v) == nil {
				return d, nil
			}
		}
	}
	cmd := exec.Command("go", "mod", "download", "-json", "golang.org/toolchain@v0.0.1-"+v+".linux-amd64")
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GO111MODULE=on", "GOTOOLCHAIN=local")
	cmd.Dir = os.TempDir()
	out, err := cmd.Output()
	if err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			l = strings.TrimSpace(l)
			if d, ok := strings.CutPrefix(l, `"Dir": `); ok {
				d, _ = strconv.Unquote(strings.TrimSuffix(d, ","))
				if checkGoroot(d, v) == nil {
					return d, nil
				}
			}
		}
	}
	return "", fmt.Errorf("cannot locate sources for %s (pass -goroot %s=DIR)", v, v)
}

func checkGoroot(d, v string) error {
	b, err := os.ReadFile(filepath.Join(d, "VERSION"))
	if err != nil {
		return err
	}
	first, _, _ := strings.Cut(string(b), "\n")
	if strings.TrimSpace(first) != v {
		return fmt.Errorf("%s is %s, not %s", d, strings.TrimSpace(first), v)
	}
	if _, err := os.Stat(filepath.Join(d, "src", "crypto", "tls")); err != nil {
		return err
	}
	return nil
}

// pristine writes pristine(v) to out and returns the relative paths written.
func (r *repo) pristine(v, out string) ([]string, error) {
	gr, err := r.goroot(v)
	if err != nil {
		return nil, err
	}
	dirs, err := r.mirrorDirs()
	if err != nil {
		return nil, err
	}
	excl := map[string]bool{}
	ex, err := r.configLines("exclude.txt")
	if err != nil {
		return nil, err
	}
	for _, f := range ex {
		excl[f[0]] = true
	}
	rw, err := r.rewrites()
	if err != nil {
		return nil, err
	}
	var written []string
	for _, d := range dirs {
		src := filepath.Join(gr, "src", filepath.FromSlash(d.updir))
		ents, err := os.ReadDir(src)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			name := e.Name()
			if !e.Type().IsRegular() || strings.HasPrefix(name, ".") {
				continue
			}
			if d.mode == "go" && !strings.HasSuffix(name, ".go") {
				continue
			}
			rel := d.local + "/" + name
			if excl[rel] {
				continue
			}
			data, err := os.ReadFile(filepath.Join(src, name))
			if err != nil {
				return nil, err
			}
			if strings.HasSuffix(name, ".go") {
				data = rewriteImports(data, rw)
			}
			dst := filepath.Join(out, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return nil, err
			}
			written = append(written, rel)
		}
	}
	sort.Strings(written)
	return written, nil
}

type rewrite struct{ old, new string }

func (r *repo) rewrites() ([]rewrite, error) {
	ls, err := r.configLines("imports.txt")
	if err != nil {
		return nil, err
	}
	var out []rewrite
	for _, f := range ls {
		if len(f) != 2 {
			return nil, fmt.Errorf("imports.txt: bad line %q", strings.Join(f, " "))
		}
		out = append(out, rewrite{f[0], strings.ReplaceAll(f[1], "@MODULE@", r.module)})
	}
	return out, nil
}

// rewriteImports replaces quoted import paths on import-spec lines only:
// optional "import", optional name, the quoted path, optional trailing comment.
func rewriteImports(src []byte, rw []rewrite) []byte {
	lines := strings.SplitAfter(string(src), "\n")
	for i, l := range lines {
		body := strings.TrimRight(l, "\n")
		trim := strings.TrimLeft(body, " \t")
		indent := body[:len(body)-len(trim)]
		rest := strings.TrimPrefix(trim, "import ")
		prefix := trim[:len(trim)-len(rest)]
		// optional import name
		name := ""
		if f := strings.Fields(rest); len(f) >= 2 && !strings.HasPrefix(f[0], `"`) && isIdent(f[0]) {
			name = f[0]
			rest = strings.TrimLeft(rest[len(f[0]):], " \t")
		}
		if !strings.HasPrefix(rest, `"`) {
			continue
		}
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 {
			continue
		}
		path, tail := rest[1:1+end], rest[2+end:]
		if strings.TrimSpace(tail) != "" && !strings.HasPrefix(strings.TrimSpace(tail), "//") {
			continue
		}
		for _, w := range rw {
			if path == w.old {
				nm := ""
				if name != "" {
					nm = name + " "
				}
				lines[i] = indent + prefix + nm + strconv.Quote(w.new) + tail + l[len(body):]
				break
			}
		}
	}
	return []byte(strings.Join(lines, ""))
}

func isIdent(s string) bool {
	if s == "_" || s == "." {
		return true
	}
	for i, c := range s {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return s != ""
}

// unmappedImports reports std-internal imports left in a pristine tree: they
// cannot compile outside GOROOT and need an imports.txt mapping or a shim.
func unmappedImports(dir string, files []string) ([]string, error) {
	var bad []string
	fset := token.NewFileSet()
	for _, rel := range files {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, filepath.FromSlash(rel)), nil, parser.ImportsOnly)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", rel, err)
		}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			first, _, _ := strings.Cut(p, "/")
			if strings.Contains(first, ".") {
				continue // not std
			}
			if strings.HasPrefix(p, "internal/") || strings.Contains(p, "/internal/") || strings.HasSuffix(p, "/internal") {
				bad = append(bad, rel+": "+p)
			}
		}
	}
	return bad, nil
}

// mirroredFiles lists mirrored paths present under tree (u_*.go excluded).
func (r *repo) mirroredFiles(tree string) ([]string, error) {
	dirs, err := r.mirrorDirs()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range dirs {
		ents, err := os.ReadDir(filepath.Join(tree, filepath.FromSlash(d.local)))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), "u_") || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if d.mode == "go" && !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			out = append(out, d.local+"/"+e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func readOpt(p string) ([]byte, bool) {
	b, err := os.ReadFile(p)
	return b, err == nil
}

// diff renders the [uTLS] patch: committed mirror vs pristine(VERSION).
func (r *repo) diff() ([]byte, error) {
	v, err := r.version()
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "utls-sync-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	pfiles, err := r.pristine(v, tmp)
	if err != nil {
		return nil, err
	}
	tfiles, err := r.mirroredFiles(r.root)
	if err != nil {
		return nil, err
	}
	all := map[string]bool{}
	for _, f := range append(pfiles, tfiles...) {
		all[f] = true
	}
	names := make([]string, 0, len(all))
	for f := range all {
		names = append(names, f)
	}
	sort.Strings(names)
	var out bytes.Buffer
	for _, f := range names {
		a, aok := readOpt(filepath.Join(tmp, filepath.FromSlash(f)))
		b, bok := readOpt(filepath.Join(r.root, filepath.FromSlash(f)))
		an, bn := "a/"+f, "b/"+f
		if !aok {
			an = "/dev/null"
		}
		if !bok {
			bn = "/dev/null"
		}
		out.Write(unifiedDiff(an, bn, a, b))
	}
	return out.Bytes(), nil
}

const stateFile = "UPDATE_STATE"

func (r *repo) check(w *os.File) error {
	var problems []string
	if b, ok := readOpt(r.up(stateFile)); ok {
		problems = append(problems, "an update is in progress (upstream/"+stateFile+"):\n"+string(b))
	}
	tfiles, err := r.mirroredFiles(r.root)
	if err != nil {
		return err
	}
	for _, f := range tfiles {
		b, _ := os.ReadFile(filepath.Join(r.root, filepath.FromSlash(f)))
		if hasConflictMarkers(b) {
			problems = append(problems, f+": contains merge conflict markers")
		}
	}
	v, err := r.version()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "utls-sync-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	pfiles, err := r.pristine(v, tmp)
	if err != nil {
		return err
	}
	// The committed tree must not import std-internal packages (pristine may:
	// such imports are removed by marked [uTLS] hunks recorded in utls.patch).
	if bad, err := unmappedImports(r.root, tfiles); err != nil {
		return err
	} else if len(bad) > 0 {
		problems = append(problems, "committed mirror imports std-internal packages:\n  "+strings.Join(bad, "\n  "))
	}
	_ = pfiles
	got, err := r.diff()
	if err != nil {
		return err
	}
	want, _ := os.ReadFile(r.up("utls.patch"))
	if !bytes.Equal(got, want) {
		problems = append(problems, "upstream/utls.patch is stale: run 'upstream/sync.sh diff > upstream/utls.patch' and review the change")
	}
	shims, err := r.shimHashes(v)
	if err != nil {
		return err
	}
	recorded, _ := os.ReadFile(r.up("shims.txt"))
	if shims != string(recorded) {
		problems = append(problems, "upstream/shims.txt does not match the upstream sources of the shimmed packages at "+v+
			"; review internal/README.md shims against upstream, then run 'upstream/sync.sh shims > upstream/shims.txt'")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	fmt.Fprintf(w, "upstream/utls.patch is up to date (%s)\n", v)
	return nil
}

func hasConflictMarkers(b []byte) bool {
	for _, l := range bytes.Split(b, []byte("\n")) {
		if bytes.HasPrefix(l, []byte("<<<<<<< ")) || bytes.HasPrefix(l, []byte(">>>>>>> ")) || bytes.Equal(l, []byte("=======")) {
			return true
		}
	}
	return false
}

// shimHashes hashes the upstream sources each hand-maintained shim replaces,
// so a Go update that changes them forces a review (see upstream/shims.txt).
func (r *repo) shimHashes(v string) (string, error) {
	ls, err := r.configLines("shims-sources.txt")
	if err != nil {
		return "", err
	}
	gr, err := r.goroot(v)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	out.WriteString("# Generated by 'upstream/sync.sh shims'. Hash of the non-test Go sources of\n")
	out.WriteString("# each upstream package a uTLS shim replaces, at the VERSION in upstream/VERSION.\n")
	out.WriteString("# 'sync.sh check' fails when these change: re-review the shim, then regenerate.\n")
	for _, f := range ls {
		if len(f) != 2 {
			return "", fmt.Errorf("shims-sources.txt: bad line %q", strings.Join(f, " "))
		}
		h, err := hashGoDir(filepath.Join(gr, "src", filepath.FromSlash(f[1])))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&out, "%-24s %-40s %s\n", f[0], f[1], h)
	}
	return out.String(), nil
}

func hashGoDir(dir string) (string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s %d\n", n, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
