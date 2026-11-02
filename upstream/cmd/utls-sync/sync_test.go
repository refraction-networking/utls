// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --- unified diff ------------------------------------------------------------

// applyOps reconstructs a and b from an edit script.
func applyOps(ops []diffOp) (a, b []string) {
	for _, o := range ops {
		if o.kind != '+' {
			a = append(a, o.text)
		}
		if o.kind != '-' {
			b = append(b, o.text)
		}
	}
	return
}

func TestMyersReconstructs(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	words := []string{"a\n", "b\n", "c\n", "d\n", "e\n"}
	for i := 0; i < 2000; i++ {
		var a, b []string
		for j := rng.IntN(12); j > 0; j-- {
			a = append(a, words[rng.IntN(len(words))])
		}
		for j := rng.IntN(12); j > 0; j-- {
			b = append(b, words[rng.IntN(len(words))])
		}
		ops := myers(a, b)
		ga, gb := applyOps(ops)
		if strings.Join(ga, "") != strings.Join(a, "") || strings.Join(gb, "") != strings.Join(b, "") {
			t.Fatalf("myers(%q,%q) does not reconstruct", a, b)
		}
		// minimality is not required, but the script must not exceed n+m
		if len(ops) > len(a)+len(b) {
			t.Fatalf("edit script too long")
		}
	}
}

// TestUnifiedDiffAppliesWithGit checks the produced patch is accepted by git apply.
func TestUnifiedDiffAppliesWithGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	rng := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 40; i++ {
		var a, b strings.Builder
		for j := 0; j < 60; j++ {
			line := []string{"x\n", "y\n", "z\n", "func f() {}\n", "\n"}[rng.IntN(5)]
			a.WriteString(line)
			if rng.IntN(6) != 0 {
				b.WriteString(line)
			}
			if rng.IntN(8) == 0 {
				b.WriteString("added\n")
			}
		}
		if rng.IntN(3) == 0 {
			b.WriteString("no newline")
		}
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "f.txt"), []byte(a.String()), 0o644)
		p := unifiedDiff("a/f.txt", "b/f.txt", []byte(a.String()), []byte(b.String()))
		os.WriteFile(filepath.Join(dir, "p.diff"), p, 0o644)
		cmd := exec.Command("git", "apply", "--unidiff-zero", "p.diff")
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git apply rejected diff: %v\n%s\n%s", err, out, p)
		}
		got, _ := os.ReadFile(filepath.Join(dir, "f.txt"))
		if string(got) != b.String() {
			t.Fatalf("patch result differs")
		}
	}
}

func TestRewriteImports(t *testing.T) {
	src := "package x\n\nimport (\n\t\"internal/godebug\"\n\tfoo \"crypto/internal/boring\" // c\n\t\"crypto/tls\"\n)\n\nconst s = \"internal/godebug\"\n"
	got := string(rewriteImports([]byte(src), []rewrite{{"internal/godebug", "m/internal/godebug"}, {"crypto/internal/boring", "m/internal/boring"}}))
	want := "package x\n\nimport (\n\t\"m/internal/godebug\"\n\tfoo \"m/internal/boring\" // c\n\t\"crypto/tls\"\n)\n\nconst s = \"internal/godebug\"\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

// --- update fixtures ----------------------------------------------------------

type fixture struct {
	t        *testing.T
	repo     string
	gorootOf map[string]string
}

func writeFiles(t *testing.T, base string, files map[string]string) {
	for name, content := range files {
		p := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// goFile produces a Go file with enough distinct lines for rename detection.
func goFile(name string, extra string) string {
	var b strings.Builder
	b.WriteString("package tls\n\n")
	for i := 0; i < 20; i++ {
		b.WriteString("// " + name + " line " + strings.Repeat("x", i) + "\n")
	}
	b.WriteString(extra)
	return b.String()
}

func newFixture(t *testing.T) *fixture {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed (needed for merge-file)")
	}
	f := &fixture{t: t, repo: t.TempDir(), gorootOf: map[string]string{}}
	base := map[string]string{
		"src/crypto/tls/conn.go":      goFile("conn", "type Conn struct {\n\t// constant\n\tx int\n}\n"),
		"src/crypto/tls/prf.go":       goFile("prf", "func prf() {}\n"),
		"src/crypto/tls/msgs.go":      goFile("msgs", "func marshal() {\n\treturn\n}\n"),
		"src/crypto/tls/ticket.go":    goFile("ticket", ""),
		"src/crypto/tls/stable.go":    goFile("stable", "import \"internal/godebug\"\n"),
		"src/crypto/tls/testdata/x":   "data\n",
		"src/internal/godebug/g.go":   "package godebug\n",
		"src/crypto/tls/excluded.go":  "package tls\n",
		"src/crypto/tls/notgo.txt":    "ignored\n",
		"src/crypto/tls/.hidden.go":   "ignored\n",
		"src/crypto/tls/sub/inner.go": "ignored (not mirrored: non-recursive)\n",
	}
	f.addGoroot("go1.0.0", base, nil)
	writeFiles(t, f.repo, map[string]string{
		"go.mod":                      "module example.com/m\n\ngo 1.27\n",
		"upstream/VERSION":            "go1.0.0\n",
		"upstream/files.txt":          "crypto/tls internal/tls go\ncrypto/tls/testdata internal/tls/testdata all\n",
		"upstream/imports.txt":        "internal/godebug @MODULE@/internal/godebug\n",
		"upstream/exclude.txt":        "internal/tls/excluded.go reason\n",
		"upstream/shims-sources.txt":  "internal/godebug internal/godebug\n",
		"internal/tls/u_owned.go":     "package tls // uTLS-owned, never touched\n",
		"internal/godebug/godebug.go": "package godebug\n",
	})
	f.must("pristine", "go1.0.0", f.repo)
	// local [uTLS] hunks
	f.edit("internal/tls/conn.go", "\t// constant\n", "\tuconn int // [uTLS]\n\n\t// constant\n")
	f.edit("internal/tls/msgs.go", "\treturn\n", "\treturn // [uTLS] hunk in a file upstream renames\n")
	f.writePatchAndShims()
	f.must("check")
	return f
}

func (f *fixture) addGoroot(v string, files map[string]string, mutate func(map[string]string)) {
	m := map[string]string{}
	for k, v := range files {
		m[k] = v
	}
	if mutate != nil {
		mutate(m)
	}
	dir := f.t.TempDir()
	m["VERSION"] = v + "\ntime 2026-01-01T00:00:00Z\n"
	writeFiles(f.t, dir, m)
	f.gorootOf[v] = dir
}

func (f *fixture) run(args ...string) error {
	for k := range goroots {
		delete(goroots, k)
	}
	for v, d := range f.gorootOf {
		goroots[v] = d
	}
	r, err := newRepo(f.repo)
	if err != nil {
		return err
	}
	// Silence stdout from commands under test.
	old := os.Stdout
	devnull, _ := os.Open(os.DevNull)
	os.Stdout = devnull
	defer func() { os.Stdout = old; devnull.Close() }()
	return run(r, args)
}

func (f *fixture) must(args ...string) {
	f.t.Helper()
	if err := f.run(args...); err != nil {
		f.t.Fatalf("%v: %v", args, err)
	}
}

func (f *fixture) read(p string) string {
	b, err := os.ReadFile(filepath.Join(f.repo, filepath.FromSlash(p)))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func (f *fixture) edit(p, old, new string) {
	s := f.read(p)
	if !strings.Contains(s, old) {
		f.t.Fatalf("%s: %q not found", p, old)
	}
	writeFiles(f.t, f.repo, map[string]string{p: strings.Replace(s, old, new, 1)})
}

func (f *fixture) writePatchAndShims() {
	r, _ := newRepo(f.repo)
	for v, d := range f.gorootOf {
		goroots[v] = d
	}
	p, err := r.diff()
	if err != nil {
		f.t.Fatal(err)
	}
	v, _ := r.version()
	s, err := r.shimHashes(v)
	if err != nil {
		f.t.Fatal(err)
	}
	writeFiles(f.t, f.repo, map[string]string{"upstream/utls.patch": string(p), "upstream/shims.txt": s})
}

func TestUpdateCleanAddDeleteRename(t *testing.T) {
	f := newFixture(t)
	base, _ := os.ReadFile(filepath.Join(f.gorootOf["go1.0.0"], "src/crypto/tls/conn.go"))
	f.addGoroot("go1.0.1", map[string]string{}, func(m map[string]string) {
		g := f.gorootOf["go1.0.0"]
		filepath.Walk(g, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && !strings.HasSuffix(p, "VERSION") {
				rel, _ := filepath.Rel(g, p)
				b, _ := os.ReadFile(p)
				m[filepath.ToSlash(rel)] = string(b)
			}
			return nil
		})
		m["src/crypto/tls/conn.go"] = strings.Replace(string(base), "x int\n", "x int\n\ty int // upstream change far from hunk\n", 1)
		m["src/crypto/tls/newfile.go"] = goFile("newfile", "")
		delete(m, "src/crypto/tls/ticket.go")
		m["src/crypto/tls/prf_renamed.go"] = m["src/crypto/tls/prf.go"]
		delete(m, "src/crypto/tls/prf.go")
		m["src/crypto/tls/messages.go"] = strings.Replace(m["src/crypto/tls/msgs.go"], "// msgs line \n", "// msgs line (renamed upstream)\n", 1)
		delete(m, "src/crypto/tls/msgs.go")
	})
	f.must("update", "go1.0.1")
	if v := strings.TrimSpace(f.read("upstream/VERSION")); v != "go1.0.1" {
		t.Fatalf("VERSION = %s", v)
	}
	if s := f.read("internal/tls/conn.go"); !strings.Contains(s, "uconn int // [uTLS]") || !strings.Contains(s, "y int") {
		t.Fatalf("conn.go not merged:\n%s", s)
	}
	if f.read("internal/tls/newfile.go") == "<missing>" || f.read("internal/tls/ticket.go") != "<missing>" {
		t.Fatal("add/delete not applied")
	}
	if f.read("internal/tls/prf.go") != "<missing>" || f.read("internal/tls/prf_renamed.go") == "<missing>" {
		t.Fatal("unmodified rename not applied")
	}
	if s := f.read("internal/tls/messages.go"); !strings.Contains(s, "[uTLS] hunk in a file upstream renames") || f.read("internal/tls/msgs.go") != "<missing>" {
		t.Fatalf("[uTLS] hunk not carried across rename:\n%s", s)
	}
	if f.read("internal/tls/u_owned.go") != "package tls // uTLS-owned, never touched\n" {
		t.Fatal("u_*.go touched")
	}
	// check must now fail (patch stale) until regenerated
	if err := f.run("check"); err == nil {
		t.Fatal("check passed with a stale patch")
	}
	f.writePatchAndShims()
	f.must("check")
}

func TestUpdateConflictIsNotReportedAsSuccess(t *testing.T) {
	f := newFixture(t)
	f.addGoroot("go1.0.1", map[string]string{}, func(m map[string]string) {
		g := f.gorootOf["go1.0.0"]
		for _, p := range []string{"conn.go", "prf.go", "msgs.go", "ticket.go", "stable.go", "excluded.go"} {
			b, _ := os.ReadFile(filepath.Join(g, "src/crypto/tls", p))
			m["src/crypto/tls/"+p] = string(b)
		}
		m["src/crypto/tls/testdata/x"] = "data\n"
		m["src/internal/godebug/g.go"] = "package godebug\n"
		m["src/crypto/tls/conn.go"] = strings.Replace(m["src/crypto/tls/conn.go"], "\t// constant\n", "\t// constant (upstream edit next to hunk)\n", 1)
	})
	err := f.run("update", "go1.0.1")
	if err == nil || !strings.Contains(err.Error(), "INCOMPLETE") {
		t.Fatalf("update err = %v, want INCOMPLETE", err)
	}
	if v := strings.TrimSpace(f.read("upstream/VERSION")); v != "go1.0.0" {
		t.Fatalf("VERSION advanced to %s despite conflict", v)
	}
	if !strings.Contains(f.read("upstream/UPDATE_STATE"), "conflict content: internal/tls/conn.go") {
		t.Fatalf("UPDATE_STATE = %s", f.read("upstream/UPDATE_STATE"))
	}
	if err := f.run("check"); err == nil {
		t.Fatal("check passed during an unresolved update")
	}
	if err := f.run("update", "go1.0.1"); err == nil {
		t.Fatal("second update allowed while one is in progress")
	}
	if err := f.run("finish"); err == nil {
		t.Fatal("finish allowed with conflict markers")
	}
	// resolve
	s := f.read("internal/tls/conn.go")
	start := strings.Index(s, "<<<<<<<")
	end := strings.Index(s, ">>>>>>> go1.0.1\n") + len(">>>>>>> go1.0.1\n")
	s = s[:start] + "\tuconn int // [uTLS]\n\n\t// constant (upstream edit next to hunk)\n" + s[end:]
	writeFiles(t, f.repo, map[string]string{"internal/tls/conn.go": s})
	f.must("finish")
	if v := strings.TrimSpace(f.read("upstream/VERSION")); v != "go1.0.1" {
		t.Fatalf("VERSION = %s after finish", v)
	}
	f.writePatchAndShims()
	f.must("check")
}

func TestUpdateRejectsUnmappedInternalImport(t *testing.T) {
	f := newFixture(t)
	before := f.read("internal/tls/conn.go")
	f.addGoroot("go1.0.1", map[string]string{}, func(m map[string]string) {
		g := f.gorootOf["go1.0.0"]
		for _, p := range []string{"conn.go", "prf.go", "msgs.go", "ticket.go", "stable.go"} {
			b, _ := os.ReadFile(filepath.Join(g, "src/crypto/tls", p))
			m["src/crypto/tls/"+p] = string(b)
		}
		m["src/crypto/tls/conn.go"] = strings.Replace(m["src/crypto/tls/conn.go"], "x int\n", "x int\n\ty int\n", 1)
		m["src/crypto/tls/newdep.go"] = "package tls\n\nimport \"internal/newpkg\"\n\nvar _ = newpkg.X\n"
		m["src/crypto/tls/testdata/x"] = "data\n"
		m["src/internal/godebug/g.go"] = "package godebug\n"
	})
	err := f.run("update", "go1.0.1")
	if err == nil || !strings.Contains(err.Error(), "internal/newpkg") {
		t.Fatalf("err = %v, want unmapped import report", err)
	}
	if f.read("internal/tls/conn.go") != before || f.read("internal/tls/newdep.go") != "<missing>" {
		t.Fatal("tree modified despite unmapped import")
	}
	if f.read("upstream/UPDATE_STATE") != "<missing>" {
		t.Fatal("state written for an aborted update")
	}
}

func TestUpdateFlagsShimReview(t *testing.T) {
	f := newFixture(t)
	f.addGoroot("go1.0.1", map[string]string{}, func(m map[string]string) {
		g := f.gorootOf["go1.0.0"]
		for _, p := range []string{"conn.go", "prf.go", "msgs.go", "ticket.go", "stable.go"} {
			b, _ := os.ReadFile(filepath.Join(g, "src/crypto/tls", p))
			m["src/crypto/tls/"+p] = string(b)
		}
		m["src/crypto/tls/testdata/x"] = "data\n"
		m["src/internal/godebug/g.go"] = "package godebug\n\nfunc New() {}\n" // upstream shim source changed
	})
	err := f.run("update", "go1.0.1")
	if err == nil || !strings.Contains(f.read("upstream/UPDATE_STATE"), "shim-review internal/godebug") {
		t.Fatalf("err=%v state=%s", err, f.read("upstream/UPDATE_STATE"))
	}
	f.must("finish")
	// shims.txt still records go1.0.0 hashes: check must fail until regenerated.
	if err := f.run("check"); err == nil || !strings.Contains(err.Error(), "shims.txt") {
		t.Fatalf("check err = %v, want shims.txt mismatch", err)
	}
	f.writePatchAndShims()
	f.must("check")
}

func TestCheckDetectsHandEditWithoutPatch(t *testing.T) {
	f := newFixture(t)
	f.edit("internal/tls/prf.go", "func prf() {}\n", "func prf() { /* unrecorded */ }\n")
	if err := f.run("check"); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("check err = %v", err)
	}
}

var _ = io.Discard
var _ = bytes.Equal
