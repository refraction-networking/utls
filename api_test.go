// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var updateAPI = flag.Bool("update-api", false, "rewrite api/v2.txt (only for reviewed, intentional API changes)")

// apiSnapshot is the type-checked public API of pkg, one fact per line,
// sorted. It records exact constant values and types, inferred variable
// types, full function and method signatures, exported struct fields
// (embedded ones included), interface method sets (and whether an interface
// is sealed by unexported methods), method sets of T and *T, and whether each
// named type is comparable — so changing a private field that makes a public
// type non-comparable is visible.
//
// Types from packages for which owned returns true (uTLS-owned packages, e.g.
// internal/tls reached through `type X = itls.X` aliases) are expanded the
// same way under the alias name; types from other packages (the standard
// library) are recorded only by name, so their evolution is not frozen here.
func apiSnapshot(pkg *types.Package, owned func(*types.Package) bool) []string {
	qual := func(p *types.Package) string {
		if p == pkg {
			return ""
		}
		return p.Path()
	}
	ts := func(t types.Type) string { return types.TypeString(t, qual) }
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	describe := func(name string, t types.Type) {
		switch u := t.Underlying().(type) {
		case *types.Struct:
			for f := range u.Fields() {
				if !f.Exported() {
					continue
				}
				if f.Embedded() {
					add("type %s embeds %s", name, ts(f.Type()))
				} else {
					add("type %s field %s %s", name, f.Name(), ts(f.Type()))
				}
			}
			add("type %s struct", name)
		case *types.Interface:
			sealed := false
			for m := range u.Methods() {
				if m.Exported() {
					add("type %s interface method %s%s", name, m.Name(), strings.TrimPrefix(ts(m.Type()), "func"))
				} else {
					sealed = true
				}
			}
			add("type %s interface sealed=%v", name, sealed)
		default:
			add("type %s underlying %s", name, ts(u))
		}
		add("type %s comparable=%v", name, types.Comparable(t))
		if _, isIface := t.Underlying().(*types.Interface); !isIface {
			for _, recv := range []types.Type{t, types.NewPointer(t)} {
				ms := types.NewMethodSet(recv)
				for sel := range ms.Methods() {
					m := sel.Obj().(*types.Func)
					if !m.Exported() {
						continue
					}
					r := name
					if _, ok := recv.(*types.Pointer); ok {
						r = "*" + name
					}
					add("method (%s).%s%s", r, m.Name(), strings.TrimPrefix(ts(m.Type()), "func"))
				}
			}
		}
	}

	scope := pkg.Scope()
	for _, n := range scope.Names() {
		obj := scope.Lookup(n)
		if !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Const:
			add("const %s %s = %s", n, ts(o.Type()), o.Val().ExactString())
		case *types.Var:
			add("var %s %s", n, ts(o.Type()))
		case *types.Func:
			add("func %s%s", n, strings.TrimPrefix(ts(o.Type()), "func"))
		case *types.TypeName:
			if o.IsAlias() {
				target := types.Unalias(o.Type())
				if named, ok := target.(*types.Named); ok && named.Obj().Pkg() != nil && owned(named.Obj().Pkg()) &&
					(named.Obj().Pkg() != pkg || !named.Obj().Exported()) {
					add("type %s = owned:%s", n, named.Obj().Name()) // expanded below
					describe(n, target)
					continue
				}
				add("type %s = %s", n, ts(target))
				continue
			}
			describe(n, o.Type())
		}
	}
	sort.Strings(out)
	return out
}

// loadChecked type-checks importPath from the compiler's export data, as
// built by `go list -export` (the checked API the compiler itself sees).
func loadChecked(t testing.TB, importPath string) *types.Package {
	t.Helper()
	cmd := exec.Command("go", "list", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}", importPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -export: %v\n%s", err, stderr.String())
	}
	exports := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if p, file, ok := strings.Cut(line, "\t"); ok && file != "" {
			exports[p] = file
		}
	}
	imp := importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		f, ok := exports[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(f)
	})
	pkg, err := imp.Import(importPath)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

const modulePath = "github.com/refraction-networking/utls/v2"

// TestAPICompatibility is the API gate: the type-checked exported API of the
// root package (with the uTLS-owned types its aliases expose) must equal
// api/v2.txt. Removing or changing a line is a breaking change and needs a
// major version; additions are reviewed and recorded with -update-api.
func TestAPICompatibility(t *testing.T) {
	pkg := loadChecked(t, modulePath)
	got := apiSnapshot(pkg, func(p *types.Package) bool { return strings.HasPrefix(p.Path(), modulePath) })
	got, leaks := publicNames(pkg, got)
	for _, l := range leaks {
		t.Errorf("public API exposes an internal type with no public alias: %s", l)
	}
	text := strings.Join(got, "\n") + "\n"
	path := filepath.Join("api", "v2.txt")
	if *updateAPI {
		os.MkdirAll("api", 0o755)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) == text {
		return
	}
	have := map[string]bool{}
	for _, l := range got {
		have[l] = true
	}
	inWant := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSuffix(string(want), "\n"), "\n") {
		inWant[l] = true
		if !have[l] {
			t.Errorf("removed or changed (breaking): %s", l)
		}
	}
	for _, l := range got {
		if !inWant[l] {
			t.Errorf("added (record with -update-api after review): %s", l)
		}
	}
}

// publicNames rewrites uTLS-internal type names to the root alias that makes
// them public, and fails for an internal type that the API exposes without an
// alias (downstream could not name it).
func publicNames(pkg *types.Package, lines []string) (out, leaks []string) {
	alias := map[string]string{} // internal qualified name -> public name
	for _, n := range pkg.Scope().Names() {
		if tn, ok := pkg.Scope().Lookup(n).(*types.TypeName); ok && tn.Exported() && tn.IsAlias() {
			if named, ok := types.Unalias(tn.Type()).(*types.Named); ok && named.Obj().Pkg() != nil && named.Obj().Pkg() != pkg {
				alias[named.Obj().Pkg().Path()+"."+named.Obj().Name()] = n
			}
		}
	}
	re := regexp.MustCompile(regexp.QuoteMeta(modulePath) + `/internal/[a-z0-9/]+\.[A-Za-z_][A-Za-z0-9_]*`)
	for _, l := range lines {
		out = append(out, re.ReplaceAllStringFunc(l, func(q string) string {
			if pub, ok := alias[q]; ok {
				return pub
			}
			leaks = append(leaks, l)
			return q
		}))
	}
	sort.Strings(out)
	return out, leaks
}

// checkSource type-checks one fixture package (standard-library imports only).
func checkSource(t *testing.T, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", "package fixture\n"+src, 0)
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("example.com/fixture", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return apiSnapshot(pkg, func(p *types.Package) bool { return p.Path() == "example.com/fixture" })
}

// Each fixture pair is a breaking change the gate must see (the old AST-only
// gate missed most of them).
func TestAPIGateDetectsBreakingChanges(t *testing.T) {
	for _, tc := range []struct{ name, before, after string }{
		{"inferred var type", "type A struct{}\ntype B struct{}\nvar V = A{}", "type A struct{}\ntype B struct{}\nvar V = B{}"},
		{"inferred var from func result", "func f() int { return 0 }\nvar V = f()", "func f() int64 { return 0 }\nvar V = f()"},
		{"typed const value", "type T uint16\nconst C T = 0x4469", "type T uint16\nconst C T = 0x44cd"},
		{"typed const type", "type T uint16\ntype U uint16\nconst C T = 1", "type T uint16\ntype U uint16\nconst C U = 1"},
		{"untyped const value", "const C = 1", "const C = 2"},
		{"const in iota group", "type T int\nconst (\n A T = iota\n B\n)", "type T int\nconst (\n X T = iota\n A\n B\n)"},
		{"embedded qualified type", "import \"io\"\ntype S struct{ io.Reader }", "import \"io\"\ntype S struct{ io.Writer }"},
		{"embedded pointer", "import \"bytes\"\ntype S struct{ *bytes.Buffer }", "import \"bytes\"\ntype S struct{ bytes.Buffer }"},
		{"private field breaks comparability", "type S struct{ A int; p int }", "type S struct{ A int; p []int }"},
		{"field type", "type S struct{ A int }", "type S struct{ A int64 }"},
		{"method signature", "type S struct{}\nfunc (S) M(int) error { return nil }", "type S struct{}\nfunc (S) M(int64) error { return nil }"},
		{"value to pointer receiver", "type S struct{}\nfunc (S) M() {}", "type S struct{}\nfunc (*S) M() {}"},
		{"owned alias gains field", "type s struct{ A int }\ntype X = s", "type s struct{ A int; B int }\ntype X = s"},
		{"owned alias method", "type s struct{}\nfunc (s) M() {}\ntype X = s", "type s struct{}\nfunc (s) N() {}\ntype X = s"},
		{"owned alias comparability", "type s struct{ p int }\ntype X = s", "type s struct{ p map[int]int }\ntype X = s"},
		{"interface sealed", "type I interface{ M() }", "type I interface{ M(); m() }"},
		{"underlying type", "type T uint16", "type T uint32"},
		{"func signature", "func F(a, b int) {}", "func F(a int, b ...int) {}"},
	} {
		a, b := checkSource(t, tc.before), checkSource(t, tc.after)
		if strings.Join(a, "\n") == strings.Join(b, "\n") {
			t.Errorf("%s: change not detected\n%s", tc.name, strings.Join(a, "\n"))
		}
	}
	// And a compatible-looking edit to unexported details that keeps the
	// public API is not reported.
	a := checkSource(t, "type S struct{ A int; p int }\nfunc helper() {}")
	b := checkSource(t, "type S struct{ A int; q string }\nfunc other() {}")
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Errorf("unexported-only change reported:\n%s\n---\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
}

// An internal type in the public API without a public alias is reported (the
// previous gate let ErrExporterUnavailable's type be internal errorString).
func TestAPIGateDetectsUnnameableInternalType(t *testing.T) {
	pkg := loadChecked(t, modulePath)
	_, leaks := publicNames(pkg, []string{
		"var ErrX " + modulePath + "/internal/tls.errorString",
		"func F() " + modulePath + "/internal/tls.ClientHelloSpec",
	})
	if len(leaks) != 1 || !strings.Contains(leaks[0], "errorString") {
		t.Fatalf("leaks = %q", leaks)
	}
}

// The real snapshot expands uTLS-owned alias targets but not standard types.
func TestAPISnapshotScope(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("api", "v2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(text)
	for _, want := range []string{
		"var HelloChrome_Auto ClientHelloID",
		"var DefaultWeights RandomizedWeights",
		"const ALPSCodepointNew uint16 = 17613",
		"type ConnectionState = crypto/tls.ConnectionState",
		"var ErrExporterUnavailable error",
		"type ClientHelloSpec field Extensions []TLSExtension",
		"type ClientHelloSpec = owned:ClientHelloSpec",
		"type ClientHelloID comparable=true",
		"type FragmentOptions field SplitAtSNI bool",
		"type TLSExtension interface sealed=true",
	} {
		if !strings.Contains(s, want+"\n") {
			t.Errorf("snapshot lacks %q", want)
		}
	}
	if strings.Contains(s, "type ConnectionState field") {
		t.Error("standard-library type expanded into the snapshot")
	}
}
