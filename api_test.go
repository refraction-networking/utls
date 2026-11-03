// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"flag"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateAPI = flag.Bool("update-api", false, "rewrite api/v2.txt (only for reviewed, intentional API changes)")

// exportedAPI lists every exported declaration of the Go package in dir (one
// line each, with its signature or type), sorted. Test files are ignored.
func exportedAPI(t testing.TB, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	src := func(n ast.Node) string {
		var b bytes.Buffer
		printer.Fprint(&b, fset, n)
		return strings.Join(strings.Fields(b.String()), " ")
	}
	var out []string
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if !d.Name.IsExported() {
						continue
					}
					name := d.Name.Name
					if d.Recv != nil {
						recv := src(d.Recv.List[0].Type)
						if !ast.IsExported(strings.TrimLeft(recv, "*")) {
							continue
						}
						name = "(" + recv + ")." + name
					}
					out = append(out, "func "+name+strings.TrimPrefix(src(d.Type), "func"))
				case *ast.GenDecl:
					for _, s := range d.Specs {
						switch s := s.(type) {
						case *ast.TypeSpec:
							if !s.Name.IsExported() {
								continue
							}
							typ := src(s.Type)
							if st, ok := s.Type.(*ast.StructType); ok {
								typ = "struct" + exportedFields(st, src)
							}
							assign := " "
							if s.Assign != 0 {
								assign = " = "
							}
							out = append(out, "type "+s.Name.Name+assign+typ)
						case *ast.ValueSpec:
							kind := d.Tok.String()
							for i, n := range s.Names {
								if !n.IsExported() {
									continue
								}
								line := kind + " " + n.Name
								if s.Type != nil {
									line += " " + src(s.Type)
								} else if i < len(s.Values) && kind == "const" {
									line += " = " + src(s.Values[i])
								}
								out = append(out, line)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// exportedFields renders only the exported fields of a struct.
func exportedFields(st *ast.StructType, src func(ast.Node) string) string {
	var fs []string
	for _, f := range st.Fields.List {
		if len(f.Names) == 0 { // embedded
			if ast.IsExported(strings.TrimLeft(src(f.Type), "*")) {
				fs = append(fs, src(f.Type))
			}
			continue
		}
		for _, n := range f.Names {
			if n.IsExported() {
				fs = append(fs, n.Name+" "+src(f.Type))
			}
		}
	}
	return "{ " + strings.Join(fs, "; ") + " }"
}

// TestAPICompatibility is the API gate: the exported API of the root package
// must equal api/v2.txt. Removing or changing a line is a breaking change and
// needs a major version; additions are reviewed and recorded with
// -update-api. The re-exported spec types come from internal/tls, so its
// exported extension and spec API is recorded too.
func TestAPICompatibility(t *testing.T) {
	var got []string
	for _, l := range exportedAPI(t, ".") {
		got = append(got, l)
	}
	for _, l := range exportedAPI(t, "internal/tls") {
		// Only the types the root package re-exports are public.
		got = append(got, "internal/tls: "+l)
	}
	got = filterReexported(t, got)
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
	wl := strings.Split(strings.TrimSuffix(string(want), "\n"), "\n")
	have := map[string]bool{}
	for _, l := range got {
		have[l] = true
	}
	inWant := map[string]bool{}
	for _, l := range wl {
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

// filterReexported keeps internal/tls declarations only for type names the
// root package re-exports (as aliases) and their methods.
func filterReexported(t *testing.T, lines []string) []string {
	aliases := map[string]bool{}
	for _, l := range lines {
		// "type X = itls.X"
		if strings.HasPrefix(l, "type ") && strings.Contains(l, " = itls.") {
			aliases[strings.TrimSpace(l[strings.Index(l, "itls.")+5:])] = true
		}
	}
	var out []string
	for _, l := range lines {
		rest, ok := strings.CutPrefix(l, "internal/tls: ")
		if !ok {
			out = append(out, l)
			continue
		}
		var name string
		switch {
		case strings.HasPrefix(rest, "type "):
			name = strings.Fields(rest)[1]
		case strings.HasPrefix(rest, "func ("):
			recv := rest[len("func ("):strings.Index(rest, ")")]
			name = strings.TrimLeft(recv, "*")
		default:
			continue
		}
		if aliases[name] {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}
