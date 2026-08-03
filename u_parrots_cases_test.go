package tls

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestUTLSIdToSpecNoDuplicateCaseLabels guards a merge hazard: ClientHelloID
// values are package-level vars, not consts, so the compiler does not reject a
// duplicate case in the utlsIdToSpec switch and the second copy silently becomes
// dead code. A cross-region merge can introduce such a duplicate without a
// textual conflict, so assert every case label appears exactly once.
func TestUTLSIdToSpecNoDuplicateCaseLabels(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "u_parrots.go", nil, 0)
	if err != nil {
		t.Fatalf("parse u_parrots.go: %v", err)
	}

	var sw *ast.SwitchStmt
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "utlsIdToSpec" {
			return true
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			s, ok := m.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if id, ok := s.Tag.(*ast.Ident); ok && id.Name == "id" {
				sw = s
				return false
			}
			return true
		})
		return false
	})
	if sw == nil {
		t.Fatal("could not find `switch id` in utlsIdToSpec")
	}

	seen := map[string]int{}
	for _, stmt := range sw.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expr := range cc.List { // nil List is the default clause
			id, ok := expr.(*ast.Ident)
			if !ok {
				t.Fatalf("unexpected non-identifier case expression at %s", fset.Position(expr.Pos()))
			}
			seen[id.Name]++
		}
	}

	for name, count := range seen {
		if count > 1 {
			t.Errorf("case %s appears %d times in utlsIdToSpec (duplicate/dead case)", name, count)
		}
	}
}

// TestChromeProfilesGenerateSpec checks that the well-known Chrome profiles are
// reachable and produce a non-empty spec without error.
func TestChromeProfilesGenerateSpec(t *testing.T) {
	for _, id := range []ClientHelloID{
		HelloChrome_133,
		HelloChrome_150,
		HelloChrome_150_PSK,
	} {
		t.Run(id.Str(), func(t *testing.T) {
			spec, err := UTLSIdToSpec(id)
			if err != nil {
				t.Fatalf("UTLSIdToSpec(%s): %v", id.Str(), err)
			}
			if len(spec.Extensions) == 0 {
				t.Fatalf("%s: empty extension list", id.Str())
			}
		})
	}
}
