package accounts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// This is a lint of the sources, not a timing test (a timing test would be flaky and prove little): it parses the
// non-test files of this package and of statekey and refuses
//
//   - calls of variable-time comparison functions (bytes.Equal, bytes.Compare, strings.Compare, strings.EqualFold,
//     reflect.DeepEqual), and
//   - == and != between two values when either side is named like secret material (sum, tag, mac, key, secret,
//     password, code, token, hash).
//
// Comparisons with a literal, nil or len are fine. A comparison of secrets goes through crypto/subtle or hmac.Equal.
// The names are a heuristic: a new secret under another name is for the reviewer.
var secretish = []string{"sum", "tag", "mac", "key", "secret", "password", "code", "token", "hash"}

func TestSecretsAreNotComparedWithVariableTimeOperations(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	more, _ := filepath.Glob(filepath.Join("..", "statekey", "*.go"))
	files = append(files, more...)
	banned := map[string]bool{"bytes.Equal": true, "bytes.Compare": true, "strings.Compare": true, "strings.EqualFold": true, "reflect.DeepEqual": true}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && banned[id.Name+"."+sel.Sel.Name] {
						t.Errorf("%s: %s.%s is variable time", fset.Position(x.Pos()), id.Name, sel.Sel.Name)
					}
				}
			case *ast.BinaryExpr:
				if x.Op != token.EQL && x.Op != token.NEQ {
					return true
				}
				if neutral(x.X) || neutral(x.Y) {
					return true
				}
				for _, side := range []ast.Expr{x.X, x.Y} {
					if name := lastName(side); looksSecret(name) {
						t.Errorf("%s: %s compared with %s: use crypto/subtle or hmac.Equal", fset.Position(x.Pos()), name, x.Op)
					}
				}
			}
			return true
		})
	}
	if scanned < 8 {
		t.Fatalf("scanned only %d files: the glob is wrong", scanned)
	}
}

// neutral is a literal, nil, true/false or a call of len/cap: comparing with it reveals nothing.
func neutral(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return x.Name == "nil" || x.Name == "true" || x.Name == "false" || isConstName(x.Name)
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok {
			return id.Name == "len" || id.Name == "cap"
		}
	case *ast.ParenExpr:
		return neutral(x.X)
	}
	return false
}

// isConstName: our constants that name states, codes and kinds start with a capital letter.
func isConstName(n string) bool { return n != "" && n[0] >= 'A' && n[0] <= 'Z' }

func lastName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.IndexExpr:
		return lastName(x.X)
	case *ast.CallExpr:
		return lastName(x.Fun)
	}
	return ""
}

func looksSecret(name string) bool {
	n := strings.ToLower(name)
	for _, s := range secretish {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// The checker itself: it must catch what it claims to.
func TestTheLintCatchesAVariableTimeCompare(t *testing.T) {
	src := `package x
import "bytes"
func f(sum, other []byte, code string) bool { return bytes.Equal(sum, other) || code == other2() }
func other2() string { return "" }`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var calls, cmps int
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Equal" {
				calls++
			}
		case *ast.BinaryExpr:
			if x.Op == token.EQL && looksSecret(lastName(x.X)) && !neutral(x.Y) {
				cmps++
			}
		}
		return true
	})
	if calls != 1 || cmps != 1 {
		t.Fatalf("calls %d comparisons %d", calls, cmps)
	}
	if !looksSecret("passwordHash") || looksSecret("username") || !neutral(&ast.BasicLit{}) {
		t.Fatal("heuristic")
	}
}
