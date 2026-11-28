package accounts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Secret-dependent comparisons (password tags, TOTP codes, MACs, keys) must be constant time. This
// guards against a later change that compares them with ==, bytes.Equal or strings.Equal.
func TestSecretsAreComparedInConstantTime(t *testing.T) {
	ents, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := regexp.MustCompile(`bytes\.Equal\(|reflect\.DeepEqual\(|strings\.EqualFold\(`)
	for _, f := range ents {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(b), "\n") {
			if banned.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				t.Errorf("%s:%d compares with a variable-time function: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	for file, want := range map[string]string{
		"password.go":  "subtle.ConstantTimeCompare(sum, h.sum)",
		"totp.go":      "subtle.ConstantTimeCompare([]byte(code)",
		"usernames.go": "hmac.Equal(got, want)",
	} {
		b, _ := os.ReadFile(file)
		if !strings.Contains(string(b), want) {
			t.Errorf("%s: expected %q", file, want)
		}
	}
	b, _ := os.ReadFile(filepath.Join("..", "statekey", "statekey.go"))
	for _, want := range []string{"subtle.ConstantTimeCompare(k.b, o.b)", "subtle.ConstantTimeCompare(k.b, session)"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("statekey.go: expected %q", want)
		}
	}
	if strings.Contains(string(b), "bytes.Equal(") {
		t.Error("statekey.go compares keys with bytes.Equal")
	}
}
