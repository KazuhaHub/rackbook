package api

import "testing"

func TestRedactPathHidesWhatIsBelowAHiddenValue(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		path   string
		hidden []string
		want   string
	}{
		{"/meta/ghp_secretkey/x", []string{"/meta"}, "/meta/(hidden)/(hidden)"},
		{"/meta", []string{"/meta"}, "/meta"},
		{"/scope", []string{"/scope"}, "/scope"},
		{"/ports/1/proto", []string{"/note"}, "/ports/1/proto"},
		{"/ports/1/proto/x", []string{"/ports/1/proto"}, "/ports/1/proto/(hidden)"},
		{"/any/thing", []string{""}, "/(hidden)/(hidden)"},
		{"", []string{"/a"}, ""},
		{"/a/b", nil, "/a/b"},
	} {
		if got := redactPath(c.path, c.hidden); got != c.want {
			t.Errorf("%q with %v: %q, want %q", c.path, c.hidden, got, c.want)
		}
	}
}
