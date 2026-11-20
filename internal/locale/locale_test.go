package locale

import "testing"

func TestNormalize(t *testing.T) {
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"zh-CN", "zh-CN", true}, {"ZH-cn", "zh-CN", true}, {"zh_CN", "zh-CN", true}, {"zh", "zh-CN", true},
		{"zh-Hans", "zh-CN", true}, {"zh-SG", "zh-CN", true},
		{"zh-TW", "zh-TW", true}, {"zh-tw", "zh-TW", true}, {"zh-Hant", "zh-TW", true}, {"zh-HK", "zh-TW", true}, {"zh-MO", "zh-TW", true},
		{"en-US", "en-US", true}, {"en", "en-US", true}, {"EN-gb", "en-US", true}, {"en-AU", "en-US", true}, {" en ", "en-US", true},
		{"", "", false}, {"fr", "", false}, {"ja-JP", "", false}, {"english", "", false}, {"zh-XX", "", false},
	} {
		got, ok := Normalize(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Normalize(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestMatch(t *testing.T) {
	for _, c := range []struct{ header, fallback, want string }{
		{"", "zh-CN", "zh-CN"},
		{"", "en-US", "en-US"},
		{"zh-CN", "en-US", "zh-CN"},
		{"zh", "en-US", "zh-CN"},
		{"zh-Hans", "en-US", "zh-CN"},
		{"zh-Hans-CN", "en-US", "zh-CN"},
		{"zh-SG", "en-US", "zh-CN"},
		{"zh-TW", "zh-CN", "zh-TW"},
		{"zh-HK", "zh-CN", "zh-TW"},
		{"zh-MO", "zh-CN", "zh-TW"},
		{"zh-Hant", "zh-CN", "zh-TW"},
		{"zh-Hant-TW", "zh-CN", "zh-TW"},
		{"zh-Hant-HK", "zh-CN", "zh-TW"},
		{"en", "zh-CN", "en-US"},
		{"en-US", "zh-CN", "en-US"},
		{"en-GB,en;q=0.9", "zh-CN", "en-US"},
		{"fr-FR,fr;q=0.9,en;q=0.8", "zh-CN", "en-US"},
		{"fr-FR,zh-HK;q=0.8", "en-US", "zh-TW"},
		{"zh-HK,zh;q=0.9,en;q=0.8", "en-US", "zh-TW"},
		{"zh-CN,zh;q=0.9,en;q=0.8", "en-US", "zh-CN"},
		{"en;q=0.5,zh-TW;q=0.9", "zh-CN", "zh-TW"},
		{"fr", "zh-CN", "zh-CN"},
		{"ja,ko;q=0.8", "en-US", "en-US"},
		{"de-DE", "zh-TW", "zh-TW"},
		{"!!not a header;;", "zh-TW", "zh-TW"},
	} {
		if got := Match(c.header, c.fallback); got != c.want {
			t.Errorf("Match(%q, %q) = %q; want %q", c.header, c.fallback, got, c.want)
		}
	}
}
