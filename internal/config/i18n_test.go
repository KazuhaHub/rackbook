package config

import (
	"strings"
	"testing"
)

func TestI18nDefault(t *testing.T) {
	for _, c := range []struct {
		name, block, want, errPart string
	}{
		{"absent (older file)", "", "zh-CN", ""},
		{"empty block", "i18n: {}\n", "zh-CN", ""},
		{"zh-CN", "i18n: {default: zh-CN}\n", "zh-CN", ""},
		{"zh-TW", "i18n: {default: zh-TW}\n", "zh-TW", ""},
		{"en-US", "i18n:\n  default: en-US\n", "en-US", ""},
		{"alias is normalized", "i18n: {default: EN}\n", "en-US", ""},
		{"unsupported", "i18n: {default: fr-FR}\n", "", "i18n.default"},
		{"not a locale", "i18n: {default: nonsense}\n", "", "i18n.default"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Parse([]byte(sample+c.block), "/r/rackbook.yml")
			if c.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), c.errPart) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.I18n.Default != c.want || cfg.DefaultLocale() != c.want {
				t.Fatalf("default = %q / %q, want %q", cfg.I18n.Default, cfg.DefaultLocale(), c.want)
			}
		})
	}
	if (*Config)(nil).DefaultLocale() != "zh-CN" {
		t.Fatal("nil config")
	}
}
