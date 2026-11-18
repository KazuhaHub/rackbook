package main

import (
	"strings"
	"testing"
)

const baseCfg = `
rackbook:
  url: https://rackbook.example.org
  token_file: rackbook-token
entra:
  tenant_id: t
  client_id: c
  certificate_file: entra.pem
`

func TestConfigDefaults(t *testing.T) {
	c, err := parseConfig([]byte(baseCfg))
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval.Hours() != 24 || c.Rackbook.Source != "entra" || c.Rackbook.Collection != "credentials" ||
		c.prefix() != "entra-" || !c.serviceFlag() || c.Entra.GraphURL != defaultGraphURL ||
		c.Entra.AuthorityHost != defaultAuthorityHost || c.Record.Purpose != defaultPurpose {
		t.Errorf("%+v", c)
	}
}

func TestConfigErrors(t *testing.T) {
	cases := map[string]struct{ yml, want string }{
		"unknown key":       {baseCfg + "bogus: 1\n", "bogus"},
		"unknown nested":    {strings.Replace(baseCfg, "client_id: c", "client_id: c\n  clientid: x", 1), "clientid"},
		"missing tenant":    {strings.Replace(baseCfg, "tenant_id: t", "", 1), "tenant_id"},
		"missing client":    {strings.Replace(baseCfg, "client_id: c", "", 1), "client_id"},
		"http rackbook":     {strings.Replace(baseCfg, "https://rackbook.example.org", "http://rackbook.example.org", 1), "https"},
		"bad graph url":     {baseCfg + "  graph_url: ftp://x\n", "graph_url"},
		"http authority":    {baseCfg + "  authority_host: http://login.example.org\n", "authority_host"},
		"bad source":        {strings.Replace(baseCfg, "token_file:", "source: manual\n  token_file:", 1), "source"},
		"short interval":    {baseCfg + "interval: 5s\n", "interval"},
		"bad type label":    {baseCfg + "record:\n  type_labels: {secret: x}\n", "type_labels"},
		"empty":             {"", "empty"},
		"missing url":       {strings.Replace(baseCfg, "url: https://rackbook.example.org", "", 1), "rackbook.url"},
		"missing cert":      {strings.Replace(baseCfg, "certificate_file: entra.pem", "", 1), "certificate_file"},
		"missing tokenfile": {strings.Replace(baseCfg, "token_file: rackbook-token", "", 1), "token_file"},
	}
	for n, c := range cases {
		_, err := parseConfig([]byte(c.yml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want mention of %q", n, err, c.want)
		}
	}
}

func TestConfigLoopbackHTTPAllowed(t *testing.T) {
	y := baseCfg + "  graph_url: http://127.0.0.1:9/v1.0/\n  authority_host: http://localhost:9\n"
	c, err := parseConfig([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if c.Entra.GraphURL != "http://127.0.0.1:9/v1.0" {
		t.Errorf("graph = %q", c.Entra.GraphURL)
	}
}

func TestLoadKeyPair(t *testing.T) {
	key, cert := genKey(t, 2048)
	for _, pkcs8 := range []bool{true, false} {
		if _, _, err := loadKeyPair(writePEM(t, key, pkcs8, cert)); err != nil {
			t.Errorf("pkcs8=%v: %v", pkcs8, err)
		}
	}
	_, other := genKey(t, 2048)
	if _, _, err := loadKeyPair(writePEM(t, key, true, other)); err == nil || !strings.Contains(err.Error(), "matches") {
		t.Errorf("mismatch err = %v", err)
	}
	if _, _, err := loadKeyPair(writePEM(t, key, true)); err == nil {
		t.Error("no certificate must fail")
	}
	small, smallCert := genKey(t, 1024)
	if _, _, err := loadKeyPair(writePEM(t, small, true, smallCert)); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("small key err = %v", err)
	}
	// certificate listed first, then a foreign one, still finds the match
	if _, _, err := loadKeyPair(writePEM(t, key, false, other, cert)); err != nil {
		t.Errorf("multi-cert: %v", err)
	}
}
