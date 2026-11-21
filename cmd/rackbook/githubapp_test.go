package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func appFlags(args ...string) *pflag.FlagSet {
	f := pflag.NewFlagSet("t", pflag.ContinueOnError)
	f.String("github-app-id", "", "")
	f.String("github-app-key-file", "", "")
	_ = f.Parse(args)
	return f
}

func TestGitHubAppConfiguration(t *testing.T) {
	t.Setenv(appIDEnv, "")
	t.Setenv(appKeyEnv, "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if app, err := newGitHubApp(appFlags(), ""); app != nil || err != nil {
		t.Fatalf("no App configured must be a no-op: %v %v", app, err)
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	file := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(file, pemKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if app, err := newGitHubApp(appFlags("--github-app-id", "9", "--github-app-key-file", file), ""); err != nil || app == nil {
		t.Fatalf("key file: %v", err)
	}
	t.Setenv(appKeyEnv, string(pemKey))
	t.Setenv(appIDEnv, "9")
	if app, err := newGitHubApp(appFlags(), ""); err != nil || app == nil {
		t.Fatalf("environment: %v", err)
	}
	t.Setenv(appIDEnv, "")
	if _, err := newGitHubApp(appFlags(), ""); err == nil || !strings.Contains(err.Error(), "need --github-app-id") {
		t.Fatalf("a key without an id must be refused: %v", err)
	}
	t.Setenv(appKeyEnv, "")
	if _, err := newGitHubApp(appFlags("--github-app-id", "9"), ""); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("an id without a key must be refused: %v", err)
	}
	t.Setenv(appKeyEnv, "not a key")
	_, err := newGitHubApp(appFlags("--github-app-id", "9"), "")
	if err == nil || strings.Contains(err.Error(), "not a key") {
		t.Fatalf("a bad key must be refused without echoing it: %v", err)
	}
}
