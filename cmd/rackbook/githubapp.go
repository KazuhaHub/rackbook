package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"

	"github.com/kazuhahub/rackbook/internal/githubapp"
)

const (
	appIDEnv         = "RACKBOOK_GITHUB_APP_ID"
	appKeyEnv        = "RACKBOOK_GITHUB_APP_KEY"
	appKeyCredential = "github-app-key" // systemd LoadCredential name
)

// newGitHubApp builds the GitHub App credential from --github-app-id and the
// private key (--github-app-key-file, else RACKBOOK_GITHUB_APP_KEY, else the
// systemd credential). It returns nil when no App is configured, and then
// SSH deploy keys and RACKBOOK_GITHUB_TOKEN work as before. The key is never
// part of a flag value, the config in Git or a log line.
func newGitHubApp(f *pflag.FlagSet, ghAPI string) (*githubapp.App, error) {
	id, _ := f.GetString("github-app-id")
	if id == "" {
		id = strings.TrimSpace(os.Getenv(appIDEnv))
	}
	keyFile, _ := f.GetString("github-app-key-file")
	keyEnv := strings.TrimSpace(os.Getenv(appKeyEnv))
	var credFile string
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if p := filepath.Join(dir, appKeyCredential); fileExists(p) {
			credFile = p
		}
	}
	if id == "" {
		if keyFile != "" || keyEnv != "" {
			return nil, errors.New("--github-app-key-file / " + appKeyEnv + " need --github-app-id")
		}
		return nil, nil
	}
	var pemData []byte
	var err error
	switch {
	case keyFile != "":
		pemData, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("--github-app-key-file: %w", err)
		}
	case keyEnv != "":
		pemData = []byte(keyEnv)
	case credFile != "":
		if pemData, err = os.ReadFile(credFile); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("--github-app-id needs the private key: --github-app-key-file, " + appKeyEnv + " or a systemd credential named " + appKeyCredential)
	}
	key, err := githubapp.ParseKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("GitHub App private key: %w", err)
	}
	return githubapp.New(githubapp.Options{AppID: id, Key: key, API: ghAPI})
}
