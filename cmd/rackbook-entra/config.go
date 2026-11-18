package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	defaultAuthorityHost = "https://login.microsoftonline.com"
	defaultGraphURL      = "https://graph.microsoft.com/v1.0"
	defaultPurpose       = `Entra application "{app}": {type} "{name}"`
)

// Config is the content of entra.yml.
type Config struct {
	Rackbook RackbookConfig `yaml:"rackbook"`
	Entra    EntraConfig    `yaml:"entra"`
	Interval time.Duration  `yaml:"interval"`
	Record   RecordConfig   `yaml:"record"`
}

type RackbookConfig struct {
	URL        string `yaml:"url"`
	TokenFile  string `yaml:"token_file"`
	Collection string `yaml:"collection"`
	Source     string `yaml:"source"`
}

type EntraConfig struct {
	TenantID          string   `yaml:"tenant_id"`
	ClientID          string   `yaml:"client_id"`
	CertificateFile   string   `yaml:"certificate_file"`
	ServicePrincipals *bool    `yaml:"service_principals"`
	ExcludeAppIDs     []string `yaml:"exclude_app_ids"`
	AuthorityHost     string   `yaml:"authority_host"`
	GraphURL          string   `yaml:"graph_url"`
}

type RecordConfig struct {
	NamePrefix  *string           `yaml:"name_prefix"`
	Purpose     string            `yaml:"purpose"`
	TypeLabels  map[string]string `yaml:"type_labels"`
	Password    map[string]any    `yaml:"password"`
	Certificate map[string]any    `yaml:"certificate"`
	Defaults    map[string]any    `yaml:"defaults"`
}

var sourceRe = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b)
}

func parseConfig(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.finish(); err != nil {
		return nil, err
	}
	return &c, nil
}

// finish fills defaults and validates.
func (c *Config) finish() error {
	r := &c.Rackbook
	if r.Collection == "" {
		r.Collection = "credentials"
	}
	if r.Source == "" {
		r.Source = "entra"
	}
	if r.URL == "" {
		return errors.New("config: rackbook.url is required")
	}
	if _, err := parseHTTPURL("rackbook.url", r.URL); err != nil {
		return err
	}
	if r.TokenFile == "" {
		return errors.New("config: rackbook.token_file is required")
	}
	if !sourceRe.MatchString(r.Source) || r.Source == "manual" {
		return fmt.Errorf("config: rackbook.source %q must be 1-32 characters of a-z 0-9 . _ - and not \"manual\"", r.Source)
	}

	e := &c.Entra
	if strings.TrimSpace(e.TenantID) == "" {
		return errors.New("config: entra.tenant_id is required")
	}
	if strings.TrimSpace(e.ClientID) == "" {
		return errors.New("config: entra.client_id is required")
	}
	if strings.ContainsAny(e.TenantID, "/?#\\ ") {
		return fmt.Errorf("config: entra.tenant_id %q is not valid", e.TenantID)
	}
	if e.CertificateFile == "" {
		return errors.New("config: entra.certificate_file is required")
	}
	var err error
	if e.AuthorityHost == "" {
		e.AuthorityHost = defaultAuthorityHost
	}
	if e.AuthorityHost, err = parseHTTPURL("entra.authority_host", e.AuthorityHost); err != nil {
		return err
	}
	if e.GraphURL == "" {
		e.GraphURL = defaultGraphURL
	}
	if e.GraphURL, err = parseHTTPURL("entra.graph_url", e.GraphURL); err != nil {
		return err
	}
	if e.ServicePrincipals == nil {
		t := true
		e.ServicePrincipals = &t
	}

	if c.Interval == 0 {
		c.Interval = 24 * time.Hour
	}
	if c.Interval < time.Minute {
		return fmt.Errorf("config: interval %s is too short (minimum 1m)", c.Interval)
	}

	rc := &c.Record
	if rc.NamePrefix == nil {
		p := "entra-"
		rc.NamePrefix = &p
	}
	if rc.Purpose == "" {
		rc.Purpose = defaultPurpose
	}
	labels := map[string]string{"password": "client secret", "certificate": "certificate"}
	for k, v := range rc.TypeLabels {
		if k != "password" && k != "certificate" {
			return fmt.Errorf("config: record.type_labels: unknown type %q (use password or certificate)", k)
		}
		labels[k] = v
	}
	rc.TypeLabels = labels
	if rc.Password == nil {
		rc.Password = map[string]any{"kind": "api_token"}
	}
	if rc.Certificate == nil {
		rc.Certificate = map[string]any{"kind": "client_cert", "self_signed": true}
	}
	return nil
}

func (c *Config) serviceFlag() bool {
	return c.Entra.ServicePrincipals == nil || *c.Entra.ServicePrincipals
}

func (c *Config) prefix() string {
	if c.Record.NamePrefix == nil {
		return ""
	}
	return *c.Record.NamePrefix
}

// parseHTTPURL validates an https URL (http only for loopback) and returns it
// without a trailing slash.
func parseHTTPURL(field, raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("config: %s %q is not an absolute URL", field, raw)
	}
	h := u.Hostname()
	loop := h == "localhost" || h == "127.0.0.1" || h == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loop) {
		return "", fmt.Errorf("config: %s %q: use https (http only for localhost)", field, raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}
