package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/modsettings"
)

const (
	defaultInterval  = 6 * time.Hour
	minInterval      = time.Minute
	maxThresholdDays = 3650
	defaultStateFile = "notify-state.json"
)

var defaultThresholds = []int{30, 14, 7, 0}

type Config struct {
	Rackbook    RackbookConfig `yaml:"rackbook"`
	Collections []string       `yaml:"collections"`
	Thresholds  []int          `yaml:"thresholds"`
	StateFile   string         `yaml:"state_file"`
	Language    string         `yaml:"language"`
	Interval    time.Duration  `yaml:"interval"`
	SMTP        *SMTPConfig    `yaml:"smtp"`
	Webhook     *WebhookConfig `yaml:"webhook"`

	// set* remember which fields the file spelled out (normalize fills
	// defaults), so a setting from the console can tell it overrides a local one.
	setThresholds, setLanguage, setCollections bool
}

type RackbookConfig struct {
	URL       string `yaml:"url"`
	TokenFile string `yaml:"token_file"`
	// Module is this module's name in rackbook.yml (modules:); default notify.
	Module string `yaml:"module"`
}

type SMTPConfig struct {
	Host         string   `yaml:"host"`
	Port         int      `yaml:"port"`
	Username     string   `yaml:"username"`
	PasswordFile string   `yaml:"password_file"`
	From         string   `yaml:"from"`
	To           []string `yaml:"to"`
	// Helo is the name sent in EHLO; default the host's name (heloName).
	Helo string `yaml:"helo"`
}

type WebhookConfig struct {
	URLFile string `yaml:"url_file"`
	URL     string `yaml:"url"`
}

func loadConfig(path string, dryRun bool) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b, dryRun)
}

func parseConfig(b []byte, dryRun bool) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.normalize(dryRun); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) normalize(dryRun bool) error {
	if strings.TrimSpace(c.Rackbook.URL) == "" {
		return errors.New("config: rackbook.url is required")
	}
	if strings.TrimSpace(c.Rackbook.TokenFile) == "" {
		return errors.New("config: rackbook.token_file is required")
	}
	if c.Rackbook.Module == "" {
		c.Rackbook.Module = "notify"
	}
	c.setThresholds, c.setLanguage, c.setCollections = len(c.Thresholds) > 0, c.Language != "", len(c.Collections) > 0
	if len(c.Thresholds) == 0 {
		c.Thresholds = append([]int(nil), defaultThresholds...)
	}
	seen := map[int]bool{}
	var ts []int
	for _, t := range c.Thresholds {
		if t < 0 || t > maxThresholdDays {
			return fmt.Errorf("config: threshold %d must be between 0 and %d", t, maxThresholdDays)
		}
		if !seen[t] {
			seen[t] = true
			ts = append(ts, t)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ts)))
	c.Thresholds = ts
	if c.StateFile == "" {
		c.StateFile = defaultStateFile
	}
	if c.Language == "" {
		c.Language = "en-US"
	} else if l, ok := modsettings.NotifyLanguage(c.Language); ok {
		c.Language = l
	} else {
		return fmt.Errorf("config: language %q must be one of %s (en and zh also work)", c.Language, strings.Join(modsettings.NotifyLanguages, ", "))
	}
	if c.Interval == 0 {
		c.Interval = defaultInterval
	}
	if c.Interval < minInterval {
		return fmt.Errorf("config: interval %s is shorter than %s", c.Interval, minInterval)
	}
	for _, col := range c.Collections {
		if strings.TrimSpace(col) == "" {
			return errors.New("config: collections contains an empty name")
		}
	}
	if s := c.SMTP; s != nil {
		if err := s.normalize(); err != nil {
			return err
		}
	}
	if w := c.Webhook; w != nil {
		if (w.URL == "") == (w.URLFile == "") {
			return errors.New("config: webhook needs exactly one of url_file and url")
		}
	}
	if c.SMTP == nil && c.Webhook == nil && !dryRun {
		return errors.New("config: configure smtp or webhook (or use --dry-run)")
	}
	return nil
}

func (s *SMTPConfig) normalize() error {
	if strings.TrimSpace(s.Host) == "" {
		return errors.New("config: smtp.host is required")
	}
	if s.Port == 0 {
		s.Port = 587
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("config: smtp.port %d is out of range", s.Port)
	}
	if s.Username != "" && s.PasswordFile == "" {
		return errors.New("config: smtp.username needs smtp.password_file")
	}
	if s.Helo != "" && !heloRe.MatchString(s.Helo) {
		return fmt.Errorf("config: smtp.helo %q must be a host name such as notify.example.org", s.Helo)
	}
	if s.From == "" {
		return errors.New("config: smtp.from is required")
	}
	if _, err := parseAddress(s.From); err != nil {
		return fmt.Errorf("config: smtp.from: %w", err)
	}
	for _, t := range s.To {
		if _, err := parseAddress(t); err != nil {
			return fmt.Errorf("config: smtp.to: %w", err)
		}
	}
	return nil
}

var heloRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$`)

// hostname is os.Hostname, replaceable in tests.
var hostname = os.Hostname

// heloName is the name sent in EHLO: smtp.helo, else the host's name when it
// is a fully qualified name, else "localhost". Some relays (smtp-relay.gmail.com)
// do not offer STARTTLS to a client that calls itself localhost.
func heloName(s *SMTPConfig) string {
	if s.Helo != "" {
		return s.Helo
	}
	if h, err := hostname(); err == nil && strings.Contains(h, ".") && heloRe.MatchString(h) {
		return h
	}
	return "localhost"
}

func parseAddress(s string) (*mail.Address, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("address contains a line break")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", s, err)
	}
	return a, nil
}
