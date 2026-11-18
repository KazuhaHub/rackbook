package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
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
}

type RackbookConfig struct {
	URL       string `yaml:"url"`
	TokenFile string `yaml:"token_file"`
}

type SMTPConfig struct {
	Host         string   `yaml:"host"`
	Port         int      `yaml:"port"`
	Username     string   `yaml:"username"`
	PasswordFile string   `yaml:"password_file"`
	From         string   `yaml:"from"`
	To           []string `yaml:"to"`
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
	switch c.Language {
	case "":
		c.Language = "en"
	case "en", "zh":
	default:
		return fmt.Errorf("config: language %q must be en or zh", c.Language)
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
	if s.From == "" || len(s.To) == 0 {
		return errors.New("config: smtp.from and smtp.to are required")
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
