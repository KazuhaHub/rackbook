package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxBrandingFile is the size limit of branding.logo and branding.favicon.
const MaxBrandingFile = 256 << 10

// MaxBrandingText is the length limit (in characters) of branding.name and auth.oidc.label.
const MaxBrandingText = 80

// Branding is the optional branding block: what the console calls itself and
// which images it shows. Logo and Favicon are paths relative to the directory
// of rackbook.yml; the files are read and checked when the config loads.
type Branding struct {
	Name    string `yaml:"name"`
	Logo    string `yaml:"logo"`    // .svg or .png
	Favicon string `yaml:"favicon"` // .svg, .png or .ico
}

// Asset is a checked branding file, held in memory so it can be served
// without touching the disk on every request.
type Asset struct {
	Data        []byte
	ContentType string
	ETag        string // quoted, from the content hash
}

// BrandLogo returns the custom logo, or nil when none is configured.
func (c *Config) BrandLogo() *Asset {
	if c == nil {
		return nil
	}
	return c.logo
}

// BrandFavicon returns the custom favicon, or nil when none is configured.
func (c *Config) BrandFavicon() *Asset {
	if c == nil {
		return nil
	}
	return c.favicon
}

// loadBranding validates the text and loads both images.
func (c *Config) loadBranding() error {
	b := &c.Branding
	b.Name = strings.TrimSpace(b.Name)
	if err := checkText("branding.name", b.Name); err != nil {
		return err
	}
	var err error
	if c.logo, err = c.loadAsset("branding.logo", b.Logo, ".svg", ".png"); err != nil {
		return err
	}
	if c.favicon, err = c.loadAsset("branding.favicon", b.Favicon, ".svg", ".png", ".ico"); err != nil {
		return err
	}
	return nil
}

// checkText rejects text that is too long or has control characters. It is
// shown in the console as plain text, never as HTML.
func checkText(key, s string) error {
	if utf8.RuneCountInString(s) > MaxBrandingText {
		return fmt.Errorf("%s must be at most %d characters", key, MaxBrandingText)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain control characters", key)
		}
	}
	return nil
}

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

func (c *Config) loadAsset(key, rel string, exts ...string) (*Asset, error) {
	if rel == "" {
		return nil, nil
	}
	ext := strings.ToLower(filepath.Ext(rel))
	ok := false
	for _, e := range exts {
		ok = ok || ext == e
	}
	if !ok {
		return nil, fmt.Errorf("%s: %q must be a %s file", key, rel, strings.Join(exts, ", "))
	}
	// Resolve refuses absolute paths, "..", .git/.rackbook and symlinks that
	// lead out of the data repository.
	abs, err := c.Resolve(rel)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	// Resolve checks .git/ and .rackbook/ by name; check where symlinks
	// actually lead too, so a committed link can't point into them.
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		if root, err := filepath.EvalSymlinks(c.Dir); err == nil {
			if r, err := filepath.Rel(root, real); err == nil {
				first := strings.SplitN(filepath.ToSlash(r), "/", 2)[0]
				if strings.EqualFold(first, ".git") || strings.EqualFold(first, StateDir) {
					return nil, fmt.Errorf("%s: %q leads into %s/, which is not part of the ledger", key, rel, first)
				}
			}
		}
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read %q: %w", key, rel, errors.Unwrap(err))
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %q is not a regular file", key, rel)
	}
	if st.Size() > MaxBrandingFile {
		return nil, fmt.Errorf("%s: %q is %d bytes; the limit is %d KiB", key, rel, st.Size(), MaxBrandingFile>>10)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read %q", key, rel)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxBrandingFile+1))
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read %q", key, rel)
	}
	if len(data) > MaxBrandingFile {
		return nil, fmt.Errorf("%s: %q is larger than %d KiB", key, rel, MaxBrandingFile>>10)
	}
	var ct string
	switch ext {
	case ".png":
		if !bytes.HasPrefix(data, pngMagic) {
			return nil, fmt.Errorf("%s: %q is not a PNG image (wrong file signature)", key, rel)
		}
		ct = "image/png"
	case ".ico":
		if !bytes.HasPrefix(data, []byte{0, 0, 1, 0}) {
			return nil, fmt.Errorf("%s: %q is not an ICO image (wrong file signature)", key, rel)
		}
		ct = "image/x-icon"
	case ".svg":
		if err := checkSVG(data); err != nil {
			return nil, fmt.Errorf("%s: %q %w", key, rel, err)
		}
		ct = "image/svg+xml"
	}
	return NewAsset(data, ct), nil
}

// NewAsset wraps image bytes; the ETag is a hash of the content.
func NewAsset(data []byte, contentType string) *Asset {
	sum := sha256.Sum256(data)
	return &Asset{Data: data, ContentType: contentType, ETag: `"` + hex.EncodeToString(sum[:16]) + `"`}
}

// checkSVG wants well-formed XML whose root element is <svg>.
func checkSVG(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	root := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("is not valid XML: %v", err)
		}
		if se, ok := tok.(xml.StartElement); ok && !root {
			if se.Name.Local != "svg" {
				return fmt.Errorf("is not an SVG image (the root element is <%s>, not <svg>)", se.Name.Local)
			}
			root = true
		}
	}
	if !root {
		return errors.New("is not an SVG image (no <svg> element)")
	}
	return nil
}
