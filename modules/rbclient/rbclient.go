// Package rbclient is a small client for the parts of Rackbook's public HTTP
// API that modules use: listing, creating and updating records, and the
// expiry list. Modules talk to Rackbook only through this API, with a Rackbook
// API token; they never touch Git or the data repository.
package rbclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Client calls one Rackbook server.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for the server at baseURL (for example
// https://rackbook.example.org) that authenticates with token (rbk_…).
func New(baseURL, token string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("rackbook url %q is not an absolute URL", baseURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("rackbook url %q: use https (http only for localhost)", baseURL)
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("empty Rackbook API token")
	}
	return &Client{base: u.String(), token: strings.TrimSpace(token), http: &http.Client{Timeout: 60 * time.Second}}, nil
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// SetHTTPClient replaces the HTTP client (tests).
func (c *Client) SetHTTPClient(h *http.Client) { c.http = h }

// Record is one ledger record.
type Record struct {
	ID   string         `json:"id"`
	Hash string         `json:"hash"`
	Data map[string]any `json:"data"`
}

// Item is one entry of the expiry list.
type Item struct {
	Collection string `json:"collection"`
	ID         string `json:"id"`
	Label      string `json:"label"`
	Expires    string `json:"expires"`
	DaysLeft   *int   `json:"daysLeft"`
	Status     string `json:"status"` // expired | expiring | unknown
	Source     string `json:"source"`
}

// Expiring is the answer of GET /api/expiring.
type Expiring struct {
	Today string `json:"today"`
	Days  int    `json:"days"`
	Items []Item `json:"items"`
}

// Error is an error answer of the API.
type Error struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("rackbook: HTTP %d", e.Status)
	}
	return fmt.Sprintf("rackbook: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// IsConflict reports a 409 (the record changed, or the id already exists).
func IsConflict(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusConflict
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		e := &Error{Status: resp.StatusCode}
		_ = json.Unmarshal(data, e)
		return e
	}
	if out == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(out)
}

// List returns every record of a collection.
func (c *Client) List(ctx context.Context, collection string) ([]Record, error) {
	var out struct {
		Records []Record `json:"records"`
	}
	err := c.do(ctx, http.MethodGet, "/api/c/"+url.PathEscape(collection), nil, &out)
	return out.Records, err
}

// Create adds a record and returns it as stored.
func (c *Client) Create(ctx context.Context, collection string, data map[string]any) (*Record, error) {
	var out Record
	err := c.do(ctx, http.MethodPost, "/api/c/"+url.PathEscape(collection), map[string]any{"data": data}, &out)
	return &out, err
}

// Update replaces the record id, which must still have hash.
func (c *Client) Update(ctx context.Context, collection, id, hash string, data map[string]any) (*Record, error) {
	var out Record
	err := c.do(ctx, http.MethodPut, "/api/c/"+url.PathEscape(collection)+"/"+url.PathEscape(id), map[string]any{"data": data, "hash": hash}, &out)
	return &out, err
}

// Expiring lists records that expired or expire within days. Empty
// collections means every collection with an expiry field.
func (c *Client) Expiring(ctx context.Context, days int, collections []string, unknown bool) (*Expiring, error) {
	q := url.Values{}
	q.Set("days", strconv.Itoa(days))
	for _, col := range collections {
		q.Add("collection", col)
	}
	if unknown {
		q.Set("unknown", "true")
	}
	var out Expiring
	err := c.do(ctx, http.MethodGet, "/api/expiring?"+q.Encode(), nil, &out)
	return &out, err
}

// ReadSecret reads a secret file. A relative name is looked up in
// $CREDENTIALS_DIRECTORY (systemd LoadCredential); surrounding whitespace is
// trimmed.
func ReadSecret(name string) (string, error) {
	b, err := os.ReadFile(SecretPath(name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// SecretPath resolves a secret file name: absolute paths stay, relative names
// are joined to $CREDENTIALS_DIRECTORY when it is set.
func SecretPath(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		return filepath.Join(dir, name)
	}
	return name
}
