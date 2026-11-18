package gitstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var scpLike = regexp.MustCompile(`^(?:[^@/]+@)?([^:/]+):(.+)$`)

// ParseRemote extracts host, owner and repository from a Git remote URL
// (https, ssh:// or scp-like syntax).
func ParseRemote(raw string) (host, owner, repo string, err error) {
	var path string
	switch {
	case strings.Contains(raw, "://"):
		u, perr := url.Parse(raw)
		if perr != nil || u.Host == "" {
			return "", "", "", fmt.Errorf("cannot parse remote %q", raw)
		}
		host, path = u.Hostname(), strings.TrimPrefix(u.Path, "/")
	case scpLike.MatchString(raw) && !strings.HasPrefix(raw, "/"):
		m := scpLike.FindStringSubmatch(raw)
		host, path = m[1], m[2]
	default:
		return "", "", "", fmt.Errorf("remote %q is not a GitHub URL", raw)
	}
	path = strings.TrimSuffix(strings.TrimSuffix(path, "/"), ".git")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("cannot find owner/repo in remote %q", raw)
	}
	return host, parts[len(parts)-2], parts[len(parts)-1], nil
}

// createPR opens a pull request and returns its URL.
func (s *Store) createPR(ctx context.Context, head, base, title, body string) (string, error) {
	owner, repo, api := s.ghOwner, s.ghRepo, s.ghAPI
	if owner == "" || api == "" {
		host, o, r, err := ParseRemote(s.remote)
		if err != nil {
			if owner == "" {
				return "", err
			}
			return "", fmt.Errorf("cannot tell which GitHub host to send the token to (%v): set --github-api", err)
		}
		if owner == "" {
			owner, repo = o, r
		}
		if api == "" {
			if host != "github.com" && host != "www.github.com" {
				return "", fmt.Errorf("refusing to send RACKBOOK_GITHUB_TOKEN to %s: set --github-api to its REST API URL to allow it", host)
			}
			api = "https://api.github.com"
		}
	}
	payload, _ := json.Marshal(map[string]string{"title": title, "head": head, "base": base, "body": body})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/%s/pulls", strings.TrimRight(api, "/"), owner, repo), bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rackbook")
	resp, err := s.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(data))
		}
		return "", fmt.Errorf("github: create pull request: %s: %s", resp.Status, e.Message)
	}
	var out struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.HTMLURL == "" {
		return "", fmt.Errorf("github: unexpected response: %s", strings.TrimSpace(string(data)))
	}
	return out.HTMLURL, nil
}
