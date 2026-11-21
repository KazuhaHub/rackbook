package gitstore

// GitHub App credentials for git over HTTPS. The installation token reaches git
// only through the environment of one command: GIT_CONFIG_COUNT/KEY/VALUE set
// an http.<url>.extraheader that is scoped to the repository's own URL. It is
// never in argv, in the remote URL, in .git/config or in a log.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/kazuhahub/rackbook/internal/githubapp"
)

// TokenSource hands out installation tokens (githubapp.App).
type TokenSource interface {
	Token(ctx context.Context, owner, repo string, p githubapp.Permissions) (string, error)
	API() string
}

// GitAuth makes fetches and pushes of one repository use a GitHub App.
type GitAuth struct {
	Source TokenSource
	// Perms is what the token may do: contents write for the ledger, contents
	// read for a clone Rackbook only reads.
	Perms githubapp.Permissions
}

// env returns the environment for one network command against remote.
func (a *GitAuth) env(ctx context.Context, remote string) ([]string, error) {
	host, owner, repo, err := ParseRemote(remote)
	if err != nil {
		return nil, fmt.Errorf("github app: %w", err)
	}
	// The token's repository and the rewrite target come from the origin URL
	// alone, and the token goes only to the host that belongs to the App's API.
	if want := githubapp.GitHost(a.Source.API()); host != want {
		return nil, fmt.Errorf("github app: refusing to send an installation token to %s: the App's API (%s) serves git on %s", host, a.Source.API(), want)
	}
	var match string // the URL the header is scoped to
	var extra [][2]string
	if strings.HasPrefix(remote, "https://") || strings.HasPrefix(remote, "http://") {
		u, perr := url.Parse(remote)
		if perr != nil {
			return nil, fmt.Errorf("github app: cannot parse the remote URL")
		}
		if u.Scheme != "https" && !githubapp.IsLoopback(u.Hostname()) {
			return nil, fmt.Errorf("github app: refusing to send an installation token over plain http to %s", u.Host)
		}
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		match = u.String()
	} else {
		// ssh:// or scp-like origin: speak https to the same repository for these
		// commands only; .git/config keeps the original URL.
		match = "https://" + host + "/" + owner + "/" + repo + ".git"
		extra = append(extra, [2]string{"url." + match + ".insteadOf", remote})
	}
	tok, err := a.Source.Token(ctx, owner, repo, a.Perms)
	if err != nil {
		return nil, err
	}
	hdr := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok))
	// Redirects are refused, so the request (and its header) cannot be sent on.
	pairs := append([][2]string{{"http." + match + ".extraheader", hdr}, {"http.followRedirects", "false"}}, extra...)
	env := []string{fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(pairs))}
	for i, p := range pairs {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, p[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, p[1]))
	}
	return env, nil
}
