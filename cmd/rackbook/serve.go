package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/auth/oauth"
	"github.com/kazuhahub/rackbook/internal/clientip"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/login"
	"github.com/kazuhahub/rackbook/internal/mcpauth"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
	"github.com/kazuhahub/rackbook/internal/tokens"
	"github.com/kazuhahub/rackbook/web"
)

func newServe() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the web console, JSON API and MCP endpoint",
		Long: `Serve the web console, the JSON API (/api), the exports (/llms.txt, /export.md, ...) and MCP (/mcp).

Run it on a clone it owns (--repo): the server fetches and resets that clone to
origin and commits every write. It listens on 127.0.0.1 by default and is meant to
sit behind Cloudflare Tunnel or a reverse proxy; use --auth cloudflare-access to
verify Cloudflare Access tokens, or --auth oidc for the built-in login (see the
README): it needs --base-url (https), RACKBOOK_OIDC_CLIENT_SECRET and a session
key (RACKBOOK_SESSION_KEY or --session-key-file). --tls-cert and --tls-key serve
HTTPS directly, for local testing or a host without a reverse proxy.

Pull request mode (write.mode: pr in rackbook.yml) reads a GitHub token from
RACKBOOK_GITHUB_TOKEN.`,
		Args: cobra.NoArgs,
		RunE: runServe,
	}
	f := cmd.Flags()
	f.String("listen", "127.0.0.1:8080", "address to listen on")
	f.String("repo", "", "data repository directory (default: the directory of the config)")
	f.String("auth", "", "authentication: none, cloudflare-access or oidc (default: auth.mode in rackbook.yml, else none)")
	f.String("session-key-file", "", "file with the base64 session signing key (--auth oidc; alternative to RACKBOOK_SESSION_KEY)")
	f.String("oidc-ca-file", "", "extra CA certificates (PEM) to trust for the OIDC issuer, for a private CA (--auth oidc)")
	f.String("tls-cert", "", "TLS certificate file: serve HTTPS (needs --tls-key)")
	f.String("tls-key", "", "TLS private key file")
	f.String("cf-team", "", "Cloudflare Access team name (<team>.cloudflareaccess.com)")
	f.String("cf-aud", "", "Cloudflare Access application audience (AUD) tag")
	f.String("editor", "", `attribute writes to "Name <email>" (auth none)`)
	f.StringSlice("editors", nil, "emails / service-token names allowed to write, added to auth.editors / auth.roles.editor (default: everyone)")
	f.String("accept-remote", "", "accept the remote's rewritten history: the commit hash of the current origin tip, checked first (see docs/design.md, Git)")
	f.Bool("read-only", false, "refuse all writes")
	f.Bool("no-git", false, "edit files in place without Git, even inside a repository")
	f.String("state-dir", "", "directory for runtime state kept across restarts (token last use); outside the data repository; empty = memory only")
	f.Duration("pull-interval", time.Minute, "how often to fetch and fast-forward from origin (0 disables)")
	f.String("committer", gitstore.DefaultCommitter.String(), `committer identity of server commits ("Name <email>")`)
	f.String("base-url", "", "public URL of the console, used in /llms.txt (default: derived from the request)")
	f.Bool("insecure-no-auth", false, "allow --auth none on a non-loopback --listen address (anyone who can reach it can edit)")
	f.String("github-repo", "", "owner/repo for pull requests (default: parsed from the origin URL)")
	f.String("github-api", "", "GitHub REST API base URL (default: derived from the origin host)")
	f.StringSlice("trusted-proxy", nil, "CIDRs (or addresses) of reverse proxies whose CF-Connecting-IP header is believed when rate-limiting failed API-token attempts")
	return cmd
}

func runServe(cmd *cobra.Command, _ []string) error {
	f := cmd.Flags()
	repo, _ := f.GetString("repo")
	path, err := configPath(cmd, repo)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if commit, _ := f.GetString("accept-remote"); commit != "" {
		if ro, _ := f.GetBool("read-only"); ro {
			return errors.New("--accept-remote changes the server's clone, so it cannot be combined with --read-only")
		}
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	committerStr, _ := f.GetString("committer")
	committer, err := gitstore.ParseIdentity(committerStr)
	if err != nil {
		return fmt.Errorf("--committer: %w", err)
	}
	noGit, _ := f.GetBool("no-git")
	interval, _ := f.GetDuration("pull-interval")
	ghRepo, _ := f.GetString("github-repo")
	ghAPI, _ := f.GetString("github-api")
	store, err := gitstore.Open(ctx, gitstore.Options{
		ConfigPath: path, NoGit: noGit, Committer: committer, PullInterval: interval,
		GitHubToken: os.Getenv("RACKBOOK_GITHUB_TOKEN"), GitHubRepo: ghRepo, GitHubAPI: ghAPI, Logger: logger,
	})
	if err != nil {
		return err
	}
	if commit, _ := f.GetString("accept-remote"); commit != "" {
		hash, err := store.AcceptRemote(ctx, commit)
		if err != nil {
			return fmt.Errorf("--accept-remote: %w", err)
		}
		logger.Warn("accepted the remote history", "remote", hash)
	}
	go store.Run(ctx)

	// auth.roles and auth.editors are read from the store's current config on every
	// request, so a config reload on pull changes roles without a restart.
	mode, _ := f.GetString("auth")
	if mode == "" {
		mode = cfg.Auth.Mode
	}
	if mode == "" {
		mode = auth.ModeNone
	}
	team, _ := f.GetString("cf-team")
	aud, _ := f.GetString("cf-aud")
	editor, _ := f.GetString("editor")
	editors, _ := f.GetStringSlice("editors")
	baseURL, _ := f.GetString("base-url")
	readOnly, _ := f.GetBool("read-only")
	var loginSvc *login.Service
	acfg := auth.Config{Mode: mode, Team: team, Audience: aud, Editor: editor, Editors: editors, Config: store.Config, Degraded: func() bool { return store.ConfigProblem() != "" }}
	if mode == auth.ModeOIDC {
		caFile, _ := f.GetString("oidc-ca-file")
		if loginSvc, err = newLogin(cfg, store, baseURL, caFile, f, readOnly, logger); err != nil {
			return err
		}
		acfg.Sessions = loginSvc
	}
	authn, err := auth.New(ctx, acfg)
	if err != nil {
		return err
	}
	if loginSvc != nil {
		loginSvc.Bind(authn)
		go loginSvc.Warm()
		if cfg.Auth.Roles == nil && len(cfg.Auth.Editors) == 0 && len(editors) == 0 {
			logger.Warn("auth.roles is not set: everyone who can log in is an editor; with a tenant-wide Entra app that is the whole tenant. Add auth.roles to rackbook.yml")
		}
	}

	dist, err := fs.Sub(web.FS, "dist")
	if err != nil {
		return err
	}
	var loginMount interface {
		Mount(mux *http.ServeMux, static http.Handler)
	}
	if loginSvc != nil {
		loginMount = loginSvc
	}
	// Bearer credentials on /mcp (OAuth access tokens of the trusted issuers) and
	// Rackbook API tokens (see docs/api.md); /mcp is an OAuth protected resource.
	proxies, perr := clientip.ParseCIDRs(trustedProxies(f))
	if perr != nil {
		return fmt.Errorf("--trusted-proxy: %w", perr)
	}
	registry := &tokens.Registry{Store: store}
	if dir, _ := f.GetString("state-dir"); dir != "" {
		// a file inside the clone would make it dirty and stop every write
		abs, _ := filepath.Abs(dir)
		if rel, err := filepath.Rel(cfg.Dir, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("--state-dir %s is inside the data repository; put it beside the clone", dir)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("--state-dir: %w", err)
		}
		registry.UsePath = filepath.Join(dir, "token-use.json")
	}
	resource := &mcpauth.Resource{Config: store.Config, Auth: authn, Verifier: &oauth.Verifier{}, Tokens: registry, Limiter: &tokens.Limiter{}, TrustedProxies: proxies, Log: logger}
	authn.SetBearer(resource)
	meta := resource.MetadataHandler()
	mcpSrv := mcpserver.NewWithOptions(mcpserver.Options{Source: store.Ledger, Version: version, Backend: store, ReadOnly: readOnly, Logger: logger})
	handler := api.New(api.Options{
		Store: store, Auth: authn, ReadOnly: readOnly, BaseURL: baseURL, Web: dist, Logger: logger, RestrictHost: mode == auth.ModeNone, Login: loginMount,
		MCP:    mcpauth.Handler(mcpserver.Handler(mcpSrv, mode != auth.ModeNone || baseURL != "" || cfg.Auth.MCP.Enabled())),
		Public: map[string]http.Handler{mcpauth.MetadataPath: meta, mcpauth.MetadataPathMCP: meta},
		Tokens: registry,
	})

	addr, _ := f.GetString("listen")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if insecure, _ := f.GetBool("insecure-no-auth"); mode == auth.ModeNone && !isLoopback(ln.Addr().String()) {
		if !insecure {
			ln.Close()
			return fmt.Errorf("refusing to listen on %s without authentication: use --auth cloudflare-access, listen on 127.0.0.1, or pass --insecure-no-auth (RACKBOOK_INSECURE_NO_AUTH=true) to accept the risk", ln.Addr())
		}
		logger.Warn("listening on a non-loopback address with --auth none: anyone who can reach it can read and edit the ledger")
	}
	certFile, _ := f.GetString("tls-cert")
	keyFile, _ := f.GetString("tls-key")
	if (certFile == "") != (keyFile == "") {
		ln.Close()
		return errors.New("--tls-cert and --tls-key go together")
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute}
	logger.Info("rackbook serving", "version", version, "title", cfg.Title, "listen", ln.Addr().String(),
		"git", store.GitEnabled(), "remote", store.HasRemote(), "auth", mode, "tls", certFile != "", "readOnly", readOnly, "writeMode", cfg.Write.Mode,
		"console", consoleBuilt(dist))

	errc := make(chan error, 1)
	go func() {
		if certFile != "" {
			errc <- srv.ServeTLS(ln, certFile, keyFile)
			return
		}
		errc <- srv.Serve(ln)
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func trustedProxies(f *pflag.FlagSet) []string {
	v, _ := f.GetStringSlice("trusted-proxy")
	return v
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func consoleBuilt(dist fs.FS) bool {
	_, err := fs.Stat(dist, "index.html")
	return err == nil
}

// newLogin builds the built-in login for --auth oidc: the OIDC client secret
// comes only from RACKBOOK_OIDC_CLIENT_SECRET, the session key from
// RACKBOOK_SESSION_KEY or --session-key-file.
func newLogin(cfg *config.Config, store *gitstore.Store, baseURL, caFile string, f *pflag.FlagSet, readOnly bool, logger *slog.Logger) (*login.Service, error) {
	keyFile, _ := f.GetString("session-key-file")
	key, err := login.LoadSessionKey(os.Getenv("RACKBOOK_SESSION_KEY"), keyFile)
	if err != nil {
		return nil, err
	}
	secret := os.Getenv("RACKBOOK_OIDC_CLIENT_SECRET")
	if secret == "" {
		return nil, errors.New("--auth oidc needs the client secret in RACKBOOK_OIDC_CLIENT_SECRET (it is never read from rackbook.yml)")
	}
	if baseURL == "" {
		return nil, errors.New("--auth oidc needs --base-url (the public https URL of the console; the IdP redirects to <base-url>/auth/oidc/callback)")
	}
	proxies, err := clientip.ParseCIDRs(trustedProxies(f))
	if err != nil {
		return nil, fmt.Errorf("--trusted-proxy: %w", err)
	}
	o := login.Options{
		TrustedProxies: proxies, Login: cfg.Auth.Login, Config: store.Config, BaseURL: baseURL, Key: key, ClientSecret: secret, CAFile: caFile,
		ReadOnly: readOnly, Logger: logger,
	}
	if cfg.Auth.Passkeys.Enabled {
		o.Files = store
	}
	return login.New(o)
}
