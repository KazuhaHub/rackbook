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
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/auth/oauth"
	"github.com/kazuhahub/rackbook/internal/clientip"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/githubapp"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/login"
	"github.com/kazuhahub/rackbook/internal/mcpauth"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
	"github.com/kazuhahub/rackbook/internal/modules"
	"github.com/kazuhahub/rackbook/internal/oauthserver"
	"github.com/kazuhahub/rackbook/internal/prefs"
	"github.com/kazuhahub/rackbook/internal/routes"
	"github.com/kazuhahub/rackbook/internal/sops"
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
	f.String("state-dir", "", "directory for runtime state kept across restarts (token last use, module runs, OAuth grants and signing key); outside the data repository; one server holds a lock on it; empty = memory only")
	f.String("audit-addr", "truncate", "how much of the client address the audit log keeps: full, truncate (IPv4 without the last octet, IPv6 first 48 bits) or none; needs --state-dir")
	f.Int("audit-retention-months", 0, "delete audit log months older than this many whole months before the current one (0 = keep everything); needs --state-dir")
	f.Duration("pull-interval", time.Minute, "how often to fetch and fast-forward from origin (0 disables)")
	f.String("committer", gitstore.DefaultCommitter.String(), `committer identity of server commits ("Name <email>")`)
	f.String("base-url", "", "public URL of the console, used in /llms.txt (default: derived from the request)")
	f.Bool("insecure-no-auth", false, "allow --auth none on a non-loopback --listen address (anyone who can reach it can edit)")
	f.String("github-repo", "", "owner/repo for pull requests (default: parsed from the origin URL)")
	f.String("github-api", "", "GitHub REST API base URL (default: derived from the origin host)")
	f.String("github-app-id", "", "GitHub App ID (or "+appIDEnv+"): fetch and push over https with installation tokens narrowed to each repository, for the data repository and --infra-repo, instead of SSH deploy keys; needs the private key from --github-app-key-file, "+appKeyEnv+" or a systemd credential (see README, Creating the GitHub App)")
	f.String("github-app-key-file", "", "private key (PEM) of the GitHub App; never put the key itself on the command line")
	f.String("infra-repo", "", "directory of a git clone of an Ansible + SOPS repository shown under /infra (needs --auth oidc, --infra-admins, --infra-oidc-issuer and --infra-oidc-client-id); Rackbook fetches and resets it to origin on --pull-interval, and writes to it only with --infra-write")
	f.String("infra-branch", "main", "branch of --infra-repo to follow")
	f.String("infra-ssh-key", "", "private key (read-only deploy key) Rackbook uses to fetch --infra-repo; only for that clone (a known_hosts file beside it is used when present)")
	f.String("infra-oidc-issuer", "", "issuer URL of the identity provider the infra administrators sign in with; /infra refuses a session issued under any other (pinned here because auth.oidc in rackbook.yml lives in the ledger, which other people can edit); needs --infra-repo")
	f.String("infra-oidc-client-id", "", "client ID of the sign-in application, pinned like --infra-oidc-issuer; needs --infra-repo")
	f.String("infra-oidc-identity-claim", "preferred_username", "the ID token claim the administrators' identities are taken from (\"sub\" for subject identities); /infra refuses a session whose identity came from another claim, so auth.oidc.identity_claim in rackbook.yml cannot change who is an administrator; needs --infra-repo")
	f.String("infra-oidc-tenant", "", "the tenant (tid claim) the administrators sign in from; required for an Entra issuer, and a tenant GUID in --infra-oidc-issuer must equal it; /infra refuses a session from another tenant (allowed_tenants in rackbook.yml is not trusted); needs --infra-repo")
	f.Bool("infra-write", false, "turn on the infra editors: one commit per edit on --infra-branch (needs --github-app-id with Contents: write on that repository, and --infra-repo)")
	f.String("sops-age-key-file", "", "age identity file Rackbook edits the SOPS secrets of --infra-repo with (its own key, a recipient of every file; needs --infra-write, and the sops and age-keygen binaries); empty = the secrets editor is off")
	f.Duration("infra-write-max-age", auth.DefaultInfraWriteAge, "how recent an administrator's sign-in must be for an infra write (older: sign in again)")
	f.String("infra-managed-group", "managed", `inventory group whose hosts must each have host_vars and a SOPS file, and that holds every host of every group ("" = no such check)`)
	f.String("infra-agent-group", "infra_agent", `inventory group that must list exactly the managed hosts, checked only when the inventory has it ("" = no such check)`)
	f.StringSlice("infra-admins", nil, "exact identities (comma-separated) who may see /infra, and at most one group:<id> or app-role:<value> entry (the syntax of auth.roles; it needs the --infra-oidc-issuer, -client-id and -tenant pins, and counts for auth.session.claims_absolute after the sign-in); they must sign in with --auth oidc (API tokens, MCP and OAuth tokens never count; not read from rackbook.yml)")
	f.StringSlice("infra-auditors", nil, "exact identities (comma-separated) who may read /infra but not its secrets and may change nothing; the same rules as --infra-admins, with its own single group:/app-role: entry, independent of the administrators' (OIDC login sessions only, the identity provider pinned by the --infra-oidc-* flags; needs --infra-admins)")
	f.String("hub-status-file", "", "status.json of the infra hub (infra-hub status -o json), shown under /infra; kept fresh by a timer outside Rackbook (needs --infra-repo)")
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
	for _, w := range cfg.Warnings {
		if w != cfg.Auth.Login.PasskeysIgnoredWarning() { // the login service says that one itself
			logger.Warn("rackbook.yml: " + w)
		}
	}

	committerStr, _ := f.GetString("committer")
	committer, err := gitstore.ParseIdentity(committerStr)
	if err != nil {
		return fmt.Errorf("--committer: %w", err)
	}
	noGit, _ := f.GetBool("no-git")
	interval, _ := f.GetDuration("pull-interval")
	ghRepo, _ := f.GetString("github-repo")
	ghAPI, _ := f.GetString("github-api")
	app, err := newGitHubApp(f, ghAPI)
	if err != nil {
		return err
	}
	var appSource gitstore.TokenSource
	if app != nil {
		appSource = app
		logger.Info("GitHub App credentials on", "api", app.API())
	}
	// The state directory is prepared first: the audit log lives in it, and the
	// store and the login record into the log from their first request on.
	stateDir, _ := f.GetString("state-dir")
	baseURL, _ := f.GetString("base-url")
	if cfg.Auth.MCP.BuiltinIssuer.Enabled && (stateDir == "" || baseURL == "") {
		return errors.New("auth.mcp.builtin_issuer needs --state-dir (it keeps the grants and the signing key there) and --base-url (the public URL, which is the issuer of its tokens)")
	}
	addrMode, retention, err := auditFlags(f)
	if err != nil {
		return err
	}
	var auditLog *audit.Log
	if stateDir == "" {
		warnAuditWithoutState(logger, addrMode, retention)
	}
	if stateDir != "" {
		unlock, err := prepareStateDir(cfg, stateDir, cfg.Auth.MCP.BuiltinIssuer.Enabled, logger)
		if err != nil {
			return err
		}
		defer unlock()
		if auditLog, err = audit.Open(filepath.Join(stateDir, "audit"), audit.Options{Addr: addrMode, RetentionMonths: retention, Logger: logger, InfraPath: filepath.Join(stateDir, "infra-audit.jsonl")}); err != nil {
			return err
		}
		defer auditLog.Close()
	}

	// The audit anchors are checked at start and after each pull; audit.anchor: daily also writes
	// them (a loop started below). The hook runs only once the pull loop does.
	anchors := &anchorWiring{log: auditLog, logger: logger}
	store, err := gitstore.Open(ctx, gitstore.Options{GitHubApp: appSource, OnCommit: commitHook(auditLog, "ledger", filepath.Base(cfg.Dir)), StateDir: stateDir,
		AfterPull:  anchors.AfterPull,
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
	anchors.Start(ctx, store, readOnlyFlag(f))
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
	infra, err := newInfra(ctx, f, cfg, mode, interval, appSource, committer, readOnlyFlag(f), auditLog, logger)
	if err != nil {
		return err
	}
	team, _ := f.GetString("cf-team")
	aud, _ := f.GetString("cf-aud")
	editor, _ := f.GetString("editor")
	editors, _ := f.GetStringSlice("editors")
	readOnly, _ := f.GetBool("read-only")
	var loginSvc *login.Service
	// Per-person preferences; the file is set below once --state-dir is known
	// (the store reads it on first use).
	prefStore := &prefs.Store{}
	acfg := auth.Config{Mode: mode, Team: team, Audience: aud, Editor: editor, Editors: editors, Config: store.Config, Degraded: func() bool { return store.ConfigProblem() != "" }}
	if mode == auth.ModeOIDC {
		caFile, _ := f.GetString("oidc-ca-file")
		if loginSvc, err = newLogin(cfg, store, prefStore, baseURL, caFile, f, readOnly, auditLog, infra, logger); err != nil {
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
		Mount(mux routes.Mux, static http.Handler)
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
	modState := &modules.State{}
	builtin := cfg.Auth.MCP.BuiltinIssuer.Enabled
	if dir := stateDir; dir != "" {
		registry.UsePath = filepath.Join(dir, "token-use.json")
		modState.Path = filepath.Join(dir, "modules.json")
		prefStore.Path = filepath.Join(dir, "preferences.json")
	}
	if infra != nil && stateDir != "" {
		infra.RevealStatePath = filepath.Join(stateDir, "infra-reveals.json")
	}
	resource := &mcpauth.Resource{Config: store.Config, Auth: authn, Verifier: &oauth.Verifier{}, Tokens: registry, Limiter: &tokens.Limiter{}, TrustedProxies: proxies, Log: logger}
	var oauthSrv api.OAuthServer
	if builtin {
		srv, err := oauthserver.New(oauthserver.Options{Issuer: baseURL, Resource: cfg.Auth.MCP.Resource, StateDir: stateDir,
			Config: store.Config, Auth: authn, Log: logger, TrustedProxies: proxies, Prefs: prefStore})
		if err != nil {
			return err
		}
		resource.Builtin, oauthSrv = srv, srv
	}
	authn.SetBearer(resource)
	meta := resource.MetadataHandler()
	mcpSrv := mcpserver.NewWithOptions(mcpserver.Options{Source: store.Ledger, Version: version, Backend: store, ReadOnly: readOnly, Logger: logger})
	handler := api.New(api.Options{
		Store: store, Auth: authn, ReadOnly: readOnly, BaseURL: baseURL, Web: dist, Logger: logger, RestrictHost: mode == auth.ModeNone, Login: loginMount,
		MCP:    mcpauth.Handler(mcpserver.Handler(mcpSrv, mode != auth.ModeNone || baseURL != "" || cfg.Auth.MCP.Enabled())),
		Public: map[string]http.Handler{mcpauth.MetadataPath: meta, mcpauth.MetadataPathMCP: meta},
		Tokens: registry, Modules: modState, Prefs: prefStore, OAuth: oauthSrv, Infra: infra, Audit: auditLog,
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

// secureStateDir makes an existing state directory private (0700): it holds
// the grants and the signing key. MkdirAll gives a new one that mode but leaves
// an old one as it was. A directory whose mode cannot be changed is refused when
// the built-in authorization server uses it (strict), else only reported.
func secureStateDir(dir string, strict bool, logger *slog.Logger) error {
	if runtime.GOOS == "windows" {
		return nil // no Unix modes; the profile's ACLs apply
	}
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("--state-dir: %w", err)
	}
	if st.Mode().Perm() == 0o700 {
		return nil
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		if strict {
			return fmt.Errorf("--state-dir %s has mode %v and could not be changed to 0700 (it holds the OAuth signing key and grants): %w", dir, st.Mode().Perm(), err)
		}
		logger.Warn("the state directory is not private and its mode could not be changed", "dir", dir, "mode", st.Mode().Perm().String(), "err", err)
		return nil
	}
	logger.Warn("the state directory mode was changed to 0700", "dir", dir, "was", st.Mode().Perm().String())
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
func newLogin(cfg *config.Config, store *gitstore.Store, prefStore *prefs.Store, baseURL, caFile string, f *pflag.FlagSet, readOnly bool, auditLog *audit.Log, infra *api.InfraOptions, logger *slog.Logger) (*login.Service, error) {
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
		ReadOnly: readOnly, Logger: logger, Prefs: prefStore, Audit: auditLog,
	}
	if infra != nil {
		o.Infra = &auth.InfraAccess{Admins: infra.Admins, Auditors: infra.Auditors}
	}
	// auth.passkeys is ignored under OIDC (login.New says so), so no credential store is given
	return login.New(o)
}

// newInfra sets up the read-only /infra pages from the --infra-* flags: nil
// when --infra-repo is not given (and then none of the others may be).
func newInfra(ctx context.Context, f *pflag.FlagSet, cfg *config.Config, mode string, interval time.Duration, app gitstore.TokenSource, committer gitstore.Identity, readOnly bool, auditLog *audit.Log, logger *slog.Logger) (*api.InfraOptions, error) {
	ledgerDir := cfg.Dir
	dir, _ := f.GetString("infra-repo")
	admins, _ := f.GetStringSlice("infra-admins")
	status, _ := f.GetString("hub-status-file")
	key, _ := f.GetString("infra-ssh-key")
	if dir == "" {
		for _, name := range []string{"infra-admins", "infra-auditors", "hub-status-file", "infra-ssh-key", "infra-oidc-issuer", "infra-oidc-client-id", "infra-oidc-identity-claim", "infra-oidc-tenant", "infra-write", "sops-age-key-file", "infra-write-max-age", "infra-managed-group", "infra-agent-group"} {
			if f.Changed(name) {
				return nil, fmt.Errorf("--%s needs --infra-repo", name)
			}
		}
		return nil, nil
	}
	if mode != auth.ModeOIDC {
		return nil, errors.New("--infra-repo needs --auth oidc: /infra is open only to people who signed in with the console login")
	}
	ia, err := auth.NewInfraAdmins(admins)
	if err != nil {
		return nil, err
	}
	issuer, _ := f.GetString("infra-oidc-issuer")
	clientID, _ := f.GetString("infra-oidc-client-id")
	maxAge, _ := f.GetDuration("infra-write-max-age")
	claim, _ := f.GetString("infra-oidc-identity-claim")
	tenant, _ := f.GetString("infra-oidc-tenant")
	if err := ia.Pin(issuer, clientID, claim, tenant, maxAge); err != nil {
		return nil, err
	}
	// a claim entry lapses claims_absolute after the sign-in, the value the login itself runs with
	ia.SetClaimsAbsolute(cfg.Auth.Session.ClaimsAbsoluteOrDefault())
	var infraAuditors *auth.InfraAdmins
	if f.Changed("infra-auditors") {
		auditors, _ := f.GetStringSlice("infra-auditors")
		if infraAuditors, err = auth.NewInfraAuditors(auditors); err != nil {
			return nil, err
		}
		// the same pinned provider, client, claim and tenant as the administrators
		if err := infraAuditors.Pin(issuer, clientID, claim, tenant, maxAge); err != nil {
			return nil, err
		}
		infraAuditors.SetClaimsAbsolute(cfg.Auth.Session.ClaimsAbsoluteOrDefault())
	}
	li := cfg.Auth.Login.OIDC
	liClaim, _ := li.ClaimsOrDefault()
	if li.BySubject() {
		liClaim = "sub"
	}
	if li.Issuer != issuer || li.ClientID != clientID || liClaim != claim {
		logger.Warn("the console login (auth.oidc in rackbook.yml) is not the identity provider pinned for /infra: nobody can open /infra until they match",
			"login_issuer", li.Issuer, "login_client_id", li.ClientID, "login_identity_claim", liClaim, "pinned_issuer", issuer, "pinned_client_id", clientID, "pinned_identity_claim", claim)
	}
	write, _ := f.GetBool("infra-write")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("--infra-repo: %w", err)
	}
	if inside(ledgerDir, absDir) || inside(absDir, ledgerDir) {
		return nil, fmt.Errorf("--infra-repo %s and the data repository %s must be separate directories", dir, ledgerDir)
	}
	branch, _ := f.GetString("infra-branch")
	managed, _ := f.GetString("infra-managed-group")
	agentGroup, _ := f.GetString("infra-agent-group")
	rules := ansiblerepo.DefaultRules()
	rules.ManagedGroup, rules.AgentGroup = managed, agentGroup
	// The entries stay in the server log (AuditLog); with --state-dir they also go to the audit log.
	var infraAudit ansiblerepo.Auditor = &ansiblerepo.AuditLog{Log: logger}
	if auditLog != nil {
		infraAudit = &audit.InfraAuditor{Log: auditLog, Next: infraAudit}
	}
	opts := ansiblerepo.Options{Dir: absDir, Branch: branch, Interval: interval, Logger: logger, Committer: committer, Rules: rules, Audit: infraAudit,
		OnCommit: func(hash string, who *auth.Identity, scope string) {
			infraCommitHook(auditLog, filepath.Base(absDir), hash, who, scope)
		}}
	if write && app == nil {
		return nil, errors.New("--infra-write needs --github-app-id: the editors push with an installation token that has Contents: write")
	}
	if app != nil {
		if key != "" {
			return nil, errors.New("--infra-ssh-key and --github-app-id are two ways to fetch --infra-repo: use one")
		}
		// Reading uses a token with contents: read. Only the editors (--infra-write) ever ask for contents: write.
		opts.Auth = &gitstore.GitAuth{Source: app, Perms: githubapp.Permissions{Contents: "read"}}
		if write {
			opts.WriteAuth = &gitstore.GitAuth{Source: app, Perms: githubapp.Permissions{Contents: "write"}}
		}
	}
	if key != "" {
		opts.SSHKey = key
		if kh := filepath.Join(filepath.Dir(key), "known_hosts"); fileExists(kh) {
			opts.KnownHosts = kh
		}
	}
	if keyFile, _ := f.GetString("sops-age-key-file"); keyFile != "" {
		if !write {
			return nil, errors.New("--sops-age-key-file needs --infra-write: a secret is edited by a commit")
		}
		if sd, _ := f.GetString("state-dir"); sd == "" {
			return nil, errors.New("--sops-age-key-file needs --state-dir: the limits on revealing secrets are kept there across restarts")
		}
		runner, err := sops.New(ctx, sops.Options{KeyFile: keyFile})
		if err != nil {
			return nil, fmt.Errorf("--sops-age-key-file: %w", err)
		}
		opts.Sops = runner
		logger.Info("secrets editor on", "recipient", runner.PublicKey())
	}
	repo, err := ansiblerepo.New(opts)
	if err != nil {
		return nil, err
	}
	go func() {
		if interval <= 0 { // --pull-interval 0: refreshed once, at start
			if err := repo.Refresh(ctx); err != nil {
				logger.Warn("infra repository refresh failed", "err", err)
			}
			return
		}
		repo.Run(ctx)
	}()
	logger.Info("infra pages on", "repo", absDir, "branch", branch, "admins", ia.Len(), "adminClaim", ia.ClaimEntry(), "auditors", infraAuditors.Len(), "auditorClaim", infraAuditors.ClaimEntry(), "hubStatus", status != "", "editors", write && !readOnly, "issuer", issuer, "writeMaxAge", ia.WriteAge().String())
	return &api.InfraOptions{Repo: repo, Admins: ia, Auditors: infraAuditors, StatusFile: status, Write: write, Audit: infraAudit}, nil
}

// inside reports whether path is dir or below it.
func inside(dir, path string) bool {
	dir, _ = filepath.Abs(dir)
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func readOnlyFlag(f *pflag.FlagSet) bool {
	v, _ := f.GetBool("read-only")
	return v
}
