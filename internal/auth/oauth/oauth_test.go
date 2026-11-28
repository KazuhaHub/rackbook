package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth/oauth/oauthtest"
	"github.com/kazuhahub/rackbook/internal/config"
)

const resource = "http://localhost:9999/mcp"

type fixture struct {
	iss *oauthtest.Issuer
	v   *Verifier
	cfg config.AuthMCP
	now time.Time
}

func newFixtureWith(t *testing.T, c oauthtest.Config, mut func(*config.TrustedIssuer)) *fixture {
	t.Helper()
	f := &fixture{iss: oauthtest.NewWith(t, c), now: time.Now()}
	f.v = &Verifier{Now: func() time.Time { return f.now }}
	ti := config.TrustedIssuer{Issuer: f.iss.URL, Alias: "idp", Kind: config.KindMCPHub}
	if mut != nil {
		mut(&ti)
	}
	f.cfg = config.AuthMCP{Resource: resource, TrustedIssuers: []config.TrustedIssuer{ti}}
	return f
}

func newFixture(t *testing.T) *fixture { return newFixtureWith(t, oauthtest.Config{}, nil) }

func (f *fixture) verify(raw string) (*Claims, error) {
	return f.v.Verify(context.Background(), raw, f.cfg)
}

func (f *fixture) mint(o oauthtest.Options) string {
	if o.Audience == nil {
		o.Audience = resource
	}
	o.Now = f.now
	return f.iss.Mint(o)
}

func wantInvalid(t *testing.T, err error, contains string) {
	t.Helper()
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), contains) {
		t.Fatalf("want invalid token (%q), got %v", contains, err)
	}
}

func TestGoodToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c, err := f.verify(f.mint(oauthtest.Options{Scope: "rackbook:write other", Subject: "Alice", ClientID: "cursor"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "Alice" || c.Username != "Alice" || c.ClientID != "cursor" || len(c.Scopes) != 2 || c.Scopes[0] != "rackbook:write" || c.Issuer != f.iss.URL || c.Kind != config.KindMCPHub || c.Alias != "idp" {
		t.Fatalf("%+v", c)
	}
	for _, typ := range []string{"AT+JWT", "application/at+jwt"} {
		if _, err := f.verify(f.mint(oauthtest.Options{Audience: []string{"https://other", resource}, Typ: typ})); err != nil {
			t.Fatalf("typ %s: %v", typ, err)
		}
	}
	if c, err := f.verify(f.mint(oauthtest.Options{})); err != nil || len(c.Scopes) != 0 {
		t.Fatalf("%v %+v", err, c)
	}
	f.cfg.TrustedIssuers[0].UsernameClaim = "preferred_username"
	if c, err := f.verify(f.mint(oauthtest.Options{Extra: map[string]any{"preferred_username": "alice@example.com"}})); err != nil || c.Username != "alice@example.com" {
		t.Fatalf("%v %+v", err, c)
	}
	wantInvalid(t, func() error { _, err := f.verify(f.mint(oauthtest.Options{})); return err }(), "username_claim")
}

func TestForgedAndWrongTokens(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.cfg.TrustedIssuers[0].Algorithms = []string{"ES256"}
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"alg none", f.iss.Unsigned(oauthtest.Options{Audience: resource, Now: f.now}), "accepted algorithm"},
		{"HS256 with the public key as secret", f.mint(oauthtest.Options{Alg: "HS256"}), "accepted algorithm"},
		{"RS256 when only ES256 is allowed", f.mint(oauthtest.Options{Alg: "RS256"}), "not allowed for this issuer"},
		{"wrong typ", f.mint(oauthtest.Options{Typ: "JWT"}), "typ"},
		{"id token typ", f.mint(oauthtest.Options{Typ: "id_token"}), "typ"},
		{"no typ", f.mint(oauthtest.Options{Typ: "-"}), "typ"},
		{"wrong issuer", f.mint(oauthtest.Options{Issuer: f.iss.URL + "/"}), "issuer"},
		{"unknown issuer", f.mint(oauthtest.Options{Issuer: "https://evil.example.com"}), "issuer"},
		{"wrong audience", f.mint(oauthtest.Options{Audience: "http://localhost:9999/other"}), "audience"},
		{"audience prefix", f.mint(oauthtest.Options{Audience: resource + "/"}), "audience"},
		{"expired", f.mint(oauthtest.Options{Exp: f.now.Add(-2 * time.Minute)}), "expired"},
		{"future nbf", f.mint(oauthtest.Options{NBF: f.now.Add(5 * time.Minute)}), "not valid yet"},
		{"future iat", f.mint(oauthtest.Options{IAT: f.now.Add(5 * time.Minute)}), "issued in the future"},
		{"no exp", f.mint(oauthtest.Options{NoExp: true}), "exp"},
		{"no sub", f.mint(oauthtest.Options{NoSub: true}), "sub"},
		{"garbage", "not.a.jwt", "not accepted"},
	}
	for _, c := range cases {
		_, err := f.verify(c.raw)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	other := oauthtest.New(t)
	forged := other.Mint(oauthtest.Options{Audience: resource, Now: f.now, Issuer: f.iss.URL})
	wantInvalid(t, func() error { _, err := f.verify(forged); return err }(), "signature")
}

func TestHS256CannotBeConfigured(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{"HS256", "none", "hs256", "RS1"} {
		cfg := `title: t
collections:
  a: {file: a.yml, schema: a.json}
auth:
  mcp:
    resource: https://ledger.example.com/mcp
    trusted_issuers:
      - {issuer: "https://idp.example.com", alias: idp, algorithms: [` + alg + `]}
`
		if _, err := config.Parse([]byte(cfg), "/x/rackbook.yml"); err == nil || !strings.Contains(err.Error(), "never accepted") {
			t.Errorf("%s: %v", alg, err)
		}
	}
}

func TestOtherSigningAlgorithms(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{"ES256", "RS256", "PS256", "EdDSA"} {
		f := newFixtureWith(t, oauthtest.Config{Alg: alg}, nil)
		if _, err := f.verify(f.mint(oauthtest.Options{Scope: "a"})); err != nil {
			t.Errorf("%s: %v", alg, err)
		}
		// A token signed with a foreign key of the same type under the published kid.
		if _, err := f.verify(f.mint(oauthtest.Options{Alg: alg})); err == nil {
			t.Errorf("%s: foreign key accepted", alg)
		}
	}
	// An algorithm outside the issuer's list is refused even with a valid signature.
	f := newFixtureWith(t, oauthtest.Config{Alg: "PS256"}, func(ti *config.TrustedIssuer) { ti.Algorithms = []string{"RS256"} })
	_, err := f.verify(f.mint(oauthtest.Options{}))
	wantInvalid(t, err, "not allowed for this issuer")
}

func TestEntraStyle(t *testing.T) {
	t.Parallel()
	// RS256, no typ at+jwt (typ JWT), scp scopes, an issuer with a /v2.0 path, and
	// OIDC metadata only.
	f := newFixtureWith(t, oauthtest.Config{Alg: "RS256", Path: "/v2.0", Discovery: "oidc"}, func(ti *config.TrustedIssuer) {
		ti.Kind, ti.Alias = "", "entra"
		off := false
		ti.RequireTypATJWT = &off
		ti.Audience = "api://rackbook"
		ti.UsernameClaim = "preferred_username"
	})
	mint := func(o oauthtest.Options) string {
		o.Audience, o.Typ, o.ClientID = "api://rackbook", "JWT", "-"
		if o.Scp == nil {
			o.Scp = "rackbook.write rackbook.read"
		}
		if o.Extra == nil {
			o.Extra = map[string]any{}
		}
		o.Extra["preferred_username"] = "Alice@Example.com"
		o.Extra["azp"] = "app-1"
		return f.mint(o)
	}
	c, err := f.verify(mint(oauthtest.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "Alice@Example.com" || c.ClientID != "app-1" || len(c.Scopes) != 2 || c.Scopes[0] != "rackbook.write" || c.Kind != config.KindOAuth || c.Alias != "entra" {
		t.Fatalf("%+v", c)
	}
	if c, err := f.verify(mint(oauthtest.Options{Scp: []string{"a", "b"}})); err != nil || len(c.Scopes) != 2 {
		t.Fatalf("scp array: %v %+v", err, c)
	}
	// No typ at all is accepted when at+jwt is not required ...
	if _, err := f.verify(mint(oauthtest.Options{Typ: "-"})); err != nil {
		t.Fatal(err)
	}
	// ... but with at+jwt required (the default) typ JWT is refused.
	f.cfg.TrustedIssuers[0].RequireTypATJWT = nil
	_, err = f.verify(mint(oauthtest.Options{}))
	wantInvalid(t, err, "typ")
}

func TestKeycloakStyleRealmPath(t *testing.T) {
	t.Parallel()
	for _, d := range []string{"rfc8414", "oidc", "both"} {
		f := newFixtureWith(t, oauthtest.Config{Alg: "RS256", Path: "/realms/ledger", Discovery: d}, func(ti *config.TrustedIssuer) {
			ti.Kind, ti.Alias = "", "kc"
			ti.ScopeClaim = "scope"
		})
		if c, err := f.verify(f.mint(oauthtest.Options{Scope: "openid rackbook:write"})); err != nil || len(c.Scopes) != 2 {
			t.Errorf("%s: %v %+v", d, err, c)
		}
	}
}

func TestIDTokenIsNotAnAccessToken(t *testing.T) {
	t.Parallel()
	f := newFixtureWith(t, oauthtest.Config{Alg: "RS256"}, func(ti *config.TrustedIssuer) {
		ti.Kind, ti.Alias = "", "idp"
		off := false
		ti.RequireTypATJWT = &off
	})
	// A real ID token: aud is the client id, not the resource.
	_, err := f.verify(f.mint(oauthtest.Options{Audience: "client-app", Typ: "JWT", Extra: map[string]any{"nonce": "n"}}))
	wantInvalid(t, err, "audience")
	// An ID token that somehow names the resource as audience: nonce and no scope.
	_, err = f.verify(f.mint(oauthtest.Options{Typ: "JWT", Extra: map[string]any{"nonce": "n"}, Scope: ""}))
	wantInvalid(t, err, "ID token")
	_, err = f.verify(f.mint(oauthtest.Options{Typ: "id_token", Scope: "x"}))
	wantInvalid(t, err, "typ")
	// With a scope the nonce alone does not matter.
	if _, err := f.verify(f.mint(oauthtest.Options{Typ: "JWT", Scope: "x", Extra: map[string]any{"nonce": "n"}})); err != nil {
		t.Fatal(err)
	}
}

func TestIntrospection(t *testing.T) {
	t.Parallel()
	f := newFixtureWith(t, oauthtest.Config{Path: "/realms/x", Discovery: "oidc"}, func(ti *config.TrustedIssuer) {
		ti.Kind, ti.Alias = "", "kc"
		ti.Introspection = &config.Introspection{ClientID: "rackbook", ClientSecretEnv: "RB_SECRET"}
	})
	f.v.Getenv = func(k string) string {
		if k == "RB_SECRET" {
			return "s3cret"
		}
		return ""
	}
	exp := float64(f.now.Add(10 * time.Minute).Unix())
	f.iss.Introspect = func(tok, id, secret string) map[string]any {
		if id != "rackbook" || secret != "s3cret" {
			return map[string]any{"active": false}
		}
		switch tok {
		case "opaque-good":
			return map[string]any{"active": true, "iss": f.iss.URL, "aud": []string{resource}, "sub": "alice", "client_id": "c1", "scope": "rackbook:write", "exp": exp}
		case "opaque-other-aud":
			return map[string]any{"active": true, "iss": f.iss.URL, "aud": "elsewhere", "sub": "alice", "exp": exp}
		case "opaque-other-iss":
			return map[string]any{"active": true, "iss": "https://evil.example.com", "aud": resource, "sub": "alice", "exp": exp}
		case "opaque-expired":
			return map[string]any{"active": true, "aud": resource, "sub": "alice", "exp": float64(f.now.Add(-time.Hour).Unix())}
		}
		return map[string]any{"active": false}
	}
	// The endpoint comes from the metadata, which a JWT verification or the
	// first introspection fetches.
	c, err := f.verify("opaque-good")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "alice" || c.ClientID != "c1" || len(c.Scopes) != 1 || c.Alias != "kc" {
		t.Fatalf("%+v", c)
	}
	// 60 s positive cache: no second call.
	n := f.iss.IntrospectCalls.Load()
	if _, err := f.verify("opaque-good"); err != nil || f.iss.IntrospectCalls.Load() != n {
		t.Fatalf("%v calls %d -> %d", err, n, f.iss.IntrospectCalls.Load())
	}
	f.now = f.now.Add(IntrospectionTTL + time.Second)
	if _, err := f.verify("opaque-good"); err != nil || f.iss.IntrospectCalls.Load() != n+1 {
		t.Fatalf("cache must expire: %v", err)
	}
	for tok, want := range map[string]string{"opaque-other-aud": "audience", "opaque-other-iss": "issuer", "opaque-expired": "expired", "opaque-revoked": "not active"} {
		_, err := f.verify(tok)
		wantInvalid(t, err, want)
	}
	f.now = f.now.Add(IntrospectionTTL + time.Second)
	// Without an introspection block opaque tokens are refused with a clear reason.
	f.cfg.TrustedIssuers[0].Introspection = nil
	_, err = f.verify("opaque-good")
	wantInvalid(t, err, "introspection")
	// A wrong client secret is "not active".
	f.cfg.TrustedIssuers[0].Introspection = &config.Introspection{ClientID: "rackbook", ClientSecretEnv: "OTHER"}
	f.v.Getenv = func(string) string { return "nope" }
	_, err = f.verify("opaque-good")
	wantInvalid(t, err, "not active")
}

func TestClockSkewIsSixtySeconds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if _, err := f.verify(f.mint(oauthtest.Options{Exp: f.now.Add(-30 * time.Second)})); err != nil {
		t.Fatalf("30 s past exp is within the skew: %v", err)
	}
	if _, err := f.verify(f.mint(oauthtest.Options{NBF: f.now.Add(30 * time.Second), IAT: f.now.Add(30 * time.Second)})); err != nil {
		t.Fatalf("30 s early is within the skew: %v", err)
	}
	if _, err := f.verify(f.mint(oauthtest.Options{Exp: f.now.Add(-90 * time.Second)})); err == nil {
		t.Fatal("90 s past exp must fail")
	}
}

func TestUnknownKidRefetchIsRateLimitedAndRotationWorks(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if _, err := f.verify(f.mint(oauthtest.Options{})); err != nil {
		t.Fatal(err)
	}
	if f.iss.JWKS.Load() != 1 {
		t.Fatalf("one JWKS fetch for the first token, got %d", f.iss.JWKS.Load())
	}
	for i := 0; i < 5; i++ {
		f.verify(f.mint(oauthtest.Options{}))
	}
	if f.iss.JWKS.Load() != 1 {
		t.Fatalf("cached keys must be reused, got %d fetches", f.iss.JWKS.Load())
	}
	f.iss.AddKey("k2")
	f.now = f.now.Add(10 * time.Second)
	if _, err := f.verify(f.mint(oauthtest.Options{KID: "k2"})); err == nil {
		t.Fatal("unknown kid within a minute of the last fetch must not refetch")
	}
	for i := 0; i < 20; i++ {
		f.verify(f.mint(oauthtest.Options{KID: "nope"}))
	}
	if n := f.iss.JWKS.Load(); n != 1 {
		t.Fatalf("refetch must be rate limited, got %d fetches", n)
	}
	f.now = f.now.Add(MinRefetch)
	if _, err := f.verify(f.mint(oauthtest.Options{KID: "k2"})); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if n := f.iss.JWKS.Load(); n != 2 {
		t.Fatalf("one refetch expected, got %d", n)
	}
	if _, err := f.verify(f.mint(oauthtest.Options{KID: "k1"})); err != nil {
		t.Fatal(err)
	}
	f.iss.DropKey("k1")
	f.now = f.now.Add(KeyTTL + time.Second)
	wantInvalid(t, func() error { _, err := f.verify(f.mint(oauthtest.Options{KID: "k1"})); return err }(), "unknown signing key")
	if _, err := f.verify(f.mint(oauthtest.Options{KID: "k2"})); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataIssuerMismatchAndTransport(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.iss.MetadataIssuer = "https://someone-else.example.com"
	_, err := f.verify(f.mint(oauthtest.Options{}))
	wantInvalid(t, err, "names issuer")

	f = newFixture(t)
	f.iss.JWKSURI = "http://keys.example.com/jwks.json"
	_, err = f.verify(f.mint(oauthtest.Options{}))
	wantInvalid(t, err, "must be https")

	if _, err := config.Parse([]byte(configWith("http://issuer.example.com")), "/x/rackbook.yml"); err == nil || !strings.Contains(err.Error(), "http is only allowed for localhost") {
		t.Fatalf("%v", err)
	}
	f = newFixture(t)
	f.cfg.TrustedIssuers = []config.TrustedIssuer{{Issuer: "http://issuer.example.com", Alias: "x"}}
	_, err = f.verify(f.iss.Mint(oauthtest.Options{Issuer: "http://issuer.example.com", Audience: resource, Now: f.now}))
	wantInvalid(t, err, "keys")

	f = newFixture(t)
	f.iss.MetadataIssuer = "https://someone-else.example.com"
	f.cfg.TrustedIssuers[0].JWKSURL = f.iss.URL + "/jwks.json"
	if _, err := f.verify(f.mint(oauthtest.Options{})); err != nil {
		t.Fatal(err)
	}
	if f.iss.Metadata.Load() != 0 {
		t.Fatal("metadata must not be fetched when jwks_url is set")
	}
}

func configWith(issuer string) string {
	return `title: t
collections:
  a: {file: a.yml, schema: a.json}
auth:
  mcp:
    resource: https://ledger.example.com/mcp
    trusted_issuers:
      - {issuer: ` + issuer + `, alias: idp}
`
}

func TestMetadataURLs(t *testing.T) {
	t.Parallel()
	for in, want := range map[string][]string{
		"https://mcp.example.com": {"https://mcp.example.com/.well-known/oauth-authorization-server", "https://mcp.example.com/.well-known/openid-configuration", "https://mcp.example.com/.well-known/openid-configuration"},
		"https://login.microsoftonline.com/t/v2.0": {
			"https://login.microsoftonline.com/.well-known/oauth-authorization-server/t/v2.0",
			"https://login.microsoftonline.com/t/v2.0/.well-known/openid-configuration",
			"https://login.microsoftonline.com/.well-known/openid-configuration/t/v2.0"},
	} {
		got, _ := metadataURLs(in)
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s[%d]: %s", in, i, got[i])
			}
		}
	}
}

func TestIDTokenLookalikesNeedAScope(t *testing.T) {
	t.Parallel()
	f := newFixtureWith(t, oauthtest.Config{Alg: "RS256"}, func(ti *config.TrustedIssuer) {
		ti.Kind, ti.Alias = "", "idp"
		off := false
		ti.RequireTypATJWT = &off
	})
	_, err := f.verify(f.mint(oauthtest.Options{Typ: "JWT", NoScope: true}))
	wantInvalid(t, err, "scope")
	for _, claim := range []string{"at_hash", "c_hash", "nonce", "auth_time"} {
		_, err := f.verify(f.mint(oauthtest.Options{Typ: "JWT", Extra: map[string]any{claim: "x"}}))
		wantInvalid(t, err, "ID token")
		if _, err := f.verify(f.mint(oauthtest.Options{Typ: "JWT", Scope: "s", Extra: map[string]any{claim: "x"}})); err != nil {
			t.Errorf("%s with a scope: %v", claim, err)
		}
	}
	// A real at+jwt token needs no scope claim to be accepted by this check.
	if _, err := f.verify(f.mint(oauthtest.Options{NoScope: true})); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedEmail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	mint := func(extra map[string]any) *Claims {
		c, err := f.verify(f.mint(oauthtest.Options{Extra: extra}))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := mint(map[string]any{"email": "a@b.c"}); c.VerifiedEmail != "" {
		t.Errorf("an unverified e-mail must not count: %q", c.VerifiedEmail)
	}
	if c := mint(map[string]any{"email": "a@b.c", "email_verified": false}); c.VerifiedEmail != "" {
		t.Errorf("email_verified false: %q", c.VerifiedEmail)
	}
	if c := mint(map[string]any{"email": "a@b.c", "email_verified": true}); c.VerifiedEmail != "a@b.c" {
		t.Errorf("verified: %q", c.VerifiedEmail)
	}
	f.cfg.TrustedIssuers[0].EmailsVerified = true
	if c := mint(map[string]any{"email": "a@b.c"}); c.VerifiedEmail != "a@b.c" {
		t.Errorf("emails_verified issuer: %q", c.VerifiedEmail)
	}
}

func introspectingFixture(t *testing.T, mut func(*config.TrustedIssuer)) *fixture {
	f := newFixtureWith(t, oauthtest.Config{Path: "/realms/x", Discovery: "oidc"}, func(ti *config.TrustedIssuer) {
		ti.Kind, ti.Alias = "", "kc"
		ti.Introspection = &config.Introspection{ClientID: "rackbook", ClientSecretEnv: "RB_SECRET"}
		if mut != nil {
			mut(ti)
		}
	})
	f.v.Getenv = func(string) string { return "s3cret" }
	f.iss.Introspect = func(tok, id, secret string) map[string]any {
		return map[string]any{"active": false}
	}
	return f
}

func TestOpaqueTokensGoToOneIssuerOnly(t *testing.T) {
	t.Parallel()
	f := introspectingFixture(t, func(ti *config.TrustedIssuer) { ti.Introspection.TokenPrefix = "kc_" })
	other := oauthtest.New(t)
	f.cfg.TrustedIssuers = append(f.cfg.TrustedIssuers, config.TrustedIssuer{
		Issuer: other.URL, Alias: "two", Introspection: &config.Introspection{ClientID: "x", ClientSecretEnv: "RB_SECRET", TokenPrefix: "two_"},
	})
	otherCalls := 0
	other.Introspect = func(string, string, string) map[string]any { otherCalls++; return map[string]any{"active": false} }
	// No prefix match: nobody is asked.
	_, err := f.verify("plain-opaque")
	wantInvalid(t, err, "token_prefix")
	if f.iss.IntrospectCalls.Load() != 0 || otherCalls != 0 {
		t.Fatal("an opaque token must not be sent to an issuer that does not match its prefix")
	}
	f.verify("kc_token")
	if f.iss.IntrospectCalls.Load() != 1 || otherCalls != 0 {
		t.Fatalf("kc_ token: %d calls here, %d at the other issuer", f.iss.IntrospectCalls.Load(), otherCalls)
	}
	// Two introspecting issuers without prefixes: refused rather than guessed.
	f.cfg.TrustedIssuers[0].Introspection.TokenPrefix = ""
	f.cfg.TrustedIssuers[1].Introspection.TokenPrefix = ""
	n := f.iss.IntrospectCalls.Load()
	_, err = f.verify("another-opaque")
	wantInvalid(t, err, "token_prefix")
	if f.iss.IntrospectCalls.Load() != n || otherCalls != 0 {
		t.Fatal("ambiguous: nothing may be sent")
	}
}

func TestRefusedOpaqueTokensAreCachedBriefly(t *testing.T) {
	t.Parallel()
	f := introspectingFixture(t, nil)
	f.verify("bad")
	n := f.iss.IntrospectCalls.Load()
	if _, err := f.verify("bad"); err == nil || f.iss.IntrospectCalls.Load() != n {
		t.Fatalf("a refused token must be remembered: %v", err)
	}
	f.now = f.now.Add(NegativeTTL + time.Second)
	f.verify("bad")
	if f.iss.IntrospectCalls.Load() != n+1 {
		t.Fatal("the negative answer must expire after 10 s")
	}
}

type gate struct {
	next    http.RoundTripper
	block   chan struct{}
	blocked atomic.Bool
}

func (g *gate) RoundTrip(r *http.Request) (*http.Response, error) {
	if g.blocked.Load() && strings.HasSuffix(r.URL.Path, "/jwks.json") {
		select {
		case <-g.block:
		case <-r.Context().Done():
		}
	}
	return g.next.RoundTrip(r)
}

func TestKnownKeysKeepVerifyingWhileARefetchRuns(t *testing.T) {
	f := newFixture(t)
	g := &gate{next: http.DefaultTransport, block: make(chan struct{})}
	f.v.HTTP = &http.Client{Transport: g, Timeout: 10 * time.Second}
	if _, err := f.verify(f.mint(oauthtest.Options{})); err != nil {
		t.Fatal(err)
	}
	f.iss.AddKey("k2")
	f.now = f.now.Add(KeyTTL + time.Second) // the cache is stale, so the refetch is due
	g.blocked.Store(true)
	done := make(chan error, 1)
	go func() { _, err := f.verify(f.mint(oauthtest.Options{KID: "k2"})); done <- err }() // starts the refetch, hangs in it
	time.Sleep(200 * time.Millisecond)
	ok := make(chan error, 1)
	go func() { _, err := f.verify(f.mint(oauthtest.Options{})); ok <- err }()
	select {
	case err := <-ok:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a token with a known kid must not wait for the refetch")
	}
	g.blocked.Store(false)
	close(g.block)
	if err := <-done; err != nil {
		t.Fatalf("the new key after the refetch: %v", err)
	}
}

type failIntro struct {
	next http.RoundTripper
	mode string // "5xx", "net" or ""
	hits atomic.Int32
}

func (g *failIntro) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/introspect") {
		g.hits.Add(1)
		switch g.mode {
		case "5xx":
			return &http.Response{StatusCode: 503, Status: "503 Service Unavailable", Body: http.NoBody, Header: http.Header{}, Request: r}, nil
		case "net":
			return nil, errors.New("connection refused")
		}
	}
	return g.next.RoundTrip(r)
}

func TestIntrospectionOutagesAreNotVerdicts(t *testing.T) {
	t.Parallel()
	f := introspectingFixture(t, nil)
	g := &failIntro{next: http.DefaultTransport}
	f.v.HTTP = &http.Client{Transport: g, Timeout: 5 * time.Second}
	for _, mode := range []string{"5xx", "net"} {
		g.mode = mode
		_, err := f.verify("tok-" + mode)
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: want ErrUnavailable, got %v", mode, err)
		}
		// Not cached as a refusal: the next attempt asks again.
		n := g.hits.Load()
		f.verify("tok-" + mode)
		if g.hits.Load() != n+1 {
			t.Fatalf("%s: an outage must not be cached", mode)
		}
	}
	// Once the issuer answers, active:false is the verdict.
	g.mode = ""
	_, err := f.verify("tok-5xx")
	wantInvalid(t, err, "not active")
}
