package oauthserver_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

// browser plays the person: it opens the authorization URL as the signed-in
// user, approves on the consent page and returns what the redirect carries.
func (e *env) browser(user string, browserVisits *atomic.Int32) auth.AuthorizationCodeFetcher {
	return func(_ context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		browserVisits.Add(1)
		u, err := url.Parse(args.URL)
		if err != nil {
			return nil, err
		}
		r := e.get(user, u.RequestURI())
		loc := r.Header.Get("Location")
		if r.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/oauth/consent?req=") {
			return nil, fmt.Errorf("authorize: %d %s", r.StatusCode, r.body)
		}
		d := e.postJSON(user, "/api/oauth/consent", map[string]any{"req": strings.TrimPrefix(loc, "/oauth/consent?req="), "approve": true})
		cb, err := url.Parse(d.str("redirect"))
		if err != nil {
			return nil, err
		}
		q := cb.Query()
		return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
	}
}

// TestSDKClientAuthorizesAndSurvivesRestart connects with the Go SDK's own
// OAuth client (discovery, registration, PKCE, resource, iss check), then stops
// the server, starts a new one over the same state directory, and shows the
// client carries on by refreshing, with no second visit to the browser.
func TestSDKClientAuthorizesAndSurvivesRestart(t *testing.T) {
	e := newEnv(t, opts{})
	var visits atomic.Int32
	handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{testRedirect}, ClientName: "SDK Client", GrantTypes: []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none",
		}},
		RedirectURL:              testRedirect,
		AuthorizationCodeFetcher: e.browser(boss, &visits),
	})
	if err != nil {
		t.Fatal(err)
	}
	connect := func(h auth.OAuthHandler, endpoint string) *mcp.ClientSession {
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "sdk", Version: "1"}, nil).Connect(context.Background(),
			&mcp.StreamableClientTransport{Endpoint: endpoint, OAuthHandler: h}, nil)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(func() { cs.Close() })
		return cs
	}
	cs := connect(handler, e.resource)
	if _, err := cs.ListTools(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if visits.Load() != 1 {
		t.Fatalf("browser visits: %d", visits.Load())
	}
	ts, err := handler.TokenSource(context.Background())
	if err != nil || ts == nil {
		t.Fatalf("token source: %v", err)
	}
	tok, err := ts.Token()
	if err != nil || tok.RefreshToken == "" {
		t.Fatalf("the client got no refresh token: %v %+v", err, tok)
	}
	var clientID string
	grants := e.get(boss, "/api/account/grants").json()["grants"].([]any)
	if len(grants) != 1 {
		t.Fatalf("grants: %v", grants)
	}
	clientID = grants[0].(map[string]any)["clientId"].(string)
	if grants[0].(map[string]any)["clientName"] != "SDK Client" {
		t.Fatalf("grant: %v", grants[0])
	}

	// Stop, start again over the same directory.
	cs.Close()
	e.restart()

	// The client holds only its refresh token. It asks the token endpoint for a
	// new access token and goes on, with no browser step.
	cfg := &oauth2.Config{ClientID: clientID, Endpoint: oauth2.Endpoint{TokenURL: e.base + "/oauth/token", AuthStyle: oauth2.AuthStyleInParams}}
	src := cfg.TokenSource(context.Background(), &oauth2.Token{RefreshToken: tok.RefreshToken})
	h2, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{testRedirect}, ClientName: "SDK Client", GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none",
		}},
		RedirectURL:              testRedirect,
		AuthorizationCodeFetcher: e.browser(boss, &visits),
		InitialTokenSource:       src,
	})
	if err != nil {
		t.Fatal(err)
	}
	cs2 := connect(h2, e.resource)
	if tools, err := cs2.ListTools(context.Background(), nil); err != nil || len(tools.Tools) == 0 {
		t.Fatalf("after the restart: %v", err)
	}
	if visits.Load() != 1 {
		t.Fatalf("the client went back to the browser after a restart (%d visits)", visits.Load())
	}
}
