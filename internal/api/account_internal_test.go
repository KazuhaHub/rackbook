package api

import (
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
)

func TestPersonal(t *testing.T) {
	for _, c := range []struct {
		name string
		id   *auth.Identity
		want bool
	}{
		{"nil", nil, false},
		{"anonymous", &auth.Identity{Method: auth.MethodNone}, false},
		{"editor flag", &auth.Identity{ID: "a@x", Method: auth.MethodNone}, true},
		{"oidc", &auth.Identity{ID: "a@x", Method: auth.MethodOIDC}, true},
		{"passkey", &auth.Identity{ID: "a@x", Method: auth.MethodPasskey}, true},
		{"cloudflare", &auth.Identity{ID: "a@x", Method: auth.MethodCloudflareAccess}, true},
		{"token", &auth.Identity{ID: "ci", Method: auth.MethodToken}, false},
		{"oauth", &auth.Identity{ID: "a@x", Method: auth.MethodOAuth}, false},
		{"mcphub", &auth.Identity{ID: "a", Method: auth.MethodMCPHub}, false},
	} {
		if got := personal(c.id); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}
