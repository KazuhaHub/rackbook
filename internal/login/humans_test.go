package login

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
)

func TestHumansOnlyRefusesTokensAndOAuth(t *testing.T) {
	t.Parallel()
	h := humansOnly(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	for method, want := range map[string]int{
		auth.MethodToken: 403, auth.MethodOAuth: 403, auth.MethodMCPHub: 403,
		auth.MethodOIDC: 200, auth.MethodPasskey: 200, auth.MethodCloudflareAccess: 200, auth.MethodNone: 200,
	} {
		r := httptest.NewRequest("DELETE", "/api/account/passkeys/x", nil)
		r = r.WithContext(auth.WithIdentity(r.Context(), &auth.Identity{ID: "a@b.c", Method: method}))
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != want {
			t.Errorf("%s: %d, want %d", method, w.Code, want)
		}
	}
}
