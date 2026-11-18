package mcpauth

import "testing"

func TestTokensReachOnlyRecordPaths(t *testing.T) {
	for p, want := range map[string]bool{
		"/mcp": true, "/api/c/devices": true, "/api/c/devices/x": true, "/api/meta": true, "/export.md": true, "/llms.txt": true,
		"/api/account": false, "/api/account/passkeys/abc": false, "/api/admin/users": false, "/api/admin/tokens": false,
		"/api/admin/passkeys/x": false, "/api/types": false, "/auth/login": false,
	} {
		if tokenPath(p) != want {
			t.Errorf("tokenPath(%q) = %v, want %v", p, !want, want)
		}
	}
}
