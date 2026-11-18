package secretscan

import "testing"

func TestUUIDKind(t *testing.T) {
	ann := Annotations{"/ids/*": KindUUID}
	for _, tc := range []struct {
		v      string
		exempt bool
	}{
		{"entra_app_id=82203fb2-64b1-4672-95c5-9da67c0cc7ea", true},
		{"entra_tenant_id=e72914d3-3d19-486e-be11-15c69540e02a", true},
		{"82203fb2-64b1-4672-95c5-9da67c0cc7ea", true},
		{"client_secret=82203fb2-64b1-4672-95c5-9da67c0cc7ea", false},
		{"api_key=82203fb2-64b1-4672-95c5-9da67c0cc7ea", false},
	} {
		got := Default().ScanRecordWith("c", "x", map[string]any{"ids": []any{tc.v}}, ann)
		if (len(got) == 0) != tc.exempt {
			t.Errorf("%s: findings %v, want exempt=%v", tc.v, got, tc.exempt)
		}
	}
}
