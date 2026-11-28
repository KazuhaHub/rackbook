package accounts

import (
	"testing"

	"github.com/kazuhahub/rackbook/internal/roles"
)

// A role entry and an account name follow one rule: roles keeps its own copy of the pattern (it
// imports nothing of this package), and this holds the two together.
func TestUsernameRuleIsTheRoleEntryRule(t *testing.T) {
	t.Parallel()
	for _, n := range []string{"alice", "a", "a.b-c_d", "1a", "A", "a b", "", "é", "aK", "a/b", "abcdefghijklmnopqrstuvwxyz0123456", "abcdefghijklmnopqrstuvwxyz012345", "-a", "a*"} {
		if ValidUsername(n) != roles.ValidLocalUsername(n) {
			t.Errorf("%q: accounts says %v, roles says %v", n, ValidUsername(n), roles.ValidLocalUsername(n))
		}
	}
}
