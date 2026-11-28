package accounts

// The audit events the writers emit as changes. Only these names, carrying the document's change marker,
// are recognised as change events when the log is read at start, by accept-restore and by the retention pin:
// an event that merely has a "change:" detail is not one.

// accountChangeEvents are the change events of the account store (design-local-accounts.md, 10).
var accountChangeEvents = names(
	"account_invited", "account_invite_revoked", "account_link_opened", "account_setup_completed",
	"account_reset_issued", "account_unlocked", "password_changed", "factor_added", "factor_removed",
	"sessions_ended", "account_disabled", "account_enabled", "account_removed", "account_revocations_applied",
	"account_store_checkpoint", "account_store_problem", "account_store_restored", "account_store_rekeyed",
)

// secretsChangeEvents are the change events of secrets.enc.
var secretsChangeEvents = names(
	"settings_secret_set", "settings_secret_cleared",
	"account_store_checkpoint", "account_store_problem", "account_store_restored", "account_store_rekeyed",
)

const (
	accountsMarker = "change:"
	secretsMarker  = "secrets_change:"
)

func names(in ...string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, n := range in {
		m[n] = true
	}
	return m
}
