// Package apierr maps the errors of a write to the HTTP status and error code
// documented in docs/api.md. The JSON API and the MCP write tools use it, so a
// write fails the same way over both.
package apierr

import (
	"errors"

	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/yamledit"
)

// Info is one classified error. Status 500 means "internal": the caller should
// log Err and show a generic message instead of Message.
type Info struct {
	Status  int
	Code    string
	Message string
	// Extra holds additional response fields (errors, current, lastGood, remote).
	Extra map[string]any
}

// Classify maps a write error. It never returns nil.
func Classify(err error) Info {
	var ce *edit.ConflictError
	var ie *edit.InvalidError
	var he *gitstore.HistoryRewrittenError
	var re *edit.ReferencedError
	var fe *edit.ForbiddenError
	var se *secretscan.Error
	switch {
	case errors.As(err, &se) && se.Suspected():
		return Info{422, "secret_suspected", "this looks like a secret; nothing was written. Confirm it is not one and retry with confirm_not_secret", map[string]any{"findings": se.Findings}}
	case errors.As(err, &se):
		return Info{422, "secret_detected", "a possible secret was found; nothing was written", map[string]any{"findings": se.Findings}}
	case errors.As(err, &fe):
		return Info{403, "forbidden", fe.Error(), nil}
	case errors.As(err, &re):
		return Info{409, "referenced", re.Error(), map[string]any{"references": re.Refs}}
	case errors.As(err, &ce):
		var cur any
		if ce.Current != nil {
			cur = ce.Current
		}
		return Info{409, "conflict", ce.Message, map[string]any{"current": cur}}
	case errors.As(err, &ie):
		return Info{422, "invalid", ie.Error(), map[string]any{"errors": ie.Issues}}
	case errors.Is(err, edit.ErrUnknownCollection):
		return Info{404, "not_found", err.Error(), nil}
	case errors.Is(err, edit.ErrBadRequest):
		return Info{400, "bad_request", err.Error(), nil}
	case errors.As(err, &he):
		return Info{503, "history_rewritten", err.Error(), map[string]any{"lastGood": he.LastGood, "remote": he.Remote}}
	case errors.Is(err, gitstore.ErrConfig):
		return Info{503, "config_error", err.Error(), nil}
	case errors.Is(err, gitstore.ErrRepoDirty):
		return Info{503, "repo_dirty", err.Error(), nil}
	case errors.Is(err, gitstore.ErrRepoDiverged):
		return Info{503, "repo_diverged", err.Error(), nil}
	case errors.Is(err, gitstore.ErrPRUnavailable):
		return Info{503, "pull_request_unavailable", err.Error(), nil}
	case errors.Is(err, yamledit.ErrUnsupported):
		return Info{422, "unsupported", err.Error(), nil}
	}
	return Info{500, "internal", "internal error", nil}
}
