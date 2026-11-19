package rbclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kazuhahub/rackbook/modsettings"
)

// The modules panel calls (docs/modules.md, section 7). A module reads its own
// settings with its own token, decides from them whether to run, and reports
// each run.

// ErrNoPanel means the server gives this module no settings: it is older than
// v0.5.0 (a token may not reach the endpoint: 403, or there is none: 404), or
// the module is not listed in rackbook.yml. The module then keeps working from
// its local config, as before.
var ErrNoPanel = errors.New("the server has no settings for this module")

// RemoteSettings reads GET /api/modules/{name}/settings.
func (c *Client) RemoteSettings(ctx context.Context, name string) (*modsettings.Remote, error) {
	var out modsettings.Remote
	err := c.do(ctx, http.MethodGet, "/api/modules/"+url.PathEscape(name)+"/settings", nil, &out)
	var e *Error
	if errors.As(err, &e) && (e.Status == http.StatusNotFound || e.Status == http.StatusForbidden) {
		return nil, fmt.Errorf("%w (%v)", ErrNoPanel, err)
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ReportRun sends one run to POST /api/modules/{name}/runs.
func (c *Client) ReportRun(ctx context.Context, name string, run modsettings.Run) error {
	return c.do(ctx, http.MethodPost, "/api/modules/"+url.PathEscape(name)+"/runs", run, nil)
}

// ModuleStatus reads GET /api/modules/status: the last run of every module.
// Only the token of a notify module may.
func (c *Client) ModuleStatus(ctx context.Context) ([]modsettings.ModuleStatus, error) {
	var out struct {
		Modules []modsettings.ModuleStatus `json:"modules"`
	}
	err := c.do(ctx, http.MethodGet, "/api/modules/status", nil, &out)
	return out.Modules, err
}

// Check is what a module learns at the start of a run.
type Check struct {
	// Remote is the server's answer; nil when Err is set.
	Remote *modsettings.Remote
	// Settings are Remote's settings, checked and typed; nil when Err is set.
	Settings modsettings.Settings
	// Err says why the panel could not be used (ErrNoPanel, a network error, a
	// type mismatch). The module then runs from its local config and logs it
	// as a warning.
	Err error
	// Decision says whether to run. Without the panel it always runs.
	Decision modsettings.Decision
}

// Panel reports whether the settings came from the server.
func (k Check) Panel() bool { return k.Err == nil && k.Remote != nil }

// CheckRun reads the module's settings and applies the scheduling rule
// (modsettings.Decide). typ is the settings type the calling program expects;
// defaultTimes are its daily slots when the settings give none.
func (c *Client) CheckRun(ctx context.Context, name, typ string, now time.Time, defaultTimes []string) Check {
	rem, err := c.RemoteSettings(ctx, name)
	if err != nil {
		return Check{Err: err, Decision: modsettings.Decision{Run: true, Reason: "local"}}
	}
	if rem.Type != typ {
		return Check{Err: fmt.Errorf("the server says module %q is of type %q, not %q", name, rem.Type, typ), Decision: modsettings.Decision{Run: true, Reason: "local"}}
	}
	set, err := modsettings.Decode(typ, rem.Settings)
	if err != nil {
		return Check{Err: fmt.Errorf("settings from the server: %w", err), Decision: modsettings.Decision{Run: true, Reason: "local"}}
	}
	times, tz := set.Schedule()
	if len(times) == 0 {
		times = defaultTimes
	}
	d := modsettings.Decide(modsettings.Input{Now: now, Times: times, Timezone: tz, LastOK: rem.LastOK, Paused: set.IsPaused(), RunRequest: rem.RunRequest})
	return Check{Remote: rem, Settings: set, Decision: d}
}
