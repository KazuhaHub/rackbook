package ansiblerepo

// Issue severities.
const (
	SevError   = "error"   // refuses the edit
	SevConfirm = "confirm" // refuses the edit unless the editor confirms it (a value that may be a secret)
	SevWarning = "warning" // shown, never refuses (a problem the repository already had)
)

// Issue is one problem found by the checks before a commit. Code and Params
// are what the console translates; Message is a plain English fallback.
type Issue struct {
	Code     string            `json:"code"`
	Severity string            `json:"severity"`
	File     string            `json:"file,omitempty"`
	Path     string            `json:"path,omitempty"` // the place inside the file (a key path)
	Params   map[string]string `json:"params,omitempty"`
	Message  string            `json:"message"`
}

func (i Issue) key() string {
	k := i.Code + "|" + i.File + "|" + i.Path
	for _, n := range []string{"host", "group", "feature", "setting", "rule", "name"} {
		k += "|" + i.Params[n]
	}
	return k
}
