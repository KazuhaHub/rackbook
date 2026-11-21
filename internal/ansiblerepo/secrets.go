package ansiblerepo

// The secrets editor: reading which keys a host's SOPS file holds (without
// decrypting anything), revealing one value, and setting or deleting one. The
// file is edited with the sops binary (internal/sops) using Rackbook's own age
// key, which must be a recipient of the file; the result goes through the
// normal write path, so an edit is one commit with the usual conflict rules,
// and the checks below insist the file is still fully encrypted for exactly
// the recipients of its creation rule in .sops.yaml.
//
// No value is ever returned by a listing, put in a diff, logged or audited.

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/sops"
)

// Sopser is what the secrets editor needs of the sops runner.
type Sopser interface {
	PublicKey() string
	Decrypt(ctx context.Context, enc []byte, key string) ([]byte, error)
	Set(ctx context.Context, enc []byte, key, value string) ([]byte, error)
	Unset(ctx context.Context, enc []byte, key string) ([]byte, error)
	Encrypt(ctx context.Context, repoDir, rel, key, value string) ([]byte, error)
}

// MaxSecretValue is the largest value the editor stores.
const MaxSecretValue = 16 << 10

var sopsKeyNameRe = regexp.MustCompile(`^[a-z0-9_-]{1,128}$`)

// Errors of the secrets editor.
var (
	// ErrSecretsOff: no age key file is configured.
	ErrSecretsOff = errors.New("editing secrets is not set up here")
	// ErrNoSecret: the file has no such key.
	ErrNoSecret = errors.New("no such key")
)

// ValidSecretKey reports whether a key name may be read, written or deleted
// by the editor: lower-case letters, digits, "_" and "-", and neither the
// reserved "sops" nor a name sops would leave unencrypted.
func ValidSecretKey(k string) bool {
	return sopsKeyNameRe.MatchString(k) && k != "sops" && !strings.HasSuffix(k, "_unencrypted")
}

var pemOneLineRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[^\n]*-----END [A-Z0-9 ]+-----`)

// ValidSecretValue returns "" or the reason a value is refused: empty, too
// large, not UTF-8, or holding a NUL.
func ValidSecretValue(v string) string {
	switch {
	case v == "":
		return "empty"
	case len(v) > MaxSecretValue:
		return "too_large"
	case !utf8.ValidString(v) || strings.ContainsRune(v, 0):
		return "not_text"
	case pemOneLineRe.MatchString(v):
		return "pem_one_line" // a PEM block whose line breaks were lost
	}
	return ""
}

// SecretKeyOf is the SOPS key of a feature's secret setting.
func SecretKeyOf(feature, setting string) string { return "feature_" + feature + "_" + setting }

func isSecretsPath(p string) bool {
	dir, name := path.Split(p)
	if strings.TrimSuffix(dir, "/") != "secrets" || !strings.HasSuffix(name, ".sops.yaml") {
		return false
	}
	host := strings.TrimSuffix(name, ".sops.yaml")
	// secrets/admin.sops.yaml holds the administrators' own secrets and is never reachable here
	return hostNameRe.MatchString(host) && host != reservedSecretsHost
}

const reservedSecretsHost = "admin"

// hasExactRule reports whether the first creation rule of .sops.yaml that
// matches file is the one whose path_regex is exactly ^<file>$ (escaped): a
// host's file is reachable only when it has a rule of its own, never through
// a broader one.
func hasExactRule(t Tree, file string) bool {
	b, ok := t.Read(".sops.yaml")
	if !ok {
		return false
	}
	_, root, err := parseDoc(b)
	if err != nil || root == nil {
		return false
	}
	rules := mapGet(root, "creation_rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	want := "^" + regexp.QuoteMeta(file) + "$"
	for _, rule := range rules.Content {
		re := mapGet(rule, "path_regex")
		if re == nil || re.Value == "" {
			return false // a catch-all rule matches first
		}
		if re.Value == want {
			return true
		}
		if rx, err := regexp.Compile(re.Value); err == nil && rx.MatchString(file) {
			return false // another rule matches first
		}
	}
	return false
}

// SecretsEnabled reports whether this server has an age key to edit with.
func (r *Repo) SecretsEnabled() bool { return r.o.Sops != nil }

// SecretsPublicKey is the age recipient of this server's key ("" = none).
func (r *Repo) SecretsPublicKey() string {
	if r.o.Sops == nil {
		return ""
	}
	return r.o.Sops.PublicKey()
}

func (r *Repo) secretsRel(host string) string {
	tmpl := r.o.Rules.SecretsFile
	if tmpl == "" {
		tmpl = DefaultRules().SecretsFile
	}
	return strings.ReplaceAll(tmpl, "{host}", host)
}

// secretsPathLocked is the SOPS file of a host of the inventory; the caller holds the read lock.
func (r *Repo) secretsPathLocked(host string) (string, error) {
	hosts, err := r.hostsLocked()
	if err != nil {
		return "", err
	}
	found := false
	for _, h := range hosts {
		if h.Name != host {
			continue
		}
		found = true
		if g := r.o.Rules.ManagedGroup; g != "" {
			managed := false
			for _, hg := range h.Groups {
				managed = managed || hg == g
			}
			if !managed {
				return "", &EditError{Err: errors.New(host + " is not a managed host")}
			}
		}
	}
	if !found {
		return "", ErrNoHost
	}
	p := r.secretsRel(host)
	if !isSecretsPath(p) || p != "secrets/"+host+".sops.yaml" {
		return "", &EditError{Err: fmt.Errorf("%s is not a file the secrets editor may change", p)}
	}
	if !hasExactRule(dirTree{r}, p) {
		return "", &EditError{Err: errors.New(".sops.yaml has no rule of its own for " + p)}
	}
	return p, nil
}

// SecretsPath is the SOPS file of a host.
func (r *Repo) SecretsPath(host string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.secretsPathLocked(host)
}

// SecretKey is one key of a SOPS file. Only the name is ever known here.
type SecretKey struct {
	Name string `json:"name"`
	// Editable: the editor can reveal, replace and delete it (a top-level
	// scalar with a name the editor accepts).
	Editable bool `json:"editable"`
}

// SecretsFile is a host's SOPS file as the secrets page shows it, read
// without decrypting.
type SecretsFile struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	// Base is the object ID to send back with an edit ("" = the file does not exist).
	Base string      `json:"base"`
	Keys []SecretKey `json:"keys"`
	// Recipients are the age recipients the file is encrypted for.
	Recipients []string `json:"recipients"`
	// Rule are the recipients of its creation rule in .sops.yaml (nil = no rule).
	Rule []string `json:"rule"`
	// CanDecrypt: this server's key is one of Recipients.
	CanDecrypt   bool   `json:"canDecrypt"`
	LastModified string `json:"lastModified,omitempty"`
	// Problem: "" or "unreadable" (not a SOPS-encrypted YAML mapping).
	Problem string `json:"problem,omitempty"`
}

// SecretsFile reads the key names and the recipients of a host's SOPS file.
func (r *Repo) SecretsFile(ctx context.Context, host string) (*SecretsFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, err := r.secretsPathLocked(host)
	if err != nil {
		return nil, err
	}
	return r.secretsFileLocked(ctx, host, p)
}

func (r *Repo) secretsFileLocked(ctx context.Context, host, p string) (*SecretsFile, error) {
	t := dirTree{r}
	sf := &SecretsFile{Host: host, Path: p, Keys: []SecretKey{}, Recipients: []string{}}
	if rule, ok := creationRecipients(t, p); ok {
		sf.Rule = rule
	}
	b, ok := t.Read(p)
	if !ok {
		return sf, nil
	}
	id, err := r.mirror.BlobID(ctx, "HEAD", p)
	if err != nil {
		return nil, err
	}
	sf.Exists, sf.Base = true, id
	info, err := parseSecretsFile(b)
	if err != nil {
		sf.Problem = "unreadable"
		return sf, nil
	}
	sf.Keys, sf.Recipients, sf.LastModified = info.keys, info.recipients, info.lastModified
	if r.o.Sops != nil {
		pub := r.o.Sops.PublicKey()
		for _, rc := range sf.Recipients {
			sf.CanDecrypt = sf.CanDecrypt || rc == pub
		}
	}
	return sf, nil
}

type secretsInfo struct {
	keys         []SecretKey
	recipients   []string
	lastModified string
	root         *yaml.Node
}

// parseSecretsFile reads a SOPS YAML file's structure only.
func parseSecretsFile(b []byte) (*secretsInfo, error) {
	_, root, err := parseDoc(b)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, errors.New("empty")
	}
	info := &secretsInfo{keys: []SecretKey{}, recipients: []string{}, root: root}
	meta := mapGet(root, "sops")
	if meta == nil || meta.Kind != yaml.MappingNode {
		return nil, errors.New("no sops metadata")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		name, v := root.Content[i].Value, root.Content[i+1]
		if name == "sops" {
			continue
		}
		info.keys = append(info.keys, SecretKey{Name: name, Editable: ValidSecretKey(name) && v.Kind == yaml.ScalarNode})
	}
	sort.Slice(info.keys, func(i, j int) bool { return info.keys[i].Name < info.keys[j].Name })
	if age := mapGet(meta, "age"); age != nil && age.Kind == yaml.SequenceNode {
		for _, e := range age.Content {
			if rc := mapGet(e, "recipient"); rc != nil && rc.Kind == yaml.ScalarNode {
				info.recipients = append(info.recipients, rc.Value)
			}
		}
	}
	if lm := mapGet(meta, "lastmodified"); lm != nil && lm.Kind == yaml.ScalarNode {
		info.lastModified = lm.Value
	}
	return info, nil
}

func (i *secretsInfo) key(name string) (SecretKey, bool) {
	for _, k := range i.keys {
		if k.Name == name {
			return k, true
		}
	}
	return SecretKey{}, false
}

// RevealSecret decrypts one value. The caller is responsible for who may ask,
// for the audit and for never storing or logging the result.
func (r *Repo) RevealSecret(ctx context.Context, host, key string) (string, error) {
	if r.o.Sops == nil {
		return "", ErrSecretsOff
	}
	if !ValidSecretKey(key) {
		return "", ErrNoSecret
	}
	r.mu.RLock()
	p, err := r.secretsPathLocked(host)
	var b []byte
	var ok bool
	if err == nil {
		b, ok = dirTree{r}.Read(p)
	}
	r.mu.RUnlock()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrNoSecret
	}
	info, err := parseSecretsFile(b)
	if err != nil {
		return "", &EditError{Err: errors.New(p + " is not a SOPS-encrypted file")}
	}
	if k, found := info.key(key); !found || !k.Editable {
		return "", ErrNoSecret
	}
	out, err := r.o.Sops.Decrypt(ctx, b, key)
	if err != nil {
		return "", secretsError(p, err)
	}
	return string(out), nil
}

// secretsError turns a runner failure into an error the editors show.
func secretsError(p string, err error) error {
	switch {
	case errors.Is(err, sops.ErrNoKey):
		return ErrNoSecret
	case errors.Is(err, sops.ErrCannotDecrypt):
		return &EditError{Err: errors.New("this server's age key is not a recipient of " + p + "; add it to .sops.yaml and run `sops updatekeys`")}
	}
	return &EditError{Err: errors.New("sops failed on " + p)}
}

// SecretOp sets or deletes one key. Value is never logged or audited.
type SecretOp struct {
	Key    string
	Value  string
	Delete bool
}

// SecretsFileEdit is the FileEdit that applies ops to a host's SOPS file as
// the editor saw it (base). Every key and value is checked here.
func (r *Repo) SecretsFileEdit(host, base string, ops []SecretOp) (FileEdit, error) {
	if r.o.Sops == nil {
		return FileEdit{}, ErrSecretsOff
	}
	if len(ops) == 0 {
		return FileEdit{}, ErrNoChange
	}
	for _, op := range ops {
		if !ValidSecretKey(op.Key) {
			return FileEdit{}, &EditError{Err: fmt.Errorf("%q is not a key name the editor accepts (lower-case letters, digits, _ and -)", op.Key)}
		}
		if !op.Delete {
			if why := ValidSecretValue(op.Value); why != "" {
				return FileEdit{}, &EditError{Err: errors.New("the value of " + op.Key + " is refused: " + why)}
			}
		}
	}
	p, err := r.SecretsPath(host)
	if err != nil {
		return FileEdit{}, err
	}
	sp := r.o.Sops
	return FileEdit{Path: p, Base: base, Make: func(cur []byte) ([]byte, error) {
		ctx := context.Background()
		for _, op := range ops {
			var err error
			switch {
			case cur == nil && op.Delete:
				return nil, ErrNoSecret
			case cur == nil:
				if _, ok := creationRecipients(dirTree{r}, p); !ok {
					return nil, errors.New("no creation rule of .sops.yaml matches " + p)
				}
				cur, err = sp.Encrypt(ctx, r.o.Dir, p, op.Key, op.Value)
			default:
				info, perr := parseSecretsFile(cur)
				if perr != nil {
					return nil, errors.New(p + " is not a SOPS-encrypted file")
				}
				k, found := info.key(op.Key)
				switch {
				case op.Delete && !found:
					return nil, ErrNoSecret
				case found && !k.Editable:
					return nil, errors.New(op.Key + " is not a plain value the editor can change")
				case op.Delete:
					cur, err = sp.Unset(ctx, cur, op.Key)
				default:
					cur, err = sp.Set(ctx, cur, op.Key, op.Value)
				}
			}
			if err != nil {
				return nil, secretsError(p, err)
			}
		}
		return cur, nil
	}}, nil
}

// SecretsAction is the action of the commit subject for ops: names only, never values.
func SecretsAction(ops []SecretOp) string {
	var parts []string
	for _, op := range ops {
		verb := "set "
		if op.Delete {
			verb = "delete "
		}
		parts = append(parts, verb+op.Key)
	}
	s := strings.Join(parts, ", ")
	if len(s) > 100 {
		return fmt.Sprintf("%d secrets changed", len(ops))
	}
	return s
}

// ---- checks ----

// creationRecipients returns the age recipients of the first creation rule of
// .sops.yaml that matches file; ok is false when there is none.
func creationRecipients(t Tree, file string) ([]string, bool) {
	b, ok := t.Read(".sops.yaml")
	if !ok {
		return nil, false
	}
	_, root, err := parseDoc(b)
	if err != nil || root == nil {
		return nil, false
	}
	rules := mapGet(root, "creation_rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return nil, false
	}
	for _, rule := range rules.Content {
		if rule.Kind != yaml.MappingNode {
			continue
		}
		if re := mapGet(rule, "path_regex"); re != nil && re.Value != "" {
			rx, err := regexp.Compile(re.Value)
			if err != nil || !rx.MatchString(file) {
				continue
			}
		}
		var out []string
		if age := mapGet(rule, "age"); age != nil && age.Kind == yaml.ScalarNode {
			for _, a := range strings.Split(age.Value, ",") {
				if a = strings.TrimSpace(a); a != "" {
					out = append(out, a)
				}
			}
		}
		if kg := mapGet(rule, "key_groups"); kg != nil && kg.Kind == yaml.SequenceNode {
			for _, g := range kg.Content {
				if age := mapGet(g, "age"); age != nil && age.Kind == yaml.SequenceNode {
					for _, a := range age.Content {
						out = append(out, a.Value)
					}
				}
			}
		}
		sort.Strings(out)
		return out, true
	}
	return nil, false
}

var encValueRe = regexp.MustCompile(`^ENC\[AES256_GCM,data:[^,\]]*,iv:[^,\]]*,tag:[^,\]]*,type:[a-z]+\]$`)

// otherKeyTypes are sops metadata lists that must be empty: the rules only use age.
var otherKeyTypes = []string{"kms", "gcp_kms", "azure_kv", "hc_vault", "pgp", "hckms"}

// secretsFileIssues checks a SOPS file as it would be after an edit: valid
// SOPS metadata, every value encrypted, and exactly the recipients of the
// file's creation rule. (The plaintext secret scan does not apply to these
// files: it would flag the ciphertext of every value.)
func secretsFileIssues(t Tree, file string, content []byte) []Issue {
	_, root, err := parseDoc(content)
	if err != nil || root == nil {
		return []Issue{newIssue("secrets.invalid", SevError, file, "", file+" is not a YAML mapping")}
	}
	meta := mapGet(root, "sops")
	if meta == nil || meta.Kind != yaml.MappingNode || mapGet(meta, "mac") == nil || !strings.HasPrefix(mapGet(meta, "mac").Value, "ENC[") {
		return []Issue{newIssue("secrets.no_metadata", SevError, file, "sops", file+" has no SOPS metadata")}
	}
	var out []Issue
	for i := 0; i+1 < len(root.Content); i += 2 {
		name := root.Content[i].Value
		if name == "sops" {
			continue
		}
		if strings.HasSuffix(name, "_unencrypted") || !allEncrypted(root.Content[i+1]) {
			out = append(out, newIssue("secrets.not_encrypted", SevError, file, name, name+" is not encrypted in "+file, "name", name))
		}
	}
	for _, k := range otherKeyTypes {
		if n := mapGet(meta, k); n != nil && len(n.Content) > 0 {
			out = append(out, newIssue("secrets.recipients", SevError, file, "sops."+k, file+" has recipients that its creation rule does not list"))
			return out
		}
	}
	have := []string{}
	if age := mapGet(meta, "age"); age != nil && age.Kind == yaml.SequenceNode {
		for _, e := range age.Content {
			if rc := mapGet(e, "recipient"); rc != nil {
				have = append(have, rc.Value)
			}
		}
	}
	sort.Strings(have)
	want, ok := creationRecipients(t, file)
	switch {
	case !ok:
		out = append(out, newIssue("secrets.no_rule", SevError, file, "", "no creation rule of .sops.yaml matches "+file))
	case strings.Join(have, ",") != strings.Join(want, ","):
		out = append(out, newIssue("secrets.recipients", SevError, file, "sops.age", file+" is not encrypted for exactly the recipients of its creation rule in .sops.yaml"))
	}
	return out
}

// allEncrypted: every scalar below n is a SOPS ciphertext.
func allEncrypted(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Tag == "!!str" && encValueRe.MatchString(n.Value)
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			if !allEncrypted(n.Content[i]) {
				return false
			}
		}
		return true
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if !allEncrypted(c) {
				return false
			}
		}
		return true
	}
	return false
}

// secretsDiff shows what changed in a SOPS file by key name only: every edit
// re-encrypts every value, so a line diff would be all noise.
func secretsDiff(file string, before, after []byte) FileDiff {
	d := FileDiff{Path: file, Status: "modified"}
	switch {
	case before == nil && after != nil:
		d.Status = "added"
	case before != nil && after == nil:
		d.Status = "removed"
	}
	names := func(b []byte) map[string]bool {
		m := map[string]bool{}
		if info, err := parseSecretsFile(b); err == nil {
			for _, k := range info.keys {
				m[k.Name] = true
			}
		}
		return m
	}
	a, b := names(before), names(after)
	var all []string
	for k := range a {
		all = append(all, k)
	}
	for k := range b {
		if !a[k] {
			all = append(all, k)
		}
	}
	sort.Strings(all)
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n@@ key names only; values are never shown @@\n", file, file)
	for _, k := range all {
		switch {
		case a[k] && b[k]:
			fmt.Fprintf(&sb, " %s\n", k)
		case b[k]:
			fmt.Fprintf(&sb, "+%s\n", k)
		default:
			fmt.Fprintf(&sb, "-%s\n", k)
		}
	}
	d.Diff = sb.String()
	return d
}
