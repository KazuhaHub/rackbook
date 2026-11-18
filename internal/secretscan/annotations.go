package secretscan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Public kinds a schema property can declare with
//
//	"x-rackbook": {"public": "<kind>"}
//
// An annotated field whose WHOLE value matches the strict format of its kind is
// exempt from the scan; any other value in it is scanned as normal text. This
// is the only exemption there is, apart from the exact placeholders and the
// allow list in rackbook.yml: free text has none.
const (
	KindSSHPublicKey    = "ssh_public_key"
	KindFingerprint     = "fingerprint"
	KindNodeKey         = "nodekey"
	KindAgeRecipient    = "age_recipient"
	KindPEMPublicKey    = "pem_public_key"
	KindJWKPublic       = "jwk_public"
	KindHexID           = "hex_id"
	KindUUID            = "uuid"
	KindSecretReference = "secret_reference"
)

// Kinds lists the annotation kinds.
var Kinds = []string{KindSSHPublicKey, KindFingerprint, KindNodeKey, KindAgeRecipient, KindPEMPublicKey, KindJWKPublic, KindHexID, KindUUID, KindSecretReference}

// Annotations maps a data path of a record ("/ssh_key", "/users/*/key"; a list
// index is written "*") to the public kind its schema property declares.
type Annotations map[string]string

// AnnotationsOf reads the x-rackbook annotations of a JSON Schema document. An
// annotation on an array property, or on its items, covers every item.
func AnnotationsOf(schema []byte) Annotations {
	if len(schema) == 0 {
		return nil
	}
	var doc map[string]any
	if json.Unmarshal(schema, &doc) != nil {
		return nil
	}
	out := Annotations{}
	var walk func(node map[string]any, path string)
	walk = func(node map[string]any, path string) {
		if x, ok := node["x-rackbook"].(map[string]any); ok {
			if k, ok := x["public"].(string); ok && path != "" {
				out[path] = k
			}
		}
		if props, ok := node["properties"].(map[string]any); ok {
			for name, p := range props {
				if pm, ok := p.(map[string]any); ok {
					walk(pm, path+"/"+ptr(name))
				}
			}
		}
		if items, ok := node["items"].(map[string]any); ok {
			walk(items, path+"/*")
		}
	}
	walk(doc, "")
	if len(out) == 0 {
		return nil
	}
	return out
}

// kindOf is the kind that applies to the string at data path (indices become
// "*"; an array's own annotation covers its items).
func (a Annotations) kindOf(path string) string {
	if len(a) == 0 {
		return ""
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if s != "" && isIndex(s) {
			segs[i] = "*"
		}
	}
	p := strings.Join(segs, "/")
	if k, ok := a[p]; ok {
		return k
	}
	if strings.HasSuffix(p, "/*") {
		return a[strings.TrimSuffix(p, "/*")]
	}
	return ""
}

func isIndex(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

var (
	sshPub    = regexp.MustCompile(`^(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) AAAA[0-9A-Za-z+/=]+(?: ([A-Za-z0-9._@+-]+))?$`)
	fpSHA256  = regexp.MustCompile(`^(?:SHA256:[A-Za-z0-9+/]{43}=?|(?i:sha256:)?[0-9a-fA-F]{64}|(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2})$`)
	fpMD5     = regexp.MustCompile(`^(?i:md5:)?(?:(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}|[0-9a-fA-F]{32})$`)
	nodeKey   = regexp.MustCompile(`^(?:nodekey|machinekey|discokey):[0-9a-f]{64}$`)
	ageRecip  = regexp.MustCompile(`^age1[0-9a-z]{58}$`)
	pemPublic = regexp.MustCompile(`^-----BEGIN (?:RSA )?PUBLIC KEY-----\s*[A-Za-z0-9+/=\s]+-----END (?:RSA )?PUBLIC KEY-----$`)
	hexID     = regexp.MustCompile(`^(?:0x)?[0-9a-fA-F]{8,128}$`)
	// a standard UUID, alone or labelled (entra_app_id=<uuid>)
	uuidID = regexp.MustCompile(`^(?:([a-z][a-z0-9_]{0,31})=)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// validFor reports whether the whole value v has the strict format of kind.
func (s *Scanner) validFor(kind, v string) bool {
	v = strings.TrimSpace(v)
	switch kind {
	case KindSSHPublicKey:
		m := sshPub.FindStringSubmatch(v)
		// the comment is the one place text can hide: it must be clean too
		return m != nil && (m[1] == "" || len(s.matches(m[1])) == 0)
	case KindFingerprint:
		return fpSHA256.MatchString(v) || fpMD5.MatchString(v)
	case KindNodeKey:
		return nodeKey.MatchString(v)
	case KindAgeRecipient:
		return ageRecip.MatchString(v)
	case KindPEMPublicKey:
		return pemPublic.MatchString(v)
	case KindJWKPublic:
		var jwk map[string]any
		if json.Unmarshal([]byte(v), &jwk) != nil || jwk["kty"] == nil {
			return false
		}
		for k, val := range jwk {
			switch {
			case k == "d" || k == "p" || k == "q" || k == "dp" || k == "dq" || k == "qi" || k == "oth" || k == "k":
				return false // private or symmetric members
			case publicJWK[k] || strings.HasPrefix(k, "x5"):
				continue
			}
			// every other member is scanned
			if len(s.matches(fmt.Sprint(val))) > 0 {
				return false
			}
		}
		return true
	case KindHexID:
		return hexID.MatchString(v)
	case KindUUID:
		// a label named like a secret ("client_secret=<uuid>") is not an id
		m := uuidID.FindStringSubmatch(v)
		return m != nil && (m[1] == "" || !isSecretName(m[1]))
	case KindSecretReference:
		// the remainder after the prefix is scanned again: "op://ghp_..." and
		// "/ghp_..." are not references, and a path that looks like a value is not a path
		return s.isReference(v) || (isPathValue(v) && len(s.matchText(v)) == 0)
	}
	return false
}

var publicJWK = map[string]bool{"kty": true, "crv": true, "x": true, "y": true, "n": true, "e": true, "kid": true, "use": true, "alg": true, "key_ops": true}

// AnnotationProblems lists the schema properties that are annotated wrongly: an
// unknown kind, or any kind other than secret_reference on a field named like a
// secret (hex_id and fingerprint cannot tell a 32-byte key from an id).
func AnnotationProblems(schema []byte) []string {
	var doc map[string]any
	if json.Unmarshal(schema, &doc) != nil {
		return nil
	}
	var out []string
	var walk func(node map[string]any, name string)
	walk = func(node map[string]any, name string) {
		if x, ok := node["x-rackbook"].(map[string]any); ok {
			if k, ok := x["public"].(string); ok && name != "" {
				known := false
				for _, kk := range Kinds {
					known = known || kk == k
				}
				switch {
				case !known:
					out = append(out, fmt.Sprintf("property %q: unknown x-rackbook public kind %q", name, k))
				case isSecretName(name) && k != KindSecretReference:
					out = append(out, fmt.Sprintf("property %q is named like a secret: only the secret_reference kind may annotate it, not %s", name, k))
				}
			}
		}
		if props, ok := node["properties"].(map[string]any); ok {
			for n, p := range props {
				if pm, ok := p.(map[string]any); ok {
					walk(pm, n)
				}
			}
		}
		if items, ok := node["items"].(map[string]any); ok {
			walk(items, name)
		}
	}
	walk(doc, "")
	sort.Strings(out)
	return out
}

// lastName is the property name a data path ends in (list indices skipped).
func lastName(path string) string {
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != "" && segs[i] != "*" && !isIndex(segs[i]) {
			return strings.NewReplacer("~1", "/", "~0", "~").Replace(segs[i])
		}
	}
	return ""
}
