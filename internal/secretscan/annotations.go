package secretscan

import (
	"encoding/json"
	"regexp"
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
	KindSecretReference = "secret_reference"
)

// Kinds lists the annotation kinds.
var Kinds = []string{KindSSHPublicKey, KindFingerprint, KindNodeKey, KindAgeRecipient, KindPEMPublicKey, KindJWKPublic, KindHexID, KindSecretReference}

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
	refOP     = regexp.MustCompile(`^op://\S+$`)
	refVault  = regexp.MustCompile(`^vault:\S+$`)
	refEnv    = regexp.MustCompile(`^(?:env:[A-Z_][A-Z0-9_]*|\$\{[A-Z_][A-Z0-9_]*\})$`)
	refPath   = regexp.MustCompile(`^(?:/|~/|\./)[A-Za-z0-9._@%+=,:/-]+$`)
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
		for _, k := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, has := jwk[k]; has {
				return false
			}
		}
		return true
	case KindHexID:
		return hexID.MatchString(v)
	case KindSecretReference:
		return refOP.MatchString(v) || refVault.MatchString(v) || refEnv.MatchString(v) || refPath.MatchString(v)
	}
	return false
}
