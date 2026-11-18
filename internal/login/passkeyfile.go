package login

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// PasskeysPath is where passkey credentials live in the data repository.
const PasskeysPath = config.StateDir + "/passkeys.yml"

const passkeysHeader = `# Passkey public keys, managed by Rackbook (enrol and delete in the console).
# Public keys are not secrets. Deleting a credential here revokes it.
`

// passkeysSchema is the built-in schema of .rackbook/passkeys.yml. The checks
// a schema cannot express (unique ids, decodable base64) are in validate.
const passkeysSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["users"],
  "properties": {
    "users": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["identity", "handle", "credentials"],
        "properties": {
          "identity": {"type": "string", "minLength": 1, "maxLength": 320},
          "name": {"type": "string", "maxLength": 200},
          "handle": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
          "credentials": {
            "type": "array",
            "minItems": 1,
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["id", "name", "created", "public_key", "flags"],
              "properties": {
                "id": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$", "maxLength": 1400},
                "name": {"type": "string", "minLength": 1, "maxLength": 100},
                "created": {"type": "string", "format": "date-time"},
                "public_key": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$", "maxLength": 4096},
                "attestation_type": {"type": "string", "maxLength": 32},
                "transports": {"type": "array", "items": {"type": "string", "maxLength": 32}},
                "flags": {"type": "integer", "minimum": 0, "maximum": 255},
                "aaguid": {"type": "string", "pattern": "^[A-Za-z0-9_-]*$", "maxLength": 64},
                "attachment": {"type": "string", "maxLength": 32}
              }
            }
          }
        }
      }
    }
  }
}`

type pkFile struct {
	Users []pkUser `yaml:"users" json:"users"`
}

type pkUser struct {
	Identity    string   `yaml:"identity" json:"identity"`
	Name        string   `yaml:"name,omitempty" json:"name,omitempty"`
	Handle      string   `yaml:"handle" json:"handle"`
	Credentials []pkCred `yaml:"credentials" json:"credentials"`
}

type pkCred struct {
	ID         string   `yaml:"id" json:"id"`
	Name       string   `yaml:"name" json:"name"`
	Created    string   `yaml:"created" json:"created"`
	PublicKey  string   `yaml:"public_key" json:"public_key"`
	Type       string   `yaml:"attestation_type,omitempty" json:"attestation_type,omitempty"`
	Transports []string `yaml:"transports,omitempty" json:"transports,omitempty"`
	Flags      uint8    `yaml:"flags" json:"flags"`
	AAGUID     string   `yaml:"aaguid,omitempty" json:"aaguid,omitempty"`
	Attachment string   `yaml:"attachment,omitempty" json:"attachment,omitempty"`
}

var pkSchema = func() *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(passkeysSchema))
	if err != nil {
		panic(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("passkeys.json", doc); err != nil {
		panic(err)
	}
	return c.MustCompile("passkeys.json")
}()

// parsePasskeys reads and validates .rackbook/passkeys.yml. Empty input is an
// empty file.
func parsePasskeys(data []byte) (*pkFile, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return &pkFile{}, nil
	}
	var raw any
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s: %w", PasskeysPath, err)
	}
	js, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", PasskeysPath, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(js))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", PasskeysPath, err)
	}
	if err := pkSchema.Validate(inst); err != nil {
		return nil, fmt.Errorf("%s does not match its schema: %v", PasskeysPath, err)
	}
	var f pkFile
	if err := json.Unmarshal(js, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", PasskeysPath, err)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", PasskeysPath, err)
	}
	return &f, nil
}

func b64ok(s string) bool {
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

func (f *pkFile) validate() error {
	ids, handles, identities := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, u := range f.Users {
		if u.Identity != roles.FoldASCII(u.Identity) || strings.TrimSpace(u.Identity) != u.Identity {
			return fmt.Errorf("identity %q must be lowercase (ASCII) without surrounding spaces", u.Identity)
		}
		if identities[u.Identity] {
			return fmt.Errorf("identity %q appears twice", u.Identity)
		}
		identities[u.Identity] = true
		if handles[u.Handle] || !b64ok(u.Handle) {
			return fmt.Errorf("user handle of %q is duplicated or not base64url", u.Identity)
		}
		handles[u.Handle] = true
		for _, c := range u.Credentials {
			if ids[c.ID] {
				return fmt.Errorf("credential id %q appears twice", c.ID)
			}
			ids[c.ID] = true
			if !b64ok(c.ID) || !b64ok(c.PublicKey) || !b64ok(c.AAGUID) {
				return fmt.Errorf("credential %q of %q: id, public_key and aaguid must be base64url", c.ID, u.Identity)
			}
			if _, err := time.Parse(time.RFC3339, c.Created); err != nil {
				return fmt.Errorf("credential %q: created: %w", c.ID, err)
			}
		}
	}
	return nil
}

// marshal renders the file and checks that it reads back: a change that
// would leave a file the loader refuses (and so lock everyone out of
// passkeys) is refused instead of committed.
func (f *pkFile) marshal() ([]byte, error) {
	if f.Users == nil {
		f.Users = []pkUser{}
	}
	b, err := yaml.Marshal(f)
	if err != nil {
		return nil, err
	}
	out := append([]byte(passkeysHeader), b...)
	if _, err := parsePasskeys(out); err != nil {
		return nil, fmt.Errorf("refusing to write an invalid file: %w", err)
	}
	return out, nil
}

func (f *pkFile) userByIdentity(id string) *pkUser {
	for i := range f.Users {
		if f.Users[i].Identity == id {
			return &f.Users[i]
		}
	}
	return nil
}

func (f *pkFile) userByHandle(h string) *pkUser {
	for i := range f.Users {
		if f.Users[i].Handle == h {
			return &f.Users[i]
		}
	}
	return nil
}

func (f *pkFile) findCred(id string) (*pkUser, *pkCred) {
	for i := range f.Users {
		for j := range f.Users[i].Credentials {
			if f.Users[i].Credentials[j].ID == id {
				return &f.Users[i], &f.Users[i].Credentials[j]
			}
		}
	}
	return nil, nil
}

// removeCred deletes a credential, and its user when it was the last one.
func (f *pkFile) removeCred(id string) (user string, ok bool) {
	for i := range f.Users {
		u := &f.Users[i]
		for j := range u.Credentials {
			if u.Credentials[j].ID != id {
				continue
			}
			user = u.Identity
			u.Credentials = append(u.Credentials[:j:j], u.Credentials[j+1:]...)
			if len(u.Credentials) == 0 {
				f.Users = append(f.Users[:i:i], f.Users[i+1:]...)
			}
			return user, true
		}
	}
	return "", false
}

var errNoSuchCredential = errors.New("no such passkey")
