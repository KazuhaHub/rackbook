package ansiblerepo

import "go.yaml.in/yaml/v3"

func yamlV3Unmarshal(b []byte, v any) error { return yaml.Unmarshal(b, v) }
