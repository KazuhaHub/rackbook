package secretscan

import "testing"

// FuzzScan feeds arbitrary text through the default scanner as a record value,
// a field name and a YAML file. Nothing may panic, and every finding must name
// a rule and be either block or confirm tier.
func FuzzScan(f *testing.F) {
	for _, seed := range []string{
		"", "hello", pemHead + "\nb3BlbnNz", age, ghp, ghPAT, openai, slack, aws,
		google, stripe, jwt, hex32, urlPw, "password: hunter2",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		s := Default()
		var all []Finding
		// As a value and as a field name, inside a record.
		all = append(all, s.ScanRecord("c", "id", map[string]any{"f": text})...)
		all = append(all, s.ScanRecord("c", "id", map[string]any{text: "v"})...)
		// As the contents of a YAML file; invalid YAML simply finds nothing.
		all = append(all, s.ScanYAML("x.yml", []byte(text))...)
		for _, fd := range all {
			if fd.Rule == "" {
				t.Fatalf("finding without a rule: %+v", fd)
			}
			if fd.Tier != TierBlock && fd.Tier != TierConfirm {
				t.Fatalf("finding with tier %q: %+v", fd.Tier, fd)
			}
		}
	})
}
