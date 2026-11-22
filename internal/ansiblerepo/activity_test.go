package ansiblerepo

import (
	"strings"
	"testing"
)

func TestIsSecretFile(t *testing.T) {
	for p, want := range map[string]bool{
		"secrets/alpha.sops.yaml":        true,
		"secrets/anything.txt":           true,
		"inventory/group_vars/vault.yml": true,
		"inventory/host_vars/a.sops.yml": true,
		"Secrets/Alpha.SOPS.yaml":        true,
		"roles/x/files/key.sops":         true,
		".sops.yaml":                     false,
		"inventory/host_vars/alpha.yml":  false,
		"inventory/hosts.yml":            false,
		"docs/secretsmanagement.md":      false,
		"a/secrets.d/x":                  false,
	} {
		if got := IsSecretFile(p); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}

func TestRedactPatchHidesSecretLookingValuesAndKeepsTheHeaders(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("a1B2", 9)
	patch := "diff --git a/x.yml b/x.yml\nindex 1..2 100644\n--- a/x.yml\n+++ b/x.yml\n@@ -1,3 +1,3 @@\n host: a\n-password: hunter22hunter\n+api_token: " + secret + "\n--- not a header\n"
	got := redactPatch(patch)
	if strings.Contains(got, "hunter22") || strings.Contains(got, secret) {
		t.Fatalf("%s", got)
	}
	for _, keep := range []string{"diff --git a/x.yml b/x.yml", "--- a/x.yml", "+++ b/x.yml", "@@ -1,3 +1,3 @@", " host: a"} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost %q in\n%s", keep, got)
		}
	}
	if !strings.Contains(got, Hidden) {
		t.Fatalf("%s", got)
	}
}

func TestRedactPatchDropsTheFunctionContextOfHunkHeaders(t *testing.T) {
	patch := "diff --git a/x.yml b/x.yml\n--- a/x.yml\n+++ b/x.yml\n@@ -7,5 +7,5 @@ ansible_become_password: hunter2hunter2\n a: 1\n-b: 2\n+b: 3\n"
	got := redactPatch(patch)
	if strings.Contains(got, "hunter2") || !strings.Contains(got, "@@ -7,5 +7,5 @@\n") {
		t.Fatalf("%s", got)
	}
}
