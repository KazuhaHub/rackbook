package login

import (
	"strings"
	"testing"
)

func TestPasskeyNameThatIsASecretIsRefusedBeforeTheCeremony(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, remote: true})
	b := e.browser()
	b.login("admin", "")
	commits := git(t, e.bare, "rev-list", "--count", "main")
	secret := "xox" + "b-1234567890-abcdefghij"
	fin := e.newDevice().enrol(b, "my key "+secret)
	if fin.StatusCode != 422 || !strings.Contains(fin.Body, `"secret_detected"`) || !strings.Contains(fin.Body, "slack-token") || strings.Contains(fin.Body, secret[:8]) {
		t.Fatalf("%d %s", fin.StatusCode, fin.Body)
	}
	if got := git(t, e.bare, "rev-list", "--count", "main"); got != commits {
		t.Fatal("a refused passkey name was committed")
	}
	// The public key and ids in the file are not scanned: a normal enrol works.
	if fin := e.newDevice().enrol(b, "MacBook"); fin.StatusCode != 201 {
		t.Fatalf("%d %s", fin.StatusCode, fin.Body)
	}
}
