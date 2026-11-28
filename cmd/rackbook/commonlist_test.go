package main

import (
	"fmt"

	"github.com/kazuhahub/rackbook/internal/accounts"
)

// The tests run local sign-in with a list of the size the gate asks for; the production code has only the embedded one.
func init() {
	extra := make([]string, accounts.MinCommonPasswords)
	for i := range extra {
		extra[i] = fmt.Sprintf("filler-common-password-%d", i)
	}
	testCommonList = accounts.NewCommonList(extra...)
}
