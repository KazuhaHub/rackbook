// Command rackbook is a Git-native infrastructure ledger: CLI, web server,
// MCP server and exports in one static binary.
package main

import (
	"errors"
	"fmt"
	"os"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

// exitError makes main exit with a code without printing anything more.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func main() {
	if err := newRoot().Execute(); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
