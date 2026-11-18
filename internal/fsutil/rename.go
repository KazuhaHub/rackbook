// Package fsutil holds the few filesystem helpers that behave differently on
// Windows.
package fsutil

import "os"

// Rename moves oldpath over newpath. On POSIX systems this is os.Rename, which
// replaces an existing file atomically. On Windows, os.Rename replaces an
// existing file with MoveFileEx, but it fails with a sharing or access violation
// while another process (a virus scanner, an editor, a concurrent reader) has
// the target open; Rename then retries for a short while before giving up.
func Rename(oldpath, newpath string) error { return rename(oldpath, newpath, os.Rename) }
