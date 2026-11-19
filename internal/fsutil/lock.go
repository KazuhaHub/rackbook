package fsutil

import (
	"errors"
	"fmt"
	"os"
)

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("locked by another process")

// Lock takes an exclusive lock on the file at path (creating it, mode 0600)
// without waiting, and returns the function that releases it. The lock is held
// by the open file, so the operating system drops it when the process ends,
// however it ends. It uses flock on Unix and LockFileEx on Windows.
func Lock(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	return func() { f.Close() }, nil
}
