//go:build windows

package fsutil

import (
	"errors"
	"syscall"
	"time"
)

const (
	errorAccessDenied     syscall.Errno = 5
	errorSharingViolation syscall.Errno = 32
	errorLockViolation    syscall.Errno = 33
)

func transient(err error) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	return en == errorAccessDenied || en == errorSharingViolation || en == errorLockViolation
}

func rename(oldpath, newpath string, do func(string, string) error) error {
	var err error
	delay := 5 * time.Millisecond
	for i := 0; i < 8; i++ {
		if err = do(oldpath, newpath); err == nil || !transient(err) {
			return err
		}
		time.Sleep(delay)
		delay *= 2
	}
	return err
}
