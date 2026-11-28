//go:build !windows

package localauth

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// The admin channel on Linux and macOS: a Unix socket <state-dir>/admin.sock, mode 0600.

func socketPath(stateDir string) string { return filepath.Join(stateDir, "admin.sock") }

func listenAdmin(stateDir string) (net.Listener, func(), error) {
	path := socketPath(stateDir)
	if len(path) > 100 {
		return nil, nil, fmt.Errorf("the admin socket path %s is too long for a Unix socket: use a shorter --state-dir", path)
	}
	// a socket left by a crashed server is removed; one that answers belongs to a running server
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, nil, fmt.Errorf("another process holds the admin socket %s", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	old := syscall.Umask(0o177) // the socket is created 0600, with no moment in which it is wider
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, nil, err
	}
	_ = os.Chmod(path, 0o600)
	return ln, func() { os.Remove(path) }, nil
}

func dialAdmin(ctx context.Context, stateDir string) (net.Conn, error) {
	path := socketPath(stateDir)
	if _, err := os.Lstat(path); err != nil {
		return nil, ErrNoServer
	}
	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoServer // a stale socket
		}
		return nil, err
	}
	return c, nil
}
