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
	// The socket is made in a directory that only this user can enter, so there is no moment at which it is reachable by
	// another user, and the process-wide umask (which every other thread would feel) is not touched. It is then given mode
	// 0600 and moved to its name.
	tmp, err := os.MkdirTemp(stateDir, ".admin-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return nil, nil, err
	}
	bound := filepath.Join(tmp, "s")
	ln, err := net.Listen("unix", bound)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(bound, 0o600); err != nil {
		ln.Close()
		return nil, nil, err
	}
	if err := os.Rename(bound, path); err != nil {
		ln.Close()
		return nil, nil, err
	}
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
