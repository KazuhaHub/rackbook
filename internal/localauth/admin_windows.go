//go:build windows

package localauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The admin channel on Windows: a named pipe \\.\pipe\rackbook-<first 16 hex of SHA-256 of the state directory's
// absolute path>, created with FILE_FLAG_FIRST_PIPE_INSTANCE and a security descriptor that grants access only to the
// server's account and Administrators. If a pipe of that name already exists the server refuses to start, so nothing
// else can stand in for the server's end. The protocol above it is the one of the other systems.

func pipeName(stateDir string) (string, error) {
	abs, err := filepath.Abs(stateDir)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	sum := sha256.Sum256([]byte(abs))
	return `\\.\pipe\rackbook-` + hex.EncodeToString(sum[:8]), nil
}

// securityDescriptor allows GENERIC_ALL to the account of this process and to Administrators, and nothing to anyone else.
func securityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sddl := fmt.Sprintf("D:P(A;;GA;;;%s)(A;;GA;;;BA)", user.User.Sid.String())
	return windows.SecurityDescriptorFromString(sddl)
}

type pipeListener struct {
	name  string
	sd    *windows.SECURITY_DESCRIPTOR
	mu    sync.Mutex
	next  windows.Handle // the instance waiting for a client
	done  chan struct{}
	once  sync.Once
	first bool
}

func (l *pipeListener) create(first bool) (windows.Handle, error) {
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: l.sd}
	mode := uint32(windows.PIPE_ACCESS_DUPLEX)
	if first {
		mode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	name, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return 0, err
	}
	return windows.CreateNamedPipe(name, mode, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, sa)
}

func listenAdmin(stateDir string) (net.Listener, func(), error) {
	name, err := pipeName(stateDir)
	if err != nil {
		return nil, nil, err
	}
	sd, err := securityDescriptor()
	if err != nil {
		return nil, nil, err
	}
	l := &pipeListener{name: name, sd: sd, done: make(chan struct{})}
	h, err := l.create(true)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, nil, fmt.Errorf("another process holds the admin pipe %s", name)
		}
		return nil, nil, err
	}
	l.next = h
	return l, nil, nil
}

type pipeConn struct {
	f *os.File
}

func (c *pipeConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *pipeConn) Close() error                       { return c.f.Close() }
func (c *pipeConn) LocalAddr() net.Addr                { return pipeAddr("pipe") }
func (c *pipeConn) RemoteAddr() net.Addr               { return pipeAddr("pipe") }
func (c *pipeConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

type pipeAddr string

func (pipeAddr) Network() string  { return "pipe" }
func (a pipeAddr) String() string { return string(a) }

func (l *pipeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	h := l.next
	l.mu.Unlock()
	if h == 0 {
		return nil, net.ErrClosed
	}
	if err := windows.ConnectNamedPipe(h, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		default:
		}
		return nil, err
	}
	next, err := l.create(false)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	l.mu.Lock()
	l.next = next
	l.mu.Unlock()
	return &pipeConn{f: os.NewFile(uintptr(h), l.name)}, nil
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.mu.Lock()
		h := l.next
		l.next = 0
		l.mu.Unlock()
		if h != 0 {
			windows.CloseHandle(h) // ends a ConnectNamedPipe that waits
		}
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.name) }

func dialAdmin(ctx context.Context, stateDir string) (net.Conn, error) {
	name, err := pipeName(stateDir)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			return &pipeConn{f: os.NewFile(uintptr(h), name)}, nil
		}
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			return nil, ErrNoServer
		case errors.Is(err, windows.ERROR_PIPE_BUSY) && time.Now().Before(deadline):
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		default:
			return nil, err
		}
	}
}
