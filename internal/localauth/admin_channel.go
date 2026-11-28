package localauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/kazuhahub/rackbook/internal/statekey"
)

// The admin channel (docs/design-local-accounts.md, 11.3): the same protocol on a Unix socket and on a Windows named
// pipe. The operating system's permission is defence in depth; access is by possession of the state key.
//
//  1. The client sends a 32-byte nonce Nc.
//  2. The server answers a nonce Ns and HMAC(k_channel, "server" || Nc || Ns), which the client checks before it sends
//     anything else.
//  3. Both derive k_session = HKDF-SHA256(k_channel, salt = Nc || Ns, info = "rackbook admin session v1"). Every request
//     and answer is sealed with AES-256-GCM under it, with a counter in the nonce and the direction in the additional
//     data; the first request that opens correctly proves the client holds the key.
//
// A caller without the key, such as a sidecar under the same account relaying the connection, can neither read nor
// forge anything, and links never cross the channel in clear.

const (
	adminNonceLen   = 32
	maxAdminFrame   = 1 << 20
	maxAdminReqs    = 16
	adminConnTime   = 2 * time.Minute
	adminMaxConns   = 8
	adminSessionTag = "rackbook admin session v1"
)

var errAdminAuth = errors.New("the admin channel could not be authenticated: is this the server's state key?")

func channelKey(k *statekey.Key) []byte { return k.Sub(statekey.PurposeAdminChannel) }

func serverProof(kc, nc, ns []byte) []byte {
	m := hmac.New(sha256.New, kc)
	m.Write([]byte("server"))
	m.Write(nc)
	m.Write(ns)
	return m.Sum(nil)
}

func sessionAEAD(kc, nc, ns []byte) (cipher.AEAD, error) {
	salt := append(append([]byte(nil), nc...), ns...)
	// crypto/hkdf: HKDF-SHA256 with the channel key as the secret and Nc||Ns as the salt
	k, err := hkdf.Key(sha256.New, kc, salt, adminSessionTag, 32)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

const (
	dirClient = 'c'
	dirServer = 's'
)

// secureConn seals and opens frames: a 4-byte length, then the ciphertext. The nonce is the direction's counter, so a
// frame that is replayed, dropped, reordered or sent back the other way does not open.
type secureConn struct {
	c        net.Conn
	aead     cipher.AEAD
	send     uint64
	recv     uint64
	sendDir  byte
	recvDir  byte
	maxFrame int
}

func (s *secureConn) nonce(counter uint64) []byte {
	n := make([]byte, s.aead.NonceSize())
	binary.BigEndian.PutUint64(n[len(n)-8:], counter)
	return n
}

func (s *secureConn) writeMsg(v any) error {
	pt, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ct := s.aead.Seal(nil, s.nonce(s.send), pt, []byte{s.sendDir})
	if len(ct) > s.maxFrame {
		return errors.New("the message is too large")
	}
	s.send++
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	_, err = s.c.Write(append(hdr[:], ct...))
	return err
}

func (s *secureConn) readMsg(v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(s.c, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int(n) > s.maxFrame || n < uint32(s.aead.Overhead()) {
		return errAdminAuth
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(s.c, ct); err != nil {
		return err
	}
	pt, err := s.aead.Open(nil, s.nonce(s.recv), ct, []byte{s.recvDir})
	if err != nil {
		return errAdminAuth
	}
	s.recv++
	return json.Unmarshal(pt, v)
}

// serverHandshake answers a client's nonce. Nothing is sent before the client's nonce arrived, and nothing is read
// from the client afterwards without opening it.
func serverHandshake(c net.Conn, kc []byte) (*secureConn, error) {
	nc := make([]byte, adminNonceLen)
	if _, err := io.ReadFull(c, nc); err != nil {
		return nil, err
	}
	ns := make([]byte, adminNonceLen)
	if _, err := rand.Read(ns); err != nil {
		return nil, err
	}
	if _, err := c.Write(append(append([]byte(nil), ns...), serverProof(kc, nc, ns)...)); err != nil {
		return nil, err
	}
	a, err := sessionAEAD(kc, nc, ns)
	if err != nil {
		return nil, err
	}
	return &secureConn{c: c, aead: a, sendDir: dirServer, recvDir: dirClient, maxFrame: maxAdminFrame}, nil
}

func clientHandshake(c net.Conn, kc []byte) (*secureConn, error) {
	nc := make([]byte, adminNonceLen)
	if _, err := rand.Read(nc); err != nil {
		return nil, err
	}
	if _, err := c.Write(nc); err != nil {
		return nil, err
	}
	resp := make([]byte, adminNonceLen+sha256.Size)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	ns, proof := resp[:adminNonceLen], resp[adminNonceLen:]
	if !hmac.Equal(proof, serverProof(kc, nc, ns)) {
		return nil, errAdminAuth // the other end is not the server of this state directory: nothing is sent to it
	}
	a, err := sessionAEAD(kc, nc, ns)
	if err != nil {
		return nil, err
	}
	return &secureConn{c: c, aead: a, sendDir: dirClient, recvDir: dirServer, maxFrame: maxAdminFrame}, nil
}

// ---- the server

// AdminServer accepts admin connections and runs their commands.
type AdminServer struct {
	ln   net.Listener
	kc   []byte
	env  func() AdminEnv
	log  func(string, ...any)
	sem  chan struct{}
	done chan struct{}
	stop func()
}

// ServeAdmin listens on the admin endpoint of the state directory (a Unix socket, or a named pipe on Windows) and
// serves commands until Close. It refuses to start when another process holds the endpoint.
func (s *Service) ServeAdmin() (*AdminServer, error) {
	return ServeAdminWith(s.o.StateDir, s.o.Key, s.AdminEnv, func(msg string, args ...any) { s.log.Warn(msg, args...) })
}

// ServeAdminWith is ServeAdmin for any source of commands' environment (the tests of the command line use it).
func ServeAdminWith(stateDir string, key *statekey.Key, env func() AdminEnv, logf func(string, ...any)) (*AdminServer, error) {
	if stateDir == "" {
		return nil, errors.New("the admin channel needs --state-dir")
	}
	ln, stop, err := listenAdmin(stateDir)
	if err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	a := &AdminServer{ln: ln, kc: channelKey(key), env: env, sem: make(chan struct{}, adminMaxConns), done: make(chan struct{}), stop: stop, log: logf}
	go a.loop()
	return a, nil
}

// Close stops listening and removes the endpoint.
func (a *AdminServer) Close() {
	a.ln.Close()
	<-a.done
	if a.stop != nil {
		a.stop()
	}
}

func (a *AdminServer) loop() {
	defer close(a.done)
	for {
		c, err := a.ln.Accept()
		if err != nil {
			return
		}
		select {
		case a.sem <- struct{}{}:
			go func() {
				defer func() { <-a.sem }()
				a.serve(c)
			}()
		default:
			c.Close() // busy: an unauthenticated peer cannot hold the server's attention
		}
	}
}

func (a *AdminServer) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(adminConnTime))
	sc, err := serverHandshake(c, a.kc)
	if err != nil {
		return
	}
	for i := 0; i < maxAdminReqs; i++ {
		var req AdminRequest
		if err := sc.readMsg(&req); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				a.log("admin channel: a request did not open; the peer does not hold the state key")
			}
			return
		}
		resp := a.env().Do(req)
		if err := sc.writeMsg(resp); err != nil {
			return
		}
	}
}

// ---- the client

// AdminClient is a connection to a running server.
type AdminClient struct{ sc *secureConn }

// ErrNoServer says there is no admin endpoint answering: the server is not running (or is not this state directory's).
var ErrNoServer = errors.New("no running server answers on the admin channel")

// DialAdmin connects to the server of the state directory and authenticates it with the state key. ErrNoServer means
// nothing listens there. A server that is there but does not prove it holds the key is refused before anything is sent.
func DialAdmin(ctx context.Context, stateDir string, key *statekey.Key) (*AdminClient, error) {
	c, err := dialAdmin(ctx, stateDir)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(adminConnTime))
	sc, err := clientHandshake(c, channelKey(key))
	if err != nil {
		c.Close()
		return nil, err
	}
	return &AdminClient{sc: sc}, nil
}

// Do sends one command and waits for its answer.
func (c *AdminClient) Do(req AdminRequest) (AdminResponse, error) {
	var resp AdminResponse
	if err := c.sc.writeMsg(req); err != nil {
		return resp, err
	}
	if err := c.sc.readMsg(&resp); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return resp, fmt.Errorf("the server closed the admin channel: %w", errAdminAuth)
		}
		return resp, err
	}
	return resp, nil
}

// Close ends the connection.
func (c *AdminClient) Close() { c.sc.c.Close() }
