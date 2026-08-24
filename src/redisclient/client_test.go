package redisclient

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRedisServer is a minimal in-process RESP2 server good enough to exercise the client
// without a real Redis instance. It records every command it receives and replies according to
// a simple in-memory key/value map, or a scripted response if one is queued.
type fakeRedisServer struct {
	t        *testing.T
	listener net.Listener

	mu       sync.Mutex
	store    map[string]string
	commands [][]string
	authSeen bool
	closeOn  string // if a command's first arg matches this, the connection is dropped instead of answered
}

func startFakeRedisServer(t *testing.T) *fakeRedisServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake redis server: %v", err)
	}

	s := &fakeRedisServer{t: t, listener: ln, store: map[string]string{}}

	go s.acceptLoop()
	t.Cleanup(func() { ln.Close() })

	return s
}

func (s *fakeRedisServer) addr() string {
	return s.listener.Addr().String()
}

func (s *fakeRedisServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *fakeRedisServer) handleConn(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}

		s.mu.Lock()
		s.commands = append(s.commands, args)
		s.mu.Unlock()

		if len(args) == 0 {
			continue
		}

		if s.closeOn != "" && strings.EqualFold(args[0], s.closeOn) {
			return
		}

		reply := s.handle(args)
		if _, err := w.WriteString(reply); err != nil {
			return
		}
		if err := w.Flush(); err != nil {
			return
		}
	}
}

func (s *fakeRedisServer) handle(args []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "AUTH":
		s.authSeen = true
		return "+OK\r\n"
	case "SELECT":
		return "+OK\r\n"
	case "PING":
		return "+PONG\r\n"
	case "SET":
		if len(args) < 3 {
			return "-ERR wrong number of arguments\r\n"
		}
		s.store[args[1]] = args[2]
		return "+OK\r\n"
	case "GET":
		val, ok := s.store[args[1]]
		if !ok {
			return "$-1\r\n"
		}
		return fmt.Sprintf("$%d\r\n%s\r\n", len(val), val)
	case "DEL":
		delete(s.store, args[1])
		return ":1\r\n"
	default:
		return fmt.Sprintf("-ERR unknown command %q\r\n", cmd)
	}
}

func (s *fakeRedisServer) receivedCommands() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.commands))
	copy(out, s.commands)
	return out
}

// readCommand decodes a single RESP2 array-of-bulk-strings command, the wire format writeCommand
// produces - i.e. it's the server-side mirror of this package's own client encoding.
func readCommand(r *bufio.Reader) ([]string, error) {
	rep, err := readReply(r)
	if err != nil {
		return nil, err
	}
	if !rep.isArray {
		return nil, fmt.Errorf("expected array, got %+v", rep)
	}
	args := make([]string, len(rep.array))
	for i, item := range rep.array {
		args[i] = item.str
	}
	return args, nil
}

func testConfig(addr string) Config {
	return Config{
		Address:      addr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolSize:     2,
	}
}

func TestSetGetRoundTrip(t *testing.T) {
	srv := startFakeRedisServer(t)
	pool := NewPool(testConfig(srv.addr()))

	if err := pool.Set("k1", "v1", 0); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	val, found, err := pool.Get("k1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !found {
		t.Fatalf("expected key to be found")
	}
	if val != "v1" {
		t.Fatalf("expected value %q, got %q", "v1", val)
	}
}

func TestGetMiss(t *testing.T) {
	srv := startFakeRedisServer(t)
	pool := NewPool(testConfig(srv.addr()))

	_, found, err := pool.Get("missing")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if found {
		t.Fatalf("expected key to not be found")
	}
}

func TestDel(t *testing.T) {
	srv := startFakeRedisServer(t)
	pool := NewPool(testConfig(srv.addr()))

	_ = pool.Set("k1", "v1", 0)
	if err := pool.Del("k1"); err != nil {
		t.Fatalf("Del failed: %v", err)
	}

	_, found, _ := pool.Get("k1")
	if found {
		t.Fatalf("expected key to be gone after Del")
	}
}

func TestSetWithTTLSendsExArg(t *testing.T) {
	srv := startFakeRedisServer(t)
	pool := NewPool(testConfig(srv.addr()))

	if err := pool.Set("k1", "v1", 30*time.Second); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	found := false
	for _, cmd := range srv.receivedCommands() {
		if len(cmd) >= 5 && strings.EqualFold(cmd[0], "SET") && strings.EqualFold(cmd[3], "EX") && cmd[4] == "30" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a SET ... EX 30 command, got %v", srv.receivedCommands())
	}
}

func TestAuthSentWhenCredentialsConfigured(t *testing.T) {
	srv := startFakeRedisServer(t)
	cfg := testConfig(srv.addr())
	cfg.Password = "secret"
	pool := NewPool(cfg)

	if err := pool.Ping(); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	srv.mu.Lock()
	authSeen := srv.authSeen
	srv.mu.Unlock()

	if !authSeen {
		t.Fatalf("expected an AUTH command to have been sent")
	}
}

func TestNoAuthSentWithoutCredentials(t *testing.T) {
	srv := startFakeRedisServer(t)
	pool := NewPool(testConfig(srv.addr()))

	if err := pool.Ping(); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	srv.mu.Lock()
	authSeen := srv.authSeen
	srv.mu.Unlock()

	if authSeen {
		t.Fatalf("expected no AUTH command without configured credentials")
	}
}

func TestConnectionErrorIsNotPooled(t *testing.T) {
	srv := startFakeRedisServer(t)
	srv.closeOn = "PING"
	pool := NewPool(testConfig(srv.addr()))

	if err := pool.Ping(); err == nil {
		t.Fatalf("expected an error when the server drops the connection")
	}

	// A second call must dial a fresh connection rather than reuse a broken one.
	srv.closeOn = ""
	if err := pool.Ping(); err != nil {
		t.Fatalf("expected the pool to recover with a fresh connection, got: %v", err)
	}
}

func TestDialErrorOnUnreachableServer(t *testing.T) {
	pool := NewPool(Config{
		Address:     "127.0.0.1:1", // reserved, nothing listens here
		DialTimeout: 200 * time.Millisecond,
		PoolSize:    1,
	})

	if err := pool.Ping(); err == nil {
		t.Fatalf("expected an error connecting to an unreachable address")
	}
}
