package session

import (
	"strings"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

// fakeRedisClient is an in-memory stand-in for redisClient, avoiding any real network I/O.
type fakeRedisClient struct {
	store map[string]string
}

func newFakeRedisClient() *fakeRedisClient {
	return &fakeRedisClient{store: map[string]string{}}
}

func (f *fakeRedisClient) Set(key, value string, ttl time.Duration) error {
	f.store[key] = value
	return nil
}

func (f *fakeRedisClient) Get(key string) (string, bool, error) {
	val, ok := f.store[key]
	return val, ok, nil
}

func (f *fakeRedisClient) Del(key string) error {
	delete(f.store, key)
	return nil
}

func newTestRedisSessionStorage(client redisClient) (*RedisSessionStorage, *config.Config) {
	storage := &RedisSessionStorage{
		client:    client,
		keyPrefix: "Test:Session:",
		ttl:       time.Hour,
	}
	cfg := &config.Config{Secret: "01234567890123456789012345678901"} // 32 chars
	return storage, cfg
}

func TestRedisSessionStorage_StoreThenRetrieve(t *testing.T) {
	client := newFakeRedisClient()
	storage, cfg := newTestRedisSessionStorage(client)
	logger := logging.CreateLogger(logging.LevelDebug)

	state := &SessionState{
		Id:          "session-1",
		AccessToken: "access-token",
	}

	ticket, err := storage.StoreSession(logger, cfg, state.Id, state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}
	if ticket != state.Id {
		t.Fatalf("expected ticket to be the bare session id %q, got %q", state.Id, ticket)
	}

	got, err := storage.TryGetSession(logger, cfg, ticket)
	if err != nil {
		t.Fatalf("TryGetSession failed: %v", err)
	}
	if got == nil {
		t.Fatalf("expected a session to be returned")
	}
	if got.AccessToken != state.AccessToken {
		t.Fatalf("expected AccessToken %q, got %q", state.AccessToken, got.AccessToken)
	}
}

func TestRedisSessionStorage_MissReturnsNilNil(t *testing.T) {
	client := newFakeRedisClient()
	storage, cfg := newTestRedisSessionStorage(client)
	logger := logging.CreateLogger(logging.LevelDebug)

	got, err := storage.TryGetSession(logger, cfg, "does-not-exist")
	if err != nil {
		t.Fatalf("expected no error on a miss, got: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil session on a miss, got: %+v", got)
	}
}

func TestRedisSessionStorage_ClearSessionThenMiss(t *testing.T) {
	client := newFakeRedisClient()
	storage, cfg := newTestRedisSessionStorage(client)
	logger := logging.CreateLogger(logging.LevelDebug)

	state := &SessionState{Id: "session-1", AccessToken: "access-token"}
	ticket, err := storage.StoreSession(logger, cfg, state.Id, state)
	if err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	if err := storage.ClearSession(logger, cfg, state.Id); err != nil {
		t.Fatalf("ClearSession failed: %v", err)
	}

	got, err := storage.TryGetSession(logger, cfg, ticket)
	if err != nil {
		t.Fatalf("TryGetSession failed: %v", err)
	}
	if got != nil {
		t.Fatalf("expected the session to be gone after ClearSession, got: %+v", got)
	}
}

func TestRedisSessionStorage_StoredValueIsEncrypted(t *testing.T) {
	client := newFakeRedisClient()
	storage, cfg := newTestRedisSessionStorage(client)
	logger := logging.CreateLogger(logging.LevelDebug)

	state := &SessionState{Id: "session-1", AccessToken: "super-secret-access-token"}
	if _, err := storage.StoreSession(logger, cfg, state.Id, state); err != nil {
		t.Fatalf("StoreSession failed: %v", err)
	}

	raw, ok := client.store[storage.keyPrefix+state.Id]
	if !ok {
		t.Fatalf("expected a value to be stored under the prefixed key")
	}
	if strings.Contains(raw, state.AccessToken) {
		t.Fatalf("expected the stored value to be encrypted, but the plaintext access token was found in it")
	}
}
