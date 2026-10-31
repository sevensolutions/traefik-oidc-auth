package session

import (
	"encoding/json"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/redisclient"
	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

// redisClient is the subset of *redisclient.Pool this storage backend needs. Depending on this
// small interface instead of the concrete type keeps RedisSessionStorage testable without a real
// TCP connection.
type redisClient interface {
	Set(key, value string, ttl time.Duration) error
	Get(key string) (value string, found bool, err error)
	Del(key string) error
}

type RedisSessionStorage struct {
	client    redisClient
	keyPrefix string
	ttl       time.Duration
}

func CreateRedisSessionStorage(cfg *config.RedisSessionStorageConfig) *RedisSessionStorage {
	dialTimeout := time.Duration(cfg.DialTimeout) * time.Second
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}

	pool := redisclient.NewPool(redisclient.Config{
		Address:            cfg.Address,
		Username:           cfg.Username,
		Password:           cfg.Password,
		Database:           cfg.Database,
		UseTLS:             cfg.TLSBool,
		InsecureSkipVerify: cfg.InsecureSkipVerifyBool,
		DialTimeout:        dialTimeout,
		ReadTimeout:        dialTimeout,
		WriteTimeout:       dialTimeout,
		PoolSize:           cfg.PoolSize,
	})

	return &RedisSessionStorage{
		client:    pool,
		keyPrefix: cfg.KeyPrefix,
		ttl:       time.Duration(cfg.SessionTimeout) * time.Second,
	}
}

func (storage *RedisSessionStorage) StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error) {
	stateJson, _ := json.Marshal(*state)

	encrypted, err := utils.Encrypt(string(stateJson), config.Secret)
	if err != nil {
		logger.Log(logging.LevelError, "Failed to encrypt session state: %s", err.Error())
		return "", err
	}

	err = storage.client.Set(storage.key(sessionId), encrypted, storage.ttl)
	if err != nil {
		logger.Log(logging.LevelError, "Failed to store session in Redis: %s", err.Error())
		return "", err
	}

	// Unlike CookieSessionStorage, the ticket handed back here is just the (already-random,
	// unguessable) session id - the actual state lives in Redis, not in the cookie.
	return sessionId, nil
}

func (storage *RedisSessionStorage) TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error) {
	encrypted, found, err := storage.client.Get(storage.key(sessionTicket))
	if err != nil {
		logger.Log(logging.LevelError, "Failed to read session from Redis: %s", err.Error())
		return nil, err
	}
	if !found {
		return nil, nil
	}

	plain, err := utils.Decrypt(encrypted, config.Secret)
	if err != nil {
		logger.Log(logging.LevelError, "Failed to decrypt session state: %s", err.Error())
		return nil, err
	}

	state := &SessionState{}

	err = json.Unmarshal([]byte(plain), state)
	if err != nil {
		return nil, err
	}

	return state, nil
}

func (storage *RedisSessionStorage) ClearSession(logger *logging.Logger, config *config.Config, sessionId string) error {
	err := storage.client.Del(storage.key(sessionId))
	if err != nil {
		logger.Log(logging.LevelError, "Failed to clear session from Redis: %s", err.Error())
	}
	return err
}

func (storage *RedisSessionStorage) key(sessionId string) string {
	return storage.keyPrefix + sessionId
}
