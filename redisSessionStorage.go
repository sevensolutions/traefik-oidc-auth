// yaegi:tags purego

package traefik_oidc_auth

import (
	"encoding/json"

	"github.com/go-redis/redis"
)

type RedisSessionStorage struct {
	client *redis.Client
}

func CreateRedisSessionStorage(address string, password string) *RedisSessionStorage {
	storage := new(RedisSessionStorage)

	storage.client = redis.NewClient(&redis.Options{
		Addr:     address,
		Password: password,
		DB:       0, // use default DB
	})

	return storage
}

func (storage *RedisSessionStorage) StoreSession(sessionId string, state *SessionState) (string, error) {
	stateJson, _ := json.Marshal(*state)

	// TODO: Get expiration from token
	storage.client.Set(sessionId, string(stateJson), 0)

	return sessionId, nil
}

func (storage *RedisSessionStorage) TryGetSession(sessionTicket string) (*SessionState, error) {
	state := &SessionState{}

	result := storage.client.Get(sessionTicket)

	stateJson := result.Val()

	err := json.Unmarshal([]byte(stateJson), state)
	if err != nil {
		return nil, err
	}

	return state, nil
}
