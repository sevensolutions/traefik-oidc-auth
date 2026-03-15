package session

import (
	"encoding/json"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

type CookieSessionStorage struct {
}

func CreateCookieSessionStorage() *CookieSessionStorage {
	storage := new(CookieSessionStorage)
	return storage
}

func (storage *CookieSessionStorage) StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error) {
	stateJson, _ := json.Marshal(*state)

	return string(stateJson), nil
}

func (storage *CookieSessionStorage) TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error) {
	state := &SessionState{}

	err := json.Unmarshal([]byte(sessionTicket), state)
	if err != nil {
		return nil, err
	}

	return state, nil
}
