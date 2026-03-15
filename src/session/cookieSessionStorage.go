package session

import (
	"encoding/json"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

type CookieSessionStorage struct {
}

func CreateCookieSessionStorage() *CookieSessionStorage {
	storage := new(CookieSessionStorage)
	return storage
}

func (storage *CookieSessionStorage) StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error) {
	stateJson, _ := json.Marshal(*state)

	encryptedSessionTicket, err := utils.Encrypt(string(stateJson), config.Secret)
	if err != nil {
		logger.Log(config.LogLevel, logging.LevelError, "Failed to encrypt session state: %s", err.Error())
		return "", err
	}

	return encryptedSessionTicket, nil
}

func (storage *CookieSessionStorage) TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error) {
	plainSessionTicket, err := utils.Decrypt(sessionTicket, config.Secret)
	if err != nil {
		logger.Log(config.LogLevel, logging.LevelError, "Failed to decrypt session ticket: %v", err.Error())
		return nil, err
	}

	state := &SessionState{}

	err = json.Unmarshal([]byte(plainSessionTicket), state)
	if err != nil {
		return nil, err
	}

	return state, nil
}
