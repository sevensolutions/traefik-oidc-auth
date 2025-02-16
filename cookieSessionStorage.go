package traefik_oidc_auth

import "encoding/json"

type CookieSessionStorage struct {
}

func CreateCookieSessionStorage() *CookieSessionStorage {
	storage := new(CookieSessionStorage)
	return storage
}

func (storage *CookieSessionStorage) StoreSession(toa *TraefikOidcAuth, sessionId string, state *SessionState) (string, error) {
	stateJson, _ := json.Marshal(*state)

	encryptedSessionTicket, err := encrypt(string(stateJson), toa.Config.Secret)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to encrypt session state: %s", err.Error())
		return "", err
	}

	return encryptedSessionTicket, nil
}

func (storage *CookieSessionStorage) TryGetSession(toa *TraefikOidcAuth, sessionTicket string) (*SessionState, error) {
	plainSessionTicket, err := decrypt(sessionTicket, toa.Config.Secret)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to decrypt session ticket: %v", err.Error())
		return nil, err
	}

	state := &SessionState{}

	err = json.Unmarshal([]byte(plainSessionTicket), state)
	if err != nil {
		return nil, err
	}

	return state, nil
}
