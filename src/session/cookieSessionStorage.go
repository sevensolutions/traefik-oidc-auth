package session

import "encoding/json"

type CookieSessionStorage struct {
}

func CreateCookieSessionStorage() *CookieSessionStorage {
	storage := new(CookieSessionStorage)
	return storage
}

func (storage *CookieSessionStorage) StoreSession(sessionId string, state *SessionState) (string, error) {
	stateJson, _ := json.Marshal(*state)

	return string(stateJson), nil
}

func (storage *CookieSessionStorage) TryGetSession(sessionTicket string) (*SessionState, error) {
	state := &SessionState{}

	err := json.Unmarshal([]byte(sessionTicket), state)
	if err != nil {
		return nil, err
	}

	return state, nil
}
