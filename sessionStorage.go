package traefik_oidc_auth

import (
	"github.com/google/uuid"
)

type SessionStorage interface {
	StoreSession(sessionId string, state SessionState) (string, error)
	TryGetSession(sessionTicket string) (*SessionState, error)
}

type SessionState struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

func GenerateSessionId() string {
	id := uuid.New()
	return id.String()
}
