package session

import (
	"time"

	"github.com/google/uuid"
	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

type SessionStorage interface {
	StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error)
	TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error)
}

type SessionState struct {
	Id             string    `json:"id"`
	RefreshedAt    time.Time `json:"created_at"`
	AccessToken    string    `json:"access_token"`
	IdToken        string    `json:"id_token"`
	RefreshToken   string    `json:"refresh_token"`
	IsAuthorized   bool      `json:"is_authorized"`
	TokenExpiresIn int       `json:"token_expires_in"`

	// Set when this session was (re-)established via a redirect triggered by UnauthorizedBehavior's
	// Challenge, regardless of whether the resulting session ends up authorized - the callback may be
	// handled by a different, more permissive middleware instance than the one that failed the check.
	// Used to avoid redirecting to the IDP again for the same session, which would otherwise risk an
	// infinite redirect loop.
	ChallengeAttempted bool `json:"challenge_attempted"`
}

func GenerateSessionId() string {
	id := uuid.New()
	return id.String()
}
