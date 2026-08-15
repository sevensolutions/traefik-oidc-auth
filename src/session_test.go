package src

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func TestSessionIdpTokenExpiration(t *testing.T) {
	config := &config.Config{
		Provider: &config.ProviderConfig{
			TokenRenewalThreshold: 0.5,
		},
		SessionCookie: &config.SessionCookieConfig{
			MaxAge: 0,
		},
	}

	logger := logging.CreateLogger(logging.LevelDebug)

	toa := &TraefikOidcAuth{
		logger: logger,
		Config: config,
	}

	now := time.Now()

	sessionState := &session.SessionState{
		RefreshedAt:    now.Add(-29 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon := checkIdpTokenExpiresSoon(toa, sessionState)

	if expiresSoon {
		t.Fail()
	}

	sessionState = &session.SessionState{
		RefreshedAt:    now.Add(-30 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon = checkIdpTokenExpiresSoon(toa, sessionState)

	if !expiresSoon {
		t.Fail()
	}
}

func TestGetSessionForRequest_WithoutSessionCookie(t *testing.T) {
	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			CookieNamePrefix: "TraefikOidcAuth",
			Provider:         &config.ProviderConfig{TokenValidation: "IdToken"},
		},
	}

	req := httptest.NewRequest("GET", "https://app.example.com/", nil)

	_, _, _, err := toa.getSessionForRequest(req)

	if err != errNoSessionCookie {
		t.Errorf("expected a missing session cookie to be reported as such, got %v", err)
	}
}

type emptySessionStorage struct{}

func (s *emptySessionStorage) StoreSession(logger *logging.Logger, cfg *config.Config, sessionId string, state *session.SessionState) (string, error) {
	return "ticket", nil
}

func (s *emptySessionStorage) TryGetSession(logger *logging.Logger, cfg *config.Config, sessionTicket string) (*session.SessionState, error) {
	return nil, nil
}

func TestGetSessionForRequest_WithoutStoredSession(t *testing.T) {
	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			CookieNamePrefix: "TraefikOidcAuth",
			Provider:         &config.ProviderConfig{TokenValidation: "IdToken"},
		},
		SessionStorage: &emptySessionStorage{},
	}

	req := httptest.NewRequest("GET", "https://app.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session", Value: "an-unknown-ticket"})

	sessionState, _, _, err := toa.getSessionForRequest(req)

	if err != errNoSession {
		t.Errorf("expected a ticket without a stored session to be reported as such, got %v", err)
	}

	if sessionState != nil {
		t.Errorf("expected no session, got %v", sessionState)
	}
}
