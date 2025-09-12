package src

import (
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func TestSessionExpiration(t *testing.T) {
	config := &Config{
		Provider: &ProviderConfig{
			TokenRenewalThreshold: 0.5,
		},
		SessionCookie: &SessionCookieConfig{
			MaxAge:            10, // seconds
			SlidingExpiration: true,
		},
	}

	logger := logging.CreateLogger(logging.LevelDebug)

	toa := &TraefikOidcAuth{
		logger: logger,
		Config: config,
	}

	now := time.Now()

	sessionState := &session.SessionState{
		RefreshedAt:    now,
		TokenExpiresIn: 60,
		ExpiresAt:      now.Add(6 * time.Second),
	}

	expiresSoon := checkSessionExpiresSoon(toa, sessionState)

	if expiresSoon {
		t.Fail()
	}

	sessionState = &session.SessionState{
		RefreshedAt:    now,
		TokenExpiresIn: 60,
		ExpiresAt:      now.Add(5 * time.Second),
	}

	expiresSoon = checkSessionExpiresSoon(toa, sessionState)

	if !expiresSoon {
		t.Fail()
	}
}

func TestSessionIdpTokenExpiration(t *testing.T) {
	config := &Config{
		Provider: &ProviderConfig{
			TokenRenewalThreshold: 0.5,
		},
		SessionCookie: &SessionCookieConfig{
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
