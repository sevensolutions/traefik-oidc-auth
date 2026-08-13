package src

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
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

type fixedSessionStorage struct {
	state *session.SessionState
}

func (s *fixedSessionStorage) StoreSession(logger *logging.Logger, cfg *config.Config, sessionId string, state *session.SessionState) (string, error) {
	return "ticket", nil
}

func (s *fixedSessionStorage) TryGetSession(logger *logging.Logger, cfg *config.Config, sessionTicket string) (*session.SessionState, error) {
	return s.state, nil
}

func newRenewalTest(t *testing.T, tokenIsActive bool) *TraefikOidcAuth {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/introspect", func(rw http.ResponseWriter, req *http.Request) {
		json.NewEncoder(rw).Encode(map[string]interface{}{"active": tokenIsActive, "sub": "user-1"})
	})
	mux.HandleFunc("/token", func(rw http.ResponseWriter, req *http.Request) {
		http.Error(rw, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	state := &session.SessionState{
		Id:             "session-1",
		AccessToken:    "current-access-token",
		RefreshToken:   "current-refresh-token",
		RefreshedAt:    time.Now().Add(-50 * time.Second),
		TokenExpiresIn: 60,
	}

	toa := &TraefikOidcAuth{
		logger:     logging.CreateLogger(logging.LevelError),
		httpClient: server.Client(),
		Config: &config.Config{
			Provider: &config.ProviderConfig{
				TokenValidation:       "Introspection",
				TokenRenewalThreshold: 0.75,
			},
		},
		SessionStorage: &fixedSessionStorage{state: state},
		DiscoveryDocument: &oidc.OidcDiscovery{
			IntrospectionEndpoint: server.URL + "/introspect",
			TokenEndpoint:         server.URL + "/token",
		},
	}

	return toa
}

func TestValidateSessionTicket_KeepsValidSessionWhenRenewalFails(t *testing.T) {
	toa := newRenewalTest(t, true)

	sessionState, claims, updatedSession, err := validateSessionTicket(toa, "ticket")

	if err != nil {
		t.Fatalf("expected the still valid session to be kept, got %v", err)
	}

	if sessionState == nil || sessionState.AccessToken != "current-access-token" {
		t.Errorf("expected the current access token to be kept, got %v", sessionState)
	}

	if claims == nil {
		t.Error("expected the claims of the current token")
	}

	if updatedSession != nil {
		t.Error("expected no session update when nothing was renewed")
	}
}

func TestValidateSessionTicket_FailsWhenRenewalFailsForAnExpiredToken(t *testing.T) {
	toa := newRenewalTest(t, false)

	sessionState, _, _, err := validateSessionTicket(toa, "ticket")

	if err == nil {
		t.Fatal("expected an error when the token is no longer valid and cannot be renewed")
	}

	if sessionState != nil {
		t.Errorf("expected no session, got %v", sessionState)
	}
}

func TestValidateToken_MissingToken(t *testing.T) {
	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Provider: &config.ProviderConfig{TokenValidation: "IdToken"},
		},
	}

	ok, _, err := toa.validateToken(&session.SessionState{AccessToken: "only-an-access-token"})

	if ok {
		t.Fatal("expected a session without an id token to be rejected")
	}

	if err == nil || !strings.Contains(err.Error(), "id_token") {
		t.Errorf("expected the error to name the missing token, got %v", err)
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
