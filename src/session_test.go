package src

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// Duplicated from oidc_test.go in #300 so this branch stands alone. Drop it once #300 merges.
func signTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-kid"

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	return signedToken
}

func newLocalValidationRenewalTest(t *testing.T, renewalStatusCode int) (*TraefikOidcAuth, *session.SessionState, *int) {
	t.Helper()

	privateKey, err := generateRSAKey()
	if err != nil {
		t.Fatal(err)
	}

	renewalAttempts := 0

	tokenServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		renewalAttempts++
		http.Error(rw, `{"error":"invalid_grant"}`, renewalStatusCode)
	}))
	t.Cleanup(tokenServer.Close)

	state := &session.SessionState{
		Id:             "session-1",
		AccessToken:    signTestToken(t, privateKey, jwt.MapClaims{"sub": "user-1", "exp": time.Now().Add(10 * time.Minute).Unix()}),
		RefreshToken:   "current-refresh-token",
		RefreshedAt:    time.Now().Add(-50 * time.Second),
		TokenExpiresIn: 60,
	}

	toa := &TraefikOidcAuth{
		logger:     logging.CreateLogger(logging.LevelError),
		httpClient: http.DefaultClient,
		Config: &config.Config{
			Provider: &config.ProviderConfig{
				TokenValidation:       "AccessToken",
				TokenRenewalThreshold: 0.75,
			},
		},
		SessionStorage:    &fixedSessionStorage{state: state},
		Jwks:              &oidc.JwksHandler{},
		DiscoveryDocument: &oidc.OidcDiscovery{TokenEndpoint: tokenServer.URL},
	}

	jwksServer := setupJWKS(t, toa, privateKey)
	t.Cleanup(jwksServer.Close)

	return toa, state, &renewalAttempts
}

func TestValidateSessionTicket_KeepsSessionWhenRenewalFailsTemporarily(t *testing.T) {
	toa, _, renewalAttempts := newLocalValidationRenewalTest(t, http.StatusInternalServerError)

	sessionState, _, updatedSession, err := validateSessionTicket(toa, "ticket")

	if err != nil {
		t.Fatalf("expected a temporary renewal failure to keep the session, got %v", err)
	}

	if sessionState == nil {
		t.Fatal("expected the current session to be kept")
	}

	if updatedSession == nil || updatedSession.RenewalFailedAt.IsZero() {
		t.Error("expected the failed renewal to be recorded on the session")
	}

	if *renewalAttempts != 1 {
		t.Errorf("expected one renewal attempt, got %d", *renewalAttempts)
	}

	if _, _, _, err := validateSessionTicket(toa, "ticket"); err != nil {
		t.Fatalf("expected the session to still be usable, got %v", err)
	}

	if *renewalAttempts != 1 {
		t.Errorf("expected the renewal not to be retried on the next request, got %d attempts", *renewalAttempts)
	}
}

func TestValidateSessionTicket_DropsSessionWhenRefreshTokenIsRejected(t *testing.T) {
	toa, _, _ := newLocalValidationRenewalTest(t, http.StatusBadRequest)

	sessionState, _, _, err := validateSessionTicket(toa, "ticket")

	if err == nil {
		t.Fatal("expected a rejected refresh token to end the session")
	}

	if sessionState != nil {
		t.Errorf("expected no session, got %v", sessionState)
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
