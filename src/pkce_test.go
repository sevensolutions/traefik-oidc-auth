package src

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func newPkceTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()
	callback, err := url.Parse("https://app.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	return &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Secret:           "0123456789abcdef0123456789abcdef",
			CookieNamePrefix: "TraefikOidcAuth",
			Scopes:           []string{"openid"},
			Provider: &config.ProviderConfig{
				ClientId:    "test-client",
				UsePkceBool: true,
			},
		},
		CallbackURL: callback,
		DiscoveryDocument: &oidc.OidcDiscovery{
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "https://idp.example.com/token",
		},
	}
}

func decodeStateFromLocation(t *testing.T, secret, location string) *oidc.OidcState {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	st, err := oidc.DecodeState(u.Query().Get("state"), secret)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func s256Challenge(verifier string) string {
	sha2 := sha256.New()
	_, _ = io.WriteString(sha2, verifier)
	return base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))
}

func TestRedirectToProvider_PkcePutsVerifierInState(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d", rw.Code)
	}
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") && c.MaxAge >= 0 && c.Value != "" {
			t.Fatalf("unexpected CodeVerifier cookie %q value set", c.Name)
		}
	}

	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	st := decodeStateFromLocation(t, toa.Config.Secret, loc.String())
	if st.CodeVerifier == "" {
		t.Fatal("expected CodeVerifier in state")
	}
	if len(st.CodeVerifier) < 32 {
		t.Fatalf("verifier too short: %q", st.CodeVerifier)
	}
	challenge := loc.Query().Get("code_challenge")
	if challenge == "" {
		t.Fatal("missing code_challenge")
	}
	if got := s256Challenge(st.CodeVerifier); got != challenge {
		t.Fatalf("code_challenge mismatch: got %q want %q", challenge, got)
	}
	if loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected method %q", loc.Query().Get("code_challenge_method"))
	}
}

func TestRedirectToProvider_ParallelFlowsHaveDistinctVerifiers(t *testing.T) {
	toa := newPkceTestAuth(t)
	verifiers := map[string]struct{}{}
	for i := 0; i < 5; i++ {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://app.example.com/page", nil)
		toa.redirectToProvider(rw, req, "https://app.example.com/page", false)
		st := decodeStateFromLocation(t, toa.Config.Secret, rw.Header().Get("Location"))
		if _, dup := verifiers[st.CodeVerifier]; dup {
			t.Fatalf("duplicate verifier across parallel redirects")
		}
		verifiers[st.CodeVerifier] = struct{}{}
	}
}

func TestRedirectToProvider_ClearsLegacyCodeVerifierCookies(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier", Value: "old"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier.abc", Value: "old2"})

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	expired := map[string]bool{}
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") && c.MaxAge < 0 {
			expired[c.Name] = true
		}
	}
	if !expired["TraefikOidcAuth.CodeVerifier"] || !expired["TraefikOidcAuth.CodeVerifier.abc"] {
		t.Fatalf("expected legacy CodeVerifier cookies expired, got %#v", expired)
	}
}

func TestRedirectToProvider_NoLegacyClearWhenPkceDisabled(t *testing.T) {
	toa := newPkceTestAuth(t)
	toa.Config.Provider.UsePkceBool = false
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier", Value: "old"})

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") {
			t.Fatalf("PKCE disabled must not clear CodeVerifier cookies, got %q", c.Name)
		}
	}
}

type memSessionStorage struct{}

func (m *memSessionStorage) StoreSession(logger *logging.Logger, cfg *config.Config, sessionId string, state *session.SessionState) (string, error) {
	return "ticket", nil
}

func (m *memSessionStorage) TryGetSession(logger *logging.Logger, cfg *config.Config, sessionTicket string) (*session.SessionState, error) {
	return nil, nil
}

func (m *memSessionStorage) ClearSession(logger *logging.Logger, cfg *config.Config, sessionId string) error {
	return nil
}

func newCallbackTestAuth(t *testing.T, usePkce bool, tokenURL, introspectURL string) *TraefikOidcAuth {
	t.Helper()
	toa := newPkceTestAuth(t)
	toa.Config.Provider.UsePkceBool = usePkce
	toa.Config.Provider.TokenValidation = "Introspection"
	toa.Config.Authorization = &config.AuthorizationConfig{}
	toa.Config.SessionCookie = &config.SessionCookieConfig{
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: "lax",
	}
	toa.Config.PostLoginRedirectUri = "/"
	toa.SessionStorage = &memSessionStorage{}
	toa.httpClient = http.DefaultClient
	toa.DiscoveryDocument.TokenEndpoint = tokenURL
	toa.DiscoveryDocument.IntrospectionEndpoint = introspectURL
	return toa
}

func TestHandleCallback_ClearsLegacyCookiesOnlyWhenPkceEnabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(&oidc.OidcTokenResponse{
			AccessToken: "access-token",
			IdToken:     "id-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true,
			"sub":    "user-1",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cases := []struct {
		name       string
		usePkce    bool
		wantClears bool
	}{
		{name: "pkce_off", usePkce: false, wantClears: false},
		{name: "pkce_on", usePkce: true, wantClears: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newCallbackTestAuth(t, tc.usePkce, server.URL+"/token", server.URL+"/introspect")

			state := &oidc.OidcState{
				Action:      "Login",
				RedirectUrl: "https://app.example.com/",
			}
			if tc.usePkce {
				state.CodeVerifier = "pkce-verifier-value-for-callback-test-01234567"
			}
			stateB64, err := oidc.EncodeState(state, toa.Config.Secret)
			if err != nil {
				t.Fatal(err)
			}

			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "https://app.example.com/oidc/callback?code=abc&state="+url.QueryEscape(stateB64), nil)
			req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier", Value: "legacy"})

			toa.handleCallback(rw, req)

			if rw.Code >= 400 {
				t.Fatalf("callback status=%d body=%s", rw.Code, rw.Body.String())
			}

			cleared := false
			for _, c := range rw.Result().Cookies() {
				if strings.Contains(c.Name, "CodeVerifier") && c.MaxAge < 0 {
					cleared = true
					break
				}
			}
			if cleared != tc.wantClears {
				t.Fatalf("cleared=%v wantClears=%v cookies=%v", cleared, tc.wantClears, rw.Result().Cookies())
			}
		})
	}
}

func TestRedirectToProvider_StateSizeReasonable(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)
	longRedirect := "https://app.example.com/" + strings.Repeat("a", 2000)
	toa.redirectToProvider(rw, req, longRedirect, false)

	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	if len(state) > 4500 {
		t.Fatalf("state too large: %d bytes", len(state))
	}
}

func TestExchangeAuthCode_UsesStateVerifier(t *testing.T) {
	const wantVerifier = "pkce-verifier-value-for-test-0123456789abcdef"
	posted := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			http.Error(w, err.Error(), 500)
			return
		}
		posted <- r.Form.Get("code_verifier")
		_ = json.NewEncoder(w).Encode(&oidc.OidcTokenResponse{
			AccessToken: "access",
			IdToken:     "id",
			TokenType:   "Bearer",
		})
	}))
	defer server.Close()

	toa := newPkceTestAuth(t)
	toa.httpClient = server.Client()
	toa.DiscoveryDocument.TokenEndpoint = server.URL

	req := httptest.NewRequest("GET", "https://app.example.com/oidc/callback", nil)
	// Cookie present must be ignored — verifier comes from state.
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier", Value: "wrong"})

	_, err := exchangeAuthCode(toa, req, "auth-code", wantVerifier)
	if err != nil {
		t.Fatalf("exchangeAuthCode: %v", err)
	}
	got := <-posted
	if got != wantVerifier {
		t.Fatalf("code_verifier=%q want %q", got, wantVerifier)
	}
}

func TestExchangeAuthCode_MissingVerifierFailsBeforePost(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	toa := newPkceTestAuth(t)
	toa.httpClient = server.Client()
	toa.DiscoveryDocument.TokenEndpoint = server.URL

	req := httptest.NewRequest("GET", "https://app.example.com/oidc/callback", nil)
	_, err := exchangeAuthCode(toa, req, "auth-code", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Fatal("token endpoint must not be called without verifier")
	}
}

func TestDoubleRedirect_DoesNotSetPkceCookieOrChallenge(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)

	toa.doubleRedirectToProvider(rw, req, "https://app.example.com/page", false)

	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d", rw.Code)
	}
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") && c.Value != "" && c.MaxAge >= 0 {
			t.Fatalf("double redirect must not set PKCE cookie: %q", c.Name)
		}
	}
	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("code_challenge") != "" {
		t.Fatal("double redirect must not send code_challenge to IdP")
	}
	st, err := oidc.DecodeState(loc.Query().Get("state"), toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if st.Action != "RedirectThenLogin" {
		t.Fatalf("action=%q", st.Action)
	}
	if st.CodeVerifier != "" {
		t.Fatal("verifier must be created only on IdP redirect hop")
	}
}
