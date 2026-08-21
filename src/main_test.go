package src

import (
	"bytes"
	"encoding/json"
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

func TestTemplate_mapToJsonArray(t *testing.T) {
	evalContext := map[string]any{
		"claims": map[string]any{
			"roles": []any{"admin", "user", 123},
		},
	}

	template, err := newTemplate().Parse("{{ .claims.roles | withPrefix \"prefix:\" | withSuffix \":suffix\" | mapToJsonArray }}")
	if err != nil {
		t.Fatal(err)
	}
	var renderedValue bytes.Buffer
	err = template.Execute(&renderedValue, evalContext)
	if err != nil {
		t.Fatal(err)
	}

	var result []string
	err = json.Unmarshal(renderedValue.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 3 {
		t.Errorf("Expected 3 elements in the array, got %d", len(result))
	}

	if result[0] != "prefix:admin:suffix" {
		t.Errorf("Expected prefix:admin:suffix at index 0, got %s", result[0])
	}

	if result[1] != "prefix:user:suffix" {
		t.Errorf("Expected prefix:user:suffix at index 1, got %s", result[1])
	}

	if result[2] != "prefix:123:suffix" {
		t.Errorf("Expected prefix:123:suffix at index 2, got %s", result[2])
	}
}

func newLogoutTest(endSessionEndpoint string) *TraefikOidcAuth {
	callbackURL, _ := url.Parse("/oidc/callback")

	return &TraefikOidcAuth{
		logger:      logging.CreateLogger(logging.LevelError),
		CallbackURL: callbackURL,
		Config: &config.Config{
			Secret:                "0123456789abcdef0123456789abcdef",
			Provider:              &config.ProviderConfig{ClientId: "my-client"},
			CookieNamePrefix:      "TraefikOidcAuth",
			SessionCookie:         &config.SessionCookieConfig{Path: "/"},
			PostLogoutRedirectUri: "/",
		},
		DiscoveryDocument: &oidc.OidcDiscovery{EndSessionEndpoint: endSessionEndpoint},
	}
}

func TestHandleLogout_WithoutEndSessionEndpoint(t *testing.T) {
	toa := newLogoutTest("")

	req := httptest.NewRequest("GET", "https://app.example.com/logout", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.Chunks", Value: "2"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.1", Value: "some"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.2", Value: "ticket"})
	rw := httptest.NewRecorder()

	toa.handleLogout(rw, req, &session.SessionState{IdToken: "some-id-token"})

	location := rw.Header().Get("Location")

	if location != "https://app.example.com/" {
		t.Errorf("expected a redirect to the post logout redirect uri, got %q", location)
	}

	assertSessionCookiesCleared(t, rw)
}

func TestHandleLogout_WithEndSessionEndpoint(t *testing.T) {
	toa := newLogoutTest("https://idp.example.com/end-session")

	req := httptest.NewRequest("GET", "https://app.example.com/logout", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.Chunks", Value: "2"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.1", Value: "some"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.2", Value: "ticket"})
	rw := httptest.NewRecorder()

	toa.handleLogout(rw, req, &session.SessionState{IdToken: "some-id-token"})

	location, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	if location.Host != "idp.example.com" || location.Path != "/end-session" {
		t.Errorf("expected a redirect to the end session endpoint, got %q", location)
	}

	if got := location.Query().Get("id_token_hint"); got != "some-id-token" {
		t.Errorf("expected the id token to be sent as a hint, got %q", got)
	}

	assertSessionCookiesCleared(t, rw)
}

func TestHandleLogout_RejectsAnUnlistedRedirectUri(t *testing.T) {
	toa := newLogoutTest("https://idp.example.com/end-session")

	req := httptest.NewRequest("GET", "https://app.example.com/logout?redirect_uri=https://evil.example.com/", nil)
	rw := httptest.NewRecorder()

	toa.handleLogout(rw, req, &session.SessionState{IdToken: "some-id-token"})

	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected an unlisted redirect uri to be rejected, got status %d", rw.Code)
	}

	if location := rw.Header().Get("Location"); location != "" {
		t.Errorf("expected no redirect, got %q", location)
	}
}

func TestHandleLogout_AcceptsAListedRedirectUri(t *testing.T) {
	toa := newLogoutTest("")
	toa.Config.ValidPostLogoutRedirectUris = []string{"/bye"}

	req := httptest.NewRequest("GET", "https://app.example.com/logout?post_logout_redirect_uri=/bye", nil)
	rw := httptest.NewRecorder()

	toa.handleLogout(rw, req, &session.SessionState{IdToken: "some-id-token"})

	if got := rw.Header().Get("Location"); got != "https://app.example.com/bye" {
		t.Errorf("expected a redirect to the listed uri, got %q", got)
	}
}

func assertSessionCookiesCleared(t *testing.T, rw *httptest.ResponseRecorder) {
	t.Helper()

	cleared := make(map[string]bool)

	for _, raw := range rw.Header().Values("Set-Cookie") {
		name, _, _ := strings.Cut(strings.Split(raw, ";")[0], "=")

		lower := strings.ToLower(raw)
		if strings.Contains(lower, "max-age=0") || strings.Contains(lower, "max-age=-1") {
			cleared[name] = true
		}
	}

	for _, name := range []string{"TraefikOidcAuth.Session.Chunks", "TraefikOidcAuth.Session.1", "TraefikOidcAuth.Session.2"} {
		if !cleared[name] {
			t.Errorf("expected %s to be cleared, got %v", name, rw.Header().Values("Set-Cookie"))
		}
	}
}
