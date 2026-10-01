package src

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/errorPages"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
)

func newCallbackErrorTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()
	toa := newPkceTestAuth(t)
	toa.Config.ErrorPages = &errorPages.ErrorPagesConfig{
		Unauthenticated: &errorPages.ErrorPageConfig{},
		Unauthorized:    &errorPages.ErrorPageConfig{},
	}
	return toa
}

func callbackWithError(t *testing.T, toa *TraefikOidcAuth, state *oidc.OidcState, query string) *httptest.ResponseRecorder {
	t.Helper()
	stateB64, err := oidc.EncodeState(state, toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/oidc/callback?"+query+"&state="+url.QueryEscape(stateB64), nil)
	toa.handleCallback(rw, req)
	return rw
}

func TestHandleCallback_AuthenticationExpiredRestartsLogin(t *testing.T) {
	for _, isChallenge := range []bool{false, true} {
		toa := newCallbackErrorTestAuth(t)
		state := &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/page", IsChallenge: isChallenge}

		rw := callbackWithError(t, toa, state, "error=temporarily_unavailable&error_description=authentication_expired")

		if rw.Code != http.StatusFound {
			t.Fatalf("isChallenge=%v: status=%d, want %d", isChallenge, rw.Code, http.StatusFound)
		}
		location := rw.Header().Get("Location")
		if !strings.HasPrefix(location, toa.DiscoveryDocument.AuthorizationEndpoint+"?") {
			t.Fatalf("isChallenge=%v: Location=%q, want a redirect to the authorization endpoint", isChallenge, location)
		}
		newState := decodeStateFromLocation(t, toa.Config.Secret, location)
		if !newState.Retried {
			t.Errorf("isChallenge=%v: Retried=false, want true", isChallenge)
		}
		if newState.RedirectUrl != state.RedirectUrl {
			t.Errorf("isChallenge=%v: RedirectUrl=%q, want %q", isChallenge, newState.RedirectUrl, state.RedirectUrl)
		}
		if newState.IsChallenge != isChallenge {
			t.Errorf("IsChallenge=%v, want %v", newState.IsChallenge, isChallenge)
		}
		if newState.CodeVerifier == "" {
			t.Errorf("isChallenge=%v: expected a fresh PKCE verifier in the new state", isChallenge)
		}
	}
}

func TestHandleCallback_AuthenticationExpiredIsRetriedOnlyOnce(t *testing.T) {
	toa := newCallbackErrorTestAuth(t)
	state := &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/page", Retried: true}

	rw := callbackWithError(t, toa, state, "error=temporarily_unavailable&error_description=authentication_expired")

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rw.Code, http.StatusUnauthorized)
	}
	if location := rw.Header().Get("Location"); location != "" {
		t.Fatalf("Location=%q, want no redirect", location)
	}
}

func TestHandleCallback_IdpErrorsDoNotReturn500(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  int
	}{
		{name: "access_denied", query: "error=access_denied", want: http.StatusForbidden},
		{name: "server_error", query: "error=server_error&error_description=boom", want: http.StatusUnauthorized},
		{name: "temporarily_unavailable_other_reason", query: "error=temporarily_unavailable&error_description=maintenance", want: http.StatusUnauthorized},
		{name: "login_required", query: "error=login_required", want: http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newCallbackErrorTestAuth(t)
			state := &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/page"}

			rw := callbackWithError(t, toa, state, tc.query)

			if rw.Code != tc.want {
				t.Fatalf("status=%d, want %d (body=%s)", rw.Code, tc.want, rw.Body.String())
			}
		})
	}
}

func TestHandleCallback_MissingCodeWithoutErrorStillFails(t *testing.T) {
	toa := newCallbackErrorTestAuth(t)
	state := &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/page"}

	rw := callbackWithError(t, toa, state, "foo=bar")

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want %d", rw.Code, http.StatusInternalServerError)
	}
}

func TestRedirectToProvider_DoesNotMarkStateAsRetried(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	state := decodeStateFromLocation(t, toa.Config.Secret, rw.Header().Get("Location"))
	if state.Retried {
		t.Fatal("Retried=true for a regular login, want false")
	}
}
