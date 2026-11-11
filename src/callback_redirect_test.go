package src

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
)

func newTokenTestServer(t *testing.T) *httptest.Server {
	t.Helper()
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
	t.Cleanup(server.Close)
	return server
}

// callbackWithState sends a callback request with the given state from a browser bound to it, unless the
// state is already bound to another browser.
func callbackWithState(t *testing.T, toa *TraefikOidcAuth, state *oidc.OidcState, query string, forwardedHost string) *httptest.ResponseRecorder {
	t.Helper()
	if state.BrowserBinding == "" {
		state.BrowserBinding = testBrowserBinding
	}
	stateB64, err := oidc.EncodeState(state, toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/oidc/callback?"+query+"&state="+url.QueryEscape(stateB64), nil)
	req.AddCookie(&http.Cookie{Name: getBrowserBindingCookieName(toa.Config), Value: testBrowserBinding})
	if forwardedHost != "" {
		req.Header.Set("X-Forwarded-Host", forwardedHost)
	}
	toa.handleCallback(rw, req)
	return rw
}

var externalRedirectUrls = []string{
	"https://evil.example.com/",
	"http://app.example.com/",
	"https://app.example.com.evil.example.com/",
	"https://app.example.com@evil.example.com/",
	"//evil.example.com/",
	"/\\evil.example.com/",
	"/\t/evil.example.com/",
	"javascript:alert(1)",
}

func TestHandleCallback_LoginIgnoresExternalRedirectUrl(t *testing.T) {
	server := newTokenTestServer(t)

	for _, redirectUrl := range externalRedirectUrls {
		t.Run(redirectUrl, func(t *testing.T) {
			toa := newCallbackTestAuth(t, false, server.URL+"/token", server.URL+"/introspect")
			state := &oidc.OidcState{Action: "Login", RedirectUrl: redirectUrl}

			rw := callbackWithState(t, toa, state, "code=abc", "")

			if rw.Code != http.StatusFound {
				t.Fatalf("status=%d, want %d (body=%s)", rw.Code, http.StatusFound, rw.Body.String())
			}
			if location := rw.Header().Get("Location"); location != "https://app.example.com/" {
				t.Fatalf("Location=%q, want the post login redirect uri", location)
			}
		})
	}
}

func TestHandleCallback_LoginFollowsSameOriginRedirectUrl(t *testing.T) {
	server := newTokenTestServer(t)

	cases := []struct {
		redirectUrl   string
		forwardedHost string
		want          string
	}{
		{redirectUrl: "https://app.example.com/page?a=1", want: "https://app.example.com/page?a=1"},
		{redirectUrl: "https://APP.example.com/page", want: "https://APP.example.com/page"},
		{redirectUrl: "/page", want: "https://app.example.com/page"},
		// Behind a reverse proxy that sets X-Forwarded-Host on both the login and the callback request.
		{redirectUrl: "https://public.example.com/page", forwardedHost: "public.example.com", want: "https://public.example.com/page"},
	}

	for _, tc := range cases {
		t.Run(tc.redirectUrl, func(t *testing.T) {
			toa := newCallbackTestAuth(t, false, server.URL+"/token", server.URL+"/introspect")
			state := &oidc.OidcState{Action: "Login", RedirectUrl: tc.redirectUrl}

			rw := callbackWithState(t, toa, state, "code=abc", tc.forwardedHost)

			if location := rw.Header().Get("Location"); location != tc.want {
				t.Fatalf("status=%d Location=%q, want %q", rw.Code, location, tc.want)
			}
		})
	}
}

func TestHandleCallback_LoginFollowsValidPostLoginRedirectUri(t *testing.T) {
	server := newTokenTestServer(t)
	toa := newCallbackTestAuth(t, false, server.URL+"/token", server.URL+"/introspect")
	toa.Config.ValidPostLoginRedirectUris = []string{"https://other.example.com/app"}
	state := &oidc.OidcState{Action: "Login", RedirectUrl: "https://other.example.com/app"}

	rw := callbackWithState(t, toa, state, "code=abc", "")

	if location := rw.Header().Get("Location"); location != "https://other.example.com/app" {
		t.Fatalf("Location=%q, want the valid post login redirect uri", location)
	}
}

func TestHandleCallback_LogoutIgnoresExternalRedirectUrl(t *testing.T) {
	for _, redirectUrl := range externalRedirectUrls {
		t.Run(redirectUrl, func(t *testing.T) {
			toa := newCallbackTestAuth(t, false, "", "")
			toa.Config.PostLogoutRedirectUri = "/bye"
			state := &oidc.OidcState{Action: "Logout", RedirectUrl: redirectUrl}

			rw := callbackWithState(t, toa, state, "", "")

			if location := rw.Header().Get("Location"); location != "https://app.example.com/bye" {
				t.Fatalf("status=%d Location=%q, want the post logout redirect uri", rw.Code, location)
			}
		})
	}
}

func TestHandleCallback_LogoutFollowsConfiguredRedirectUris(t *testing.T) {
	cases := []struct {
		name        string
		redirectUrl string
		configure   func(toa *TraefikOidcAuth)
	}{
		{name: "same_origin", redirectUrl: "https://app.example.com/bye", configure: func(toa *TraefikOidcAuth) {}},
		{name: "post_logout_redirect_uri", redirectUrl: "https://www.example.org/bye", configure: func(toa *TraefikOidcAuth) {
			toa.Config.PostLogoutRedirectUri = "https://www.example.org/bye"
		}},
		{name: "valid_post_logout_redirect_uris", redirectUrl: "https://www.example.org/signed-out", configure: func(toa *TraefikOidcAuth) {
			toa.Config.ValidPostLogoutRedirectUris = []string{"https://www.example.org/signed-out"}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newCallbackTestAuth(t, false, "", "")
			tc.configure(toa)
			state := &oidc.OidcState{Action: "Logout", RedirectUrl: tc.redirectUrl}

			rw := callbackWithState(t, toa, state, "", "")

			if location := rw.Header().Get("Location"); location != tc.redirectUrl {
				t.Fatalf("status=%d Location=%q, want %q", rw.Code, location, tc.redirectUrl)
			}
		})
	}
}

func TestHandleCallback_RetryAndRedirectThenLoginDropExternalRedirectUrl(t *testing.T) {
	cases := []struct {
		name  string
		state *oidc.OidcState
		query string
	}{
		{name: "authentication_expired", state: &oidc.OidcState{Action: "Login", RedirectUrl: "https://evil.example.com/"}, query: "error=temporarily_unavailable&error_description=authentication_expired"},
		{name: "redirect_then_login", state: &oidc.OidcState{Action: "RedirectThenLogin", RedirectUrl: "https://evil.example.com/"}, query: ""},
		{name: "browser_binding_mismatch", state: &oidc.OidcState{Action: "Login", RedirectUrl: "https://evil.example.com/", BrowserBinding: strings.Repeat("cd", browserBindingBytes)}, query: "code=abc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newCallbackErrorTestAuth(t)

			rw := callbackWithState(t, toa, tc.state, tc.query, "")

			newState := decodeStateFromLocation(t, toa.Config.Secret, rw.Header().Get("Location"))
			if newState.RedirectUrl != "" {
				t.Fatalf("RedirectUrl=%q in the new state, want it dropped", newState.RedirectUrl)
			}
		})
	}
}

// The attack: a state issued for a login request with a spoofed X-Forwarded-Host, then opened by a victim
// whose own callback request carries no such header. The restart re-binds the state to the victim's browser,
// so the browser binding alone doesn't stop it.
func TestHandleCallback_StateIssuedForSpoofedForwardedHostDoesNotRedirectThere(t *testing.T) {
	toa := newCallbackErrorTestAuth(t)
	callbackUrl, err := url.Parse("/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callbackUrl

	loginRw := httptest.NewRecorder()
	loginReq := httptest.NewRequest("GET", "https://app.example.com/page", nil)
	loginReq.RequestURI = "/page" // as on a real server, not the absolute url httptest puts there
	loginReq.Header.Set("X-Forwarded-Host", "evil.example.com")
	toa.handleLogin(loginRw, loginReq, false, "")

	issued := decodeStateFromLocation(t, toa.Config.Secret, loginRw.Header().Get("Location"))
	if issued.RedirectUrl != "https://evil.example.com/page" {
		t.Fatalf("precondition: RedirectUrl=%q in the issued state", issued.RedirectUrl)
	}

	rw := callbackWithState(t, toa, issued, "error=temporarily_unavailable&error_description=authentication_expired", "")

	newState := decodeStateFromLocation(t, toa.Config.Secret, rw.Header().Get("Location"))
	if newState.BrowserBinding != testBrowserBinding {
		t.Fatalf("precondition: BrowserBinding=%q in the new state, want the victim's", newState.BrowserBinding)
	}
	if newState.RedirectUrl != "" {
		t.Fatalf("RedirectUrl=%q in the new state, want it dropped", newState.RedirectUrl)
	}
}
