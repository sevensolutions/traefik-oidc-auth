package src

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
)

var testBrowserBinding = strings.Repeat("ab", browserBindingBytes)

func findCookie(rw *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rw.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestRedirectToProvider_BindsStateToNewCookie(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	cookie := findCookie(rw, "TraefikOidcAuth.BrowserBinding")
	if cookie == nil {
		t.Fatal("expected a browser binding cookie")
	}
	if !isWellFormedBrowserBinding(cookie.Value) {
		t.Fatalf("unexpected cookie value %q", cookie.Value)
	}
	if state := decodeStateFromLocation(t, toa.Config.Secret, rw.Header().Get("Location")); state.BrowserBinding != cookie.Value {
		t.Fatalf("state binding=%q, cookie=%q", state.BrowserBinding, cookie.Value)
	}
	if strings.Contains(rw.Header().Get("Location"), cookie.Value) {
		t.Fatal("the binding must not be readable from the authorization URL")
	}
}

func TestRedirectToProvider_ReusesCookieForParallelLogins(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.BrowserBinding", Value: testBrowserBinding})

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	if cookie := findCookie(rw, "TraefikOidcAuth.BrowserBinding"); cookie == nil || cookie.Value != testBrowserBinding || cookie.MaxAge != browserBindingMaxAge {
		t.Fatalf("expected the cookie to be reused and refreshed, got %+v", cookie)
	}
	if state := decodeStateFromLocation(t, toa.Config.Secret, rw.Header().Get("Location")); state.BrowserBinding != testBrowserBinding {
		t.Fatalf("state binding=%q", state.BrowserBinding)
	}
}

func TestRedirectToProvider_ReplacesMalformedCookie(t *testing.T) {
	for _, value := range []string{"short", strings.Repeat("z", browserBindingBytes*2)} {
		toa := newPkceTestAuth(t)
		rw := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://app.example.com/page", nil)
		req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.BrowserBinding", Value: value})

		toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

		if cookie := findCookie(rw, "TraefikOidcAuth.BrowserBinding"); cookie == nil || !isWellFormedBrowserBinding(cookie.Value) {
			t.Fatalf("value %q: expected a new cookie, got %+v", value, cookie)
		}
	}
}

func TestBrowserBindingCookieAttributes(t *testing.T) {
	cases := []struct {
		sessionSameSite string
		want            http.SameSite
	}{
		{sessionSameSite: "default", want: http.SameSiteLaxMode},
		{sessionSameSite: "lax", want: http.SameSiteLaxMode},
		// Strict would keep the cookie from being sent on the redirect back from the identity provider.
		{sessionSameSite: "strict", want: http.SameSiteLaxMode},
		{sessionSameSite: "none", want: http.SameSiteNoneMode},
	}

	for _, tc := range cases {
		t.Run(tc.sessionSameSite, func(t *testing.T) {
			toa := newPkceTestAuth(t)
			toa.Config.SessionCookie.SameSite = tc.sessionSameSite
			toa.Config.SessionCookie.Path = "/app"
			toa.Config.SessionCookie.Domain = "example.com"
			toa.Config.SessionCookie.HttpOnly = false
			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "https://app.example.com/page", nil)

			toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

			cookie := findCookie(rw, "TraefikOidcAuth.BrowserBinding")
			if cookie == nil {
				t.Fatal("expected a browser binding cookie")
			}
			if cookie.SameSite != tc.want {
				t.Errorf("SameSite=%v, want %v", cookie.SameSite, tc.want)
			}
			if cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.MaxAge != browserBindingMaxAge {
				t.Errorf("unexpected attributes: %+v", cookie)
			}
		})
	}
}

func TestHandleCallback_UnboundLogins(t *testing.T) {
	const otherBinding = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

	cases := []struct {
		name         string
		stateBinding string
		cookie       string
	}{
		{name: "missing_cookie", stateBinding: testBrowserBinding},
		{name: "mismatching_cookie", stateBinding: testBrowserBinding, cookie: otherBinding},
		{name: "state_without_binding", cookie: testBrowserBinding},
		{name: "state_without_binding_and_no_cookie"},
	}

	for _, tc := range cases {
		for _, retried := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/retried=%v", tc.name, retried), func(t *testing.T) {
				tokenEndpointCalled := false
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					tokenEndpointCalled = true
					_ = json.NewEncoder(w).Encode(&oidc.OidcTokenResponse{AccessToken: "access", IdToken: "id"})
				}))
				defer server.Close()

				toa := newCallbackTestAuth(t, false, server.URL, server.URL)

				state := &oidc.OidcState{
					Action:         "Login",
					RedirectUrl:    "https://app.example.com/page",
					BrowserBinding: tc.stateBinding,
					IsChallenge:    true,
					Retried:        retried,
				}
				stateB64, err := oidc.EncodeState(state, toa.Config.Secret)
				if err != nil {
					t.Fatal(err)
				}

				rw := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "https://app.example.com/oidc/callback?code=abc&state="+url.QueryEscape(stateB64), nil)
				if tc.cookie != "" {
					req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.BrowserBinding", Value: tc.cookie})
				}

				toa.handleCallback(rw, req)

				if tokenEndpointCalled {
					t.Error("the code must not be exchanged")
				}
				if cookie := findCookie(rw, "TraefikOidcAuth.Session"); cookie != nil {
					t.Errorf("no session must be created, got %+v", cookie)
				}

				if retried {
					// Already restarted once, so stop here instead of looping.
					if rw.Code != http.StatusBadRequest {
						t.Fatalf("status=%d, want %d", rw.Code, http.StatusBadRequest)
					}
					if body := strings.TrimSpace(rw.Body.String()); body != "Bad Request" {
						t.Errorf("body=%q", body)
					}
					return
				}

				if rw.Code != http.StatusFound {
					t.Fatalf("status=%d, want %d", rw.Code, http.StatusFound)
				}
				location := rw.Header().Get("Location")
				if !strings.HasPrefix(location, toa.DiscoveryDocument.AuthorizationEndpoint+"?") {
					t.Fatalf("Location=%q, want a redirect to the authorization endpoint", location)
				}

				newState := decodeStateFromLocation(t, toa.Config.Secret, location)
				if !newState.Retried {
					t.Error("Retried=false, want true")
				}
				if newState.RedirectUrl != state.RedirectUrl || newState.IsChallenge != state.IsChallenge {
					t.Errorf("RedirectUrl=%q IsChallenge=%v, want %q %v", newState.RedirectUrl, newState.IsChallenge, state.RedirectUrl, state.IsChallenge)
				}

				// The new login is bound to this browser: the existing cookie is reused if it's well-formed.
				cookie := findCookie(rw, "TraefikOidcAuth.BrowserBinding")
				if cookie == nil || cookie.Value != newState.BrowserBinding {
					t.Fatalf("expected the restarted login to be bound, cookie=%+v state=%q", cookie, newState.BrowserBinding)
				}
				if tc.cookie != "" && cookie.Value != tc.cookie {
					t.Errorf("cookie=%q, want the existing value %q to be reused", cookie.Value, tc.cookie)
				}
			})
		}
	}
}

func TestHandleCallback_BadStateIsBadRequest(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{name: "missing", query: "code=abc"},
		{name: "not_base64", query: "code=abc&state=%21%21%21"},
		{name: "not_encrypted", query: "code=abc&state=e30"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newPkceTestAuth(t)
			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "https://app.example.com/oidc/callback?"+tc.query, nil)

			toa.handleCallback(rw, req)

			if rw.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want %d", rw.Code, http.StatusBadRequest)
			}
			if body := strings.TrimSpace(rw.Body.String()); body != "Bad Request" {
				t.Errorf("body=%q", body)
			}
		})
	}
}

func TestHandleCallback_IdpErrorDoesNotRequireBinding(t *testing.T) {
	toa := newCallbackErrorTestAuth(t)
	state := &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/page", BrowserBinding: testBrowserBinding}

	// No cookie, e.g. because the login form was left open for longer than the cookie lives.
	rw := callbackWithError(t, toa, state, "error=temporarily_unavailable&error_description=authentication_expired")

	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d, want %d", rw.Code, http.StatusFound)
	}
	newState := decodeStateFromLocation(t, toa.Config.Secret, rw.Header().Get("Location"))
	cookie := findCookie(rw, "TraefikOidcAuth.BrowserBinding")
	if cookie == nil || cookie.Value != newState.BrowserBinding {
		t.Fatalf("expected the restarted login to be bound, cookie=%+v state=%q", cookie, newState.BrowserBinding)
	}
}

func TestNeedsDoubleRedirect(t *testing.T) {
	cases := []struct {
		name       string
		callback   string
		requestUrl string
		usePkce    bool
		wantDouble bool
	}{
		{name: "relative_callback", callback: "/oidc/callback", requestUrl: "https://app.example.com/page"},
		{name: "same_host", callback: "https://app.example.com/oidc/callback", requestUrl: "https://app.example.com/page"},
		{name: "other_host_pkce", callback: "https://auth.example.com/oidc/callback", requestUrl: "https://app.example.com/page", usePkce: true, wantDouble: true},
		{name: "other_host_no_pkce", callback: "https://auth.example.com/oidc/callback", requestUrl: "https://app.example.com/page", wantDouble: true},
		{name: "other_port", callback: "https://app.example.com:8443/oidc/callback", requestUrl: "https://app.example.com/page", wantDouble: true},
		{name: "host_is_prefix_of_callback_host", callback: "https://app.example.com.evil.test/oidc/callback", requestUrl: "https://app.example.com/page", wantDouble: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newPkceTestAuth(t)
			toa.Config.Provider.UsePkceBool = tc.usePkce

			callback, err := url.Parse(tc.callback)
			if err != nil {
				t.Fatal(err)
			}
			toa.CallbackURL = callback

			req := httptest.NewRequest("GET", tc.requestUrl, nil)
			req.Header.Set("X-Forwarded-Proto", "https")

			if got := toa.needsDoubleRedirect(req); got != tc.wantDouble {
				t.Fatalf("needsDoubleRedirect=%v, want %v", got, tc.wantDouble)
			}
		})
	}
}
