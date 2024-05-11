package traefik_oidc_auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TraefikOidcAuth struct {
	next              http.Handler
	ProviderURL       *url.URL
	Config            *Config
	DiscoveryDocument *OidcDiscovery
}

func (toa *TraefikOidcAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if strings.HasPrefix(req.RequestURI, toa.Config.RedirectUri) {
		toa.handleCallback(rw, req)
		return
	}

	if toa.Config.LoginUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.LoginUri) {
		toa.redirectToProvider(rw, req)
		return
	}

	if strings.HasPrefix(req.RequestURI, toa.Config.LogoutUri) {
		toa.handleLogout(rw, req)
		return
	}

	cookie, err := req.Cookie(toa.Config.StateCookie.Name)

	if err == nil && strings.HasPrefix(cookie.Value, "Bearer ") {
		token := strings.Trim(strings.TrimPrefix(cookie.Value, "Bearer "), " ")

		var ok = false
		var usernameClaim string

		if token != "" {
			isValid, username, err := introspectToken(toa, token)
			if err != nil {
				log("ERROR", "Verifying token: %s", err.Error())
				toa.handleUnauthorized(rw, req)
				return
			}

			ok = isValid
			usernameClaim = username
		}

		if !ok {
			http.SetCookie(rw, &http.Cookie{
				Name:    toa.Config.StateCookie.Name,
				Value:   "",
				Path:    toa.Config.StateCookie.Path,
				Expires: time.Now().Add(-24 * time.Hour),
				MaxAge:  -1,
			})

			toa.handleUnauthorized(rw, req)
			return
		}

		if len(toa.Config.UsernameHeaderName) > 0 && len(usernameClaim) > 0 {
			req.Header.Set(toa.Config.UsernameHeaderName, usernameClaim)
		}

		// Forward the request
		toa.next.ServeHTTP(rw, req)
		return
	}

	toa.handleUnauthorized(rw, req)
}

func (toa *TraefikOidcAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	authCode := req.URL.Query().Get("code")
	if authCode == "" {
		log("WARN", "Code is missing, redirect to Provider")
		toa.redirectToProvider(rw, req)
		return
	}

	base64State := req.URL.Query().Get("state")
	if base64State == "" {
		log("WARN", "State is missing, redirect to Provider")
		toa.redirectToProvider(rw, req)
		return
	}

	state, err := base64DecodeState(base64State)
	if err != nil {
		log("WARN", "State is invalid, redirect to Provider")
		toa.redirectToProvider(rw, req)
		return
	}

	redirectUrl := state.RedirectUrl

	if state.Action == "Login" {
		token, err := exchangeAuthCode(toa, req, authCode, state)

		log("INFO", "Exchange Auth Code completed: %+v", token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			log("ERROR", "Exchange Auth Code: %s", err.Error())
			return
		}

		http.SetCookie(rw, &http.Cookie{
			Name:     toa.Config.StateCookie.Name,
			Value:    "Bearer " + token,
			Secure:   toa.Config.StateCookie.Secure,
			HttpOnly: toa.Config.StateCookie.HttpOnly,
			Path:     toa.Config.StateCookie.Path,
			SameSite: parseCookieSameSite(toa.Config.StateCookie.SameSite),
		})

		if toa.Config.PostLoginRedirectUri != "" {
			redirectUrl = ensureAbsoluteUrl(req, toa.Config.PostLoginRedirectUri)
		}
	} else if state.Action == "Logout" {
		// Clear the cookie
		http.SetCookie(rw, &http.Cookie{
			Name:    toa.Config.StateCookie.Name,
			Value:   "",
			Path:    toa.Config.StateCookie.Path,
			Expires: time.Now().Add(-24 * time.Hour),
			MaxAge:  -1,
		})
	}

	http.Redirect(rw, req, redirectUrl, http.StatusFound)
}

func (toa *TraefikOidcAuth) handleLogout(rw http.ResponseWriter, req *http.Request) {
	log("INFO", "Logging out...")

	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html

	endSessionURL, err := url.Parse(toa.DiscoveryDocument.EndSessionEndpoint)
	if err != nil {
		log("ERROR", "Error while parsing the AuthorizationEndpoint: %s", err.Error())
	}

	host := getFullHost(req)

	postLogoutUri := host + toa.Config.RedirectUri

	// TODO: Grab redirect uri from query-param, if any
	state := OidcState{
		Action:      "Logout",
		RedirectUrl: ensureAbsoluteUrl(req, toa.Config.PostLogoutRedirectUri),
	}

	base64State, err := state.base64Encode()
	if err != nil {
		log("ERROR", "Failed to serialize state: %s", err.Error())
	}

	endSessionURL.RawQuery = url.Values{
		"client_id":                {toa.Config.Provider.ClientID},
		"post_logout_redirect_uri": {postLogoutUri},
		"state":                    {base64State},
	}.Encode()

	// Clear the cookie
	http.SetCookie(rw, &http.Cookie{
		Name:    toa.Config.StateCookie.Name,
		Value:   "",
		Path:    toa.Config.StateCookie.Path,
		Expires: time.Now().Add(-24 * time.Hour),
		MaxAge:  -1,
	})

	http.Redirect(rw, req, endSessionURL.String(), http.StatusFound)
}

func (toa *TraefikOidcAuth) handleUnauthorized(rw http.ResponseWriter, req *http.Request) {
	if toa.Config.LoginUri == "" {
		toa.redirectToProvider(rw, req)
	} else {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
}

func (toa *TraefikOidcAuth) redirectToProvider(rw http.ResponseWriter, req *http.Request) {
	log("INFO", "Redirecting to OIDC provider...")

	host := getFullHost(req)

	// TODO: Grab redirect uri from query-param, if any
	originalUrl := fmt.Sprintf("%s%s", host, req.RequestURI)
	redirectUrl := host + toa.Config.RedirectUri

	state := OidcState{
		Action:      "Login",
		RedirectUrl: originalUrl,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	log("INFO", "AuthorizationEndPoint: %s", toa.DiscoveryDocument.AuthorizationEndpoint)

	redirectURL, err := url.Parse(toa.DiscoveryDocument.AuthorizationEndpoint)
	if err != nil {
		log("ERROR", "Error while parsing the AuthorizationEndpoint: %s", err.Error())
	}

	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"client_id":     {toa.Config.Provider.ClientID},
		"redirect_uri":  {redirectUrl},
		"state":         {stateBase64},
	}.Encode()

	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}
