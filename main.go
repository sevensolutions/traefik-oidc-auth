package traefik_oidc_auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type TraefikOidcAuth struct {
	next              http.Handler
	ProviderURL       *url.URL
	Config            *Config
	DiscoveryDocument *OidcDiscovery
	Jwks              *JwksHandler
	Lock              sync.RWMutex
}

// Make sure we fetch oidc discovery document during first request - avoid race condition
// Perform lock when changing document - we are in concurrent environment
func (toa *TraefikOidcAuth) EnsureOidcDiscovery() error {
	var config = toa.Config
	var parsedURL = toa.ProviderURL
	if toa.DiscoveryDocument == nil {
		toa.Lock.Lock()
		defer toa.Lock.Unlock()
		// check again after lock
		if toa.DiscoveryDocument == nil {
			var jwks = &JwksHandler{}
			toa.Jwks = jwks
			log(config.LogLevel, LogLevelInfo, "Getting OIDC discovery document...")

			oidcDiscoveryDocument, err := GetOidcDiscovery(config.LogLevel, parsedURL)
			if err != nil {
				log(config.LogLevel, LogLevelError, "Error while retrieving discovery document: %s", err.Error())
				return err
			}

			// Apply defaults
			if config.Provider.ValidIssuer == "" {
				config.Provider.ValidIssuer = oidcDiscoveryDocument.Issuer
			}
			if config.Provider.ValidAudience == "" {
				config.Provider.ValidAudience = config.Provider.ClientId
			}

			log(config.LogLevel, LogLevelInfo, "OIDC Discovery successful. AuthEndPoint: %s", oidcDiscoveryDocument.AuthorizationEndpoint)

			toa.DiscoveryDocument = oidcDiscoveryDocument
			toa.Jwks.Url = oidcDiscoveryDocument.JWKSURI
		}
		return nil
	}

	return nil
}

func (toa *TraefikOidcAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	err := toa.EnsureOidcDiscovery()

	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Error getting oidc discovery: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if strings.HasPrefix(req.RequestURI, toa.Config.CallbackUri) {
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

		if token != "" {
			isValid, claims, err := validateToken(toa, token)
			if err != nil {
				// TODO: Should we return InternalServerError here?
				log(toa.Config.LogLevel, LogLevelError, "Verifying token: %s", err.Error())
				toa.handleUnauthorized(rw, req)
				return
			}

			ok = isValid

			if ok && claims != nil {
				for _, claimMap := range toa.Config.Headers.MapClaims {
					for claimName, claimValue := range *claims {
						if claimName == claimMap.Claim {
							req.Header.Set(claimMap.Header, fmt.Sprintf("%s", claimValue))
							break
						}
					}
				}
			}
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

		// Forward the request
		toa.next.ServeHTTP(rw, req)
		return
	}

	toa.handleUnauthorized(rw, req)
}

func (toa *TraefikOidcAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	base64State := req.URL.Query().Get("state")
	if base64State == "" {
		log(toa.Config.LogLevel, LogLevelWarn, "State is missing, redirect to Provider")
		toa.redirectToProvider(rw, req)
		return
	}

	state, err := base64DecodeState(base64State)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelWarn, "State is invalid, redirect to Provider")
		toa.redirectToProvider(rw, req)
		return
	}

	redirectUrl := state.RedirectUrl

	if state.Action == "Login" {
		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			log(toa.Config.LogLevel, LogLevelWarn, "Code is missing, redirect to Provider")
			toa.redirectToProvider(rw, req)
			return
		}

		token, err := exchangeAuthCode(toa, req, authCode)
		if err != nil {
			log(toa.Config.LogLevel, LogLevelError, "Exchange Auth Code: %s", err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		redactedToken := token
		if len(redactedToken) > 16 {
			redactedToken = redactedToken[0:16] + " *** REDACTED ***"
		}

		_, claims, err := validateToken(toa, token)
		if err != nil {
			log(toa.Config.LogLevel, LogLevelError, "Returned token is not valid: %s", err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		log(toa.Config.LogLevel, LogLevelInfo, "Exchange Auth Code completed. Token: %+v", redactedToken)

		if !toa.isAuthorized(claims) {
			http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Set the cookie
		http.SetCookie(rw, &http.Cookie{
			Name:     toa.Config.StateCookie.Name,
			Value:    "Bearer " + token,
			Secure:   toa.Config.StateCookie.Secure,
			HttpOnly: toa.Config.StateCookie.HttpOnly,
			Path:     toa.Config.StateCookie.Path,
			SameSite: parseCookieSameSite(toa.Config.StateCookie.SameSite),
		})

		http.SetCookie(rw, &http.Cookie{
			Name:     "CodeVerifier",
			Value:    "",
			Expires:  time.Now().Add(-24 * time.Hour),
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			Path:     toa.Config.CallbackUri,
			SameSite: http.SameSiteDefaultMode,
		})

		// If we have a static redirect uri, use this one
		if toa.Config.PostLoginRedirectUri != "" {
			redirectUrl = ensureAbsoluteUrl(req, toa.Config.PostLoginRedirectUri)
		}
	} else if state.Action == "Logout" {
		log(toa.Config.LogLevel, LogLevelDebug, "Post logout. Clearing cookie.")

		// Clear the cookie
		http.SetCookie(rw, &http.Cookie{
			Name:    toa.Config.StateCookie.Name,
			Value:   "",
			Path:    toa.Config.StateCookie.Path,
			Expires: time.Now().Add(-24 * time.Hour),
			MaxAge:  -1,
		})
	}

	log(toa.Config.LogLevel, LogLevelInfo, "Redirecting to %s", redirectUrl)

	http.Redirect(rw, req, redirectUrl, http.StatusFound)
}

func (toa *TraefikOidcAuth) handleLogout(rw http.ResponseWriter, req *http.Request) {
	log(toa.Config.LogLevel, LogLevelInfo, "Logging out...")

	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html

	endSessionURL, err := url.Parse(toa.DiscoveryDocument.EndSessionEndpoint)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Error while parsing the AuthorizationEndpoint: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	callbackUri := ensureAbsoluteUrl(req, toa.Config.CallbackUri)
	redirectUri := ensureAbsoluteUrl(req, toa.Config.PostLogoutRedirectUri)

	if req.URL.Query().Get("redirect_uri") != "" {
		redirectUri = ensureAbsoluteUrl(req, req.URL.Query().Get("redirect_uri"))
	} else if req.URL.Query().Get("post_logout_redirect_uri") != "" {
		redirectUri = ensureAbsoluteUrl(req, req.URL.Query().Get("post_logout_redirect_uri"))
	}

	state := OidcState{
		Action:      "Logout",
		RedirectUrl: redirectUri,
	}

	base64State, err := state.base64Encode()
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to serialize state: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	endSessionURL.RawQuery = url.Values{
		"client_id":                {toa.Config.Provider.ClientId},
		"post_logout_redirect_uri": {callbackUri},
		"state":                    {base64State},
	}.Encode()

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
	log(toa.Config.LogLevel, LogLevelInfo, "Redirecting to OIDC provider...")

	host := getFullHost(req)

	originalUrl := fmt.Sprintf("%s%s", host, req.RequestURI)
	redirectUrl := host + toa.Config.CallbackUri

	state := OidcState{
		Action:      "Login",
		RedirectUrl: originalUrl,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	log(toa.Config.LogLevel, LogLevelDebug, "AuthorizationEndPoint: %s", toa.DiscoveryDocument.AuthorizationEndpoint)

	redirectURL, err := url.Parse(toa.DiscoveryDocument.AuthorizationEndpoint)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Error while parsing the AuthorizationEndpoint: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	urlValues := url.Values{
		"response_type": {"code"},
		"scope":         {strings.Join(toa.Config.Scopes, " ")},
		"client_id":     {toa.Config.Provider.ClientId},
		"redirect_uri":  {redirectUrl},
		"state":         {stateBase64},
	}

	if toa.Config.Provider.UsePkce {
		codeVerifier, err := randomBytesInHex(32)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		sha2 := sha256.New()
		if _, writeErr := io.WriteString(sha2, codeVerifier); writeErr != nil {
			http.Error(rw, writeErr.Error(), http.StatusInternalServerError)
			return
		}
		codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

		urlValues.Add("code_challenge_method", "S256")
		urlValues.Add("code_challenge", codeChallenge)

		encryptedCodeVerifier, err := encrypt(codeVerifier, toa.Config.Secret)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: Make configurable
		http.SetCookie(rw, &http.Cookie{
			Name:     "CodeVerifier",
			Value:    encryptedCodeVerifier,
			Secure:   true,
			HttpOnly: true,
			Path:     toa.Config.CallbackUri,
			SameSite: http.SameSiteDefaultMode,
		})
	}

	redirectURL.RawQuery = urlValues.Encode()

	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}
