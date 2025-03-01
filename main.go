package traefik_oidc_auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"
)

type TraefikOidcAuth struct {
	next              http.Handler
	httpClient        *http.Client
	ProviderURL       *url.URL
	CallbackURL       *url.URL
	Config            *Config
	SessionStorage    SessionStorage
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

			oidcDiscoveryDocument, err := GetOidcDiscovery(config.LogLevel, toa.httpClient, parsedURL)
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

func (toa *TraefikOidcAuth) GetAbsoluteCallbackURL(req *http.Request) *url.URL {
	if urlIsAbsolute(toa.CallbackURL) {
		return toa.CallbackURL
	} else {
		abs := *toa.CallbackURL
		fillHostSchemeFromRequest(req, &abs)
		return &abs
	}
}

func (toa *TraefikOidcAuth) isCallbackRequest(req *http.Request) bool {
	u := req.URL
	fillHostSchemeFromRequest(req, u)

	if u.Path != toa.CallbackURL.Path {
		return false
	}

	if urlIsAbsolute(toa.CallbackURL) {
		if u.Scheme != toa.CallbackURL.Scheme || u.Host != toa.CallbackURL.Host {
			return false
		}
	}

	return true
}

func (toa *TraefikOidcAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	err := toa.EnsureOidcDiscovery()

	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Error getting oidc discovery: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if toa.isCallbackRequest(req) {
		toa.handleCallback(rw, req)
		return
	}

	if toa.Config.LoginUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.LoginUri) {
		toa.redirectToProvider(rw, req)
		return
	}

	session, updateSession, claims, err := toa.getSessionForRequest(req)

	if err == nil && session != nil {
		// Handle logout
		if strings.HasPrefix(req.RequestURI, toa.Config.LogoutUri) {
			toa.handleLogout(rw, req, session)
			return
		}

		// Attach upstream headers
		err = toa.attachHeaders(req, session, claims)
		if err != nil {
			log(toa.Config.LogLevel, LogLevelError, "Error while attaching headers: %s", err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if updateSession {
			toa.storeSessionAndAttachCookie(session, rw)
		}

		// Forward the request
		toa.sanitizeForUpstream(req)
		toa.next.ServeHTTP(rw, req)
		return
	} else {
		log(toa.Config.LogLevel, LogLevelWarn, "Verifying token: %s", err.Error())
	}

	// Clear the session cookie
	toa.clearChunkedCookie(rw, req, getSessionCookieName(toa.Config))

	toa.handleUnauthorized(rw, req)
}

func (toa *TraefikOidcAuth) sanitizeForUpstream(req *http.Request) {
	// Remove all internal cookies from the request before forwarding
	keepCookies := make([]*http.Cookie, 0)

	for _, c := range req.Cookies() {
		if !strings.HasPrefix(c.Name, toa.Config.CookieNamePrefix) {
			keepCookies = append(keepCookies, c)
		}
	}

	req.Header.Del("Cookie")

	for _, c := range keepCookies {
		req.AddCookie(c)
	}
}

func (toa *TraefikOidcAuth) attachHeaders(req *http.Request, session *SessionState, claims map[string]interface{}) error {
	if toa.Config.Headers != nil {
		evalContext := make(map[string]interface{})

		evalContext["claims"] = claims
		evalContext["accessToken"] = session.AccessToken
		evalContext["idToken"] = session.IdToken
		evalContext["refreshToken"] = session.RefreshToken

		for _, header := range toa.Config.Headers {
			if header.Value != "" {
				if header.template == nil {
					tpl, err := template.New("").Parse(header.Value)

					if err != nil {
						return err
					}

					header.template = tpl
				}

				var renderedValue bytes.Buffer
				err := header.template.Execute(&renderedValue, evalContext)

				if err == nil {
					req.Header.Set(header.Name, renderedValue.String())
				} else {
					req.Header.Set(header.Name, err.Error())
				}
			} else {
				req.Header.Set(header.Name, "")
			}
		}
	}

	return nil
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
			http.Error(rw, "Code is missing", http.StatusInternalServerError)
			return
		}

		token, err := exchangeAuthCode(toa, req, authCode)
		if err != nil {
			log(toa.Config.LogLevel, LogLevelError, "Exchange Auth Code: %s", err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		usedToken := ""

		if toa.Config.Provider.TokenValidation == "AccessToken" {
			usedToken = token.AccessToken
		} else if toa.Config.Provider.TokenValidation == "IdToken" {
			usedToken = token.IdToken
		} else if toa.Config.Provider.TokenValidation == "Introspection" {
			usedToken = token.AccessToken
		} else {
			log(toa.Config.LogLevel, LogLevelError, "Invalid value '%s' for VerificationToken", toa.Config.Provider.TokenValidation)
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

		redactedToken := usedToken
		if len(redactedToken) > 16 {
			redactedToken = redactedToken[0:16] + " *** REDACTED ***"
		}

		var claims map[string]interface{}

		if toa.Config.Provider.TokenValidation == "Introspection" {
			_, claims, err = toa.introspectToken(usedToken)
		} else {
			_, claims, err = toa.validateTokenLocally(usedToken)
		}

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

		session := &SessionState{
			Id:           GenerateSessionId(),
			AccessToken:  token.AccessToken,
			IdToken:      token.IdToken,
			RefreshToken: token.RefreshToken,
		}

		toa.storeSessionAndAttachCookie(session, rw)

		http.SetCookie(rw, &http.Cookie{
			Name:     getCodeVerifierCookieName(toa.Config),
			Value:    "",
			Expires:  time.Now().Add(-24 * time.Hour),
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			Path:     toa.CallbackURL.Path,
			Domain:   toa.CallbackURL.Host,
			SameSite: http.SameSiteDefaultMode,
		})

		if redirectUrl != "" {
			redirectUrl = ensureAbsoluteUrl(req, redirectUrl)
		} else {
			redirectUrl = ensureAbsoluteUrl(req, toa.Config.PostLoginRedirectUri)
		}

	} else if state.Action == "Logout" {
		log(toa.Config.LogLevel, LogLevelDebug, "Post logout. Clearing cookie.")

		// Clear the cookie
		toa.clearChunkedCookie(rw, req, getSessionCookieName(toa.Config))
	}

	log(toa.Config.LogLevel, LogLevelInfo, "Redirecting to %s", redirectUrl)

	http.Redirect(rw, req, redirectUrl, http.StatusFound)
}

func (toa *TraefikOidcAuth) handleLogout(rw http.ResponseWriter, req *http.Request, session *SessionState) {
	log(toa.Config.LogLevel, LogLevelInfo, "Logging out...")

	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html

	endSessionURL, err := url.Parse(toa.DiscoveryDocument.EndSessionEndpoint)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Error while parsing the AuthorizationEndpoint: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	callbackUri := toa.GetAbsoluteCallbackURL(req).String()
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
		"id_token_hint":            {session.IdToken},
	}.Encode()

	http.Redirect(rw, req, endSessionURL.String(), http.StatusFound)
}

func (toa *TraefikOidcAuth) handleUnauthorized(rw http.ResponseWriter, req *http.Request) {
	if toa.Config.UnauthorizedBehavior == "Challenge" {
		toa.redirectToProvider(rw, req)
	} else {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
}

func (toa *TraefikOidcAuth) redirectToProvider(rw http.ResponseWriter, req *http.Request) {
	log(toa.Config.LogLevel, LogLevelInfo, "Redirecting to OIDC provider...")

	var redirectUrl string

	// If the user specified one on the /login request, use this one
	if redirectUrlFromQuery := req.URL.Query().Get("redirect_uri"); toa.Config.LoginUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.LoginUri) && redirectUrlFromQuery != "" {
		redirectUrl = redirectUrlFromQuery
	} else if toa.Config.PostLoginRedirectUri != "" {
		host := getFullHost(req)
		postLoginUri, _ := strings.CutPrefix(toa.Config.PostLoginRedirectUri, "/")
		redirectUrl = fmt.Sprintf("%s/%s", host, postLoginUri)
	} else {
		host := getFullHost(req)
		redirectUrl = fmt.Sprintf("%s%s", host, req.RequestURI)

		// Special case: If someone just calls /login but doesn't provide a redirect_uri, we go to / instead of /login again.
		if toa.Config.LoginUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.LoginUri) {
			redirectUrl = host
		}
	}

	callbackUrl := toa.GetAbsoluteCallbackURL(req).String()

	state := OidcState{
		Action:      "Login",
		RedirectUrl: redirectUrl,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	log(toa.Config.LogLevel, LogLevelDebug, "AuthorizationEndPoint: %s", toa.DiscoveryDocument.AuthorizationEndpoint)

	authorizationEndpointUrl, err := url.Parse(toa.DiscoveryDocument.AuthorizationEndpoint)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Error while parsing the AuthorizationEndpoint: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	urlValues := url.Values{
		"response_type": {"code"},
		"scope":         {strings.Join(toa.Config.Scopes, " ")},
		"client_id":     {toa.Config.Provider.ClientId},
		"redirect_uri":  {callbackUrl},
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
		// TODO does this need domain tweaks?  it is in the login flow
		http.SetCookie(rw, &http.Cookie{
			Name:     getCodeVerifierCookieName(toa.Config),
			Value:    encryptedCodeVerifier,
			Secure:   true,
			HttpOnly: true,
			Path:     toa.CallbackURL.Path,
			Domain:   toa.CallbackURL.Host,
			SameSite: http.SameSiteDefaultMode,
		})
	}

	authorizationEndpointUrl.RawQuery = urlValues.Encode()

	http.Redirect(rw, req, authorizationEndpointUrl.String(), http.StatusFound)
}
