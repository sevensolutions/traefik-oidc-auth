package traefik_oidc_auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TraefikOidcAuth struct {
	next              http.Handler
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

func (toa *TraefikOidcAuth) CallbackURLAbsolute(req *http.Request) *url.URL {
	if urlIsAbsolute(toa.CallbackURL) {
		return toa.CallbackURL
	} else {
		abs := *toa.CallbackURL
		fillHostSchemeFromRequest(req, &abs)
		return &abs
	}
}

func (toa *TraefikOidcAuth) isReqForCallback(req *http.Request) bool {
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

	if toa.isReqForCallback(req) {
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

	sessionTicket, err := toa.ReadChunkedCookie(req, toa.Config.StateCookie.Name)

	if err == nil {
		var ok = false

		if sessionTicket != "" {
			isValid, claims, updatedSession, err := validateSessionTicket(toa, sessionTicket)
			if err != nil {
				// TODO: Should we return InternalServerError here?
				log(toa.Config.LogLevel, LogLevelError, "Verifying token: %s", err.Error())
				toa.handleUnauthorized(rw, req)
				return
			}

			ok = isValid

			if ok && claims != nil {
				log(toa.Config.LogLevel, LogLevelDebug, "Claims: %+v", claims)
				for _, claimMap := range toa.Config.Headers.MapClaims {
					for claimName, claimValue := range claims {
						if claimName == claimMap.Claim {
							req.Header.Set(claimMap.Header, fmt.Sprintf("%s", claimValue))
							break
						}
					}
				}
			}

			if updatedSession != nil {
				toa.storeSessionAndAttachCookie(*updatedSession, rw)
			}
		}

		if !ok {
			c := toa.stateCookieTemplate()
			makeCookieExpireImmediately(c)
			http.SetCookie(rw, c)

			toa.handleUnauthorized(rw, req)
			return
		}

		// Forward the request
		toa.next.ServeHTTP(rw, req)
		return
	} else {
		log(toa.Config.LogLevel, LogLevelError, "Failed reading state cookie: %s", err.Error())
	}

	toa.handleUnauthorized(rw, req)
}

func validateSessionTicket(toa *TraefikOidcAuth, encryptedTicket string) (bool, map[string]interface{}, *SessionState, error) {
	plainSessionTicket, err := decrypt(encryptedTicket, toa.Config.Secret)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to decrypt session ticket: %v", err.Error())
		return false, nil, nil, err
	}

	session, err := toa.SessionStorage.TryGetSession(plainSessionTicket)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Reading session failed: %v", err.Error())
		return false, nil, nil, err
	}
	if session == nil {
		log(toa.Config.LogLevel, LogLevelDebug, "No session found")
		return false, nil, nil, nil
	}

	success, claims, err := toa.validateToken(session)

	if !success || err != nil {
		if session.RefreshToken != "" {
			log(toa.Config.LogLevel, LogLevelInfo, "Trying to renew session...")

			newTokens, err := toa.renewToken(session.RefreshToken)

			if err != nil {
				return false, nil, nil, err
			}

			log(toa.Config.LogLevel, LogLevelInfo, "Successfully renewed session")

			session.AccessToken = newTokens.AccessToken
			session.RefreshToken = newTokens.RefreshToken

			success, claims, err = toa.validateToken(session)

			if !success || err != nil {
				return false, nil, session, err
			}

			return success, claims, session, err
		} else {
			return false, nil, nil, err
		}
	}

	return success, claims, nil, nil
}

func (toa *TraefikOidcAuth) validateToken(session *SessionState) (bool, map[string]interface{}, error) {
	if toa.Config.Provider.TokenValidation == "AccessToken" {
		return toa.validateTokenLocally(session.AccessToken)
	} else if toa.Config.Provider.TokenValidation == "IdToken" {
		return toa.validateTokenLocally(session.IdToken)
	} else if toa.Config.Provider.TokenValidation == "Introspection" {
		return toa.introspectToken(session.AccessToken)
	} else {
		return false, nil, errors.New(fmt.Sprintf("Invalid value '%s' for VerificationToken", toa.Config.Provider.TokenValidation))
	}
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

		session := SessionState{
			Id:           GenerateSessionId(),
			AccessToken:  token.AccessToken,
			IdToken:      token.IdToken,
			RefreshToken: token.RefreshToken,
		}

		toa.storeSessionAndAttachCookie(session, rw)

		http.SetCookie(rw, &http.Cookie{
			Name:     "CodeVerifier",
			Value:    "",
			Expires:  time.Now().Add(-24 * time.Hour),
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			Path:     toa.CallbackURL.Path,
			Domain:   toa.CallbackURL.Host,
			SameSite: http.SameSiteDefaultMode,
		})

		// If we have a static redirect uri, use this one
		if toa.Config.PostLoginRedirectUri != "" {
			redirectUrl = ensureAbsoluteUrl(req, toa.Config.PostLoginRedirectUri)
		}
	} else if state.Action == "Logout" {
		log(toa.Config.LogLevel, LogLevelDebug, "Post logout. Clearing cookie.")

		// Clear the cookie
		toa.ClearChunkedCookie(rw, req, toa.Config.StateCookie.Name)
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

	callbackUri := toa.CallbackURLAbsolute(req).String()
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

	redirectUrl := toa.CallbackURLAbsolute(req).String()

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
		// TODO does this need domain tweaks?  it is in the login flow
		http.SetCookie(rw, &http.Cookie{
			Name:     "CodeVerifier",
			Value:    encryptedCodeVerifier,
			Secure:   true,
			HttpOnly: true,
			Path:     toa.CallbackURL.Path,
			Domain:   toa.CallbackURL.Host,
			SameSite: http.SameSiteDefaultMode,
		})
	}

	redirectURL.RawQuery = urlValues.Encode()

	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}

func (toa *TraefikOidcAuth) storeSessionAndAttachCookie(session SessionState, rw http.ResponseWriter) {
	sessionTicket, err := toa.SessionStorage.StoreSession(session.Id, session)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to store session: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	log(toa.Config.LogLevel, LogLevelDebug, "Session stored. Id %s", session.Id)

	encryptedSessionTicket, err := encrypt(sessionTicket, toa.Config.Secret)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to encrypt session ticket: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	toa.SetChunkedCookies(rw, toa.Config.StateCookie.Name, encryptedSessionTicket)
}

func (toa *TraefikOidcAuth) stateCookieTemplate() *http.Cookie {
	return &http.Cookie{
		Name:     toa.Config.StateCookie.Name,
		Value:    "",
		Secure:   toa.Config.StateCookie.Secure,
		HttpOnly: toa.Config.StateCookie.HttpOnly,
		Path:     toa.Config.StateCookie.Path,
		Domain:   toa.Config.StateCookie.Domain,
		SameSite: parseCookieSameSite(toa.Config.StateCookie.SameSite),
	}
}

func (toa *TraefikOidcAuth) SetChunkedCookies(rw http.ResponseWriter, cookieName string, cookieValue string) {
	cookieChunks := ChunkString(cookieValue, 3072)

	baseCookie := toa.stateCookieTemplate()
	baseCookie.Name = cookieName

	// Set the cookie
	if len(cookieChunks) == 1 {
		c := baseCookie
		c.Value = cookieValue
		http.SetCookie(rw, c)
	} else {
		c := baseCookie
		c.Name = cookieName + "Chunks"
		c.Value = fmt.Sprintf("%d", len(cookieChunks))
		http.SetCookie(rw, c)

		for index, chunk := range cookieChunks {
			c.Name = fmt.Sprintf("%s%d", cookieName, index+1)
			c.Value = chunk
			http.SetCookie(rw, c)
		}
	}
}
func (toa *TraefikOidcAuth) ReadChunkedCookie(req *http.Request, cookieName string) (string, error) {
	chunkCount, err := getChunkedCookieCount(req, cookieName)
	if err != nil {
		return "", err
	}

	if chunkCount == 0 {
		cookie, err := req.Cookie(cookieName)
		if err != nil {
			return "", err
		}

		return cookie.Value, nil
	}

	value := ""

	for i := 0; i < chunkCount; i++ {
		cookie, err := req.Cookie(fmt.Sprintf("%s%d", cookieName, i+1))
		if err != nil {
			return "", err
		}

		value += cookie.Value
	}

	return value, nil
}
func getChunkedCookieCount(req *http.Request, cookieName string) (int, error) {
	chunksCookie, err := req.Cookie(fmt.Sprintf("%sChunks", cookieName))
	if err != nil {
		return 0, nil
	}

	chunkCount, err := strconv.Atoi(chunksCookie.Value)
	if err != nil {
		return 0, err
	}

	return chunkCount, nil
}
func (toa *TraefikOidcAuth) ClearChunkedCookie(rw http.ResponseWriter, req *http.Request, cookieName string) error {
	chunkCount, err := getChunkedCookieCount(req, cookieName)
	if err != nil {
		return err
	}

	baseCookie := toa.stateCookieTemplate()
	baseCookie.Name = cookieName
	baseCookie.Value = ""
	makeCookieExpireImmediately(baseCookie)

	if chunkCount == 0 {
		http.SetCookie(rw, baseCookie)
	} else {
		c := baseCookie
		c.Name = cookieName + "Chunks"
		http.SetCookie(rw, c)

		for i := 0; i < chunkCount; i++ {
			c.Name = fmt.Sprintf("%s%d", cookieName, i+1)
			http.SetCookie(rw, c)
		}
	}

	return nil
}
