package traefik_oidc_auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func (toa *TraefikOidcAuth) getSessionForRequest(req *http.Request) (*SessionState, bool, map[string]interface{}, error) {
	// Use AuthorizationHeader, if present
	if toa.Config.AuthorizationHeader != nil && toa.Config.AuthorizationHeader.Name != "" {
		authHeader := req.Header.Get(toa.Config.AuthorizationHeader.Name)

		if authHeader != "" {
			if toa.Config.AuthorizationHeader.Name == "Authorization" {
				authHeader = strings.TrimPrefix(authHeader, "Bearer ")
			}

			log(toa.Config.LogLevel, LogLevelDebug, "Custom AuthorizationHeader is present on the request and will be used.")

			session := &SessionState{
				Id:          "AuthorizationHeader",
				AccessToken: authHeader,
			}

			ok, claims, err := toa.validateToken(session)

			if ok {
				return session, false, claims, err
			} else {
				return nil, false, nil, fmt.Errorf("failed to validate token from AuthorizationHeader: %s", err.Error())
			}
		}
	}

	// Use AuthorizationCookie, if present
	if toa.Config.AuthorizationCookie != nil && toa.Config.AuthorizationCookie.Name != "" {
		authCookie, err := req.Cookie(toa.Config.AuthorizationCookie.Name)

		if authCookie != nil && err == nil && authCookie.Value != "" {
			log(toa.Config.LogLevel, LogLevelDebug, "Custom AuthorizationCookie is present on the request and will be used.")

			session := &SessionState{
				Id:          "AuthorizationCookie",
				AccessToken: authCookie.Value,
			}

			ok, claims, err := toa.validateToken(session)

			if ok {
				return session, false, claims, err
			} else {
				return nil, false, nil, fmt.Errorf("failed to validate token from AuthorizationCookie: %s", err.Error())
			}
		}
	}

	// Use SessionCookie, if present
	sessionTicket, err := toa.readChunkedCookie(req, toa.Config.SessionCookie.Name)

	if err != nil {
		return nil, false, nil, fmt.Errorf("unable to read session cookie: %s", strings.TrimLeft(err.Error(), "http: "))
	}

	log(toa.Config.LogLevel, LogLevelDebug, "A session is present for the request and will be used.")

	session, claims, updatedSession, err := validateSessionTicket(toa, sessionTicket)

	if err != nil {
		return nil, false, claims, fmt.Errorf("failed to validate session ticket: %s", err.Error())
	}

	return session, updatedSession != nil, claims, nil
}

func validateSessionTicket(toa *TraefikOidcAuth, encryptedTicket string) (*SessionState, map[string]interface{}, *SessionState, error) {
	plainSessionTicket, err := decrypt(encryptedTicket, toa.Config.DerivedKey)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to decrypt session ticket: %v", err.Error())
		return nil, nil, nil, err
	}

	session, err := toa.SessionStorage.TryGetSession(plainSessionTicket)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Reading session failed: %v", err.Error())
		return nil, nil, nil, err
	}
	if session == nil {
		log(toa.Config.LogLevel, LogLevelDebug, "No session found")
		return nil, nil, nil, nil
	}

	success, claims, err := toa.validateToken(session)

	if !success || err != nil {
		if session.RefreshToken != "" {
			log(toa.Config.LogLevel, LogLevelInfo, "Trying to renew session...")

			newTokens, err := toa.renewToken(session.RefreshToken)

			if err != nil {
				return nil, nil, nil, err
			}

			log(toa.Config.LogLevel, LogLevelInfo, "Successfully renewed session")

			session.AccessToken = newTokens.AccessToken
			session.RefreshToken = newTokens.RefreshToken

			success, claims, err = toa.validateToken(session)

			if !success || err != nil {
				log(toa.Config.LogLevel, LogLevelError, "Failed to validate renewed session: %v", err)
				return nil, nil, session, err
			}

			return session, claims, session, err
		} else {
			return nil, nil, nil, err
		}
	}

	return session, claims, nil, nil
}

func (toa *TraefikOidcAuth) validateToken(session *SessionState) (bool, map[string]interface{}, error) {
	var token string

	// Little bit hacky. In case the request contains a custom AuthorizationHeader or Cookie, only AccessToken is used.
	// See getSessionForRequest-function.
	if session.Id == "AuthorizationHeader" || session.Id == "AuthorizationCookie" {
		token = session.AccessToken
	} else {
		switch toa.Config.Provider.TokenValidation {
		case "AccessToken", "Introspection":
			token = session.AccessToken
		case "IdToken":
			token = session.IdToken
		default:
			return false, nil, errors.New(fmt.Sprintf("Invalid value '%s' for TokenValidation", toa.Config.Provider.TokenValidation))
		}
	}

	if toa.Config.Provider.TokenValidation == "Introspection" {
		return toa.introspectToken(token)
	}

	return toa.validateTokenLocally(token)
}

func (toa *TraefikOidcAuth) storeSessionAndAttachCookie(session *SessionState, rw http.ResponseWriter) {
	sessionTicket, err := toa.SessionStorage.StoreSession(session.Id, session)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to store session: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	log(toa.Config.LogLevel, LogLevelDebug, "Session stored. Id %s", session.Id)

	encryptedSessionTicket, err := encrypt(sessionTicket, toa.Config.DerivedKey)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to encrypt session ticket: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	toa.setChunkedCookies(rw, toa.Config.SessionCookie.Name, encryptedSessionTicket)
}

func (toa *TraefikOidcAuth) createSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     toa.Config.SessionCookie.Name,
		Value:    "",
		Secure:   toa.Config.SessionCookie.Secure,
		HttpOnly: toa.Config.SessionCookie.HttpOnly,
		Path:     toa.Config.SessionCookie.Path,
		Domain:   toa.Config.SessionCookie.Domain,
		SameSite: parseCookieSameSite(toa.Config.SessionCookie.SameSite),
		MaxAge:   toa.Config.SessionCookie.MaxAge,
	}
}
