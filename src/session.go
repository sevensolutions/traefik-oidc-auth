package src

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

func (toa *TraefikOidcAuth) getSessionForRequest(req *http.Request) (*session.SessionState, bool, map[string]interface{}, error) {
	// Use AuthorizationHeader, if present
	if toa.Config.AuthorizationHeader != nil && toa.Config.AuthorizationHeader.Name != "" {
		authHeader := req.Header.Get(toa.Config.AuthorizationHeader.Name)

		if authHeader != "" {
			if toa.Config.AuthorizationHeader.Name == "Authorization" {
				authHeader = strings.TrimPrefix(authHeader, "Bearer ")
			}

			toa.logger.Log(logging.LevelDebug, "Custom AuthorizationHeader is present on the request and will be used.")

			session := &session.SessionState{
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
			toa.logger.Log(logging.LevelDebug, "Custom AuthorizationCookie is present on the request and will be used.")

			session := &session.SessionState{
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
	sessionTicket, err := readChunkedCookie(req, getSessionCookieName(toa.Config))

	if err != nil {
		return nil, false, nil, fmt.Errorf("unable to read session cookie: %s", strings.TrimLeft(err.Error(), "http: "))
	}
	if sessionTicket == "" {
		return nil, false, nil, fmt.Errorf("no session cookie is present")
	}

	session, claims, updatedSession, err := validateSessionTicket(toa, sessionTicket)

	if err != nil {
		return nil, false, claims, fmt.Errorf("failed to validate session ticket: %s", err.Error())
	}

	if toa.logger.MinLevel == logging.LevelDebug {
		tokenExpiresText := ""
		if session.TokenExpiresIn > 0 {
			tokenExpiresText = fmt.Sprintf("The IDP token expires in %ds.", int(math.Round(time.Until(session.RefreshedAt.Add(time.Duration(session.TokenExpiresIn)*time.Second)).Seconds())))
		}

		toa.logger.Log(logging.LevelDebug, "A session is present for the request. %s", tokenExpiresText)
	}

	return session, updatedSession != nil, claims, nil
}

func validateSessionTicket(toa *TraefikOidcAuth, encryptedTicket string) (*session.SessionState, map[string]interface{}, *session.SessionState, error) {
	plainSessionTicket, err := utils.Decrypt(encryptedTicket, toa.Config.Secret)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to decrypt session ticket: %v", err.Error())
		return nil, nil, nil, err
	}

	session, err := toa.SessionStorage.TryGetSession(plainSessionTicket)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Reading session failed: %v", err.Error())
		return nil, nil, nil, err
	}
	if session == nil {
		toa.logger.Log(logging.LevelDebug, "No session found")
		return nil, nil, nil, nil
	}

	success, claims, err := toa.validateToken(session)

	// Check if the session or IDP token expires soon
	idpTokenExpiresSoon := false
	if success {
		idpTokenExpiresSoon = checkIdpTokenExpiresSoon(toa, session)
	}

	if !success || err != nil || idpTokenExpiresSoon {
		if session.RefreshToken != "" {
			toa.logger.Log(logging.LevelInfo, "Trying to renew tokens...")

			newTokens, err := toa.renewToken(session.RefreshToken)

			if err != nil {
				return nil, nil, nil, err
			}

			session.AccessToken = newTokens.AccessToken

			if newTokens.RefreshToken != "" {
				session.RefreshToken = newTokens.RefreshToken
			} else {
				toa.logger.Log(logging.LevelDebug, "The auth provider didn't return a new RefreshToken. Still keeping the old one.")
			}

			// We had some problems with some providers which didn't return a new IdToken when renewing the tokens.
			// Thats why i'am logging this case specifically here.
			if newTokens.IdToken != "" {
				session.IdToken = newTokens.IdToken
			} else {
				if toa.Config.Provider.TokenValidation == "IdToken" {
					toa.logger.Log(logging.LevelWarn, "The auth provider didn't return a new IdToken. Still keeping the old one.")
				} else {
					toa.logger.Log(logging.LevelDebug, "The auth provider didn't return a new IdToken. Still keeping the old one.")
				}
			}

			success, claims, err = toa.validateToken(session)

			if !success || err != nil {
				toa.logger.Log(logging.LevelError, "Failed to validate renewed session: %v", err)
				return nil, nil, session, err
			}

			// Update expirations
			session.RefreshedAt = time.Now()
			session.TokenExpiresIn = newTokens.ExpiresIn

			toa.logger.Log(logging.LevelInfo, "Successfully renewed session")

			return session, claims, session, err
		} else {
			if err == nil {
				err = errors.New("no refresh_token available")
			}
			return nil, nil, nil, err
		}
	}

	return session, claims, nil, nil
}

func checkIdpTokenExpiresSoon(toa *TraefikOidcAuth, session *session.SessionState) bool {
	if session.TokenExpiresIn > 0 {
		pastDuration := time.Since(session.RefreshedAt)

		halfMaxAge := float64(session.TokenExpiresIn) * toa.Config.Provider.TokenRenewalThreshold

		if pastDuration.Seconds() > halfMaxAge {
			toa.logger.Log(logging.LevelDebug, "The IDP token reached %d%% of it's expiration. Renewing now...", int32(toa.Config.Provider.TokenRenewalThreshold*100))
			return true
		}
	}

	return false
}

func (toa *TraefikOidcAuth) validateToken(session *session.SessionState) (bool, map[string]interface{}, error) {
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

	ok, claims, err := toa.validateTokenLocally(token)

	if !ok {
		return ok, claims, err
	}

	if toa.Config.Provider.UseClaimsFromUserInfoBool {
		subClaim, ok := claims["sub"].(string)
		if !ok {
			return false, nil, fmt.Errorf("failed to fetch UserInfo: 'sub' claim is not a string or missing")
		}

		userInfoClaims, err := toa.getUserInfo(session.AccessToken, subClaim)
		if err != nil {
			return false, nil, fmt.Errorf("failed to fetch UserInfo: %s", err.Error())
		}

		claims = mergeClaims(claims, userInfoClaims)
	}

	return ok, claims, err
}

func (toa *TraefikOidcAuth) storeSessionAndAttachCookie(session *session.SessionState, rw http.ResponseWriter) {
	sessionTicket, err := toa.SessionStorage.StoreSession(session.Id, session)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to store session: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	toa.logger.Log(logging.LevelDebug, "Session stored. Id %s", session.Id)

	encryptedSessionTicket, err := utils.Encrypt(sessionTicket, toa.Config.Secret)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to encrypt session ticket: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	setChunkedCookies(toa.Config, rw, getSessionCookieName(toa.Config), encryptedSessionTicket)
}

func createSessionCookie(config *Config) *http.Cookie {
	return &http.Cookie{
		Name:     getSessionCookieName(config),
		Value:    "",
		Secure:   config.SessionCookie.Secure,
		HttpOnly: config.SessionCookie.HttpOnly,
		Path:     config.SessionCookie.Path,
		Domain:   config.SessionCookie.Domain,
		SameSite: parseCookieSameSite(config.SessionCookie.SameSite),
		MaxAge:   config.SessionCookie.MaxAge,
	}
}
