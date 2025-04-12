package traefik_oidc_auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sevensolutions/traefik-oidc-auth/logging"
	"github.com/sevensolutions/traefik-oidc-auth/oidc"
	"github.com/sevensolutions/traefik-oidc-auth/utils"
)

func GetOidcDiscovery(logger *logging.Logger, httpClient *http.Client, providerUrl *url.URL) (*oidc.OidcDiscovery, error) {
	wellKnownUrl := *providerUrl

	wellKnownUrl.Path = path.Join(wellKnownUrl.Path, ".well-known/openid-configuration")

	// // create a http client with configurable options
	// // needed to skip certificate verification
	// tr := &http.Transport{
	// 	MaxIdleConns:    10,
	// 	IdleConnTimeout: 30 * time.Second,
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	// client := &http.Client{Transport: tr}

	// Make HTTP GET request to the OpenID provider's discovery endpoint
	resp, err := httpClient.Get(wellKnownUrl.String())

	if err != nil {
		logger.Log(logging.LevelError, "http-get discovery endpoints - Err: %s", err.Error())
		return nil, errors.New("HTTP GET error")
	}

	defer resp.Body.Close()

	// Check if the response status code is successful
	if resp.StatusCode >= 300 {
		logger.Log(logging.LevelError, "http-get OIDC discovery endpoints - http status code: %s", resp.Status)
		return nil, errors.New("HTTP error - Status code: " + resp.Status)
	}

	// Decode the JSON response
	document := oidc.OidcDiscovery{}
	err = json.NewDecoder(resp.Body).Decode(&document)

	if err != nil {
		logger.Log(logging.LevelError, "Failed to decode OIDC discovery document. Status code: %s", err.Error())
		return &document, errors.New("Failed to decode OIDC discovery document. Status code: " + err.Error())
	}

	return &document, nil
}

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}

func exchangeAuthCode(oidcAuth *TraefikOidcAuth, req *http.Request, authCode string) (*oidc.OidcTokenResponse, error) {
	redirectUrl := oidcAuth.GetAbsoluteCallbackURL(req).String()

	urlValues := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {oidcAuth.Config.Provider.ClientId},
		"code":         {authCode},
		"redirect_uri": {redirectUrl},
	}

	if oidcAuth.Config.Provider.ClientSecret != "" {
		urlValues.Add("client_secret", oidcAuth.Config.Provider.ClientSecret)
	}

	if oidcAuth.Config.Provider.UsePkce {
		codeVerifierCookie, err := req.Cookie(getCodeVerifierCookieName(oidcAuth.Config))
		if err != nil {
			return nil, err
		}

		codeVerifier, err := utils.Decrypt(codeVerifierCookie.Value, oidcAuth.Config.Secret)
		if err != nil {
			return nil, err
		}

		urlValues.Add("code_verifier", codeVerifier)
	}

	resp, err := oidcAuth.httpClient.PostForm(oidcAuth.DiscoveryDocument.TokenEndpoint, urlValues)

	if err != nil {
		oidcAuth.logger.Log(logging.LevelError, "exchangeAuthCode: couldn't POST to Provider: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		oidcAuth.logger.Log(logging.LevelError, "exchangeAuthCode: received bad HTTP response from Provider: %s", string(body))
		return nil, errors.New("invalid status code")
	}

	tokenResponse := &oidc.OidcTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		oidcAuth.logger.Log(logging.LevelError, "exchangeAuthCode: couldn't decode OidcTokenResponse: %s", err.Error())
		return nil, err
	}

	return tokenResponse, nil
}

func (toa *TraefikOidcAuth) validateTokenLocally(tokenString string) (bool, map[string]interface{}, error) {
	claims := jwt.MapClaims{}

	err := toa.Jwks.EnsureLoaded(toa.logger, toa.httpClient, false)
	if err != nil {
		return false, nil, err
	}

	options := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
	}

	if toa.Config.Provider.ValidateIssuerBool {
		options = append(options, jwt.WithIssuer(toa.Config.Provider.ValidIssuer))
	}
	if toa.Config.Provider.ValidateAudienceBool {
		options = append(options, jwt.WithAudience(toa.Config.Provider.ValidAudience))
	}

	parser := jwt.NewParser(options...)

	_, err = parser.ParseWithClaims(tokenString, claims, toa.Jwks.Keyfunc)

	if err != nil {
		err := toa.Jwks.EnsureLoaded(toa.logger, toa.httpClient, true)
		if err != nil {
			return false, nil, err
		}

		_, err = parser.ParseWithClaims(tokenString, claims, toa.Jwks.Keyfunc)

		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) || err.Error() == "token has invalid claims: token is expired" {
				toa.logger.Log(logging.LevelInfo, "The token is expired.")
			} else {
				toa.logger.Log(logging.LevelError, "Failed to parse token: %v", err)
			}

			return false, nil, err
		}
	}

	return true, claims, nil
}

func (toa *TraefikOidcAuth) introspectToken(token string) (bool, map[string]interface{}, error) {
	data := url.Values{
		"token": {token},
	}

	//log(toa.Config.LogLevel, LogLevelDebug, "Token: %s", token)

	endpoint := toa.DiscoveryDocument.IntrospectionEndpoint

	//if endpoint == "" {
	//	endpoint = toa.DiscoveryDocument.UserinfoEndpoint
	//}

	req, err := http.NewRequest(
		http.MethodPost,
		endpoint,
		strings.NewReader(data.Encode()),
	)

	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(toa.Config.Provider.ClientId, toa.Config.Provider.ClientSecret)

	resp, err := toa.httpClient.Do(req)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Error on introspection request: %s", err.Error())
		return false, nil, err
	}

	defer resp.Body.Close()

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)

	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to decode introspection response: %s", err.Error())
		return false, nil, err
	}

	// TODO: Remove
	//toa.logAvailableClaims(introspectResponse)

	if introspectResponse["active"] != nil {
		return introspectResponse["active"].(bool), introspectResponse, nil
	} else {
		return false, nil, errors.New("received invalid introspection response")
	}
}

func (toa *TraefikOidcAuth) renewToken(refreshToken string) (*oidc.OidcTokenResponse, error) {
	urlValues := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {toa.Config.Provider.ClientId},
		"scope":         {strings.Join(toa.Config.Scopes, " ")},
		"refresh_token": {refreshToken},
	}

	if toa.Config.Provider.ClientSecret != "" {
		urlValues.Add("client_secret", toa.Config.Provider.ClientSecret)
	}

	resp, err := toa.httpClient.PostForm(toa.DiscoveryDocument.TokenEndpoint, urlValues)

	if err != nil {
		toa.logger.Log(logging.LevelError, "renewToken: couldn't POST to Provider: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		toa.logger.Log(logging.LevelError, "renewToken: received bad HTTP response from Provider: %s", string(body))
		return nil, errors.New("invalid status code")
	}

	tokenResponse := &oidc.OidcTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		toa.logger.Log(logging.LevelError, "renewToken: couldn't decode OidcTokenResponse: %s", err.Error())
		return nil, err
	}

	return tokenResponse, nil
}
