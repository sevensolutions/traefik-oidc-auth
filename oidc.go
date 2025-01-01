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
)

type OidcEndpoints struct {
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	BackchannelAuthenticationEndpoint  string `json:"backchannel_authentication_endpoint"`
	DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint"`
	EndSessionEndpoint                 string `json:"end_session_endpoint"`
	IntrospectionEndpoint              string `json:"introspection_endpoint"`
	KerberosEndpoint                   string `json:"kerberos_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
	RegistrationEndpoint               string `json:"registration_endpoint"`
	RevocationEndpoint                 string `json:"revocation_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	TokenRevocationEndpoint            string `json:"token_revocation_endpoint"`
	UserinfoEndpoint                   string `json:"userinfo_endpoint"`
}

// OidcDiscovery represents the discovered OIDC endpoints
type OidcDiscovery struct {
	AcrValuesSupported                                        []string       `json:"acr_values_supported"`
	AuthorizationEncryptionAlgValuesSupported                 []string       `json:"authorization_encryption_alg_values_supported"`
	AuthorizationEncryptionEncValuesSupported                 []string       `json:"authorization_encryption_enc_values_supported"`
	AuthorizationEndpoint                                     string         `json:"authorization_endpoint"`
	AuthorizationSigningAlgValuesSupported                    []string       `json:"authorization_signing_alg_values_supported"`
	BackchannelAuthenticationEndpoint                         string         `json:"backchannel_authentication_endpoint"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string       `json:"backchannel_authentication_request_signing_alg_values_supported"`
	BackchannelLogoutSessionSupported                         bool           `json:"backchannel_logout_session_supported"`
	BackchannelLogoutSupported                                bool           `json:"backchannel_logout_supported"`
	BackchannelTokenDeliveryModesSupported                    []string       `json:"backchannel_token_delivery_modes_supported"`
	CheckSessionIframe                                        string         `json:"check_session_iframe"`
	ClaimsParameterSupported                                  bool           `json:"claims_parameter_supported"`
	ClaimsSupported                                           []string       `json:"claims_supported"`
	ClaimTypesSupported                                       []string       `json:"claim_types_supported"`
	CloudGraphHostName                                        string         `json:"cloud_graph_host_name"`
	CloudInstanceName                                         string         `json:"cloud_instance_name"`
	CodeChallengeMethodsSupported                             []string       `json:"code_challenge_methods_supported"`
	DeviceAuthorizationEndpoint                               string         `json:"device_authorization_endpoint"`
	DisplayValuesSupported                                    []string       `json:"display_values_supported"`
	EndSessionEndpoint                                        string         `json:"end_session_endpoint"`
	FrontchannelLogoutSessionSupported                        bool           `json:"frontchannel_logout_session_supported"`
	FrontchannelLogoutSupported                               bool           `json:"frontchannel_logout_supported"`
	GrantTypesSupported                                       []string       `json:"grant_types_supported"`
	HttpLogoutSupported                                       bool           `json:"http_logout_supported"`
	IdTokenEncryptionAlgValuesSupported                       []string       `json:"id_token_encryption_alg_values_supported"`
	IdTokenEncryptionEncValuesSupported                       []string       `json:"id_token_encryption_enc_values_supported"`
	IdTokenSigningAlgValuesSupported                          []string       `json:"id_token_signing_alg_values_supported"`
	IntrospectionEndpoint                                     string         `json:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported                 []string       `json:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        []string       `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	Issuer                                                    string         `json:"issuer"`
	JWKSURI                                                   string         `json:"jwks_uri"`
	KerberosEndpoint                                          string         `json:"kerberos_endpoint"`
	MicrosoftGraphHost                                        string         `json:"msgraph_host"`
	MtlsEndpointAliases                                       *OidcEndpoints `json:"mtls_endpoint_aliases"`
	PushedAuthorizationRequestEndpoint                        string         `json:"pushed_authorization_request_endpoint"`
	RbacURL                                                   string         `json:"rbac_url"`
	RegistrationEndpoint                                      string         `json:"registration_endpoint"`
	RequestObjectEncryptionAlgValuesSupported                 []string       `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported                 []string       `json:"request_object_encryption_enc_values_supported"`
	RequestObjectSigningAlgValuesSupported                    []string       `json:"request_object_signing_alg_values_supported"`
	RequestParameterSupported                                 bool           `json:"request_parameter_supported"`
	RequestURIParameterSupported                              bool           `json:"request_uri_parameter_supported"`
	RequirePushedAuthorizationRequests                        bool           `json:"require_pushed_authorization_requests"`
	RequireRequestUriRegistration                             bool           `json:"require_request_uri_registration"`
	ResponseModesSupported                                    []string       `json:"response_modes_supported"`
	ResponseTypesSupported                                    []string       `json:"response_types_supported"`
	RevocationEndpoint                                        string         `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported                    []string       `json:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported           []string       `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                                           []string       `json:"scopes_supported"`
	SubjectTypesSupported                                     []string       `json:"subject_types_supported"`
	TenantRegionScope                                         string         `json:"tenant_region_scope"`
	TlsClientCertificateBoundAccessTokens                     bool           `json:"tls_client_certificate_bound_access_tokens"`
	TokenEndpoint                                             string         `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported                         []string       `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported                []string       `json:"token_endpoint_auth_signing_alg_values_supported"`
	TokenRevocationEndpoint                                   string         `json:"token_revocation_endpoint"`
	UserinfoEncryptionAlgValuesSupported                      []string       `json:"userinfo_encryption_alg_values_supported"`
	UserinfoEncryptionEncValuesSupported                      []string       `json:"userinfo_encryption_enc_values_supported"`
	UserinfoEndpoint                                          string         `json:"userinfo_endpoint"`
	UserinfoSigningAlgValuesSupported                         []string       `json:"userinfo_signing_alg_values_supported"`
}

type OidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type OidcIntrospectionResponse struct {
	Active bool `json:"active"`
}

type OidcState struct {
	Action      string `json:"action"`
	RedirectUrl string `json:"redirect_url"`
}

func GetOidcDiscovery(logLevel string, providerUrl *url.URL) (*OidcDiscovery, error) {
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
	resp, err := http.Get(wellKnownUrl.String())

	if err != nil {
		log(logLevel, LogLevelError, "http-get discovery endpoints - Err: %s", err.Error())
		return nil, errors.New("HTTP GET error")
	}

	defer resp.Body.Close()

	// Check if the response status code is successful
	if resp.StatusCode >= 300 {
		log(logLevel, LogLevelError, "http-get OIDC discovery endpoints - http status code: %s", resp.Status)
		return nil, errors.New("HTTP error - Status code: " + resp.Status)
	}

	// Decode the JSON response
	document := OidcDiscovery{}
	err = json.NewDecoder(resp.Body).Decode(&document)

	if err != nil {
		log(logLevel, LogLevelError, "Failed to decode OIDC discovery document. Status code: %s", err.Error())
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

func exchangeAuthCode(oidcAuth *TraefikOidcAuth, req *http.Request, authCode string) (*OidcTokenResponse, error) {
	redirectUrl := oidcAuth.CallbackURLAbsolute(req).String()

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
		codeVerifierCookie, err := req.Cookie("CodeVerifier")
		if err != nil {
			return nil, err
		}

		codeVerifier, err := decrypt(codeVerifierCookie.Value, oidcAuth.Config.Secret)
		if err != nil {
			return nil, err
		}

		urlValues.Add("code_verifier", codeVerifier)
	}

	resp, err := http.PostForm(oidcAuth.DiscoveryDocument.TokenEndpoint, urlValues)

	if err != nil {
		log(oidcAuth.Config.LogLevel, LogLevelError, "Sending AuthorizationCode in POST: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log(oidcAuth.Config.LogLevel, LogLevelError, "Received bad HTTP response from Provider: %s", string(body))
		return nil, err
	}

	tokenResponse := &OidcTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		log(oidcAuth.Config.LogLevel, LogLevelError, "Decoding OidcTokenResponse: %s", err.Error())
		return nil, err
	}

	return tokenResponse, nil
}

func (toa *TraefikOidcAuth) validateTokenLocally(tokenString string) (bool, map[string]interface{}, error) {
	claims := jwt.MapClaims{}

	err := toa.Jwks.EnsureLoaded(toa, false)
	if err != nil {
		return false, nil, err
	}

	options := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
	}

	if toa.Config.Provider.ValidateIssuer {
		options = append(options, jwt.WithIssuer(toa.Config.Provider.ValidIssuer))
	}
	if toa.Config.Provider.ValidateAudience {
		options = append(options, jwt.WithAudience(toa.Config.Provider.ValidAudience))
	}

	parser := jwt.NewParser(options...)

	_, err = parser.ParseWithClaims(tokenString, claims, toa.Jwks.Keyfunc)

	if err != nil {
		err := toa.Jwks.EnsureLoaded(toa, true)
		if err != nil {
			return false, nil, err
		}

		_, err = parser.ParseWithClaims(tokenString, claims, toa.Jwks.Keyfunc)

		if err != nil {
			return false, nil, err
		}
	}

	return true, claims, nil
}

func (toa *TraefikOidcAuth) introspectToken(token string) (bool, map[string]interface{}, error) {
	client := &http.Client{}

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

	resp, err := client.Do(req)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Error on introspection request: %s", err.Error())
		return false, nil, err
	}

	defer resp.Body.Close()

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)

	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Failed to decode introspection response: %s", err.Error())
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

func (toa *TraefikOidcAuth) renewToken(refreshToken string) (*OidcTokenResponse, error) {
	urlValues := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {toa.Config.Provider.ClientId},
		"scope":         {strings.Join(toa.Config.Scopes, " ")},
		"refresh_token": {refreshToken},
	}

	if toa.Config.Provider.ClientSecret != "" {
		urlValues.Add("client_secret", toa.Config.Provider.ClientSecret)
	}

	resp, err := http.PostForm(toa.DiscoveryDocument.TokenEndpoint, urlValues)

	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Sending token renewal request in POST: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log(toa.Config.LogLevel, LogLevelError, "Received bad HTTP response from Provider: %s", string(body))
		return nil, err
	}

	tokenResponse := &OidcTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		log(toa.Config.LogLevel, LogLevelError, "Decoding OidcTokenResponse: %s", err.Error())
		return nil, err
	}

	return tokenResponse, nil
}
