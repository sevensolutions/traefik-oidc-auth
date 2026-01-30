package src

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sevensolutions/traefik-oidc-auth/src/errorPages"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/rules"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

const DefaultSecret = "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

type Config struct {
	LogLevel string `json:"log_level"`

	Secret string `json:"secret"`

	Provider *ProviderConfig `json:"provider"`
	Scopes   []string        `json:"scopes"`

	// Can be a relative path or a full URL.
	// If a relative path is used, the scheme and domain will be taken from the incoming request.
	// In this case, the callback path will overlay all hostnames behind the middleware.
	// If a full URL is used, all callbacks are sent there.  It is the user's responsibility to ensure
	// that the callback URL is also routed to this middleware plugin.
	CallbackUri string `json:"callback_uri"`

	// The URL used to start authorization when needed.
	// All other requests that are not already authorized will return a 401 Unauthorized.
	// When left empty, all requests can start authorization.
	LoginUri                    string   `json:"login_uri"`
	PostLoginRedirectUri        string   `json:"post_login_redirect_uri"`
	ValidPostLoginRedirectUris  []string `json:"valid_post_login_redirect_uris"`
	LogoutUri                   string   `json:"logout_uri"`
	PostLogoutRedirectUri       string   `json:"post_logout_redirect_uri"`
	ValidPostLogoutRedirectUris []string `json:"valid_post_logout_redirect_uris"`

	CookieNamePrefix     string                     `json:"cookie_name_prefix"`
	SessionCookie        *SessionCookieConfig       `json:"session_cookie"`
	AuthorizationHeader  *AuthorizationHeaderConfig `json:"authorization_header"`
	AuthorizationCookie  *AuthorizationCookieConfig `json:"authorization_cookie"`
	UnauthorizedBehavior string                     `json:"unauthorized_behavior"`

	Authorization *AuthorizationConfig `json:"authorization"`

	Headers []HeaderConfig `json:"headers"`

	BypassAuthenticationRule string `json:"bypass_authentication_rule"`

	ErrorPages *errorPages.ErrorPagesConfig `json:"error_pages"`

	RequestedResources []string `json:"requested_resources"`
}

type ProviderConfig struct {
	Url string `json:"url"`

	InsecureSkipVerify     string `json:"insecure_skip_verify"`
	InsecureSkipVerifyBool bool   `json:"insecure_skip_verify_bool"`

	CABundle     string `json:"ca_bundle"`
	CABundleFile string `json:"ca_bundle_file"`

	ClientId              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	ClientJwtPrivateKey   string `json:"client_jwt_private_key"`
	ClientJwtPrivateKeyId string `json:"client_jwt_private_key_id"`

	UsePkce     string `json:"use_pkce"`
	UsePkceBool bool   `json:"use_pkce_bool"`

	ValidateAudience     string `json:"validate_audience"`
	ValidateAudienceBool bool   `json:"validate_audience_bool"`
	ValidAudience        string `json:"valid_audience"`

	ValidateIssuer     string `json:"validate_issuer"`
	ValidateIssuerBool bool   `json:"validate_issuer_bool"`
	ValidIssuer        string `json:"valid_issuer"`

	// AccessToken or IdToken or Introspection
	TokenValidation string `json:"verification_token"`

	TokenRenewalThreshold float64 `json:"token_renewal_threshold"`

	UseClaimsFromUserInfo     string `json:"use_claims_from_user_info"`
	UseClaimsFromUserInfoBool bool   `json:"use_claims_from_user_info_bool"`
}

type SessionCookieConfig struct {
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
	MaxAge   int    `json:"max_age"`
}

type AuthorizationHeaderConfig struct {
	Name string `json:"name"`
}
type AuthorizationCookieConfig struct {
	Name string `json:"name"`
}

type AuthorizationConfig struct {
	AssertClaims        []ClaimAssertion `json:"assert_claims"`
	CheckOnEveryRequest bool             `json:"check_on_every_request"`
}

type ClaimAssertion struct {
	Name  string   `json:"name"`
	AnyOf []string `json:"anyOf"`
	AllOf []string `json:"allOf"`
}

type HeaderConfig struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Values string `json:"values"`

	// A reference to the parsed Value-template
	template *template.Template
}

// Will be called by traefik
func CreateConfig() *Config {
	return &Config{
		LogLevel: logging.LevelWarn,
		Secret:   DefaultSecret,
		Provider: &ProviderConfig{
			UsePkceBool:               false,
			InsecureSkipVerifyBool:    false,
			ValidateIssuerBool:        true,
			ValidateAudienceBool:      true,
			TokenValidation:           "IdToken",
			TokenRenewalThreshold:     0.75,
			UseClaimsFromUserInfoBool: false,
		},
		// Note: It looks like we're not allowed to specify a default value for arrays here.
		// Maybe a traefik bug. So I've moved this to the New() method.
		//Scopes:                []string{"openid", "profile", "email"},
		CallbackUri:           "/oidc/callback",
		LogoutUri:             "/logout",
		PostLogoutRedirectUri: "/",
		CookieNamePrefix:      "TraefikOidcAuth",
		SessionCookie: &SessionCookieConfig{
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "default",
			MaxAge:   0,
		},
		AuthorizationHeader:  &AuthorizationHeaderConfig{},
		AuthorizationCookie:  &AuthorizationCookieConfig{},
		UnauthorizedBehavior: "Auto",
		Authorization: &AuthorizationConfig{
			CheckOnEveryRequest: false,
		},
		ErrorPages: &errorPages.ErrorPagesConfig{
			Unauthenticated: &errorPages.ErrorPageConfig{},
			Unauthorized:    &errorPages.ErrorPageConfig{},
		},
	}
}

// Will be called by traefik
func New(uctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	config.LogLevel = utils.ExpandEnvironmentVariableString(config.LogLevel)

	logger := logging.CreateLogger(config.LogLevel)

	logger.Log(logging.LevelInfo, "Loading Configuration...")

	if config.Provider == nil {
		return nil, errors.New("missing provider configuration")
	}

	// Hack: Trick the traefik plugin catalog to successfully execute this method with the testData from .traefik.yml.
	if config.Provider.Url == "https://..." {
		return &TraefikOidcAuth{
			next: next,
		}, nil
	}

	var err error

	config.Secret = utils.ExpandEnvironmentVariableString(config.Secret)
	config.CallbackUri = utils.ExpandEnvironmentVariableString(config.CallbackUri)
	config.LoginUri = utils.ExpandEnvironmentVariableString(config.LoginUri)
	config.PostLoginRedirectUri = utils.ExpandEnvironmentVariableString(config.PostLoginRedirectUri)
	config.LogoutUri = utils.ExpandEnvironmentVariableString(config.LogoutUri)
	config.PostLogoutRedirectUri = utils.ExpandEnvironmentVariableString(config.PostLogoutRedirectUri)
	config.CookieNamePrefix = utils.ExpandEnvironmentVariableString(config.CookieNamePrefix)
	config.UnauthorizedBehavior = utils.ExpandEnvironmentVariableString(config.UnauthorizedBehavior)
	config.BypassAuthenticationRule = utils.ExpandEnvironmentVariableString(config.BypassAuthenticationRule)
	config.Provider.Url = utils.ExpandEnvironmentVariableString(config.Provider.Url)
	config.Provider.ClientId = utils.ExpandEnvironmentVariableString(config.Provider.ClientId)
	config.Provider.ClientSecret = utils.ExpandEnvironmentVariableString(config.Provider.ClientSecret)
	config.Provider.ClientJwtPrivateKeyId = utils.ExpandEnvironmentVariableString(config.Provider.ClientJwtPrivateKeyId)
	config.Provider.ClientJwtPrivateKey = utils.ExpandEnvironmentVariableString(config.Provider.ClientJwtPrivateKey)
	config.Provider.UsePkceBool, err = utils.ExpandEnvironmentVariableBoolean(config.Provider.UsePkce, config.Provider.UsePkceBool)
	if err != nil {
		return nil, err
	}
	config.Provider.UseClaimsFromUserInfoBool, err = utils.ExpandEnvironmentVariableBoolean(config.Provider.UseClaimsFromUserInfo, config.Provider.UseClaimsFromUserInfoBool)
	if err != nil {
		return nil, err
	}
	config.Provider.ValidateIssuerBool, err = utils.ExpandEnvironmentVariableBoolean(config.Provider.ValidateIssuer, config.Provider.ValidateIssuerBool)
	if err != nil {
		return nil, err
	}
	config.Provider.ValidIssuer = utils.ExpandEnvironmentVariableString(config.Provider.ValidIssuer)
	config.Provider.ValidateAudienceBool, err = utils.ExpandEnvironmentVariableBoolean(config.Provider.ValidateAudience, config.Provider.ValidateAudienceBool)
	if err != nil {
		return nil, err
	}
	config.Provider.ValidAudience = utils.ExpandEnvironmentVariableString(config.Provider.ValidAudience)
	config.Provider.InsecureSkipVerifyBool, err = utils.ExpandEnvironmentVariableBoolean(config.Provider.InsecureSkipVerify, config.Provider.InsecureSkipVerifyBool)
	if err != nil {
		return nil, err
	}

	var clientAssertionPrivateKey *rsa.PrivateKey
	if config.Provider.ClientJwtPrivateKey != "" && config.Provider.ClientJwtPrivateKeyId != "" {
		clientAssertionPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(config.Provider.ClientJwtPrivateKey))
		if err != nil {
			return nil, err
		}
	}

	config.Provider.CABundle = utils.ExpandEnvironmentVariableString(config.Provider.CABundle)
	config.Provider.CABundleFile = utils.ExpandEnvironmentVariableString(config.Provider.CABundleFile)
	config.Provider.TokenValidation = utils.ExpandEnvironmentVariableString(config.Provider.TokenValidation)

	config.ErrorPages.Unauthenticated.FilePath = utils.ExpandEnvironmentVariableString(config.ErrorPages.Unauthenticated.FilePath)
	config.ErrorPages.Unauthenticated.RedirectTo = utils.ExpandEnvironmentVariableString(config.ErrorPages.Unauthenticated.RedirectTo)
	config.ErrorPages.Unauthorized.FilePath = utils.ExpandEnvironmentVariableString(config.ErrorPages.Unauthorized.FilePath)
	config.ErrorPages.Unauthorized.RedirectTo = utils.ExpandEnvironmentVariableString(config.ErrorPages.Unauthorized.RedirectTo)

	if config.Secret == DefaultSecret {
		logger.Log(logging.LevelWarn, "You're using the default secret! It is highly recommended to change the secret by specifying a random 32 character value using the Secret-option.")
	}

	secret := []byte(config.Secret)
	if len(secret) != 32 {
		logger.Log(logging.LevelError, "Invalid secret provided. Secret must be exactly 32 characters in length. The provided secret has %d characters.", len(secret))
		return nil, errors.New("invalid secret")
	}

	if config.Provider.CABundle != "" && config.Provider.CABundleFile != "" {
		logger.Log(logging.LevelError, "You can only use an inline CABundle OR CABundleFile, not both.")
		return nil, errors.New("you can only use an inline CABundle OR CABundleFile, not both.")
	}

	// Specify default scopes if not provided
	if config.Scopes == nil || len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email"}
	}

	parsedURL, err := utils.ParseUrl(config.Provider.Url)
	if err != nil {
		logger.Log(logging.LevelError, "Error while parsing Provider.Url: %s", err.Error())
		return nil, err
	}

	parsedCallbackURL, err := url.Parse(config.CallbackUri)
	if err != nil {
		logger.Log(logging.LevelError, "Error while parsing CallbackUri: %s", err.Error())
		return nil, err
	}

	logger.Log(logging.LevelInfo, "Provider Url: %v", parsedURL)
	logger.Log(logging.LevelInfo, "I will use this URL for callbacks from the IDP: %v", parsedCallbackURL)
	if utils.UrlIsAbsolute(parsedCallbackURL) {
		logger.Log(logging.LevelInfo, "Callback URL is absolute, will not overlay wrapped services")
	} else {
		logger.Log(logging.LevelInfo, "Callback URL is relative, will overlay any wrapped host")
	}
	logger.Log(logging.LevelDebug, "Scopes: %s", strings.Join(config.Scopes, ", "))
	logger.Log(logging.LevelDebug, "SessionCookie: %v", config.SessionCookie)

	if config.Provider.TokenRenewalThreshold < 0.5 || config.Provider.TokenRenewalThreshold > 1.0 {
		logger.Log(logging.LevelError, "Invalid TokenRenewalThreshold. The value must be >= 0.5 and <= 1.0.")
		return nil, errors.New("invalid TokenRenewalThreshold")
	}

	var conditionalAuth *rules.RequestCondition
	if config.BypassAuthenticationRule != "" {
		ca, err := rules.ParseRequestCondition(config.BypassAuthenticationRule)

		if err != nil {
			return nil, err
		}

		conditionalAuth = ca
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	var caBundleData []byte

	if config.Provider.CABundle != "" {
		if strings.HasPrefix(config.Provider.CABundle, "base64:") {
			caBundleData, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(config.Provider.CABundle, "base64:"))
			if err != nil {
				logger.Log(logging.LevelInfo, "Failed to base64-decode the inline CA bundle")
				return nil, err
			}
		} else {
			caBundleData = []byte(config.Provider.CABundle)
		}

		logger.Log(logging.LevelDebug, "Loaded CA bundle provided inline")
	} else if config.Provider.CABundleFile != "" {
		caBundleData, err = os.ReadFile(config.Provider.CABundleFile)
		if err != nil {
			logger.Log(logging.LevelInfo, "Failed to load CA bundle from %v: %v", config.Provider.CABundleFile, err)
			return nil, err
		}

		logger.Log(logging.LevelDebug, "Loaded CA bundle from %v", config.Provider.CABundleFile)
	}

	if caBundleData != nil {
		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(caBundleData); !ok {
			logger.Log(logging.LevelWarn, "Failed to append CA bundle. Using system certificates only.")
		}

	}

	for _, header := range config.Headers {
		if header.Value != "" && header.Values != "" {
			logger.Log(logging.LevelError, "Invalid Header: you can only use one of Value or Values, not both")
			return nil, errors.New("invalid Header")
		}
	}

	httpTransport := &http.Transport{
		// MaxIdleConns:    10,
		// IdleConnTimeout: 30 * time.Second,
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Provider.InsecureSkipVerifyBool,
			RootCAs:            rootCAs,
		},
	}

	httpClient := &http.Client{
		Transport: httpTransport,
	}

	logger.Log(logging.LevelInfo, "Configuration loaded successfully, starting OIDC Auth middleware...")

	return &TraefikOidcAuth{
		logger:                   logger,
		next:                     next,
		httpClient:               httpClient,
		ProviderURL:              parsedURL,
		ClientJwtPrivateKey:      clientAssertionPrivateKey,
		CallbackURL:              parsedCallbackURL,
		Config:                   config,
		SessionStorage:           session.CreateCookieSessionStorage(),
		BypassAuthenticationRule: conditionalAuth,
	}, nil
}
