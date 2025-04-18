package traefik_oidc_auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/sevensolutions/traefik-oidc-auth/logging"
	"github.com/sevensolutions/traefik-oidc-auth/rules"
	"github.com/sevensolutions/traefik-oidc-auth/session"
	"github.com/sevensolutions/traefik-oidc-auth/utils"
)

const DefaultSecret = "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

type Config struct {
	LogLevel string `json:"log_level"`

	Secret    string `json:"secret"`
	SecretEnv string `json:"secret_env"`

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
	LoginUri              string `json:"login_uri"`
	PostLoginRedirectUri  string `json:"post_login_redirect_uri"`
	LogoutUri             string `json:"logout_uri"`
	PostLogoutRedirectUri string `json:"post_logout_redirect_uri"`

	CookieNamePrefix     string                     `json:"cookie_name_prefix"`
	SessionCookie        *SessionCookieConfig       `json:"session_cookie"`
	AuthorizationHeader  *AuthorizationHeaderConfig `json:"authorization_header"`
	AuthorizationCookie  *AuthorizationCookieConfig `json:"authorization_cookie"`
	UnauthorizedBehavior string                     `json:"unauthorized_behavior"`

	Authorization *AuthorizationConfig `json:"authorization"`

	Headers []HeaderConfig `json:"headers"`

	BypassAuthenticationRule string
}

type ProviderConfig struct {
	Url    string `json:"url"`
	UrlEnv string `json:"url_env"`

	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	CABundle           string `json:"ca_bundle"`
	CABundleFile       string `json:"ca_bundle_file"`
	CABundleFileEnv    string `json:"ca_bundle_file_env"`

	ClientId        string `json:"client_id"`
	ClientIdEnv     string `json:"client_id_env"`
	ClientSecret    string `json:"client_secret"`
	ClientSecretEnv string `json:"client_secret_env"`

	UsePkce bool `json:"use_pkce"`

	ValidateAudience bool   `json:"validate_audience"`
	ValidAudience    string `json:"valid_audience"`
	ValidAudienceEnv string `json:"valid_audience_env"`

	ValidateIssuer bool   `json:"validate_issuer"`
	ValidIssuer    string `json:"valid_issuer"`
	ValidIssuerEnv string `json:"valid_issuer_env"`

	// AccessToken or IdToken or Introspection
	TokenValidation string `json:"verification_token"`
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
	AssertClaims []ClaimAssertion `json:"assert_claims"`
}

type ClaimAssertion struct {
	Name  string   `json:"name"`
	AnyOf []string `json:"anyOf"`
	AllOf []string `json:"allOf"`
}

type HeaderConfig struct {
	Name  string `json:"name"`
	Value string `json:"value"`

	// A reference to the parsed Value-template
	template *template.Template
}

// Will be called by traefik
func CreateConfig() *Config {
	return &Config{
		LogLevel: logging.LevelWarn,
		Secret:   DefaultSecret,
		Provider: &ProviderConfig{
			ValidateIssuer:   true,
			ValidateAudience: true,
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
		UnauthorizedBehavior: "Challenge",
		Authorization:        &AuthorizationConfig{},
	}
}

// Will be called by traefik
func New(uctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
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

	if (config.Secret == "" || config.Secret == DefaultSecret) && config.SecretEnv != "" {
		config.Secret = os.Getenv(config.SecretEnv)
	}
	if config.Provider.Url == "" && config.Provider.UrlEnv != "" {
		config.Provider.Url = os.Getenv(config.Provider.UrlEnv)
	}
	if config.Provider.ClientId == "" && config.Provider.ClientIdEnv != "" {
		config.Provider.ClientId = os.Getenv(config.Provider.ClientIdEnv)
	}
	if config.Provider.ClientSecret == "" && config.Provider.ClientSecretEnv != "" {
		config.Provider.ClientSecret = os.Getenv(config.Provider.ClientSecretEnv)
	}
	if config.Provider.ValidIssuer == "" && config.Provider.ValidIssuerEnv != "" {
		config.Provider.ValidIssuer = os.Getenv(config.Provider.ValidIssuerEnv)
	}
	if config.Provider.ValidAudience == "" && config.Provider.ValidAudienceEnv != "" {
		config.Provider.ValidAudience = os.Getenv(config.Provider.ValidAudienceEnv)
	}
	if config.Provider.CABundleFile == "" && config.Provider.CABundleFileEnv != "" {
		config.Provider.CABundleFile = os.Getenv(config.Provider.CABundleFileEnv)
	}

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

	if config.Provider.TokenValidation == "" {
		// For EntraID, we cannot validate the access token using JWKS, so we fall back to the id token by default
		if strings.HasPrefix(config.Provider.Url, "https://login.microsoftonline.com") {
			config.Provider.TokenValidation = "IdToken"
		} else {
			config.Provider.TokenValidation = "AccessToken"
		}
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

	httpTransport := &http.Transport{
		// MaxIdleConns:    10,
		// IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Provider.InsecureSkipVerify,
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
		CallbackURL:              parsedCallbackURL,
		Config:                   config,
		SessionStorage:           session.CreateCookieSessionStorage(),
		BypassAuthenticationRule: conditionalAuth,
	}, nil
}
