package traefik_oidc_auth

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
)

const (
	LogLevelDebug string = "DEBUG"
	LogLevelInfo  string = "INFO"
	LogLevelWarn  string = "WARN"
	LogLevelError string = "ERROR"
)

var LogLevels = map[string]int{
	LogLevelError: 1,
	LogLevelWarn:  2,
	LogLevelInfo:  3,
	LogLevelDebug: 4,
}

type Config struct {
	LogLevel string `json:"log_level"`

	Secret string `json:"secret"`

	Provider *ProviderConfig `json:"provider"`
	Scopes   []string        `json:"scopes"`

	CallbackUri string `json:"callback_uri"`
	// If set, use a fixed callback domain to interface with the IDP.
	// Particularly useful when combined with StateCookie.Domain.
	CallbackDomain string `json:"callback_domain"`
	CallbackScheme string `json:"callback_scheme"`

	// The URL used to start authorization when needed.
	// All other requests that are not already authorized will return a 401 Unauthorized.
	// When left empty, all requests can start authorization.
	LoginUri              string `json:"login_uri"`
	PostLoginRedirectUri  string `json:"post_login_redirect_uri"`
	LogoutUri             string `json:"logout_uri"`
	PostLogoutRedirectUri string `json:"post_logout_redirect_uri"`

	StateCookie *StateCookieConfig `json:"state_cookie"`

	Authorization *AuthorizationConfig `json:"authorization"`

	Headers *HeadersConfig `json:"headers"`
}

type ProviderConfig struct {
	Url    string `json:"url"`
	UrlEnv string `json:"url_env"`

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

type StateCookieConfig struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

type AuthorizationConfig struct {
	AssertClaims []ClaimAssertion `json:"assert_claims"`
}

type ClaimAssertion struct {
	Name  string   `json:"name"`
	AnyOf []string `json:"anyOf"`
	AllOf []string `json:"allOf"`
}

type HeadersConfig struct {
	MapClaims []ClaimHeaderConfig `json:"map_claims"`
}

type ClaimHeaderConfig struct {
	Claim  string `json:"claim"`
	Header string `json:"header"`
}

// Will be called by traefik
func CreateConfig() *Config {
	return &Config{
		LogLevel: LogLevelError,
		Secret:   "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ",
		Provider: &ProviderConfig{
			ValidateIssuer:   true,
			ValidateAudience: true,
		},
		// Note: It looks like we're not allowed to specify a default value for arrays here.
		// Maybe a traefik bug. So I've moved this to the New() method.
		//Scopes:                []string{"openid", "profile", "email"},
		CallbackUri:           "/oidc/callback",
		CallbackDomain:        "",
		CallbackScheme:        "",
		LogoutUri:             "/logout",
		PostLogoutRedirectUri: "/",
		StateCookie: &StateCookieConfig{
			Name:     "Authorization",
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "default",
		},
		Authorization: &AuthorizationConfig{},
		Headers:       &HeadersConfig{},
	}
}

// Will be called by traefik
func New(uctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log(config.LogLevel, LogLevelInfo, "Loading Configuration...")

	if config.Provider == nil {
		return nil, errors.New("missing provider configuration")
	}

	// Hack: Trick to traefik plugin catalog to successfully execute this method with the testData from .traefik.yml.
	if config.Provider.Url == "https://..." {
		return &TraefikOidcAuth{
			next: next,
		}, nil
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

	// Specify default scopes if not provided
	if config.Scopes == nil || len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email"}
	}

	parsedURL, err := parseUrl(config.Provider.Url)
	if err != nil {
		log(config.LogLevel, LogLevelError, "Error while parsing Provider.Url: %s", err.Error())
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

	log(config.LogLevel, LogLevelInfo, "Configuration loaded. Provider Url: %v", parsedURL)
	log(config.LogLevel, LogLevelDebug, "Scopes: %s", strings.Join(config.Scopes, ", "))
	log(config.LogLevel, LogLevelDebug, "StateCookie: %v", config.StateCookie)

	return &TraefikOidcAuth{
		next:           next,
		ProviderURL:    parsedURL,
		Config:         config,
		SessionStorage: CreateCookieSessionStorage(),
	}, nil
}
