package traefik_oidc_auth

import (
	"context"
	"errors"
	"net/http"
	"os"
)

const (
	LogLevelDebug string = "DEBUG"
	LogLevelInfo  string = "INFO"
	LogLevelWarn  string = "WARN"
	LogLevelError string = "ERROR"
)

type Config struct {
	LogLevel string `json:"log_level"`

	Provider *ProviderConfig `json:"provider"`
	Scopes   []string        `json:"scopes"`

	CallbackUri string `json:"callback_uri"`

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
	Url             string `json:"url"`
	UrlEnv          string `json:"url_env"`
	ClientId        string `json:"client_id"`
	ClientIdEnv     string `json:"client_id_env"`
	ClientSecret    string `json:"client_secret"`
	ClientSecretEnv string `json:"client_secret_env"`
}

type StateCookieConfig struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

type AuthorizationConfig struct {
	AssertClaims []ClaimAssertion `json:"assert_claims"`
}

type ClaimAssertion struct {
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Values []string `json:"values"`
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
		LogLevel:              LogLevelError,
		Provider:              &ProviderConfig{},
		Scopes:                []string{"openid"},
		CallbackUri:           "/oidc/callback",
		LogoutUri:             "/logout",
		PostLogoutRedirectUri: "/",
		StateCookie: &StateCookieConfig{
			Name:     "Authorization",
			Path:     "/",
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

	parsedURL, err := parseUrl(config.Provider.Url)
	if err != nil {
		log(config.LogLevel, LogLevelError, "Error while parsing Provider.Url: %s", err.Error())
		return nil, err
	}

	oidcDiscoveryDocument, err := GetOidcDiscovery(config.LogLevel, parsedURL)
	if err != nil {
		log(config.LogLevel, LogLevelError, "Error while retrieving discovery document: %s", err.Error())
		return nil, err
	}

	log(config.LogLevel, LogLevelInfo, "OIDC Discovery successfull. AuthEndPoint: %s", oidcDiscoveryDocument.AuthorizationEndpoint)

	log(config.LogLevel, LogLevelInfo, "Configuration loaded. Provider Url: %v", parsedURL)

	return &TraefikOidcAuth{
		next:              next,
		ProviderURL:       parsedURL,
		Config:            config,
		DiscoveryDocument: oidcDiscoveryDocument,
	}, nil
}
