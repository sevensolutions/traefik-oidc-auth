package traefik_oidc_auth

import (
	"context"
	"errors"
	"net/http"
	"os"
)

type Config struct {
	Provider *ProviderConfig `json:"provider"`
	Scopes   []string        `json:"scopes"`

	RedirectUri string `json:"redirect_uri"`

	// The URL used to start authorization when needed.
	// All other requests that are not already authorized will return a 401 Unauthorized.
	// When left empty, all requests can start authorization.
	LoginUri              string `json:"login_uri"`
	PostLoginRedirectUri  string `json:"post_login_redirect_uri"`
	LogoutUri             string `json:"logout_uri"`
	PostLogoutRedirectUri string `json:"post_logout_redirect_uri"`

	StateCookie *StateCookieConfig `json:"state_cookie"`

	UsernameClaim      string `json:"user_claim_name"`
	UsernameHeaderName string `json:"user_header_name"`
}

type ProviderConfig struct {
	Url             string `json:"url"`
	UrlEnv          string `json:"url_env"`
	ClientID        string `json:"client_id"`
	ClientIDEnv     string `json:"client_id_env"`
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

func CreateConfig() *Config {
	return &Config{
		Scopes:                []string{"openid"},
		RedirectUri:           "/oidc/callback",
		LogoutUri:             "/logout",
		PostLogoutRedirectUri: "/",
		StateCookie: &StateCookieConfig{
			Name:     "Authorization",
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: "default",
		},
		UsernameClaim: "preferred_username",
	}
}

func New(uctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log("INFO", "Loading Configuration...")

	if config.Provider == nil {
		return nil, errors.New("missing provider configuration")
	}

	if config.Provider.Url == "" && config.Provider.UrlEnv != "" {
		log("DEBUG", "Using URL ENV")
		config.Provider.Url = os.Getenv(config.Provider.UrlEnv)
		log("DEBUG", "Using URL ENV"+config.Provider.Url)
	}
	if config.Provider.ClientID == "" && config.Provider.ClientIDEnv != "" {
		config.Provider.ClientID = os.Getenv(config.Provider.ClientIDEnv)
	}
	if config.Provider.ClientSecret == "" && config.Provider.ClientSecretEnv != "" {
		config.Provider.ClientSecret = os.Getenv(config.Provider.ClientSecretEnv)
	}

	parsedURL, err := parseUrl(config.Provider.Url)
	if err != nil {
		log("ERROR", "Error while parsing Provider.Url: %s", err.Error())
		return nil, err
	}

	oidcDiscoveryDocument, err := GetOidcDiscovery(parsedURL)
	if err != nil {
		log("ERROR", "Error while retrieving discovery document: %s", err.Error())
		return nil, err
	}

	log("INFO", "OIDC Discovery successfull. AuthEndPoint: %s", oidcDiscoveryDocument.AuthorizationEndpoint)

	log("INFO", "Configuration loaded. Provider.Url: %v", parsedURL)

	return &TraefikOidcAuth{
		next:              next,
		ProviderURL:       parsedURL,
		Config:            config,
		DiscoveryDocument: oidcDiscoveryDocument,
	}, nil
}
