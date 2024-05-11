package traefik_oidc_auth

import (
	"context"
	"net/http"
)

type Config struct {
	ProviderURL        string `json:"url"`
	ClientID           string `json:"client_id"`
	ClientSecret       string `json:"client_secret"`
	RedirectUri        string `json:"redirect_uri"`
	LogoutUri          string `json:"logout_uri"`
	UsernameClaim      string `json:"user_claim_name"`
	UsernameHeaderName string `json:"user_header_name"`
	ClientIDFile       string `json:"client_id_file"`
	ClientSecretFile   string `json:"client_secret_file"`
	ProviderURLEnv     string `json:"url_env"`
	ClientIDEnv        string `json:"client_id_env"`
	ClientSecretEnv    string `json:"client_secret_env"`
}

func CreateConfig() *Config {
	return &Config{
		RedirectUri:   "/oidc/callback",
		LogoutUri:     "/logout",
		UsernameClaim: "preferred_username",
	}
}

func New(uctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log("INFO", "Loading Configuration...")

	parsedURL, err := parseUrl(config.ProviderURL)
	if err != nil {
		log("ERROR", "Error while parsing ProviderURL: %s", err.Error())
		return nil, err
	}

	oidcDiscoveryDocument, err := GetOidcDiscovery(parsedURL)
	if err != nil {
		log("ERROR", "Error while retrieving discovery document: %s", err.Error())
		return nil, err
	}

	log("INFO", "OIDC Discovery successfull. AuthEndPoint: %s", oidcDiscoveryDocument.AuthorizationEndpoint)

	log("INFO", "Configuration loaded. ProviderURL: %v", parsedURL)

	return &TraefikOidcAuth{
		next:              next,
		ProviderURL:       parsedURL,
		Config:            config,
		DiscoveryDocument: oidcDiscoveryDocument,
	}, nil
}
