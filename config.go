package traefik_oidc_auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
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

	SessionCookie        *SessionCookieConfig       `json:"session_cookie"`
	AuthorizationHeader  *AuthorizationHeaderConfig `json:"authorization_header"`
	AuthorizationCookie  *AuthorizationCookieConfig `json:"authorization_cookie"`
	UnauthorizedBehavior string                     `json:"unauthorized_behavior"`

	Authorization *AuthorizationConfig `json:"authorization"`

	Headers []HeaderConfig `json:"headers"`
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

type SessionCookieConfig struct {
	Name     string `json:"name"`
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
		LogoutUri:             "/logout",
		PostLogoutRedirectUri: "/",
		SessionCookie: &SessionCookieConfig{
			Name:     "Authorization",
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

	parsedCallbackURL, err := url.Parse(config.CallbackUri)
	if err != nil {
		log(config.LogLevel, LogLevelError, "Error while parsing CallbackUri: %s", err.Error())
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

	log(config.LogLevel, LogLevelInfo, "Provider Url: %v", parsedURL)
	log(config.LogLevel, LogLevelInfo, "I will use this URL for callbacks from the IDP: %v", parsedCallbackURL)
	if urlIsAbsolute(parsedCallbackURL) {
		log(config.LogLevel, LogLevelInfo, "Callback URL is absolute, will not overlay wrapped services")
	} else {
		log(config.LogLevel, LogLevelInfo, "Callback URL is relative, will overlay any wrapped host")
	}
	log(config.LogLevel, LogLevelDebug, "Scopes: %s", strings.Join(config.Scopes, ", "))
	log(config.LogLevel, LogLevelDebug, "SessionCookie: %v", config.SessionCookie)

	log(config.LogLevel, LogLevelInfo, "Configuration loaded successfully, starting OIDC Auth middleware...")
	return &TraefikOidcAuth{
		next:           next,
		ProviderURL:    parsedURL,
		CallbackURL:    parsedCallbackURL,
		Config:         config,
		SessionStorage: CreateCookieSessionStorage(),
	}, nil
}
