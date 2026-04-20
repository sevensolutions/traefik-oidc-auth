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

	"github.com/golang-jwt/jwt/v5"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/errorPages"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/rules"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

// Will be called by traefik
func CreateConfig() *config.Config {
	return &config.Config{
		LogLevel: logging.LevelWarn,
		Secret:   config.DefaultSecret,
		Provider: &config.ProviderConfig{
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
		SessionCookie: &config.SessionCookieConfig{
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "default",
			MaxAge:   0,
		},
		AuthorizationHeader:  &config.AuthorizationHeaderConfig{},
		AuthorizationCookie:  &config.AuthorizationCookieConfig{},
		UnauthorizedBehavior: "Auto",
		Authorization: &config.AuthorizationConfig{
			CheckOnEveryRequest: false,
		},
		ErrorPages: &errorPages.ErrorPagesConfig{
			Unauthenticated: &errorPages.ErrorPageConfig{},
			Unauthorized:    &errorPages.ErrorPageConfig{},
		},
	}
}

// Will be called by traefik
func New(uctx context.Context, next http.Handler, cfg *config.Config, name string) (http.Handler, error) {
	cfg.LogLevel = utils.ExpandEnvironmentVariableString(cfg.LogLevel)

	logger := logging.CreateLogger(cfg.LogLevel)

	logger.Log(logging.LevelInfo, "Loading Configuration...")

	if cfg.Provider == nil {
		return nil, errors.New("missing provider configuration")
	}

	// Hack: Trick the traefik plugin catalog to successfully execute this method with the testData from .traefik.yml.
	if cfg.Provider.Url == "https://..." {
		return &TraefikOidcAuth{
			next: next,
		}, nil
	}

	var err error

	cfg.Secret = utils.ExpandEnvironmentVariableString(cfg.Secret)
	cfg.CallbackUri = utils.ExpandEnvironmentVariableString(cfg.CallbackUri)
	cfg.LoginUri = utils.ExpandEnvironmentVariableString(cfg.LoginUri)
	cfg.PostLoginRedirectUri = utils.ExpandEnvironmentVariableString(cfg.PostLoginRedirectUri)
	cfg.LogoutUri = utils.ExpandEnvironmentVariableString(cfg.LogoutUri)
	cfg.PostLogoutRedirectUri = utils.ExpandEnvironmentVariableString(cfg.PostLogoutRedirectUri)
	cfg.CookieNamePrefix = utils.ExpandEnvironmentVariableString(cfg.CookieNamePrefix)
	cfg.UnauthorizedBehavior = utils.ExpandEnvironmentVariableString(cfg.UnauthorizedBehavior)
	cfg.BypassAuthenticationRule = utils.ExpandEnvironmentVariableString(cfg.BypassAuthenticationRule)
	cfg.Provider.Url = utils.ExpandEnvironmentVariableString(cfg.Provider.Url)
	cfg.Provider.ClientId = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientId)
	cfg.Provider.ClientSecret = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientSecret)
	cfg.Provider.ClientJwtPrivateKeyId = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientJwtPrivateKeyId)
	cfg.Provider.ClientJwtPrivateKey = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientJwtPrivateKey)
	cfg.Provider.UsePkceBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.UsePkce, cfg.Provider.UsePkceBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.UseClaimsFromUserInfoBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.UseClaimsFromUserInfo, cfg.Provider.UseClaimsFromUserInfoBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidateIssuerBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.ValidateIssuer, cfg.Provider.ValidateIssuerBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidIssuer = utils.ExpandEnvironmentVariableString(cfg.Provider.ValidIssuer)
	cfg.Provider.ValidateAudienceBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.ValidateAudience, cfg.Provider.ValidateAudienceBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidAudience = utils.ExpandEnvironmentVariableString(cfg.Provider.ValidAudience)
	cfg.Provider.InsecureSkipVerifyBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.InsecureSkipVerify, cfg.Provider.InsecureSkipVerifyBool)
	if err != nil {
		return nil, err
	}

	var clientAssertionPrivateKey *rsa.PrivateKey
	if cfg.Provider.ClientJwtPrivateKey != "" && cfg.Provider.ClientJwtPrivateKeyId != "" {
		clientAssertionPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.Provider.ClientJwtPrivateKey))
		if err != nil {
			return nil, err
		}
	}

	cfg.Provider.CABundle = utils.ExpandEnvironmentVariableString(cfg.Provider.CABundle)
	cfg.Provider.CABundleFile = utils.ExpandEnvironmentVariableString(cfg.Provider.CABundleFile)
	cfg.Provider.TokenValidation = utils.ExpandEnvironmentVariableString(cfg.Provider.TokenValidation)

	cfg.ErrorPages.Unauthenticated.FilePath = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthenticated.FilePath)
	cfg.ErrorPages.Unauthenticated.RedirectTo = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthenticated.RedirectTo)
	cfg.ErrorPages.Unauthorized.FilePath = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthorized.FilePath)
	cfg.ErrorPages.Unauthorized.RedirectTo = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthorized.RedirectTo)

	if cfg.Secret == config.DefaultSecret {
		logger.Log(logging.LevelWarn, "You're using the default secret! It is highly recommended to change the secret by specifying a random 32 character value using the Secret-option.")
	}

	secret := []byte(cfg.Secret)
	if len(secret) != 32 {
		logger.Log(logging.LevelError, "Invalid secret provided. Secret must be exactly 32 characters in length. The provided secret has %d characters.", len(secret))
		return nil, errors.New("invalid secret")
	}

	if cfg.Provider.CABundle != "" && cfg.Provider.CABundleFile != "" {
		logger.Log(logging.LevelError, "You can only use an inline CABundle OR CABundleFile, not both.")
		return nil, errors.New("you can only use an inline CABundle OR CABundleFile, not both.")
	}

	// Specify default scopes if not provided
	if cfg.Scopes == nil || len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	parsedURL, err := utils.ParseUrl(cfg.Provider.Url)
	if err != nil {
		logger.Log(logging.LevelError, "Error while parsing Provider.Url: %s", err.Error())
		return nil, err
	}

	parsedCallbackURL, err := url.Parse(cfg.CallbackUri)
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
	logger.Log(logging.LevelDebug, "Scopes: %s", strings.Join(cfg.Scopes, ", "))
	logger.Log(logging.LevelDebug, "SessionCookie: %v", cfg.SessionCookie)

	if cfg.Provider.TokenRenewalThreshold < 0.5 || cfg.Provider.TokenRenewalThreshold > 1.0 {
		logger.Log(logging.LevelError, "Invalid TokenRenewalThreshold. The value must be >= 0.5 and <= 1.0.")
		return nil, errors.New("invalid TokenRenewalThreshold")
	}

	var conditionalAuth *rules.RequestCondition
	if cfg.BypassAuthenticationRule != "" {
		ca, err := rules.ParseRequestCondition(cfg.BypassAuthenticationRule)

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

	if cfg.Provider.CABundle != "" {
		if strings.HasPrefix(cfg.Provider.CABundle, "base64:") {
			caBundleData, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(cfg.Provider.CABundle, "base64:"))
			if err != nil {
				logger.Log(logging.LevelInfo, "Failed to base64-decode the inline CA bundle")
				return nil, err
			}
		} else {
			caBundleData = []byte(cfg.Provider.CABundle)
		}

		logger.Log(logging.LevelDebug, "Loaded CA bundle provided inline")
	} else if cfg.Provider.CABundleFile != "" {
		caBundleData, err = os.ReadFile(cfg.Provider.CABundleFile)
		if err != nil {
			logger.Log(logging.LevelInfo, "Failed to load CA bundle from %v: %v", cfg.Provider.CABundleFile, err)
			return nil, err
		}

		logger.Log(logging.LevelDebug, "Loaded CA bundle from %v", cfg.Provider.CABundleFile)
	}

	if caBundleData != nil {
		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(caBundleData); !ok {
			logger.Log(logging.LevelWarn, "Failed to append CA bundle. Using system certificates only.")
		}

	}

	for _, header := range cfg.Headers {
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
			InsecureSkipVerify: cfg.Provider.InsecureSkipVerifyBool,
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
		Config:                   cfg,
		SessionStorage:           session.CreateCookieSessionStorage(),
		BypassAuthenticationRule: conditionalAuth,
	}, nil
}
