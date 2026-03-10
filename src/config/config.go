package config

import (
	"text/template"

	"github.com/sevensolutions/traefik-oidc-auth/src/errorPages"
)

const DefaultSecret = "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

const (
	SessionStorageTypeCookie string = "Cookie"
)

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

	SessionStorageType string `json:"session_storage_type"`

	CookieNamePrefix     string                     `json:"cookie_name_prefix"`
	SessionCookie        *SessionCookieConfig       `json:"session_cookie"`
	AuthorizationHeader  *AuthorizationHeaderConfig `json:"authorization_header"`
	AuthorizationCookie  *AuthorizationCookieConfig `json:"authorization_cookie"`
	UnauthorizedBehavior string                     `json:"unauthorized_behavior"`

	UnauthorizedPassthrough     string `json:"unauthorized_passthrough"`
	UnauthorizedPassthroughBool bool   `json:"unauthorized_passthrough_bool"`

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
	Template *template.Template
}
