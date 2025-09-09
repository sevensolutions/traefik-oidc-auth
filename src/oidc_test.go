package src

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
)

func newGetUserInfoTest(t *testing.T, handler http.HandlerFunc) (*TraefikOidcAuth, *httptest.Server) {
	server := httptest.NewServer(handler)

	config := &Config{
		Provider: &ProviderConfig{},
		Scopes:   []string{"openid"},
	}

	logger := logging.CreateLogger(logging.LevelDebug)

	toa := &TraefikOidcAuth{
		logger:     logger,
		Config:     config,
		httpClient: server.Client(),
		DiscoveryDocument: &oidc.OidcDiscovery{
			UserinfoEndpoint: server.URL,
		},
		Jwks: &oidc.JwksHandler{},
	}

	return toa, server
}

func TestGetUserInfo_Success_JSON(t *testing.T) {
	expectedClaims := jwt.MapClaims{
		"sub":   "12345",
		"name":  "John Doe",
		"email": "john.doe@example.com",
	}

	toa, server := newGetUserInfoTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedClaims)
	})
	defer server.Close()

	idTokenClaims := jwt.MapClaims{"sub": "12345"}
	claims, err := toa.getUserInfo("some-access-token", idTokenClaims["sub"].(string))

	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if claims["sub"] != expectedClaims["sub"] {
		t.Errorf("Expected sub to be '%s', but got '%s'", expectedClaims["sub"], claims["sub"])
	}

	if claims["name"] != expectedClaims["name"] {
		t.Errorf("Expected name to be '%s', but got '%s'", expectedClaims["name"], claims["name"])
	}
}

func TestGetUserInfo_Unauthorized(t *testing.T) {
	toa, server := newGetUserInfoTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer server.Close()

	idTokenClaims := jwt.MapClaims{"sub": "12345"}
	_, err := toa.getUserInfo("some-access-token", idTokenClaims["sub"].(string))

	if err == nil {
		t.Fatal("Expected an error, but got none")
	}

	if err.Error() != "token is not valid" {
		t.Errorf("Expected error message 'token is not valid', but got '%s'", err.Error())
	}
}

func TestGetUserInfo_SubMismatch(t *testing.T) {
	userInfoClaims := jwt.MapClaims{"sub": "67890"}

	toa, server := newGetUserInfoTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfoClaims)
	})
	defer server.Close()

	idTokenClaims := jwt.MapClaims{"sub": "12345"}
	claims, err := toa.getUserInfo("some-access-token", idTokenClaims["sub"].(string))

	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if len(claims) != 0 {
		t.Errorf("Expected empty claims map when subject mismatch occurs, but got: %v", claims)
	}
}

func TestGetUserInfo_NoEndpoint(t *testing.T) {
	toa, server := newGetUserInfoTest(t, nil)
	server.Close() // we don't need the server for this test
	toa.DiscoveryDocument.UserinfoEndpoint = ""

	idTokenClaims := jwt.MapClaims{"sub": "12345"}
	_, err := toa.getUserInfo("some-access-token", idTokenClaims["sub"].(string))

	if err == nil {
		t.Fatal("Expected an error, but got none")
	}

	expectedError := "userinfo_endpoint is not set"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', but got '%s'", expectedError, err.Error())
	}
}

func TestGetUserInfo_Success_JWT(t *testing.T) {
	// Create a private key for signing JWT
	privateKey, err := generateRSAKey()
	if err != nil {
		t.Fatal(err)
	}

	userInfoClaims := jwt.MapClaims{
		"sub":   "12345",
		"name":  "Jane Doe",
		"email": "jane.doe@example.com",
		"iss":   "https://issuer.example.com",
		"aud":   "test-audience",
	}

	// Create and sign the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, userInfoClaims)
	token.Header["kid"] = "test-kid"
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	toa, server := newGetUserInfoTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		fmt.Fprint(w, signedToken)
	})
	defer server.Close()

	// Setup JWKS for JWT verification
	jwksServer := setupJWKS(t, toa, privateKey)
	defer jwksServer.Close()
	toa.Config.Provider.ValidateIssuerBool = true
	toa.Config.Provider.ValidIssuer = "https://issuer.example.com"

	idTokenClaims := jwt.MapClaims{"sub": "12345"}
	claims, err := toa.getUserInfo("some-access-token", idTokenClaims["sub"].(string))

	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	if claims["sub"] != "12345" {
		t.Errorf("Expected sub to be '12345', but got '%v'", claims["sub"])
	}

	if claims["name"] != "Jane Doe" {
		t.Errorf("Expected name to be 'Jane Doe', but got '%v'", claims["name"])
	}

	if claims["email"] != "jane.doe@example.com" {
		t.Errorf("Expected email to be 'jane.doe@example.com', but got '%v'", claims["email"])
	}
}

func TestMergeClaims_BasicMerging(t *testing.T) {
	tokenClaims := map[string]interface{}{
		"sub":   "12345",
		"iss":   "https://issuer.example.com",
		"aud":   "test-audience",
		"exp":   1234567890,
		"iat":   1234567800,
		"email": "old@example.com",
	}

	userInfoClaims := map[string]interface{}{
		"sub":         "12345",
		"name":        "John Doe",
		"email":       "new@example.com",
		"given_name":  "John",
		"family_name": "Doe",
		"picture":     "https://example.com/avatar.jpg",
	}

	merged := mergeClaims(tokenClaims, userInfoClaims)

	// Protected claims should not be overwritten
	if merged["iss"] != "https://issuer.example.com" {
		t.Errorf("Expected iss to remain 'https://issuer.example.com', but got '%v'", merged["iss"])
	}

	if merged["aud"] != "test-audience" {
		t.Errorf("Expected aud to remain 'test-audience', but got '%v'", merged["aud"])
	}

	if merged["exp"] != 1234567890 {
		t.Errorf("Expected exp to remain '1234567890', but got '%v'", merged["exp"])
	}

	// Non-protected claims should be merged/overwritten
	if merged["email"] != "new@example.com" {
		t.Errorf("Expected email to be overwritten to 'new@example.com', but got '%v'", merged["email"])
	}

	if merged["name"] != "John Doe" {
		t.Errorf("Expected name to be 'John Doe', but got '%v'", merged["name"])
	}

	if merged["given_name"] != "John" {
		t.Errorf("Expected given_name to be 'John', but got '%v'", merged["given_name"])
	}

	if merged["picture"] != "https://example.com/avatar.jpg" {
		t.Errorf("Expected picture to be 'https://example.com/avatar.jpg', but got '%v'", merged["picture"])
	}
}

func TestMergeClaims_ProtectedClaimsNotOverwritten(t *testing.T) {
	tokenClaims := map[string]interface{}{
		"iss": "https://token-issuer.example.com",
		"aud": "token-audience",
		"exp": 1234567890,
		"iat": 1234567800,
		"nbf": 1234567750,
		"jti": "token-jwt-id",
		"azp": "token-authorized-party",
	}

	userInfoClaims := map[string]interface{}{
		"iss":  "https://userinfo-issuer.example.com",
		"aud":  "userinfo-audience",
		"exp":  9999999999,
		"iat":  9999999990,
		"nbf":  9999999980,
		"jti":  "userinfo-jwt-id",
		"azp":  "userinfo-authorized-party",
		"name": "John Doe",
	}

	merged := mergeClaims(tokenClaims, userInfoClaims)

	// All protected claims should retain token values
	if merged["iss"] != "https://token-issuer.example.com" {
		t.Errorf("Expected iss to remain token value, but got '%v'", merged["iss"])
	}

	if merged["aud"] != "token-audience" {
		t.Errorf("Expected aud to remain token value, but got '%v'", merged["aud"])
	}

	if merged["exp"] != 1234567890 {
		t.Errorf("Expected exp to remain token value, but got '%v'", merged["exp"])
	}

	if merged["iat"] != 1234567800 {
		t.Errorf("Expected iat to remain token value, but got '%v'", merged["iat"])
	}

	if merged["nbf"] != 1234567750 {
		t.Errorf("Expected nbf to remain token value, but got '%v'", merged["nbf"])
	}

	if merged["jti"] != "token-jwt-id" {
		t.Errorf("Expected jti to remain token value, but got '%v'", merged["jti"])
	}

	if merged["azp"] != "token-authorized-party" {
		t.Errorf("Expected azp to remain token value, but got '%v'", merged["azp"])
	}

	// Non-protected claims should be merged
	if merged["name"] != "John Doe" {
		t.Errorf("Expected name to be merged as 'John Doe', but got '%v'", merged["name"])
	}
}

func TestMergeClaims_EmptyUserInfo(t *testing.T) {
	tokenClaims := map[string]interface{}{
		"sub":   "12345",
		"email": "user@example.com",
	}

	userInfoClaims := map[string]interface{}{}

	merged := mergeClaims(tokenClaims, userInfoClaims)

	// Original claims should be preserved
	if merged["sub"] != "12345" {
		t.Errorf("Expected sub to be preserved as '12345', but got '%v'", merged["sub"])
	}

	if merged["email"] != "user@example.com" {
		t.Errorf("Expected email to be preserved as 'user@example.com', but got '%v'", merged["email"])
	}

	if len(merged) != 2 {
		t.Errorf("Expected 2 claims, but got %d", len(merged))
	}
}

func TestMergeClaims_EmptyTokenClaims(t *testing.T) {
	tokenClaims := map[string]interface{}{}

	userInfoClaims := map[string]interface{}{
		"name":  "John Doe",
		"email": "john@example.com",
		"iss":   "should-not-be-added", // Protected claim
	}

	merged := mergeClaims(tokenClaims, userInfoClaims)

	// Non-protected claims should be added
	if merged["name"] != "John Doe" {
		t.Errorf("Expected name to be 'John Doe', but got '%v'", merged["name"])
	}

	if merged["email"] != "john@example.com" {
		t.Errorf("Expected email to be 'john@example.com', but got '%v'", merged["email"])
	}

	// Protected claims should not be added even if token is empty
	if _, exists := merged["iss"]; exists {
		t.Errorf("Expected iss to not be added from userinfo, but it was: '%v'", merged["iss"])
	}

	if len(merged) != 2 {
		t.Errorf("Expected 2 claims, but got %d", len(merged))
	}
}

func TestMergeClaims_ComplexClaims(t *testing.T) {
	tokenClaims := map[string]interface{}{
		"sub":    "12345",
		"groups": []string{"admin", "user"},
		"roles": map[string]interface{}{
			"app1": []string{"read", "write"},
			"app2": []string{"read"},
		},
	}

	userInfoClaims := map[string]interface{}{
		"name":   "John Doe",
		"groups": []string{"power-user", "admin"},
		"address": map[string]interface{}{
			"street":  "123 Main St",
			"city":    "Anytown",
			"country": "US",
		},
		"roles": map[string]interface{}{
			"app1": []string{"admin"},
			"app3": []string{"read", "write", "delete"},
		},
	}

	merged := mergeClaims(tokenClaims, userInfoClaims)

	// Check that complex claims are properly merged (overwritten)
	if merged["name"] != "John Doe" {
		t.Errorf("Expected name to be 'John Doe', but got '%v'", merged["name"])
	}

	// Groups should be overwritten by userinfo
	groups, ok := merged["groups"].([]string)
	if !ok {
		t.Fatalf("Expected groups to be []string, but got %T", merged["groups"])
	}
	if len(groups) != 2 || groups[0] != "power-user" || groups[1] != "admin" {
		t.Errorf("Expected groups to be ['power-user', 'admin'], but got %v", groups)
	}

	// Roles should be overwritten by userinfo
	roles, ok := merged["roles"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected roles to be map[string]interface{}, but got %T", merged["roles"])
	}

	// Should have app1 and app3 from userinfo, app2 should be gone
	if _, exists := roles["app2"]; exists {
		t.Errorf("Expected app2 to be overwritten and not exist, but it does: %v", roles["app2"])
	}

	app1Roles, ok := roles["app1"].([]string)
	if !ok || len(app1Roles) != 1 || app1Roles[0] != "admin" {
		t.Errorf("Expected app1 roles to be ['admin'], but got %v", roles["app1"])
	}

	// Address should be added from userinfo
	address, ok := merged["address"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected address to be map[string]interface{}, but got %T", merged["address"])
	}
	if address["city"] != "Anytown" {
		t.Errorf("Expected address city to be 'Anytown', but got '%v'", address["city"])
	}
}

func TestGetUserInfo_InvalidJWT(t *testing.T) {
	toa, server := newGetUserInfoTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		fmt.Fprint(w, "this is not a valid jwt")
	})
	defer server.Close()

	idTokenClaims := jwt.MapClaims{"sub": "12345"}
	_, err := toa.getUserInfo("some-access-token", idTokenClaims["sub"].(string))

	if err == nil {
		t.Fatal("Expected an error, but got none")
	}
}

// generateRSAKey generates an RSA private key for testing
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// setupJWKS sets up a JWKS server for JWT verification in tests
func setupJWKS(t *testing.T, toa *TraefikOidcAuth, privateKey *rsa.PrivateKey) *httptest.Server {
	publicKey := &privateKey.PublicKey
	jwk := oidc.JwksKey{
		Kid: "test-kid",
		Kty: "RSA",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
	jwks := &oidc.JwksKeys{
		Keys: []oidc.JwksKey{jwk},
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))

	toa.Jwks.Url = jwksServer.URL
	return jwksServer
}
