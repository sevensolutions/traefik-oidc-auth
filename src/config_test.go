package src

import (
	"context"
	"net/http"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
)

func newTestConfig() *config.Config {
	cfg := CreateConfig()
	cfg.Secret = "0123456789abcdef0123456789abcdef"
	cfg.Provider.Url = "https://idp.example.com"
	cfg.Provider.ClientId = "my-client"

	return cfg
}

func TestNew_RejectsUnknownTokenValidation(t *testing.T) {
	cfg := newTestConfig()
	cfg.Provider.TokenValidation = "Nonsense"

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("expected an unknown TokenValidation to be rejected")
	}
}

func TestNew_AcceptsKnownTokenValidation(t *testing.T) {
	for _, tokenValidation := range []string{"AccessToken", "IdToken", "Introspection"} {
		cfg := newTestConfig()
		cfg.Provider.TokenValidation = tokenValidation

		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err != nil {
			t.Errorf("expected TokenValidation %s to be accepted, got %v", tokenValidation, err)
		}
	}
}
