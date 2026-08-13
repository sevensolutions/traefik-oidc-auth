package src

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
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

func TestNew_ParsesHeaderTemplatesUpfront(t *testing.T) {
	cfg := newTestConfig()
	cfg.Headers = []config.HeaderConfig{
		{Name: "X-Subject", Value: "{{ .claims.sub }}"},
		{Name: "X-Roles", Values: "{{ .claims.roles | mapToJsonArray }}"},
		{Name: "X-Empty"},
	}

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err != nil {
		t.Fatal(err)
	}

	if cfg.Headers[0].Template == nil || cfg.Headers[1].Template == nil {
		t.Error("expected the header templates to be parsed while loading the config")
	}

	if cfg.Headers[2].Template != nil {
		t.Error("expected no template for a header without a value")
	}
}

func TestNew_RejectsInvalidHeaderTemplate(t *testing.T) {
	cfg := newTestConfig()
	cfg.Headers = []config.HeaderConfig{
		{Name: "X-Broken", Value: "{{ .claims.sub "},
	}

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("expected an invalid header template to be rejected")
	}
}

func TestAttachHeaders_UsesThePreparsedTemplates(t *testing.T) {
	cfg := newTestConfig()
	cfg.Headers = []config.HeaderConfig{
		{Name: "X-Subject", Value: "{{ .claims.sub }}"},
		{Name: "X-Roles", Values: "{{ .claims.roles | mapToJsonArray }}"},
		{Name: "X-Broken-Values", Values: "not a json array"},
		{Name: "X-Empty"},
	}

	handler, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatal(err)
	}

	toa := handler.(*TraefikOidcAuth)

	req := httptest.NewRequest("GET", "https://app.example.com/", nil)
	req.Header.Set("X-Broken-Values", "spoofed")

	claims := map[string]interface{}{
		"sub":   "user-1",
		"roles": []interface{}{"admin", "user"},
	}

	if err := toa.attachHeaders(req, &session.SessionState{}, claims, false, true); err != nil {
		t.Fatal(err)
	}

	if got := req.Header.Get("X-Subject"); got != "user-1" {
		t.Errorf("expected the rendered subject, got %q", got)
	}

	if got := req.Header.Values("X-Roles"); len(got) != 2 || got[0] != "admin" || got[1] != "user" {
		t.Errorf("expected both roles as separate values, got %v", got)
	}

	if got := req.Header.Values("X-Broken-Values"); len(got) != 0 {
		t.Errorf("expected a header whose values fail to render to be removed, got %v", got)
	}

	if _, ok := req.Header["X-Empty"]; !ok {
		t.Error("expected a header without a value to still be set")
	}
}
