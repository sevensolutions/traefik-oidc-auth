package src

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func TestTemplate_mapToJsonArray(t *testing.T) {
	evalContext := map[string]any{
		"claims": map[string]any{
			"roles": []any{"admin", "user", 123},
		},
	}

	template, err := newTemplate().Parse("{{ .claims.roles | withPrefix \"prefix:\" | withSuffix \":suffix\" | mapToJsonArray }}")
	if err != nil {
		t.Fatal(err)
	}
	var renderedValue bytes.Buffer
	err = template.Execute(&renderedValue, evalContext)
	if err != nil {
		t.Fatal(err)
	}

	var result []string
	err = json.Unmarshal(renderedValue.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 3 {
		t.Errorf("Expected 3 elements in the array, got %d", len(result))
	}

	if result[0] != "prefix:admin:suffix" {
		t.Errorf("Expected prefix:admin:suffix at index 0, got %s", result[0])
	}

	if result[1] != "prefix:user:suffix" {
		t.Errorf("Expected prefix:user:suffix at index 1, got %s", result[1])
	}

	if result[2] != "prefix:123:suffix" {
		t.Errorf("Expected prefix:123:suffix at index 2, got %s", result[2])
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
