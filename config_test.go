package traefik_oidc_auth

import (
	"context"
	"testing"
)

func TestMissingProvider(t *testing.T) {
	cfg := CreateConfig()
	_, err := New(context.TODO(), nil, cfg, "pluginname")
	if err == nil {
		t.Errorf("Expected error for missing provider")
	}
}

func TestSecretTooShort(t *testing.T) {
	cfg := CreateConfig()
	cfg.Provider.Url = "https://provider/"
	cfg.Secret = "12345"
	_, err := New(context.TODO(), nil, cfg, "pluginname")
	if err == nil {
		t.Errorf("Expected error for secret too short")
	}
	// TODO: should use errors.Is() against some public error type?
}
