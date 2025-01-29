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

func TestMissingSecret(t *testing.T) {
	cfg := CreateConfig()
	key, err := getDerivedKey(cfg)
	if err != nil {
		t.Errorf("Expected no error for missing secret")
	}
	if key == nil {
		t.Errorf("Expected key to be generated")
	}
}

func TestSecretTooShort(t *testing.T) {
	cfg := CreateConfig()
	cfg.Secret = "12345🧳"
	_, err := getDerivedKey(cfg)
	if err == nil {
		t.Errorf("Expected error for secret too short")
	}
}
