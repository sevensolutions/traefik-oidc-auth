package oidc

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestKeyfunc_MissingOrInvalidKid(t *testing.T) {
	tests := []struct {
		name   string
		method jwt.SigningMethod
		header map[string]any
	}{
		{
			name:   "RS256 missing kid",
			method: jwt.SigningMethodRS256,
			header: map[string]any{},
		},
		{
			name:   "RS256 invalid kid type",
			method: jwt.SigningMethodRS256,
			header: map[string]any{"kid": 123},
		},
		{
			name:   "ES256 missing kid",
			method: jwt.SigningMethodES256,
			header: map[string]any{},
		},
		{
			name:   "ES256 invalid kid type",
			method: jwt.SigningMethodES256,
			header: map[string]any{"kid": true},
		},
	}

	h := &JwksHandler{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := &jwt.Token{
				Method: tc.method,
				Header: tc.header,
			}

			_, err := h.Keyfunc(token)
			if err == nil {
				t.Fatal("expected error for missing or invalid kid")
			}
		})
	}
}
