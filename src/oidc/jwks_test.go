package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
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

func TestKeyfunc_ConcurrentWithReload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(JwksKeys{
			Keys: []JwksKey{
				{
					Kid: "test-key",
					Kty: "RSA",
					Use: "sig",
					N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					E:   "AQAB",
				},
			},
		})
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}
	logger := logging.CreateLogger(logging.LevelError)

	if err := h.EnsureLoaded(logger, server.Client(), false); err != nil {
		t.Fatal(err)
	}

	token := &jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]any{"kid": "test-key"},
	}

	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				h.Keyfunc(token)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			h.Lock.Lock()
			h.CacheDate = time.Time{}
			h.Lock.Unlock()

			if err := h.EnsureLoaded(logger, server.Client(), false); err != nil {
				t.Error(err)
				return
			}
		}
	}()

	wg.Wait()
}
