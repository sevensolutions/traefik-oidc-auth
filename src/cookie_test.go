package src

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
)

func TestSetChunkedCookiesNonChunked(t *testing.T) {
	config := &config.Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie: &config.SessionCookieConfig{
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "default",
			MaxAge:   0,
		},
	}

	rw := newMockResponseWriter()

	setChunkedCookies(config, rw, "TraefikOidcAuth.Session", "some-short-value")

	setCookieHeader := rw.HeaderMap.Get("Set-Cookie")

	if setCookieHeader != "TraefikOidcAuth.Session=some-short-value; Path=/; HttpOnly; Secure" {
		t.Fail()
	}
}

func TestSetChunkedCookiesChunked(t *testing.T) {
	config := &config.Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie: &config.SessionCookieConfig{
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "default",
			MaxAge:   0,
		},
	}

	rw := newMockResponseWriter()

	longValue := randomFixedLengthString(4000)

	setChunkedCookies(config, rw, "TraefikOidcAuth.Session", longValue)

	setCookieHeader := rw.HeaderMap.Values("Set-Cookie")

	if len(setCookieHeader) != 3 {
		t.Fail()
	}

	if setCookieHeader[0] != "TraefikOidcAuth.Session.Chunks=2; Path=/; HttpOnly; Secure" {
		t.Fail()
	}
	if setCookieHeader[1] != fmt.Sprintf("TraefikOidcAuth.Session.1=%s; Path=/; HttpOnly; Secure", longValue[:3072]) {
		t.Fail()
	}
	if setCookieHeader[2] != fmt.Sprintf("TraefikOidcAuth.Session.2=%s; Path=/; HttpOnly; Secure", longValue[3072:]) {
		t.Fail()
	}
}

func TestReadChunkedCookieOrdered(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fail()
	}

	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.Chunks",
		Value: "3",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.1",
		Value: "111",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.2",
		Value: "222",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.3",
		Value: "333",
	})

	cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")
	if err != nil {
		t.Fail()
	}

	if cookieValue != "111222333" {
		t.Fail()
	}
}

func TestReadChunkedCookieUnordered(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fail()
	}

	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.3",
		Value: "333",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.Chunks",
		Value: "3",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.1",
		Value: "111",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.2",
		Value: "222",
	})

	cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")
	if err != nil {
		t.Fail()
	}

	if cookieValue != "111222333" {
		t.Fail()
	}
}

func TestReadChunkedCookieWithIncompleteChunks(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fail()
	}

	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.Chunks",
		Value: "3",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.1",
		Value: "111",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.2",
		Value: "222",
	})

	cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")

	// readChunkedCookie should fail
	if err == nil || cookieValue != "" {
		t.Fail()
	}
}

func TestReadChunkedCookieWithNoCount(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fail()
	}

	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.3",
		Value: "333",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.1",
		Value: "111",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.2",
		Value: "222",
	})

	cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")

	// readChunkedCookie should fail
	if err == nil || cookieValue != "" {
		t.Fail()
	}
}

func TestReadChunkedCookieWithOutOfRangeCount(t *testing.T) {
	for _, chunkCount := range []string{"-1", "1000000000"} {
		req, err := http.NewRequest("GET", "https://example.com", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.AddCookie(&http.Cookie{
			Name:  "TraefikOidcAuth.Session.Chunks",
			Value: chunkCount,
		})

		cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")

		if err == nil || cookieValue != "" {
			t.Errorf("expected a chunk count of %s to be rejected, got value %q and error %v", chunkCount, cookieValue, err)
		}
	}
}

func TestClearChunkedCookieWithOutOfRangeCount(t *testing.T) {
	cfg := &config.Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie:    &config.SessionCookieConfig{Path: "/"},
	}

	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.Chunks", Value: "1000000000"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.1", Value: "111"})

	rw := newMockResponseWriter()

	if err := clearChunkedCookie(cfg, rw, req, "TraefikOidcAuth.Session"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	headers := rw.HeaderMap.Values("Set-Cookie")

	if len(headers) != 3 {
		t.Fatalf("expected the 3 cookies present on the request to be cleared, got %d: %v", len(headers), headers)
	}

	for _, name := range []string{"TraefikOidcAuth.Session=", "TraefikOidcAuth.Session.Chunks=", "TraefikOidcAuth.Session.1="} {
		found := false
		for _, raw := range headers {
			if strings.HasPrefix(raw, name) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s to be cleared, got %v", name, headers)
		}
	}
}

type mockResponseWriter struct {
	HeaderMap http.Header
}

func newMockResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{
		HeaderMap: make(http.Header),
	}
}

func (writer *mockResponseWriter) Header() http.Header {
	return writer.HeaderMap
}
func (writer *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}
func (writer *mockResponseWriter) WriteHeader(statusCode int) {
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomFixedLengthString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func TestClearLegacyCodeVerifierCookies_ExpiresHostnameAndHostOnly(t *testing.T) {
	cfg := &config.Config{CookieNamePrefix: "TraefikOidcAuth"}
	callback, err := url.Parse("https://app.example.com:8443/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	rw := newMockResponseWriter()
	req, err := http.NewRequest("GET", "https://app.example.com:8443/oidc/callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier", Value: "legacy"})

	clearLegacyCodeVerifierCookies(cfg, rw, req, callback)

	headers := rw.HeaderMap.Values("Set-Cookie")
	hasHostname := false
	hasHostOnly := false
	for _, raw := range headers {
		if !strings.HasPrefix(raw, "TraefikOidcAuth.CodeVerifier=") {
			continue
		}
		lower := strings.ToLower(raw)
		// Go serializes MaxAge=-1 as Max-Age=0.
		if !strings.Contains(lower, "max-age=0") && !strings.Contains(lower, "max-age=-1") {
			t.Fatalf("expected expired cookie: %s", raw)
		}
		switch {
		case strings.Contains(raw, "Domain=app.example.com"):
			hasHostname = true
		case !strings.Contains(lower, "domain="):
			hasHostOnly = true
		}
	}
	if !hasHostname || !hasHostOnly {
		t.Fatalf("missing domain variants hostname=%v hostOnly=%v headers=%v",
			hasHostname, hasHostOnly, headers)
	}
}
