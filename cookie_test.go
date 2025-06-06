package traefik_oidc_auth

import (
	"fmt"
	"math/rand"
	"net/http"
	"testing"
)

func TestSetChunkedCookiesNonChunked(t *testing.T) {
	config := &Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie: &SessionCookieConfig{
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
	config := &Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie: &SessionCookieConfig{
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
