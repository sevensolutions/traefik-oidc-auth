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

func TestClearChunkedCookieClearsEveryPresentChunk(t *testing.T) {
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

	clearChunkedCookie(cfg, rw, req, "TraefikOidcAuth.Session")

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

func TestClearChunkedCookieIsBounded(t *testing.T) {
	cfg := &config.Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie:    &config.SessionCookieConfig{Path: "/"},
	}

	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5000; i++ {
		req.AddCookie(&http.Cookie{Name: fmt.Sprintf("TraefikOidcAuth.Session.%d", i+1), Value: "x"})
	}

	rw := newMockResponseWriter()

	clearChunkedCookie(cfg, rw, req, "TraefikOidcAuth.Session")

	headers := rw.HeaderMap.Values("Set-Cookie")

	if len(headers) > maxCookieChunks+2 {
		t.Errorf("expected at most %d cleared cookies, got %d", maxCookieChunks+2, len(headers))
	}
}

func TestSetChunkedCookiesRejectsAnOversizedValue(t *testing.T) {
	cfg := &config.Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie:    &config.SessionCookieConfig{Path: "/"},
	}

	rw := newMockResponseWriter()

	tooLong := randomFixedLengthString(cookieChunkSize*maxCookieChunks + 1)

	if err := setChunkedCookies(cfg, rw, "TraefikOidcAuth.Session", tooLong); err == nil {
		t.Fatal("expected a value that needs more chunks than can be read back to be rejected")
	}

	if len(rw.HeaderMap.Values("Set-Cookie")) != 0 {
		t.Error("expected no cookie to be written for an oversized value")
	}

	stillFits := randomFixedLengthString(cookieChunkSize * maxCookieChunks)

	if err := setChunkedCookies(cfg, rw, "TraefikOidcAuth.Session", stillFits); err != nil {
		t.Errorf("expected the largest readable value to be accepted, got %v", err)
	}

	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range rw.HeaderMap.Values("Set-Cookie") {
		name, value, _ := strings.Cut(strings.Split(raw, ";")[0], "=")
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	readBack, err := readChunkedCookie(req, "TraefikOidcAuth.Session")
	if err != nil {
		t.Fatalf("expected the largest accepted value to be readable again, got %v", err)
	}

	if readBack != stillFits {
		t.Error("expected the value read back to match the value written")
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

func TestReadChunkedCookieReportsTruncation(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.Chunks", Value: "2"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session.1", Value: "111"})

	_, err = readChunkedCookie(req, "TraefikOidcAuth.Session")

	if err == nil {
		t.Fatal("expected a truncated session cookie to be an error")
	}

	if err == http.ErrNoCookie {
		t.Error("expected a truncated session cookie to be told apart from a missing one")
	}

	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("expected the error to mention the truncation, got %v", err)
	}
}
