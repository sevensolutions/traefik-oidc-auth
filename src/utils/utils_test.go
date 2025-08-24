package utils

import (
	"net/http"
	"testing"
)

func TestChunkString(t *testing.T) {
	originalText := "abcdefghijklmnopqrstuvwxyz"

	chunks := ChunkString(originalText, 10)

	if len(chunks) != 3 {
		t.Fail()
	}

	value := ""

	for i := 0; i < len(chunks); i++ {
		value += chunks[i]
	}

	if value != originalText {
		t.Fail()
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	secret := "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"
	originalText := "hello"

	encrypted, err := Encrypt(originalText, secret)
	if err != nil {
		t.Fail()
	}

	decrypted, err := Decrypt(encrypted, secret)
	if err != nil {
		t.Fail()
	}

	if decrypted != originalText {
		t.Fail()
	}
}

func TestDecryptEmptyString(t *testing.T) {
	secret := "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

	_, err := Decrypt("", secret)

	// Must return an error
	if err == nil {
		t.Fail()
	}
}

func TestValidateRedirectUri(t *testing.T) {
	validUris := []string{
		"/",
		"https://example.com",
		"https://something.com",
	}

	expectRedirectUriMatch(t, "https://example.com", validUris, true)
	expectRedirectUriMatch(t, "https://malicious.com", validUris, false)
}

func TestValidateRedirectUriWildcards(t *testing.T) {
	validUris := []string{
		"/",
		"https://example.com",
		"https://something.com",
		"*",
	}

	expectRedirectUriMatch(t, "https://malicious.com", validUris, true)

	validUris = []string{
		"https://example.com",
		"https://*.something.com",
		"https://*.something.com/good",
		"https://*.something.com/good/*",
	}

	expectRedirectUriMatch(t, "https://app.something.com", validUris, true)
	expectRedirectUriMatch(t, "https://app.sub.something.com", validUris, false)
	expectRedirectUriMatch(t, "https://app.something.com/login", validUris, false)
	expectRedirectUriMatch(t, "https://app.something.com/good", validUris, true)
	expectRedirectUriMatch(t, "https://app.something.com/good/something", validUris, true)
	expectRedirectUriMatch(t, "https://app.something.com/good/something/bad", validUris, false)
}

func expectRedirectUriMatch(t *testing.T, uri string, validUris []string, shouldMatch bool) {
	matchedUri, err := ValidateRedirectUri(uri, validUris)

	if (shouldMatch && err != nil) || (!shouldMatch && err == nil) {
		t.Fail()
	}

	if (shouldMatch && matchedUri != uri) || (!shouldMatch && matchedUri != "") {
		t.Fail()
	}
}

func TestParseAcceptType(t *testing.T) {
	acceptType := ParseAcceptType("text/html")
	if acceptType.Type != "text/html" {
		t.Fail()
	}
	if acceptType.Weight != 1.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("text/html;q=0.8")
	if acceptType.Type != "text/html" {
		t.Fail()
	}
	if acceptType.Weight != 0.8 {
		t.Fail()
	}

	acceptType = ParseAcceptType("application/json; q=0.5")
	if acceptType.Type != "application/json" {
		t.Fail()
	}
	if acceptType.Weight != 0.5 {
		t.Fail()
	}

	acceptType = ParseAcceptType("text/html;q=invalid")
	if acceptType.Type != "" {
		t.Fail()
	}
	if acceptType.Weight != 0.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("*/*")
	if acceptType.Type != "*/*" {
		t.Fail()
	}
	if acceptType.Weight != 1.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("")
	if acceptType.Type != "" {
		t.Fail()
	}
	if acceptType.Weight != 0.0 {
		t.Fail()
	}
}

func TestParseAcceptHeader(t *testing.T) {
	acceptTypes := ParseAcceptHeader("text/html,application/json")
	if len(acceptTypes) != 2 {
		t.Fail()
	}
	if acceptTypes[0].Type != "text/html" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 1.0 {
		t.Fail()
	}
	if acceptTypes[1].Type != "application/json" {
		t.Fail()
	}
	if acceptTypes[1].Weight != 1.0 {
		t.Fail()
	}

	acceptTypes = ParseAcceptHeader("application/json;q=0.8,text/html;q=0.9")
	if len(acceptTypes) != 2 {
		t.Fail()
	}
	if acceptTypes[0].Type != "text/html" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 0.9 {
		t.Fail()
	}
	if acceptTypes[1].Type != "application/json" {
		t.Fail()
	}
	if acceptTypes[1].Weight != 0.8 {
		t.Fail()
	}

	acceptTypes = ParseAcceptHeader("*/*")
	if len(acceptTypes) != 1 {
		t.Fail()
	}
	if acceptTypes[0].Type != "*/*" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 1.0 {
		t.Fail()
	}
}

func TestIsHtmlRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/json")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html, application/json")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/json;q=0.9, text/html;q=0.8")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/json;q=0.8, text/html;q=0.9")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "*/*")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest("GET", "/", nil)
	if IsHtmlRequest(req) {
		t.Fail()
	}
}
