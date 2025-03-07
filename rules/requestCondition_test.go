package rules

import (
	"net/http"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/logging"
)

func TestRequestConditionHeader(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("Header(`abc`, `def`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test", nil)

	request.Header.Set("abc", "def")

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}
}

func TestRequestConditionHeaderRegexp(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("HeaderRegexp(`abc`, `d.*`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test", nil)

	request.Header.Set("abc", "def")

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}
}

func TestRequestConditionPath(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("Path(`/products/socks`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test/products/socks", nil)

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}
}

func TestRequestConditionPathPrefix(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("PathPrefix(`/products/socks`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test/products/socks/34", nil)

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}
}

func TestRequestConditionPathRegexp(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("PathRegexp(`^/products/(shoes|socks)/[0-9]+$`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test/products/socks/23", nil)

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}
}

func TestRequestConditionMethod(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("Method(`POST`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test", nil)

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}
}

func TestRequestConditionLogicalAnd(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("PathPrefix(`/products`) && HeaderRegexp(`abc`, `.*`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test/products/23", nil)

	request.Header.Set("abc", "def")

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}
}
