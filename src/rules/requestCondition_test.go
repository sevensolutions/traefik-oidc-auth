package rules

import (
	"net/http"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
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

	request, _ = http.NewRequest(http.MethodPost, "http://test", nil)

	request.Header.Set("abc", "xyz")

	result = rule.Match(logger, request)

	if result {
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

	request, _ = http.NewRequest(http.MethodPost, "http://test", nil)

	request.Header.Set("abc", "xef")

	result = rule.Match(logger, request)

	if result {
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

	request, _ = http.NewRequest(http.MethodPost, "http://test/products/shirts", nil)

	result = rule.Match(logger, request)

	if result {
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

	request, _ = http.NewRequest(http.MethodPost, "http://test/products/shirts/34", nil)

	result = rule.Match(logger, request)

	if result {
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

	request, _ = http.NewRequest(http.MethodPost, "http://test/products/shirts/23", nil)

	result = rule.Match(logger, request)

	if result {
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

	request, _ = http.NewRequest(http.MethodPut, "http://test", nil)

	result = rule.Match(logger, request)

	if result {
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

func TestRequestConditionNegatedMethod(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("!Method(`POST`)")

	request, _ := http.NewRequest(http.MethodPut, "http://test", nil)

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}

	request, _ = http.NewRequest(http.MethodPost, "http://test", nil)

	result = rule.Match(logger, request)

	if result {
		t.Fail()
	}
}

func TestRequestConditionQuery(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("Query(`apikey`, `1234`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test/products/socks?apikey=1234", nil)

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}

	request, _ = http.NewRequest(http.MethodPost, "http://test/products/socks?apikey=1235", nil)

	result = rule.Match(logger, request)

	if result {
		t.Fail()
	}
}

func TestRequestConditionQueryRegexp(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("QueryRegexp(`apikey`, `^[0-9]abc$`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test/products/socks/23?apikey=4abc", nil)

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}

	request, _ = http.NewRequest(http.MethodPost, "http://test/products/socks/23?apikey=abcd", nil)

	result = rule.Match(logger, request)

	if result {
		t.Fail()
	}
}
