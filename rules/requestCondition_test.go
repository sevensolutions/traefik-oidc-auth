package rules

import (
	"net/http"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/logging"
)

func TestRequestCondition(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)

	rule, _ := ParseRequestCondition("Header(`abc`) && HeaderRegexp(`abc`, `.*`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test", nil)

	request.Header.Set("abc", "def")

	result := rule.Match(logger, request)

	if !result {
		t.Fail()
	}
}
