package rules

import (
	"net/http"
	"testing"
)

func TestRequestCondition(t *testing.T) {
	rule, _ := ParseRequestCondition("Header(`abc`) && HeaderRegexp(`abc`, `.*`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test", nil)

	request.Header.Set("abc", "def")

	result := rule.Match(request)

	if !result {
		t.Fail()
	}
}
