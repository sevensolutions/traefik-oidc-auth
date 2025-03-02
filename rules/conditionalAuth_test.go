package rules

import (
	"fmt"
	"net/http"
	"testing"
)

func TestConditionalAuth(t *testing.T) {
	rule, _ := ParseConditionalAuth("Header(`abc`, `def`) && Header(`abc`, `def`)")

	request, _ := http.NewRequest(http.MethodPost, "http://test", nil)

	request.Header.Set("abc", "def")

	result := rule.Match(request)

	fmt.Print(result)
}
