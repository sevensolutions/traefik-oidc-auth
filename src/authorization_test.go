package src

import (
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
)

func createAuthInstance(claims []ClaimAssertion) *AuthorizationConfig {
	return &AuthorizationConfig{
		AssertClaims: claims,
	}
}

func getTestClaims() map[string]interface{} {
	bytes := []byte(`{
		"name": "Alice",
		"age": 67,
		"children": [
			{ "name": "Bob", "age": 25 },
			{ "name": "Eve", "age": 22 }
		],
		"roles": [
			"support",
			"accountant",
			"administrator"
		],
		"address": {
			"country": "USA",
			"street": "Freedom Rd.",
			"neighbours": [
				"Joe",
				"Sam"
			]
		},
		"my:zitadel:grants": [
			"abc",
			"def",
			"ghi"
		]
	}`)

	claims := jwt.MapClaims{}
	err := json.Unmarshal(bytes, &claims)
	if err != nil {
		panic(err)
	}
	return claims
}

func TestClaimNameExists(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]ClaimAssertion{
		{Name: "name"},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize as a claim with the provided name exists")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "names"},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize as no claim with the provided name exists")
	}
}

func TestSimpleAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]ClaimAssertion{
		{Name: "name", AnyOf: []string{"Alice", "Bob", "Bruno"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since value is any of the provided values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "name", AnyOf: []string{"Ben", "Joe", "Sam"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since value is none of the provided values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "name", AllOf: []string{"Alice"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since the single value matches all of the provided values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "name", AllOf: []string{"Alice", "Bob", "Bruno"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since the single value match cannot contain all values of array")
	}

	// We need to use ['my:zitadel:grants'] here to escape the colons in the jsonpath.
	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "['my:zitadel:grants']", AllOf: []string{"abc", "def", "ghi"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since all values are contained in the array")
	}
}

func TestNestedAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]ClaimAssertion{
		{Name: "address.street", AnyOf: []string{"Freedom Rd.", "Eagle St."}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since nested value is any of the provided values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "address.street", AnyOf: []string{"Concrete HWY"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since nested value is none of the provided values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "address.street", AllOf: []string{"Freedom Rd."}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since the single value matches all of the provided values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "address.street", AllOf: []string{"Freedom Rd.", "Eagle St."}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since the single value match cannot contain all values of array")
	}
}

func TestArrayAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since some of the values are part of the provided values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Sam", "Alex"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since values are none of the provided values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AllOf: []string{"Bob", "Eve"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since all of the provided values have a matching claim value")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AllOf: []string{"Bob", "Eve", "Alex"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since not all of the provided values have a matching claim value")
	}
}

func TestCombinedAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since both assertion quantifiers have matching values")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since not all values of the allOf quantifier are matched")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Sam"}, AllOf: []string{"Eve", "Bob"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since no value of the anyOf quantifier is matched")
	}
}

func TestMultipleAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob"}},
		{Name: "name", AnyOf: []string{"Alice", "Alex"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since both assertions hold against the provided claims")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
		{Name: "name", AnyOf: []string{"Alice", "Alex"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since one of the assertions does not hold")
	}

	authorization = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
		{Name: "name", AnyOf: []string{"Alex", "Ben"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since both of the assertions do not hold")
	}
}
