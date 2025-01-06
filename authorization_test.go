package traefik_oidc_auth

import (
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func createAuthInstance(claims []ClaimAssertion) TraefikOidcAuth {
	return TraefikOidcAuth{
		Config: &Config{
			Authorization: &AuthorizationConfig{
				AssertClaims: claims,
			},
		},
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
	claims := getTestClaims()
	toa := createAuthInstance([]ClaimAssertion{
		{Name: "name"},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize as a claim with the provided name exists")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "names"},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize as no claim with the provided name exists")
	}
}

func TestSimpleAssertions(t *testing.T) {
	claims := getTestClaims()
	toa := createAuthInstance([]ClaimAssertion{
		{Name: "name", AnyOf: []string{"Alice", "Bob", "Bruno"}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since value is any of the provided values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "name", AnyOf: []string{"Ben", "Joe", "Sam"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since value is none of the provided values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "name", AllOf: []string{"Alice"}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since the single value matches all of the provided values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "name", AllOf: []string{"Alice", "Bob", "Bruno"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since the single value match cannot contain all values of array")
	}

	// We need to use ['my:zitadel:grants'] here to escape the colons in the jsonpath.
	toa = createAuthInstance([]ClaimAssertion{
		{Name: "['my:zitadel:grants']", AllOf: []string{"abc", "def", "ghi"}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since all values are contained in the array")
	}
}

func TestNestedAssertions(t *testing.T) {
	claims := getTestClaims()
	toa := createAuthInstance([]ClaimAssertion{
		{Name: "address.street", AnyOf: []string{"Freedom Rd.", "Eagle St."}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since nested value is any of the provided values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "address.street", AnyOf: []string{"Concrete HWY"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since nested value is none of the provided values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "address.street", AllOf: []string{"Freedom Rd."}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since the single value matches all of the provided values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "address.street", AllOf: []string{"Freedom Rd.", "Eagle St."}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since the single value match cannot contain all values of array")
	}
}

func TestArrayAssertions(t *testing.T) {
	claims := getTestClaims()
	toa := createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since some of the values are part of the provided values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Sam", "Alex"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since values are none of the provided values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AllOf: []string{"Bob", "Eve"}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since all of the provided values have a matching claim value")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AllOf: []string{"Bob", "Eve", "Alex"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since not all of the provided values have a matching claim value")
	}
}

func TestCombinedAssertions(t *testing.T) {
	claims := getTestClaims()
	toa := createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob"}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since both assertion quantifiers have matching values")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since not all values of the allOf quantifier are matched")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Sam"}, AllOf: []string{"Eve", "Bob"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since no value of the anyOf quantifier is matched")
	}
}

func TestMultipleAssertions(t *testing.T) {
	claims := getTestClaims()
	toa := createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob"}},
		{Name: "name", AnyOf: []string{"Alice", "Alex"}},
	})

	if !toa.isAuthorized(claims) {
		t.Fatal("Should authorize since both assertions hold against the provided claims")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
		{Name: "name", AnyOf: []string{"Alice", "Alex"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since one of the assertions does not hold")
	}

	toa = createAuthInstance([]ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
		{Name: "name", AnyOf: []string{"Alex", "Ben"}},
	})

	if toa.isAuthorized(claims) {
		t.Fatal("Should not authorize since both of the assertions do not hold")
	}
}
