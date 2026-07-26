package oidc

import (
	"encoding/base64"
	"encoding/json"

	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

type OidcState struct {
	Action      string `json:"action"`
	RedirectUrl string `json:"redirect_url"`

	// Set when this login was triggered by UnauthorizedBehavior's Challenge (an authorization
	// re-check that failed), as opposed to a plain unauthenticated login. Carried through the
	// callback so the resulting session can be marked as having already attempted a challenge,
	// regardless of which middleware instance's rules end up handling the callback.
	IsChallenge bool `json:"is_challenge"`
}

// EncodeState serializes and encrypts the state so it can be safely round-tripped through the
// identity provider as an opaque value. It must be encrypted rather than just encoded: the callback
// endpoint trusts the decoded fields (notably RedirectUrl) without further validation, so a plain
// encoding would let anyone forge a state value and turn the callback into an open redirect.
func EncodeState(state *OidcState, secret string) (string, error) {
	stateBytes, err := json.Marshal(state)

	if err != nil {
		return "", err
	}

	encrypted, err := utils.Encrypt(string(stateBytes), secret)
	if err != nil {
		return "", err
	}

	// Encrypt() returns standard base64, which includes '+', '/' and '='. Re-encode with URL-safe
	// base64 so the token travels through query strings and identity provider redirects unmodified,
	// matching the character set of the previous plain encoding.
	return base64.RawURLEncoding.EncodeToString([]byte(encrypted)), nil
}

func DecodeState(encodedState string, secret string) (*OidcState, error) {
	encryptedBytes, err := base64.RawURLEncoding.DecodeString(encodedState)
	if err != nil {
		return nil, err
	}

	stateBytes, err := utils.Decrypt(string(encryptedBytes), secret)
	if err != nil {
		return nil, err
	}

	var state OidcState
	if err := json.Unmarshal([]byte(stateBytes), &state); err != nil {
		return nil, err
	}

	return &state, nil
}
