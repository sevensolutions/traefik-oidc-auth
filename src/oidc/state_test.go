package oidc

import (
	"encoding/base64"
	"strings"
	"testing"
)

const testStateSecret = "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

func TestEncodeDecodeStateRoundtrip(t *testing.T) {
	original := &OidcState{
		Action:      "Login",
		RedirectUrl: "https://example.com/dashboard",
		IsChallenge: true,
	}

	encoded, err := EncodeState(original, testStateSecret)
	if err != nil {
		t.Fatalf("EncodeState failed: %v", err)
	}

	decoded, err := DecodeState(encoded, testStateSecret)
	if err != nil {
		t.Fatalf("DecodeState failed: %v", err)
	}

	if decoded.Action != original.Action {
		t.Errorf("expected Action %q, got %q", original.Action, decoded.Action)
	}
	if decoded.RedirectUrl != original.RedirectUrl {
		t.Errorf("expected RedirectUrl %q, got %q", original.RedirectUrl, decoded.RedirectUrl)
	}
	if decoded.IsChallenge != original.IsChallenge {
		t.Errorf("expected IsChallenge %v, got %v", original.IsChallenge, decoded.IsChallenge)
	}
}

func TestEncodeStateIsNotPlainBase64Json(t *testing.T) {
	state := &OidcState{
		Action:      "Logout",
		RedirectUrl: "https://google.com/",
	}

	encoded, err := EncodeState(state, testStateSecret)
	if err != nil {
		t.Fatalf("EncodeState failed: %v", err)
	}

	// A forged state used to be plain base64url(json) with no integrity protection, which let an
	// attacker hand-craft e.g. {"action":"Logout","redirect_url":"https://google.com/"} and hit
	// /oidc/callback directly to trigger an open redirect. Guard against regressing back to that by
	// asserting the encoded value can't be interpreted as raw base64-encoded JSON.
	if decodedBytes, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		if strings.Contains(string(decodedBytes), "redirect_url") {
			t.Fatalf("state is stored as plain, forgeable base64-encoded JSON: %s", decodedBytes)
		}
	}
}

func TestDecodeStateRejectsForgedState(t *testing.T) {
	// Simulate an attacker who doesn't know the secret hand-crafting a state value directly (as
	// opposed to tampering with a genuine one), the way the old base64(json) encoding allowed.
	forged := &OidcState{
		Action:      "Logout",
		RedirectUrl: "https://evil.example/phish",
	}
	forgedBytes, err := EncodeState(forged, "a-completely-different-secret-32")
	if err != nil {
		t.Fatalf("failed to build forged state fixture: %v", err)
	}

	if _, err := DecodeState(forgedBytes, testStateSecret); err == nil {
		t.Fatal("expected DecodeState to reject a state encoded with a different secret, but it did not")
	}
}

func TestDecodeStateRejectsTamperedState(t *testing.T) {
	original := &OidcState{
		Action:      "Login",
		RedirectUrl: "https://example.com/ok",
	}

	encoded, err := EncodeState(original, testStateSecret)
	if err != nil {
		t.Fatalf("EncodeState failed: %v", err)
	}

	// Flip a character in the ciphertext to simulate tampering with a genuine state value.
	tampered := []rune(encoded)
	mid := len(tampered) / 2
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}

	if _, err := DecodeState(string(tampered), testStateSecret); err == nil {
		t.Fatal("expected DecodeState to reject a tampered state value, but it did not")
	}
}

func TestDecodeStateRejectsGarbage(t *testing.T) {
	if _, err := DecodeState("not-a-valid-state", testStateSecret); err == nil {
		t.Fatal("expected DecodeState to reject a garbage state value, but it did not")
	}
}
