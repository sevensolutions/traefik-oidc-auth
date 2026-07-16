# GH-170 PKCE: State-Embedded Verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix intermittent `Invalid code verifier` (issue [#170](https://github.com/sevensolutions/traefik-oidc-auth/issues/170)) by storing the encrypted PKCE `code_verifier` inside the OIDC `state` parameter, eliminating the shared PKCE cookie race entirely.

**Architecture:** On login redirect, generate PKCE verifier + challenge as today, encrypt the verifier with `Config.Secret` (existing AES-GCM helper), put ciphertext on `OidcState`, encode state into the authorize URL. On callback, decrypt verifier from state and use it in the token exchange. Stop setting/reading/clearing a `CodeVerifier` cookie. Parallel authorize redirects no longer overwrite each other because there is no shared browser storage key.

**Tech Stack:** Go 1.23 (yaegi Traefik plugin), existing `utils.Encrypt` / `utils.Decrypt`, `src/oidc` state encode/decode, `go test` in `src/`.

## Global Constraints

- Fix [#170](https://github.com/sevensolutions/traefik-oidc-auth/issues/170) only — no unrelated refactors.
- Keep PKCE S256 behavior unchanged (`code_challenge_method=S256`).
- Stay compatible with Traefik plugin loading (no new deps beyond `go.mod`).
- Do not put plaintext verifier in `state` / URL — always encrypt with `Config.Secret`.
- Preserve unsigned-state behavior for non-PKCE fields for this plan (encrypting whole state is out of scope unless needed for verifier field).
- Also apply the cookie `Domain` fix (`Hostname()` not `Host`) anywhere remaining PKCE cookie clear code is removed or touched; if no cookie left, still fix Domain if any other cookies use `CallbackURL.Host` in the same flow.
- Base branch: `main` (or discard incomplete unique-cookie work on `fix/gh-170` before implementing this approach).
- Unit tests must cover parallel-flow isolation without depending on live IdP.

## File map

| File | Responsibility |
|------|----------------|
| `src/oidc/state.go` | Add encrypted verifier field on `OidcState` |
| `src/main.go` | Write encrypted verifier into state on redirect; stop setting PKCE cookie; clear cookie path on callback |
| `src/oidc.go` | Read verifier from state arg instead of cookie during `exchangeAuthCode` |
| `src/cookie.go` | Remove or stop using `getCodeVerifierCookieName` if unused |
| `src/oidc/state_test.go` | Encode/decode round-trip including encrypted verifier field |
| `src/oidc_test.go` or `src/pkce_test.go` | Token exchange uses state verifier; missing verifier fails closed |
| `website/docs/...` | Only if public docs mention CodeVerifier cookie (likely none) |

---

### Task 1: Extend `OidcState` with encrypted verifier field

**Files:**
- Modify: `src/oidc/state.go`
- Create: `src/oidc/state_test.go`

**Interfaces:**
- Produces: `OidcState.CodeVerifierEnc string` with JSON tag `cve,omitempty` (encrypted ciphertext; never plaintext)

- [ ] **Step 1: Write failing tests for encode/decode**

Create `src/oidc/state_test.go`:

```go
package oidc

import "testing"

func TestEncodeDecodeState_WithCodeVerifierEnc(t *testing.T) {
	in := &OidcState{
		Action:           "Login",
		RedirectUrl:      "https://app.example.com/path",
		CodeVerifierEnc:  "encrypted-verifier-ciphertext",
	}

	encoded, err := EncodeState(in)
	if err != nil {
		t.Fatalf("EncodeState: %v", err)
	}
	if encoded == "" {
		t.Fatal("expected non-empty encoded state")
	}

	out, err := DecodeState(encoded)
	if err != nil {
		t.Fatalf("DecodeState: %v", err)
	}
	if out.Action != in.Action {
		t.Fatalf("Action: got %q want %q", out.Action, in.Action)
	}
	if out.RedirectUrl != in.RedirectUrl {
		t.Fatalf("RedirectUrl: got %q want %q", out.RedirectUrl, in.RedirectUrl)
	}
	if out.CodeVerifierEnc != in.CodeVerifierEnc {
		t.Fatalf("CodeVerifierEnc: got %q want %q", out.CodeVerifierEnc, in.CodeVerifierEnc)
	}
}

func TestEncodeDecodeState_OmitsEmptyCodeVerifierEnc(t *testing.T) {
	in := &OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"}
	encoded, err := EncodeState(in)
	if err != nil {
		t.Fatalf("EncodeState: %v", err)
	}
	out, err := DecodeState(encoded)
	if err != nil {
		t.Fatalf("DecodeState: %v", err)
	}
	if out.CodeVerifierEnc != "" {
		t.Fatalf("expected empty CodeVerifierEnc, got %q", out.CodeVerifierEnc)
	}
}
```

- [ ] **Step 2: Run tests — expect fail on missing field**

Run: `cd src && go test ./oidc -run TestEncodeDecodeState -v`

Expected: FAIL compile or missing field until Step 3.

- [ ] **Step 3: Add field to `OidcState`**

In `src/oidc/state.go`, change struct to:

```go
type OidcState struct {
	Action          string `json:"action"`
	RedirectUrl     string `json:"redirect_url"`
	// CodeVerifierEnc is the AES-GCM encrypted PKCE code_verifier (utils.Encrypt output).
	// Carried in state so parallel login redirects cannot overwrite each other via a shared cookie.
	CodeVerifierEnc string `json:"cve,omitempty"`
}
```

Do **not** keep `CodeVerifierKey` / `cvk` from `fix/gh-170` if present — this approach does not use per-request cookie names.

- [ ] **Step 4: Re-run tests**

Run: `cd src && go test ./oidc -run TestEncodeDecodeState -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/oidc/state.go src/oidc/state_test.go
git commit -m "$(cat <<'EOF'
feat(oidc): add encrypted PKCE verifier field to state

EOF
)"
```

---

### Task 2: Write encrypted verifier into state on authorize redirect

**Files:**
- Modify: `src/main.go` (`redirectToProvider`)
- Test: `src/main_test.go` or `src/pkce_test.go` (prefer new `src/pkce_test.go` to keep focused)

**Interfaces:**
- Consumes: `OidcState.CodeVerifierEnc`, `utils.Encrypt`, `randomBytesInHex`, existing PKCE challenge generation
- Produces: authorize redirect with `state` containing `cve`; **no** `CodeVerifier` `Set-Cookie`

- [ ] **Step 1: Write failing test — parallel redirects yield distinct verifiers in state, no shared cookie**

Add `src/pkce_test.go` (package `src`). Sketch (adapt helpers from existing tests / mock writer in `cookie_test.go`):

```go
package src

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

func newPkceTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()
	callback, err := url.Parse("https://app.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	return &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Secret:           "0123456789abcdef0123456789abcdef", // 32 bytes
			CookieNamePrefix: "TraefikOidcAuth",
			Scopes:           []string{"openid"},
			Provider: &config.ProviderConfig{
				ClientId:    "test-client",
				UsePkceBool: true,
			},
		},
		CallbackURL: callback,
		DiscoveryDocument: &oidc.OidcDiscovery{
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "https://idp.example.com/token",
		},
	}
}

func decodeStateFromLocation(t *testing.T, location string) *oidc.OidcState {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	raw := u.Query().Get("state")
	st, err := oidc.DecodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRedirectToProvider_PkcePutsEncryptedVerifierInState(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://app.example.com/page", nil)

	toa.redirectToProvider(rw, req, "https://app.example.com/page")

	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d", rw.Code)
	}
	// Must not set any CodeVerifier cookie
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") {
			t.Fatalf("unexpected CodeVerifier cookie %q", c.Name)
		}
	}
	st := decodeStateFromLocation(t, rw.Header().Get("Location"))
	if st.CodeVerifierEnc == "" {
		t.Fatal("expected CodeVerifierEnc in state")
	}
	plain, err := utils.Decrypt(st.CodeVerifierEnc, toa.Config.Secret)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(plain) < 32 {
		t.Fatalf("verifier too short: %q", plain)
	}
	// challenge in URL must match S256(plain)
	loc, _ := url.Parse(rw.Header().Get("Location"))
	challenge := loc.Query().Get("code_challenge")
	if challenge == "" {
		t.Fatal("missing code_challenge")
	}
	// optional: recompute S256 and compare (same logic as production)
	_ = base64.RawURLEncoding
	_ = json.Marshal
}

func TestRedirectToProvider_ParallelFlowsHaveDistinctVerifiers(t *testing.T) {
	toa := newPkceTestAuth(t)
	var verifiers []string
	for i := 0; i < 5; i++ {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://app.example.com/page", nil)
		toa.redirectToProvider(rw, req, "https://app.example.com/page")
		st := decodeStateFromLocation(t, rw.Header().Get("Location"))
		plain, err := utils.Decrypt(st.CodeVerifierEnc, toa.Config.Secret)
		if err != nil {
			t.Fatal(err)
		}
		verifiers = append(verifiers, plain)
	}
	seen := map[string]struct{}{}
	for _, v := range verifiers {
		if _, ok := seen[v]; ok {
			t.Fatalf("duplicate verifier across parallel redirects: %q", v)
		}
		seen[v] = struct{}{}
	}
}
```

Fill in S256 assertion using the same `sha256` + `base64.RawURLEncoding` pattern as `redirectToProvider` in `src/main.go`.

- [ ] **Step 2: Run test — expect fail (cookie still used / no `cve`)**

Run: `cd src && go test -run 'TestRedirectToProvider_Pkce' -v`

Expected: FAIL

- [ ] **Step 3: Implement redirect changes**

In `src/main.go` `redirectToProvider`, inside `UsePkceBool` block:

1. Keep verifier + challenge generation.
2. `encrypted, err := utils.Encrypt(codeVerifier, toa.Config.Secret)`
3. `state.CodeVerifierEnc = encrypted`
4. **Delete** `http.SetCookie` for CodeVerifier (and any `fix/gh-170` nonce cookie naming).
5. Ensure `EncodeState` runs **after** assigning `CodeVerifierEnc` (move encode below PKCE block if currently above).

Also ensure authorize query still gets `state` after PKCE block.

- [ ] **Step 4: Run tests**

Run: `cd src && go test -run 'TestRedirectToProvider_Pkce|TestEncodeDecodeState' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main.go src/pkce_test.go
git commit -m "$(cat <<'EOF'
fix(pkce): store encrypted code_verifier in OIDC state

Avoids shared CodeVerifier cookie races under parallel logins (#170).
EOF
)"
```

---

### Task 3: Consume verifier from state in token exchange

**Files:**
- Modify: `src/oidc.go` (`exchangeAuthCode`)
- Modify: `src/main.go` (`handleCallback` call site)
- Modify: `src/pkce_test.go`

**Interfaces:**
- Change signature to pass encrypted verifier (or full state), e.g.:

```go
func exchangeAuthCode(oidcAuth *TraefikOidcAuth, req *http.Request, authCode string, codeVerifierEnc string) (*oidc.OidcTokenResponse, error)
```

- When `UsePkceBool`: decrypt `codeVerifierEnc`; on empty/decrypt error return error (fail closed).
- Do not read any CodeVerifier cookie.

- [ ] **Step 1: Write failing tests for exchange path**

```go
func TestExchangeAuthCode_UsesStateVerifier(t *testing.T) {
	// httptest token endpoint that asserts form code_verifier == expected
	// build toa with UsePkceBool, Secret, DiscoveryDocument.TokenEndpoint = server.URL
	// encrypt known verifier into codeVerifierEnc
	// call exchangeAuthCode(..., codeVerifierEnc)
	// expect success
}

func TestExchangeAuthCode_MissingVerifierFails(t *testing.T) {
	// UsePkceBool true, codeVerifierEnc ""
	// expect error, no HTTP call (or call without verifier — prefer error before POST)
}
```

Implement with `httptest.NewServer` inspecting `r.ParseForm()` / `r.Form.Get("code_verifier")`.

- [ ] **Step 2: Run — expect fail**

Run: `cd src && go test -run 'TestExchangeAuthCode_' -v`

Expected: FAIL

- [ ] **Step 3: Implement**

1. Update `exchangeAuthCode` to decrypt from `codeVerifierEnc` instead of cookie.
2. Update `handleCallback` to pass `state.CodeVerifierEnc`.
3. Remove callback `Set-Cookie` that expires CodeVerifier (no longer set).
4. Remove `getCodeVerifierCookieName` from `src/cookie.go` if unused; remove dead imports.

- [ ] **Step 4: Full unit tests**

Run: `cd src && go test`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/oidc.go src/main.go src/cookie.go src/pkce_test.go
git commit -m "$(cat <<'EOF'
fix(pkce): exchange auth code using verifier from state

EOF
)"
```

---

### Task 4: Size / compatibility sanity + manual verification notes

**Files:**
- Optionally modify: `website/docs/getting-started/middleware-configuration.md` only if it documents CodeVerifier cookies (skip if silent).
- No code unless URL length check fails.

- [ ] **Step 1: Assert state URL length stays reasonable**

Add test that a typical state (action + long redirect URL ~2KB + encrypted verifier) encodes to under ~3KB query value. Fail if > 3500 bytes (conservative IdP/proxy limit cushion).

- [ ] **Step 2: Manual check against Pocket ID / Keycloak workspace**

```bash
task run:pocketid
# or task run:keycloak
```

Enable `UsePkce: true`, open an app that fires parallel requests (or spam-refresh protected URL before login). Confirm no `Invalid code verifier`. Confirm DevTools: no `*.CodeVerifier*` cookies on authorize redirect.

- [ ] **Step 3: Commit test if added**

```bash
git add src/pkce_test.go
git commit -m "$(cat <<'EOF'
test(pkce): guard OIDC state size with embedded verifier

EOF
)"
```

---

### Task 5: Cleanup leftover fix/gh-170 artifacts (if branch based on that)

**Files:** any remaining `CodeVerifierKey` / `cvk` / unique cookie name helpers

- [ ] **Step 1:** `rg -n 'CodeVerifierKey|cvk|CodeVerifier\\.' src`
- [ ] **Step 2:** Remove leftovers; keep only `CodeVerifierEnc` / `cve`.
- [ ] **Step 3:** `cd src && go test`
- [ ] **Step 4:** Commit cleanup if needed.

---

## Success criteria

- Parallel `redirectToProvider` calls never share mutable PKCE storage.
- Token exchange uses decrypt(`state.cve`) as `code_verifier`.
- No PKCE CodeVerifier cookies set or required.
- Unit tests green; manual PKCE login works with Pocket ID / Keycloak.
- Issue #170 race class addressed without cookie-jar growth.

## Out of scope

- Encrypting / signing entire `state` (redirect URL integrity).
- Server-side session store for pending logins.
- Changing PKCE method beyond S256.
- oauth2-proxy-style multi-cookie cleanup (not needed without PKCE cookies).
