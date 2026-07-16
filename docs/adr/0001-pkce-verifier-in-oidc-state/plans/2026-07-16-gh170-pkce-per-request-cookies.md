# GH-170 PKCE: Per-Request Verifier Cookies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix intermittent `Invalid code verifier` (issue [#170](https://github.com/sevensolutions/traefik-oidc-auth/issues/170)) by giving each authorization request a uniquely named PKCE cookie (keyed via `state`), plus cookie hygiene so parallel logins cannot overwrite verifiers or blow past browser/proxy cookie header limits.

**Architecture:** Same pattern as oauth2-proxy `--cookie-csrf-per-request`: generate a short nonce per login attempt, store encrypted `code_verifier` in cookie `CookieNamePrefix.CodeVerifier.<nonce>`, put `<nonce>` in OIDC `state` (`cvk`), read that exact cookie on callback. Clear the used cookie after success. Cap/clear excess CodeVerifier cookies to avoid HTTP 431. Also fix cookie `Domain` to use `Hostname()` (not `Host`, which can include a port).

**Tech Stack:** Go 1.23 (yaegi Traefik plugin), existing cookie helpers, `utils.Encrypt` / `utils.Decrypt`, `go test` in `src/`.

## Global Constraints

- Fix [#170](https://github.com/sevensolutions/traefik-oidc-auth/issues/170) only — no unrelated refactors.
- Keep PKCE S256 behavior unchanged.
- No new dependencies.
- Verifier in cookie stays encrypted with `Config.Secret`.
- Cookie `Path` remains callback path; `HttpOnly` + `Secure` remain true.
- Default max concurrent pending PKCE cookies: **5** (oauth2-proxy-style hygiene); document constant in code.
- Cookie TTL: **600 seconds** (10 minutes).
- Base: can start from `main` or finish incomplete work on `fix/gh-170` (unique names exist there; hygiene + Domain + tests still missing).

## File map

| File | Responsibility |
|------|----------------|
| `src/oidc/state.go` | `CodeVerifierKey` (`cvk`) on state |
| `src/cookie.go` | Cookie name helper; list/clear excess CodeVerifier cookies |
| `src/main.go` | Set unique cookie + `cvk` on redirect; clear used (+ extras) on callback; Domain=`Hostname()` |
| `src/oidc.go` | Read cookie by `cvk` during exchange |
| `src/cookie_test.go` / `src/pkce_test.go` | Naming, parallel isolation, excess clear |
| `src/oidc/state_test.go` | Encode/decode `cvk` |

---

### Task 1: Add `CodeVerifierKey` to state

**Files:**
- Modify: `src/oidc/state.go`
- Create: `src/oidc/state_test.go`

**Interfaces:**
- Produces: `OidcState.CodeVerifierKey string` JSON `cvk,omitempty`

- [ ] **Step 1: Write failing encode/decode tests**

```go
package oidc

import "testing"

func TestEncodeDecodeState_WithCodeVerifierKey(t *testing.T) {
	in := &OidcState{
		Action:          "Login",
		RedirectUrl:     "https://app.example.com/",
		CodeVerifierKey: "deadbeefcafebabe",
	}
	enc, err := EncodeState(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeState(enc)
	if err != nil {
		t.Fatal(err)
	}
	if out.CodeVerifierKey != in.CodeVerifierKey {
		t.Fatalf("got %q want %q", out.CodeVerifierKey, in.CodeVerifierKey)
	}
}
```

- [ ] **Step 2: Run — expect fail**

Run: `cd src && go test ./oidc -run TestEncodeDecodeState_WithCodeVerifierKey -v`

- [ ] **Step 3: Add field**

```go
type OidcState struct {
	Action          string `json:"action"`
	RedirectUrl     string `json:"redirect_url"`
	// CodeVerifierKey names the PKCE cookie for this auth request (CookieNamePrefix.CodeVerifier.<key>).
	CodeVerifierKey string `json:"cvk,omitempty"`
}
```

If implementing on top of state-embedded approach leftovers, remove `CodeVerifierEnc` / `cve` — this plan does not embed the verifier in state.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/oidc/state.go src/oidc/state_test.go
git commit -m "$(cat <<'EOF'
feat(oidc): add PKCE cookie key to state

EOF
)"
```

---

### Task 2: Cookie naming + excess cleanup helpers

**Files:**
- Modify: `src/cookie.go`
- Modify: `src/cookie_test.go`

**Interfaces:**
- Produces:

```go
const maxPendingCodeVerifierCookies = 5

func getCodeVerifierCookieName(config *config.Config, nonce string) string
func listCodeVerifierCookieNames(req *http.Request, config *config.Config) []string
func clearCodeVerifierCookie(config *config.Config, rw http.ResponseWriter, name string, callbackPath string, domain string)
func clearExcessCodeVerifierCookies(config *config.Config, rw http.ResponseWriter, req *http.Request, keepName string, callbackPath string, domain string)
```

Behavior of `clearExcessCodeVerifierCookies`:
1. Collect request cookies whose names match `CookieNamePrefix+".CodeVerifier."` prefix.
2. Always keep `keepName` (the cookie for the current successful callback).
3. If count of *other* pending cookies > `maxPendingCodeVerifierCookies-1` (or total > max after keep), expire oldest extras.
4. Because browsers do not send cookie creation time reliably, expire **all** matching cookies except `keepName` when `len(names) > maxPendingCodeVerifierCookies`. Simpler, deterministic, matches “limit pending flows” intent. (oauth2-proxy sorts by decoded CSRF time; we skip that complexity unless already decrypting cookie payloads for sorting — YAGNI: clear all extras except `keepName` when over limit **on callback**, and on **redirect** clear extras when already at max before setting a new one.)

Recommended policy (document in code comment):
- **On redirect:** if existing CodeVerifier.* cookies on the request ≥ max, expire the oldest-looking extras until there is room for one new cookie. Without timestamps, expire arbitrary extras until `len < max`, then set the new cookie.
- **On callback:** expire the used cookie; if still > max leftovers, expire extras.

- [ ] **Step 1: Write failing tests**

```go
func TestGetCodeVerifierCookieName(t *testing.T) {
	cfg := &config.Config{CookieNamePrefix: "TraefikOidcAuth"}
	got := getCodeVerifierCookieName(cfg, "abc123")
	want := "TraefikOidcAuth.CodeVerifier.abc123"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestListCodeVerifierCookieNames(t *testing.T) {
	cfg := &config.Config{CookieNamePrefix: "TraefikOidcAuth"}
	req, _ := http.NewRequest("GET", "https://app.example.com/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier.one", Value: "x"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.Session", Value: "y"})
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier.two", Value: "z"})
	names := listCodeVerifierCookieNames(req, cfg)
	if len(names) != 2 {
		t.Fatalf("got %v", names)
	}
}

func TestClearExcessCodeVerifierCookies_KeepsTarget(t *testing.T) {
	// seed req with 6 CodeVerifier cookies; keep one name; assert Set-Cookie expires the others (or all but keep when over max)
}
```

- [ ] **Step 2: Run — expect fail**

Run: `cd src && go test -run 'TestGetCodeVerifierCookieName|TestListCodeVerifierCookieNames|TestClearExcess' -v`

- [ ] **Step 3: Implement helpers in `src/cookie.go`**

```go
func getCodeVerifierCookieName(config *config.Config, nonce string) string {
	return makeCookieName(config, "CodeVerifier."+nonce)
}

func listCodeVerifierCookieNames(req *http.Request, config *config.Config) []string {
	prefix := makeCookieName(config, "CodeVerifier.")
	var names []string
	for _, c := range req.Cookies() {
		if strings.HasPrefix(c.Name, prefix) && c.Name != prefix {
			// prefix alone would be legacy shared name "....CodeVerifier." — also treat exact legacy name
			names = append(names, c.Name)
		}
	}
	// Also include legacy shared cookie if present:
	legacy := makeCookieName(config, "CodeVerifier")
	if _, err := req.Cookie(legacy); err == nil {
		names = append(names, legacy)
	}
	return names
}
```

Use `makeCookieExpireImmediately` when clearing. Set `Path` and `Domain` to match how cookies were set (callback path + hostname).

Import `strings` in `cookie.go` if not present.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/cookie.go src/cookie_test.go
git commit -m "$(cat <<'EOF'
feat(cookies): unique PKCE cookie names and excess cleanup

EOF
)"
```

---

### Task 3: Set unique cookie + `cvk` on authorize redirect

**Files:**
- Modify: `src/main.go` (`redirectToProvider`)
- Create/Modify: `src/pkce_test.go`

**Interfaces:**
- Consumes: `getCodeVerifierCookieName`, `clearExcessCodeVerifierCookies`, `randomBytesInHex(8)` for nonce
- Produces: `Set-Cookie` unique name; `state.cvk` set **before** `EncodeState`

- [ ] **Step 1: Write failing parallel-redirect test**

```go
func TestRedirectToProvider_ParallelPkceCookiesDoNotShareName(t *testing.T) {
	toa := newPkceTestAuth(t) // UsePkceBool true, Secret 32 bytes, CallbackURL set
	names := map[string]struct{}{}
	for i := 0; i < 3; i++ {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://app.example.com/x", nil)
		toa.redirectToProvider(rw, req, "https://app.example.com/x")
		var cvCookie *http.Cookie
		for _, c := range rw.Result().Cookies() {
			if strings.Contains(c.Name, "CodeVerifier.") {
				cvCookie = c
			}
		}
		if cvCookie == nil {
			t.Fatal("missing CodeVerifier.* cookie")
		}
		if _, dup := names[cvCookie.Name]; dup {
			t.Fatalf("duplicate cookie name %q", cvCookie.Name)
		}
		names[cvCookie.Name] = struct{}{}
		st := decodeStateFromLocation(t, rw.Header().Get("Location"))
		if !strings.HasSuffix(cvCookie.Name, st.CodeVerifierKey) {
			t.Fatalf("cookie %q not keyed by state cvk %q", cvCookie.Name, st.CodeVerifierKey)
		}
		if cvCookie.MaxAge != 600 {
			t.Fatalf("MaxAge=%d", cvCookie.MaxAge)
		}
		if cvCookie.Domain != "app.example.com" { // Hostname(), not Host with port
			t.Fatalf("Domain=%q", cvCookie.Domain)
		}
	}
}
```

Also add a test with `CallbackURL` that has a port in `Host` (`https://app.example.com:8443/...`) asserting cookie Domain is hostname without port.

- [ ] **Step 2: Run — expect fail on main**

Run: `cd src && go test -run TestRedirectToProvider_ParallelPkce -v`

- [ ] **Step 3: Implement in `redirectToProvider`**

Inside `UsePkceBool` block after encrypting verifier:

```go
nonce, err := randomBytesInHex(8)
if err != nil {
	http.Error(rw, err.Error(), http.StatusInternalServerError)
	return
}
state.CodeVerifierKey = nonce

clearExcessCodeVerifierCookies(
	toa.Config, rw, req,
	getCodeVerifierCookieName(toa.Config, nonce), // keepName for new cookie may not exist yet — pass "" keep and clear down to max-1
	toa.CallbackURL.Path,
	toa.CallbackURL.Hostname(),
)

http.SetCookie(rw, &http.Cookie{
	Name:     getCodeVerifierCookieName(toa.Config, nonce),
	Value:    encryptedCodeVerifier,
	MaxAge:   600,
	Secure:   true,
	HttpOnly: true,
	Path:     toa.CallbackURL.Path,
	Domain:   toa.CallbackURL.Hostname(),
	SameSite: http.SameSiteDefaultMode,
})
```

Move `EncodeState` to **after** this block so `cvk` is included. Add `state` query param after encode.

Adjust `clearExcess` API so “make room for one new cookie” is explicit, e.g. `ensureCodeVerifierCookieCapacity(..., roomFor int)`.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add src/main.go src/pkce_test.go src/cookie.go
git commit -m "$(cat <<'EOF'
fix(pkce): use per-request CodeVerifier cookies keyed by state

EOF
)"
```

---

### Task 4: Callback reads keyed cookie; clears used + excess

**Files:**
- Modify: `src/oidc.go`
- Modify: `src/main.go` (`handleCallback`)
- Modify: `src/pkce_test.go`

**Interfaces:**

```go
func exchangeAuthCode(oidcAuth *TraefikOidcAuth, req *http.Request, authCode string, codeVerifierKey string) (*oidc.OidcTokenResponse, error)
```

- Require non-empty `codeVerifierKey` when `UsePkceBool` (fail closed; also try legacy shared cookie name only if you want one-release backward compat — optional, document decision).
- **Recommendation:** support legacy `CookieNamePrefix.CodeVerifier` for one release if `cvk` empty, then remove — reduces breakage for in-flight logins during upgrade. If YAGNI, fail closed on empty `cvk`.

- [ ] **Step 1: Write exchange + callback clear tests**

```go
func TestExchangeAuthCode_ReadsKeyedCookie(t *testing.T) { /* token server asserts verifier */ }
func TestHandleCallback_ClearsUsedPkceCookie(t *testing.T) {
	// harder end-to-end; at minimum unit-test clearCodeVerifierCookie Set-Cookie MaxAge=-1
}
```

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement**

1. `exchangeAuthCode`: `req.Cookie(getCodeVerifierCookieName(..., codeVerifierKey))`, decrypt, add `code_verifier`.
2. `handleCallback`: pass `state.CodeVerifierKey`; after success, expire that cookie with `Domain: Hostname()`, `Path: CallbackURL.Path`; call excess clear.
3. Empty `cvk` + UsePkce → clear error log `"missing PKCE cookie key in state"`.

- [ ] **Step 4:** `cd src && go test` → PASS

- [ ] **Step 5: Commit**

```bash
git add src/oidc.go src/main.go src/pkce_test.go
git commit -m "$(cat <<'EOF'
fix(pkce): exchange and clear per-request verifier cookies

EOF
)"
```

---

### Task 5: Manual verification

- [ ] **Step 1:** `task run:pocketid` or `task run:keycloak` with `UsePkce: true`
- [ ] **Step 2:** Trigger parallel unauthenticated requests (browser reopen multi-tab, or code-server-like app)
- [ ] **Step 3:** Confirm login succeeds; DevTools shows `CodeVerifier.<nonce>` not a single shared name; after callback used cookie cleared
- [ ] **Step 4:** Spam >5 parallel logins; confirm cookie count stays bounded (no runaway `CodeVerifier.*`)

No commit unless docs/changelog needed.

---

## Success criteria

- Parallel authorize redirects use distinct CodeVerifier cookies keyed by `state.cvk`.
- Callback always reads the matching cookie (no cross-flow overwrite).
- Pending PKCE cookies capped (~5); used cookie cleared.
- Cookie Domain uses hostname only.
- Unit tests cover naming, parallel uniqueness, excess clear, exchange.
- Manual PKCE login OK under concurrency.

## Out of scope

- Embedding verifier in `state` (see alternate plan).
- Encrypting/signing entire state.
- Redis/server-side pending-login store.
- Changing session cookie chunking.

## Relation to existing `fix/gh-170`

Branch already has unique cookie names + `cvk` + Domain/`MaxAge` partial fix. This plan **completes** that approach with:
1. excess cookie cleanup / max pending
2. legacy shared-cookie handling (optional)
3. proper unit tests
4. corrected diagnosis (login concurrency, not token renew)
