# GH-170 PKCE Approach Review

**Plans reviewed**

- Approach A: `2026-07-16-gh170-pkce-state-embedded-verifier.md` (encrypt verifier into OIDC `state`)
- Approach B: `2026-07-16-gh170-pkce-per-request-cookies.md` (unique `CodeVerifier.<nonce>` cookies + `cvk`)

**Code checked (workspace = `fix/gh-170`, incomplete B):** `src/main.go` (`redirectToProvider`, `handleCallback`), `src/oidc.go` (`exchangeAuthCode`), `src/oidc/state.go`, `src/cookie.go`, `src/utils/utils.go` (`Encrypt`/`Decrypt` use AES-GCM + **StdEncoding**). `main` still uses one shared `CodeVerifier` cookie and `CallbackURL.Host` (port-sensitive Domain).

---

## 1. Problem restatement

Unauthenticated parallel requests each call `redirectToProvider`. With PKCE enabled, each flow generates a `code_verifier` / `code_challenge` pair and (on `main`) stores the encrypted verifier in a **single shared** cookie name (`CookieNamePrefix.CodeVerifier`). Later flows overwrite that cookie. Callback for an earlier authorize URL still carries that flow’s `code` + `state`, but the browser now sends a **different** verifier → IdP returns intermittent `Invalid code verifier`.

Root cause: **shared mutable client storage for a per-authorization secret**, not token renew, not IdP flakiness.

Industry patterns:

- oauth2-proxy: per-request CSRF/PKCE cookies keyed from state
- ASP.NET / Duende: bind verifier into protected state (or related auth ticket)

---

## 2. Pros / cons

### Approach A — state-embedded encrypted verifier

| Pros | Cons |
|------|------|
| Removes shared key entirely; parallel flows cannot overwrite each other | Encrypted verifier rides in authorize URL (`state`) → browser history, IdP logs, proxies, Referer surface |
| No PKCE cookie jar growth → no PKCE-driven HTTP 431 | Adds ~120–150 chars ciphertext per login on top of already-variable `redirect_url` in state |
| Smaller code delta than B’s hygiene layer; better fit for mostly-stateless plugin | Relies on `Config.Secret` strength forever for any logged `state` |
| Matches Duende-style “verifier travels with the auth request” | Upgrade from `fix/gh-170` / old shared cookie leaves orphan cookies unless cleared once |
| Unit-testable without cookie jar simulation | Does not fix unsigned `state` / `redirect_url` integrity (pre-existing; still OOS) |

### Approach B — per-request cookies + `cvk`

| Pros | Cons |
|------|------|
| Verifier stays out of URL; only short nonce in `state` | Cookie proliferation under fan-out login (SPAs, code-server, multi-tab) |
| Aligns with oauth2-proxy; `fix/gh-170` already ~70% done | Excess-clear without timestamps can **delete sibling in-flight cookies** → new intermittent failures under >max parallel logins |
| Domain=`Hostname()` fix is correctly in scope | More moving parts: naming, list, clear-on-redirect, clear-on-callback, legacy name, capacity API |
| HttpOnly + Secure + Path=callback still good cookie hygiene | Cookie header size / 431 remains a real ops class; hygiene is necessary, not optional |
| | Plan’s clear policy is internally inconsistent (see §5) |

---

## 3. Security analysis

### Shared facts (both approaches)

- Verifier today is already AES-GCM-encrypted with `Config.Secret` before storage (`utils.Encrypt`).
- Outer `OidcState` is **not** signed/MACed — only JSON + `RawURLEncoding`. Attacker who can forge `state` can already point `redirect_url` (pre-existing). Neither plan fixes that.
- CSRF binding for OAuth callback is “unforgeable association between authorize and callback.” Both put unguessable material in `state` (A: GCM ciphertext; B: 8-byte hex nonce). Nonce in B is weaker entropy than A’s sealed blob, but still fine as a cookie name key if cookie value stays secret.
- PKCE itself still proves possession of verifier at token endpoint; IdP must enforce S256.

### URL leakage of `state`

| Channel | Approach A | Approach B |
|---------|------------|------------|
| Authorize URL / browser history | Full encrypted verifier in `state` | Only `cvk` nonce (~16 hex chars) |
| IdP access/audit logs | Same | Same (nonce only) |
| `Referer` to third parties | If IdP or error pages leak full authorize URL, ciphertext leaks | Only nonce leaks |
| Impact if leaked | Ciphertext only; break requires `Secret` or GCM break | Nonce alone useless without cookie |

**Verdict:** A increases **confidentiality surface** of encrypted material; B keeps verifier in HttpOnly cookie (better against passive URL/log observers). Both OK **if** `Secret` is strong and not logged. Do not treat URL presence of ciphertext as “plaintext PKCE failure.”

### Encryption details (accuracy check)

- `Encrypt` → AES-GCM, output `base64.StdEncoding` (`+`, `/`, `=`).
- `EncodeState` → JSON then `base64.RawURLEncoding`.
- Embedding StdEncoding ciphertext **inside JSON** then RawURL-encoding the whole state is **safe** for query strings. Putting raw `Encrypt` output directly as a query value would be a footgun (`+` → space). Plan A does the safe nesting; call it out in impl notes so nobody “simplifies” later.
- Rough size: 64-char hex verifier → ~124-char StdEncoding ciphertext field; typical state param stays hundreds of bytes; a ~2KB `redirect_url` already dominates (~3KB state). A’s incremental cost is small vs existing state bloat.

### CSRF / login CSRF

- Neither plan adds `nonce` OIDC param or state MAC.
- A binds challenge↔verifier by construction (same state object).
- B binds via `cvk` → cookie name; attacker needs victim browser to hold that cookie (normal same-site cookie rules). Path=callback limits send scope — good.

### Cookie jar (B-specific)

- Unique names fix overwrite race — correct.
- Cap at 5 without creation-time ordering → arbitrary eviction of live flows. That is a **correctness regression under load**, not just hygiene.
- oauth2-proxy sorts by embedded timestamp; Plan B explicitly YAGNIs that, then still claims oauth2-proxy-style behavior. Incomplete analogy.

### Referer

- A: encrypted verifier may appear in Referer if IdP navigates with full query. Mitigations are IdP/Referrer-Policy side, not plugin. Residual risk: secret compromise + log scrape.
- B: negligible Referer impact for verifier.

---

## 4. Operational concerns

### URL length / HTTP 431

- **A:** grows authorize URL slightly. Real 431 risk for this plugin is mostly **Cookie** request headers (session chunks + many `CodeVerifier.*`). A **reduces** 431 risk for PKCE. Remaining URL limits: IdP `state` max, browser URL max, reverse-proxy request-line limits — unlikely to tip solely from `cve` (~150 chars). Plan A’s ~3500-byte guard is reasonable but should measure **full authorize URL**, not only state, if worried.
- **B:** can still hit Cookie header limits; hygiene mandatory. Failed clear (wrong Domain/Path) leaves zombies forever.

### Traefik / yaegi

- Both stay in existing packages; no new deps — good.
- B adds more cookie helper surface and string prefix scanning — fine for yaegi, but more code to keep correct under plugin constraints.
- A deletes cookie path for PKCE — fewer runtime moving parts in middleware hot path.

### Upgrade / compatibility

| From | A | B |
|------|---|---|
| `main` shared cookie | In-flight logins mid-upgrade break once (expected); old cookie unused | Can optionally read legacy name when `cvk` empty (Plan B soft option) |
| `fix/gh-170` unique cookies | Must **remove** `cvk` / unique cookies; should one-shot clear `CodeVerifier*` leftovers | Natural finish of branch |
| Cookie Domain port bug | Irrelevant if cookies gone; don’t drag Domain fix into A as cargo cult | Must ship `Hostname()` |

**Base-branch note:** Plan A says start from `main` / discard incomplete unique-cookie work — correct. Implementing A on top of current `fix/gh-170` without deleting `cvk` creates a confused hybrid.

---

## 5. Plan quality critique

### Approach A — gaps / risks

1. **Incomplete S256 test sketch** — leaves ` _ = base64.RawURLEncoding` placeholders; easy for agent to ship without challenge↔verifier assert.
2. **“Domain fix if any cookie left”** — muddies A’s scope. A should delete PKCE cookies; Domain belongs to B / other cookies. Don’t expand A into session-cookie Domain audit.
3. **No upgrade orphan cleanup** — users on `fix/gh-170` or long-lived browsers keep `CodeVerifier.*` cookies. Optional one-time expire of `*.CodeVerifier*` on successful PKCE callback (or first redirect) is a small, useful add; plan ignores it.
4. **Fail-closed decrypt** — plan says it; good. Must not POST token without verifier when `UsePkceBool`.
5. **Double-redirect path** — current code sets PKCE only in `redirectToProvider`, not `doubleRedirectToProvider` (`RedirectThenLogin`). A must keep that invariant (verifier created on the hop that hits IdP). Plan silent; verify in tests.
6. **Overengineering:** low. Field + encrypt + wire change is right-sized. Size test is borderline useful, not harmful.
7. **Missing tests:** challenge matches decrypt(state); exchange never reads cookies; parallel isolation (present); upgrade leftover cookie ignored (optional).

### Approach B — gaps / risks

1. **Clear policy contradicts itself** — “expire oldest” vs “no timestamps” vs “expire all except keep when over max” vs “on redirect clear to max-1.” Agents will implement inconsistent helpers; tests won’t catch production fan-out.
2. **Eviction vs correctness** — clearing arbitrary pending cookies under concurrency **reintroduces** intermittent verifier loss for flows still waiting on IdP. Cap without LRU/timestamp is not a complete fix.
3. **`listCodeVerifierCookieNames` sketch is buggy** — `c.Name != prefix` comment about legacy/`CodeVerifier.` confusion; easy off-by-prefix bugs matching session cookies or missing legacy exact name.
4. **Legacy compat waffle** — “optional one release” vs “YAGNI fail closed” undecided. Pick before coding.
5. **Tests weak on callback clear / exchange** — “harder e2e; at minimum unit-test clear” under-specs the actual race fix verification (cookie name from state must equal cookie read).
6. **Overengineering relative to A** — capacity APIs, excess clear on two paths, legacy handling: justified only if choosing cookies. For this codebase’s stateless bias, it is the heavier design.
7. **Branch status accurate** — unique names + `cvk` + `Hostname()` already on `fix/gh-170`; hygiene + tests missing. Plan correctly frames “complete B,” but “complete B” is still more design risk than “switch to A from main.”

### Shared plan process smells

- Both are agent-checkbox novels with per-task git commits — fine for subagent execution, noisy for humans.
- Both correctly keep signing whole state OOS — good scope control.
- Neither requires live IdP for the race unit test — good.

---

## 6. Recommendation

**Implement Approach A (state-embedded encrypted verifier) from `main`.**

Why:

1. Fixes the actual bug class (shared mutable PKCE storage) with **no remaining shared key**.
2. Best match for a **stateless Traefik/yaegi** middleware: less cookie machinery, less 431 exposure, less eviction footgun.
3. Smaller, clearer success criteria; fewer ways for “hygiene” to break sibling logins.
4. Security tradeoff (ciphertext in `state`) is acceptable given existing AES-GCM + Secret model and StdEncoding nested inside RawURL state encoding.
5. Industry precedent (Duende/ASP.NET) is as legitimate as oauth2-proxy; oauth2-proxy’s cookie model exists partly because of its broader cookie-CSRF design, not because embedding is wrong.

**When B wins**

- Hard requirement: **no verifier material (even encrypted) in URLs/IdP logs**.
- Org already standardized on oauth2-proxy-style per-request cookies and wants behavioral parity.
- You must **ship `fix/gh-170` ASAP** with minimal conceptual change and accept finishing hygiene carefully (then add timestamps or stop evicting in-flight cookies aggressively).

Do **not** hybridize (embed verifier **and** keep unique cookies). Pick one storage.

---

## 7. Suggested deltas to Approach A before execution

1. **Base:** soft-reset / branch from `main`; do not layer A onto current `fix/gh-170` `cvk` code. Delete `CodeVerifierKey` if present.
2. **Encoding note in plan/code comment:** `Encrypt` uses StdEncoding; only embed via JSON → `EncodeState` RawURL. Never put ciphertext bare in query.
3. **Finish the S256 test:** decrypt `cve` → recompute challenge → assert equals authorize `code_challenge`.
4. **Exchange tests:** assert no `Cookie` dependency; empty/garbage `cve` errors before token POST.
5. **Double-redirect test:** `RedirectThenLogin` path still ends with verifier-only-on-IdP-redirect; no cookie set.
6. **Orphan cleanup (small):** on PKCE login redirect or successful callback, expire legacy `CookieNamePrefix.CodeVerifier` and any `CookieNamePrefix.CodeVerifier.*` if present (Domain=`Hostname()`, Path=callback). Prevents jar junk after switching from B/`main`.
7. **Drop Domain cargo-cult** from A’s global constraints; only touch Domain while clearing orphans.
8. **Size assert:** keep, but treat failure as “investigate long `redirect_url`,” not as reason to abandon A — existing state already carries that URL.
9. **Secret ops one-liner in PR:** rotating `Secret` invalidates in-flight PKCE states (same as today for encrypted cookies/sessions).
10. **Out of scope stay out:** no full-state MAC in this fix; track separately if open redirect via forged `state` matters.

---

## Bottom line

| Pick | Approach A from `main` |
| Skip for now | Approach B unless URL-avoidance or finishing `fix/gh-170` is a hard constraint |
| Biggest B landmine | Excess cookie eviction without timestamps under parallel login |
| Biggest A residual | Encrypted verifier in URL/logs; acceptable with strong `Secret` |
