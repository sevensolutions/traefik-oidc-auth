# 0001. Store PKCE `code_verifier` in OIDC `state`

**Status:** Accepted  
**Date:** 2026-07-16  
**Issue:** [sevensolutions/traefik-oidc-auth#170](https://github.com/sevensolutions/traefik-oidc-auth/issues/170)

## Context

With `UsePkce: true`, login stores an encrypted PKCE `code_verifier` in a **single shared** cookie (`CookieNamePrefix.CodeVerifier`). Apps that fire parallel unauthenticated requests (SPAs, code-server, multi-tab restore) each call `redirectToProvider`. Later flows overwrite the cookie. The callback for an earlier authorize URL then sends the wrong verifier → IdP responds `Invalid code verifier` / `Failed to exchange auth code`.

Whoami-style single-request apps rarely hit this; high-fan-out apps do. Upstream branch `fix/gh-170` explored unique per-request cookies keyed via `state`.

This middleware is a Traefik/yaegi plugin: mostly stateless, cookie-backed sessions, no Redis pending-login store. Two industry patterns fit:

1. **Embed encrypted verifier in OIDC `state`** (ASP.NET / Duende-style)
2. **Per-request PKCE cookies** keyed by `state` (oauth2-proxy `--cookie-csrf-per-request`)

Supporting material for this decision:

| Doc | Role |
|-----|------|
| [plans/2026-07-16-gh170-pkce-state-embedded-verifier.md](plans/2026-07-16-gh170-pkce-state-embedded-verifier.md) | Implementation plan — Approach A |
| [plans/2026-07-16-gh170-pkce-per-request-cookies.md](plans/2026-07-16-gh170-pkce-per-request-cookies.md) | Implementation plan — Approach B |
| [plans/2026-07-16-gh170-pkce-approach-review.md](plans/2026-07-16-gh170-pkce-approach-review.md) | Comparative review (pros/cons, security, recommendation) |

## Decision

**Use Approach A:** put the PKCE `code_verifier` on `OidcState` (JSON field `cv`) and stop using a PKCE `CodeVerifier` cookie for the happy path.

Since [#284](https://github.com/sevensolutions/traefik-oidc-auth/pull/284) encrypts the **entire** OIDC state blob (`EncodeState` / `DecodeState` with plugin `Secret`), the verifier is stored as **plaintext inside state** — no nested second encryption.

On callback, read `state.cv` and send it as `code_verifier` to the token endpoint. Fail closed if PKCE is enabled and `cv` is missing.

Optionally expire legacy `CodeVerifier` / `CodeVerifier.*` cookies on redirect/callback so upgrades from shared-cookie or unique-cookie experiments do not leave jar junk.

**Rejected for now:** Approach B (unique cookies + excess cleanup), unless a hard policy forbids even sealed verifier material in authorize URLs / IdP logs.

## Consequences

### Positive

- Parallel login redirects cannot overwrite each other’s verifier (no shared storage key).
- Less cookie-header growth / HTTP 431 risk from PKCE.
- Smaller surface than cookie naming + eviction logic (eviction without timestamps can kill sibling in-flight logins).
- Fits stateless plugin model.

### Negative / residual

- Encrypted verifier rides in the authorize URL (`state`) → browser history, IdP logs, possible Referer leakage of **ciphertext**. Acceptable only with a strong `Secret` (same trust model as today’s encrypted cookie).
- Slightly larger `state` query param (~120–150 chars). Existing `redirect_url` in state already dominates size.
- Rotating `Secret` invalidates in-flight PKCE states (same as encrypted cookies today).
- Does **not** MAC/sign whole `state` (pre-existing `redirect_url` integrity gap stays out of scope).

### Follow-ups

- Implement per Approach A plan + review deltas (S256 round-trip tests, exchange fail-closed, orphan cookie clear).
- Track separate ADR/issue if full-state integrity (signed/encrypted state blob) is required.
