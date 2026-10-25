# 0001. Store PKCE `code_verifier` in OIDC `state`

**Status:** Accepted  
**Date:** 2026-07-16  
**Issue:** [sevensolutions/traefik-oidc-auth#170](https://github.com/sevensolutions/traefik-oidc-auth/issues/170)

## Context

With `UsePkce: true`, login stored an encrypted PKCE `code_verifier` in a **single shared** cookie (`CookieNamePrefix.CodeVerifier`). Apps that fire parallel unauthenticated requests (SPAs, multi-tab restore) each call `redirectToProvider`. Later flows overwrite the cookie. The callback for an earlier authorize URL then sends the wrong verifier → IdP responds `Invalid code verifier`.

Two common patterns:

1. **Carry the verifier in OIDC `state`** (ASP.NET / Duende-style)
2. **Per-request PKCE cookies** keyed by `state` (oauth2-proxy)

This middleware is a Traefik/yaegi plugin with cookie sessions and no shared pending-login store.

## Decision

Put the PKCE `code_verifier` on `OidcState` (JSON field `cv`) and stop using a PKCE `CodeVerifier` cookie for the happy path.

[#284](https://github.com/sevensolutions/traefik-oidc-auth/pull/284) already encrypts the **entire** state blob, so the verifier is stored as plaintext *inside* that sealed blob (no nested second encryption).

On callback, read `state.cv` and send it as `code_verifier`. Fail closed if PKCE is enabled and `cv` is missing.

Legacy `CodeVerifier` / `CodeVerifier.*` cookies are expired on redirect/callback as temporary upgrade hygiene.

**Rejected for now:** per-request cookies (need naming + eviction to avoid cookie-jar growth / HTTP 431).

## Consequences

### Positive

- Parallel login redirects cannot overwrite each other’s verifier.
- Less cookie-header growth from PKCE.
- Fits the stateless plugin model.

### Negative / residual

- Sealed verifier still travels in the authorize URL (`state`) → browser history / IdP logs see ciphertext. Same trust model as the old encrypted cookie (`Secret`).
- Slightly larger `state` query param.
- Rotating `Secret` invalidates in-flight PKCE states.
- Legacy cookie clearing can be removed once old builds are gone.
