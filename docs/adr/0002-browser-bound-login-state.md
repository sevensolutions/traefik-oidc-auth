# 0002. Bind the login state to the browser

**Status:** Accepted  
**Date:** 2026-11-04  
**Advisory:** GHSA-6qvg-9xhq-947r

## Context

The encrypted OIDC `state` proves the middleware issued it, but not which browser started the login. Anyone could capture their own callback URL and make a victim's browser complete it, leaving the victim logged in to the attacker's account (login CSRF). PKCE doesn't help, because the verifier travels in the same `state` since [ADR 0001](0001-pkce-verifier-in-oidc-state.md).

## Decision

Keep a random value in one `CookieNamePrefix.BrowserBinding` cookie and copy it into `state` (JSON field `bb`) whenever a login starts. An existing cookie is reused and refreshed, so parallel logins of a browser share it. Before exchanging the code, the callback compares both values. If they differ, the cookie is missing, or `state` has no binding, the code is discarded and a new login bound to this browser is started (`Retried=true`). If that happens again for a restarted login, the callback responds with `400 Bad Request`, so it can't loop. A missing or undecryptable `state` always gets a `400`, as there's nothing to restart from.

- The cookie uses `Path=/`, because a login can start on any path, and no `Domain`. `SameSite` is `Lax`, or `None` if the session cookie uses `none`, because `Strict` isn't sent on the redirect back from the identity provider.
- It isn't cleared after a login, because another flow of the browser may still be running. It expires after an hour.
- Errors reported by the identity provider are handled before the check. They create no session, and it keeps the `authentication_expired` restart working for a login form left open for a long time.
- The double redirect through the callback URL now also applies without PKCE, as the cookie has to be set on the callback host.
- The binding is generic, but only the `Login` action enforces it. `RedirectThenLogin` runs before the cookie exists on the callback host and creates no session. `Logout` has no double redirect, so enforcing it would break logout with an absolute `CallbackUri` on another host.

**Rejected:** a new cookie value per login (reintroduces the overwrite race of #170), and per-flow cookies (cookie growth, see ADR 0001, and eviction could drop the flow the user is actually completing).

**Rejected:** always failing with a `400` on a mismatch. A user can hit the check without any attack involved (see below), and a restart recovers from that, usually without a prompt thanks to the identity provider's session. The restart is safe: the forged code is never used, so the victim of a malicious link can only log in as themselves, and they land on a redirect URL which was validated when the `state` was created.

## Consequences

### Positive

- A callback URL can only be completed by the browser which started the login, with or without PKCE.
- The browser only gets one additional small cookie, which is never forwarded upstream.

### Negative / residual

- Parallel logins of a browser which has no cookie yet (e.g. restoring several tabs) each create their own value and the last response wins. The other flows are restarted once.
- Logins in progress during the upgrade to this version, and login forms left open for longer than an hour, are restarted once as well.
- A malicious callback link shows the victim the identity provider's login instead of an error, so the attack is only visible in the warning log.
- The restart shares `Retried` with the `authentication_expired` restart, so a login is restarted at most once in total.
- Someone able to set cookies for the host (a sibling subdomain, or tampering with plain HTTP traffic) can plant a known value and bypass the check. A `__Host-` cookie name could prevent this later.
- `Logout` states stay unbound. The logout URI accepts a plain GET anyway, so this needs a separate solution.
