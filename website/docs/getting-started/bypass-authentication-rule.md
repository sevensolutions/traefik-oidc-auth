---
sidebar_position: 5
---

# Bypass Authentication Rule

When using the *traefik-oidc-auth* middleware, every request requires authentication by default.
But you might want to forward some public paths to the upstream directly or skip authentication if you're accessing your service from an internal network etc. This is where the `BypassAuthenticationRule` comes in.

It lets you specify a rule, similar to traefik's `router`-rules. If a request matches this rule, it is forwarded to the upstream service without any authentication.

Here is an example:

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "${PROVIDER_URL}"
            ClientId: "${CLIENT_ID}"
            ClientSecret: "${CLIENT_SECRET}"
          // highlight-next-line
          BypassAuthenticationRule: "PathPrefix(`/public`) || HeaderRegexp(`X-Real-Ip`, `^172\\.18\\.`)"
```

:::tip
Multiple rules can also be combined logically by using `&&` (logical and) and `||` (logical or). A rule can also be negated by putting a `!` in front of it.
:::

The following rules are available:

| Rule | Description |
|---|---|
| <code>Header(&#96;X-Real-Ip&#96;, &#96;172.18.0.2&#96;)</code> | Match every request with an `X-Real-Ip` header set to `172.18.0.2`. |
| <code>HeaderRegexp(&#96;X-Real-Ip&#96;, &#96;^172\\.18\\.&#96;)</code> | Match every request with an `X-Real-Ip` header matching the given regex. |
| <code>Path(&#96;/products&#96;)</code> | Match every request where the path matches `/products` exactly. |
| <code>PathPrefix(&#96;/products&#96;)</code> | Match every request by a path prefix. Eg. `/products/123` would match, `/user` would not match. |
| <code>PathRegexp(&#96;^/products/(shoes&#124;socks)/[0-9]+$&#96;)</code> | Match every request path against the given regex. |
| <code>Method(&#96;POST&#96;)</code> | Match every POST request. |

:::note
When authentication is bypassed, no headers etc. will be forwarded to the upstream service, even if an existing session is present.
:::
