---
sidebar_position: 4
---

# Callback URLs

The `CallbackUri` field of the top-level [plugin config block](./middleware-configuration.md#plugin-config-block) can be either an absolute or relative URL.

## Relative URL (the default)

If configured as a relative URL (by default, `/oidc/callback`), then the plugin will intercept calls to that path under any hostname it is given.

When authentication is needed, whatever host the user is accessing will be used as the callback URL for the redirect to the identity provider.

When the plugin is protecting only one hostname, this is zero-configuration.

If you protect many different hostnames using the plugin, it's likely desirable to use an identity provider with dynamic callback URL patterns, or to instead use the plugin in absolute URL mode.

## Absolute URL

If `CallbackUri` is an absolute URL with a protocol scheme and a hostname, for example `https://login.example.com/oidc/callback`, then the plugin will only intercept calls to that path and hostname, and, that URL will always be used as the callback URL for the redirect to the identity provider.

This will likely greatly simplify your identity provider configuration.

Of course you must pick an absolute URL where the plugin will receive the traffic.

:::warning
Absolute callback URLs are incompatible with PKCE.  See [GH-42](https://github.com/sevensolutions/traefik-oidc-auth/issues/42).
:::

For users familiar with [thomseddon/traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth), this is equivalent to its [Auth Host Mode](https://github.com/thomseddon/traefik-forward-auth?tab=readme-ov-file#auth-host-mode).

If you are protecting many different subdomains that share parent domain (for example `example.com`), you might wish to store the cookie at the common level:

```yml
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
        # highlight-start
          CallbackUri: "https://login.example.com/oidc/callback"
          SessionCookie:
            Domain: ".example.com"
        # highlight-end
          Provider:
            Url: "https://ident.example.com/"
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
          Scopes: ["openid", "profile", "email"]
```

This is not required, but is a performance optimization.

### Full working example for local development
```yml
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          LogLevel: DEBUG
          Provider:
            Url: "${PROVIDER_URL}"
            ClientId: "${CLIENT_ID}"
            ClientSecret: "${CLIENT_SECRET}"
            UsePkce: false
          Scopes: ["openid", "profile", "email"]
          CallbackUri: "https://auth.127.0.0.1.sslip.io/oidc/callback"
          SessionCookie:
            Domain: ".127.0.0.1.sslip.io"

  routers:
    service1:
      entryPoints: ["websecure"]
      tls: {}
      rule: "Host(`service1.127.0.0.1.sslip.io`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    service2:
      entryPoints: ["websecure"]
      tls: {}
      rule: "Host(`service2.127.0.0.1.sslip.io`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    auth:
      entryPoints: ["websecure"]
      tls: {}
      rule: "Host(`auth.127.0.0.1.sslip.io`)"
      service: noop@internal
      middlewares: ["oidc-auth@file"]
```

:::caution
If you're sharing the session cookie (by providing `SessionCookie.Domain`) as shown above, authorization may not work as expected.
Authorization is only checked when the session is being created.
This means, if you have two different middlewares with different authorization rules but you're sharing the session cookie,
you will also be logged in on the other application.
:::
