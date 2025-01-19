---
sidebar_position: 3
---

# Kanidm

[Website Link](https://github.com/kanidm/kanidm)

## Create Kanidm client

```bash
kanidm system oauth2 create <client_id> "Client Readable Name" https://login.example.com
kanidm system oauth2 update-scope-map <client_id> <group_name> openid email profile groups
kanidm system oauth2 add-redirect-url <client_id> https://whoami.example.com/oidc/callback # and every other domain, if you want to use Relative URL
kanidm system oauth2 add-redirect-url <client_id> https://login.example.com/oidc/callback # if you want to use Absolute URL
kanidm system oauth2 warning-insecure-client-disable-pkce <client_id> # required if you want to use Absolute URL
kanidm system oauth2 show-basic-secret <client_id> # this will print your <client_secret>

kanidm system oauth2 get <client_id> # to verify
```

## Middleware Configuration

:::tip
Before you start, make sure your Kanidm has a valid (and not self-signed) TLS certificate and `idm.example.com` is accessible from Traefik container/host
:::

### Simple configuration for [Relative URL](../getting-started/callback-uri.md#relative-url-the-default)

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://idm.example.com/oauth2/openid/<client_id>"
            ClientId: "<client_id>"
            ClientSecret: "<client_secret>"
            UsePkce: true
            TokenValidation: "IdToken"
          Scopes: ["openid", "profile"]
          Headers:
            - Name: "X-Oidc-Subject"
              Value: "{{`{{ .claims.sub }}`}}"
            - Name: "X-Oidc-Username"
              Value: "{{`{{ .claims.preferred_username }}`}}"
```

### Slightly more complicated [Absolute URL](../getting-started/callback-uri.md#absolute-url) configuration

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          LogLevel: DEBUG
          CallbackUri: "https://login.example.com/oidc/callback"
          SessionCookie:
            Domain: ".example.com"
          Provider:
            Url: "https://idm.example.com/oauth2/openid/<client_id>"
            ClientId: "<client_id>"
            ClientSecret: "<client_secret>"
            UsePkce: false
            TokenValidation: "IdToken"
          Scopes: ["openid", "profile", "email", "groups"]
          Headers:
            - Name: "Remote-User"
              Value: "{{`{{ .claims.preferred_username }}`}}"
            - Name: "Remote-Email"
              Value: "{{`{{ .claims.email }}`}}"
            - Name: "Remote-Groups"
              Value: "{{`{{ .claims.groups }}`}}"
            - Name: "Remote-Name"
              Value: "{{`{{ .claims.name }}`}}"

  routers:
    auth:
      rule: "Host(`login.example.com)"
      service: noop@internal
      middlewares: ["oidc-auth@file"]
```
