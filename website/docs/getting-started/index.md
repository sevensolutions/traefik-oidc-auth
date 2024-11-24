---
sidebar_position: 1
---

# Getting Started

## Configure the Plugin

Enable the plugin in your traefik configuration.

```yml
experimental:
  plugins:
    traefik-oidc-auth:
      moduleName: "github.com/sevensolutions/traefik-oidc-auth"
      version: "v0.4.0"
```

## Configure Middleware

```yml
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
  # highlight-start
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://<YourIdentityProviderUrl>"
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
            #UsePkce: true # Or use PKCE if your Provider supports this
          Scopes: ["openid", "profile", "email"]
    # highlight-end

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(`.+`)"
      service: whoami
      # highlight-next-line
      middlewares: ["oidc-auth"]
```