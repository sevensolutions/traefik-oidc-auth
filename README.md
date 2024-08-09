# Traefik OpenID Connect Middleware

<p align="left" style="text-align:left;">
  <a href="https://github.com/sevensolutions/traefik-oidc-auth">
    <img alt="Logo" src=".assets/icon.png" width="150" />
  </a>
</p>

A traefik Plugin for securing the upstream service with OpenID Connect using the Relying Party Flow.

> [!NOTE]  
> This document always represents the latest version, which may not have been released yet.  
> Therefore, some features may not be available currently but will be available soon.
> You can use the GIT-Tags to check individual versions.

> [!WARNING]
> This middleware is under development and only tested against [ZITADEL](https://zitadel.com/) yet. Although it should be compatible with any OIDC-compatible IDP.

## 💡 Getting Started

Enable the plugin in your traefik configuration.

```yml
experimental:
  plugins:
    traefik-oidc-auth:
      moduleName: "github.com/sevensolutions/traefik-oidc-auth"
      version: "v0.1.0"
```

Add a middleware and reference it in a route.

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
          Provider:
            Url: "https://..."
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
          Scopes: ["openid", "profile", "email"]

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "HostRegexp(`.+`)"
      service: whoami
      middlewares: ["oidc-auth"]
```

## 🛠 Configuration Options

### Plugin Block

| Name | Required | Default | Description |
|---|---|---|---|
| Provider | yes | *none* | Identity Provider Configuration. See *Provider* block. |
| Scopes | no | `["openid"]` | A list of scopes to request from the IDP. |
| CallbackUri | no | `/oidc/callback` | Defines the callback url used by the IDP. This needs to be registered in your IDP. |
| LoginUri | no | `null` | An optional url, which should trigger the login-flow. By default every url triggers a login-flow, if the user is not already logged in. If you set this to eg. `/login`, only this url will trigger a login-flow while all other requests return *Unauthorized*.  |
| PostLoginRedirectUri | no | `null` | An optional static redirect url where the user should be redirected after login. By default the user will be redirected to the url which triggered the login-flow. |
| LogoutUri | no | `/logout` | The url which should trigger a logout-flow. |
| PostLogoutRedirectUri | no | `/` | The url where the user should be redirected after logout. |
| UsernameClaim | no | `preferred_username` | The access_token-claim where to read the username from. |

### Provider Block

| Name | Required | Description |
|---|---|---|
| Url | no | The full URL of the Identity Provider. This is required, if *UrlEnv* is not used. |
| UrlEnv | no | The name of an environment variable, containing the full URL of the Identity Provider. This is required, if *Url* is not used. |
| ClientId | no | The client id of the application. This is required, if *ClientIdEnv* is not used. |
| ClientIdEnv | no | The name of an environment variable, containing the client id. This is required, if *ClientId* is not used. |
| ClientSecret | no | The client secret of the application. This is required, if *ClientSecretEnv* is not used. |
| ClientSecretEnv | no | The name of an environment variable, containing the client secret. This is required, if *ClientSecret* is not used. |

## 🧪 Local Development

Create the following `.env` file:

```
PROVIDER_URL=...
CLIENT_ID=...
CLIENT_SECRET=...
```

The run `docker compose up` to run traefik locally.

Now browse to http://localhost:9080. You should be redirected to your IDP.  
After you've logged in, you should be redirected back to http://localhost:9080 and see a WHOAMI page.
