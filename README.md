# Traefik OpenID Connect Middleware

<p align="left" style="text-align:left;">
  <a href="https://github.com/sevensolutions/traefik-oidc-auth">
    <img alt="Logo" src=".assets/icon.png" width="150" />
  </a>
</p>

A traefik Plugin for securing the upstream service with OpenID Connect acting as a relying party.

> [!NOTE]
> This document always represents the latest version, which may not have been released yet.
> Therefore, some features may not be available currently but will be available soon.
> You can use the GIT-Tags to check individual versions.

> [!WARNING]
> This middleware is under active development and breaking changes may occur.

## Tested Providers

| Provider | Status | Notes |
|---|---|---|
| [ZITADEL](https://zitadel.com/) | ✅ | |
| [Kanidm](https://github.com/kanidm/kanidm) | ✅ | See [GH-12](https://github.com/sevensolutions/traefik-oidc-auth/issues/12) |
| [Keycloak](https://github.com/kanidm/keycloak) | ✅ | |
| [Microsoft EntraID](https://learn.microsoft.com/de-de/entra/identity/) | ⚠️ | See [GH-15](https://github.com/sevensolutions/traefik-oidc-auth/issues/15) |
| [HashiCorp Vault](https://www.vaultproject.io/) | ❌ | See [GH-13](https://github.com/sevensolutions/traefik-oidc-auth/issues/13) |
| [Pocket ID](https://github.com/stonith404/pocket-id) | ✅ | |

## 📚 Documentation

Please see the full documentation [HERE](https://traefik-oidc-auth.sevensolutions.cc/).

> [!NOTE]
> The documentation is being built from the *production* branch, representing the latest released version.
> If you want to check the documentation of the main branch to see whats comming in the next version, [see here](https://main.traefik-oidc-auth.pages.dev/).

## 🧪 Local Development and Testing

Create the following `.env` file:

```
PROVIDER_URL=...
CLIENT_ID=...
CLIENT_SECRET=...
```

The run `docker compose up` to run traefik locally.

Now browse to http://localhost:9080. You should be redirected to your IDP.
After you've logged in, you should be redirected back to http://localhost:9080 and see a WHOAMI page.
