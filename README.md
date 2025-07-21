# Traefik OpenID Connect Middleware

![E2E Tests](https://img.shields.io/github/actions/workflow/status/sevensolutions/traefik-oidc-auth/.github%2Fworkflows%2Fe2e-tests.yml?logo=github&label=E2E%20Tests&color=green)
[![Go Report Card](https://goreportcard.com/badge/github.com/sevensolutions/traefik-oidc-auth)](https://goreportcard.com/report/github.com/sevensolutions/traefik-oidc-auth)
[![Release](https://img.shields.io/github/v/release/sevensolutions/traefik-oidc-auth?label=Release)](https://github.com/sevensolutions/traefik-oidc-auth/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/sevensolutions/traefik-oidc-auth/blob/main/LICENSE)

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
> It is only tested against traefik v3+.

## Tested Providers

| Provider | Status | Notes |
|---|---|---|
| [ZITADEL](https://zitadel.com/) | ✅ | |
| [Kanidm](https://github.com/kanidm/kanidm) | ✅ | See [GH-12](https://github.com/sevensolutions/traefik-oidc-auth/issues/12) |
| [Keycloak](https://github.com/keycloak/keycloak) | ✅ | |
| [Microsoft EntraID](https://learn.microsoft.com/de-de/entra/identity/) | ✅ | |
| [HashiCorp Vault](https://www.vaultproject.io/) | ❌ | See [GH-13](https://github.com/sevensolutions/traefik-oidc-auth/issues/13) |
| [Authentik](https://goauthentik.io/) | ✅ | |
| [Pocket ID](https://github.com/stonith404/pocket-id) | ✅ | |
| [GitHub](https://github.com) | ❌ | GitHub doesn't seem to support OIDC, only plain OAuth. |

## 📚 Documentation

Please see the full documentation [HERE](https://traefik-oidc-auth.sevensolutions.cc/).

> [!NOTE]
> The documentation is being built from the *production* branch, representing the latest released version.
> If you want to check the documentation of the main branch to see whats comming in the next version, [see here](https://main.traefik-oidc-auth.pages.dev/).

## 🧪 Local Development and Testing

This project uses a [Taskfile](https://taskfile.dev/) for easy access to commonly used tasks. You need to install the Taskfile CLI by following the [official documentation](https://taskfile.dev/installation/). You also need Docker installed on your machine.

You can then run the following command to list all available tasks:

```
task --list
```

The easiest way to get started is to run the plugin with Keycloak because this repo comes with a pre-configured instance.
Just do:

1. Run `task run:keycloak` and wait a moment for everything to be settled
2. Open a web browser and navigate to `http://localhost:9080`
3. You will be redirected to Keycloak's login page. Log in with user `admin` and password `admin`.


If you want to start the plugin with your own identity provider, create the following `.env` file in `workspaces/external-idp`:

```
PROVIDER_URL=...
CLIENT_ID=...
CLIENT_SECRET=...
VALIDATE_AUDIENCE=true
```

And then do:
1. Run `task run:external`
2. Open a web browser and navigate to `http://localhost:9080`
3. You will be redirected to your own identity provider

If you want to play around with the plugin config, modify the file `workspaces/configs/http.yml`.
Changes will be reloaded automatically and you should see some debug output in the container logs.
