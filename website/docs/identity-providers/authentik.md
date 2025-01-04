---
sidebar_position: 6
---

# Authentik

[Website Link](https://goauthentik.io/)

## Setup Authentik

1. Log in to the Authentik Admin Interface and navigate to *Applications > Providers*.
2. Click *Create* and select *OAuth2/OpenID Provider*.
3. Give it a name and select the *Authorization flow* you want.
4. Scroll down to *Redirect URIs/Origins* and specify the public URL of your application and append the path `/oidc/callback`.  
Eg.: `https://my-app.mydomain.com/oidc/callback`.
5. Once the provider is set up, navigate to *Applications > Applications*.
6. Click *Create* to add a new one and enter a name and slug. Choose your newly created provider.

## Middleware Configuration

:::tip
You will find the url, client id and secret in the Provider-details.
:::

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://login.my-authentik.com/application/o/<app-slug>"
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
          Scopes: ["openid", "profile", "email"]
```
