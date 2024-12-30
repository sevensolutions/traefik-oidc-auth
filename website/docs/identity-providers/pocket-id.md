
# Pocket ID
A simple and easy-to-use OIDC provider that allows users to authenticate exclusively using [passkeys](https://fidoalliance.org/passkeys/).

https://github.com/stonith404/pocket-id

## Setup Pocket ID

1. Log into the admin interface and navigate to  *OIDC Clients* on the sidebar.
2. Click *Add OIDC Client*. Give it a name and provide a callback URL e.g. `https://my-app.mydomain.com/oidc/callback`.  Save.
3. Copy the client ID and client secret and use them below.

## Middleware Configuration

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://pocket-id.mydomain.com/"
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
            TokenValidation: "IdToken"
          Scopes: ["openid", "profile", "email"]  # "groups" also supported
```