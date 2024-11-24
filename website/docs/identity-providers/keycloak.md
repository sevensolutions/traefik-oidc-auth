---
sidebar_position: 4
---

# Keycloak

[Website Link](https://www.keycloak.org/)

## Setup Keycloak

1. Log in to the Keycloak Admin Interface and navigate to *Clients*. Make sure you have first selected the correct Realm.
2. Click *Create client*.
3. Select Client Type *OpenID Connect* and enter a client id. Click Next.
4. In the *Capability config* step, enable *Client Authentication*. Click *Save*.
5. Scroll down to the *Access settings* section and configure the *Valid redirect URIs*.
Specify the public URL of your application and append the path `/oidc/callback`.  
Eg.: `https://my-app.mydomain.com/oidc/callback`.
6. Enter the same for *Valid post logout redirect URIs*.
7. In *Web Origins* enter a `+` and click *Save*.

## Middleware Configuration

:::tip
You will find the client secret on the *Credentials* tab within your Keycloak client.
:::

```yml
http:
  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          Provider:
            Url: "https://login.my-keycloak.com/realms/<myRealm>"
            ClientId: "<YourClientId>"
            ClientSecret: "<YourClientSecret>"
            UsePkce: true
            ValidAudience: "account"
          Scopes: ["openid", "profile", "email"]
```

:::note
You need to set `ValidAudience`to `account`. I don't really know why Keycloak tokens always contain the `account` audience.
:::